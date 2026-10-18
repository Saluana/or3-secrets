import { Database } from 'bun:sqlite';
import { randomBytes } from 'node:crypto';
import { closeSync, statSync, copyFileSync, constants } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import {
  derive,
  mac,
  equal,
  encryptValue,
  decryptValue,
  seal,
  unseal,
  newCredential,
  credentialId,
  digest,
  randomId,
  type Envelope,
} from './crypto.js';
import {
  absent,
  createPrivate,
  newPrivateDirectory,
  openPrivate,
  outsideVault,
  privateDirectory,
  readPrivate,
  syncDirectory,
  syncFile,
  writePrivate,
} from './files.js';
import {
  fail,
  identifier,
  integer,
  MAX_LIVE,
  MAX_SNAPSHOT,
  MAX_WRAPS,
  parseAuditEvent,
  parseScope,
  SecretError,
  type Context,
  type Cursor,
  type Operation,
  type OperationInput,
  type Receipt,
  type Scope,
  type SecretMeta,
} from './protocol.js';

const SCHEMA = [
  `CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK(id=1), vault_id TEXT NOT NULL, format INTEGER NOT NULL CHECK(format=1), wrap_count INTEGER NOT NULL CHECK(wrap_count>=0 AND wrap_count<=1000000), verification TEXT NOT NULL, created_at INTEGER NOT NULL, mac TEXT NOT NULL) STRICT`,
  `CREATE TABLE secrets (id TEXT PRIMARY KEY, namespace TEXT NOT NULL, owner_user_id TEXT NOT NULL, workspace_id TEXT NOT NULL, consumer_id TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=1 AND revision<=9007199254740990), state TEXT NOT NULL CHECK(state IN ('available','deleted')), updated_at INTEGER NOT NULL, envelope TEXT, mac TEXT NOT NULL, CHECK((state='available' AND envelope IS NOT NULL) OR (state='deleted' AND envelope IS NULL))) STRICT`,
  `CREATE UNIQUE INDEX secrets_scope ON secrets(namespace,owner_user_id,workspace_id,consumer_id,name)`,
  `CREATE TABLE tokens (id TEXT PRIMARY KEY, digest TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('operator','service','audit-reader')), namespace TEXT, owner_user_id TEXT, workspace_id TEXT, consumer_id TEXT, capabilities TEXT NOT NULL, expires_at INTEGER, revoked_at INTEGER, created_at INTEGER NOT NULL, mac TEXT NOT NULL) STRICT`,
  `CREATE TABLE audit (seq INTEGER PRIMARY KEY CHECK(seq>=1 AND seq<=9007199254740990), previous_mac TEXT NOT NULL, payload TEXT NOT NULL, mac TEXT NOT NULL) STRICT`,
];
const SCHEMA_NAMES = ['vault', 'secrets', 'secrets_scope', 'tokens', 'audit'];
const AUTO_INDEXES = new Map([
  ['sqlite_autoindex_secrets_1', 'secrets'],
  ['sqlite_autoindex_tokens_1', 'tokens'],
]);
const ZERO_MAC = '0'.repeat(64);
const VERIFY = Buffer.from('or3-secrets master-key verification v1');

type Header = {
  id: number;
  vault_id: string;
  format: number;
  wrap_count: number;
  verification: string;
  created_at: number;
  mac: string;
};
type SecretRow = {
  id: string;
  namespace: string;
  owner_user_id: string;
  workspace_id: string;
  consumer_id: string;
  name: string;
  revision: number;
  state: 'available' | 'deleted';
  updated_at: number;
  envelope: string | null;
  mac: string;
};
type TokenRow = {
  id: string;
  digest: string;
  kind: 'operator' | 'service' | 'audit-reader';
  namespace: string | null;
  owner_user_id: string | null;
  workspace_id: string | null;
  consumer_id: string | null;
  capabilities: string;
  expires_at: number | null;
  revoked_at: number | null;
  created_at: number;
  mac: string;
};
export type AuditEvent = { seq: number; previousMac: string; event: AuditPayload; mac: string };
type AuditRow = { seq: number; previous_mac: string; payload: string; mac: string };
type AuditPayload = {
  at: string;
  operation: string;
  outcome: string;
  requestId: string;
  tokenId?: string;
  scopeId?: string;
  recordId?: string;
  revision?: number;
  actorId?: string;
  activationId?: string;
  detail?: {
    after?: number;
    through?: number;
    returned?: number;
    priorReceipt?: Receipt;
    targetTokenId?: string;
    wrapCount?: number;
    recordMac?: string;
  };
};
type Keys = { wrap: Buffer; record: Buffer; audit: Buffer; verify: Buffer };
export type InitOptions = { vaultDir: string; keyFile: string; operatorFile: string };
function scopeOf(row: SecretRow): Scope {
  return {
    namespace: row.namespace,
    ownerUserId: row.owner_user_id,
    workspaceId: row.workspace_id,
    consumerId: row.consumer_id,
  };
}
function scopeArgs(scope: Scope): string[] {
  return [scope.namespace, scope.ownerUserId, scope.workspaceId, scope.consumerId];
}
function headerFields(h: Header) {
  return [h.id, h.vault_id, h.format, h.wrap_count, h.verification, h.created_at];
}
function secretFields(r: SecretRow) {
  return [
    r.id,
    r.namespace,
    r.owner_user_id,
    r.workspace_id,
    r.consumer_id,
    r.name,
    r.revision,
    r.state,
    r.updated_at,
    r.envelope,
  ];
}
function tokenFields(r: TokenRow) {
  return [
    r.id,
    r.digest,
    r.kind,
    r.namespace,
    r.owner_user_id,
    r.workspace_id,
    r.consumer_id,
    r.capabilities,
    r.expires_at,
    r.revoked_at,
    r.created_at,
  ];
}
function metadata(r: SecretRow): SecretMeta {
  return {
    ref: { id: r.id, revision: r.revision },
    name: r.name,
    state: r.state,
    updatedAt: new Date(r.updated_at).toISOString(),
  };
}
function parsed<T>(text: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    fail('integrity_failure', 503);
  }
}
function configure(db: Database): void {
  db.exec(
    'PRAGMA busy_timeout=1000; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=EXTRA;',
  );
  const expected = {
    trusted_schema: 0,
    foreign_keys: 1,
    journal_mode: 'delete',
    locking_mode: 'exclusive',
    synchronous: 3,
  };
  for (const [key, value] of Object.entries(expected))
    if (Object.values(db.query(`PRAGMA ${key}`).get() as object)[0] !== value)
      fail('unsupported_storage', 503);
  const attached = db.query('PRAGMA database_list').all() as { name: string }[];
  if (attached.length !== 1 || attached[0]!.name !== 'main') fail('integrity_failure', 503);
  db.exec('BEGIN EXCLUSIVE; COMMIT;');
}
function schemaCheck(db: Database): void {
  const objects = db.query('SELECT type,name,tbl_name,sql FROM sqlite_schema').all() as {
    type: string;
    name: string;
    tbl_name: string;
    sql: string | null;
  }[];
  if (objects.length !== SCHEMA.length + AUTO_INDEXES.size) fail('integrity_failure', 503);
  for (const object of objects) {
    const index = SCHEMA_NAMES.indexOf(object.name);
    if (index >= 0) {
      if (
        object.sql !== SCHEMA[index] ||
        object.type !== (object.name === 'secrets_scope' ? 'index' : 'table')
      )
        fail('integrity_failure', 503);
    } else if (
      object.type !== 'index' ||
      object.sql !== null ||
      AUTO_INDEXES.get(object.name) !== object.tbl_name
    )
      fail('integrity_failure', 503);
  }
  if (Object.values(db.query('PRAGMA integrity_check(1)').get() as object)[0] !== 'ok')
    fail('integrity_failure', 503);
}

export class Vault {
  readonly dbPath: string;
  readonly vaultId: string;
  private keys: Keys;
  private closed = false;
  private failed = false;
  private polling = new Map<
    string,
    { second: number; count: number; captured: number; expiresAt: number }
  >();
  private constructor(
    private db: Database,
    private master: Buffer,
    readonly vaultDir: string,
    readonly keyFile: string,
    private header: Header,
  ) {
    this.dbPath = join(vaultDir, 'vault.sqlite');
    this.vaultId = header.vault_id;
    this.keys = {
      wrap: derive(master, this.vaultId, 'wrap'),
      record: derive(master, this.vaultId, 'record-mac'),
      audit: derive(master, this.vaultId, 'audit'),
      verify: derive(master, this.vaultId, 'verify'),
    };
  }
  static open(vaultDir: string, keyFile: string): Vault {
    return Vault.openVerified(vaultDir, keyFile, true);
  }
  // Only authenticated, private maintenance staging may use this path; normal admission always requires complete.
  static openSnapshot(vaultDir: string, keyFile: string): Vault {
    return Vault.openVerified(vaultDir, keyFile, false);
  }
  private static openVerified(vaultDir: string, keyFile: string, complete: boolean): Vault {
    privateDirectory(vaultDir);
    outsideVault(vaultDir, keyFile);
    const marker = complete ? readPrivate(join(vaultDir, 'complete'), 128).toString('utf8') : null;
    const master = readPrivate(keyFile, 32);
    if (master.length !== 32) {
      master.fill(0);
      fail('invalid_key', 503);
    }
    const dbPath = join(vaultDir, 'vault.sqlite');
    let db: Database | undefined, vault: Vault | undefined;
    try {
      const descriptor = openPrivate(dbPath, true);
      closeSync(descriptor);
      db = new Database(dbPath, { create: false, strict: true });
      configure(db);
      schemaCheck(db);
      const rows = db.query('SELECT * FROM vault').all() as Header[];
      if (
        rows.length !== 1 ||
        !/^[a-f0-9]{32}$/.test(rows[0]!.vault_id) ||
        (complete && marker !== `${rows[0]!.vault_id}\n`)
      )
        fail('integrity_failure', 503);
      vault = new Vault(db, master, resolve(vaultDir), resolve(keyFile), rows[0]!);
      vault.verify();
      return vault;
    } catch (error) {
      if (vault) vault.close();
      else db?.close();
      master.fill(0);
      if (error instanceof SecretError) throw error;
      fail('unavailable', 503);
    }
  }
  static create(
    options: InitOptions,
    source?: Vault,
    operation: 'init' | 'restore' | 'rekey' = 'init',
  ): Receipt {
    const { vaultDir, keyFile, operatorFile } = options;
    outsideVault(vaultDir, keyFile, operatorFile);
    if (source) outsideVault(source.vaultDir, vaultDir, keyFile, operatorFile);
    for (const path of [vaultDir, keyFile, operatorFile]) absent(path);
    privateDirectory(dirname(keyFile));
    privateDirectory(dirname(operatorFile));
    source?.verify();
    const master = randomBytes(32),
      vaultId = source?.vaultId ?? randomId();
    let db: Database | undefined, vault: Vault | undefined;
    try {
      newPrivateDirectory(vaultDir);
      writePrivate(keyFile, master);
      const dbPath = join(vaultDir, 'vault.sqlite');
      closeSync(createPrivate(dbPath));
      db = new Database(dbPath, { create: false, strict: true });
      configure(db);
      for (const sql of SCHEMA) db.exec(sql);
      const verificationKey = derive(master, vaultId, 'verify');
      let verification: string;
      try {
        verification = JSON.stringify(
          seal(verificationKey, randomBytes(12), VERIFY, Buffer.from(vaultId)),
        );
      } finally {
        verificationKey.fill(0);
      }
      const header: Header = {
        id: 1,
        vault_id: vaultId,
        format: 1,
        wrap_count: 0,
        verification,
        created_at: Date.now(),
        mac: '',
      };
      vault = new Vault(db, master, resolve(vaultDir), resolve(keyFile), header);
      const credential = newCredential();
      db.exec('BEGIN EXCLUSIVE');
      try {
        vault.persistHeader(true);
        if (source) {
          for (const row of source.secretRows()) {
            source.verifySecret(row);
            const copied = { ...row };
            if (row.state === 'available') {
              const value = source.plaintext(row);
              copied.envelope = vault.encrypt(copied, value);
            }
            copied.mac = mac(vault.keys.record, 'secret', secretFields(copied));
            vault.insertSecret(copied);
          }
          for (const row of source.tokenRows()) {
            source.verifyToken(row);
            const copied = { ...row, revoked_at: Date.now() };
            copied.mac = mac(vault.keys.record, 'token', tokenFields(copied));
            vault.insertToken(copied);
          }
          for (const old of source.auditRows()) {
            const event = parsed<AuditPayload>(old.payload);
            if (
              event.outcome === 'success' &&
              ['secrets/put', 'secrets/delete'].includes(event.operation)
            ) {
              // The copied chain uses a fresh key. Translate only the binding
              // for each current revision; the recovery event anchors the
              // unchanged source chain through its independently retained head.
              const current = db
                .query('SELECT revision,mac FROM secrets WHERE id=?')
                .get(event.recordId!) as { revision: number; mac: string } | null;
              if (current && current.revision === event.revision)
                event.detail = { ...event.detail, recordMac: current.mac };
            }
            vault.appendPayload(event);
          }
        }
        const operator: TokenRow = {
          id: credential.id,
          digest: credential.hash,
          kind: 'operator',
          namespace: null,
          owner_user_id: null,
          workspace_id: null,
          consumer_id: null,
          capabilities: '[]',
          expires_at: null,
          revoked_at: null,
          created_at: Date.now(),
          mac: '',
        };
        operator.mac = mac(vault.keys.record, 'token', tokenFields(operator));
        vault.insertToken(operator);
        vault.audit(operation, { requestId: randomId() }, credential.id, undefined, 'success', {
          wrapCount: vault.header.wrap_count,
          ...(source ? { priorReceipt: source.receipt() } : {}),
        });
        vault.persistHeader();
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      vault.verify();
      const receipt = vault.receipt();
      writePrivate(operatorFile, credential.raw + '\n');
      vault.close();
      vault = undefined;
      db = undefined;
      syncFile(dbPath);
      syncDirectory(vaultDir);
      syncDirectory(dirname(vaultDir));
      writePrivate(join(vaultDir, 'complete'), vaultId + '\n');
      return receipt;
    } finally {
      vault?.close();
      db?.close();
      master.fill(0);
    }
  }
  private secretRows(): IterableIterator<SecretRow> {
    return this.db
      .query('SELECT * FROM secrets ORDER BY id')
      .iterate() as IterableIterator<SecretRow>;
  }
  private tokenRows(): IterableIterator<TokenRow> {
    return this.db
      .query('SELECT * FROM tokens ORDER BY id')
      .iterate() as IterableIterator<TokenRow>;
  }
  private auditRows(): IterableIterator<AuditRow> {
    return this.db
      .query('SELECT * FROM audit ORDER BY seq')
      .iterate() as IterableIterator<AuditRow>;
  }
  private persistHeader(insert = false): void {
    this.header.mac = mac(this.keys.record, 'header', headerFields(this.header));
    if (insert)
      this.db
        .query('INSERT INTO vault VALUES(?,?,?,?,?,?,?)')
        .run(
          ...(headerFields(this.header) as [number, string, number, number, string, number]),
          this.header.mac,
        );
    else
      this.db
        .query('UPDATE vault SET wrap_count=?,mac=? WHERE id=1')
        .run(this.header.wrap_count, this.header.mac);
  }
  private verifyHeader(): void {
    const h = this.header;
    if (
      h.id !== 1 ||
      h.format !== 1 ||
      !equal(h.mac, mac(this.keys.record, 'header', headerFields(h)))
    )
      fail('integrity_failure', 503);
    integer(h.wrap_count, 0, MAX_WRAPS);
    integer(h.created_at);
    const marker = unseal(this.keys.verify, parsed(h.verification), Buffer.from(this.vaultId));
    try {
      if (!marker.equals(VERIFY)) fail('integrity_failure', 503);
    } finally {
      marker.fill(0);
    }
  }
  private verifySecret(row: SecretRow): void {
    if (!equal(row.mac, mac(this.keys.record, 'secret', secretFields(row))))
      fail('integrity_failure', 503);
    identifier(row.id);
    parseScope(scopeOf(row));
    identifier(row.name);
    integer(row.revision, 1);
    integer(row.updated_at);
    if (
      (row.state !== 'available' && row.state !== 'deleted') ||
      (row.state === 'available'
        ? typeof row.envelope !== 'string' || row.envelope.length > 67000
        : row.envelope !== null)
    )
      fail('integrity_failure', 503);
  }
  private verifyToken(row: TokenRow): void {
    if (
      !equal(row.mac, mac(this.keys.record, 'token', tokenFields(row))) ||
      !/^[a-f0-9]{32}$/.test(row.id) ||
      !/^[a-f0-9]{64}$/.test(row.digest)
    )
      fail('integrity_failure', 503);
    integer(row.created_at);
    if (row.revoked_at !== null) integer(row.revoked_at);
    const caps = parsed<unknown>(row.capabilities);
    if (!Array.isArray(caps) || new Set(caps).size !== caps.length) fail('integrity_failure', 503);
    if (row.kind === 'operator') {
      if (
        row.expires_at !== null ||
        caps.length ||
        [row.namespace, row.owner_user_id, row.workspace_id, row.consumer_id].some(
          (x) => x !== null,
        )
      )
        fail('integrity_failure', 503);
    } else {
      integer(row.expires_at, 1);
      if (
        !caps.length ||
        caps.some(
          (cap) =>
            !(
              row.kind === 'audit-reader' ? ['audit'] : ['metadata', 'read', 'write', 'delete']
            ).includes(cap),
        )
      )
        fail('integrity_failure', 503);
      if (row.kind === 'audit-reader') {
        if (
          [row.namespace, row.owner_user_id, row.workspace_id, row.consumer_id].some(
            (x) => x !== null,
          )
        )
          fail('integrity_failure', 503);
      } else {
        identifier(row.namespace);
        for (const field of [row.owner_user_id, row.workspace_id, row.consumer_id])
          if (field !== null) identifier(field);
      }
    }
  }
  verify(): Receipt {
    schemaCheck(this.db);
    this.verifyHeader();
    // Row MACs alone cannot detect removal or replay of an older, valid row.
    // Reconcile the current inventory with the authenticated mutation history.
    // Negative revisions represent tombstones; token values represent revocation.
    const secrets = new Map<string, { revision: number; mac: string }>(),
      tokens = new Map<string, boolean>();
    let wrapCount: number | undefined;
    let previous = ZERO_MAC,
      seq = 0;
    for (const row of this.auditRows()) {
      if (
        row.seq !== seq + 1 ||
        row.previous_mac !== previous ||
        Buffer.byteLength(row.payload) > 4096 ||
        !equal(row.mac, mac(this.keys.audit, 'event', [row.seq, row.previous_mac, row.payload]))
      )
        fail('integrity_failure', 503);
      const event = parsed<AuditPayload>(row.payload);
      parseAuditEvent(event);
      if (seq === 0 && event.operation !== 'init') fail('integrity_failure', 503);
      if (event.outcome === 'success') {
        if (['init', 'restore', 'rekey'].includes(event.operation)) {
          if (
            !event.tokenId ||
            tokens.has(event.tokenId) ||
            (event.operation === 'init' && seq !== 0) ||
            event.detail?.wrapCount === undefined
          )
            fail('integrity_failure', 503);
          for (const id of tokens.keys()) tokens.set(id, true);
          tokens.set(event.tokenId, false);
          wrapCount = event.detail.wrapCount;
        } else if (event.operation === 'tokens/issue' || event.operation === 'tokens/revoke') {
          const id = event.detail?.targetTokenId;
          if (!id || (event.operation === 'tokens/issue' ? tokens.has(id) : !tokens.has(id)))
            fail('integrity_failure', 503);
          tokens.set(id, event.operation === 'tokens/revoke');
        } else if (event.operation === 'secrets/put' || event.operation === 'secrets/delete') {
          if (
            !event.recordId ||
            !event.detail?.recordMac ||
            event.revision !== Math.abs(secrets.get(event.recordId)?.revision ?? 0) + 1
          )
            fail('integrity_failure', 503);
          secrets.set(event.recordId, {
            revision: event.operation === 'secrets/delete' ? -event.revision : event.revision,
            mac: event.detail.recordMac,
          });
          if (event.operation === 'secrets/put') {
            if (
              event.detail?.wrapCount === undefined ||
              event.detail.wrapCount !== (wrapCount ?? 0) + 1
            )
              fail('integrity_failure', 503);
            wrapCount = event.detail.wrapCount;
          }
        }
      }
      previous = row.mac;
      seq = integer(row.seq, 1);
    }
    if (!seq || wrapCount !== this.header.wrap_count) fail('integrity_failure', 503);
    for (const row of this.secretRows()) {
      this.verifySecret(row);
      if (row.state === 'available') this.plaintext(row);
      const committed = secrets.get(row.id);
      if (
        committed?.revision !== (row.state === 'deleted' ? -row.revision : row.revision) ||
        !equal(committed.mac, row.mac)
      )
        fail('integrity_failure', 503);
      secrets.delete(row.id);
    }
    for (const row of this.tokenRows()) {
      this.verifyToken(row);
      if (tokens.get(row.id) !== (row.revoked_at !== null)) fail('integrity_failure', 503);
      tokens.delete(row.id);
    }
    if (secrets.size || tokens.size) fail('integrity_failure', 503);
    return { vaultId: this.vaultId, seq, mac: previous };
  }
  receipt(): Receipt {
    const row = this.db
      .query('SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1')
      .get() as Cursor | null;
    if (!row) fail('integrity_failure', 503);
    return { vaultId: this.vaultId, ...row };
  }
  checkReceipt(receipt: Receipt): void {
    if (receipt.vaultId !== this.vaultId || !this.cursorMatches(receipt))
      fail('audit_checkpoint_mismatch', 409);
  }
  private appendPayload(event: AuditPayload): void {
    parseAuditEvent(event);
    const head = this.db
      .query('SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1')
      .get() as Cursor | null;
    const seq = integer((head?.seq ?? 0) + 1, 1),
      previous = head?.mac ?? ZERO_MAC,
      payload = JSON.stringify(event);
    if (Buffer.byteLength(payload) > 4096) fail('integrity_failure', 503);
    this.db
      .query('INSERT INTO audit VALUES(?,?,?,?)')
      .run(seq, previous, payload, mac(this.keys.audit, 'event', [seq, previous, payload]));
  }
  private audit(
    operation: string,
    context: Context,
    tokenId: string | undefined,
    scope: Scope | undefined,
    outcome = 'success',
    detail?: AuditPayload['detail'],
    record?: SecretRow,
  ): void {
    this.appendPayload({
      at: new Date().toISOString(),
      operation,
      outcome,
      requestId: context.requestId,
      ...(tokenId ? { tokenId } : {}),
      ...(scope ? { scopeId: mac(this.keys.record, 'scope', scopeArgs(scope)) } : {}),
      ...(record ? { recordId: record.id, revision: record.revision } : {}),
      ...(context.actorId ? { actorId: context.actorId } : {}),
      ...(context.activationId ? { activationId: context.activationId } : {}),
      ...(detail ? { detail } : {}),
    });
  }
  private insertSecret(row: SecretRow): void {
    this.db
      .query('INSERT INTO secrets VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(
        ...(secretFields(row) as [
          string,
          string,
          string,
          string,
          string,
          string,
          number,
          string,
          number,
          string | null,
        ]),
        row.mac,
      );
  }
  private insertToken(row: TokenRow): void {
    this.db
      .query('INSERT INTO tokens VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(
        ...(tokenFields(row) as [
          string,
          string,
          string,
          string | null,
          string | null,
          string | null,
          string | null,
          string,
          number | null,
          number | null,
          number,
        ]),
        row.mac,
      );
  }
  private encrypt(row: SecretRow, plaintext: string): string {
    if (this.header.wrap_count >= MAX_WRAPS) fail('wrap_limit', 503);
    const encrypted = encryptValue(
      this.keys.wrap,
      this.vaultId,
      row.id,
      scopeOf(row),
      row.name,
      row.revision,
      plaintext,
    );
    this.header.wrap_count++;
    return JSON.stringify(encrypted);
  }
  private plaintext(row: SecretRow): string {
    this.verifySecret(row);
    if (row.state !== 'available' || row.envelope === null) fail('not_found', 404);
    return decryptValue(
      this.keys.wrap,
      this.vaultId,
      row.id,
      scopeOf(row),
      row.name,
      row.revision,
      parsed<Envelope>(row.envelope),
    );
  }
  private authenticate(raw: string): TokenRow {
    const id = credentialId(raw);
    if (!id) fail('unauthorized', 401);
    const row = this.db.query('SELECT * FROM tokens WHERE id=?').get(id) as TokenRow | null;
    if (!row) fail('unauthorized', 401);
    this.verifyToken(row);
    if (
      !equal(row.digest, digest(raw)) ||
      row.revoked_at !== null ||
      (row.expires_at !== null && row.expires_at <= Date.now())
    )
      fail('unauthorized', 401);
    return row;
  }
  private authorize(row: TokenRow, operation: Operation, scope?: Scope): void {
    if (operation === 'status') return;
    if (operation.startsWith('tokens/')) {
      if (row.kind !== 'operator') fail('forbidden', 403);
      return;
    }
    if (operation === 'audit/read') {
      if (row.kind !== 'audit-reader') fail('forbidden', 403);
      return;
    }
    if (row.kind !== 'service' || !scope) fail('forbidden', 403);
    for (const [restriction, actual] of [
      [row.namespace, scope.namespace],
      [row.owner_user_id, scope.ownerUserId],
      [row.workspace_id, scope.workspaceId],
      [row.consumer_id, scope.consumerId],
    ])
      if (restriction !== null && restriction !== actual) fail('forbidden', 403);
    const needed = (
      {
        'secrets/inspect': 'metadata',
        'secrets/list': 'metadata',
        'secrets/put': 'write',
        'secrets/resolve': 'read',
        'secrets/delete': 'delete',
      } as const
    )[operation as 'secrets/inspect'];
    if (!parsed<string[]>(row.capabilities).includes(needed)) fail('forbidden', 403);
  }
  preflight(credential: string, expectedVault: string): void {
    if (this.failed || this.closed) fail('unavailable', 503);
    try {
      this.authenticate(credential);
      if (expectedVault !== this.vaultId) fail('vault_mismatch', 409);
    } catch (error) {
      if (error instanceof SecretError) {
        if (error.code === 'integrity_failure') this.failed = true;
        throw error;
      }
      this.failed = true;
      fail('unavailable', 503);
    }
  }
  private admitReader(token: TokenRow): void {
    if (token.kind !== 'audit-reader') return;
    const now = Date.now(),
      second = Math.floor(now / 1000);
    let poll = this.polling.get(token.id);
    if (!poll) {
      if (this.polling.size >= 1024) {
        for (const [id, value] of this.polling) if (value.expiresAt <= now) this.polling.delete(id);
        if (this.polling.size >= 1024) fail('busy', 429);
      }
      poll = { second, count: 0, captured: 0, expiresAt: token.expires_at! };
      this.polling.set(token.id, poll);
    }
    if (poll.second !== second) {
      poll.second = second;
      poll.count = 0;
    }
    if (poll.count >= 5) fail('busy', 429);
    poll.count++;
  }
  perform(
    operation: Operation,
    input: OperationInput,
    credential: string,
    expectedVault: string,
  ): unknown {
    if (this.failed || this.closed) fail('unavailable', 503);
    const startingCount = this.header.wrap_count;
    let inTransaction = false,
      token: TokenRow | undefined,
      rejection: SecretError | undefined,
      result: unknown;
    try {
      // Keep filesystem failures inside the fail-stop boundary. One operation
      // can add a bounded value, metadata and audit entry; reserve a further MiB.
      if (statSync(this.dbPath).size + 1024 ** 2 >= MAX_LIVE) fail('capacity_reached', 503);
      this.db.exec('BEGIN EXCLUSIVE');
      inTransaction = true;
      token = this.authenticate(credential);
      this.admitReader(token);
      try {
        if (expectedVault !== this.vaultId) fail('vault_mismatch', 409);
        this.authorize(token, operation, input.scope);
        result = this.dispatch(operation, input, token);
      } catch (error) {
        if (!(error instanceof SecretError) || error.status >= 500) throw error;
        rejection = error;
        // Pre-admission throttling is bounded telemetry rather than an attacker-driven write loop.
        if (error.status !== 429)
          this.audit(operation, input.context, token.id, input.scope, error.code);
      }
      this.db.exec('COMMIT');
      inTransaction = false;
    } catch (error) {
      if (inTransaction) {
        try {
          this.db.exec('ROLLBACK');
        } catch {
          this.failed = true;
        }
      }
      this.header.wrap_count = startingCount;
      if (error instanceof SecretError) {
        if (error.code === 'integrity_failure') this.failed = true;
        throw error;
      }
      this.failed = true;
      fail('unavailable', 503);
    }
    if (rejection) throw rejection;
    return result;
  }
  private dispatch(operation: Operation, input: OperationInput, token: TokenRow): unknown {
    if (operation === 'status') {
      const result = {
        vaultId: this.vaultId,
        protocolVersion: 1,
        expiresAt: token.expires_at,
        auditSeq: this.receipt().seq,
        storage: {
          databaseBytes: statSync(this.dbPath).size,
          maxLiveBytes: MAX_LIVE,
          maxSnapshotBytes: MAX_SNAPSHOT,
          wrapCount: this.header.wrap_count,
          maxWraps: MAX_WRAPS,
          journalMode: 'delete',
          lockingMode: 'exclusive',
          synchronous: 'extra',
        },
      };
      this.audit(operation, input.context, token.id, undefined);
      return result;
    }
    if (operation === 'tokens/issue') {
      const policy = input.policy!,
        credential = newCredential(),
        now = Date.now();
      const row: TokenRow = {
        id: credential.id,
        digest: credential.hash,
        kind: policy.kind,
        namespace: policy.namespace ?? null,
        owner_user_id: policy.ownerUserId ?? null,
        workspace_id: policy.workspaceId ?? null,
        consumer_id: policy.consumerId ?? null,
        capabilities: JSON.stringify(policy.capabilities),
        expires_at: now + policy.expiresInSeconds * 1000,
        revoked_at: null,
        created_at: now,
        mac: '',
      };
      row.mac = mac(this.keys.record, 'token', tokenFields(row));
      this.insertToken(row);
      this.audit(operation, input.context, token.id, undefined, 'success', {
        targetTokenId: row.id,
      });
      return { token: credential.raw, meta: this.tokenMeta(row) };
    }
    if (operation === 'tokens/list') {
      const rows = this.db
        .query('SELECT * FROM tokens WHERE id>? ORDER BY id LIMIT ?')
        .all((input.after as string) ?? '', input.limit! + 1) as TokenRow[];
      for (const row of rows) this.verifyToken(row);
      this.audit(operation, input.context, token.id, undefined);
      return {
        items: rows.slice(0, input.limit).map((row) => this.tokenMeta(row)),
        ...(rows.length > input.limit! ? { next: rows[input.limit! - 1]!.id } : {}),
      };
    }
    if (operation === 'tokens/revoke') {
      const row = this.db
        .query('SELECT * FROM tokens WHERE id=?')
        .get(input.id!) as TokenRow | null;
      if (!row) fail('not_found', 404);
      this.verifyToken(row);
      if (row.kind === 'operator') fail('forbidden', 403);
      row.revoked_at = Date.now();
      row.mac = mac(this.keys.record, 'token', tokenFields(row));
      this.db
        .query('UPDATE tokens SET revoked_at=?,mac=? WHERE id=?')
        .run(row.revoked_at, row.mac, row.id);
      this.audit(operation, input.context, token.id, undefined, 'success', {
        targetTokenId: row.id,
      });
      return this.tokenMeta(row);
    }
    if (operation === 'audit/read') return this.auditRead(input, token);
    const scope = input.scope!;
    if (operation === 'secrets/list') {
      const rows = this.db
        .query(
          'SELECT * FROM secrets WHERE namespace=? AND owner_user_id=? AND workspace_id=? AND consumer_id=? AND id>? ORDER BY id LIMIT ?',
        )
        .all(...scopeArgs(scope), (input.after as string) ?? '', input.limit! + 1) as SecretRow[];
      for (const row of rows) {
        this.verifySecret(row);
        if (scopeArgs(scopeOf(row)).some((value, index) => value !== scopeArgs(scope)[index]))
          fail('integrity_failure', 503);
      }
      this.audit(operation, input.context, token.id, scope);
      return {
        items: rows.slice(0, input.limit).map(metadata),
        ...(rows.length > input.limit! ? { next: rows[input.limit! - 1]!.id } : {}),
      };
    }
    const selector = input.selector;
    const row = (
      selector && 'ref' in selector
        ? this.db
            .query(
              'SELECT * FROM secrets WHERE namespace=? AND owner_user_id=? AND workspace_id=? AND consumer_id=? AND id=?',
            )
            .get(...scopeArgs(scope), selector.ref.id)
        : this.db
            .query(
              'SELECT * FROM secrets WHERE namespace=? AND owner_user_id=? AND workspace_id=? AND consumer_id=? AND name=?',
            )
            .get(...scopeArgs(scope), selector && 'name' in selector ? selector.name : input.name!)
    ) as SecretRow | null;
    if (row) {
      this.verifySecret(row);
      if (
        scopeArgs(scopeOf(row)).some((value, index) => value !== scopeArgs(scope)[index]) ||
        (selector && 'ref' in selector
          ? row.id !== selector.ref.id
          : row.name !== (selector && 'name' in selector ? selector.name : input.name))
      )
        fail('integrity_failure', 503);
    }
    if (operation === 'secrets/inspect') {
      this.audit(operation, input.context, token.id, scope, 'success', undefined, row ?? undefined);
      return row ? metadata(row) : null;
    }
    if (operation === 'secrets/resolve') {
      if (
        !row ||
        row.state !== 'available' ||
        (selector && 'ref' in selector && selector.ref.revision !== row.revision)
      )
        fail('not_found', 404);
      const value = this.plaintext(row);
      this.audit(operation, input.context, token.id, scope, 'success', undefined, row);
      return { value, meta: metadata(row) };
    }
    if ((row?.revision ?? 0) !== input.expectedRevision) fail('revision_conflict', 409);
    if (operation === 'secrets/delete' && !row) fail('not_found', 404);
    const changed: SecretRow = {
      id: row?.id ?? randomId(),
      namespace: scope.namespace,
      owner_user_id: scope.ownerUserId,
      workspace_id: scope.workspaceId,
      consumer_id: scope.consumerId,
      name: input.name!,
      revision: integer((row?.revision ?? 0) + 1, 1),
      state: operation === 'secrets/delete' ? 'deleted' : 'available',
      updated_at: Date.now(),
      envelope: null,
      mac: '',
    };
    if (changed.state === 'available') changed.envelope = this.encrypt(changed, input.value!);
    changed.mac = mac(this.keys.record, 'secret', secretFields(changed));
    if (row)
      this.db
        .query('UPDATE secrets SET revision=?,state=?,updated_at=?,envelope=?,mac=? WHERE id=?')
        .run(
          changed.revision,
          changed.state,
          changed.updated_at,
          changed.envelope,
          changed.mac,
          changed.id,
        );
    else this.insertSecret(changed);
    this.persistHeader();
    this.audit(
      operation,
      input.context,
      token.id,
      scope,
      'success',
      {
        recordMac: changed.mac,
        ...(changed.state === 'available' ? { wrapCount: this.header.wrap_count } : {}),
      },
      changed,
    );
    return metadata(changed);
  }
  private tokenMeta(row: TokenRow) {
    return {
      id: row.id,
      kind: row.kind,
      namespace: row.namespace,
      ownerUserId: row.owner_user_id,
      workspaceId: row.workspace_id,
      consumerId: row.consumer_id,
      capabilities: parsed(row.capabilities),
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
    };
  }
  private cursorMatches(cursor: Cursor): boolean {
    const row = this.db.query('SELECT mac FROM audit WHERE seq=?').get(cursor.seq) as {
      mac: string;
    } | null;
    return Boolean(row && equal(row.mac, cursor.mac));
  }
  private auditRead(input: OperationInput, token: TokenRow): unknown {
    const now = Date.now(),
      poll = this.polling.get(token.id)!;
    if (!input.through && poll.captured && now - poll.captured < 30000) fail('busy', 429);
    const through = input.through ?? this.receipt(),
      after = input.after as Cursor | null;
    if (
      !this.cursorMatches(through) ||
      (after && (!this.cursorMatches(after) || after.seq > through.seq))
    )
      fail('audit_checkpoint_mismatch', 409);
    const rows = this.db
      .query('SELECT * FROM audit WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?')
      .all(after?.seq ?? 0, through.seq, input.limit!) as AuditRow[];
    let previousMac = after?.mac ?? ZERO_MAC,
      expectedSeq = (after?.seq ?? 0) + 1;
    for (const row of rows) {
      if (
        row.seq !== expectedSeq++ ||
        row.previous_mac !== previousMac ||
        !equal(row.mac, mac(this.keys.audit, 'event', [row.seq, row.previous_mac, row.payload]))
      )
        fail('integrity_failure', 503);
      parseAuditEvent(parsed(row.payload));
      previousMac = row.mac;
    }
    const events: AuditEvent[] = rows.map((row) => ({
      seq: row.seq,
      previousMac: row.previous_mac,
      event: parsed(row.payload),
      mac: row.mac,
    }));
    const last = rows.at(-1),
      cursor = last ? { seq: last.seq, mac: last.mac } : after;
    const result = { events, cursor, through: { seq: through.seq, mac: through.mac } };
    if (Buffer.byteLength(JSON.stringify(result)) > 256 * 1024) fail('integrity_failure', 503);
    this.audit('audit_read', input.context, token.id, undefined, 'success', {
      after: after?.seq ?? 0,
      through: through.seq,
      returned: rows.length,
    });
    if (!input.through) poll.captured = now;
    return result;
  }
  snapshot(path: string): void {
    this.verify();
    copyFileSync(this.dbPath, path, constants.COPYFILE_EXCL);
    syncFile(path);
    syncDirectory(dirname(path));
  }
  logicalBytes(): number {
    const pages = Object.values(this.db.query('PRAGMA page_count').get() as object)[0] as number;
    const size = Object.values(this.db.query('PRAGMA page_size').get() as object)[0] as number;
    return pages * size;
  }
  backupKey(salt: Buffer): Buffer {
    return derive(this.master, this.vaultId, 'backup', salt);
  }
  isFailed() {
    return this.failed;
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.db.close();
    } finally {
      this.master.fill(0);
      for (const key of Object.values(this.keys)) key.fill(0);
    }
  }
}
