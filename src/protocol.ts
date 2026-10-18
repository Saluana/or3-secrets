export const PROTOCOL_VERSION = 1;
export const ID_PATTERN = /^[a-f0-9]{32}$/;
export const MAC_PATTERN = /^[a-f0-9]{64}$/;
export const CREDENTIAL_PATTERN = /^ors1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/;
export const SERVICE_CAPABILITIES = ['metadata', 'read', 'write', 'delete'] as const;
export const MAX_PAGE_SIZE = 100;
export const MAX_TOKEN_LIFETIME_SECONDS = 90 * 86400;
export const MAX_BODY = 256 * 1024;
export const MAX_VALUE = 32 * 1024;
export const MAX_SNAPSHOT = 2 ** 30;
// Preserve 64 MiB below the backup ceiling for recovery construction and audit.
export const MAX_LIVE = MAX_SNAPSHOT - 64 * 1024 ** 2;
export const MAX_WRAPS = 1_000_000;
export const MAX_REVISION = Number.MAX_SAFE_INTEGER - 1;
export type Scope = Readonly<{
  namespace: string;
  ownerUserId: string;
  workspaceId: string;
  consumerId: string;
}>;
export type Context = Readonly<{ requestId: string; actorId?: string; activationId?: string }>;
export type SecretRef = Readonly<{ id: string; revision: number }>;
export type SecretMeta = Readonly<{
  ref: SecretRef;
  name: string;
  state: 'available' | 'deleted';
  updatedAt: string;
}>;
export type Capability = 'metadata' | 'read' | 'write' | 'delete';
export type Cursor = Readonly<{ seq: number; mac: string }>;
export type Receipt = Cursor & Readonly<{ vaultId: string }>;
export type Box = Readonly<{ nonce: string; ciphertext: string; tag: string }>;
export type TokenPolicy = {
  kind: 'service' | 'audit-reader';
  capabilities: (Capability | 'audit')[];
  namespace?: string;
  ownerUserId?: string;
  workspaceId?: string;
  consumerId?: string;
  expiresInSeconds: number;
};
export type TokenMeta = Readonly<{
  id: string;
  kind: 'operator' | 'service' | 'audit-reader';
  namespace: string | null;
  ownerUserId: string | null;
  workspaceId: string | null;
  consumerId: string | null;
  capabilities: (Capability | 'audit')[];
  expiresAt: number | null;
  revokedAt: number | null;
  createdAt: number;
}>;
export type Page<T> = { items: T[]; next?: string };
export type StatusResult = {
  vaultId: string;
  protocolVersion: typeof PROTOCOL_VERSION;
  expiresAt: number | null;
  auditSeq: number;
  storage: {
    databaseBytes: number;
    maxLiveBytes: number;
    maxSnapshotBytes: number;
    journalMode: 'delete';
    lockingMode: 'exclusive';
    synchronous: 'extra';
    wrapCount: number;
    maxWraps: number;
  };
};
export type AuditPayload = {
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
export type AuditEvent = { seq: number; previousMac: string; event: AuditPayload; mac: string };
export type AuditPage = { events: AuditEvent[]; cursor: Cursor | null; through: Cursor };
export type OperationResults = {
  status: StatusResult;
  'secrets/inspect': SecretMeta | null;
  'secrets/list': Page<SecretMeta>;
  'secrets/put': SecretMeta;
  'secrets/resolve': { value: string; meta: SecretMeta };
  'secrets/delete': SecretMeta;
  'tokens/issue': { token: string; meta: TokenMeta };
  'tokens/list': Page<TokenMeta>;
  'tokens/revoke': TokenMeta;
  'audit/read': AuditPage;
};
export interface SecretStore {
  inspect(
    input: { scope: Scope; name: string },
    context?: Partial<Context>,
  ): Promise<SecretMeta | null>;
  list(
    input: { scope: Scope; after?: string; limit?: number },
    context?: Partial<Context>,
  ): Promise<{ items: SecretMeta[]; next?: string }>;
  put(
    input: { scope: Scope; name: string; value: string; expectedRevision: number },
    context?: Partial<Context>,
  ): Promise<SecretMeta>;
  resolve(
    input: { scope: Scope; selector: { name: string } | { ref: SecretRef } },
    context?: Partial<Context>,
  ): Promise<{ value: string; meta: SecretMeta }>;
  delete(
    input: { scope: Scope; name: string; expectedRevision: number },
    context?: Partial<Context>,
  ): Promise<SecretMeta>;
}
export class SecretError extends Error {
  constructor(
    public readonly code: string,
    public readonly status = 400,
  ) {
    super(code);
    this.name = 'SecretError';
  }
}
export function fail(code: string, status = 400): never {
  throw new SecretError(code, status);
}
export function object(
  value: unknown,
  keys: readonly string[],
  required: readonly string[] = keys,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_request');
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).some((key) => !keys.includes(key)) ||
    required.some((key) => record[key] === undefined)
  )
    fail('invalid_request');
  return record;
}
export function identifier(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value ||
    Buffer.byteLength(value) > 128 ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value) ||
    Buffer.from(value).toString('utf8') !== value
  )
    fail('invalid_request');
  return value;
}
export function integer(value: unknown, min = 0, max = MAX_REVISION): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max)
    fail('invalid_request');
  return value;
}
export function parseScope(value: unknown): Scope {
  const r = object(value, ['namespace', 'ownerUserId', 'workspaceId', 'consumerId']);
  return {
    namespace: identifier(r.namespace),
    ownerUserId: identifier(r.ownerUserId),
    workspaceId: identifier(r.workspaceId),
    consumerId: identifier(r.consumerId),
  };
}
export function parseContext(value: unknown): Context {
  const r = object(value, ['requestId', 'actorId', 'activationId'], ['requestId']);
  return {
    requestId: identifier(r.requestId),
    ...(r.actorId === undefined ? {} : { actorId: identifier(r.actorId) }),
    ...(r.activationId === undefined ? {} : { activationId: identifier(r.activationId) }),
  };
}
export function parseCursor(value: unknown): Cursor {
  const r = object(value, ['seq', 'mac']);
  if (typeof r.mac !== 'string' || !MAC_PATTERN.test(r.mac)) fail('invalid_request');
  return { seq: integer(r.seq, 1), mac: r.mac };
}
export interface OperationInput {
  context: Context;
  scope?: Scope;
  name?: string;
  value?: string;
  expectedRevision?: number;
  selector?: { name: string } | { ref: SecretRef };
  limit?: number;
  after?: string | Cursor | null;
  through?: Cursor;
  id?: string;
  policy?: TokenPolicy;
}
export const OPERATIONS = [
  'status',
  'secrets/inspect',
  'secrets/list',
  'secrets/put',
  'secrets/resolve',
  'secrets/delete',
  'tokens/issue',
  'tokens/list',
  'tokens/revoke',
  'audit/read',
] as const;
export type Operation = (typeof OPERATIONS)[number];
const INPUT_FIELDS: Record<Operation, readonly string[]> = {
  status: [],
  'secrets/inspect': ['scope', 'name'],
  'secrets/list': ['scope', 'after', 'limit'],
  'secrets/put': ['scope', 'name', 'value', 'expectedRevision'],
  'secrets/resolve': ['scope', 'selector'],
  'secrets/delete': ['scope', 'name', 'expectedRevision'],
  'tokens/issue': [
    'kind',
    'namespace',
    'ownerUserId',
    'workspaceId',
    'consumerId',
    'capabilities',
    'expiresInSeconds',
  ],
  'tokens/list': ['after', 'limit'],
  'tokens/revoke': ['id'],
  'audit/read': ['after', 'through', 'limit'],
};
function parseSelector(value: unknown): NonNullable<OperationInput['selector']> {
  const selector = object(value, ['name', 'ref'], []);
  if (Object.keys(selector).length !== 1) fail('invalid_request');
  if (selector.name !== undefined) return { name: identifier(selector.name) };
  const ref = object(selector.ref, ['id', 'revision']);
  return { ref: { id: identifier(ref.id), revision: integer(ref.revision, 1) } };
}
function parseTokenPolicy(r: Record<string, unknown>): TokenPolicy {
  if (r.kind !== 'service' && r.kind !== 'audit-reader') fail('invalid_request');
  if (
    !Array.isArray(r.capabilities) ||
    !r.capabilities.length ||
    r.capabilities.length > 4 ||
    new Set(r.capabilities).size !== r.capabilities.length
  )
    fail('invalid_request');
  const allowed = r.kind === 'audit-reader' ? ['audit'] : [...SERVICE_CAPABILITIES];
  if (r.capabilities.some((cap) => !allowed.includes(cap))) fail('invalid_request');
  const policy: TokenPolicy = {
    kind: r.kind,
    capabilities: r.capabilities as TokenPolicy['capabilities'],
    expiresInSeconds: integer(r.expiresInSeconds, 1, MAX_TOKEN_LIFETIME_SECONDS),
  };
  if (r.kind === 'service') {
    policy.namespace = identifier(r.namespace);
    for (const field of ['ownerUserId', 'workspaceId', 'consumerId'] as const)
      if (r[field] !== undefined) policy[field] = identifier(r[field]);
  } else if (
    ['namespace', 'ownerUserId', 'workspaceId', 'consumerId'].some(
      (field) => r[field] !== undefined,
    )
  )
    fail('invalid_request');
  return policy;
}
export function parseInput(operation: Operation, input: unknown): OperationInput {
  const r = object(input, ['context', ...INPUT_FIELDS[operation]], ['context']);
  const out: OperationInput = { context: parseContext(r.context) };
  if (operation.startsWith('secrets/')) out.scope = parseScope(r.scope);
  if (['secrets/inspect', 'secrets/put', 'secrets/delete'].includes(operation))
    out.name = identifier(r.name);
  if (operation === 'secrets/put' || operation === 'secrets/delete')
    out.expectedRevision = integer(r.expectedRevision);
  if (operation === 'secrets/put') {
    if (typeof r.value !== 'string' || Buffer.from(r.value).toString('utf8') !== r.value)
      fail('invalid_request');
    if (Buffer.byteLength(r.value) > MAX_VALUE) fail('too_large', 413);
    out.value = r.value;
  }
  if (operation === 'secrets/resolve') out.selector = parseSelector(r.selector);
  if (operation === 'secrets/list' || operation === 'tokens/list') {
    if (r.after !== undefined) out.after = identifier(r.after);
    out.limit = r.limit === undefined ? 100 : integer(r.limit, 1, 100);
  }
  if (operation === 'tokens/revoke') out.id = identifier(r.id);
  if (operation === 'tokens/issue') out.policy = parseTokenPolicy(r);
  if (operation === 'audit/read') {
    out.after = r.after === null ? null : parseCursor(r.after);
    if (r.through !== undefined) out.through = parseCursor(r.through);
    out.limit = integer(r.limit, 1, 100);
    if (out.after && out.through && out.after.seq > out.through.seq)
      fail('audit_checkpoint_mismatch', 409);
  }
  return out;
}

/** Wire response validation; no remote response is trusted by a TypeScript cast. */
function validateReference(value: unknown): void {
  const r = object(value, ['id', 'revision']);
  identifier(r.id);
  integer(r.revision, 1);
}
function validateMetadata(value: unknown): void {
  const r = object(value, ['ref', 'name', 'state', 'updatedAt']);
  validateReference(r.ref);
  identifier(r.name);
  if (
    !['available', 'deleted'].includes(r.state as string) ||
    typeof r.updatedAt !== 'string' ||
    !Number.isFinite(Date.parse(r.updatedAt))
  )
    fail('invalid_response', 503);
}
function validateTokenMetadata(value: unknown): void {
  const r = object(value, [
    'id',
    'kind',
    'namespace',
    'ownerUserId',
    'workspaceId',
    'consumerId',
    'capabilities',
    'expiresAt',
    'revokedAt',
    'createdAt',
  ]);
  identifier(r.id);
  integer(r.createdAt);
  if (r.expiresAt !== null) integer(r.expiresAt);
  if (r.revokedAt !== null) integer(r.revokedAt);
  if (
    !['service', 'operator', 'audit-reader'].includes(r.kind as string) ||
    !Array.isArray(r.capabilities) ||
    r.capabilities.some((x) => !['metadata', 'read', 'write', 'delete', 'audit'].includes(x))
  )
    fail('invalid_response', 503);
  for (const key of ['namespace', 'ownerUserId', 'workspaceId', 'consumerId'])
    if (r[key] !== null) identifier(r[key]);
}
export function parseResponse<O extends Operation>(
  operation: O,
  value: unknown,
): OperationResults[O] {
  if (operation === 'secrets/inspect') {
    if (value !== null) validateMetadata(value);
  } else if (operation === 'secrets/put' || operation === 'secrets/delete') validateMetadata(value);
  else if (operation === 'secrets/resolve') {
    const r = object(value, ['value', 'meta']);
    validateMetadata(r.meta);
    if (
      typeof r.value !== 'string' ||
      Buffer.byteLength(r.value) > MAX_VALUE ||
      Buffer.from(r.value).toString('utf8') !== r.value
    )
      fail('invalid_response', 503);
  } else if (operation === 'secrets/list' || operation === 'tokens/list') {
    const r = object(value, ['items', 'next'], ['items']);
    if (!Array.isArray(r.items) || r.items.length > 100) fail('invalid_response', 503);
    for (const item of r.items)
      (operation === 'secrets/list' ? validateMetadata : validateTokenMetadata)(item);
    if (r.next !== undefined) identifier(r.next);
  } else if (operation === 'tokens/issue') {
    const r = object(value, ['token', 'meta']);
    validateTokenMetadata(r.meta);
    if (typeof r.token !== 'string' || !CREDENTIAL_PATTERN.test(r.token))
      fail('invalid_response', 503);
  } else if (operation === 'tokens/revoke') validateTokenMetadata(value);
  else if (operation === 'status') {
    const r = object(value, ['vaultId', 'protocolVersion', 'expiresAt', 'auditSeq', 'storage']);
    if (
      typeof r.vaultId !== 'string' ||
      !ID_PATTERN.test(r.vaultId) ||
      r.protocolVersion !== PROTOCOL_VERSION
    )
      fail('invalid_response', 503);
    integer(r.auditSeq, 1);
    if (r.expiresAt !== null) integer(r.expiresAt);
    const storage = object(r.storage, [
      'databaseBytes',
      'maxLiveBytes',
      'maxSnapshotBytes',
      'journalMode',
      'lockingMode',
      'synchronous',
      'wrapCount',
      'maxWraps',
    ]);
    if (storage.maxLiveBytes !== MAX_LIVE) fail('invalid_response', 503);
    if (
      storage.journalMode !== 'delete' ||
      storage.lockingMode !== 'exclusive' ||
      storage.synchronous !== 'extra' ||
      storage.maxWraps !== MAX_WRAPS
    )
      fail('invalid_response', 503);
    integer(storage.wrapCount, 0, MAX_WRAPS);
    integer(storage.databaseBytes);
    if (storage.maxSnapshotBytes !== MAX_SNAPSHOT) fail('invalid_response', 503);
  } else {
    const r = object(value, ['events', 'cursor', 'through']);
    parseCursor(r.through);
    if (r.cursor !== null) parseCursor(r.cursor);
    if (!Array.isArray(r.events) || r.events.length > 100) fail('invalid_response', 503);
    for (const event of r.events) {
      const row = object(event, ['seq', 'previousMac', 'event', 'mac']);
      parseCursor({ seq: row.seq, mac: row.mac });
      if (typeof row.previousMac !== 'string' || !MAC_PATTERN.test(row.previousMac))
        fail('invalid_response', 503);
      parseAuditEvent(row.event);
    }
  }
  return value as OperationResults[O];
}
export function parseAuditEvent(value: unknown): void {
  const r = object(
    value,
    [
      'at',
      'operation',
      'outcome',
      'requestId',
      'tokenId',
      'scopeId',
      'recordId',
      'revision',
      'actorId',
      'activationId',
      'detail',
    ],
    ['at', 'operation', 'outcome', 'requestId'],
  );
  parseContext({
    requestId: r.requestId,
    ...(r.actorId === undefined ? {} : { actorId: r.actorId }),
    ...(r.activationId === undefined ? {} : { activationId: r.activationId }),
  });
  if (
    typeof r.at !== 'string' ||
    !Number.isFinite(Date.parse(r.at)) ||
    typeof r.operation !== 'string' ||
    ![...OPERATIONS, 'init', 'restore', 'rekey', 'audit_read'].includes(r.operation as Operation) ||
    typeof r.outcome !== 'string' ||
    !/^[a-z_]{1,64}$/.test(r.outcome)
  )
    fail('integrity_failure', 503);
  for (const key of ['tokenId', 'scopeId', 'recordId'])
    if (r[key] !== undefined && (typeof r[key] !== 'string' || !/^[a-f0-9]{32,64}$/.test(r[key])))
      fail('integrity_failure', 503);
  if (r.revision !== undefined) integer(r.revision, 1);
  if (r.detail !== undefined) validateAuditDetail(r.detail);
}

function validateAuditDetail(value: unknown): void {
  const detail = object(
    value,
    ['after', 'through', 'returned', 'priorReceipt', 'targetTokenId', 'wrapCount', 'recordMac'],
    [],
  );
  for (const key of ['after', 'through', 'returned'])
    if (detail[key] !== undefined) integer(detail[key]);
  if (
    detail.targetTokenId !== undefined &&
    (typeof detail.targetTokenId !== 'string' || !ID_PATTERN.test(detail.targetTokenId))
  )
    fail('integrity_failure', 503);
  if (detail.wrapCount !== undefined) integer(detail.wrapCount, 0, MAX_WRAPS);
  if (
    detail.recordMac !== undefined &&
    (typeof detail.recordMac !== 'string' || !MAC_PATTERN.test(detail.recordMac))
  )
    fail('integrity_failure', 503);
  if (detail.priorReceipt !== undefined) {
    const receipt = object(detail.priorReceipt, ['vaultId', 'seq', 'mac']);
    identifier(receipt.vaultId);
    parseCursor({ seq: receipt.seq, mac: receipt.mac });
  }
}
