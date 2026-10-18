import type { Database } from 'bun:sqlite';
import { fail } from './protocol.js';

export const SCHEMA = [
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

export function configure(db: Database): void {
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
export function schemaCheck(db: Database): void {
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
