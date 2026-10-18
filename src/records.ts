import { equal, mac } from './crypto.js';
import { fail, identifier, integer, parseScope, type Scope, type SecretMeta } from './protocol.js';

export type Header = {
  id: number;
  vault_id: string;
  format: number;
  wrap_count: number;
  verification: string;
  created_at: number;
  mac: string;
};
export type SecretRow = {
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
export type TokenRow = {
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
export type AuditRow = { seq: number; previous_mac: string; payload: string; mac: string };
export function scopeOf(row: SecretRow): Scope {
  return {
    namespace: row.namespace,
    ownerUserId: row.owner_user_id,
    workspaceId: row.workspace_id,
    consumerId: row.consumer_id,
  };
}
export function scopeArgs(scope: Scope): string[] {
  return [scope.namespace, scope.ownerUserId, scope.workspaceId, scope.consumerId];
}
export function headerFields(h: Header) {
  return [h.id, h.vault_id, h.format, h.wrap_count, h.verification, h.created_at];
}
export function secretFields(r: SecretRow) {
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
export function tokenFields(r: TokenRow) {
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
export function metadata(r: SecretRow): SecretMeta {
  return {
    ref: { id: r.id, revision: r.revision },
    name: r.name,
    state: r.state,
    updatedAt: new Date(r.updated_at).toISOString(),
  };
}
export function parsed<T>(text: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    fail('integrity_failure', 503);
  }
}
export function verifySecret(row: SecretRow, recordKey: Buffer): void {
  if (!equal(row.mac, mac(recordKey, 'secret', secretFields(row)))) fail('integrity_failure', 503);
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
export function verifyToken(row: TokenRow, recordKey: Buffer): void {
  if (
    !equal(row.mac, mac(recordKey, 'token', tokenFields(row))) ||
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
      [row.namespace, row.owner_user_id, row.workspace_id, row.consumer_id].some((x) => x !== null)
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
