import { equal, mac } from './crypto.js';
import { parsed, type AuditRow } from './records.js';
import { fail, integer, parseAuditEvent, type AuditPayload } from './protocol.js';

export const ZERO_MAC = '0'.repeat(64);

export function verifyHistory(
  rows: Iterable<AuditRow>,
  auditKey: Buffer,
  expectedWrapCount: number,
) {
  // Row MACs alone cannot detect removal or replay of an older, valid row.
  // Reconcile the current inventory with the authenticated mutation history.
  // Negative revisions represent tombstones; token values represent revocation.
  const secrets = new Map<string, { revision: number; mac: string }>(),
    tokens = new Map<string, boolean>();
  let wrapCount: number | undefined;
  let previous = ZERO_MAC,
    seq = 0;
  for (const row of rows) {
    if (
      row.seq !== seq + 1 ||
      row.previous_mac !== previous ||
      Buffer.byteLength(row.payload) > 4096 ||
      !equal(row.mac, mac(auditKey, 'event', [row.seq, row.previous_mac, row.payload]))
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
  if (!seq || wrapCount !== expectedWrapCount) fail('integrity_failure', 503);
  return { secrets, tokens, seq, mac: previous };
}
