import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { fail, type Box, type Scope } from './protocol.js';

export function randomId() {
  return randomBytes(16).toString('hex');
}
export function hkdf(key: Buffer, salt: Buffer, info: Buffer, length = 32): Buffer {
  return Buffer.from(hkdfSync('sha256', key, salt, info, length));
}
export function derive(master: Buffer, vaultId: string, purpose: string, salt?: Buffer): Buffer {
  return hkdf(
    master,
    salt ?? Buffer.from(vaultId),
    Buffer.from(`or3-secrets:v1:${purpose}:${vaultId}`),
  );
}
export function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
export function mac(key: Buffer, domain: string, fields: unknown): string {
  return createHmac('sha256', key)
    .update(JSON.stringify(['or3-secrets', 1, domain, fields]))
    .digest('hex');
}
export function equal(a: string, b: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
function bytes(value: string, length?: number): Buffer {
  if (
    typeof value !== 'string' ||
    value.length > 65536 ||
    !/^(?:[a-f0-9]{2})*$/.test(value) ||
    (length !== undefined && value.length !== length * 2)
  )
    fail('integrity_failure', 503);
  return Buffer.from(value, 'hex');
}
export function seal(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Box {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    nonce: nonce.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
  };
}
export function unseal(key: Buffer, box: Box, aad: Buffer): Buffer {
  let pending: Buffer | undefined;
  try {
    if (!box || Object.keys(box).sort().join(',') !== 'ciphertext,nonce,tag')
      fail('integrity_failure', 503);
    const decipher = createDecipheriv('aes-256-gcm', key, bytes(box.nonce, 12), {
      authTagLength: 16,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(bytes(box.tag, 16));
    pending = decipher.update(bytes(box.ciphertext));
    const final = decipher.final();
    return Buffer.concat([pending, final]);
  } catch {
    return fail('integrity_failure', 503);
  } finally {
    pending?.fill(0);
  }
}
export type Envelope = { value: Box; wrappedKey: Box };
function aad(
  vaultId: string,
  id: string,
  scope: Scope,
  name: string,
  revision: number,
  purpose: string,
): Buffer {
  return Buffer.from(
    JSON.stringify([
      'or3-secrets',
      1,
      purpose,
      vaultId,
      id,
      scope.namespace,
      scope.ownerUserId,
      scope.workspaceId,
      scope.consumerId,
      name,
      revision,
    ]),
  );
}
export function encryptValue(
  wrappingKey: Buffer,
  vaultId: string,
  id: string,
  scope: Scope,
  name: string,
  revision: number,
  plaintext: string,
): Envelope {
  const dataKey = randomBytes(32),
    value = Buffer.from(plaintext);
  try {
    return {
      value: seal(
        dataKey,
        randomBytes(12),
        value,
        aad(vaultId, id, scope, name, revision, 'value'),
      ),
      wrappedKey: seal(
        wrappingKey,
        randomBytes(12),
        dataKey,
        aad(vaultId, id, scope, name, revision, 'wrapped-key'),
      ),
    };
  } finally {
    dataKey.fill(0);
    value.fill(0);
  }
}
export function decryptValue(
  wrappingKey: Buffer,
  vaultId: string,
  id: string,
  scope: Scope,
  name: string,
  revision: number,
  envelope: Envelope,
): string {
  let dataKey: Buffer | undefined, plaintext: Buffer | undefined;
  try {
    if (!envelope || Object.keys(envelope).sort().join(',') !== 'value,wrappedKey')
      fail('integrity_failure', 503);
    dataKey = unseal(
      wrappingKey,
      envelope.wrappedKey,
      aad(vaultId, id, scope, name, revision, 'wrapped-key'),
    );
    if (dataKey.length !== 32) fail('integrity_failure', 503);
    plaintext = unseal(dataKey, envelope.value, aad(vaultId, id, scope, name, revision, 'value'));
    const value = plaintext.toString('utf8');
    if (!Buffer.from(value).equals(plaintext)) fail('integrity_failure', 503);
    return value;
  } finally {
    dataKey?.fill(0);
    plaintext?.fill(0);
  }
}
export function newCredential(): { id: string; raw: string; hash: string } {
  const id = randomId(),
    raw = `ors1.${id}.${randomBytes(32).toString('base64url')}`;
  return { id, raw, hash: digest(raw) };
}
export function credentialId(raw: string): string | null {
  return /^ors1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/.test(raw) ? raw.split('.')[1]! : null;
}
