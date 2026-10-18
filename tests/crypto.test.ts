import { expect, test } from 'bun:test';
import { hkdf, seal, unseal } from '../src/crypto';

// NIST AES-256-GCM empty plaintext and RFC 5869 SHA-256 test case 1.
// Independent published vectors detect a broken primitive/encoding, not merely a roundtrip.
test('AES-256-GCM agrees with the independent NIST vector and rejects authentication changes', () => {
  const key = Buffer.alloc(32), nonce = Buffer.alloc(12);
  const box = seal(key, nonce, Buffer.alloc(0), Buffer.alloc(0));
  expect(box.tag).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  expect(box.ciphertext).toBe('');
  expect(unseal(key, box, Buffer.alloc(0)).length).toBe(0);
  for (const bad of [Buffer.from('other scope'), Buffer.from('other revision')]) {
    expect(() => unseal(key, box, bad)).toThrow();
  }
  expect(() => unseal(Buffer.alloc(32, 1), box, Buffer.alloc(0))).toThrow();
  expect(() => unseal(key, { ...box, tag: '00'.repeat(16) }, Buffer.alloc(0))).toThrow();
});

test('HKDF-SHA256 agrees with RFC 5869 test case 1', () => {
  const actual = hkdf(Buffer.alloc(22, 0x0b), Buffer.from('000102030405060708090a0b0c', 'hex'), Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42);
  expect(actual.toString('hex')).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});
