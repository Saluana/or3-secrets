import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, mkdtempSync, readSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { derive } from './crypto.js';
import {
  absent,
  writeAll,
  createPrivate,
  headroom,
  openPrivate,
  outsideVault,
  privateDirectory,
  readPrivate,
  syncDirectory,
} from './files.js';
import { fail, ID_PATTERN, MAX_SNAPSHOT, type Receipt } from './protocol.js';
import { Vault } from './store.js';

export const BACKUP_HEADER = 96;
export const BACKUP_OVERHEAD = BACKUP_HEADER + 16;
const MAGIC = Buffer.from('OR3BAK01');
function readExact(fd: number, length: number): Buffer {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const read = readSync(fd, bytes, offset, length - offset, null);
    if (!read) fail('invalid_backup');
    offset += read;
  }
  return bytes;
}
function eof(fd: number): void {
  if (readSync(fd, Buffer.alloc(1), 0, 1, null)) fail('invalid_backup', 400);
}
function transform(
  fd: number,
  output: number,
  length: number,
  cipher: ReturnType<typeof createCipheriv> | ReturnType<typeof createDecipheriv>,
): void {
  let remaining = length;
  const chunk = Buffer.alloc(64 * 1024);
  try {
    while (remaining > 0) {
      const read = readSync(fd, chunk, 0, Math.min(chunk.length, remaining), null);
      if (!read) fail('invalid_backup');
      writeAll(output, cipher.update(chunk.subarray(0, read)));
      remaining -= read;
    }
  } finally {
    chunk.fill(0);
  }
}
function headerFor(vaultId: string, length: number): Buffer {
  const header = Buffer.alloc(BACKUP_HEADER);
  MAGIC.copy(header);
  header.write(vaultId, 8, 32, 'ascii');
  randomBytes(32).copy(header, 40);
  randomBytes(12).copy(header, 72);
  header.writeBigUInt64BE(BigInt(length), 84);
  return header;
}
function inspectHeader(header: Buffer, fileSize: number): { vaultId: string; length: number } {
  if (!header.subarray(0, 8).equals(MAGIC) || !header.subarray(92).equals(Buffer.alloc(4)))
    fail('invalid_backup');
  const vaultId = header.subarray(8, 40).toString('ascii'),
    length = header.readBigUInt64BE(84);
  if (
    !ID_PATTERN.test(vaultId) ||
    length < 1n ||
    length > BigInt(MAX_SNAPSHOT) ||
    BigInt(fileSize) !== length + BigInt(BACKUP_OVERHEAD)
  )
    fail('invalid_backup');
  return { vaultId, length: Number(length) };
}
export function backup(options: {
  vaultDir: string;
  keyFile: string;
  outFile: string;
  receipt?: Receipt;
}): Receipt {
  outsideVault(options.vaultDir, options.outFile);
  privateDirectory(dirname(options.outFile));
  absent(options.outFile);
  const vault = Vault.open(options.vaultDir, options.keyFile);
  let staging: string | undefined,
    output: number | undefined,
    source: number | undefined,
    key: Buffer | undefined;
  try {
    if (options.receipt) vault.checkReceipt(options.receipt);
    const size = fstatSize(vault.dbPath);
    if (size > MAX_SNAPSHOT) fail('too_large', 413);
    // Reserve the private snapshot before allocating it on live custody storage.
    headroom(vault.vaultDir, size);
    // Raw metadata stays on live custody storage, including after interruption.
    staging = mkdtempSync(join(vault.vaultDir, '.or3-backup-'));
    const snapshot = join(staging, 'snapshot.sqlite');
    vault.snapshot(snapshot);
    source = openPrivate(snapshot);
    const length = fstatSync(source).size;
    if (!length || length > MAX_SNAPSHOT) fail('too_large', 413);
    // Staging already consumes space, including when output shares its filesystem.
    headroom(dirname(options.outFile), length + BACKUP_OVERHEAD);
    const header = headerFor(vault.vaultId, length);
    key = vault.backupKey(header.subarray(40, 72));
    const cipher = createCipheriv('aes-256-gcm', key, header.subarray(72, 84), {
      authTagLength: 16,
    });
    cipher.setAAD(header);
    output = createPrivate(options.outFile);
    writeAll(output, header);
    transform(source, output, length, cipher);
    eof(source);
    writeAll(output, cipher.final());
    writeAll(output, cipher.getAuthTag());
    fsyncSync(output);
    syncDirectory(dirname(options.outFile));
    return vault.receipt();
  } finally {
    if (source !== undefined) closeSync(source);
    if (output !== undefined) closeSync(output);
    key?.fill(0);
    vault.close();
    if (staging) rmSync(staging, { recursive: true, force: true });
  }
}
function fstatSize(path: string): number {
  const fd = openPrivate(path);
  try {
    return fstatSync(fd).size;
  } finally {
    closeSync(fd);
  }
}
export function restore(options: {
  backupFile: string;
  keyFile: string;
  destination: string;
  newKeyFile: string;
  operatorFile: string;
  receipt?: Receipt;
}): Receipt {
  privateDirectory(dirname(options.destination));
  absent(options.destination);
  absent(options.newKeyFile);
  absent(options.operatorFile);
  const master = readPrivate(options.keyFile, 32);
  let input: number | undefined;
  let staging: string | undefined,
    output: number | undefined,
    key: Buffer | undefined,
    old: Vault | undefined;
  try {
    if (master.length !== 32) fail('invalid_key');
    input = openPrivate(options.backupFile);
    const size = fstatSync(input).size;
    if (size < BACKUP_OVERHEAD + 1 || size > MAX_SNAPSHOT + BACKUP_OVERHEAD) fail('invalid_backup');
    const header = readExact(input, BACKUP_HEADER),
      { vaultId, length } = inspectHeader(header, size);
    // Reserve the input, decrypted staging, fresh-key copy and SQLite construction space.
    headroom(dirname(options.destination), length * 4);
    key = derive(master, vaultId, 'backup', header.subarray(40, 72));
    const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(72, 84), {
      authTagLength: 16,
    });
    decipher.setAAD(header);
    staging = mkdtempSync(join(dirname(options.destination), '.or3-restore-'));
    output = createPrivate(join(staging, 'vault.sqlite'));
    transform(input, output, length, decipher);
    decipher.setAuthTag(readExact(input, 16));
    eof(input);
    try {
      writeAll(output, decipher.final());
    } catch {
      fail('invalid_backup');
    }
    fsyncSync(output);
    closeSync(output);
    output = undefined;
    syncDirectory(staging);
    // No SQLite connection, schema read, or writable destination exists until complete AEAD/EOF verification.
    old = Vault.openSnapshot(staging, options.keyFile);
    if (old.vaultId !== vaultId) fail('invalid_backup');
    if (options.receipt) old.checkReceipt(options.receipt);
    return Vault.create(
      {
        vaultDir: options.destination,
        keyFile: options.newKeyFile,
        operatorFile: options.operatorFile,
      },
      old,
      'restore',
    );
  } finally {
    if (output !== undefined) closeSync(output);
    if (input !== undefined) closeSync(input);
    master.fill(0);
    key?.fill(0);
    old?.close();
    if (staging) rmSync(staging, { recursive: true, force: true });
  }
}
export function rekey(options: {
  vaultDir: string;
  keyFile: string;
  destination: string;
  newKeyFile: string;
  operatorFile: string;
  receipt?: Receipt;
}): Receipt {
  outsideVault(options.vaultDir, options.destination, options.newKeyFile, options.operatorFile);
  const source = Vault.open(options.vaultDir, options.keyFile);
  try {
    if (options.receipt) source.checkReceipt(options.receipt);
    const size = source.logicalBytes();
    // Reserve staging, fresh-key copy and SQLite construction space; source stays intact.
    headroom(dirname(options.destination), size * 3);
    return Vault.create(
      {
        vaultDir: options.destination,
        keyFile: options.newKeyFile,
        operatorFile: options.operatorFile,
      },
      source,
      'rekey',
    );
  } finally {
    source.close();
  }
}
