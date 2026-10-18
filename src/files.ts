import {
  constants,
  lstatSync,
  fstatSync,
  openSync,
  readFileSync,
  writeSync,
  fsyncSync,
  closeSync,
  mkdirSync,
  existsSync,
  statfsSync,
} from 'node:fs';
import { dirname, resolve, relative, isAbsolute, sep } from 'node:path';
import { fail, CREDENTIAL_PATTERN } from './protocol.js';

const uid = () => process.getuid?.() ?? fail('unsupported_platform');
export function safeParents(path: string, owner = uid()): void {
  let dir = resolve(path);
  // Inspect the same path the kernel will traverse. Lexically collapsing '..'
  // before checking symlinks can validate a different directory from the one opened.
  if (path !== dir) fail('unsafe_path');
  while (true) {
    const st = lstatSync(dir);
    if (!st.isDirectory() || st.isSymbolicLink() || (st.uid !== 0 && st.uid !== owner))
      fail('unsafe_path');
    // Sticky root-owned temporary roots are supported; private leaves remain mandatory.
    const stickyRoot = st.uid === 0 && (st.mode & 0o1000) !== 0;
    if ((st.mode & 0o022) !== 0 && !stickyRoot) fail('unsafe_path');
    const parent = dirname(dir);
    if (dir === parent) break;
    dir = parent;
  }
}
export function privateDirectory(path: string): void {
  safeParents(path);
  const st = lstatSync(path);
  if (st.uid !== uid() || (st.mode & 0o777) !== 0o700) fail('unsafe_path');
}
export function newPrivateDirectory(path: string): void {
  safeParents(dirname(path));
  if (existsSync(path)) fail('already_exists', 409);
  mkdirSync(path, { mode: 0o700 });
  privateDirectory(path);
  syncDirectory(dirname(path));
}
export function syncDirectory(path: string): void {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
export function openPrivate(path: string, write = false): number {
  privateDirectory(dirname(path));
  const fd = openSync(
    path,
    (write ? constants.O_RDWR : constants.O_RDONLY) | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.uid !== uid() || (st.mode & 0o777) !== 0o600 || st.nlink !== 1)
      fail('unsafe_path');
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}
export function readPrivate(path: string, max: number): Buffer {
  const fd = openPrivate(path);
  try {
    if (fstatSync(fd).size > max) fail('unsafe_file');
    const data = readFileSync(fd);
    if (data.length > max) fail('unsafe_file');
    return data;
  } finally {
    closeSync(fd);
  }
}
export function createPrivate(path: string): number {
  privateDirectory(dirname(path));
  return openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
}
/** Complete a synchronous write before the caller syncs or closes its private file. */
export function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
}
export function writePrivate(path: string, data: string | Buffer): void {
  const fd = createPrivate(path);
  try {
    const buffer = typeof data === 'string' ? Buffer.from(data) : data;
    writeAll(fd, buffer);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  syncDirectory(dirname(path));
}
export function syncFile(path: string): void {
  const fd = openPrivate(path);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
export function outsideVault(vault: string, ...paths: string[]): void {
  const names = paths.map((path) => resolve(path));
  if (new Set(names).size !== names.length) fail('unsafe_path');
  for (const path of names) {
    const rel = relative(resolve(vault), path);
    if (!rel || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel)))
      fail('unsafe_path');
  }
}
export function absent(path: string): void {
  try {
    lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  fail('already_exists', 409);
}
export function headroom(path: string, bytes: number): void {
  const stat = statfsSync(path, { bigint: true });
  if (stat.bavail * stat.bsize < BigInt(Math.ceil(bytes)) + 64n * 1024n * 1024n)
    fail('insufficient_space', 503);
}
export function readCredential(path: string): string {
  const bytes = readPrivate(path, 256);
  try {
    const text = bytes.toString('utf8').replace(/\n$/, '');
    if (!CREDENTIAL_PATTERN.test(text)) fail('invalid_credential', 401);
    return text;
  } finally {
    bytes.fill(0);
  }
}
export function validateSocket(path: string, owner = uid()): void {
  const dir = lstatSync(dirname(path)),
    sock = lstatSync(path);
  if (dir.uid !== owner || sock.uid !== owner) fail('unsafe_socket');
  safeParents(dirname(path), owner);
  if (!sock.isSocket() || (sock.mode & 0o007) !== 0 || (dir.mode & 0o027) !== 0)
    fail('unsafe_socket');
}
