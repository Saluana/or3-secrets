// Real-filesystem regression: shared staging/output must preserve the reserve,
// split filesystems must remain usable, envelope overhead must count, and refusal
// must leave no output/staging or source mutation. No production fault hooks.
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statfsSync,
  statSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { expect } from 'bun:test';
import { Fixture, cli, scope } from './lib/fixture';

const reserve = 64 * 1024 ** 2;
const maxFill = 80 * 1024 ** 2;
if (process.platform !== 'linux' || process.getuid?.() === 0)
  throw new Error('Disposable non-root Linux profile required');
const mounts = readFileSync('/proc/self/mountinfo', 'utf8').split('\n');
for (const path of ['/tmp', '/staging']) {
  const mount = mounts.find((line) => line.split(' ')[4] === path);
  const disk = statfsSync(path, { bigint: true });
  if (
    !mount ||
    mount.split(' - ')[1]?.split(' ')[0] !== 'tmpfs' ||
    disk.type !== 0x01021994n ||
    disk.blocks * disk.bsize !== BigInt(maxFill)
  )
    throw new Error('Dedicated 80 MiB /tmp and /staging tmpfs mounts required');
}
if (statSync('/tmp').dev === statSync('/staging').dev)
  throw new Error('The two tmpfs mounts must be distinct');

function free(path: string): number {
  const disk = statfsSync(path);
  return disk.bavail * disk.bsize;
}
function leaveFree(path: string, bytes: number): void {
  const count = free(path) - bytes;
  if (count < 0 || count > maxFill) throw new Error('Filler exceeds its bounded profile');
  const fd = openSync(join(path, 'fill'), 'wx', 0o600);
  const chunk = Buffer.alloc(64 * 1024);
  try {
    let written = 0;
    while (written < count)
      written += writeSync(fd, chunk, 0, Math.min(chunk.length, count - written));
  } finally {
    closeSync(fd);
  }
  expect(free(path)).toBe(bytes);
}

const f = new Fixture();
const other = mkdtempSync('/staging/ors-backup-space-');
try {
  await f.start();
  const token = await f.token();
  expect(
    (
      await f.call(
        'secrets/put',
        { scope, name: 'capacity', value: 'synthetic-capacity', expectedRevision: 0 },
        token.token,
      )
    ).status,
  ).toBe(200);
  await f.stop();
  const database = join(f.vault, 'vault.sqlite');
  const size = statSync(database).size;
  const block = statfsSync(f.root).bsize;
  const sourceHash = () => createHash('sha256').update(readFileSync(database)).digest('hex');
  const before = sourceHash();
  const run = (out: string) =>
    cli(['backup', '--vault-dir', f.vault, '--key-file', f.key, '--out-file', out]);
  const refused = (out: string) => {
    const result = run(out);
    expect(result.status, result.stderr || result.stdout).toBe(75);
    expect(JSON.parse(result.stderr).error.code).toBe('insufficient_space');
    expect(existsSync(out)).toBe(false);
    expect(readdirSync(f.vault).some((name) => name.startsWith('.or3-backup-'))).toBe(false);
    expect(sourceHash()).toBe(before);
  };

  // Enough for either allocation on its own, but not both plus the reserve.
  leaveFree(f.root, reserve + size + block);
  refused(join(f.root, 'shared.backup'));
  expect(free(f.root)).toBe(reserve + size + block);

  // Each independent filesystem only needs to accommodate its own allocation.
  leaveFree(other, reserve + size + block);
  const split = join(other, 'split.backup');
  expect(run(split).status).toBe(0);
  expect(statSync(split).size).toBe(size + 112);
  expect(free(other)).toBeGreaterThanOrEqual(reserve);
  rmSync(split);
  rmSync(join(other, 'fill'));

  // Exactly one snapshot of free space still lacks the 112-byte envelope.
  leaveFree(other, reserve + size);
  refused(join(other, 'overhead.backup'));
  rmSync(join(other, 'fill'));
  rmSync(join(f.root, 'fill'));

  // Freeing space permits a same-filesystem retry and a verified fresh-key restore.
  const retry = join(f.root, 'retry.backup');
  expect(run(retry).status).toBe(0);
  const restored = join(other, 'restored');
  const key = join(other, 'restored.key');
  expect(
    cli([
      'restore',
      '--backup-file',
      retry,
      '--key-file',
      f.key,
      '--destination',
      restored,
      '--new-key-file',
      key,
      '--operator-file',
      join(other, 'restored.token'),
    ]).status,
  ).toBe(0);
  expect(cli(['audit', 'verify', '--vault-dir', restored, '--key-file', key]).status).toBe(0);
  expect(sourceHash()).toBe(before);
  writeFileSync(
    '/receipts/backup-space.json',
    JSON.stringify(
      {
        runtime: Bun.version,
        snapshotBytes: size,
        sourceSha256: before,
        sharedFilesystemRefused: true,
        separateFilesystemsSucceeded: true,
        envelopeOverheadRefused: true,
        retryAndRestoreVerified: true,
        sourceUnchanged: true,
      },
      null,
      2,
    ),
  );
} finally {
  await f.close();
  rmSync(other, { recursive: true, force: true });
}
