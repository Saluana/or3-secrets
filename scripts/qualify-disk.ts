// Real ENOSPC, no production fault-injection hooks. Run only inside the disposable
// 8 MiB /tmp tmpfs described in docs/qualification.md, as the unprivileged bun user.
import {
  openSync,
  closeSync,
  writeSync,
  rmSync,
  writeFileSync,
  readFileSync,
  statfsSync,
} from 'node:fs';
import { join } from 'node:path';
import { Fixture, scope, removeCrashSocket } from '../tests/helpers';
import { expect } from 'bun:test';
if (process.platform !== 'linux' || process.getuid?.() === 0)
  throw new Error('Disposable non-root Linux profile required');
// Refuse before creating a fixture unless /tmp is its own bounded tmpfs mount.
// The write cap remains independent of mount discovery and ENOSPC behavior.
const mount = readFileSync('/proc/self/mountinfo', 'utf8')
  .split('\n')
  .find((line) => line.split(' ')[4] === '/tmp');
const disk = statfsSync('/tmp', { bigint: true });
const maxFill = 8 * 1024 ** 2;
if (
  !mount ||
  mount.split(' - ')[1]?.split(' ')[0] !== 'tmpfs' ||
  disk.type !== 0x01021994n ||
  disk.blocks * disk.bsize > BigInt(maxFill)
)
  throw new Error('A dedicated /tmp tmpfs of at most 8 MiB is required');
const outcomes = [];
for (const mode of ['read', 'write']) {
  const f = new Fixture();
  try {
    await f.start();
    const t = await f.token();
    expect(
      (
        await f.call(
          'secrets/put',
          { scope, name: 'existing', value: 'synthetic-disk-canary', expectedRevision: 0 },
          t.token,
        )
      ).status,
    ).toBe(200);
    const fill = join(f.root, 'fill');
    const fd = openSync(fill, 'wx', 0o600),
      bytes = Buffer.alloc(4096);
    try {
      let written = 0;
      while (written < maxFill)
        written += writeSync(fd, bytes, 0, Math.min(bytes.length, maxFill - written));
      throw new Error('Filler reached its strict byte cap without ENOSPC');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOSPC') throw error;
    } finally {
      closeSync(fd);
    }
    let failedName = '',
      refused = false,
      successes = 0;
    for (let n = 0; n < 500; n++) {
      const response =
        mode === 'read'
          ? await f.call('secrets/resolve', { scope, selector: { name: 'existing' } }, t.token)
          : await f.call(
              'secrets/put',
              {
                scope,
                name: `failed-${n}`,
                value: 'synthetic-uncommitted'.repeat(1000),
                expectedRevision: 0,
              },
              t.token,
            );
      if (response.status === 200) {
        successes++;
        continue;
      }
      expect(response.status).toBe(503);
      expect(JSON.stringify(response.data).includes('synthetic-')).toBe(false);
      failedName = `failed-${n}`;
      refused = true;
      break;
    }
    expect(refused).toBe(true);
    await f.stop();
    rmSync(fill);
    removeCrashSocket(f);
    f.logs = '';
    await f.start();
    expect(
      (await f.call('secrets/resolve', { scope, selector: { name: 'existing' } }, t.token)).data
        .value,
    ).toBe('synthetic-disk-canary');
    if (mode === 'write')
      expect(
        (await f.call('secrets/inspect', { scope, name: failedName }, t.token)).data,
      ).toBeNull();
    outcomes.push({
      mode,
      refused: true,
      recovery: 'verified',
      successfulOperationsBeforeAllocationFailure: successes,
    });
  } finally {
    await f.close();
  }
}
writeFileSync(
  '/receipts/disk-full.json',
  JSON.stringify(
    { runtime: Bun.version, node: process.versions.node, uid: process.getuid?.(), outcomes },
    null,
    2,
  ),
);
