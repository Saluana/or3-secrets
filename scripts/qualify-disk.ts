// Real ENOSPC, no production fault-injection hooks. Run only inside the disposable
// 8 MiB /tmp tmpfs described in docs/qualification.md, as the unprivileged bun user.
import { openSync, closeSync, writeSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Fixture, scope, removeCrashSocket } from '../tests/helpers';
import { expect } from 'bun:test';
if (process.platform !== 'linux' || process.getuid?.() === 0) throw new Error('Disposable non-root Linux profile required');
const outcomes = [];
for (const mode of ['read', 'write']) {
  const f = new Fixture();
  try {
    await f.start(); const t = await f.token();
    expect((await f.call('secrets/put', { scope, name: 'existing', value: 'synthetic-disk-canary', expectedRevision: 0 }, t.token)).status).toBe(200);
    const fill = join(f.root, 'fill'); const fd = openSync(fill, 'wx', 0o600), bytes = Buffer.alloc(4096);
    try { while (true) writeSync(fd, bytes); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOSPC') throw error; }
    finally { closeSync(fd); }
    let failedName = '', refused = false, successes = 0;
    for (let n = 0; n < 500; n++) {
      const response = mode === 'read'
        ? await f.call('secrets/resolve', { scope, selector: { name: 'existing' } }, t.token)
        : await f.call('secrets/put', { scope, name: `failed-${n}`, value: 'synthetic-uncommitted'.repeat(1000), expectedRevision: 0 }, t.token);
      if (response.status === 200) { successes++; continue; }
      expect(response.status).toBe(503);
      expect(JSON.stringify(response.data).includes('synthetic-')).toBe(false);
      failedName = `failed-${n}`; refused = true; break;
    }
    expect(refused).toBe(true);
    await f.stop(); rmSync(fill); removeCrashSocket(f); f.logs = ''; await f.start();
    expect((await f.call('secrets/resolve', { scope, selector: { name: 'existing' } }, t.token)).data.value).toBe('synthetic-disk-canary');
    if (mode === 'write') expect((await f.call('secrets/inspect', { scope, name: failedName }, t.token)).data).toBeNull();
    outcomes.push({ mode, refused: true, recovery: 'verified', successfulOperationsBeforeAllocationFailure: successes });
  } finally { await f.close(); }
}
writeFileSync('/receipts/disk-full.json', JSON.stringify({ runtime: Bun.version, node: process.versions.node, uid: process.getuid?.(), outcomes }, null, 2));
