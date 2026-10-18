// Real ENOSPC, no production fault-injection hooks. Run only inside the disposable
// 8 MiB /tmp tmpfs described in docs/qualification.md, as the unprivileged bun user.
import { openSync, closeSync, writeSync, rmSync, writeFileSync, statfsSync, mkdtempSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Fixture, scope, removeCrashSocket } from '../tests/helpers';
import { expect } from 'bun:test';
import { backup, restore, rekey } from '../src/maintenance';
if (process.platform !== 'linux' || process.getuid?.() === 0) throw new Error('Disposable non-root Linux profile required');
// Refuse to fill arbitrary host storage when a mount was forgotten.
const storage = statfsSync('/tmp');
if (storage.type !== 0x01021994 || storage.blocks * storage.bsize !== 8 * 1024 * 1024) throw new Error('Exactly 8 MiB disposable /tmp tmpfs required');
const outcomes = [];
const thresholds: string[] = [];
const staging = mkdtempSync('/staging/ors-disk-');
try {
for (const mode of ['read', 'write']) {
  const f = new Fixture();
  try {
    if (mode === 'read') {
      const refused = (action: () => unknown) => {
        let code = '';
        try { action(); } catch (error) { code = (error as { code: string }).code; }
        expect(code).toBe('insufficient_space');
      };
      const outFile = join(f.root, 'refused.backup');
      refused(() => backup({ vaultDir: f.vault, keyFile: f.key, outFile }));
      expect(existsSync(outFile)).toBe(false); thresholds.push('backup');
      const backupFile = join(staging, 'valid.backup');
      backup({ vaultDir: f.vault, keyFile: f.key, outFile: backupFile });
      const target = { destination: join(f.root, 'refused-destination'), newKeyFile: join(f.root, 'refused.key'), operatorFile: join(f.root, 'refused.token') };
      refused(() => restore({ backupFile, keyFile: f.key, ...target }));
      expect(existsSync(target.destination)).toBe(false); thresholds.push('restore');
      refused(() => rekey({ vaultDir: f.vault, keyFile: f.key, ...target }));
      expect(existsSync(target.destination)).toBe(false); thresholds.push('rekey');
    }
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
writeFileSync('/receipts/disk-full.json', JSON.stringify({ runtime: Bun.version, node: process.versions.node, uid: process.getuid?.(), filesystemBytes: storage.blocks * storage.bsize, headroomRefusalsBeforeOutput: thresholds, outcomes }, null, 2));

} finally { rmSync(staging, { recursive: true, force: true }); }
