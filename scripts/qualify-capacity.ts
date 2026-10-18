// Offline format fixture: genuine aged authenticated history, one 1 GiB SQLite file.
// This does not expose a service API for manufacturing audit rows.
import { Database } from 'bun:sqlite';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { derive, mac } from '../src/crypto';
import { Vault } from '../src/store';
import { backup, restore, rekey, BACKUP_OVERHEAD } from '../src/maintenance';
import { MAX_SNAPSHOT } from '../src/protocol';
const root = mkdtempSync(process.platform === 'darwin' ? '/private/tmp/ors-capacity-' : '/tmp/ors-capacity-');
const vaultDir = join(root, 'vault'), keyFile = join(root, 'master.key');
const timings: Record<string, number> = {};
function measure<T>(name: string, action: () => T): T { const started = performance.now(); try { return action(); } finally { timings[name] = Math.round(performance.now() - started); } }
try {
  const init = Vault.create({ vaultDir, keyFile, operatorFile: join(root, 'operator.token') });
  const key = derive(readFileSync(keyFile), init.vaultId, 'audit');
  const dbPath = join(vaultDir, 'vault.sqlite'), db = new Database(dbPath);
  // The production schema remains exact; an offline fixture limits allocation to exactly 1 GiB.
  db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA max_page_count=${MAX_SNAPSHOT / 4096}`);
  const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
  let seq = init.seq, previous = init.mac;
  measure('ageFixture', () => {
    for (const batch of [2000, 100, 1]) {
    let full = false;
    while (!full) {
      const beforeSeq = seq, beforeMac = previous;
      db.exec('BEGIN');
      try {
        for (let n = 0; n < batch; n++) {
          const payload = JSON.stringify({ at: '2020-01-01T00:00:00.000Z', operation: 'status', outcome: 'success', requestId: 'r'.repeat(128), actorId: 'a'.repeat(128), activationId: 'x'.repeat(128) });
          const next = seq + 1, hash = mac(key, 'event', [next, previous, payload]);
          insert.run(next, previous, payload, hash); seq = next; previous = hash;
        }
        db.exec('COMMIT');
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch { /* SQLITE_FULL may already roll back. */ }
        seq = beforeSeq; previous = beforeMac;
        if (!String((error as Error).message).includes('full')) throw error;
        full = true;
      }
    }
    }
    // Check the exact snapshot bound without changing the production schema.
    const pages = (db.query('PRAGMA page_count').get() as { page_count: number }).page_count;
    if (pages * 4096 !== MAX_SNAPSHOT) throw new Error('Fixture did not reach exact cap');
  });
  db.close(); key.fill(0);
  const size = statSync(dbPath).size;
  const receipt = measure('verify', () => { const v = Vault.open(vaultDir, keyFile); try { return v.verify(); } finally { v.close(); } });
  const backupFile = join(root, 'snapshot.backup');
  measure('backup', () => backup({ vaultDir, keyFile, outFile: backupFile, receipt }));
  measure('restore', () => restore({ backupFile, keyFile, destination: join(root, 'restored'), newKeyFile: join(root, 'restored.key'), operatorFile: join(root, 'restored.token'), receipt }));
  measure('rekey', () => rekey({ vaultDir, keyFile, destination: join(root, 'rekeyed'), newKeyFile: join(root, 'rekeyed.key'), operatorFile: join(root, 'rekeyed.token'), receipt }));
  const result = { runtime: Bun.version, platform: process.platform, architecture: process.arch, agedEvents: seq, databaseBytes: size, capBytes: MAX_SNAPSHOT, backupBytes: statSync(backupFile).size, restoredBytes: statSync(join(root, 'restored/vault.sqlite')).size, rekeyedBytes: statSync(join(root, 'rekeyed/vault.sqlite')).size, exactEnvelopeSize: statSync(backupFile).size === size + BACKUP_OVERHEAD, timingsMs: timings, reportedMaxRssRaw: process.resourceUsage().maxRSS, rssBytesAtFinish: process.memoryUsage().rss, powerLoss: 'not qualified' };
  mkdirSync('test-results', { recursive: true }); writeFileSync('test-results/capacity.json', JSON.stringify(result, null, 2)); console.log(JSON.stringify(result));
} finally { rmSync(root, { recursive: true, force: true }); }
