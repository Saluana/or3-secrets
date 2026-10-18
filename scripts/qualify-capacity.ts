// Offline format fixture: genuine aged authenticated history, one 1 GiB SQLite file.
// This does not expose a service API for manufacturing audit rows.
import { Database } from 'bun:sqlite';
import { mkdirSync, readFileSync, writeFileSync, statSync, statfsSync } from 'node:fs';
import { join } from 'node:path';
import { derive, mac } from '../src/crypto';
import { Vault } from '../src/store';
import { backup, restore, rekey, BACKUP_OVERHEAD } from '../src/maintenance';
import { MAX_SNAPSHOT, parseInput, type Operation } from '../src/protocol';
import { Fixture, cli, scope } from '../tests/helpers';
// ARM64 local budgets remain unchanged. CI's x64-baseline Bun build has a
// separate ceiling and must also pass a same-host, same-fixture base comparison.
// Neither profile chooses a production SLO; the job timeout stays unchanged.
const baselineDir = process.env.OR3_SECRETS_CAPACITY_BASELINE;
const ciBaseline = process.platform === 'linux' && process.arch === 'x64' && process.env.CI === 'true';
if (ciBaseline && !baselineDir) throw new Error('x64 CI capacity requires a pinned baseline checkout');
const factor = ciBaseline ? 4 : 1;
const budgets = { verify: 45000 * factor, backup: 60000 * factor, restore: 120000 * factor, rekey: 120000 * factor, peakRssBytes: 512 * 1024 ** 2 };
const fixture = new Fixture(), root = fixture.root;
const vaultDir = fixture.vault, keyFile = fixture.key;
const timings: Record<string, number> = {};
function measure<T>(name: string, action: () => T): T {
  console.log(JSON.stringify({ phase: name, state: 'started' }));
  const started = performance.now();
  try { return action(); }
  finally { timings[name] = Math.round(performance.now() - started); console.log(JSON.stringify({ phase: name, elapsedMs: timings[name] })); }
}
try {
  const storage = statfsSync(root);
  if (storage.bavail * storage.bsize < 6 * MAX_SNAPSHOT) throw new Error('Capacity qualification needs 6 GiB free disposable storage');
  const init = { vaultId: fixture.vaultId }, operator = fixture.operator;
  await fixture.start();
  const token = await fixture.token();
  const perform = async (operation: Operation, input: Record<string, unknown>, credential = token.token) => {
    const result = await fixture.call(operation, input, credential);
    if (result.status !== 200) throw new Error(`Mixed capacity seed failed: ${operation}`);
    return result.data;
  };
  const seedStarted = performance.now();
  console.log(JSON.stringify({ phase: 'seedMixedInventory', state: 'started' }));
  const value = 'synthetic-capacity-inventory-'.repeat(10);
  for (let n = 0; n < 2000; n++) await perform('secrets/put', { scope, name: `mixed-${n}`, value, expectedRevision: 0 });
  for (let n = 0; n < 500; n++) await perform('secrets/delete', { scope, name: `mixed-${n}`, expectedRevision: 1 });
  for (let n = 1500; n < 2000; n++) await perform('secrets/put', { scope, name: `mixed-${n}`, value: value + 'revision-2', expectedRevision: 1 });
  for (let n = 0; n < 500; n++) {
    const issued = await perform('tokens/issue', { kind: 'service', namespace: scope.namespace, capabilities: ['read'], expiresInSeconds: n < 250 ? 1 : 3600 }, operator);
    if (n >= 250) await perform('tokens/revoke', { id: issued.meta.id }, operator);
  }
  for (let n = 0; n < 100; n++) await perform('secrets/resolve', { scope, selector: { name: 'mixed-1999' } });
  timings.seedMixedInventory = Math.round(performance.now() - seedStarted);
  console.log(JSON.stringify({ phase: 'seedMixedInventory', elapsedMs: timings.seedMixedInventory }));
  await fixture.stop();
  const verified = cli(['audit', 'verify', '--vault-dir', vaultDir, '--key-file', keyFile]);
  if (verified.status !== 0) throw new Error('Seeded capacity inventory failed verification');
  const checkpoint = JSON.parse(verified.stdout);
  const key = derive(readFileSync(keyFile), init.vaultId, 'audit');
  const dbPath = join(vaultDir, 'vault.sqlite'), db = new Database(dbPath);
  // The production schema remains exact; an offline fixture limits allocation to exactly 1 GiB.
  db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA max_page_count=${MAX_SNAPSHOT / 4096}`);
  const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
  let seq = checkpoint.seq, previous = checkpoint.mac;
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
  if (baselineDir) {
    const { Vault: BaseVault }: { Vault: typeof Vault } = await import(join(baselineDir, 'src/store.ts'));
    measure('baselineVerify', () => { const v = BaseVault.open(vaultDir, keyFile); try { return v.verify(); } finally { v.close(); } });
  }
  let liveRefusal = '';
  const receipt = measure('verify', () => { const v = Vault.open(vaultDir, keyFile); try {
    try { v.perform('status', parseInput('status', { context: { requestId: 'capacity-live-refusal' } }), operator, init.vaultId); }
    catch (error) { liveRefusal = (error as { code: string }).code; }
    if (liveRefusal !== 'capacity_reached') throw new Error('Exact-limit inventory was admitted for live work');
    return v.verify();
  } finally { v.close(); } });
  const backupFile = join(root, 'snapshot.backup');
  measure('backup', () => backup({ vaultDir, keyFile, outFile: backupFile, receipt }));
  measure('restore', () => restore({ backupFile, keyFile, destination: join(root, 'restored'), newKeyFile: join(root, 'restored.key'), operatorFile: join(root, 'restored.token'), receipt }));
  measure('rekey', () => rekey({ vaultDir, keyFile, destination: join(root, 'rekeyed'), newKeyFile: join(root, 'rekeyed.key'), operatorFile: join(root, 'rekeyed.token'), receipt }));
  const peakRssBytes = process.platform === 'linux' ? Number(/^VmHWM:\s+(\d+) kB$/m.exec(readFileSync('/proc/self/status', 'utf8'))?.[1]) * 1024 : process.resourceUsage().maxRSS;
  const failures: string[] = [];
  for (const name of ['verify', 'backup', 'restore', 'rekey'] as const)
    if (timings[name]! > budgets[name]) failures.push(`${name} exceeded the capacity profile budget`);
  if (!Number.isFinite(peakRssBytes) || peakRssBytes > budgets.peakRssBytes) failures.push('Capacity peak RSS exceeded its budget');
  const verificationRatio = baselineDir ? timings.verify! / timings.baselineVerify! : null;
  if (verificationRatio !== null && verificationRatio > 1.2) failures.push('Verification regressed more than 20% against the same-host baseline');
  const result = { runtime: Bun.version, platform: process.platform, architecture: process.arch, budgetProfile: ciBaseline ? 'linux-x64-baseline CI, with same-host comparison' : 'local reference (measured on ARM64)', baselineRevision: baselineDir ? '0888b45cea9428e9daf769a976b45d082187c3e1' : null, verificationRatio, failures, profile: { liveSecrets: 1500, tombstones: 500, updatedSecrets: 500, expiredTokens: 250, revokedTokens: 250 }, budgets, peakRssBytes, agedEvents: seq, databaseBytes: size, capBytes: MAX_SNAPSHOT, backupBytes: statSync(backupFile).size, restoredBytes: statSync(join(root, 'restored/vault.sqlite')).size, rekeyedBytes: statSync(join(root, 'rekeyed/vault.sqlite')).size, exactEnvelopeSize: statSync(backupFile).size === size + BACKUP_OVERHEAD, liveAdmission: liveRefusal, timingsMs: timings, rssBytesAtFinish: process.memoryUsage().rss, powerLoss: 'not qualified', deploymentAcceptance: false };
  mkdirSync('test-results', { recursive: true }); writeFileSync('test-results/capacity.json', JSON.stringify(result, null, 2)); console.log(JSON.stringify(result));
  if (failures.length) throw new Error(failures.join('; '));
} finally { await fixture.close(); }
