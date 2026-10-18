// Offline, authenticated mixed inventory. No production fault-injection switches.
import { Database } from 'bun:sqlite';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync, statfsSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { derive, mac } from '../src/crypto';
import { Vault } from '../src/store';
import { backup, restore, rekey, BACKUP_OVERHEAD } from '../src/maintenance';
import { MAX_SNAPSHOT, parseInput, type Operation, type Receipt } from '../src/protocol';
import budgets from './linux-budgets.json';

const limits = budgets.capacity;
function check(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
function perform(v: Vault, op: Operation, body: Record<string, unknown>, credential: string): any {
  return v.perform(op, parseInput(op, { context: { requestId: 'qualification' }, ...body }), credential, v.vaultId);
}
const scope = { namespace: 'capacity', ownerUserId: 'u', workspaceId: 'w', consumerId: 'p' };
const value = (i: number) => `synthetic-${i}:`.padEnd(limits.valueSizesBytes[i % limits.valueSizesBytes.length]!, 'x');

// Each operation has its own process: Linux ru_maxrss is KiB, not cumulative
// across fixture creation, and a real service child owns startup measurement.
if (process.argv[2] === '--worker') {
  const [operation, root, receiptText] = process.argv.slice(3) as [string, string, string];
  const vaultDir = join(root, 'vault'), keyFile = join(root, 'master.key');
  const receipt = JSON.parse(receiptText) as Receipt;
  const started = performance.now();
  let result: any = null, serviceMaxRssBytes = 0;
  if (operation === 'startup') {
    const socket = join(root, 'run', 'api.sock');
    mkdirSync(join(root, 'run'), { mode: 0o700 });
    const child = spawn(process.execPath, ['--no-env-file', 'src/cli.ts', 'serve', '--vault-dir', vaultDir, '--key-file', keyFile, '--socket', socket], { stdio: ['ignore', 'pipe', 'pipe'] });
    try {
      await new Promise<void>((yes, no) => {
        const timer = setTimeout(() => { child.kill('SIGKILL'); no(new Error('Startup budget exceeded')); }, limits.startupMs);
        let output = '';
        child.stdout!.on('data', bytes => { output += bytes; if (output.includes('"ready":true')) { clearTimeout(timer); yes(); } });
        child.once('exit', () => { clearTimeout(timer); no(new Error('Service exited before readiness')); });
      });
      serviceMaxRssBytes = Number(readFileSync(`/proc/${child.pid}/status`, 'utf8').match(/^VmHWM:\s+(\d+)/m)![1]) * 1024;
    } finally {
      if (child.exitCode === null && child.signalCode === null) await new Promise<void>(yes => { child.once('exit', () => yes()); child.kill('SIGTERM'); });
      rmSync(join(root, 'run'), { recursive: true, force: true });
    }
  } else if (operation === 'verify') {
    const v = Vault.open(vaultDir, keyFile); try { result = v.verify(); } finally { v.close(); }
  } else if (operation === 'backup') {
    result = backup({ vaultDir, keyFile, outFile: join(root, 'snapshot.backup'), receipt });
  } else if (operation === 'restore' || operation === 'rekey') {
    const target = { destination: join(root, operation), newKeyFile: join(root, `${operation}.key`), operatorFile: join(root, `${operation}.token`), receipt };
    result = operation === 'restore'
      ? restore({ backupFile: join(root, 'snapshot.backup'), keyFile, ...target })
      : rekey({ vaultDir, keyFile, ...target });
    // Reissue authority, resolve independently specified bytes, inspect a tombstone,
    // reject old authority, and count fresh wraps after the real copy completes.
    const destination = Vault.open(target.destination, target.newKeyFile);
    try {
      let oldDenied = false;
      try { perform(destination, 'status', {}, readFileSync(join(root, 'operator.token'), 'utf8').trim()); } catch (e) { oldDenied = (e as any).code === 'unauthorized'; }
      check(oldDenied, 'Old authority was accepted');
      const operator = readFileSync(target.operatorFile, 'utf8').trim();
      const issued = perform(destination, 'tokens/issue', { kind: 'service', namespace: scope.namespace, capabilities: ['read', 'metadata'], expiresInSeconds: 3600 }, operator);
      for (const i of [0, 1, 2, 3, limits.liveSecrets - 1]) {
        const actual = perform(destination, 'secrets/resolve', { scope, selector: { name: `live-${i}` } }, issued.token);
        check(actual.value === value(i) && actual.meta.ref.revision === 2, 'Recovered value/revision mismatch');
      }
      check(perform(destination, 'secrets/inspect', { scope, name: 'dead-0' }, issued.token).state === 'deleted', 'Tombstone lost');
      check(perform(destination, 'status', {}, operator).storage.wrapCount === limits.liveSecrets, 'Fresh wraps not counted');
      destination.verify();
    } finally { destination.close(); }
  } else throw new Error('Unknown worker');
  console.log(JSON.stringify({ result, ms: Math.round(performance.now() - started), maxRssBytes: Math.max(process.resourceUsage().maxRSS * 1024, serviceMaxRssBytes) }));
} else {
  check(process.platform === 'linux' && process.arch === 'x64' && Bun.version === '1.3.14', 'Pinned Linux runtime required');
  const oversizeOnly = process.argv[2] === '--oversize-only';
  const temp = resolve(process.env.OR3_QUALIFY_TMPDIR ?? '/tmp');
  const free = () => { const s = statfsSync(temp); return s.bavail * s.bsize; };
  check(free() >= limits.minimumFreeBytes, 'At least 8 GiB of disposable persistent storage required');
  const root = mkdtempSync(join(temp, 'ors-capacity-'));
  const vaultDir = join(root, 'vault'), keyFile = join(root, 'master.key'), dbPath = join(vaultDir, 'vault.sqlite');
  const stages: any[] = [];
  const run = async (operation: string, receipt: Receipt) => {
    const child = spawn(process.execPath, ['--no-env-file', import.meta.path, '--worker', operation, root, JSON.stringify(receipt)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', minimumFree = free();
    const sample = setInterval(() => { minimumFree = Math.min(minimumFree, free()); }, 25);
    const timeout = setTimeout(() => child.kill('SIGKILL'), 2 * limits.restoreMs);
    child.stdout!.on('data', data => { stdout += data; }); child.stderr!.on('data', data => { stderr += data; });
    try {
      const exit = await new Promise<number | null>((yes, no) => { child.once('error', no); child.once('exit', yes); });
      check(exit === 0, `${operation} failed: ${stderr.slice(-2000)}`);
      return { ...JSON.parse(stdout), sampledFilesystemConsumptionBytes: Math.max(0, initialFree - minimumFree) };
    } finally { clearInterval(sample); clearTimeout(timeout); }
  };
  const initialFree = free();
  try {
    const init = Vault.create({ vaultDir, keyFile, operatorFile: join(root, 'operator.token') });
    const v = Vault.open(vaultDir, keyFile), operator = readFileSync(join(root, 'operator.token'), 'utf8').trim();
    try {
      let service = '';
      for (let i = 0; i < limits.serviceTokens; i++) service = perform(v, 'tokens/issue', { kind: 'service', namespace: scope.namespace, capabilities: ['metadata', 'read', 'write', 'delete'], expiresInSeconds: 86400 }, operator).token;
      for (let i = 0; i < limits.liveSecrets; i++) {
        perform(v, 'secrets/put', { scope, name: `live-${i}`, value: 'superseded', expectedRevision: 0 }, service);
        perform(v, 'secrets/put', { scope, name: `live-${i}`, value: value(i), expectedRevision: 1 }, service);
      }
      for (let i = 0; i < limits.tombstones; i++) {
        perform(v, 'secrets/put', { scope, name: `dead-${i}`, value: 'deleted', expectedRevision: 0 }, service);
        perform(v, 'secrets/delete', { scope, name: `dead-${i}`, expectedRevision: 1 }, service);
      }
    } finally { v.close(); }
    const key = derive(readFileSync(keyFile), init.vaultId, 'audit');
    let db = new Database(dbPath);
    let head = db.query('SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1').get() as { seq: number; mac: string };
    let seq = head.seq, previous = head.mac;
    db.close();
    for (const target of (oversizeOnly ? [MAX_SNAPSHOT] : limits.stagesBytes)) {
      const started = performance.now();
      db = new Database(dbPath);
      db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA max_page_count=${target / 4096}`);
      const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
      const payload = JSON.stringify({ at: '2020-01-01T00:00:00.000Z', operation: 'status', outcome: 'success', requestId: 'r'.repeat(128), actorId: 'a'.repeat(128), activationId: 'x'.repeat(128) });
      for (const batch of [2000, 100, 1]) {
        let full = false;
        while (!full) {
          const beforeSeq = seq, beforeMac = previous;
          db.exec('BEGIN');
          try {
            for (let n = 0; n < batch; n++) {
              const next = seq + 1, hash = mac(key, 'event', [next, previous, payload]);
              insert.run(next, previous, payload, hash); seq = next; previous = hash;
            }
            db.exec('COMMIT');
          } catch (error) {
            try { db.exec('ROLLBACK'); } catch { /* SQLITE_FULL can roll back. */ }
            seq = beforeSeq; previous = beforeMac;
            if (!String((error as Error).message).includes('full')) throw error;
            full = true;
          }
        }
      }
      db.close();
      check(statSync(dbPath).size === target, 'Fixture did not reach exact stage');
      if (oversizeOnly) continue;
      const stage: any = { databaseBytes: target, auditEvents: seq, ageFixtureMs: Math.round(performance.now() - started), operations: {} };
      const receipt = { vaultId: init.vaultId, seq, mac: previous };
      for (const operation of ['startup', 'verify', 'backup', 'restore', 'rekey']) {
        console.error(`Qualifying ${target} bytes: ${operation}`);
        stage.operations[operation] = await run(operation, receipt);
      }
      check(statSync(join(root, 'snapshot.backup')).size === target + BACKUP_OVERHEAD, 'Wrong envelope size');
      stage.backupBytes = statSync(join(root, 'snapshot.backup')).size;
      stage.restoredBytes = statSync(join(root, 'restore/vault.sqlite')).size;
      stage.rekeyedBytes = statSync(join(root, 'rekey/vault.sqlite')).size;
      stage.passed = Object.entries(stage.operations).every(([name, measured]: [string, any]) => measured.ms <= (limits[`${name}Ms` as keyof typeof limits] as number) && measured.maxRssBytes <= limits.maxRssBytes);
      stages.push(stage);
      for (const name of ['snapshot.backup', 'restore', 'restore.key', 'restore.token', 'rekey', 'rekey.key', 'rekey.token']) rmSync(join(root, name), { recursive: true, force: true });
      mkdirSync('test-results', { recursive: true });
      writeFileSync('test-results/capacity.json', JSON.stringify({ profile: budgets.profile, generatedAt: new Date().toISOString(), runtime: Bun.version, platform: process.platform, architecture: process.arch, limits, inventory: { live: limits.liveSecrets, tombstones: limits.tombstones, serviceTokens: limits.serviceTokens, allLiveRevisions: 2 }, stages, powerLoss: 'not performed', complete: false, allMeasuredStagesPassed: stages.every(s => s.passed), passed: false }, null, 2));
    }
    // A real SQLite file beyond the input limit must fail before output creation.
    db = new Database(dbPath); db.exec('PRAGMA max_page_count=2147483646');
    db.exec('BEGIN');
    try {
      const payload = JSON.stringify({ at: '2020-01-01T00:00:00.000Z', operation: 'status', outcome: 'success', requestId: 'oversize' });
      const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
      while (statSync(dbPath).size <= MAX_SNAPSHOT) {
        for (let i = 0; i < 5; i++) { const next = seq + 1, hash = mac(key, 'event', [next, previous, payload]); insert.run(next, previous, payload, hash); seq = next; previous = hash; }
        db.exec('COMMIT'); db.exec('BEGIN');
      }
      db.exec('COMMIT');
    } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
    db.close(); key.fill(0);
    let refused = false;
    try { backup({ vaultDir, keyFile, outFile: join(root, 'oversize.backup') }); } catch (e) { refused = (e as any).code === 'too_large'; }
    check(refused && !existsSync(join(root, 'oversize.backup')), 'Oversize snapshot admitted');
    const receiptPath = oversizeOnly ? 'test-results/capacity-oversize.json' : 'test-results/capacity.json';
    const result = oversizeOnly ? { profile: budgets.profile, runtime: Bun.version, generatedAt: new Date().toISOString(), stages: [] } : JSON.parse(readFileSync(receiptPath, 'utf8'));
    mkdirSync('test-results', { recursive: true });
    result.oversize = { bytes: statSync(dbPath).size, refusedBeforeOutput: true };
    result.complete = oversizeOnly || stages.length === limits.stagesBytes.length;
    result.passed = result.complete && stages.every(s => s.passed);
    writeFileSync(receiptPath, JSON.stringify(result, null, 2));
    check(result.passed, 'Capacity budget exceeded; revise supported envelope');
    console.log(JSON.stringify({ passed: true, stages: stages.map(s => ({ bytes: s.databaseBytes, passed: s.passed })), oversize: result.oversize }));
  } finally { rmSync(root, { recursive: true, force: true }); }
}
