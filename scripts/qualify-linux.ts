// Real process/IPC observations and disposable collector state; no production hooks.
import { strict as assert } from 'node:assert';
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync, fsyncSync, statfsSync, statSync, readdirSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { Fixture, scope, removeCrashSocket } from '../tests/helpers';
import budgets from './linux-budgets.json';

assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.equal(Bun.version, '1.3.14');
assert.equal(spawnSync('node', ['--version'], { encoding: 'utf8' }).stdout.trim(), 'v24.13.0');
const f = new Fixture(process.env.OR3_QUALIFY_TMPDIR ?? '/var/tmp');
const elapsed = async <T>(action: () => Promise<T>) => { const start = performance.now(); const result = await action(); return { ms: performance.now() - start, result }; };
const rss = () => Number(readFileSync(`/proc/${f.child!.pid}/status`, 'utf8').match(/^VmRSS:\s+(\d+)/m)![1]) * 1024;
const pause = (ms: number) => new Promise(yes => setTimeout(yes, ms));
const memory: number[] = [];
const result: Record<string, any> = { profile: budgets.profile, generatedAt: new Date().toISOString(), runtime: Bun.version, node: '24.13.0', kernel: spawnSync('uname', ['-sr'], { encoding: 'utf8' }).stdout.trim(), architecture: process.arch, filesystem: spawnSync('findmnt', ['-n', '-o', 'FSTYPE,OPTIONS', '-T', f.root], { encoding: 'utf8' }).stdout.trim(), powerLoss: 'not performed' };
try {
  const syncFile = join(f.root, 'sync-probe'), fd = openSync(syncFile, 'wx', 0o600);
  writeFileSync(fd, 'synthetic-sync'); fsyncSync(fd); closeSync(fd);
  const dir = openSync(f.root, 'r'); fsyncSync(dir); closeSync(dir);
  result.sync = { fileFsync: 'passed', directoryFsync: 'passed', persistedAcrossProcessRestart: false, powerLoss: 'not performed' };
  const startup = await elapsed(() => f.start()); result.startupMs = startup.ms;
  const token = await f.token();
  for (let i = 0; i < budgets.small.secrets; i++) assert.equal((await f.call('secrets/put', { scope, name: `small-${i}`, value: 'x'.repeat(1024), expectedRevision: 0 }, token.token)).status, 200);
  memory.push(rss());
  result.latencyMs = {};
  for (const operation of ['secrets/resolve', 'secrets/put']) {
    const samples: number[] = [];
    for (let i = 0; i < budgets.small.samplesPerOperation; i++) {
      const measured = await elapsed(() => f.call(operation, operation === 'secrets/resolve' ? { scope, selector: { name: `small-${i % 100}` } } : { scope, name: `small-${i % 100}`, value: 'y'.repeat(1024), expectedRevision: 1 + Math.floor(i / 100) }, token.token));
      assert.equal(measured.result.status, 200); samples.push(measured.ms);
    }
    samples.sort((a, b) => a - b);
    result.latencyMs[operation] = { samples: samples.length, p50: samples[Math.floor(samples.length * 0.5)], p95: samples[Math.ceil(samples.length * 0.95) - 1], maximum: samples.at(-1), load: 'sequential closed-loop; no artificial delay' };
    assert.ok(result.latencyMs[operation].p95 <= budgets.small.p95Ms);
  }
  const status = await f.call('status'); assert.equal(status.status, 200);
  result.storage = status.data.storage;
  assert.equal(result.storage.journalMode, 'delete'); assert.equal(result.storage.lockingMode, 'exclusive'); assert.equal(result.storage.synchronous, 'extra');
  const journal = join(f.vault, 'vault.sqlite-journal');
  result.journal = { existsWhileOwnerActive: statSync(journal).isFile(), bytes: statSync(journal).size, first28BytesZero: readFileSync(journal).subarray(0, 28).equals(Buffer.alloc(28)) };
  assert.equal(result.journal.first28BytesZero, true);
  // Match only this service's socket inodes with /proc net tables; unrelated host
  // listeners are outside this process and must not influence the conclusion.
  const inodes = readdirSync(`/proc/${f.child!.pid}/fd`).flatMap(name => {
    try { const link = readlinkSync(`/proc/${f.child!.pid}/fd/${name}`); const match = /^socket:\[(\d+)\]$/.exec(link); return match ? [match[1]!] : []; } catch { return []; }
  });
  const tcp = ['tcp', 'tcp6'].flatMap(name => readFileSync(`/proc/${f.child!.pid}/net/${name}`, 'utf8').trim().split('\n').slice(1));
  result.tcpListeners = tcp.filter(line => { const fields = line.trim().split(/\s+/); return fields[3] === '0A' && inodes.includes(fields[9]!); }).length;
  assert.equal(result.tcpListeners, 0);
  result.socketMode = (statSync(f.socket).mode & 0o777).toString(8); assert.equal(result.socketMode, '600');

  // Durable external collector progress: repeat an unacknowledged page after a
  // collector interruption, then resume the frozen head from persisted progress.
  const audit = await f.token({ kind: 'audit-reader', namespace: undefined, capabilities: ['audit'] });
  const first = await f.call('audit/read', { after: null, limit: 100 }, audit.token); assert.equal(first.status, 200);
  const through = first.data.through;
  const progressFile = join(f.root, 'collector-progress.json');
  writeFileSync(progressFile, JSON.stringify({ after: null, through }), { mode: 0o600 });
  const written = openSync(progressFile, 'r'); fsyncSync(written); closeSync(written);
  const batchFile = join(f.root, 'collector-batch.json');
  const collector = spawn('node', ['--input-type=module', '-e', `
    import { readFileSync, writeFileSync, openSync, fsyncSync, closeSync } from 'node:fs';
    import { dirname } from 'node:path';
    import { createClient } from ${JSON.stringify(join(process.cwd(), 'dist/client.js'))};
    const config = JSON.parse(process.argv[1]);
    const progress = JSON.parse(readFileSync(config.progressFile, 'utf8'));
    const page = await createClient(config.client).readAudit({ ...progress, limit: 100 });
    writeFileSync(config.batchFile, JSON.stringify(page), { flag: 'wx', mode: 0o600 });
    for (const path of [config.batchFile, dirname(config.batchFile)]) { const fd = openSync(path, 'r'); fsyncSync(fd); closeSync(fd); }
    // Crash after durable forwarding and before checkpoint advancement.
    process.stdout.write('durable\\n'); setInterval(() => {}, 1000);
  `, JSON.stringify({ progressFile, batchFile, client: { socketPath: f.socket, tokenFile: audit.file, vaultId: f.vaultId } })], { stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(new Error('Collector did not forward batch')), 5000);
      collector.stdout!.once('data', () => { clearTimeout(timer); yes(); });
      collector.once('exit', () => { clearTimeout(timer); no(new Error('Collector exited before forwarding')); });
    });
    assert.deepEqual(JSON.parse(readFileSync(batchFile, 'utf8')).events, first.data.events);
  } finally {
    if (collector.exitCode === null && collector.signalCode === null) await new Promise<void>(yes => { collector.once('exit', () => yes()); collector.kill('SIGKILL'); });
  }
  await pause(1100);
  const retry = await f.call('audit/read', { ...JSON.parse(readFileSync(progressFile, 'utf8')), limit: 100 }, audit.token);
  assert.equal(retry.status, 200); assert.deepEqual(retry.data.events, first.data.events);
  let cursor = retry.data.cursor, pages = 1;
  while (cursor.seq < through.seq) {
    await pause(300); // stay below the actual five-attempts/second budget
    const page = await f.call('audit/read', { after: cursor, through, limit: 100 }, audit.token);
    assert.equal(page.status, 200); assert.deepEqual(page.data.through, through);
    assert.equal(page.data.events[0].seq, cursor.seq + 1);
    cursor = page.data.cursor; pages++;
    writeFileSync(progressFile, JSON.stringify({ after: cursor, through }), { mode: 0o600 });
    const out = openSync(progressFile, 'r'); fsyncSync(out); closeSync(out);
  }
  result.collector = { interruption: 'actual Node 24 collector SIGKILL after durable batch, before progress advance', interruptedPageReplayedIdentically: true, resumedWithoutGaps: true, frozenHead: through.seq, pages, externalSink: 'disposable fixture, not a production collector' };

  // Actual rejected requests must coalesce to one bounded, sanitized summary.
  for (let i = 0; i < 512; i++) assert.equal((await f.call('status', {}, 'synthetic-bad-credential')).status, 401);
  await pause(31000);
  const lines = f.logs.split('\n').filter(line => line.includes('request_rejections')).map(line => JSON.parse(line));
  assert.ok(lines.length >= 1 && lines.length <= 2);
  assert.equal(lines.reduce((n, line) => n + line.unauthorized, 0), 512);
  assert.ok(lines.every(line => JSON.stringify(line).length < 512 && line.droppedIntervals === 0));
  assert.ok(!f.logs.includes('synthetic-bad-credential'));
  result.diagnostics = { requests: 512, summaries: lines, maximumSummaryBytes: Math.max(...lines.map(line => Buffer.byteLength(JSON.stringify(line)))), rawCredentialAbsent: true };
  memory.push(rss()); result.idleRssBytes = Math.max(...memory);
  assert.ok(result.idleRssBytes <= budgets.small.idleRssBytes); assert.ok(startup.ms <= budgets.small.startupMs);

  const short = await f.token({ expiresInSeconds: 1 });
  assert.equal((await f.call('status', {}, short.token)).status, 200); await pause(1100);
  assert.equal((await f.call('status', {}, short.token)).status, 401);
  const journalBeforeCrash = statSync(journal).size;
  await f.stop('SIGKILL'); removeCrashSocket(f); f.logs = ''; const restarted = await elapsed(() => f.start());
  assert.equal(readFileSync(syncFile, 'utf8'), 'synthetic-sync');
  assert.equal((await f.call('secrets/resolve', { scope, selector: { name: 'small-0' } }, token.token)).data.value, 'y'.repeat(1024));
  result.sync.persistedAcrossProcessRestart = true;
  assert.ok(restarted.ms <= budgets.small.startupMs);
  result.crash = { signal: 'SIGKILL', restartMs: restarted.ms, committedValueRetained: true, journalBeforeCrashBytes: journalBeforeCrash };
  // Exercise existing signal evaluation responsibilities with actual status and
  // summaries, and negative collector/disk/clock/drop fixtures outside the core.
  const signals = (s: { lag: number; clock: number; free: number; drops: number; age: number; expiry: number; size: number }) => ({
    collectorLag: s.lag > budgets.monitoring.collectorLagSeconds,
    clockOffset: Math.abs(s.clock) > budgets.monitoring.clockOffsetMs,
    diskHeadroom: s.free < budgets.monitoring.minimumFreeBytes,
    droppedDiagnostics: s.drops > budgets.monitoring.dropAlertAbove,
    missingSummary: s.age > budgets.monitoring.missingSummarySeconds,
    expiry: s.expiry < budgets.monitoring.expiryWarningSeconds,
    auditGrowth: s.size >= budgets.capacity.operatingWarningBytes,
  });
  const fs = statfsSync(f.root);
  const healthy = signals({ lag: 0, clock: 0, free: fs.bavail * fs.bsize, drops: 0, age: 0, expiry: 90000, size: result.storage.databaseBytes });
  assert.ok(Object.values(healthy).every(x => !x));
  const negative = signals({ lag: 61, clock: 1001, free: 0, drops: 1, age: 61, expiry: 0, size: budgets.capacity.operatingStopBytes });
  assert.ok(Object.values(negative).every(Boolean));
  const clock = spawnSync('timedatectl', ['timesync-status'], { encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' } });
  const offset = /^\s*Offset:\s*([+-]?[\d.]+)(us|µs|ms|s)\s*$/m.exec(clock.stdout);
  assert.ok(offset, 'Actual NTP offset unavailable');
  const offsetMs = Number(offset[1]) * (offset[2] === 's' ? 1000 : offset[2] === 'ms' ? 1 : 0.001);
  assert.ok(Math.abs(offsetMs) <= budgets.monitoring.clockOffsetMs);
  result.monitoring = { ntpOffsetMs: offsetMs, ntpStatus: clock.stdout.trim(), healthy, negative, evaluator: 'disposable qualification assertions, not installed monitoring', observedTime: new Date().toISOString(), clockStatus: spawnSync('timedatectl', ['show', '-p', 'NTPSynchronized', '-p', 'TimeUSec'], { encoding: 'utf8' }).stdout.trim(), clockOffsetMeasured: true, blockedStderrDropBranch: 'not forced; observed zero drops' };
  result.passed = true;
  mkdirSync('test-results', { recursive: true }); writeFileSync('test-results/linux-core.json', JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally { await f.close(); }
