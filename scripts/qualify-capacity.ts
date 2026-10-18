// Offline format fixture: genuine aged authenticated history, one 1 GiB SQLite file.
// This does not expose a service API for manufacturing audit rows.
import { Database } from 'bun:sqlite';
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  statSync,
  statfsSync,
  rmSync,
  existsSync,
} from 'node:fs';
import { join } from 'node:path';
import { derive, mac } from '../src/crypto';
import { Vault } from '../src/store';
import { backup, restore, rekey, BACKUP_OVERHEAD } from '../src/maintenance';
import { MAX_SNAPSHOT, parseInput, type Operation } from '../src/protocol';
import { Fixture, cli, scope } from './lib/fixture';
// ARM64 local budgets remain unchanged. CI's x64-baseline Bun build has a
// separate ceiling and must also pass a same-host, same-fixture base comparison.
// Neither profile chooses a production SLO; the job timeout stays unchanged.
const baselineDir = process.env.OR3_SECRETS_CAPACITY_BASELINE;
const ciBaseline =
  process.platform === 'linux' && process.arch === 'x64' && process.env.CI === 'true';
if (ciBaseline && !baselineDir)
  throw new Error('x64 CI capacity requires a pinned baseline checkout');
const factor = ciBaseline ? 4 : 1;
const budgets = {
  verify: 45000 * factor,
  backup: 60000 * factor,
  restore: 120000 * factor,
  rekey: 120000 * factor,
  peakRssBytes: 512 * 1024 ** 2,
};
const fixture = new Fixture(),
  root = fixture.root;
const vaultDir = fixture.vault,
  keyFile = fixture.key;
let timings: Record<string, number> = {};
const staged = process.argv.includes('--stages');
const targets = staged ? [64, 256, 768, 1024].map((mib) => mib * 1024 ** 2) : [MAX_SNAPSHOT];
const stages: Record<string, unknown>[] = [];
const valueSizes = [128, 1024, 8192, 32768];
const value = (n: number, revision = 1) =>
  `synthetic-capacity-${n}-${revision}:`.padEnd(valueSizes[n % valueSizes.length]!, 'x');
function measure<T>(name: string, action: () => T): T {
  console.log(JSON.stringify({ phase: name, state: 'started' }));
  const started = performance.now();
  try {
    return action();
  } finally {
    timings[name] = Math.round(performance.now() - started);
    console.log(JSON.stringify({ phase: name, elapsedMs: timings[name] }));
  }
}
try {
  const storage = statfsSync(root);
  if (storage.bavail * storage.bsize < 6 * MAX_SNAPSHOT)
    throw new Error('Capacity qualification needs 6 GiB free disposable storage');
  const init = { vaultId: fixture.vaultId },
    operator = fixture.operator;
  await fixture.start();
  const token = await fixture.token();
  const perform = async (
    operation: Operation,
    input: Record<string, unknown>,
    credential = token.token,
  ) => {
    const result = await fixture.call(operation, input, credential);
    if (result.status !== 200) throw new Error(`Mixed capacity seed failed: ${operation}`);
    return result.data;
  };
  const seedStarted = performance.now();
  console.log(JSON.stringify({ phase: 'seedMixedInventory', state: 'started' }));
  for (let n = 0; n < 2000; n++)
    await perform('secrets/put', {
      scope,
      name: `mixed-${n}`,
      value: value(n),
      expectedRevision: 0,
    });
  for (let n = 0; n < 500; n++)
    await perform('secrets/delete', { scope, name: `mixed-${n}`, expectedRevision: 1 });
  for (let n = 1500; n < 2000; n++)
    await perform('secrets/put', {
      scope,
      name: `mixed-${n}`,
      value: value(n, 2),
      expectedRevision: 1,
    });
  for (let n = 0; n < 500; n++) {
    const issued = await perform(
      'tokens/issue',
      {
        kind: 'service',
        namespace: scope.namespace,
        capabilities: ['read'],
        expiresInSeconds: n < 250 ? 1 : 3600,
      },
      operator,
    );
    if (n >= 250) await perform('tokens/revoke', { id: issued.meta.id }, operator);
  }
  for (let n = 0; n < 100; n++)
    await perform('secrets/resolve', { scope, selector: { name: 'mixed-1999' } });
  timings.seedMixedInventory = Math.round(performance.now() - seedStarted);
  console.log(
    JSON.stringify({ phase: 'seedMixedInventory', elapsedMs: timings.seedMixedInventory }),
  );
  await fixture.stop();
  const verified = cli(['audit', 'verify', '--vault-dir', vaultDir, '--key-file', keyFile]);
  if (verified.status !== 0) throw new Error('Seeded capacity inventory failed verification');
  const checkpoint = JSON.parse(verified.stdout);
  const key = derive(readFileSync(keyFile), init.vaultId, 'audit');
  const dbPath = join(vaultDir, 'vault.sqlite');
  let seq = checkpoint.seq,
    previous = checkpoint.mac;
  for (const target of targets) {
    timings = {};
    const db = new Database(dbPath);
    // The production schema remains exact; an offline fixture limits allocation to exactly 1 GiB.
    db.exec(
      `PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA max_page_count=${target / 4096}`,
    );
    const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
    measure('ageFixture', () => {
      for (const batch of [2000, 100, 1]) {
        let full = false;
        while (!full) {
          const beforeSeq = seq,
            beforeMac = previous;
          db.exec('BEGIN');
          try {
            for (let n = 0; n < batch; n++) {
              const payload = JSON.stringify({
                at: '2020-01-01T00:00:00.000Z',
                operation: 'status',
                outcome: 'success',
                requestId: 'r'.repeat(128),
                actorId: 'a'.repeat(128),
                activationId: 'x'.repeat(128),
              });
              const next = seq + 1,
                hash = mac(key, 'event', [next, previous, payload]);
              insert.run(next, previous, payload, hash);
              seq = next;
              previous = hash;
            }
            db.exec('COMMIT');
          } catch (error) {
            try {
              db.exec('ROLLBACK');
            } catch {
              /* SQLITE_FULL may already roll back. */
            }
            seq = beforeSeq;
            previous = beforeMac;
            if (!String((error as Error).message).includes('full')) throw error;
            full = true;
          }
        }
      }
      // Check the exact snapshot bound without changing the production schema.
      const pages = (db.query('PRAGMA page_count').get() as { page_count: number }).page_count;
      if (pages * 4096 !== target) throw new Error('Fixture did not reach exact cap');
    });
    db.close();
    const size = statSync(dbPath).size;
    if (baselineDir && target === MAX_SNAPSHOT) {
      const { Vault: BaseVault }: { Vault: typeof Vault } = await import(
        join(baselineDir, 'src/store.ts')
      );
      measure('baselineVerify', () => {
        const v = BaseVault.open(vaultDir, keyFile);
        try {
          return v.verify();
        } finally {
          v.close();
        }
      });
    }
    let liveRefusal = '';
    const receipt = measure('verify', () => {
      const v = Vault.open(vaultDir, keyFile);
      try {
        try {
          if (target === MAX_SNAPSHOT)
            v.perform(
              'status',
              parseInput('status', { context: { requestId: 'capacity-live-refusal' } }),
              operator,
              init.vaultId,
            );
        } catch (error) {
          liveRefusal = (error as { code: string }).code;
        }
        if (liveRefusal !== (target === MAX_SNAPSHOT ? 'capacity_reached' : ''))
          throw new Error('Unexpected capacity admission result');
        return v.verify();
      } finally {
        v.close();
      }
    });
    seq = receipt.seq;
    previous = receipt.mac;
    const backupFile = join(root, 'snapshot.backup');
    measure('backup', () => backup({ vaultDir, keyFile, outFile: backupFile, receipt }));
    measure('restore', () =>
      restore({
        backupFile,
        keyFile,
        destination: join(root, 'restored'),
        newKeyFile: join(root, 'restored.key'),
        operatorFile: join(root, 'restored.token'),
        receipt,
      }),
    );
    measure('rekey', () =>
      rekey({
        vaultDir,
        keyFile,
        destination: join(root, 'rekeyed'),
        newKeyFile: join(root, 'rekeyed.key'),
        operatorFile: join(root, 'rekeyed.token'),
        receipt,
      }),
    );
    if (target < MAX_SNAPSHOT)
      measure('validateRecovered', () => {
        for (const name of ['restored', 'rekeyed']) {
          const v = Vault.open(join(root, name), join(root, `${name}.key`));
          const call = (op: Operation, body: Record<string, unknown>, credential: string) =>
            v.perform(
              op,
              parseInput(op, { context: { requestId: 'capacity-recovered' }, ...body }),
              credential,
              init.vaultId,
            ) as any;
          try {
            let oldDenied = false;
            try {
              call('status', {}, operator);
            } catch (error) {
              oldDenied = (error as { code: string }).code === 'unauthorized';
            }
            if (!oldDenied) throw new Error('Copied authority admitted after recovery');
            const freshOperator = readFileSync(join(root, `${name}.token`), 'utf8').trim();
            const fresh = call(
              'tokens/issue',
              {
                kind: 'service',
                namespace: scope.namespace,
                capabilities: ['read', 'metadata'],
                expiresInSeconds: 3600,
              },
              freshOperator,
            );
            for (const n of [500, 501, 502, 503, 1999]) {
              const revision = n >= 1500 ? 2 : 1;
              const recovered = call(
                'secrets/resolve',
                { scope, selector: { name: `mixed-${n}` } },
                fresh.token,
              );
              if (
                recovered.value !== value(n, revision) ||
                recovered.meta.ref.revision !== revision
              )
                throw new Error('Recovered exact value or revision changed');
            }
            if (
              call('secrets/inspect', { scope, name: 'mixed-0' }, fresh.token).state !== 'deleted'
            )
              throw new Error('Recovered tombstone lost');
            if (call('status', {}, freshOperator).storage.wrapCount !== 1500)
              throw new Error('Recovery wrapping count changed');
            v.verify();
          } finally {
            v.close();
          }
        }
      });
    // Bun 1.3.14 exposes native getrusage().ru_maxrss directly: Darwin bytes,
    // unlike Node's normalized KiB. Linux /proc reports KiB and is converted.
    // See tagged src/jsc/bindings/BunProcess.cpp Process_functionResourceUsage.
    const peakRssBytes =
      process.platform === 'linux'
        ? Number(/^VmHWM:\s+(\d+) kB$/m.exec(readFileSync('/proc/self/status', 'utf8'))?.[1]) * 1024
        : process.resourceUsage().maxRSS;
    const failures: string[] = [];
    for (const name of ['verify', 'backup', 'restore', 'rekey'] as const)
      if (timings[name]! > budgets[name])
        failures.push(`${name} exceeded the capacity profile budget`);
    if (!Number.isFinite(peakRssBytes) || peakRssBytes > budgets.peakRssBytes)
      failures.push('Capacity peak RSS exceeded its budget');
    const verificationRatio =
      baselineDir && target === MAX_SNAPSHOT ? timings.verify! / timings.baselineVerify! : null;
    if (verificationRatio !== null && verificationRatio > 1.2)
      failures.push('Verification regressed more than 20% against the same-host baseline');
    const result = {
      runtime: Bun.version,
      platform: process.platform,
      architecture: process.arch,
      budgetProfile: ciBaseline
        ? 'linux-x64-baseline CI, with same-host comparison'
        : 'local reference (measured on ARM64)',
      baselineRevision: baselineDir ? '0888b45cea9428e9daf769a976b45d082187c3e1' : null,
      verificationRatio,
      failures,
      profile: {
        liveSecrets: 1500,
        tombstones: 500,
        updatedSecrets: 500,
        expiredTokens: 250,
        revokedTokens: 250,
        valueSizes,
      },
      budgets,
      peakRssBytes,
      agedEvents: seq,
      databaseBytes: size,
      capBytes: MAX_SNAPSHOT,
      backupBytes: statSync(backupFile).size,
      restoredBytes: statSync(join(root, 'restored/vault.sqlite')).size,
      rekeyedBytes: statSync(join(root, 'rekeyed/vault.sqlite')).size,
      exactEnvelopeSize: statSync(backupFile).size === size + BACKUP_OVERHEAD,
      liveAdmission:
        target === MAX_SNAPSHOT ? liveRefusal : 'not measured (offline intermediate stage)',
      timingsMs: timings,
      rssBytesAtFinish: process.memoryUsage().rss,
      powerLoss: 'not qualified',
      deploymentAcceptance: false,
    };
    if (!result.exactEnvelopeSize) failures.push('Incorrect backup envelope size');
    stages.push(result);
    mkdirSync('test-results', { recursive: true });
    writeFileSync(
      'test-results/capacity.json',
      JSON.stringify({ ...result, stages, complete: false }, null, 2),
    );
    console.log(JSON.stringify(result));
    if (failures.length) throw new Error(failures.join('; '));
    for (const name of [
      'snapshot.backup',
      'restored',
      'restored.key',
      'restored.token',
      'rekeyed',
      'rekeyed.key',
      'rekeyed.token',
    ])
      rmSync(join(root, name), { recursive: true, force: true });
  }
  // A valid authenticated input beyond the format bound must refuse before any
  // backup output exists. Reuse the exact-cap fixture rather than aging it twice.
  const db = new Database(dbPath);
  try {
    db.exec('PRAGMA max_page_count=2147483646');
    const insert = db.query('INSERT INTO audit VALUES(?,?,?,?)');
    while (statSync(dbPath).size <= MAX_SNAPSHOT) {
      db.transaction(() => {
        for (let n = 0; n < 5; n++) {
          const payload = JSON.stringify({
            at: '2020-01-01T00:00:00.000Z',
            operation: 'status',
            outcome: 'success',
            requestId: 'oversize',
          });
          const next = seq + 1,
            hash = mac(key, 'event', [next, previous, payload]);
          insert.run(next, previous, payload, hash);
          seq = next;
          previous = hash;
        }
      })();
    }
  } finally {
    db.close();
    key.fill(0);
  }
  const outFile = join(root, 'oversize.backup');
  let code = '';
  try {
    backup({ vaultDir, keyFile, outFile });
  } catch (error) {
    code = (error as { code: string }).code;
  }
  const oversize = {
    bytes: statSync(dbPath).size,
    code,
    refusedBeforeOutput: code === 'too_large' && !existsSync(outFile),
  };
  const result = { ...stages.at(-1), stages, oversize, complete: oversize.refusedBeforeOutput };
  writeFileSync('test-results/capacity.json', JSON.stringify(result, null, 2));
  if (!oversize.refusedBeforeOutput) throw new Error('Oversize snapshot was admitted');
  console.log(JSON.stringify({ staged, oversize, receipt: 'test-results/capacity.json' }));
} finally {
  await fixture.close();
}
