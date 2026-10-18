// One bounded OR3 workload, with budgets selected before measurement. It covers
// live inventory, tombstones, revoked/expired tokens, audit growth, HTTP read
// latency and maintenance; the aged-history benchmark has a different owner.
import { statSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { Fixture, cli, scope, project } from '../tests/helpers';
const budgets = {
  startupMs: 5000,
  rssBytes: 512 * 1024 ** 2,
  httpReadP95Ms: 100,
  backupMs: 30000,
  restoreMs: 60000,
  rekeyMs: 60000,
};
const f = new Fixture();
const measurements: Record<string, number> = {};
const check = (value: unknown, message: string) => {
  if (!value) throw new Error(message);
};
const timed = (name: string, args: string[]) => {
  const began = performance.now();
  const result = spawnSync(process.execPath, ['--no-env-file', 'src/cli.ts', ...args], {
    cwd: project,
    encoding: 'utf8',
    timeout: 65000,
  });
  measurements[name] = Math.round(performance.now() - began);
  check(result.status === 0, `${name} failed: ${result.stderr}`);
};
try {
  await f.start();
  const token = await f.token();
  const value = 'synthetic-inventory-value-'.repeat(10);
  for (let n = 0; n < 2000; n++)
    check(
      (
        await f.call(
          'secrets/put',
          { scope, name: `profile-${n}`, value, expectedRevision: 0 },
          token.token,
        )
      ).status === 200,
      'Inventory setup failed',
    );
  for (let n = 0; n < 500; n++)
    check(
      (
        await f.call(
          'secrets/delete',
          { scope, name: `profile-${n}`, expectedRevision: 1 },
          token.token,
        )
      ).status === 200,
      'Tombstone setup failed',
    );
  for (let n = 0; n < 500; n++) {
    const t = await f.call('tokens/issue', {
      kind: 'service',
      namespace: 'test',
      capabilities: ['read'],
      expiresInSeconds: n < 250 ? 1 : 3600,
    });
    check(t.status === 200, 'Token setup failed');
    if (n >= 250)
      check(
        (await f.call('tokens/revoke', { id: t.data.meta.id })).status === 200,
        'Revocation setup failed',
      );
  }
  // Reads, status, denials and bounded collection all contribute actual audit.
  for (let n = 0; n < 1000; n++) {
    const denied = n % 10 === 0;
    const r = await f.call(
      n % 5 === 0 && !denied ? 'status' : 'secrets/resolve',
      {
        ...(n % 5 === 0 && !denied
          ? {}
          : {
              scope: denied ? { ...scope, namespace: 'other' } : scope,
              selector: { name: 'profile-1999' },
            }),
      },
      token.token,
    );
    check(r.status === (denied ? 403 : 200), 'Mixed read/denial failed');
  }
  const audit = await f.token({
    kind: 'audit-reader',
    namespace: undefined,
    capabilities: ['audit'],
  });
  check(
    (await f.call('audit/read', { after: null, limit: 100 }, audit.token)).status === 200,
    'Collection failed',
  );
  await f.stop();
  await Bun.sleep(1100);
  f.logs = '';
  const began = performance.now();
  await f.start();
  measurements.startupMs = Math.round(performance.now() - began);
  const latencies: number[] = [];
  for (let n = 0; n < 100; n++) {
    const start = performance.now();
    check(
      (await f.call('secrets/resolve', { scope, selector: { name: 'profile-1999' } }, token.token))
        .data.value === value,
      'Read lost exact value',
    );
    latencies.push(performance.now() - start);
  }
  latencies.sort((a, b) => a - b);
  measurements.httpReadP95Ms = Math.ceil(latencies[94]!);
  if (process.platform === 'linux') {
    const rss = /^VmRSS:\s+(\d+) kB$/m.exec(readFileSync(`/proc/${f.child!.pid}/status`, 'utf8'));
    check(rss, 'Service RSS unavailable');
    measurements.rssBytes = Number(rss![1]) * 1024;
  } else {
    const rss = spawnSync('ps', ['-o', 'rss=', '-p', String(f.child!.pid)], { encoding: 'utf8' });
    check(rss.status === 0 && Number(rss.stdout.trim()) > 0, 'Service RSS unavailable');
    measurements.rssBytes = Number(rss.stdout.trim()) * 1024;
  }
  await f.stop();
  const databaseBytes = statSync(join(f.vault, 'vault.sqlite')).size;
  const backup = join(f.root, 'profile.backup');
  timed('backupMs', ['backup', '--vault-dir', f.vault, '--key-file', f.key, '--out-file', backup]);
  timed('restoreMs', [
    'restore',
    '--backup-file',
    backup,
    '--key-file',
    f.key,
    '--destination',
    join(f.root, 'restore'),
    '--new-key-file',
    join(f.root, 'restore.key'),
    '--operator-file',
    join(f.root, 'restore.token'),
  ]);
  timed('rekeyMs', [
    'rekey',
    '--vault-dir',
    f.vault,
    '--key-file',
    f.key,
    '--destination',
    join(f.root, 'rekey'),
    '--new-key-file',
    join(f.root, 'rekey.key'),
    '--operator-file',
    join(f.root, 'rekey.token'),
  ]);
  // Service steady-state RSS after startup/read sampling; maintenance peak RSS
  // is a separate deployment measurement, not inferred from the parent process.
  for (const [key, bound] of Object.entries(budgets))
    check(measurements[key]! <= bound, `${key} exceeded the declared budget`);
  const recoveredSizes = ['restore', 'rekey'].map(
    (name) => statSync(join(f.root, name, 'vault.sqlite')).size,
  );
  check(
    recoveredSizes.every((size) => size + 1024 ** 2 < 960 * 1024 ** 2),
    'Recovered vault reached unsupported capacity',
  );
  writeFileSync(
    join(project, 'test-results/profile.json'),
    JSON.stringify(
      {
        runtime: Bun.version,
        platform: process.platform,
        profile: {
          liveSecrets: 1500,
          tombstones: 500,
          expiredTokens: 250,
          revokedTokens: 250,
          mixedRequests: 1000,
          sampleHttpReads: 100,
        },
        budgets,
        measurements,
        databaseBytes,
        recoveredSizes,
        deploymentAcceptance: false,
      },
      null,
      2,
    ),
  );
  console.log(JSON.stringify({ budgets, measurements, databaseBytes, recoveredSizes }));
} finally {
  await f.close();
}
