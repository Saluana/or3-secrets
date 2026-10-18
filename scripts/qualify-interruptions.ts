// External construction-stage interrupts: custody loss, incomplete admission,
// false completion, source mutation, overwrite retries and backup staging leaks.
// Existing service-crash tests cannot reach these maintenance construction stages.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Fixture, cli, scope, project } from '../tests/helpers';
const check = (value: unknown, message: string) => {
  if (!value) throw new Error(message);
};
const hash = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
const f = new Fixture();
const outcomes: unknown[] = [];
const launch = (args: string[]) => {
  const child = spawn(process.execPath, ['--no-env-file', 'src/cli.ts', ...args], {
    cwd: project,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const ended = new Promise<void>((yes) => child.once('close', () => yes()));
  return { child, ended };
};
// A tight, bounded parent-side observation loop can stop the child between real
// filesystem operations without modifying production code or injecting failures.
const interrupt = async (args: string[], observable: () => boolean) => {
  const { child, ended } = launch(args);
  let seen = false;
  try {
    const deadline = performance.now() + 5000;
    while (performance.now() < deadline) {
      if (observable()) {
        seen = true;
        break;
      }
    }
    if (seen) {
      try {
        child.kill('SIGSTOP');
      } catch {}
    }
  } finally {
    child.kill('SIGKILL');
    await ended;
  }
  return seen;
};
const nonempty = (path: string) => {
  try {
    return statSync(path).size > 0;
  } catch {
    return false;
  }
};
try {
  await f.start();
  const t = await f.token();
  for (let n = 0; n < 300; n++)
    check(
      (
        await f.call(
          'secrets/put',
          {
            scope,
            name: `interrupt-${n}`,
            value: 'synthetic-construction-secret',
            expectedRevision: 0,
          },
          t.token,
        )
      ).status === 200,
      'Source setup failed',
    );
  await f.stop();
  const backup = join(f.root, 'source.backup');
  check(
    cli(['backup', '--vault-dir', f.vault, '--key-file', f.key, '--out-file', backup]).status === 0,
    'Source backup failed',
  );
  const sourceHash = hash(join(f.vault, 'vault.sqlite'));
  for (const operation of ['init', 'restore', 'rekey'] as const) {
    const argumentsFor = (prefix: string) => {
      const destination = join(f.root, prefix),
        key = join(f.root, prefix + '.key'),
        operator = join(f.root, prefix + '.token');
      const args =
        operation === 'init'
          ? ['init', '--vault-dir', destination, '--key-file', key, '--operator-file', operator]
          : [
              operation,
              ...(operation === 'restore' ? ['--backup-file', backup] : ['--vault-dir', f.vault]),
              '--key-file',
              f.key,
              '--destination',
              destination,
              '--new-key-file',
              key,
              '--operator-file',
              operator,
            ];
      return { args, destination, key, operator };
    };
    for (const stage of ['key', 'database', 'operator', 'complete'] as const) {
      const target = argumentsFor(`${operation}-${stage}`);
      const file = {
        key: target.key,
        database: join(target.destination, 'vault.sqlite'),
        operator: target.operator,
        complete: join(target.destination, 'complete'),
      }[stage];
      check(
        await interrupt(target.args, () => nonempty(file)),
        `${operation}/${stage} was not observed`,
      );
      let completed = false;
      try {
        completed = /^[a-f0-9]{32}\n$/.test(
          readFileSync(join(target.destination, 'complete'), 'utf8'),
        );
      } catch {}
      const admission = cli([
        'audit',
        'verify',
        '--vault-dir',
        target.destination,
        '--key-file',
        target.key,
      ]);
      check(
        completed ? admission.status === 0 : admission.status !== 0,
        `${operation}/${stage} completion disagrees with admission`,
      );
      if (completed) {
        const { child, ended } = launch([
          'serve',
          '--vault-dir',
          target.destination,
          '--key-file',
          target.key,
          '--socket',
          f.socket,
        ]);
        try {
          await new Promise<void>((yes, no) => {
            const timer = setTimeout(
              () => no(new Error('Completed destination did not start')),
              5000,
            );
            child.stdout!.once('data', () => {
              clearTimeout(timer);
              yes();
            });
          });
          const id = readFileSync(join(target.destination, 'complete'), 'utf8').trim();
          check(
            cli(['status', '--socket', f.socket, '--vault-id', id, '--token-file', target.operator])
              .status === 0,
            'Saved operator credential unusable',
          );
        } finally {
          child.kill('SIGTERM');
          await ended;
        }
      }
      check(cli(target.args).status !== 0, 'Retry overwrote existing construction custody');
      check(hash(join(f.vault, 'vault.sqlite')) === sourceHash, 'Preserved source changed');
      check(
        cli(['audit', 'verify', '--vault-dir', f.vault, '--key-file', f.key]).status === 0,
        'Preserved source unusable',
      );
      outcomes.push({
        operation,
        observedStage: stage,
        completed,
        admission: completed ? 'accepted with saved key/operator' : 'refused',
        source: 'preserved',
        samePathRetry: 'refused',
      });
    }
    const retry = argumentsFor(`${operation}-fresh-retry`);
    check(cli(retry.args).status === 0, 'Fresh-path retry failed');
    check(
      cli(['audit', 'verify', '--vault-dir', retry.destination, '--key-file', retry.key]).status ===
        0,
      'Fresh retry did not verify',
    );
  }
  const medium = join(f.root, 'backup-medium');
  mkdirSync(medium, { mode: 0o700 });
  const oldStages = new Set(readdirSync(f.vault));
  let rawStage = '';
  check(
    await interrupt(
      [
        'backup',
        '--vault-dir',
        f.vault,
        '--key-file',
        f.key,
        '--out-file',
        join(medium, 'interrupted.backup'),
      ],
      () => {
        const name = readdirSync(f.vault).find(
          (name) =>
            !oldStages.has(name) &&
            name.startsWith('.or3-backup-') &&
            nonempty(join(f.vault, name, 'snapshot.sqlite')),
        );
        if (name) rawStage = join(f.vault, name);
        return !!name;
      },
    ),
    'Raw backup staging was not observed',
  );
  check(
    statSync(rawStage).dev === statSync(f.vault).dev,
    'Raw staging left live custody filesystem',
  );
  check(
    !readdirSync(medium).some((name) => name.includes('sqlite') || name.startsWith('.or3-')),
    'Raw snapshot reached backup medium',
  );
  for (const name of readdirSync(medium))
    check(
      !readFileSync(join(medium, name)).includes(Buffer.from('interrupt-299')),
      'Metadata reached backup medium',
    );
  check(
    cli(['audit', 'verify', '--vault-dir', f.vault, '--key-file', f.key]).status === 0,
    'Backup interruption damaged source',
  );
  writeFileSync(
    join(project, 'test-results/interruptions.json'),
    JSON.stringify(
      {
        runtime: Bun.version,
        platform: process.platform,
        sourceCommit: process.env.GITHUB_SHA ?? 'working-tree',
        outcomes,
        backupRawStaging: 'live custody filesystem only',
        powerLoss: 'not qualified',
      },
      null,
      2,
    ),
  );
  console.log(
    `Construction interruption matrix passed: ${outcomes.length} observed stages; backup staging confined to live custody`,
  );
} finally {
  await f.close();
}
