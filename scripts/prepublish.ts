// npm runs this before packing a directory, including `npm publish --dry-run`.
// The CI tarball path is qualified separately and deliberately uses --ignore-scripts.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const run = (command: string, args: string[]) => {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} ${args.join(' ')} failed; nothing was published`);
};
try {
  assert.ok(Number(process.versions.node.split('.')[0]) >= 24, 'Node 24 or newer required');
  const bun = spawnSync('bun', ['--version'], { encoding: 'utf8' });
  assert.ok(
    bun.status === 0 && bun.stdout.trim() === manifest.engines.bun,
    `Bun ${manifest.engines.bun} required on PATH; install the qualified runtime before publishing`,
  );
  run(process.execPath, ['scripts/check-release.ts', '--manual']);
  run('bun', ['--no-env-file', 'install', '--frozen-lockfile', '--ignore-scripts']);
  // Package qualification owns the clean rebuild, declarations and packaged CLI/service smoke.
  run('bun', ['--no-env-file', 'scripts/qualify.ts']);
  run('bun', ['--no-env-file', 'run', 'typecheck']);
  run('bun', ['--no-env-file', 'run', 'format:check']);
  run('bun', ['--no-env-file', 'run', 'test']);
  run(process.execPath, ['scripts/check-release.ts', '--manual', 'test-results']);
  // Verify the directory npm is about to pack, not just the earlier qualification tarball.
  const staging = mkdtempSync(join(tmpdir(), 'or3-prepublish-'));
  try {
    const [packed] = JSON.parse(
      execFileSync(
        'npm',
        ['pack', '--ignore-scripts', '--dry-run=false', '--json', '--pack-destination', staging],
        {
          cwd: root,
          encoding: 'utf8',
          timeout: 60000,
        },
      ),
    );
    const receipt = JSON.parse(
      readFileSync(join(root, 'test-results/package-receipt.json'), 'utf8'),
    );
    assert.equal(packed.integrity, receipt.integrity, 'Package files changed after qualification');
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  console.log(
    `Ready to publish ${manifest.name}@${manifest.version}; npm will now pack the validated build`,
  );
} catch (error) {
  console.error(`Publish blocked: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
