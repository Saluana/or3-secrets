// Real npm lifecycle boundary. Failure catalog: missing/stale builds, dirty sources,
// unavailable/existing versions, wrong runtime, failed tests, changed payloads.
// Registry metadata is synthetic; npm itself and all build/test commands are real.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { cleanApplicationEnv } from './lib/process';

const root = resolve(import.meta.dir, '..');
const results = join(root, 'test-results');
mkdirSync(results, { recursive: true });
const work = mkdtempSync(
  process.platform === 'darwin' ? '/private/tmp/ors-publish-' : '/tmp/ors-publish-',
);
const project = join(work, 'project');
mkdirSync(project);
const env: NodeJS.ProcessEnv = {
  ...cleanApplicationEnv(process.env),
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  npm_config_userconfig: join(work, '.npmrc'),
  npm_config_cache: join(work, 'cache'),
};
writeFileSync(join(work, '.npmrc'), '');
const run = (command: string, args: string[], cwd = project, extra: NodeJS.ProcessEnv = {}) =>
  spawnSync(command, args, { cwd, env: { ...env, ...extra }, encoding: 'utf8', timeout: 180000 });
const checked = (command: string, args: string[], cwd = project) => {
  const result = run(command, args, cwd);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  return result.stdout;
};
const steps: { name: string; result: string }[] = [];
let passed = false;
try {
  const paths = checked(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    root,
  )
    .split('\0')
    .filter(Boolean);
  for (const path of paths) {
    mkdirSync(dirname(join(project, path)), { recursive: true });
    copyFileSync(join(root, path), join(project, path));
  }
  checked('git', ['init', '--quiet', '--initial-branch=main']);
  checked('git', ['config', 'user.name', 'Disposable release fixture']);
  checked('git', ['config', 'user.email', 'fixture@example.invalid']);
  checked('git', ['add', '.']);
  checked('git', ['commit', '--quiet', '-m', 'Disposable source snapshot']);
  checked('bun', ['--no-env-file', 'install', '--frozen-lockfile', '--ignore-scripts']);
  const preload = join(project, 'scripts/fixtures/publish-metadata.ts');
  const lifecycleEnv = { NODE_OPTIONS: `--import=${preload}` };
  const publish = (name: string, extra: NodeJS.ProcessEnv = {}) => {
    const result = run('npm', ['publish', '--dry-run', '--json'], project, {
      ...lifecycleEnv,
      ...extra,
    });
    writeFileSync(join(results, `publish-${name}.log`), result.stdout + result.stderr);
    return result;
  };
  const expectRejection = (name: string, message: string, extra: NodeJS.ProcessEnv = {}) => {
    const result = publish(name, extra);
    assert.notEqual(result.status, 0, `${name} must block publication`);
    assert.ok(
      (result.stdout + result.stderr).includes(message),
      `${name}: wrong failure; see publish-${name}.log`,
    );
    steps.push({ name, result: 'publication blocked' });
  };
  for (const name of ['missing-build', 'stale-build']) {
    if (name === 'stale-build')
      writeFileSync(join(project, 'dist/client.js'), 'throw new Error("stale-build-canary");\n');
    const result = publish(name);
    assert.equal(result.status, 0, result.stderr + result.stdout);
    const jsonStart = result.stdout.lastIndexOf('\n{');
    const packed = JSON.parse(result.stdout.slice(jsonStart < 0 ? 0 : jsonStart + 1));
    for (const file of [
      'dist/client.js',
      'dist/client.d.ts',
      'dist/cli.js',
      'dist/module.js',
      'dist/runtime/plugin.js',
      'LICENSE',
    ]) {
      assert.ok(
        packed.files.some((entry: { path: string }) => entry.path === file),
        `Plain npm publish must build missing ${file}`,
      );
    }
    const receipt = JSON.parse(
      readFileSync(join(project, 'test-results/package-receipt.json'), 'utf8'),
    );
    assert.equal(
      packed.integrity,
      receipt.integrity,
      'npm must publish the qualified package bytes',
    );
    assert.ok(
      !readFileSync(join(project, 'dist/client.js'), 'utf8').includes('stale-build-canary'),
    );
    steps.push({ name, result: 'rebuilt and qualified actual npm package' });
  }
  appendFileSync(join(project, 'README.md'), '\nUncommitted change\n');
  expectRejection('dirty', 'Release sources must be clean');
  checked('git', ['restore', 'README.md']);
  expectRejection('existing-version', 'Version already exists', {
    OR3_PUBLISH_FIXTURE_MODE: 'published',
  });
  expectRejection('registry-offline', 'fixture-registry-offline', {
    OR3_PUBLISH_FIXTURE_MODE: 'offline',
  });
  const bin = join(work, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'bun'), '#!/bin/sh\necho 1.3.6\n', { mode: 0o755 });
  expectRejection('wrong-runtime', 'Bun 1.3.14 required', { PATH: `${bin}:${env.PATH}` });
  writeFileSync(
    join(project, 'tests/publish-failure.test.ts'),
    "import { test } from 'bun:test';\ntest('publish gate failure', () => {\n  throw new Error('publish-gate-deliberate-failure');\n});\n",
  );
  checked('git', ['add', 'tests/publish-failure.test.ts']);
  checked('git', ['commit', '--quiet', '-m', 'Deliberately failing committed test']);
  expectRejection('failed-test', 'publish-gate-deliberate-failure');
  rmSync(join(project, 'tests/publish-failure.test.ts'));
  writeFileSync(
    join(project, 'tests/publish-drift.test.ts'),
    "import { appendFileSync } from 'node:fs';\nimport { test } from 'bun:test';\ntest('publish payload drift', () => {\n  appendFileSync('dist/client.js', '\\n// changed by test\\n');\n});\n",
  );
  checked('git', ['add', 'tests']);
  checked('git', ['commit', '--quiet', '-m', 'Deliberately change generated payload during tests']);
  expectRejection('payload-drift', 'Package files changed after qualification');
  passed = true;
  console.log(`npm publish lifecycle: ${steps.length} scenarios passed; no publication attempted`);
} finally {
  writeFileSync(
    join(results, 'publish-lifecycle.json'),
    JSON.stringify(
      {
        passed,
        metadata: 'synthetic npm registry responses',
        npm: 'real publish --dry-run',
        steps,
      },
      null,
      2,
    ),
  );
  rmSync(work, { recursive: true, force: true });
}
