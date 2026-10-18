// Runs with Node's native TypeScript support; no installed dependencies or lifecycle hooks.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
assert.equal(manifest.name, '@or3/secrets');
assert.equal(manifest.private, undefined, 'Release package must be publishable');
assert.match(manifest.version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
assert.ok(
  typeof manifest.license === 'string' && manifest.license.length > 0,
  'Choose a release license',
);
assert.equal(manifest.publishConfig.access, 'public');
assert.equal(manifest.publishConfig.registry, 'https://registry.npmjs.org/');
assert.equal(process.env.GITHUB_REF, `refs/tags/v${manifest.version}`, 'Tag/version mismatch');
const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
assert.equal(process.env.GITHUB_SHA, source, 'Checkout must match the release commit');
assert.equal(
  execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim(),
  '',
  'Release sources must be clean',
);

// Only an explicit registry E404 proves absence; connectivity/auth failures must stop release.
const response = await fetch(`https://registry.npmjs.org/@or3%2fsecrets/${manifest.version}`, {
  signal: AbortSignal.timeout(15000),
  redirect: 'error',
});
assert.equal(response.status, 404, 'Version already exists or registry check failed');
const missing = await response.json();
assert.ok(
  missing === 'Not Found' ||
    (typeof missing === 'object' &&
      missing !== null &&
      ['Not found', 'version not found'].includes((missing as { error: string }).error)),
  'Unexpected registry reply',
);

const receiptDirectory = process.argv[2];
if (receiptDirectory) {
  const receipt = JSON.parse(readFileSync(join(receiptDirectory, 'package-receipt.json'), 'utf8'));
  assert.equal(receipt.packageName, manifest.name);
  assert.equal(receipt.packageVersion, manifest.version);
  assert.equal(receipt.sourceBase, source);
  assert.equal(receipt.sourceState, 'clean committed sources; not a release');
  assert.equal(receipt.cleanImportAndLauncher, 'passed');
  assert.equal(receipt.packagedServiceRoundtrip, 'passed');
  assert.equal(receipt.artifact, `or3-secrets-${manifest.version}.tgz`);
  const tarball = join(receiptDirectory, receipt.artifact);
  const bytes = readFileSync(tarball);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), receipt.artifactSha256);
  assert.equal(`sha512-${createHash('sha512').update(bytes).digest('base64')}`, receipt.integrity);
  const packed = JSON.parse(
    execFileSync('tar', ['-xOf', tarball, 'package/package.json'], { encoding: 'utf8' }),
  );
  assert.deepEqual(packed, manifest, 'Qualified artifact must contain this exact manifest');
}
console.log(`Release checks passed for ${manifest.name}@${manifest.version} (${source})`);
