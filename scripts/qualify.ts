import { stopChild } from './lib/process';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
if (Bun.version !== '1.3.14') throw new Error('Qualified Bun 1.3.14 required');
const root = resolve(import.meta.dir, '..'),
  resultDir = join(root, 'test-results');
mkdirSync(resultDir, { recursive: true });
const work = mkdtempSync(
  join(process.platform === 'darwin' ? '/private/tmp' : '/tmp', 'or3-package-'),
);
const run = (command: string, args: string[], cwd = root) => {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, PATH: `${join(process.execPath, '..')}:${process.env.PATH}` },
  });
  if (result.status !== 0)
    throw new Error(`Qualification command failed: ${command} ${args.join(' ')}\n${result.stderr}`);
  return result.stdout;
};
const hash = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
try {
  run(process.execPath, ['--no-env-file', 'scripts/build.ts']);
  run('node', ['node_modules/typescript/bin/tsc', '--emitDeclarationOnly']);
  const pack = JSON.parse(
    run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', work]),
  )[0];
  const tarball = join(work, pack.filename),
    unpack = join(work, 'clean');
  mkdirSync(unpack);
  run('tar', ['-xf', tarball, '-C', unpack]);
  const pkg = join(unpack, 'package');
  for (const file of ['client.js', 'runtime/plugin.js', 'module.js']) {
    const code = readFileSync(join(pkg, 'dist', file), 'utf8');
    if (/from\s*["']bun:|\bBun\./.test(code))
      throw new Error('Bun-only import escaped server runtime');
  }
  if (
    !readFileSync(join(pkg, 'dist/runtime/plugin.js'), 'utf8').includes(
      '~~/server/secrets/registry',
    )
  )
    throw new Error('Core registry boundary missing');
  const contents = pack.files.map((file: { path: string }) => file.path) as string[];
  for (const name of contents) {
    if (
      /\.(?:js|ts|md|json)$/.test(name) &&
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ors1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}/.test(
        readFileSync(join(pkg, name), 'utf8'),
      )
    )
      throw new Error('Credential-like material in package');
  }
  if (
    contents.some((name) =>
      /(^|\/)(node_modules|test-results|\.env|vault)(\/|$)|\.(key|token|sqlite|backup)$/.test(name),
    )
  )
    throw new Error('Private/developer state in package');
  run(
    'node',
    [join(root, 'scripts/fixtures/package-client.ts'), join(pkg, 'dist/client.js')],
    work,
  );
  run('node', [join(pkg, 'bin/or3-secrets.mjs'), '--help'], work);
  const custody = join(work, 'custody');
  mkdirSync(custody, { mode: 0o700 });
  const launcher = join(pkg, 'bin/or3-secrets.mjs'),
    vaultDir = join(custody, 'vault'),
    keyFile = join(custody, 'master.key'),
    operatorFile = join(custody, 'operator.token'),
    socketPath = join(custody, 'api.sock');
  const initialized = JSON.parse(
    run(
      'node',
      [
        launcher,
        'init',
        '--vault-dir',
        vaultDir,
        '--key-file',
        keyFile,
        '--operator-file',
        operatorFile,
      ],
      work,
    ),
  );
  const child = spawn(
    'node',
    [launcher, 'serve', '--vault-dir', vaultDir, '--key-file', keyFile, '--socket', socketPath],
    {
      cwd: work,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PATH: `${join(process.execPath, '..')}:${process.env.PATH}` },
    },
  );
  try {
    await new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(new Error('Packaged service did not start')), 5000);
      child.stdout!.once('data', () => {
        clearTimeout(timer);
        yes();
      });
      child.once('exit', () => {
        clearTimeout(timer);
        no(new Error('Packaged service exited'));
      });
    });
    const transport = ['--socket', socketPath, '--vault-id', initialized.vaultId];
    const tokenFile = join(custody, 'service.token');
    run(
      'node',
      [
        launcher,
        'token',
        'issue',
        ...transport,
        '--token-file',
        operatorFile,
        '--kind',
        'service',
        '--namespace',
        'package',
        '--capabilities',
        'metadata,read,write,delete',
        '--expires-in',
        '1h',
        '--out-file',
        tokenFile,
      ],
      work,
    );
    run(
      'node',
      [
        join(root, 'scripts/fixtures/package-client.ts'),
        join(pkg, 'dist/client.js'),
        JSON.stringify({ socketPath, tokenFile, vaultId: initialized.vaultId }),
      ],
      work,
    );
  } finally {
    await stopChild(child);
  }

  // Lockfile JSONC contains version, registry and integrity for every build dependency.
  const lock = Bun.JSONC.parse(readFileSync(join(root, 'bun.lock'), 'utf8')) as {
    packages: Record<string, [string, string, unknown, string]>;
  };
  const components = Object.entries(
    lock.packages as Record<string, [string, string, unknown, string]>,
  ).map(([name, entry]) => ({
    type: 'library',
    name,
    version: entry[0].slice(entry[0].lastIndexOf('@') + 1),
    purl: `pkg:npm/${entry[0].startsWith('@') ? '%40' + entry[0].slice(1) : entry[0]}`,
    properties: [{ name: 'or3:scope', value: 'build-only' }],
    hashes: entry[3]?.startsWith('sha512-')
      ? [{ alg: 'SHA-512', content: Buffer.from(entry[3].slice(7), 'base64').toString('hex') }]
      : [],
  }));
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { component: { type: 'application', name: '@or3/secrets', version: pack.version } },
    components,
  };
  writeFileSync(join(resultDir, 'sbom.cdx.json'), JSON.stringify(sbom, null, 2));
  const artifact = join(resultDir, pack.filename);
  writeFileSync(artifact, readFileSync(tarball));
  const receipt = {
    packageName: pack.name,
    packageVersion: pack.version,
    runtime: Bun.version,
    node: run('node', ['--version']).trim(),
    platform: process.platform,
    architecture: process.arch,
    sourceBase: run('git', ['rev-parse', 'HEAD']).trim(),
    sourceState: run('git', ['status', '--porcelain']).trim()
      ? 'working-tree changes; not a release'
      : 'clean committed sources; not a release',
    hostRevision: JSON.parse(readFileSync(join(root, 'host-compatibility.json'), 'utf8')).revision,
    lockSha256: hash(join(root, 'bun.lock')),
    artifact: pack.filename,
    artifactSha256: hash(artifact),
    integrity: pack.integrity,
    packageFiles: contents,
    productionDependencies: [],
    buildDependencyCount: components.length,
    cleanImportAndLauncher: 'passed',
    packagedServiceRoundtrip: 'passed',
    independentReview: 'not performed',
    signedRelease: 'not produced',
    generatedAt: new Date().toISOString(),
  };
  writeFileSync(join(resultDir, 'package-receipt.json'), JSON.stringify(receipt, null, 2));
  console.log(
    JSON.stringify({
      artifact: receipt.artifact,
      sha256: receipt.artifactSha256,
      files: contents.length,
      buildDependencies: components.length,
      cleanImportAndLauncher: 'passed',
      packagedServiceRoundtrip: 'passed',
    }),
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}
