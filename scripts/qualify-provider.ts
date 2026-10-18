// Packaged Nuxt/Node boundary: ambient credentials must receive zero calls;
// a stable read must succeed, report unavailable during outage, then recover.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Database } from 'bun:sqlite';
const root = resolve(import.meta.dir, '..'),
  host = resolve(process.env.OR3_SECRETS_HOST_DIR ?? join(root, '../or3-chat'));
const work = mkdtempSync(
  process.platform === 'darwin' ? '/private/tmp/ors-provider-' : '/tmp/ors-provider-',
);
const cleanEnv = (input: NodeJS.ProcessEnv) => {
  const result = { ...input };
  for (const key of Object.keys(result))
    if (
      /^(OR3_|NUXT_|NITRO_|VITE_|AUTH_|CLERK_|CONVEX_|OPENROUTER_)/.test(key) ||
      ['NODE_OPTIONS', 'DOTENV_CONFIG_PATH'].includes(key)
    )
      delete result[key];
  return {
    ...result,
    PATH: `${join(process.execPath, '..')}:${process.env.PATH}`,
    NUXT_TELEMETRY_DISABLED: '1',
  };
};
let env: NodeJS.ProcessEnv = cleanEnv(process.env);
const run = (cmd: string, args: string[], cwd = work, input?: string) => {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120000, env, input });
  if (r.status !== 0) {
    writeFileSync(join(root, 'test-results/provider-build.log'), r.stderr + '\n' + r.stdout, {
      mode: 0o600,
    });
    throw new Error('Provider qualification failed; see test-results/provider-build.log');
  }
  return r.stdout;
};
const stop = async (child?: ReturnType<typeof spawn>) => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((yes) => {
    child.once('exit', () => yes());
    child.kill('SIGTERM');
  });
};
let service: ReturnType<typeof spawn> | undefined,
  server: ReturnType<typeof spawn> | undefined,
  ambient: ReturnType<typeof spawn> | undefined;
try {
  symlinkSync(join(host, 'node_modules'), join(work, 'node_modules'), 'dir');
  const receipt = JSON.parse(readFileSync(join(root, 'test-results/package-receipt.json'), 'utf8'));
  const pin = JSON.parse(readFileSync(join(root, 'host-compatibility.json'), 'utf8'));
  if (!/^[a-f0-9]{40}$/.test(pin.revision))
    throw new Error('Pin a committed compatible host revision');
  const artifact = join(root, 'test-results', receipt.artifact);
  if (createHash('sha256').update(readFileSync(artifact)).digest('hex') !== receipt.artifactSha256)
    throw new Error('Package checksum mismatch');
  run('tar', ['-xf', artifact, '-C', work]);
  const launcher = join(work, 'package/bin/or3-secrets.mjs');
  const fixture = (name: string) => {
    const dir = join(work, name);
    mkdirSync(dir, { mode: 0o700 });
    const vault = join(dir, 'vault'),
      key = join(dir, 'master.key'),
      operator = join(dir, 'operator.token'),
      socket = join(dir, 'api.sock'),
      token = join(dir, 'service.token');
    const initialized = JSON.parse(
      run('node', [
        launcher,
        'init',
        '--vault-dir',
        vault,
        '--key-file',
        key,
        '--operator-file',
        operator,
      ]),
    );
    return { dir, vault, key, operator, socket, token, id: initialized.vaultId };
  };
  const real = fixture('custody'),
    other = fixture('ambient');
  const start = async (f: typeof real) => {
    const child = spawn(
      process.execPath,
      [
        '--no-env-file',
        join(work, 'package/dist/cli.js'),
        'serve',
        '--vault-dir',
        f.vault,
        '--key-file',
        f.key,
        '--socket',
        f.socket,
      ],
      { env, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    await new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(new Error('Service readiness timeout')), 5000);
      child.stdout!.once('data', () => {
        clearTimeout(timer);
        yes();
      });
      child.once('exit', () => {
        clearTimeout(timer);
        no(new Error('Service startup failed'));
      });
    });
    return child;
  };
  const issue = (f: typeof real) =>
    run('node', [
      launcher,
      'token',
      'issue',
      '--socket',
      f.socket,
      '--vault-id',
      f.id,
      '--token-file',
      f.operator,
      '--kind',
      'service',
      '--namespace',
      'provider',
      '--capabilities',
      'metadata,read,write,delete',
      '--expires-in',
      '1h',
      '--out-file',
      f.token,
    ]);
  service = await start(real);
  ambient = await start(other);
  issue(real);
  issue(other);
  // Deliberately supply a fully capable second synthetic vault as ambient config.
  env = cleanEnv({
    ...process.env,
    NUXT_SECRETS_PROVIDER: 'or3-secrets',
    NUXT_SECRETS_NAMESPACE: 'provider',
    NUXT_SECRETS_SOCKET_PATH: other.socket,
    NUXT_SECRETS_TOKEN_FILE: other.token,
    NUXT_SECRETS_VAULT_ID: other.id,
    NUXT_SECRETS_SERVICE_UID: String(process.getuid!()),
  });
  run(
    'node',
    [
      launcher,
      'put',
      '--socket',
      real.socket,
      '--vault-id',
      real.id,
      '--token-file',
      real.token,
      '--namespace',
      'provider',
      '--owner-user-id',
      'u',
      '--workspace-id',
      'w',
      '--consumer-id',
      'p',
      '--name',
      'probe',
      '--expected-revision',
      '0',
    ],
    work,
    'synthetic-provider-value',
  );
  const app = join(work, 'app');
  mkdirSync(app);
  for (const path of ['server/api', 'server/secrets', 'server/utils/registry'])
    mkdirSync(join(app, path), { recursive: true });
  for (const path of [
    'server/secrets/registry.ts',
    'server/utils/registry/create-runtime-config-registry.ts',
  ])
    writeFileSync(join(app, path), run('git', ['-C', host, 'show', `${pin.revision}:${path}`]));
  writeFileSync(
    join(app, 'nuxt.config.ts'),
    `export default defineNuxtConfig({devtools:{enabled:false},modules:[${JSON.stringify(join(work, 'package/dist/module.js'))}],runtimeConfig:{secrets:${JSON.stringify({ provider: 'or3-secrets', namespace: 'provider', socketPath: real.socket, tokenFile: real.token, vaultId: real.id, serviceUid: String(process.getuid!()) })}},nitro:{preset:'node-server'}})`,
  );
  writeFileSync(
    join(app, 'app.vue'),
    '<template><main>Secret provider qualification</main></template>',
  );
  writeFileSync(
    join(app, 'server/api/probe.get.ts'),
    `import{getActiveSecretStore}from '../secrets/registry';import{useRuntimeConfig}from '#imports';export default defineEventHandler(async()=>{if(useRuntimeConfig().secrets.vaultId!==${JSON.stringify(real.id)})throw createError({statusCode:500,statusMessage:'Fixture identity mismatch'});try{const c=getActiveSecretStore()!;await c.available();return{ok:(await c.resolve({scope:{namespace:'provider',ownerUserId:'u',workspaceId:'w',consumerId:'p'},selector:{name:'probe'}})).value==='synthetic-provider-value'}}catch(e){throw createError({statusCode:503,statusMessage:'Secret provider unavailable',data:{code:e.code}})}})`,
  );
  run('node', [join(host, 'node_modules/nuxt/bin/nuxt.mjs'), 'build', app], app);
  const publicFiles = run('find', [join(app, '.output/public'), '-type', 'f'])
    .trim()
    .split('\n');
  for (const path of publicFiles) {
    const bytes = readFileSync(path);
    if (
      [real.socket, real.token, real.key, readFileSync(real.token, 'utf8').trim()].some((value) =>
        bytes.includes(Buffer.from(value)),
      )
    )
      throw new Error('Private provider configuration in browser bundle');
  }
  server = spawn('node', [join(app, '.output/server/index.mjs')], {
    cwd: app,
    env: { ...env, NITRO_UNIX_SOCKET: join(real.dir, 'nuxt.sock') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '';
  server.stderr!.on('data', (data) => {
    logs += data;
  });
  await new Promise<void>((yes, no) => {
    const timer = setTimeout(
      () => no(new Error(`Nitro startup timeout: ${logs.slice(-1500)}`)),
      10000,
    );
    server!.stdout!.on('data', (data) => {
      if (String(data).includes('Listening')) {
        clearTimeout(timer);
        yes();
      }
    });
    server!.once('exit', () => {
      clearTimeout(timer);
      no(new Error(`Nitro exited: ${logs.slice(-1500)}`));
    });
  });
  const probe = (outage = false) =>
    run('node', [
      '--input-type=module',
      '-e',
      `import{request}from'node:http';const q=request({socketPath:${JSON.stringify(join(real.dir, 'nuxt.sock'))},path:'/api/probe'},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{const d=JSON.parse(b);if(${outage ? "r.statusCode!==503||d.data?.code!=='unavailable'" : 'r.statusCode!==200||!d.ok'})process.exit(2)})});q.on('error',()=>process.exit(3));q.end();`,
    ]);
  probe();
  await stop(service);
  service = undefined;
  probe(true);
  service = await start(real);
  probe();
  await stop(ambient);
  ambient = undefined;
  const db = new Database(join(other.vault, 'vault.sqlite'), { readonly: true });
  const seq = (db.query('SELECT max(seq) AS seq FROM audit').get() as { seq: number }).seq;
  db.close();
  if (seq !== 2) throw new Error('Ambient synthetic vault received a request');
  writeFileSync(
    join(root, 'test-results/provider.json'),
    JSON.stringify(
      {
        sourceCommit: run('git', ['-C', root, 'rev-parse', 'HEAD']).trim(),
        hostRevision: pin.revision,
        artifactSha256: receipt.artifactSha256,
        packagedNuxtBuild: 'passed',
        node: run('node', ['--version']).trim(),
        readBeforeOutage: 'passed',
        selectedOutage: '503 unavailable',
        sameReadAfterRestart: 'passed',
        ambientVaultRequests: 0,
        publicBundlePrivateInputs: 'absent',
      },
      null,
      2,
    ),
  );
  console.log(
    'Packaged provider read/outage/recovery, ambient isolation and bundle boundary passed',
  );
} finally {
  await stop(server);
  await stop(service);
  await stop(ambient);
  rmSync(work, { recursive: true, force: true });
}
