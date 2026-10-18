// Actual packaged Nuxt/Nitro registration and Node-runtime socket roundtrip.
// Uses the existing OR3 host toolchain, not a production credential/deployment.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
const root = resolve(import.meta.dir, '..'), host = resolve(root, '../or3-chat');
const work = mkdtempSync(process.platform === 'darwin' ? '/private/tmp/ors-provider-' : '/tmp/ors-provider-');
const run = (cmd: string, args: string[], cwd = work) => {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120000, env: { ...process.env, PATH: `${join(process.execPath, '..')}:${process.env.PATH}`, NUXT_TELEMETRY_DISABLED: '1' } });
  if (r.status !== 0) { writeFileSync(join(root, 'test-results/provider-build.log'), r.stderr + '\n' + r.stdout); throw new Error('Provider qualification failed; see test-results/provider-build.log'); } return r.stdout;
};
let service: ReturnType<typeof spawn> | undefined, server: ReturnType<typeof spawn> | undefined;
const stop = async (child?: ReturnType<typeof spawn>) => { if (!child || child.exitCode !== null) return; await new Promise<void>(yes => { child.once('exit', () => yes()); child.kill('SIGTERM'); }); };
try {
  symlinkSync(join(host, 'node_modules'), join(work, 'node_modules'), 'dir');
  const receipt = JSON.parse(readFileSync(join(root, 'test-results/package-receipt.json'), 'utf8'));
  run('tar', ['-xf', join(root, 'test-results', receipt.artifact), '-C', work]);
  const custody = join(work, 'custody'); mkdirSync(custody, { mode: 0o700 });
  const launcher = join(work, 'package/bin/or3-secrets.mjs');
  const vault = join(custody, 'vault'), key = join(custody, 'master.key'), operator = join(custody, 'operator.token'), socket = join(custody, 'api.sock'), token = join(custody, 'service.token');
  const initialized = JSON.parse(run('node', [launcher, 'init', '--vault-dir', vault, '--key-file', key, '--operator-file', operator]));
  service = spawn(process.execPath, ['--no-env-file', join(work, 'package/dist/cli.js'), 'serve', '--vault-dir', vault, '--key-file', key, '--socket', socket], { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise<void>((yes, no) => { const timer = setTimeout(() => no(new Error('Service readiness timeout')), 5000); service!.stdout!.once('data', () => { clearTimeout(timer); yes(); }); service!.once('exit', () => { clearTimeout(timer); no(new Error('Service startup failed')); }); });
  run('node', [launcher, 'token', 'issue', '--socket', socket, '--vault-id', initialized.vaultId, '--token-file', operator, '--kind', 'service', '--namespace', 'provider', '--capabilities', 'metadata,read,write,delete', '--expires-in', '1h', '--out-file', token]);
  const app = join(work, 'app'); mkdirSync(app);
  mkdirSync(join(app, 'server/api'), { recursive: true }); mkdirSync(join(app, 'server/secrets'), { recursive: true }); mkdirSync(join(app, 'server/utils/registry'), { recursive: true });
  for (const path of ['server/secrets/registry.ts', 'server/utils/registry/create-runtime-config-registry.ts']) writeFileSync(join(app, path), readFileSync(join(host, path)));
  writeFileSync(join(app, 'nuxt.config.ts'), `export default defineNuxtConfig({devtools:{enabled:false},modules:[${JSON.stringify(join(work, 'package/dist/module.js'))}],runtimeConfig:{secrets:${JSON.stringify({ provider: 'or3-secrets', namespace: 'provider', socketPath: socket, tokenFile: token, vaultId: initialized.vaultId })}},nitro:{preset:'node-server'}})`);
  writeFileSync(join(app, 'app.vue'), '<template><main>Secret provider qualification</main></template>');
  writeFileSync(join(app, 'server/api/probe.get.ts'), `import{getActiveSecretStore}from '../secrets/registry';export default defineEventHandler(async()=>{const c=getActiveSecretStore()!;const scope={namespace:'provider',ownerUserId:'u',workspaceId:'w',consumerId:'p'};await c.put({scope,name:'probe',value:'synthetic-provider-value',expectedRevision:0});return{ok:(await c.resolve({scope,selector:{name:'probe'}})).value==='synthetic-provider-value'}})`);
  // Import is from api/ -> ../secrets, a real Nitro route, not an in-process registry mock.
  run('node', [join(host, 'node_modules/nuxt/bin/nuxt.mjs'), 'build', app], app);
  const publicFiles = run('find', [join(app, '.output/public'), '-type', 'f']).trim().split('\n');
  for (const path of publicFiles) { const bytes = readFileSync(path); if ([socket, token, key, readFileSync(token, 'utf8').trim()].some(value => bytes.includes(Buffer.from(value)))) throw new Error('Private provider configuration in browser bundle'); }
  server = spawn('node', [join(app, '.output/server/index.mjs')], { cwd: app, env: { ...process.env, NITRO_UNIX_SOCKET: join(custody, 'nuxt.sock') }, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = ''; server.stderr!.on('data', data => { logs += data; });
  await new Promise<void>((yes, no) => { const timer = setTimeout(() => no(new Error(`Nitro startup timeout: ${logs.slice(-1500)}`)), 10000); server!.stdout!.on('data', data => { if (String(data).includes('Listening')) { clearTimeout(timer); yes(); } }); server!.once('exit', () => { clearTimeout(timer); no(new Error(`Nitro exited: ${logs.slice(-1500)}`)); }); });
  const nodeProbe = `import{request}from'node:http';const req=request({socketPath:${JSON.stringify(join(custody, 'nuxt.sock'))},path:'/api/probe'},r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>{if(r.statusCode!==200||!JSON.parse(b).ok)process.exit(2)})});req.on('error',()=>process.exit(3));req.end();`;
  run('node', ['--input-type=module', '-e', nodeProbe]);
  await stop(service); service = undefined;
  // A selected outage must remain an error (the probe cannot fall back to device storage).
  const outageProbe = nodeProbe.replace("r.statusCode!==200||!JSON.parse(b).ok", 'r.statusCode<500');
  run('node', ['--input-type=module', '-e', outageProbe]);
  writeFileSync(join(root, 'test-results/provider.json'), JSON.stringify({ packagedNuxtBuild: 'passed', node: run('node', ['--version']).trim(), socketRoundtrip: 'passed', selectedOutage: 'failed closed', publicBundlePrivateInputs: 'absent', realBrowserActivationWalkthrough: 'not performed' }, null, 2));
  console.log('Packaged Nuxt provider, Node socket roundtrip, private bundle boundary and selected outage passed');
} finally { await stop(server); await stop(service); rmSync(work, { recursive: true, force: true }); }
