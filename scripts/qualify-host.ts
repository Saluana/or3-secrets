// Real full-app boundary: reviewed package -> trusted loader -> host.secrets ->
// authenticated Nitro route -> packaged Node client -> separate Bun vault.
// Failure owners: wrong provider selection, broken activation, scope confusion,
// lost persistence, device fallback, stale grants/handles and plaintext leakage.
// Existing route fixtures and the minimal Nuxt packaging probe cannot cover this
// composition. Only the synthetic plugin exposes its host for browser assertions;
// no test-only production API or authentication bypass is installed.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, openSync, closeSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';

const root = resolve(import.meta.dir, '..'), checkout = resolve(process.env.OR3_SECRETS_HOST_DIR ?? join(root, '../or3-chat'));
const work = mkdtempSync(process.platform === 'darwin' ? '/private/tmp/ors-host-' : '/tmp/ors-host-');
const host = join(work, 'host');
const results = join(root, 'test-results'); mkdirSync(results, { recursive: true });
const session = `ors-host-${randomBytes(6).toString('hex')}`;
const children: ChildProcess[] = [];
let browserOpened = false;
const check = (ok: unknown, reason: string) => { if (!ok) throw new Error(reason); };
const env: NodeJS.ProcessEnv = { ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH}` };
// Never inherit the checkout's real application credentials or backing stores.
for (const key of Object.keys(env)) {
  if (/^(OR3_|NUXT_|VITE_|CLERK_|CONVEX_|OPENROUTER_|AUTH_)/.test(key) || ['SSR_AUTH_ENABLED', 'PORT', 'HOST', 'NITRO_UNIX_SOCKET', 'DOTENV_CONFIG_PATH', 'NODE_OPTIONS'].includes(key)) delete env[key];
}
const run = (command: string, args: string[], input?: string) => {
  const result = spawnSync(command, args, { cwd: checkout, env, input, encoding: 'utf8', timeout: 60000, maxBuffer: 2 ** 20 });
  if (result.status !== 0) {
    if (command === 'agent-browser') spawnSync(command, ['doctor'], { env, stdio: 'ignore', timeout: 30000 });
    // Inputs may include disposable credentials. Keep diagnostic output private.
    writeFileSync(join(work, 'command-error.log'), `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`, { mode: 0o600 });
    throw new Error(`${command} ${args.slice(0, 2).join(' ')} failed; private diagnostics: ${work}`);
  }
  return result.stdout.trim();
};
const browser = (...args: string[]) => run('agent-browser', ['--session', session, ...args]);
const evaluate = (body: string) => JSON.parse(run('agent-browser', ['--session', session, 'eval', '--stdin'], `(async()=>{${body}})()`));
const requestHelpers = `const post=async(url,data,intent='admin')=>{const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json',[intent==='admin'?'x-or3-admin-intent':'x-or3-cloud-intent']:intent==='admin'?'admin':'mutation'},body:JSON.stringify(data)});const b=await r.json();if(!r.ok)throw Error(url+': '+r.status);return b};const check=(ok,why)=>{if(!ok)throw Error(why)};`;
const stop = async (child?: ChildProcess, group = false) => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>(yes => child.once('exit', () => yes()));
  try { if (group) process.kill(-child.pid!, 'SIGTERM'); else child.kill('SIGTERM'); } catch { return; }
  const timeout = setTimeout(() => { try { if (group) process.kill(-child.pid!, 'SIGKILL'); else child.kill('SIGKILL'); } catch {} }, 5000);
  try { await exited; } finally { clearTimeout(timeout); }
};
const waitFor = async (probe: () => Promise<boolean>, timeout = 120000) => {
  const until = Date.now() + timeout;
  while (Date.now() < until) { if (await probe().catch(() => false)) return; await Bun.sleep(250); }
  throw new Error(`Full-app readiness timeout; private diagnostics: ${work}`);
};
let server: ChildProcess | undefined, service: ChildProcess | undefined;
let passed = false;
try {
  check(Bun.version === '1.3.14', 'Use the pinned Bun 1.3.14 runtime');
  const hostPin = JSON.parse(readFileSync(join(root, 'host-compatibility.json'), 'utf8'));
  check(run('git', ['-C', checkout, 'rev-parse', 'HEAD']) === hostPin.revision, 'Use the pinned immutable host checkout');
  check(!run('git', ['-C', checkout, 'status', '--porcelain', '--untracked-files=no']), 'Pinned host source must be clean');
  // Generate Nuxt state only beside an export of the pinned sources. The host's
  // root tsconfig references .nuxt; a relocated buildDir can accidentally depend
  // on old generated files in a developer checkout.
  run('git', ['-C', checkout, 'archive', '--format=tar', '--output', join(work, 'host.tar'), hostPin.revision]);
  mkdirSync(host);
  run('tar', ['-xf', join(work, 'host.tar'), '-C', host]);
  symlinkSync(join(checkout, 'node_modules'), join(host, 'node_modules'), 'dir');
  const packageReceipt = JSON.parse(readFileSync(join(results, 'package-receipt.json'), 'utf8'));
  const artifact = join(results, packageReceipt.artifact);
  check(createHash('sha256').update(readFileSync(artifact)).digest('hex') === packageReceipt.artifactSha256, 'Package receipt checksum mismatch');
  run('tar', ['-xf', artifact, '-C', work]);
  symlinkSync(join(host, 'node_modules'), join(work, 'node_modules'), 'dir');
  const { zipSync, strToU8 } = await import(join(host, 'node_modules/fflate/esm/index.mjs'));
  const custody = join(work, 'custody'); mkdirSync(custody, { mode: 0o700 });
  const vault = join(custody, 'vault'), key = join(custody, 'master.key'), operator = join(custody, 'operator.token');
  const socket = join(custody, 'api.sock'), token = join(custody, 'service.token');
  const cli = (...args: string[]) => run('node', [join(work, 'package/bin/or3-secrets.mjs'), ...args]);
  const initialized = JSON.parse(cli('init', '--vault-dir', vault, '--key-file', key, '--operator-file', operator));
  const startVault = async () => {
    const child = spawn(process.execPath, ['--no-env-file', join(work, 'package/dist/cli.js'), 'serve', '--vault-dir', vault, '--key-file', key, '--socket', socket], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    await new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(new Error('Vault readiness timeout')), 10000);
      child.stdout!.once('data', () => { clearTimeout(timer); yes(); });
      child.once('exit', () => { clearTimeout(timer); no(new Error('Vault startup failed')); });
    });
    return child;
  };
  service = await startVault();
  cli('token', 'issue', '--socket', socket, '--vault-id', initialized.vaultId, '--token-file', operator, '--kind', 'service', '--namespace', 'host-e2e', '--capabilities', 'metadata,read,write,delete', '--expires-in', '1h', '--out-file', token);
  const profile = join(work, 'profile');
  for (const name of ['auth', 'sqlite', 'storage', 'admin', 'extensions']) mkdirSync(join(profile, name), { recursive: true, mode: 0o700 });
  const password = randomBytes(32).toString('base64url');
  writeFileSync(join(work, 'empty.env'), '');
  const layer = join(work, 'layer'); mkdirSync(layer);
  writeFileSync(join(layer, 'nuxt.config.ts'), `export default defineNuxtConfig({modules:[${JSON.stringify(join(work, 'package/dist/module.js'))}]})`);
  const listener = createServer(); await new Promise<void>(yes => listener.listen(0, '127.0.0.1', yes));
  const port = (listener.address() as { port: number }).port; await new Promise<void>(yes => listener.close(() => yes()));
  const origin = `http://127.0.0.1:${port}`;
  Object.assign(env, {
    NODE_ENV: 'development', NUXT_TELEMETRY_DISABLED: '1', DOTENV_CONFIG_PATH: join(work, 'empty.env'), SSR_AUTH_ENABLED: 'true',
    OR3_AUTH_PROVIDER: 'basic-auth', OR3_SYNC_PROVIDER: 'sqlite', OR3_SYNC_ENABLED: 'true', OR3_CLOUD_SYNC_ENABLED: 'true', OR3_STORAGE_ENABLED: 'true', OR3_CLOUD_STORAGE_ENABLED: 'true', NUXT_PUBLIC_STORAGE_PROVIDER: 'fs', OR3_LOCAL_PROVIDERS: 'true', OR3_CONNECT_ENABLED: 'false', OR3_AUTH_REGISTRATION_MODE: 'invite_only',
    OR3_ADMIN_USERNAME: 'secrets-e2e', OR3_ADMIN_PASSWORD: password, OR3_BASIC_AUTH_BOOTSTRAP_EMAIL: 'secrets-e2e@example.test', OR3_BASIC_AUTH_BOOTSTRAP_PASSWORD: password,
    OR3_BASIC_AUTH_JWT_SECRET: randomBytes(32).toString('base64url'), OR3_BASIC_AUTH_REFRESH_SECRET: randomBytes(32).toString('base64url'), OR3_STORAGE_FS_TOKEN_SECRET: randomBytes(32).toString('base64url'),
    OR3_EXTENSIONS_ROOT: join(profile, 'extensions'), OR3_SQLITE_DB_PATH: join(profile, 'sqlite/sync.sqlite'), OR3_BASIC_AUTH_DB_PATH: join(profile, 'auth/auth.sqlite'), OR3_STORAGE_FS_ROOT: join(profile, 'storage'), OR3_ADMIN_DATA_DIR: join(profile, 'admin'), OR3_PLUGIN_MODULE_LOADER_V2_ENABLED: 'true',
    NUXT_SECRETS_PROVIDER: 'or3-secrets', NUXT_SECRETS_NAMESPACE: 'host-e2e', NUXT_SECRETS_SOCKET_PATH: socket, NUXT_SECRETS_TOKEN_FILE: token, NUXT_SECRETS_VAULT_ID: initialized.vaultId,
  });
  const startHost = async () => {
    const log = openSync(join(work, 'host.log'), 'a', 0o600);
    server = spawn('node', [join(host, 'node_modules/nuxt/bin/nuxt.mjs'), 'dev', host, '--extends', layer, '--dotenv', join(work, 'empty.env'), '--host', '127.0.0.1', '--port', String(port), '--no-fork'], { cwd: host, env, stdio: ['ignore', log, log], detached: true });
    closeSync(log);
    await waitFor(async () => { check(server!.exitCode === null, 'OR3 server exited'); return (await fetch(`${origin}/api/auth/session`, { signal: AbortSignal.timeout(2000) })).ok; });
  };
  await startHost();
  console.log('Full OR3 instance ready with disposable Basic Auth, SQLite and filesystem storage');
  browserOpened = true; browser('open', `${origin}/admin/login`);
  const manifest = { manifestVersion: 2, kind: 'plugin', id: 'or3.secrets-qualification', name: 'Secrets qualification', version: '1.0.0', capabilities: [], engines: { or3: '^0.3.0', pluginApi: '^2.0.0' }, runtime: { client: { entry: 'client.mjs', format: 'esm', isolation: 'host' } }, requestedGrants: ['secrets.read', 'secrets.write', 'secrets.use'], features: { required: [], optional: [] }, dependencies: { required: [], optional: [] }, trust: 'trusted-host', settings: { version: 1 }, stateCompatibility: { version: 1, reads: { minimum: 1, maximum: 1 }, rollback: 'safe' } };
  const entry = `export default{manifest:${JSON.stringify(manifest)},setup(host){globalThis.__or3SecretQualification=host;const panel=document.createElement('div');panel.id='secrets-qualification';panel.style='position:fixed;bottom:10px;left:10px;z-index:99999;background:white;color:black;padding:16px';panel.textContent='Real trusted plugin activated';document.body.append(panel);host.onCleanup(()=>panel.remove());}}`;
  const archive = Buffer.from(zipSync({ 'or3.manifest.json': strToU8(JSON.stringify(manifest)), 'client.mjs': strToU8(entry) }));
  const setup = evaluate(`${requestHelpers}
    await post('/api/admin/auth/login',{username:'secrets-e2e',password:${JSON.stringify(password)}});
    await post('/api/basic-auth/sign-in',{email:'secrets-e2e@example.test',password:${JSON.stringify(password)}},'cloud');
    const session=await(await fetch('/api/auth/session')).json();check(session.secretStoreEnabled===true,'Provider not advertised');
    const workspaceId=session.session.workspace.id;
    const upload=await post('/api/admin/extensions/install',{zipBase64:${JSON.stringify(archive.toString('base64'))},force:true,expectedKind:'plugin',workspaceId});
    check(upload.grantReviewRequired===true,'Unreviewed package did not require consent');
    const base='/api/admin/plugins/packages/${manifest.id}';
    const review=await(await fetch(base+'/review?workspaceId='+workspaceId)).json();
    await post(base+'/grants',{workspaceId,approvedGrants:review.requestedGrants,expectedPackageDigest:review.packageDigest,expectedAuthoritySha256:review.authoritySha256});
    return {workspaceId,userId:session.session.user.id,packageDigest:upload.packageDigest};`);
  browser('open', `${origin}/admin/plugins?scope=workspace&workspaceId=${setup.workspaceId}`);
  browser('wait', '--text', 'Run browser check');
  browser('find', 'role', 'button', 'click', '--name', 'Run browser check');
  browser('wait', '--text', 'Canary passed in this browser.');
  browser('find', 'role', 'button', 'click', '--name', 'Promote');
  await waitFor(async () => evaluate(`const r=await(await fetch('/api/admin/plugins/packages/${manifest.id}/status?workspaceId=${setup.workspaceId}')).json();return {ready:r.pointer?.current?.packageDigest===${JSON.stringify(setup.packageDigest)}};`).ready, 15000);
  browser('open', `${origin}/chat`); browser('wait', '--text', 'Real trusted plugin activated');
  // Existing device/Dexie credentials belong to their existing owners. Seed the
  // actual stores through browser APIs, without adding a production test seam.
  const legacyKey = `or3.plugin.${manifest.id}.secret.legacy`;
  const openLegacyDb = `const db=await new Promise((yes,no)=>{const q=indexedDB.open('or3-db-${setup.workspaceId}');q.onsuccess=()=>yes(q.result);q.onerror=()=>no(q.error);q.onupgradeneeded=()=>{q.transaction.abort();no(Error('Workspace DB must already exist'))}});`;
  evaluate(`${requestHelpers}${openLegacyDb}
    localStorage.setItem(${JSON.stringify(legacyKey)},'synthetic-device-legacy');
    await new Promise((yes,no)=>{const t=db.transaction('kv','readwrite');t.objectStore('kv').put({id:'kv:openrouter_api_key',name:'openrouter_api_key',value:'synthetic-dexie-owner-key',deleted:false,clock:1,created_at:Date.now(),updated_at:Date.now()});t.oncomplete=yes;t.onerror=()=>no(t.error)});db.close();
    check((await globalThis.__or3SecretQualification.secrets.get('legacy')).value===null,'Provider implicitly imported device secret');return {seeded:true};`);
  const roundtrip = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;
    check((await s.set('remembered','synthetic-host-value-v1',{persistence:'remember'})).ok,'Persistent write');
    const read=await s.get('remembered'),ref=await s.ref('remembered'),status=await s.status('remembered');
    check(read.ok&&read.value==='synthetic-host-value-v1'&&ref.ok&&ref.value.revision===1&&status.ok&&status.value==='available','Persistent roundtrip');
    check((await s.set('session-only','synthetic-session-only',{persistence:'session'})).ok,'Session write');
    check((await s.get('session-only')).value==='synthetic-session-only','Session read');
    const storage=JSON.stringify({...localStorage})+JSON.stringify({...sessionStorage});check(!storage.includes('synthetic-host-value')&&!storage.includes('synthetic-session-only'),'Browser storage plaintext');
    return {remembered:true,reference:true,status:true,sessionOnly:true,browserStoragePlaintext:false};`);
  browser('reload'); browser('wait', '--text', 'Real trusted plugin activated');
  const reload = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;
    check((await s.get('remembered')).value==='synthetic-host-value-v1','Reload lost remembered value');
    const session=await s.get('session-only');check(session.ok&&session.value===null,'Session survived reload');
    const old=await s.ref('remembered');check((await s.delete('remembered')).ok,'Delete');check((await s.get('remembered')).value===null,'Deleted value readable');
    check((await s.set('remembered','synthetic-host-value-v2',{persistence:'remember'})).ok,'Recreate');const current=await s.ref('remembered');check(current.ok&&current.value.revision>old.value.revision,'Old reference revived');
    const forged=await fetch('/api/plugins/secrets',{method:'POST',headers:{'content-type':'application/json','x-or3-plugin-intent':'plugin'},body:JSON.stringify({operation:'get',pluginId:'${manifest.id}',activationId:'invalid',key:'remembered',workspaceId:'forged'})});check(forged.status===400,'Scope injection accepted');
    return {rememberedSurvived:true,sessionCleared:true,deleteRecreate:true,oldRevision:old.value.revision,newRevision:current.value.revision,scopeInjectionStatus:forged.status};`);
  console.log('Reviewed package, browser canary, real host CRUD, reload and scope validation passed');
  const { createClient }: typeof import('../src/client') = await import(join(work, 'package/dist/client.js'));
  const client = createClient({ socketPath: socket, tokenFile: token, vaultId: initialized.vaultId });
  const scope = { namespace: 'host-e2e', ownerUserId: setup.userId, workspaceId: setup.workspaceId, consumerId: manifest.id };
  const inventory = await client.list({ scope });
  check(inventory.items.length === 1 && inventory.items[0].name === 'remembered', 'Session-only secret persisted in vault');
  let staleRefRefused = false;
  try { await client.resolve({ scope, selector: { ref: { id: inventory.items[0].ref.id, revision: reload.oldRevision } } }); } catch (error) { staleRefRefused = (error as { code: string }).code === 'not_found'; }
  check(staleRefRefused, 'Old reference resolved after delete/recreate');
  for (const name of readdirSync(vault)) { const bytes = readFileSync(join(vault, name)); check(!['synthetic-host-value', 'synthetic-session-only'].some(value => bytes.includes(Buffer.from(value))), 'Plaintext in vault files'); }
  const publicState = evaluate("return {payload:JSON.stringify(globalThis.__NUXT__??{})+(document.querySelector('#__NUXT_DATA__')?.textContent??'')};").payload;
  check(![socket, token, key, readFileSync(token, 'utf8').trim()].some(value => publicState.includes(value)), 'Private configuration in page payload');
  const noMigration = evaluate(`${requestHelpers}${openLegacyDb}
    const row=await new Promise((yes,no)=>{const q=db.transaction('kv').objectStore('kv').get('kv:openrouter_api_key');q.onsuccess=()=>yes(q.result);q.onerror=()=>no(q.error)});db.close();
    check(localStorage.getItem(${JSON.stringify(legacyKey)})==='synthetic-device-legacy'&&row?.value==='synthetic-dexie-owner-key','Provider altered existing credential stores');return {deviceUnchanged:true,dexieKeyUnchanged:true,deviceImport:false};`);
  browser('screenshot', join(results, 'host-browser.png'));
  await stop(service); service = undefined;
  const outage = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;const read=await s.get('remembered'),write=await s.set('outage-write','synthetic-outage-value',{persistence:'remember'});check(!read.ok&&!write.ok&&read.error.code==='host-unavailable'&&write.error.code==='host-unavailable','Selected outage did not fail closed');check(!(JSON.stringify({...localStorage})+JSON.stringify({...sessionStorage})).includes('synthetic-outage-value'),'Outage device fallback');return {read:read.error.code,write:write.error.code,deviceFallback:false};`);
  service = await startVault();
  const recovery = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;check((await s.get('remembered')).value==='synthetic-host-value-v2','Vault restart lost value');check((await s.get('outage-write')).value===null,'Outage write persisted');return {persisted:true,outageWriteAbsent:true};`);
  const workspace = evaluate(`${requestHelpers}const previous=globalThis.__or3SecretQualification.secrets;const other=await post('/api/workspaces',{name:'Secrets isolation'},'cloud');await post('/api/workspaces/active',{id:other.id},'cloud');const denied=await previous.get('remembered');check(!denied.ok,'Old workspace activation disclosed');await post('/api/workspaces/active',{id:${JSON.stringify(setup.workspaceId)}},'cloud');return {previousActivationRefused:true,code:denied.error.code};`);
  browser('reload'); browser('wait', '--text', 'Real trusted plugin activated');
  const revocation = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;check((await s.get('remembered')).value==='synthetic-host-value-v2','New activation unavailable');const base='/api/admin/plugins/packages/${manifest.id}';const review=await(await fetch(base+'/review?target=current&workspaceId=${setup.workspaceId}')).json();await post(base+'/grants',{target:'current',workspaceId:${JSON.stringify(setup.workspaceId)},approvedGrants:[],expectedPackageDigest:review.packageDigest,expectedAuthoritySha256:review.authoritySha256});const denied=await s.get('remembered');check(!denied.ok,'Revoked grants disclosed');return {oldActivationRefused:true,code:denied.error.code};`);
  const unauthenticated = await fetch(`${origin}/api/plugins/secrets`, { method: 'POST', headers: { origin, 'content-type': 'application/json', 'x-or3-plugin-intent': 'plugin' }, body: JSON.stringify({ operation: 'get', pluginId: manifest.id, activationId: 'invalid', key: 'remembered' }) });
  check(unauthenticated.status === 401, 'Unauthenticated request accepted');
  const auditFile = join(custody, 'audit.token');
  cli('token', 'issue', '--socket', socket, '--vault-id', initialized.vaultId, '--token-file', operator, '--kind', 'audit-reader', '--capabilities', 'audit', '--expires-in', '1h', '--out-file', auditFile);
  const auditor = createClient({ socketPath: socket, tokenFile: auditFile, vaultId: initialized.vaultId });
  const auditPage = await auditor.readAudit({ after: null, limit: 100 });
  check(auditPage.cursor?.seq === auditPage.through.seq, 'Host audit fixture exceeded one bounded page');
  const logs = readFileSync(join(work, 'host.log'), 'utf8');
  const hostEvents = logs.split('\n').flatMap(line => { const text = /\{"event":"plugin_secret_authorized",.*\}/.exec(line)?.[0]; return text ? [JSON.parse(text)] : []; });
  const correlated = auditPage.events.filter(row => hostEvents.some(event => event.requestId === row.event.requestId && event.actorId === setup.userId && row.event.actorId === event.actorId && row.event.activationId === event.activationId));
  check(correlated.length >= 3 && correlated.some(row => row.event.operation === 'secrets/put') && correlated.some(row => row.event.operation === 'secrets/resolve'), 'Host/vault actor and request correlation missing');
  check(!logs.includes('synthetic-host-value') && !JSON.stringify(auditPage).includes('synthetic-host-value'), 'Secret value in authorization evidence');
  // Reuse the reviewed package and account with selection disabled. The legacy
  // value must remain available locally and never appear in the vault inventory.
  evaluate(`${requestHelpers}const base='/api/admin/plugins/packages/${manifest.id}';const r=await(await fetch(base+'/review?target=current&workspaceId=${setup.workspaceId}')).json();await post(base+'/grants',{target:'current',workspaceId:${JSON.stringify(setup.workspaceId)},approvedGrants:r.requestedGrants,expectedPackageDigest:r.packageDigest,expectedAuthoritySha256:r.authoritySha256});return {approved:true};`);
  await stop(server, true); server = undefined;
  env.NUXT_SECRETS_VAULT_ID = '0'.repeat(32);
  await startHost();
  browser('reload'); browser('wait', '--text', 'Real trusted plugin activated');
  const wrongVault = evaluate(`${requestHelpers}const s=globalThis.__or3SecretQualification.secrets;const r=await s.get('remembered'),w=await s.set('wrong-vault-write','synthetic-wrong-vault',{persistence:'remember'});check(!r.ok&&!w.ok,'Wrong-vault provider released or wrote a secret');return {read:r.error.code,write:w.error.code};`);
  check((await client.list({ scope })).items.length === 1, 'Wrong-vault request mutated inventory');
  await stop(server, true); server = undefined;
  env.NUXT_SECRETS_VAULT_ID = initialized.vaultId;
  env.NUXT_SECRETS_PROVIDER = '';
  await startHost();
  browser('reload'); browser('wait', '--text', 'Real trusted plugin activated');
  const unselected = evaluate(`${requestHelpers}${openLegacyDb}
    const session=await(await fetch('/api/auth/session')).json();check(!Object.hasOwn(session,'secretStoreEnabled'),'Disabled provider still advertised');
    const s=globalThis.__or3SecretQualification.secrets;check((await s.get('legacy')).value==='synthetic-device-legacy','Legacy local value lost without provider');
    check((await s.set('device-only','synthetic-device-only')).ok,'Unselected device write failed');
    const row=await new Promise((yes,no)=>{const q=db.transaction('kv').objectStore('kv').get('kv:openrouter_api_key');q.onsuccess=()=>yes(q.result);q.onerror=()=>no(q.error)});db.close();check(row?.value==='synthetic-dexie-owner-key','Unselected provider altered Dexie credential');
    const r=await fetch('/api/plugins/secrets',{method:'POST',headers:{'content-type':'application/json','x-or3-plugin-intent':'plugin'},body:'{}'});check(r.status===404,'Unselected secret route exposed');return {advertised:false,legacyDeviceRead:true,deviceWrite:true,dexieKeyUnchanged:true,routeStatus:r.status};`);
  const finalInventory = await client.list({ scope });
  check(finalInventory.items.length === 1 && finalInventory.items[0].name === 'remembered', 'Provider selection migrated device or Dexie credentials');
  const receipt = { generatedAt: new Date().toISOString(), source: 'development server, not production acceptance', sourceCommit: packageReceipt.sourceBase, sourceState: packageReceipt.sourceState, hostRevision: hostPin.revision, vaultPackageSha256: packageReceipt.artifactSha256, bun: Bun.version, node: run('node', ['--version']), browser: run('agent-browser', ['--version']), profile: 'Basic Auth + SQLite + filesystem, isolated data and empty dotenv', reviewedPackageDigest: setup.packageDigest, browserCanary: 'passed', roundtrip, reload, serverDerivedScopeInventory: 'passed', staleReference: 'refused', databasePlaintext: 'absent', pagePrivateConfiguration: 'absent', noMigration, unselected, wrongVault, hostVaultCorrelation: { matchedEvents: correlated.length, actorRequestActivation: 'matched', plaintext: 'absent' }, outage, recovery, workspace, revocation, unauthenticatedStatus: unauthenticated.status, screenshot: 'host-browser.png' };
  writeFileSync(join(results, 'host-browser.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  passed = true;
  console.log('Full browser/provider qualification passed; test-results/host-browser.json');
} finally {
  if (browserOpened) { try { browser('close'); } catch {} }
  await stop(server, true);
  for (const child of children) await stop(child);
  // Immutable package directories are read-only by design. Loosen only our
  // disposable tree, without following the node_modules symlink into the host.
  const remove = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name); if (entry.isDirectory()) { chmodSync(child, 0o700); remove(child); }
    }
  };
  if (passed) { remove(work); rmSync(work, { recursive: true, force: true }); }
  else console.error(`Failed fixture retained for diagnosis (synthetic credentials only): ${work}`);
}
