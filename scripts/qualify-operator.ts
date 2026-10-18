import { stopChild } from './lib/process';
// Operator-guide contract, exercised through the clean packaged CLI only.
// Failure cases: expired/replaced credentials, lost collector progress, unsafe
// outputs, wrong recovery keys, source mutation and stale recovered authority.
// Individual API tests cannot establish that the documented sequence composes.
// No production hooks or credentials; the receipt contains metadata only.
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const root = resolve(import.meta.dir, '..'),
  results = join(root, 'test-results');
const work = mkdtempSync(
  process.platform === 'darwin' ? '/private/tmp/ors-operator-' : '/tmp/ors-operator-',
);
const env: NodeJS.ProcessEnv = {
  ...process.env,
  PATH: `${dirname(process.execPath)}:${process.env.PATH}`,
};
delete env.NODE_OPTIONS;
delete env.DOTENV_CONFIG_PATH;
const check = (ok: unknown, why: string) => {
  if (!ok) throw new Error(why);
};
const hash = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
const transcript: { command: string; exit: number; output: string }[] = [];
const value = 'synthetic-operator-value\nwith-exact-newline\n';
let child: ChildProcess | undefined,
  serviceLog = '',
  passed = false,
  failed = false;
let vault = join(work, 'vault'),
  key = join(work, 'master.key'),
  operator = join(work, 'operator.token');
const socket = join(work, 'run/api.sock'),
  service = join(work, 'service.token');
const stop = () => stopChild(child, { requireGraceful: true });

try {
  check(Bun.version === '1.3.14', 'Use the qualified Bun runtime');
  const packageReceipt = JSON.parse(readFileSync(join(results, 'package-receipt.json'), 'utf8'));
  const artifact = join(results, packageReceipt.artifact);
  check(hash(artifact) === packageReceipt.artifactSha256, 'Package checksum mismatch');
  check(
    spawnSync('tar', ['-xf', artifact, '-C', work]).status === 0,
    'Cannot unpack qualified package',
  );
  const launcher = join(work, 'package/bin/or3-secrets.mjs');
  const cli = (args: string[], expected = 0, input?: string) => {
    const r = spawnSync('node', [launcher, ...args], {
      cwd: work,
      env,
      input,
      encoding: 'utf8',
      timeout: 30000,
    });
    const output = r.stdout + r.stderr;
    check(
      !output.includes(value) && !/ors1\.[a-f0-9]{32}\.[A-Za-z0-9_-]{43}/.test(output),
      'Incidental credential disclosure',
    );
    transcript.push({
      command: args[0] + (['token', 'audit'].includes(args[0]!) ? ` ${args[1]}` : ''),
      exit: r.status ?? -1,
      output,
    });
    check(
      r.status === expected,
      `Operator command ${args[0]} failed (expected ${expected}, got ${r.status})`,
    );
    return r.stdout ? JSON.parse(r.stdout) : undefined;
  };
  mkdirSync(join(work, 'run'), { mode: 0o700 });
  const init = cli(['init', '--vault-dir', vault, '--key-file', key, '--operator-file', operator]);
  const connect = (file = service) => [
    '--socket',
    socket,
    '--vault-id',
    init.vaultId,
    '--token-file',
    file,
  ];
  const scope = [
    '--namespace',
    'operator',
    '--owner-user-id',
    'internal-user',
    '--workspace-id',
    'workspace',
    '--consumer-id',
    'fixture',
  ];
  const start = async () => {
    serviceLog = '';
    child = spawn(
      'node',
      [launcher, 'serve', '--vault-dir', vault, '--key-file', key, '--socket', socket],
      { cwd: work, env, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    child.stdout!.on('data', (data) => {
      serviceLog += data;
    });
    child.stderr!.on('data', (data) => {
      serviceLog += data;
    });
    const deadline = Date.now() + 10000;
    while (!serviceLog.includes('"ready":true')) {
      check(child.exitCode === null && Date.now() < deadline, 'Operator service readiness failed');
      await Bun.sleep(25);
    }
  };
  const issue = (file: string, expires = '1h', kind = 'service') =>
    cli([
      'token',
      'issue',
      ...connect(operator),
      '--kind',
      kind,
      '--capabilities',
      kind === 'service' ? 'metadata,read,write,delete' : 'audit',
      ...(kind === 'service' ? scope : []),
      '--expires-in',
      expires,
      '--out-file',
      file,
    ]);
  await start();
  const initial = issue(service);
  const status = cli(['status', ...connect()]);
  check(
    status.storage.journalMode === 'delete' &&
      status.storage.lockingMode === 'exclusive' &&
      status.storage.synchronous === 'extra',
    'Unexpected storage durability modes',
  );
  cli(['put', ...connect(), ...scope, '--name', 'api', '--expected-revision', '0'], 0, value);
  const output = join(work, 'recovered-value');
  cli(['get', ...connect(), ...scope, '--name', 'api', '--out-file', output]);
  check(
    readFileSync(output, 'utf8') === value && (statSync(output).mode & 0o777) === 0o600,
    'Private exact-byte output failed',
  );
  cli(['get', ...connect(), ...scope, '--name', 'api', '--out-file', output], 64);
  check(readFileSync(output, 'utf8') === value, 'Refused output was overwritten');
  cli(
    [
      'get',
      ...connect(operator),
      ...scope,
      '--name',
      'api',
      '--out-file',
      join(work, 'operator-refused'),
    ],
    77,
  );
  check(!existsSync(join(work, 'operator-refused')), 'Failed disclosure left an incomplete output');

  const expiring = join(work, 'expiring.token');
  issue(expiring, '2s');
  cli(['status', ...connect(expiring)]);
  await Bun.sleep(2100);
  cli(['status', ...connect(expiring)], 77);
  const replacement = join(work, 'replacement.token'),
    previous = join(work, 'previous.token');
  issue(replacement);
  cli(['status', ...connect(replacement)]);
  copyFileSync(service, previous);
  renameSync(replacement, service);
  cli(['status', ...connect()]);
  cli(['token', 'revoke', ...connect(operator), '--id', initial.id]);
  cli(['status', ...connect(previous)], 77);

  const audit = join(work, 'audit.token');
  issue(audit, '1h', 'audit-reader');
  cli(
    [
      'get',
      ...connect(audit),
      ...scope,
      '--name',
      'api',
      '--out-file',
      join(work, 'audit-refused'),
    ],
    77,
  );
  check(
    !existsSync(join(work, 'audit-refused')),
    'Failed audit-reader disclosure left an incomplete output',
  );
  const readPage = async (
    after?: { seq: number; mac: string },
    through?: { seq: number; mac: string },
  ) => {
    await Bun.sleep(250);
    return cli([
      'audit',
      'read',
      ...connect(audit),
      '--limit',
      '3',
      ...(after ? ['--after', `${after.seq}:${after.mac}`] : []),
      ...(through ? ['--through', `${through.seq}:${through.mac}`] : []),
    ]);
  };
  const first = await readPage();
  const checkpoint = join(work, 'checkpoint.json');
  writeFileSync(checkpoint, JSON.stringify({ cursor: first.cursor, through: first.through }), {
    mode: 0o600,
  });
  // Lose the collector after fetching a page, before durable progress advances.
  const fetched = await readPage(first.cursor, first.through);
  const progress = JSON.parse(readFileSync(checkpoint, 'utf8'));
  const replayed = await readPage(progress.cursor, progress.through);
  check(
    JSON.stringify(fetched) === JSON.stringify(replayed),
    'Collector restart lost or changed a frozen page',
  );
  let cursor = first.cursor,
    pages = 1,
    expected = cursor.seq + 1;
  while (cursor.seq < first.through.seq) {
    const page = await readPage(cursor, first.through);
    check(
      page.events.length > 0 && JSON.stringify(page.through) === JSON.stringify(first.through),
      'Collector failed to make bounded progress',
    );
    for (const row of page.events) {
      check(row.seq === expected++, 'Collector sequence gap');
    }
    const temporary = join(work, 'checkpoint.next');
    writeFileSync(temporary, JSON.stringify({ cursor: page.cursor, through: page.through }), {
      mode: 0o600,
    });
    renameSync(temporary, checkpoint);
    cursor = page.cursor;
    pages++;
  }
  const receiptFile = join(work, 'retained.json');
  writeFileSync(receiptFile, JSON.stringify({ vaultId: init.vaultId, ...first.through }), {
    mode: 0o600,
  });
  let noTcp = 'Linux process socket ownership check only';
  if (process.platform === 'linux') {
    // Inspect the actual Bun service child, since the CLI launcher is Node.
    const descendants = readFileSync(`/proc/${child!.pid}/task/${child!.pid}/children`, 'utf8')
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    check(descendants.length === 1, 'Cannot identify the vault service process');
    const fds = new Set(
      readdirSync(`/proc/${descendants[0]}/fd`).map((fd) => {
        try {
          return readlinkSync(`/proc/${descendants[0]}/fd/${fd}`);
        } catch {
          return '';
        }
      }),
    );
    for (const name of ['tcp', 'tcp6', 'udp', 'udp6'])
      for (const row of readFileSync(`/proc/net/${name}`, 'utf8').trim().split('\n').slice(1))
        check(
          !fds.has(`socket:[${row.trim().split(/\s+/)[9]}]`),
          'Vault opened an Internet socket',
        );
    noTcp = 'No TCP/UDP socket owned by the running vault process';
  }
  await stop();
  cli(['audit', 'verify', '--vault-dir', vault, '--key-file', key, '--receipt-file', receiptFile]);
  const source = vault,
    sourceKey = key,
    sourceHash = hash(join(source, 'vault.sqlite'));
  const backup = join(work, 'snapshot.backup');
  cli([
    'backup',
    '--vault-dir',
    source,
    '--key-file',
    sourceKey,
    '--receipt-file',
    receiptFile,
    '--out-file',
    backup,
  ]);
  const backupHash = hash(backup);
  for (const operation of ['restore', 'rekey']) {
    vault = join(work, operation);
    key = join(work, `${operation}.key`);
    operator = join(work, `${operation}.token`);
    cli([
      operation,
      ...(operation === 'restore' ? ['--backup-file', backup] : ['--vault-dir', source]),
      '--key-file',
      sourceKey,
      '--receipt-file',
      receiptFile,
      '--destination',
      vault,
      '--new-key-file',
      key,
      '--operator-file',
      operator,
    ]);
    check(
      hash(join(source, 'vault.sqlite')) === sourceHash && hash(backup) === backupHash,
      'Maintenance modified its source',
    );
    check(hash(key) !== hash(sourceKey), 'Recovery reused the source key');
    await start();
    cli(['status', ...connect()], 77);
    cli(['status', ...connect(audit)], 77);
    const fresh = join(work, `${operation}-service.token`);
    issue(fresh);
    const recovered = join(work, `${operation}-value`);
    cli(['get', ...connect(fresh), ...scope, '--name', 'api', '--out-file', recovered]);
    check(readFileSync(recovered, 'utf8') === value, 'Recovery lost exact contents');
    await stop();
    cli(['audit', 'verify', '--vault-dir', vault, '--key-file', key]);
  }
  cli(
    [
      'restore',
      '--backup-file',
      backup,
      '--key-file',
      key,
      '--destination',
      join(work, 'wrong-key'),
      '--new-key-file',
      join(work, 'wrong.key'),
      '--operator-file',
      join(work, 'wrong.token'),
    ],
    65,
  );
  check(!existsSync(join(work, 'wrong-key/complete')), 'Wrong-key restore became usable');
  const receipt = {
    generatedAt: new Date().toISOString(),
    sourceCommit: packageReceipt.sourceBase,
    sourceState: packageReceipt.sourceState,
    artifactSha256: packageReceipt.artifactSha256,
    runtime: Bun.version,
    node: spawnSync('node', ['--version'], { env, encoding: 'utf8' }).stdout.trim(),
    platform: process.platform,
    architecture: process.arch,
    steps: transcript.length,
    exactPrivateOutput: 'passed',
    expiry: 'refused',
    atomicTokenReplacement: 'passed',
    priorToken: 'revoked',
    collectorResume: { pages, through: first.through.seq, gapFree: true, frozenReplay: true },
    checkpointVerification: 'passed',
    storage: status.storage,
    noTcp,
    freshKeyRestoreAndRekey: 'passed',
    copiedCredentials: 'revoked',
    wrongKey: 'refused',
    sourceAndBackup: 'unchanged',
    transcript,
    productionAcceptance: false,
    externalControls:
      'MFA, independent custody/collector, power loss and independent review not exercised',
  };
  writeFileSync(join(results, 'operator.json'), JSON.stringify(receipt, null, 2));
  passed = true;
  console.log(
    JSON.stringify({
      steps: transcript.length,
      collectorPages: pages,
      expiryAndRenewal: 'passed',
      restoreAndRekey: 'passed',
      noTcp,
      receipt: 'test-results/operator.json',
    }),
  );
} catch (error) {
  failed = true;
  throw error;
} finally {
  try {
    await stop();
  } catch (error) {
    if (!failed) throw error;
    console.error(
      'Operator fixture cleanup also failed; preserving the original qualification error.',
    );
  }
  if (passed) rmSync(work, { recursive: true, force: true });
  else console.error(`Failed disposable operator fixture retained: ${work}`);
}
