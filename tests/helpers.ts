import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { request } from 'node:http';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { expect } from 'bun:test';

export const project = resolve(import.meta.dir, '..');
export const scope = {
  namespace: 'test',
  ownerUserId: 'user-1',
  workspaceId: 'workspace-1',
  consumerId: 'plugin-1',
};
export const context = () => ({
  requestId: randomUUID(),
  actorId: 'actor-1',
  activationId: 'activation-hash-1',
});
export function cli(args: string[], input?: string | Buffer) {
  return spawnSync(process.execPath, ['--no-env-file', 'src/cli.ts', ...args], {
    cwd: project,
    input,
    encoding: 'utf8',
    timeout: 15000,
  });
}
export class Fixture {
  root: string;
  vault: string;
  key: string;
  operatorFile: string;
  socket: string;
  vaultId = '';
  child?: ChildProcess;
  logs = '';
  constructor(parent = process.platform === 'darwin' ? '/private/tmp' : '/tmp') {
    this.root = mkdtempSync(join(parent, 'ors-'));
    this.vault = join(this.root, 'vault');
    this.key = join(this.root, 'master.key');
    this.operatorFile = join(this.root, 'operator.token');
    this.socket = join(this.root, 'run', 'api.sock');
    mkdirSync(join(this.root, 'run'), { mode: 0o700 });
    const result = cli([
      'init',
      '--vault-dir',
      this.vault,
      '--key-file',
      this.key,
      '--operator-file',
      this.operatorFile,
    ]);
    expect(result.status, result.stderr).toBe(0);
    this.vaultId = JSON.parse(result.stdout).vaultId;
  }
  get operator() {
    return readFileSync(this.operatorFile, 'utf8').trim();
  }
  async start(extra: string[] = []) {
    const child = spawn(
      process.execPath,
      [
        '--no-env-file',
        'src/cli.ts',
        'serve',
        '--vault-dir',
        this.vault,
        '--key-file',
        this.key,
        '--socket',
        this.socket,
        ...extra,
      ],
      { cwd: project, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    this.child = child;
    await new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(new Error('Service did not become ready')), 5000);
      child.stdout!.on('data', (data) => {
        this.logs += data;
        if (this.logs.includes('"ready":true')) {
          clearTimeout(timer);
          yes();
        }
      });
      child.stderr!.on('data', (data) => {
        this.logs += data;
      });
      child.once('exit', () => {
        clearTimeout(timer);
        no(new Error(`Service exited: ${this.logs}`));
      });
    });
  }
  async stop(signal: NodeJS.Signals = 'SIGTERM') {
    const child = this.child;
    if (!child || child.exitCode !== null || child.signalCode !== null) {
      this.child = undefined;
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const killTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
      const deadline = setTimeout(() => {
        child.removeListener('exit', exited);
        reject(new Error('Service did not exit after SIGKILL'));
      }, 10000);
      const exited = () => {
        clearTimeout(killTimer);
        clearTimeout(deadline);
        resolve();
      };
      child.once('exit', exited);
      child.kill(signal);
    });
    this.child = undefined;
  }
  async close() {
    await this.stop();
    rmSync(this.root, { recursive: true, force: true });
  }
  async call(
    operation: string,
    body: Record<string, unknown> = {},
    token = this.operator,
    vaultId = this.vaultId,
    headers: Record<string, string> = {},
  ) {
    return raw(this.socket, operation, { context: context(), ...body }, token, vaultId, headers);
  }
  async token(policy: Record<string, unknown> = {}) {
    const issued = await this.call('tokens/issue', {
      kind: 'service',
      namespace: 'test',
      capabilities: ['metadata', 'read', 'write', 'delete'],
      expiresInSeconds: 3600,
      ...policy,
    });
    expect(issued.status, JSON.stringify(issued.data)).toBe(200);
    const file = join(this.root, `${issued.data.meta.id}.token`);
    writeFileSync(file, issued.data.token + '\n', { mode: 0o600 });
    return { ...issued.data, file } as { token: string; meta: { id: string }; file: string };
  }
  args(tokenFile: string) {
    return [
      '--socket',
      this.socket,
      '--token-file',
      tokenFile,
      '--vault-id',
      this.vaultId,
      '--namespace',
      scope.namespace,
      '--owner-user-id',
      scope.ownerUserId,
      '--workspace-id',
      scope.workspaceId,
      '--consumer-id',
      scope.consumerId,
    ];
  }
}
export function raw(
  socket: string,
  operation: string,
  body: unknown,
  token: string,
  vaultId: string,
  headers: Record<string, string> = {},
) {
  return new Promise<{ status: number; data: any; headers: any }>((yes, no) => {
    const bytes = typeof body === 'string' ? body : JSON.stringify(body);
    const req = request(
      {
        socketPath: socket,
        path: `/v1/${operation}`,
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'x-or3-vault-id': vaultId,
          ...headers,
        },
      },
      (res) => {
        let out = '';
        res.setEncoding('utf8');
        res.on('data', (data) => (out += data));
        res.on('end', () => {
          try {
            yes({ status: res.statusCode!, data: JSON.parse(out), headers: res.headers });
          } catch {
            no(new Error('Invalid JSON response'));
          }
        });
      },
    );
    req.setTimeout(6000, () => req.destroy(new Error('timeout')));
    req.on('error', no);
    req.end(bytes);
  });
}
export function removeCrashSocket(f: Fixture) {
  if (existsSync(f.socket)) rmSync(f.socket);
}
