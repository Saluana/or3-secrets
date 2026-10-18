import { afterAll, expect, test } from 'bun:test';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
  mkdirSync,
  rmSync,
} from 'node:fs';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { request } from 'node:http';
import { createHmac, hkdfSync } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { Fixture, cli, context, scope, removeCrashSocket, project } from './helpers';
import { createClient } from '../src/client';

const outcomes: { name: string; outcome: string }[] = [];
function scenario(name: string, fn: () => Promise<void>) {
  test(name, async () => {
    try {
      await fn();
      outcomes.push({ name, outcome: 'passed' });
    } catch (error) {
      outcomes.push({ name, outcome: 'failed' });
      throw error;
    }
  });
}
afterAll(() => {
  mkdirSync(join(project, 'test-results'), { recursive: true });
  writeFileSync(
    join(project, 'test-results/security-receipt.json'),
    JSON.stringify(
      {
        runtime: Bun.version,
        platform: process.platform,
        architecture: process.arch,
        independentReview: 'not performed',
        powerLossQualification: 'not performed',
        outcomes,
      },
      null,
      2,
    ),
  );
});

// CLI UX owns safe operator guidance, which the transport/security matrix does
// not assert. These are real CLI processes; no exported parser or test seam.
scenario('CLI help explains command options and safe examples without a vault', async () => {
  for (const args of [
    ['put', '--help'],
    ['help', 'put'],
  ]) {
    const result = cli(args);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('--expected-revision');
    expect(result.stdout).toContain('--socket');
    expect(result.stdout).toContain('<');
  }
  const tokens = cli(['help', 'token', 'issue']);
  expect(tokens.status, tokens.stderr).toBe(0);
  expect(tokens.stdout).toContain('--capabilities');
  expect(tokens.stdout).toContain('--expires-in');
  expect(cli(['token', '--help']).stdout).toContain('token revoke');
  expect(cli(['restore', '-h']).stdout).toContain('--new-key-file');
});

scenario('CLI validation names missing options and never reflects rejected arguments', async () => {
  const missing = cli(['put']);
  expect(missing.status).toBe(64);
  const error = JSON.parse(missing.stderr).error;
  expect(error.code).toBe('invalid_request');
  expect(error.message).toContain('--socket');
  expect(error.message).toContain('--expected-revision');
  expect(error.hint).toContain('put --help');
  const canary = 'synthetic-rejected-argument-never-echo';
  const unknown = cli(['put', '--value', canary]);
  expect(unknown.status).toBe(64);
  expect(unknown.stdout + unknown.stderr).not.toContain(canary);
  expect(JSON.parse(unknown.stderr).error.hint).toContain('--help');
});

// The source-CLI fixtures do not exercise the Node launcher or terminal process
// groups. This owns graceful launcher shutdown, socket cleanup and durable data
// at the real process boundary, without introducing a production test seam.
scenario(
  'launcher shuts down cleanly for terminal and direct signals and preserves the vault',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const token = await f.token();
      expect(
        cli(
          ['put', ...f.args(token.file), '--name', 'shutdown', '--expected-revision', '0'],
          'synthetic-shutdown-value',
        ).status,
      ).toBe(0);
      await f.stop();
      for (const delivery of ['terminal', 'direct'] as const) {
        for (const signal of ['SIGINT', 'SIGTERM'] as const) {
          const child = spawn(
            'node',
            [
              'bin/or3-secrets.mjs',
              'serve',
              '--vault-dir',
              f.vault,
              '--key-file',
              f.key,
              '--socket',
              f.socket,
            ],
            {
              cwd: project,
              detached: true,
              stdio: ['ignore', 'pipe', 'pipe'],
              env: { ...process.env, PATH: `${join(process.execPath, '..')}:${process.env.PATH}` },
            },
          );
          let logs = '';
          const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
            (yes) => child.once('exit', (code, signal) => yes({ code, signal })),
          );
          try {
            await new Promise<void>((yes, no) => {
              const timer = setTimeout(() => no(new Error('Launcher readiness timed out')), 5000);
              child.stdout!.on('data', (data) => {
                logs += data;
                if (logs.includes('"ready":true')) {
                  clearTimeout(timer);
                  yes();
                }
              });
              child.stderr!.on('data', (data) => {
                logs += data;
              });
              child.once('error', (error) => {
                clearTimeout(timer);
                no(error);
              });
              void exited.then(() => {
                clearTimeout(timer);
                no(new Error(`Launcher exited before ready: ${logs}`));
              });
            });
            expect(
              cli(['get', ...f.args(token.file), '--name', 'shutdown', '--stdout']).stdout,
            ).toBe('synthetic-shutdown-value');
            if (delivery === 'terminal') process.kill(-child.pid!, signal);
            else child.kill(signal);
            let timer: ReturnType<typeof setTimeout> | undefined;
            try {
              const outcome = await Promise.race([
                exited,
                new Promise<never>((_, no) => {
                  timer = setTimeout(() => no(new Error('Launcher shutdown timed out')), 5000);
                }),
              ]);
              expect(outcome, `${delivery} ${signal}: ${logs}`).toEqual({ code: 0, signal: null });
            } finally {
              clearTimeout(timer);
            }
            expect(existsSync(f.socket)).toBe(false);
            const verified = cli(['audit', 'verify', '--vault-dir', f.vault, '--key-file', f.key]);
            expect(verified.status, verified.stderr).toBe(0);
          } finally {
            try {
              process.kill(-child.pid!, 'SIGKILL');
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
            }
            await exited;
          }
        }
      }
    } finally {
      await f.close();
    }
  },
);

scenario('exact CLI bytes, explicit disclosure, protected files and Node 24 client', async () => {
  const f = new Fixture();
  try {
    expect(statSync(f.key).mode & 0o777).toBe(0o600);
    expect(statSync(f.vault).mode & 0o777).toBe(0o700);
    await f.start();
    const token = await f.token();
    const canary = 'synthetic-CLI-value\nwith trailing newline\n';
    const args = f.args(token.file);
    const put = cli(['put', ...args, '--name', 'api-key', '--expected-revision', '0'], canary);
    expect(put.status, put.stderr).toBe(0);
    expect(put.stdout.includes(canary)).toBe(false);
    expect(cli(['get', ...args, '--name', 'api-key']).status).not.toBe(0);
    const result = cli(['get', ...args, '--name', 'api-key', '--stdout']);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(canary);
    const output = join(f.root, 'value.out');
    expect(cli(['get', ...args, '--name', 'api-key', '--out-file', output]).status).toBe(0);
    expect(statSync(output).mode & 0o777).toBe(0o600);
    const existing = cli(['get', ...args, '--name', 'api-key', '--out-file', output]);
    expect(existing.status).toBe(64);
    expect(JSON.parse(existing.stderr).error.code).toBe('output_exists');
    expect(JSON.parse(existing.stderr).error.hint).toContain('new');
    expect(readFileSync(output, 'utf8')).toBe(canary);
    expect(f.logs.includes(canary)).toBe(false);
    expect(readFileSync(join(f.vault, 'vault.sqlite')).includes(Buffer.from(canary))).toBe(false);
    for (const [index, bytes] of [
      Buffer.from('\ufeffabc\n'),
      Buffer.from('\ufeff'),
      Buffer.from('a\ufeffb\n\n'),
    ].entries()) {
      const name = `utf8-${index}`;
      expect(cli(['put', ...args, '--name', name, '--expected-revision', '0'], bytes).status).toBe(
        0,
      );
      const recovered = cli(['get', ...args, '--name', name, '--stdout']);
      expect(recovered.status).toBe(0);
      expect(Buffer.from(recovered.stdout)).toEqual(bytes);
    }
    const node = spawnSync(
      'node',
      [
        '--input-type=module',
        '-e',
        `import {createClient} from './dist/client.js'; const c=createClient(JSON.parse(process.argv[1])); const r=await c.inspect({scope:${JSON.stringify(scope)},name:'api-key'}); if(r?.ref.revision!==1)process.exit(2);`,
        JSON.stringify({ socketPath: f.socket, tokenFile: token.file, vaultId: f.vaultId }),
      ],
      { cwd: project, encoding: 'utf8' },
    );
    expect(node.status, node.stderr).toBe(0);
    const aborted = spawnSync(
      'node',
      [
        '--input-type=module',
        '-e',
        `import {createClient} from './dist/client.js';const signal=AbortSignal.abort();const c=createClient({...JSON.parse(process.argv[1]),signal});try{await c.status();process.exit(2)}catch(e){if(e.code!=='request_aborted')process.exit(3)}`,
        JSON.stringify({ socketPath: f.socket, tokenFile: token.file, vaultId: f.vaultId }),
      ],
      { cwd: project, encoding: 'utf8' },
    );
    expect(aborted.status, aborted.stderr).toBe(0);
  } finally {
    await f.close();
  }
});

scenario(
  'authorization separates all scope fields, capabilities, and credential kinds',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const writer = await f.token({
        ownerUserId: scope.ownerUserId,
        workspaceId: scope.workspaceId,
        consumerId: scope.consumerId,
      });
      expect(
        (
          await f.call(
            'secrets/put',
            { scope, name: 'key', value: 'synthetic-scope-value', expectedRevision: 0 },
            writer.token,
          )
        ).status,
      ).toBe(200);
      for (const field of Object.keys(scope)) {
        const foreign = { ...scope, [field]: 'foreign' };
        for (const op of ['inspect', 'list', 'resolve', 'put', 'delete']) {
          const args: any = { scope: foreign };
          if (op === 'resolve') args.selector = { name: 'key' };
          if (['inspect', 'put', 'delete'].includes(op)) args.name = 'key';
          if (['put', 'delete'].includes(op)) args.expectedRevision = 1;
          if (op === 'put') args.value = 'forbidden';
          expect((await f.call(`secrets/${op}`, args, writer.token)).status).toBe(403);
        }
      }
      for (const capabilities of [['metadata'], ['write'], ['delete']]) {
        const limited = await f.token({ capabilities });
        expect(
          (await f.call('secrets/resolve', { scope, selector: { name: 'key' } }, limited.token))
            .status,
        ).toBe(403);
        expect((await f.call('tokens/list', {}, limited.token)).status).toBe(403);
        expect((await f.call('audit/read', { after: null, limit: 10 }, limited.token)).status).toBe(
          403,
        );
      }
      expect((await f.call('secrets/inspect', { scope, name: 'key' })).status).toBe(403);
      expect((await f.call('status', {}, 'invalid-token')).status).toBe(401);
      await f.call('tokens/revoke', { id: writer.meta.id });
      expect((await f.call('secrets/inspect', { scope, name: 'key' }, writer.token)).status).toBe(
        401,
      );
      const expired = await f.token({ expiresInSeconds: 1 });
      await new Promise((r) => setTimeout(r, 1100));
      expect((await f.call('status', {}, expired.token)).status).toBe(401);
    } finally {
      await f.close();
    }
  },
);

scenario('CAS concurrency and delete/recreate never revive a reference', async () => {
  const f = new Fixture();
  try {
    await f.start();
    const t = await f.token();
    const created = await f.call(
      'secrets/put',
      { scope, name: 'key', value: 'first', expectedRevision: 0 },
      t.token,
    );
    const ref = created.data.ref;
    const raced = await Promise.all(
      ['second', 'third'].map((value) =>
        f.call('secrets/put', { scope, name: 'key', value, expectedRevision: 1 }, t.token),
      ),
    );
    expect(raced.map((x) => x.status).sort()).toEqual([200, 409]);
    expect((await f.call('secrets/resolve', { scope, selector: { ref } }, t.token)).status).toBe(
      404,
    );
    const deleted = await f.call(
      'secrets/delete',
      { scope, name: 'key', expectedRevision: 2 },
      t.token,
    );
    expect(deleted.data.ref.revision).toBe(3);
    const recreated = await f.call(
      'secrets/put',
      { scope, name: 'key', value: 'fourth', expectedRevision: 3 },
      t.token,
    );
    expect(recreated.data.ref.id).toBe(ref.id);
    expect(recreated.data.ref.revision).toBe(4);
    expect((await f.call('secrets/resolve', { scope, selector: { ref } }, t.token)).status).toBe(
      404,
    );
  } finally {
    await f.close();
  }
});

scenario(
  'wrong-vault and malformed input fail before mutation and never reflect values',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const t = await f.token();
      const input = { scope, name: 'key', value: 'synthetic-request-canary', expectedRevision: 0 };
      expect((await f.call('secrets/put', input, t.token, '0'.repeat(32))).data.error.code).toBe(
        'vault_mismatch',
      );
      expect((await f.call('secrets/inspect', { scope, name: 'key' }, t.token)).data).toBeNull();
      for (const body of [
        { ...input, unknown: 'synthetic-request-canary' },
        { ...input, expectedRevision: Number.MAX_SAFE_INTEGER + 1 },
        { ...input, value: 'a'.repeat(32769) },
        { ...input, context: { requestId: 'bad\ncontext' } },
      ]) {
        const response = await f.call('secrets/put', body, t.token);
        expect([400, 413]).toContain(response.status);
        expect(JSON.stringify(response.data).includes('synthetic-request-canary')).toBe(false);
      }
      expect(
        (
          await f.call('secrets/put', input, t.token, f.vaultId, {
            origin: 'https://other.example',
          })
        ).status,
      ).toBe(403);
      expect(
        (await f.call('secrets/put', input, t.token, f.vaultId, { 'content-type': 'text/plain' }))
          .status,
      ).toBe(415);
      expect(statSync(f.socket).mode & 0o777).toBe(0o600);
    } finally {
      await f.close();
    }
  },
);

scenario('audit export freezes the head, authenticates cursors, and records access', async () => {
  const f = new Fixture();
  try {
    await f.start();
    const audit = await f.token({
      kind: 'audit-reader',
      namespace: undefined,
      capabilities: ['audit'],
    });
    expect((await f.call('secrets/list', { scope }, audit.token)).status).toBe(403);
    const page = await f.call('audit/read', { after: null, limit: 1 }, audit.token);
    expect(page.status).toBe(200);
    expect(page.data.events[0].seq).toBe(1);
    const through = page.data.through;
    let cursor = page.data.cursor;
    while (cursor.seq < through.seq) {
      const next = await f.call('audit/read', { after: cursor, through, limit: 100 }, audit.token);
      expect(next.status).toBe(200);
      expect(next.data.through).toEqual(through);
      cursor = next.data.cursor;
    }
    const empty = await f.call('audit/read', { after: cursor, through, limit: 100 }, audit.token);
    expect(empty.data.events).toEqual([]);
    expect(empty.data.cursor).toEqual(cursor);
    expect((await f.call('audit/read', { after: null, limit: 1 }, audit.token)).status).toBe(429);
    // Use a separate reader so the negative control reaches cursor verification, not throttling.
    const second = await f.token({
      kind: 'audit-reader',
      namespace: undefined,
      capabilities: ['audit'],
    });
    expect(
      (
        await f.call(
          'audit/read',
          { after: { seq: 1, mac: '0'.repeat(64) }, through, limit: 1 },
          second.token,
        )
      ).data.error.code,
    ).toBe('audit_checkpoint_mismatch');
    // A divergent collector must not bypass its budget by repeatedly writing denial events.
    const rejected = await Promise.all(
      Array.from({ length: 12 }, () =>
        f.call(
          'audit/read',
          { after: { seq: 1, mac: '0'.repeat(64) }, through, limit: 1 },
          second.token,
        ),
      ),
    );
    expect(rejected.some((response) => response.status === 429)).toBe(true);
  } finally {
    await f.close();
  }
});

scenario(
  'unsafe initialization, missing/wrong key, second owner and crash recovery fail safely',
  async () => {
    const f = new Fixture();
    try {
      const original = readFileSync(f.key);
      expect(
        cli([
          'init',
          '--vault-dir',
          f.vault,
          '--key-file',
          f.key,
          '--operator-file',
          f.operatorFile,
        ]).status,
      ).not.toBe(0);
      expect(readFileSync(f.key)).toEqual(original);
      const linked = join(f.root, 'linked.key');
      symlinkSync(f.key, linked);
      expect(
        cli(['serve', '--vault-dir', f.vault, '--key-file', linked, '--socket', f.socket]).status,
      ).not.toBe(0);
      chmodSync(f.key, 0o644);
      expect(
        cli(['serve', '--vault-dir', f.vault, '--key-file', f.key, '--socket', f.socket]).status,
      ).not.toBe(0);
      chmodSync(f.key, 0o600);
      writeFileSync(f.key, Buffer.alloc(32, 7));
      expect(
        cli(['serve', '--vault-dir', f.vault, '--key-file', f.key, '--socket', f.socket]).status,
      ).not.toBe(0);
      writeFileSync(f.key, original);
      await f.start();
      expect(cli(['audit', 'verify', '--vault-dir', f.vault, '--key-file', f.key]).status).not.toBe(
        0,
      );
      const t = await f.token();
      await f.call(
        'secrets/put',
        { scope, name: 'key', value: 'persisted', expectedRevision: 0 },
        t.token,
      );
      await f.stop('SIGKILL');
      removeCrashSocket(f);
      f.logs = '';
      await f.start();
      expect(
        (await f.call('secrets/resolve', { scope, selector: { name: 'key' } }, t.token)).data.value,
      ).toBe('persisted');
    } finally {
      await f.close();
    }
  },
);

scenario(
  'schema and authenticated record/policy/history tampering are rejected on startup',
  async () => {
    for (const sql of [
      'CREATE TRIGGER hostile AFTER INSERT ON audit BEGIN DELETE FROM audit; END',
      'CREATE VIEW hostile AS SELECT * FROM tokens',
      'UPDATE tokens SET capabilities=\'["read"]\'',
      'UPDATE vault SET wrap_count=wrap_count+1',
      "UPDATE audit SET mac=printf('%064d',0)",
    ]) {
      const f = new Fixture();
      try {
        const db = new Database(join(f.vault, 'vault.sqlite'));
        db.exec(sql);
        db.close();
        const started = cli([
          'serve',
          '--vault-dir',
          f.vault,
          '--key-file',
          f.key,
          '--socket',
          f.socket,
        ]);
        expect(started.status).not.toBe(0);
        expect(existsSync(f.socket)).toBe(false);
      } finally {
        await f.close();
      }
    }
  },
);

// A database-only attacker can copy authenticated bytes without knowing a key.
// Existing MAC corruption cases do not exercise replay or removal of valid rows.
scenario('selective replay and deletion cannot revive secrets or revoked tokens', async () => {
  const failures: string[] = [];
  for (const attack of [
    'secret-replay',
    'secret-delete',
    'token-replay',
    'token-delete',
    'header-replay',
  ]) {
    const f = new Fixture();
    try {
      await f.start();
      const t = await f.token();
      expect(
        (
          await f.call(
            'secrets/put',
            { scope, name: 'replay', value: 'old-value', expectedRevision: 0 },
            t.token,
          )
        ).status,
      ).toBe(200);
      await f.stop();
      let db = new Database(join(f.vault, 'vault.sqlite'));
      const oldSecret = db.query('SELECT * FROM secrets').get() as any;
      const oldToken = db.query('SELECT * FROM tokens WHERE id=?').get(t.meta.id) as any;
      const oldHeader = db.query('SELECT * FROM vault').get() as any;
      db.close();
      f.logs = '';
      await f.start();
      expect(
        (
          await f.call(
            'secrets/put',
            { scope, name: 'replay', value: 'new-value', expectedRevision: 1 },
            t.token,
          )
        ).status,
      ).toBe(200);
      expect(
        (await f.call('secrets/delete', { scope, name: 'replay', expectedRevision: 2 }, t.token))
          .status,
      ).toBe(200);
      expect((await f.call('tokens/revoke', { id: t.meta.id })).status).toBe(200);
      await f.stop();
      db = new Database(join(f.vault, 'vault.sqlite'));
      if (attack === 'secret-replay')
        db.query('UPDATE secrets SET revision=?,state=?,updated_at=?,envelope=?,mac=?').run(
          oldSecret.revision,
          oldSecret.state,
          oldSecret.updated_at,
          oldSecret.envelope,
          oldSecret.mac,
        );
      if (attack === 'secret-delete') db.exec('DELETE FROM secrets');
      if (attack === 'token-replay')
        db.query('UPDATE tokens SET revoked_at=?,mac=? WHERE id=?').run(
          oldToken.revoked_at,
          oldToken.mac,
          oldToken.id,
        );
      if (attack === 'token-delete') db.query('DELETE FROM tokens WHERE id=?').run(oldToken.id);
      if (attack === 'header-replay')
        db.query('UPDATE vault SET wrap_count=?,mac=?').run(oldHeader.wrap_count, oldHeader.mac);
      db.close();
      const verified = cli(['audit', 'verify', '--vault-dir', f.vault, '--key-file', f.key]);
      if (verified.status !== 65) failures.push(attack);
    } finally {
      await f.close();
    }
  }
  expect(failures).toEqual([]);
});

scenario(
  'client rejects symlink traversal hidden by dot segments before sending credentials',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const t = await f.token();
      mkdirSync(join(f.root, 'unsafe'), { mode: 0o700 });
      chmodSync(join(f.root, 'unsafe'), 0o777);
      mkdirSync(join(f.root, 'unsafe/sub'), { mode: 0o700 });
      mkdirSync(join(f.root, 'unsafe/actual'), { mode: 0o700 });
      mkdirSync(join(f.root, 'run/actual'), { mode: 0o700 });
      symlinkSync(join(f.root, 'unsafe/sub'), join(f.root, 'run/link'));
      copyFileSync(t.file, join(f.root, 'unsafe/actual/token'));
      // Do not path.join: lexical normalization would remove the attack's '..'.
      const client = createClient({
        socketPath: f.socket,
        tokenFile: `${f.root}/run/link/../actual/token`,
        vaultId: f.vaultId,
      });
      let code: string | undefined;
      try {
        await client.status();
      } catch (error) {
        code = (error as { code: string }).code;
      }
      expect(code).toBe('unsafe_path');
    } finally {
      await f.close();
    }
  },
);

scenario(
  'encrypted backup, fresh-key restore/rekey and tampered envelope rejection preserve the source',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const t = await f.token();
      const canary = 'synthetic-recovery-value';
      await f.call(
        'secrets/put',
        { scope, name: 'recover', value: canary, expectedRevision: 0 },
        t.token,
      );
      await f.stop();
      const source = readFileSync(join(f.vault, 'vault.sqlite'));
      const backup = join(f.root, 'snapshot.backup');
      const result = cli([
        'backup',
        '--vault-dir',
        f.vault,
        '--key-file',
        f.key,
        '--out-file',
        backup,
      ]);
      expect(result.status, result.stderr).toBe(0);
      expect(readFileSync(backup).includes(Buffer.from(canary))).toBe(false);
      expect(readFileSync(backup).includes(Buffer.from('recover'))).toBe(false);
      for (const operation of ['restore', 'rekey']) {
        const dest = join(f.root, operation),
          newKey = join(f.root, `${operation}.key`),
          operator = join(f.root, `${operation}.token`);
        const args =
          operation === 'restore'
            ? ['restore', '--backup-file', backup]
            : ['rekey', '--vault-dir', f.vault];
        const copied = cli([
          ...args,
          '--key-file',
          f.key,
          '--destination',
          dest,
          '--new-key-file',
          newKey,
          '--operator-file',
          operator,
        ]);
        expect(copied.status, copied.stderr).toBe(0);
        expect(readFileSync(newKey)).not.toEqual(readFileSync(f.key));
        const db = new Database(join(dest, 'vault.sqlite'), { readonly: true });
        expect((db.query('SELECT wrap_count FROM vault').get() as any).wrap_count).toBe(1);
        db.close();
        const savedVault = f.vault,
          savedKey = f.key,
          savedOperator = f.operatorFile;
        f.vault = dest;
        f.key = newKey;
        f.operatorFile = operator;
        f.logs = '';
        await f.start();
        expect((await f.call('status', {}, t.token)).status).toBe(401);
        const fresh = await f.token();
        expect(
          (await f.call('secrets/resolve', { scope, selector: { name: 'recover' } }, fresh.token))
            .data.value,
        ).toBe(canary);
        if (operation === 'rekey') {
          // A later mutation and second recovery must translate the latest row
          // binding without confusing it with the first recovery's old revision.
          expect(
            (
              await f.call(
                'secrets/put',
                { scope, name: 'recover', value: 'synthetic-after-recovery', expectedRevision: 1 },
                fresh.token,
              )
            ).status,
          ).toBe(200);
          await f.stop();
          const next = join(f.root, 'second-recovery'),
            nextKey = join(f.root, 'second.key');
          const again = cli([
            'rekey',
            '--vault-dir',
            dest,
            '--key-file',
            newKey,
            '--destination',
            next,
            '--new-key-file',
            nextKey,
            '--operator-file',
            join(f.root, 'second.token'),
          ]);
          expect(again.status, again.stderr).toBe(0);
          expect(cli(['audit', 'verify', '--vault-dir', next, '--key-file', nextKey]).status).toBe(
            0,
          );
        }
        await f.stop();
        f.vault = savedVault;
        f.key = savedKey;
        f.operatorFile = savedOperator;
      }
      const bad = join(f.root, 'bad.backup');
      const bytes = readFileSync(backup);
      bytes[bytes.length - 1]! ^= 1;
      writeFileSync(bad, bytes, { mode: 0o600 });
      const failedDest = join(f.root, 'invalid');
      expect(
        cli([
          'restore',
          '--backup-file',
          bad,
          '--key-file',
          f.key,
          '--destination',
          failedDest,
          '--new-key-file',
          join(f.root, 'bad.key'),
          '--operator-file',
          join(f.root, 'bad.token'),
        ]).status,
      ).not.toBe(0);
      expect(existsSync(join(failedDest, 'complete'))).toBe(false);
      expect(readFileSync(join(f.vault, 'vault.sqlite'))).toEqual(source);
      const trailing = join(f.root, 'trailing.backup');
      writeFileSync(trailing, Buffer.concat([readFileSync(backup), Buffer.from('trailing')]), {
        mode: 0o600,
      });
      expect(
        cli([
          'restore',
          '--backup-file',
          trailing,
          '--key-file',
          f.key,
          '--destination',
          join(f.root, 'trailing'),
          '--new-key-file',
          join(f.root, 'trailing.key'),
          '--operator-file',
          join(f.root, 'trailing.token'),
        ]).status,
      ).not.toBe(0);
    } finally {
      await f.close();
    }
  },
);

scenario(
  'unsafe disclosure outputs are refused before a secret read or credential issuance',
  async () => {
    const f = new Fixture();
    try {
      await f.start();
      const t = await f.token();
      await f.call(
        'secrets/put',
        { scope, name: 'output', value: 'synthetic-output', expectedRevision: 0 },
        t.token,
      );
      const existing = join(f.root, 'existing');
      writeFileSync(existing, 'preserve', { mode: 0o600 });
      const audit = await f.token({
        kind: 'audit-reader',
        namespace: undefined,
        capabilities: ['audit'],
      });
      const beforeExport = (await f.call('status')).data.auditSeq;
      expect(
        cli([
          'audit',
          'read',
          '--socket',
          f.socket,
          '--vault-id',
          f.vaultId,
          '--token-file',
          audit.file,
          '--out-file',
          existing,
        ]).status,
      ).not.toBe(0);
      expect((await f.call('status')).data.auditSeq - beforeExport).toBe(1);
      expect(
        cli(['get', ...f.args(t.file), '--name', 'output', '--out-file', existing]).status,
      ).not.toBe(0);
      expect(
        cli([
          'token',
          'issue',
          '--socket',
          f.socket,
          '--vault-id',
          f.vaultId,
          '--token-file',
          f.operatorFile,
          '--kind',
          'service',
          '--namespace',
          'test',
          '--capabilities',
          'read',
          '--expires-in',
          '1h',
          '--out-file',
          existing,
        ]).status,
      ).not.toBe(0);
      const after = (await f.call('status')).data.auditSeq;
      expect(after - beforeExport).toBe(2); // Two status events; no read, export or issued credential.
      expect(readFileSync(existing, 'utf8')).toBe('preserve');
    } finally {
      await f.close();
    }
  },
);

scenario(
  'startup verifies cipher context and both GCM layers independently of row MACs',
  async () => {
    for (const field of [
      'id',
      'namespace',
      'owner_user_id',
      'workspace_id',
      'consumer_id',
      'name',
      'revision',
      'value',
      'wrappedKey',
    ]) {
      const f = new Fixture();
      try {
        await f.start();
        const t = await f.token();
        expect(
          (
            await f.call(
              'secrets/put',
              { scope, name: 'bound', value: 'synthetic-layer-canary', expectedRevision: 0 },
              t.token,
            )
          ).status,
        ).toBe(200);
        await f.stop();
        const db = new Database(join(f.vault, 'vault.sqlite'));
        const row = db.query('SELECT * FROM secrets').get() as Record<string, any>;
        if (field === 'value' || field === 'wrappedKey') {
          const envelope = JSON.parse(row.envelope);
          envelope[field].tag = '00'.repeat(16);
          row.envelope = JSON.stringify(envelope);
        } else row[field] = field === 'revision' ? 2 : 'substituted';
        // Independent format oracle: preserve outer integrity to reach the GCM/AAD boundary.
        const key = Buffer.from(
          hkdfSync(
            'sha256',
            readFileSync(f.key),
            Buffer.from(f.vaultId),
            Buffer.from(`or3-secrets:v1:record-mac:${f.vaultId}`),
            32,
          ),
        );
        const fields = [
          row.id,
          row.namespace,
          row.owner_user_id,
          row.workspace_id,
          row.consumer_id,
          row.name,
          row.revision,
          row.state,
          row.updated_at,
          row.envelope,
        ];
        row.mac = createHmac('sha256', key)
          .update(JSON.stringify(['or3-secrets', 1, 'secret', fields]))
          .digest('hex');
        key.fill(0);
        db.query(
          'UPDATE secrets SET id=?,namespace=?,owner_user_id=?,workspace_id=?,consumer_id=?,name=?,revision=?,envelope=?,mac=?',
        ).run(
          row.id,
          row.namespace,
          row.owner_user_id,
          row.workspace_id,
          row.consumer_id,
          row.name,
          row.revision,
          row.envelope,
          row.mac,
        );
        db.close();
        const started = cli([
          'serve',
          '--vault-dir',
          f.vault,
          '--key-file',
          f.key,
          '--socket',
          f.socket,
        ]);
        expect(started.status).toBe(65);
        expect(existsSync(f.socket)).toBe(false);
      } finally {
        await f.close();
      }
    }
  },
);

scenario(
  'slow bodies have a whole-request deadline and in-flight admission is bounded',
  async () => {
    const f = new Fixture(),
      held: ReturnType<typeof request>[] = [];
    try {
      await f.start();
      // Invalid credentials and a wrong expected vault must be rejected before
      // unfinished bodies can occupy the authenticated request budget.
      for (const [credential, vaultId, expected] of [
        ['ors1.' + '0'.repeat(32) + '.' + 'x'.repeat(43), f.vaultId, 401],
        [f.operator, '0'.repeat(32), 409],
      ] as const) {
        const invalid = Array.from(
          { length: 16 },
          () =>
            new Promise<number>((yes, no) => {
              const req = request(
                {
                  socketPath: f.socket,
                  path: '/v1/status',
                  method: 'POST',
                  headers: {
                    authorization: `Bearer ${credential}`,
                    'x-or3-vault-id': vaultId,
                    'content-type': 'application/json',
                    'transfer-encoding': 'chunked',
                  },
                },
                (res) => {
                  res.resume();
                  res.on('end', () => yes(res.statusCode!));
                },
              );
              held.push(req);
              req.on('error', no);
              req.write('{');
            }),
        );
        expect(await Promise.all(invalid)).toEqual(Array(16).fill(expected));
        expect((await f.call('status')).status).toBe(200);
        for (const req of held.splice(0)) req.destroy();
      }
      const responses: Promise<number>[] = [];
      for (let n = 0; n < 16; n++) {
        responses.push(
          new Promise<number>((yes, no) => {
            const req = request(
              {
                socketPath: f.socket,
                path: '/v1/status',
                method: 'POST',
                headers: {
                  authorization: `Bearer ${f.operator}`,
                  'x-or3-vault-id': f.vaultId,
                  'content-type': 'application/json',
                  'transfer-encoding': 'chunked',
                },
              },
              (res) => {
                res.resume();
                res.on('end', () => yes(res.statusCode!));
              },
            );
            held.push(req);
            req.on('error', no);
            req.write('{');
          }),
        );
      }
      let overloaded = false;
      for (let n = 0; n < 20; n++) {
        await new Promise((yes) => setTimeout(yes, 10));
        if ((await f.call('status')).status === 429) {
          overloaded = true;
          break;
        }
      }
      expect(overloaded).toBe(true);
      expect(await Promise.all(responses)).toEqual(Array(16).fill(408));
      expect((await f.call('status')).status).toBe(200);
    } finally {
      for (const req of held) req.destroy();
      await f.close();
    }
  },
);

scenario(
  'authenticated wrapping budget accepts its last write and refuses further wrapping',
  async () => {
    const f = new Fixture();
    try {
      const db = new Database(join(f.vault, 'vault.sqlite')),
        h = db.query('SELECT * FROM vault').get() as any;
      const key = Buffer.from(
        hkdfSync(
          'sha256',
          readFileSync(f.key),
          Buffer.from(f.vaultId),
          Buffer.from(`or3-secrets:v1:record-mac:${f.vaultId}`),
          32,
        ),
      );
      h.wrap_count = 999999;
      const hash = createHmac('sha256', key)
        .update(
          JSON.stringify([
            'or3-secrets',
            1,
            'header',
            [h.id, h.vault_id, h.format, h.wrap_count, h.verification, h.created_at],
          ]),
        )
        .digest('hex');
      key.fill(0);
      db.query('UPDATE vault SET wrap_count=?,mac=?').run(h.wrap_count, hash);
      // Independently authenticate the fixture's initial budget in the history too.
      const event = db.query('SELECT * FROM audit WHERE seq=1').get() as any;
      const payload = JSON.parse(event.payload);
      payload.detail = { wrapCount: h.wrap_count };
      event.payload = JSON.stringify(payload);
      const auditKey = Buffer.from(
        hkdfSync(
          'sha256',
          readFileSync(f.key),
          Buffer.from(f.vaultId),
          Buffer.from(`or3-secrets:v1:audit:${f.vaultId}`),
          32,
        ),
      );
      const eventMac = createHmac('sha256', auditKey)
        .update(JSON.stringify(['or3-secrets', 1, 'event', [1, event.previous_mac, event.payload]]))
        .digest('hex');
      auditKey.fill(0);
      db.query('UPDATE audit SET payload=?,mac=? WHERE seq=1').run(event.payload, eventMac);
      db.close();
      await f.start();
      const t = await f.token();
      expect(
        (
          await f.call(
            'secrets/put',
            { scope, name: 'last', value: 'synthetic-last', expectedRevision: 0 },
            t.token,
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await f.call(
            'secrets/put',
            { scope, name: 'exhausted', value: 'must-not-exist', expectedRevision: 0 },
            t.token,
          )
        ).status,
      ).toBe(503);
      expect(
        (await f.call('secrets/inspect', { scope, name: 'exhausted' }, t.token)).data,
      ).toBeNull();
      expect((await f.call('status')).data.storage.wrapCount).toBe(1000000);
      expect(
        (await f.call('secrets/resolve', { scope, selector: { name: 'last' } }, t.token)).data
          .value,
      ).toBe('synthetic-last');
      expect(
        (await f.call('secrets/delete', { scope, name: 'last', expectedRevision: 1 }, t.token))
          .status,
      ).toBe(200);
    } finally {
      await f.close();
    }
  },
);
