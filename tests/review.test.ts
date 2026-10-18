// Review regressions at storage/CLI/HTTP boundaries. The original suite did not
// corrupt secondary-index bytes, alias maintenance outputs into source sidecars,
// exercise all audit-reader routes, or promise rejection before network access.
// No fault-injection options or private production exports are used.
import { expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import {
  existsSync,
  openSync,
  closeSync,
  ftruncateSync,
  readFileSync,
  writeFileSync,
  statSync,
  renameSync,
  mkdirSync,
  copyFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { Fixture, cli, scope } from './helpers';
import { createClient } from '../src/client';

// A restored filesystem snapshot can fork an admitted lineage without exposing
// its key. Prior replay tests only substituted different revision numbers. A
// retained receipt must also reject a valid same-revision row from another fork.
test('retained audit receipt binds same-revision contents across database forks', async () => {
  const f = new Fixture();
  const original = f.vault,
    fork = join(f.root, 'fork');
  try {
    await f.start();
    const t = await f.token();
    const put = (value: string, expectedRevision: number) =>
      f.call('secrets/put', { scope, name: 'forked', value, expectedRevision }, t.token);
    expect((await put('synthetic-seed', 0)).status).toBe(200);
    await f.stop();
    mkdirSync(fork, { mode: 0o700 });
    for (const name of ['vault.sqlite', 'complete'])
      copyFileSync(join(original, name), join(fork, name));
    f.logs = '';
    await f.start();
    expect((await put('synthetic-original', 1)).status).toBe(200);
    await f.stop();
    const receiptFile = join(f.root, 'retained.json');
    const receipt = cli(['audit', 'verify', '--vault-dir', original, '--key-file', f.key]);
    expect(receipt.status).toBe(0);
    writeFileSync(receiptFile, receipt.stdout, { mode: 0o600 });

    f.vault = fork;
    f.logs = '';
    await f.start();
    expect((await put('synthetic-other-branch', 1)).status).toBe(200);
    await f.stop();
    const branchDb = new Database(join(fork, 'vault.sqlite'));
    const other = branchDb.query('SELECT envelope,updated_at,mac FROM secrets').get() as {
      envelope: string;
      updated_at: number;
      mac: string;
    };
    branchDb.close();
    const db = new Database(join(original, 'vault.sqlite'));
    db.query('UPDATE secrets SET envelope=?,updated_at=?,mac=?')
      .run(other.envelope, other.updated_at, other.mac);
    db.close();
    const refused = cli([
      'audit', 'verify', '--vault-dir', original, '--key-file', f.key,
      '--receipt-file', receiptFile,
    ]);
    expect(refused.status, 'a foreign revision-2 row must not pass the retained original receipt')
      .toBe(65);
    expect(JSON.parse(refused.stderr).error.code).toBe('integrity_failure');
  } finally {
    await f.close();
  }
});

// Admission checks must retain the existing fail-stop contract for real storage
// failures. Moving the live database is an external fault, not a production seam.
test('storage admission failure stops service and preserves recoverable source', async () => {
  const f = new Fixture();
  const file = join(f.vault, 'vault.sqlite'),
    held = file + '.held';
  try {
    await f.start();
    renameSync(file, held);
    expect((await f.call('status')).status).toBe(503);
    const until = Date.now() + 2000;
    while (f.child!.exitCode === null && Date.now() < until) await Bun.sleep(20);
    expect(f.child!.exitCode).toBe(1);
    expect(existsSync(f.socket)).toBe(false);
    renameSync(held, file);
    f.logs = '';
    await f.start();
    expect((await f.call('status')).status).toBe(200);
  } finally {
    await f.close();
  }
});

test('secondary-index corruption is rejected by service and maintenance admission', async () => {
  const f = new Fixture();
  try {
    await f.start();
    const t = await f.token();
    expect(
      (
        await f.call(
          'secrets/put',
          { scope, name: 'index-only', value: 'synthetic-index', expectedRevision: 0 },
          t.token,
        )
      ).status,
    ).toBe(200);
    await f.stop();
    const file = join(f.vault, 'vault.sqlite');
    let db = new Database(file);
    const page = (
      db.query("SELECT rootpage FROM sqlite_schema WHERE name='secrets_scope'").get() as {
        rootpage: number;
      }
    ).rootpage;
    const size = Object.values(db.query('PRAGMA page_size').get() as object)[0] as number;
    db.close();
    const bytes = readFileSync(file),
      start = (page - 1) * size;
    expect(bytes[start]).toBe(10); // One-entry index leaf, not an authenticated table page.
    const offset = bytes.subarray(start, start + size).indexOf(Buffer.from(scope.namespace));
    expect(offset).toBeGreaterThan(0);
    bytes[start + offset] = 'u'.charCodeAt(0);
    writeFileSync(file, bytes);
    db = new Database(file);
    expect(Object.values(db.query('PRAGMA quick_check(1)').get() as object)[0]).toBe('ok');
    expect(Object.values(db.query('PRAGMA integrity_check(1)').get() as object)[0]).not.toBe('ok');
    db.close();
    for (const args of [
      ['serve', '--socket', f.socket],
      ['audit', 'verify'],
      ['backup', '--out-file', join(f.root, 'corrupt.backup')],
      [
        'rekey',
        '--destination',
        join(f.root, 'copy'),
        '--new-key-file',
        join(f.root, 'copy.key'),
        '--operator-file',
        join(f.root, 'copy.token'),
      ],
    ])
      expect(cli([...args, '--vault-dir', f.vault, '--key-file', f.key]).status).toBe(65);
    expect(existsSync(f.socket)).toBe(false);
  } finally {
    await f.close();
  }
});

test('maintenance artifacts cannot alias either managed vault and survive subsequent source use', async () => {
  const f = new Fixture();
  try {
    for (const sidecar of ['vault.sqlite-journal', 'vault.sqlite-wal']) {
      const path = join(f.vault, sidecar);
      expect(
        cli(['backup', '--vault-dir', f.vault, '--key-file', f.key, '--out-file', path]).status,
      ).not.toBe(0);
      expect(existsSync(path)).toBe(false);
      for (const field of ['key', 'token']) {
        const suffix = sidecar + field;
        const result = cli([
          'rekey',
          '--vault-dir',
          f.vault,
          '--key-file',
          f.key,
          '--destination',
          join(f.root, suffix),
          '--new-key-file',
          field === 'key' ? path : join(f.root, suffix + '.key'),
          '--operator-file',
          field === 'token' ? path : join(f.root, suffix + '.token'),
        ]);
        expect(result.status).not.toBe(0);
        expect(existsSync(path)).toBe(false);
      }
    }
    const backup = join(f.root, 'safe.backup');
    expect(
      cli(['backup', '--vault-dir', f.vault, '--key-file', f.key, '--out-file', backup]).status,
    ).toBe(0);
    const original = readFileSync(backup);
    await f.start();
    expect((await f.call('status')).status).toBe(200);
    await f.stop();
    expect(readFileSync(backup)).toEqual(original);
  } finally {
    await f.close();
  }
});

test('audit-reader admission bounds status and denial audit writes across all operations', async () => {
  const f = new Fixture();
  try {
    await f.start();
    const reader = await f.token({
      kind: 'audit-reader',
      namespace: undefined,
      capabilities: ['audit'],
    });
    const before = (await f.call('status')).data.auditSeq;
    const began = Math.floor(Date.now() / 1000);
    const responses = await Promise.all(
      Array.from({ length: 40 }, (_, n) =>
        f.call(n % 2 ? 'status' : 'tokens/list', {}, reader.token),
      ),
    );
    const seconds = Math.floor(Date.now() / 1000) - began + 1;
    const admitted = responses.filter((r) => r.status !== 429).length;
    expect(admitted).toBeLessThanOrEqual(seconds * 5);
    expect(responses.some((r) => r.status === 429)).toBe(true);
    expect((await f.call('status')).data.auditSeq - before).toBe(admitted + 1);
  } finally {
    await f.close();
  }
});

test('client operation failures reject promises and a mismatched service UID sends no credential', async () => {
  const f = new Fixture();
  try {
    await f.start();
    const t = await f.token();
    const options = { socketPath: f.socket, tokenFile: t.file, vaultId: f.vaultId };
    // The Node process exercises the shipped client as well as source behavior.
    const wrong = createClient({ ...options, serviceUid: process.getuid!() + 1 } as Parameters<
      typeof createClient
    >[0]);
    const missing = createClient({ ...options, tokenFile: join(f.root, 'missing.token') });
    const c = createClient(options);
    const before = (await f.call('status')).data.auditSeq;
    for (const run of [
      () => wrong.status(),
      () => missing.status(),
      () => c.revokeToken('bad\nidentifier'),
    ]) {
      const promise = run();
      expect(promise).toBeInstanceOf(Promise);
      await expect(promise).rejects.toBeDefined();
    }
    expect((await f.call('status')).data.auditSeq - before).toBe(1);
  } finally {
    await f.close();
  }
});

test('live capacity refuses work before backup limits and oversized sources retain row-wise rekey', async () => {
  const f = new Fixture();
  try {
    const file = join(f.vault, 'vault.sqlite');
    // The live boundary is lower than the backup ceiling, even with no new
    // secret write: status itself would need a durable audit allocation.
    let boundary = openSync(file, 'r+');
    try {
      ftruncateSync(boundary, 960 * 1024 ** 2 - 1024 ** 2);
    } finally {
      closeSync(boundary);
    }
    await f.start();
    expect((await f.call('status')).data.error.code).toBe('capacity_reached');
    await f.stop();
    f.logs = '';
    const fd = openSync(file, 'r+');
    try {
      ftruncateSync(fd, 2 ** 30 + 4096);
    } finally {
      closeSync(fd);
    }
    await f.start();
    const refused = await f.call('status');
    expect(refused.status).toBe(503);
    expect(refused.data.error.code).toBe('capacity_reached');
    await f.stop();
    const dest = join(f.root, 'recovered'),
      key = join(f.root, 'recovered.key'),
      operator = join(f.root, 'recovered.token');
    const result = cli([
      'rekey',
      '--vault-dir',
      f.vault,
      '--key-file',
      f.key,
      '--destination',
      dest,
      '--new-key-file',
      key,
      '--operator-file',
      operator,
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(statSync(join(dest, 'vault.sqlite')).size).toBeLessThan(960 * 1024 ** 2);
    expect(cli(['audit', 'verify', '--vault-dir', dest, '--key-file', key]).status).toBe(0);
    expect(statSync(file).size).toBe(2 ** 30 + 4096);
  } finally {
    await f.close();
  }
});
