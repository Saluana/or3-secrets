import { parseArgs } from 'node:util';
import {
  readSync,
  writeSync,
  fsyncSync,
  closeSync,
  fstatSync,
  lstatSync,
  unlinkSync,
} from 'node:fs';
import { resolve, dirname } from 'node:path';
import { createClient } from './client.js';
import { Vault } from './store.js';
import { serve } from './server.js';
import { backup, restore, rekey } from './maintenance.js';
import { readPrivate, createPrivate, syncDirectory } from './files.js';
import {
  MAX_VALUE,
  SecretError,
  fail,
  identifier,
  parseCursor,
  parseScope,
  type Receipt,
  type TokenPolicy,
} from './protocol.js';
import { cliCommands, cliHelp, cliOptions } from './cli-help.js';

process.umask(0o077);
let activeCommand = '';
class CliUsageError extends SecretError {
  constructor(
    public readonly guidance: string,
    public readonly hint: string,
    code = 'invalid_request',
  ) {
    super(code);
  }
}
function usage(message: string, code = 'invalid_request'): never {
  throw new CliUsageError(
    message,
    `Run or3-secrets${activeCommand ? ` ${activeCommand}` : ''} --help for options and examples.`,
    code,
  );
}
function number(value: unknown, flag: string): number {
  if (
    typeof value !== 'string' ||
    !/^\d+$/.test(value) ||
    !Number.isSafeInteger(Number(value)) ||
    Number(value) > Number.MAX_SAFE_INTEGER - 1
  )
    usage(`--${flag} must be a non-negative safe integer.`);
  return Number(value);
}
function expiration(value: unknown): number {
  if (typeof value !== 'string' || !/^\d+[smhd]?$/.test(value))
    usage('--expires-in must be a duration between 1s and 90d, for example 15m or 1h.');
  const suffix = value.at(-1)!,
    scale = ({ s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>)[suffix] ?? 1;
  const seconds = Number(value.replace(/[smhd]$/, '')) * scale;
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 90 * 86400)
    usage('--expires-in must be between 1s and 90d.');
  return seconds;
}
function cursor(value: unknown, flag: string) {
  if (typeof value !== 'string') usage(`--${flag} must use SEQ:MAC from the preceding audit page.`);
  const [seq, mac, extra] = value.split(':');
  if (extra !== undefined || !seq || !/^\d+$/.test(seq) || !mac || !/^[a-f0-9]{64}$/.test(mac))
    usage(`--${flag} must use SEQ:MAC from the preceding audit page.`);
  return parseCursor({ seq: number(seq, flag), mac });
}
function stdin(): string {
  if (process.stdin.isTTY) fail('interactive_input_refused');
  const parts: Buffer[] = [],
    chunk = Buffer.alloc(4096);
  let size = 0;
  try {
    while (true) {
      const count = readSync(0, chunk);
      if (!count) break;
      size += count;
      if (size > MAX_VALUE) fail('too_large', 413);
      parts.push(Buffer.from(chunk.subarray(0, count)));
    }
    const data = Buffer.concat(parts);
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
    } catch {
      return usage('Secret input must be valid UTF-8 text.');
    } finally {
      data.fill(0);
    }
  } finally {
    chunk.fill(0);
    for (const part of parts) part.fill(0);
  }
}
async function privateOutput<T>(
  path: string,
  action: () => Promise<{ bytes: string; result: T }>,
): Promise<T> {
  const fd = createPrivate(path);
  const reserved = fstatSync(fd);
  let complete = false;
  const cleanup = () => {
    if (complete) return;
    try {
      const current = lstatSync(path);
      // Never remove a path replaced while the request was outstanding.
      if (current.dev === reserved.dev && current.ino === reserved.ino) {
        unlinkSync(path);
        syncDirectory(dirname(path));
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
        process.stderr.write(
          'Unable to remove incomplete private output; inspect the output path.\n',
        );
    }
  };
  const interrupted = () => {
    cleanup();
    process.exit(130);
  };
  const terminated = () => {
    cleanup();
    process.exit(143);
  };
  process.once('SIGINT', interrupted);
  process.once('SIGTERM', terminated);
  try {
    const { bytes, result } = await action();
    const buffer = Buffer.from(bytes);
    try {
      let offset = 0;
      while (offset < buffer.length)
        offset += writeSync(fd, buffer, offset, buffer.length - offset);
      fsyncSync(fd);
    } finally {
      buffer.fill(0);
    }
    syncDirectory(dirname(path));
    complete = true;
    return result;
  } finally {
    process.removeListener('SIGINT', interrupted);
    process.removeListener('SIGTERM', terminated);
    cleanup();
    closeSync(fd);
  }
}
async function main() {
  if (Bun.version !== '1.3.14') fail('unsupported_runtime');
  const parsed = (() => {
    try {
      return parseArgs({
        options: {
          ...Object.fromEntries(
            Object.entries(cliOptions).map(([key, option]) => [
              key,
              { type: option.value ? ('string' as const) : ('boolean' as const) },
            ]),
          ),
          help: { type: 'boolean', short: 'h' },
        },
        allowPositionals: true,
        strict: true,
      });
    } catch {
      usage(
        'Unknown option or missing option value. Secret values must be supplied on stdin, not as command arguments.',
      );
    }
  })();
  const values = parsed.values as Record<string, string | boolean | undefined>;
  const { positionals } = parsed;
  const command = (positionals[0] === 'help' ? positionals.slice(1) : positionals).join(' ');
  if (
    values.help ||
    !positionals.length ||
    positionals[0] === 'help' ||
    command === 'token' ||
    command === 'audit'
  ) {
    const help = cliHelp(command);
    if (!help) usage('Unknown command. Use --help to see available commands.');
    process.stdout.write(help);
    return;
  }
  if (!Object.hasOwn(cliCommands, command))
    usage('Unknown command or extra argument. Use --help to see available commands.');
  activeCommand = command;
  const definition = cliCommands[command]!;
  const allowed = [...definition.required, ...(definition.optional ?? [])];
  if (Object.keys(values).some((key) => !allowed.includes(key)))
    usage('An option is not supported by this command.');
  const required = [
    ...definition.required,
    ...(command === 'token issue' && values.kind === 'service' ? ['namespace'] : []),
  ];
  const missing = required.filter((key) => typeof values[key] !== 'string' || !values[key]);
  if (missing.length)
    usage(`Missing required options: ${missing.map((key) => `--${key}`).join(', ')}.`);
  const str = (key: string): string => {
    try {
      return identifier(values[key]);
    } catch {
      usage(
        `--${key} must be nonempty UTF-8 text of at most 128 bytes with no control characters.`,
      );
    }
  };
  const path = (key: string): string => {
    const value = values[key];
    if (typeof value !== 'string' || !value) usage(`Missing required option: --${key}.`);
    return resolve(value);
  };
  if (
    values['vault-id'] !== undefined &&
    (typeof values['vault-id'] !== 'string' || !/^[a-f0-9]{32}$/.test(values['vault-id']))
  )
    usage('--vault-id must be the 32-character lowercase vault ID printed by init.');
  const json = (value: unknown) =>
    process.stdout.write(JSON.stringify(value, null, process.stdout.isTTY ? 2 : undefined) + '\n');
  const receipt = (): Receipt | undefined => {
    if (!values['receipt-file']) return;
    const bytes = readPrivate(path('receipt-file'), 1024);
    try {
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (
        !data ||
        typeof data !== 'object' ||
        Array.isArray(data) ||
        Object.keys(data).some((key) => !['seq', 'mac', 'vaultId'].includes(key)) ||
        typeof data.vaultId !== 'string' ||
        !/^[a-f0-9]{32}$/.test(data.vaultId)
      )
        usage('--receipt-file must contain a JSON receipt with vaultId, seq and mac.');
      return { ...parseCursor({ seq: data.seq, mac: data.mac }), vaultId: data.vaultId };
    } catch {
      usage(
        '--receipt-file must contain a JSON receipt with a 32-character vaultId, positive seq and 64-character mac.',
      );
    } finally {
      bytes.fill(0);
    }
  };
  if (command === 'init') {
    json(
      Vault.create({
        vaultDir: path('vault-dir'),
        keyFile: path('key-file'),
        operatorFile: path('operator-file'),
      }),
    );
    return;
  }
  if (command === 'serve') {
    const service = serve({
      vaultDir: path('vault-dir'),
      keyFile: path('key-file'),
      socketPath: path('socket'),
      ...(values['socket-group']
        ? { socketGroup: number(values['socket-group'], 'socket-group') }
        : {}),
    });
    json({ ready: true, vaultId: service.vaultId });
    return;
  }
  if (command === 'audit verify') {
    const vault = Vault.open(path('vault-dir'), path('key-file'));
    try {
      const expected = receipt();
      if (expected) vault.checkReceipt(expected);
      json(vault.verify());
    } finally {
      vault.close();
    }
    return;
  }
  if (command === 'backup') {
    json(
      backup({
        vaultDir: path('vault-dir'),
        keyFile: path('key-file'),
        outFile: path('out-file'),
        receipt: receipt(),
      }),
    );
    return;
  }
  if (command === 'restore' || command === 'rekey') {
    const common = {
      keyFile: path('key-file'),
      destination: path('destination'),
      newKeyFile: path('new-key-file'),
      operatorFile: path('operator-file'),
      receipt: receipt(),
    };
    json(
      command === 'restore'
        ? restore({ ...common, backupFile: path('backup-file') })
        : rekey({ ...common, vaultDir: path('vault-dir') }),
    );
    return;
  }
  if (command === 'get' && Boolean(values.stdout) === Boolean(values['out-file']))
    usage(
      'Choose exactly one output: --out-file NEW_FILE or --stdout.',
      'explicit_output_required',
    );
  const client = createClient({
    socketPath: path('socket'),
    tokenFile: path('token-file'),
    vaultId: str('vault-id'),
    ...(values['service-uid'] !== undefined
      ? { serviceUid: number(values['service-uid'], 'service-uid') }
      : {}),
  });
  if (command === 'status') {
    json(await client.status());
    return;
  }
  if (command === 'token issue') {
    const outFile = path('out-file');
    const policy: TokenPolicy = {
      kind: str('kind') as TokenPolicy['kind'],
      capabilities: str('capabilities').split(',') as TokenPolicy['capabilities'],
      expiresInSeconds: expiration(values['expires-in']),
    };
    if (!['service', 'audit-reader'].includes(policy.kind))
      usage('--kind must be service or audit-reader.');
    const capabilities =
      policy.kind === 'service' ? ['metadata', 'read', 'write', 'delete'] : ['audit'];
    if (
      !policy.capabilities.length ||
      policy.capabilities.some((value) => !capabilities.includes(value)) ||
      new Set(policy.capabilities).size !== policy.capabilities.length
    )
      usage(
        policy.kind === 'service'
          ? '--capabilities must be a comma-separated subset of metadata,read,write,delete without duplicates.'
          : 'Audit-reader credentials require --capabilities audit.',
      );
    for (const [arg, key] of [
      ['namespace', 'namespace'],
      ['owner-user-id', 'ownerUserId'],
      ['workspace-id', 'workspaceId'],
      ['consumer-id', 'consumerId'],
    ] as const)
      if (values[arg] !== undefined) policy[key] = str(arg);
    if (
      policy.kind === 'audit-reader' &&
      ['namespace', 'owner-user-id', 'workspace-id', 'consumer-id'].some(
        (key) => values[key] !== undefined,
      )
    )
      usage(
        'Audit-reader credentials cannot specify namespace, owner, workspace or consumer scope.',
      );
    const meta = await privateOutput(outFile, async () => {
      const result = await client.issueToken(policy);
      return { bytes: result.token + '\n', result: result.meta };
    });
    json(meta);
    return;
  }
  const limit = values.limit !== undefined ? number(values.limit, 'limit') : undefined;
  if (limit !== undefined && (limit < 1 || limit > 100))
    usage('--limit must be between 1 and 100.');
  const page = {
    ...(values.after ? { after: str('after') } : {}),
    ...(limit !== undefined ? { limit } : {}),
  };
  if (command === 'token list') {
    json(await client.listTokens(page));
    return;
  }
  if (command === 'token revoke') {
    json(await client.revokeToken(str('id')));
    return;
  }
  if (command === 'audit read') {
    const input = {
      after: values.after ? cursor(values.after, 'after') : null,
      ...(values.through ? { through: cursor(values.through, 'through') } : {}),
      limit: limit ?? 100,
    };
    if (values['out-file']) {
      await privateOutput(path('out-file'), async () => ({
        bytes: JSON.stringify(await client.readAudit(input)) + '\n',
        result: undefined,
      }));
    } else json(await client.readAudit(input));
    return;
  }
  const scope = parseScope({
    namespace: str('namespace'),
    ownerUserId: str('owner-user-id'),
    workspaceId: str('workspace-id'),
    consumerId: str('consumer-id'),
  });
  if (command === 'list') {
    json(await client.list({ scope, ...page }));
    return;
  }
  if (command === 'get') {
    if (Boolean(values.name) === Boolean(values.ref))
      usage('Choose exactly one selector: --name NAME or --ref ID:REVISION.');
    let selector: { name: string } | { ref: { id: string; revision: number } };
    if (values.ref) {
      const [id, revision, extra] = str('ref').split(':');
      if (extra || !id || !/^[a-f0-9]{32}$/.test(id) || !revision)
        usage('--ref must use ID:REVISION from inspect.');
      selector = { ref: { id, revision: number(revision, 'ref') } };
    } else selector = { name: str('name') };
    if (values.stdout) process.stdout.write((await client.resolve({ scope, selector })).value);
    else {
      await privateOutput(path('out-file'), async () => ({
        bytes: (await client.resolve({ scope, selector })).value,
        result: undefined,
      }));
      if (process.stderr.isTTY)
        process.stderr.write('Secret saved to the new private output file.\n');
    }
    return;
  }
  const name = str('name');
  if (command === 'inspect') {
    json(await client.inspect({ scope, name }));
    return;
  }
  if (command === 'put' || command === 'delete') {
    const expectedRevision = number(values['expected-revision'], 'expected-revision');
    json(
      command === 'put'
        ? await client.put({ scope, name, value: stdin(), expectedRevision })
        : await client.delete({ scope, name, expectedRevision }),
    );
    return;
  }
  fail('invalid_request');
}
main().catch((error) => {
  const systemCode = (error as NodeJS.ErrnoException)?.code;
  const safe =
    systemCode === 'EEXIST' || systemCode === 'already_exists'
      ? new SecretError('output_exists')
      : error instanceof SecretError
        ? error
        : new SecretError(
            systemCode === 'ENOENT'
              ? 'file_not_found'
              : systemCode === 'EACCES' || systemCode === 'EPERM'
                ? 'permission_denied'
                : 'unavailable',
            systemCode === 'ENOENT' ? 400 : 503,
          );
  const guidance: Record<string, [string, string]> = {
    output_exists: [
      'The output path already exists. Nothing was overwritten.',
      'Choose a new file or destination path. Inspect any existing output before removing it.',
    ],
    file_not_found: [
      'A required file or parent directory does not exist.',
      'Check input paths and create private parent directories (0700). Run the command with --help for an example.',
    ],
    permission_denied: [
      'The operating system denied access.',
      'Check file ownership and directory permissions. Do not loosen private-file permissions.',
    ],
    unsafe_path: [
      'The path does not meet private ownership or permission requirements.',
      'Use trusted paths without symlinks, private directories (0700) and private files (0600). On macOS use /private/tmp, not /tmp.',
    ],
    unsafe_file: [
      'The file does not meet private-file requirements.',
      'Use a regular, single-link file owned by you with mode 0600, inside a private 0700 directory.',
    ],
    unsafe_socket: [
      'The socket does not meet ownership or permission requirements.',
      'Check the service identity, private socket directory and configured client group.',
    ],
    explicit_output_required: [
      'Reading plaintext requires an explicit output choice.',
      'Use --out-file NEW_FILE or --stdout.',
    ],
    interactive_input_refused: [
      'Secret entry in an echoing terminal is refused.',
      'Use a privately prepared UTF-8 file: put [options] < ./input-value. Never put a secret in command arguments.',
    ],
    revision_conflict: [
      'The secret changed since the expected revision.',
      'Run inspect, review the current revision, then explicitly retry with --expected-revision.',
    ],
    not_found: [
      'No current secret matches this name or reference.',
      'Run inspect or list in the same scope. Deleted or superseded references cannot be read.',
    ],
    unauthorized: [
      'The credential is invalid, expired or revoked.',
      'Use the operator credential to issue a new scoped token into a new private file.',
    ],
    forbidden: [
      'This credential is not allowed to perform the operation in this scope.',
      'Check the credential kind, capabilities and complete namespace/owner/workspace/consumer scope.',
    ],
    vault_mismatch: [
      'The running vault does not match --vault-id.',
      'Check the socket path and the vault ID from initialization before continuing.',
    ],
    integrity_failure: [
      'Vault integrity verification failed.',
      'Stop and preserve the vault, key and retained receipts for investigation. Do not initialize or overwrite them.',
    ],
    invalid_backup: [
      'The backup could not be authenticated or validated.',
      'Check that the backup and key belong together. Preserve the source and choose new output paths for any retry.',
    ],
    too_large: [
      'The input exceeds the size limit.',
      'Secret values must be UTF-8 and at most 32 KiB.',
    ],
    unsupported_runtime: [
      'This CLI requires Bun 1.3.14.',
      'Put the qualified Bun 1.3.14 runtime on PATH.',
    ],
    unavailable: [
      'The operation is unavailable.',
      'Check that the service is running, paths and permissions are correct, and disk space is available. Inspect the current revision before retrying a mutation.',
    ],
    capacity_reached: [
      'The vault reached its supported live capacity.',
      'Stop the service and back up or rekey to fresh paths. Preserve the source; do not delete audit history.',
    ],
  };
  const [message, hint] =
    error instanceof CliUsageError
      ? [error.guidance, error.hint]
      : (guidance[safe.code] ?? [
          'The operation was refused.',
          `Run or3-secrets${activeCommand ? ` ${activeCommand}` : ''} --help and inspect the fixed error code.`,
        ]);
  if (process.stderr.isTTY) process.stderr.write(`Error: ${message} [${safe.code}]\n${hint}\n`);
  else process.stderr.write(JSON.stringify({ error: { code: safe.code, message, hint } }) + '\n');
  process.exitCode =
    safe.code === 'integrity_failure' || safe.code === 'invalid_backup'
      ? 65
      : safe.status === 401 || safe.status === 403
        ? 77
        : safe.status >= 500 || safe.status === 409 || safe.status === 429
          ? 75
          : 64;
});
