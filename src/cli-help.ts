const transport = ['socket', 'vault-id', 'token-file'];
const transportOptions = ['service-uid'];
const scoped = [...transport, 'namespace', 'owner-user-id', 'workspace-id', 'consumer-id'];
const onlineExample = '--socket ./run/api.sock --vault-id VAULT_ID --token-file ./service.token';
const scopeExample = `${onlineExample} \\\n  --namespace example --owner-user-id user --workspace-id workspace --consumer-id plugin`;

export const cliOptions: Record<string, { value?: string; description: string }> = {
  'vault-dir': {
    value: 'DIR',
    description: 'Vault directory; init creates it, other commands open it.',
  },
  'key-file': {
    value: 'FILE',
    description: 'Private master-key file, outside the vault directory.',
  },
  'operator-file': {
    value: 'FILE',
    description: 'New private operator credential file; must not exist.',
  },
  socket: { value: 'PATH', description: 'Unix socket path for the running service.' },
  'service-uid': {
    value: 'UID',
    description: 'Expected service/socket owner UID; defaults to your UID.',
  },
  'socket-group': {
    value: 'GID',
    description: 'Numeric client group; socket directory must already match.',
  },
  'token-file': {
    value: 'FILE',
    description: 'Private credential file; never the credential itself.',
  },
  'vault-id': { value: 'ID', description: '32-character vault ID printed by init.' },
  namespace: { value: 'NAME', description: 'Deployment namespace (required for service tokens).' },
  'owner-user-id': {
    value: 'ID',
    description: 'Secret owner; token issue may restrict to this owner.',
  },
  'workspace-id': {
    value: 'ID',
    description: 'Workspace; token issue may restrict to this workspace.',
  },
  'consumer-id': {
    value: 'ID',
    description: 'Plugin/consumer; token issue may restrict to this consumer.',
  },
  name: { value: 'NAME', description: 'Secret name within the complete scope.' },
  'expected-revision': {
    value: 'N',
    description: 'Current revision from inspect; 0 creates a new name.',
  },
  ref: {
    value: 'ID:REVISION',
    description: 'Exact current reference from inspect; alternative to --name.',
  },
  'out-file': {
    value: 'FILE',
    description: 'New private output file; existing paths are never overwritten.',
  },
  stdout: { description: 'Explicitly release plaintext to standard output (get only).' },
  kind: {
    value: 'KIND',
    description: 'service or audit-reader; operator credential required to issue.',
  },
  capabilities: {
    value: 'LIST',
    description: 'Service: metadata,read,write,delete. Audit-reader: audit.',
  },
  'expires-in': {
    value: 'DURATION',
    description: 'Lifetime, e.g. 15m, 1h, 7d; minimum 1s, maximum 90d.',
  },
  id: { value: 'ID', description: 'Credential ID from token issue/list; never the bearer token.' },
  after: {
    value: 'CURSOR',
    description: 'Page cursor: record/token ID, or SEQ:MAC for audit read.',
  },
  through: {
    value: 'SEQ:MAC',
    description: 'Frozen audit head returned by the first export page.',
  },
  limit: { value: 'N', description: 'Maximum number of entries in this page (1–100).' },
  'backup-file': { value: 'FILE', description: 'Authenticated encrypted backup to restore.' },
  destination: { value: 'DIR', description: 'New recovery directory; the source is preserved.' },
  'new-key-file': { value: 'FILE', description: 'New private master-key file; must not exist.' },
  'receipt-file': {
    value: 'FILE',
    description: 'Private retained {vaultId,seq,mac} checkpoint to verify.',
  },
};

interface Command {
  summary: string;
  required: string[];
  optional?: string[];
  example: string;
  notes?: string[];
}
export const cliCommands: Record<string, Command> = {
  init: {
    summary: 'Create a vault, master key and operator credential.',
    required: ['vault-dir', 'key-file', 'operator-file'],
    example:
      'or3-secrets init --vault-dir ./vault --key-file ./master.key --operator-file ./operator.token',
    notes: [
      'Create a private parent directory first: mkdir -m 700 ./example-private',
      'Run commands inside that directory. Copy the vaultId from the result; credentials are written only to files.',
    ],
  },
  serve: {
    summary: 'Run the vault service in the foreground.',
    required: ['vault-dir', 'key-file', 'socket'],
    optional: ['socket-group'],
    example:
      'or3-secrets serve --vault-dir ./vault --key-file ./master.key --socket ./run/api.sock',
    notes: [
      'Create the private socket directory first: mkdir -m 700 ./run',
      'Leave this terminal running; use a second terminal for client commands. Ctrl-C stops the service gracefully (exit 0 after cleanup).',
    ],
  },
  status: {
    optional: transportOptions,
    summary: 'Check vault identity, credential expiry and storage health.',
    required: transport,
    example: `or3-secrets status ${onlineExample}`,
  },
  put: {
    optional: transportOptions,
    summary: 'Create or update a secret from standard input.',
    required: [...scoped, 'name', 'expected-revision'],
    example: `or3-secrets put ${scopeExample} \\\n  --name api --expected-revision 0 < ./input-value`,
    notes: [
      'Input must be UTF-8, at most 32 KiB; bytes and trailing newlines are preserved.',
      'Prepare the input file privately (directory 0700, file 0600). Terminal input is refused to prevent echoing a secret.',
      'To update, inspect first and use its current revision. Never retry a mutation automatically.',
    ],
  },
  get: {
    summary: 'Read a secret with explicit plaintext disclosure.',
    required: scoped,
    optional: [...transportOptions, 'name', 'ref', 'out-file', 'stdout'],
    example: `or3-secrets get ${scopeExample} \\\n  --name api --out-file ./recovered-value`,
    notes: [
      'Choose exactly one selector: --name NAME or --ref ID:REVISION.',
      'Choose exactly one output: --out-file NEW_FILE or --stdout. Output files are 0600 and never overwritten.',
      'A stale or deleted reference cannot read a recreated secret.',
    ],
  },
  inspect: {
    optional: transportOptions,
    summary: 'Show metadata and current revision without reading plaintext.',
    required: [...scoped, 'name'],
    example: `or3-secrets inspect ${scopeExample} --name api`,
  },
  list: {
    summary: 'List secret metadata within one scope.',
    required: scoped,
    optional: [...transportOptions, 'after', 'limit'],
    example: `or3-secrets list ${scopeExample} --limit 100`,
  },
  delete: {
    optional: transportOptions,
    summary: 'Delete a secret at its current revision.',
    required: [...scoped, 'name', 'expected-revision'],
    example: `or3-secrets delete ${scopeExample} --name api --expected-revision 1`,
    notes: [
      'Inspect first. Deletion keeps a tombstone and advances the revision; recreation uses that revision.',
    ],
  },
  'token issue': {
    summary: 'Issue a scoped, expiring credential into a new private file.',
    required: [...transport, 'kind', 'capabilities', 'expires-in', 'out-file'],
    optional: [...transportOptions, 'namespace', 'owner-user-id', 'workspace-id', 'consumer-id'],
    example: `or3-secrets token issue --socket ./run/api.sock --vault-id VAULT_ID \\\n  --token-file ./operator.token --kind service --namespace example \\\n  --owner-user-id user --workspace-id workspace --consumer-id plugin \\\n  --capabilities metadata,read,write,delete --expires-in 1h --out-file ./service.token`,
    notes: [
      'Service tokens require --namespace. Restrict owner/workspace/consumer whenever possible.',
      'For audit export: --kind audit-reader --capabilities audit; omit all scope options.',
      'Only credential metadata is printed; the credential is written exclusively to --out-file.',
    ],
  },
  'token list': {
    summary: 'List credential metadata using operator authority.',
    required: transport,
    optional: [...transportOptions, 'after', 'limit'],
    example:
      'or3-secrets token list --socket ./run/api.sock --vault-id VAULT_ID --token-file ./operator.token',
  },
  'token revoke': {
    optional: transportOptions,
    summary: 'Revoke a credential by its ID using operator authority.',
    required: [...transport, 'id'],
    example:
      'or3-secrets token revoke --socket ./run/api.sock --vault-id VAULT_ID --token-file ./operator.token --id TOKEN_ID',
  },
  'audit read': {
    summary: 'Export a bounded page of authenticated audit events.',
    required: transport,
    optional: [...transportOptions, 'after', 'through', 'limit', 'out-file'],
    example:
      'or3-secrets audit read --socket ./run/api.sock --vault-id VAULT_ID --token-file ./audit.token --limit 100 --out-file ./audit-page.json',
    notes: [
      'Use an audit-reader credential. Omit --after on the first page; subsequent pages use cursor and through as SEQ:MAC.',
      'Persist each page before advancing the checkpoint. Pause at least 30 seconds before capturing another head.',
    ],
  },
  'audit verify': {
    summary: 'Verify a stopped vault and optionally a retained checkpoint.',
    required: ['vault-dir', 'key-file'],
    optional: ['receipt-file'],
    example: 'or3-secrets audit verify --vault-dir ./vault --key-file ./master.key',
    notes: ['Stop the service first; offline maintenance requires exclusive ownership.'],
  },
  backup: {
    summary: 'Encrypt a stopped vault into a new backup file.',
    required: ['vault-dir', 'key-file', 'out-file'],
    optional: ['receipt-file'],
    example:
      'or3-secrets backup --vault-dir ./vault --key-file ./master.key --out-file ./snapshot.backup',
    notes: [
      'Stop the service first. Keep the backup and its key under separately controlled custody.',
    ],
  },
  restore: {
    summary: 'Restore an encrypted backup to a fresh-key copy.',
    required: ['backup-file', 'key-file', 'destination', 'new-key-file', 'operator-file'],
    optional: ['receipt-file'],
    example:
      'or3-secrets restore --backup-file ./snapshot.backup --key-file ./master.key \\\n  --destination ./restored --new-key-file ./restored.key --operator-file ./restored.token',
    notes: [
      'All destination paths must be new. All copied credentials are revoked; use the new operator file to issue new ones.',
      'The source is preserved. Reconcile restored upstream credentials before reconnecting real consumers.',
    ],
  },
  rekey: {
    summary: 'Copy a stopped vault under a fresh master key.',
    required: ['vault-dir', 'key-file', 'destination', 'new-key-file', 'operator-file'],
    optional: ['receipt-file'],
    example:
      'or3-secrets rekey --vault-dir ./vault --key-file ./master.key \\\n  --destination ./rekeyed --new-key-file ./rekeyed.key --operator-file ./rekeyed.token',
    notes: [
      'Stop the service first. All destination paths must be new; the source is preserved.',
      'All copied credentials are revoked. Retain old keys for retained backups.',
    ],
  },
};

export function cliHelp(command = ''): string | undefined {
  const definition = Object.hasOwn(cliCommands, command) ? cliCommands[command] : undefined;
  if (definition) {
    const options = (keys: string[]) =>
      keys
        .map((key) => {
          const option = cliOptions[key]!;
          return `  ${`--${key}${option.value ? ` ${option.value}` : ''}`.padEnd(32)}${option.description}`;
        })
        .join('\n');
    return `or3-secrets ${command} — ${definition.summary}\n\nUsage: or3-secrets ${command} [options]${command === 'put' ? ' < PRIVATE_FILE' : ''}\n\nRequired options:\n${options(definition.required)}\n${definition.optional?.length ? `\nOptional options:\n${options(definition.optional)}\n` : ''}\n  -h, --help                      Show this help.\n\nExample:\n  ${definition.example}\n${definition.notes?.length ? `\n${definition.notes.join('\n')}\n` : ''}`;
  }
  if (command && command !== 'token' && command !== 'audit') return;
  const commands = Object.entries(cliCommands).filter(
    ([name]) => !command || name.startsWith(`${command} `),
  );
  return `or3-secrets — private local secret storage\n\nUsage: or3-secrets ${command ? `${command} ` : ''}<command> [options]\n\nCommands:\n${commands.map(([name, spec]) => `  ${name.padEnd(18)}${spec.summary}`).join('\n')}\n\nRun or3-secrets ${command ? `${command} ` : ''}<command> --help for required options and an example.\n${command ? '' : '\nStart here: init → serve (leave running) → token issue → put / get.\nClient commands require socket, vault ID and a private token file; secret commands also require their full scope.\nSecret values use stdin; get requires --out-file or --stdout. Credentials stay in private files.\n'}\nOperator guide: docs/operations.md\n`;
}
