# or3-secrets

A small Bun service, CLI, Node client, and optional OR3 Nuxt provider. One Unix socket and one private SQLite database; encrypted secret values, scoped expiring tokens, compare-and-set revisions, required authenticated audit, and fresh-key recovery.

**Initial release candidate (`0.1.0`); npm publication pending.** Qualified locally on Bun **1.3.14** and Node **24.13.0**. Standard AES-256-GCM/HKDF-SHA256 primitives; no FIPS validation or independent security audit. See [assurance](docs/assurance.md), [qualification](https://github.com/Saluana/or3-secrets/blob/main/docs/qualification.md), [Linux core measurements](https://github.com/Saluana/or3-secrets/blob/main/docs/linux-qualification.md), and the [production control gates](https://github.com/Saluana/or3-secrets/blob/main/planning/secure-secret-store/security-profile.md) before use. Production credentials have not been imported.

```sh
# Use exactly Bun 1.3.14 on PATH; do not upgrade another project's global runtime.
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run typecheck
bun run format:check
bun test --timeout 30000 tests
```

The CLI launcher uses Bun with automatic `.env` loading disabled. `serve` never initializes storage. Initialization creates a random 32-byte master key outside the vault directory and a separate operator credential, both exclusively as `0600` files in `0700` directories. It prints an identity/checkpoint receipt, never the credentials. Supported platforms are macOS development and separately qualified Linux; Windows and network filesystems are unsupported.

Read [operations](docs/operations.md) for complete commands, backup/recovery, audit collection, private files, service identities, and rotation. The [local qualification record](https://github.com/Saluana/or3-secrets/blob/main/docs/local-qualification.md) maps the completed checklist to repeatable evidence and separates production acceptance. Read [security and API](docs/security.md) for formats and limits.

Start with `or3-secrets --help`. Every command has its own required options, example and safety notes: `or3-secrets put --help`, `or3-secrets help token issue`, or `or3-secrets restore -h`. Missing options are listed together before any operation. Terminals show readable errors and formatted metadata; redirected output remains JSON, with `{error:{code,message,hint}}` on stderr. `get --stdout` always preserves the exact secret bytes. Existing output paths are refused as `output_exists` (exit 64); choose a new path rather than overwriting one.

Ctrl-C or SIGTERM stops the foreground service gracefully; successful cleanup exits 0 and removes the socket.

Read [architecture](docs/architecture.md) for module boundaries and the security rules they share. Unpublished vault-format compatibility requirements are documented in [security and API](docs/security.md).

## Publishing

From a clean, committed checkout, run `npm publish --dry-run`, then `npm publish`. The publish hook requires Bun 1.3.14 on PATH, checks that the npm version is unused, installs frozen dependencies without lifecycle scripts, rebuilds and qualifies the package, and runs types, formatting, and all tests. npm publishes the validated build directly; no artifact path is needed. Keep lifecycle scripts enabled. See [releasing](docs/releasing.md) for first publication and trusted publishing.

## Installation

Once `0.1.0` is published, install the exact version:

```sh
npm install --save-exact @or3/secrets@0.1.0
npx --yes @or3/secrets@0.1.0 --help
```

The Node client requires Node 24 or newer. Running the CLI or service also requires Bun 1.3.14 on PATH. Installing this package never starts a service or creates credentials. Until publication, install the qualified tarball instead. See [releasing](https://github.com/Saluana/or3-secrets/blob/main/docs/releasing.md) for the qualification and publishing procedure.

## Node client

```ts
import { createClient } from '@or3/secrets/client';
const store = createClient({
  socketPath: '/run/or3-secrets/api.sock',
  tokenFile: '/run/or3/credentials/secrets.token',
  vaultId: 'REPLACE_WITH_INITIALIZATION_VAULT_ID',
  serviceUid: 1000, // Explicit UID of the separately provisioned vault service.
});
const scope = {
  namespace: 'deployment',
  ownerUserId: 'internal-user',
  workspaceId: 'workspace',
  consumerId: 'plugin',
};
await store.put({ scope, name: 'api', value: valueFromProtectedInput, expectedRevision: 0 });
```

`inspect`, `list`, `put`, `resolve`, and `delete` accept optional `{requestId, actorId, activationId}` correlation context. Actor claims are application assertions, never storage authority. The client uses Node HTTP over the socket, rereads its private token file per request, accepts an optional lifecycle `AbortSignal`, validates both directions, enforces expected vault identity, and performs no redirects or automatic retries. A lost mutation response requires inspecting the current revision before an explicit retry.

## OR3 provider

Build this package, then add `@or3/secrets/nuxt` to the updated OR3 host's `modules`. Before publication, install the qualified local tarball explicitly; no registry version is implied. Configure **private** runtime values:

```ts
export default defineNuxtConfig({
  modules: ['@or3/secrets/nuxt'],
  runtimeConfig: {
    secrets: {
      provider: 'or3-secrets',
      namespace: 'deployment',
      socketPath: '/run/or3-secrets/api.sock',
      tokenFile: '/run/or3/credentials/secrets.token',
      vaultId: 'REPLACE_WITH_INITIALIZATION_VAULT_ID',
      serviceUid: 1000,
    },
  },
});
```

Nuxt runtime overrides are `NUXT_SECRETS_PROVIDER`, `NUXT_SECRETS_NAMESPACE`, `NUXT_SECRETS_SOCKET_PATH`, `NUXT_SECRETS_TOKEN_FILE`, `NUXT_SECRETS_VAULT_ID`, and `NUXT_SECRETS_SERVICE_UID`. They contain paths/identity, **not bearer token contents or the master key**. No secret paths enter public runtime config. The module is skipped for static generation and `ssr: false`.

The initial consumer is remembered `host.secrets` in reviewed, package-backed trusted plugins. OR3 derives owner/workspace/plugin from its authenticated session and live sealed activation, rechecks grants, and correlates acting identity separately. `secrets.read` allows trusted plugin code to receive plaintext. Explicit session values remain activation memory; default/remember values use the selected service. Selected provider failures and unsupported activations fail closed. No existing localStorage, Dexie, connection, webhook, Connect, or background-job credentials are migrated. Old remembered values require explicit re-entry. An unselected provider preserves existing deployment behavior.

Secret-bearing browser requests refuse redirects. The OR3 route admits at most 60 requests per minute per internal user across plugins and 16 concurrent package/vault operations per process, returning `429` and `Retry-After` on saturation. No mutation is retried automatically. Configure normal HTTP upload/time limits at the host ingress; the vault's own Unix API has a five-second body deadline.

## Scope

No TCP API, dashboard, identity service, MCP, command runner, offline cache, dynamic credentials, automatic migration, replication, or audit pruning. Encryption does not protect a compromised service identity, kernel, root, OR3 principal, or a plugin already authorized to read a value. Metadata in the live database is authenticated, not encrypted. Whole snapshots require independent encryption/custody.

## Reviewed safety boundaries

The compatible host commit is pinned in [host-compatibility.json](host-compatibility.json); earlier hosts lack the registry and authenticated secret route. This integration requires that commit or a descendant containing it.

Socket clients bind to `serviceUid` (default: the client's own UID); separate service identities require an explicit expected UID and a correctly provisioned service-owned run directory. Every operation rechecks the socket before reading/sending its private credential.

Startup and maintenance run full SQLite index/table integrity checks in addition to authenticated state reconciliation. Invalid credentials and vault IDs are refused before request bodies occupy the authenticated 16-request budget; authentication and authorization repeat in the operation transaction. Audit-reader credentials share a five-per-second budget across every audit-producing operation, including status and denials.

Backup outputs belong outside the source vault. Recovery keys and operator credentials belong outside both managed vaults. Raw backup staging stays on live custody storage; only encrypted bytes are written to the backup medium. Ordinary operations stop at the 960 MiB high-water mark, with an additional 1 MiB admission margin and 64 MiB below the backup ceiling reserved for recovery growth. Offline row-wise rekey can rotate an oversized source without the backup envelope limit and compacts unused/trailing pages. It never drops audit history; an oversized recovered inventory remains blocked for live service and requires an explicit capacity review.
