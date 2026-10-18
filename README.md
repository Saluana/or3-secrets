# or3-secrets

A small Bun service, CLI, Node client, and optional OR3 Nuxt provider. One Unix socket and one private SQLite database; encrypted secret values, scoped expiring tokens, compare-and-set revisions, required authenticated audit, and fresh-key recovery.

**Development implementation, unpublished (`0.0.0`).** Qualified locally on Bun **1.3.14** and Node **24.13.0**. Standard AES-256-GCM/HKDF-SHA256 primitives; no FIPS validation or independent security audit. See [assurance](docs/assurance.md), [qualification](docs/qualification.md), [Linux core measurements](docs/linux-qualification.md), and the [production control gates](planning/secure-secret-store/security-profile.md) before use. Production credentials have not been imported.

```sh
# Use exactly Bun 1.3.14 on PATH; do not upgrade another project's global runtime.
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run typecheck
bun test --timeout 30000 tests
```

The CLI launcher uses Bun with automatic `.env` loading disabled. `serve` never initializes storage. Initialization creates a random 32-byte master key outside the vault directory and a separate operator credential, both exclusively as `0600` files in `0700` directories. It prints an identity/checkpoint receipt, never the credentials. Supported platforms are macOS development and separately qualified Linux; Windows and network filesystems are unsupported.

Read [operations](docs/operations.md) for complete commands, backup/recovery, audit collection, private files, service identities, and rotation. Read [security and API](docs/security.md) for formats and limits. The [upstream source analysis](planning/secure-secret-store/source-analysis.md) explains the selected ideas from secretctl and Dopbase; no upstream source was copied.

Start with `or3-secrets --help`. Every command has its own required options, example and safety notes: `or3-secrets put --help`, `or3-secrets help token issue`, or `or3-secrets restore -h`. Missing options are listed together before any operation. Terminals show readable errors and formatted metadata; redirected output remains JSON, with `{error:{code,message,hint}}` on stderr. `get --stdout` always preserves the exact secret bytes. Existing output paths are refused as `output_exists` (exit 64); choose a new path rather than overwriting one.

Ctrl-C or SIGTERM stops the foreground service gracefully; successful cleanup exits 0 and removes the socket.

The [internal security review](docs/security-review.md) records the replay, filesystem, redirect and admission fixes and their regression evidence. Earlier development vaults without the new audit state evidence are refused; create a fresh disposable vault rather than reusing or overwriting those fixtures.

## Node client

```ts
import { createClient } from '@or3/secrets/client';
const store = createClient({
  socketPath: '/run/or3-secrets/api.sock',
  tokenFile: '/run/or3/credentials/secrets.token',
  vaultId: 'REPLACE_WITH_INITIALIZATION_VAULT_ID',
});
const scope = { namespace: 'deployment', ownerUserId: 'internal-user', workspaceId: 'workspace', consumerId: 'plugin' };
await store.put({ scope, name: 'api', value: valueFromProtectedInput, expectedRevision: 0 });
```

`inspect`, `list`, `put`, `resolve`, and `delete` accept optional `{requestId, actorId, activationId}` correlation context. Actor claims are application assertions, never storage authority. The client uses Node HTTP over the socket, rereads its private token file per request, accepts an optional lifecycle `AbortSignal`, validates both directions, enforces expected vault identity, and performs no redirects or automatic retries. A lost mutation response requires inspecting the current revision before an explicit retry.

## OR3 provider

Build this package, then add `@or3/secrets/nuxt` to the updated OR3 host's `modules`. Before publication, install the qualified local tarball explicitly; no registry version is implied. Configure **private** runtime values:

```ts
export default defineNuxtConfig({
  modules: ['@or3/secrets/nuxt'],
  runtimeConfig: { secrets: {
    provider: 'or3-secrets', namespace: 'deployment',
    socketPath: '/run/or3-secrets/api.sock',
    tokenFile: '/run/or3/credentials/secrets.token',
    vaultId: 'REPLACE_WITH_INITIALIZATION_VAULT_ID',
  } },
});
```

Nuxt runtime overrides are `NUXT_SECRETS_PROVIDER`, `NUXT_SECRETS_NAMESPACE`, `NUXT_SECRETS_SOCKET_PATH`, `NUXT_SECRETS_TOKEN_FILE`, and `NUXT_SECRETS_VAULT_ID`. They contain paths/identity, **not bearer token contents or the master key**. No secret paths enter public runtime config. The module is skipped for static generation and `ssr: false`.

The initial consumer is remembered `host.secrets` in reviewed, package-backed trusted plugins. OR3 derives owner/workspace/plugin from its authenticated session and live sealed activation, rechecks grants, and correlates acting identity separately. `secrets.read` allows trusted plugin code to receive plaintext. Explicit session values remain activation memory; default/remember values use the selected service. Selected provider failures and unsupported activations fail closed. No existing localStorage, Dexie, connection, webhook, Connect, or background-job credentials are migrated. Old remembered values require explicit re-entry. An unselected provider preserves existing deployment behavior.

Secret-bearing browser requests refuse redirects. The OR3 route admits at most 60 requests per minute per internal user across plugins and 16 concurrent package/vault operations per process, returning `429` and `Retry-After` on saturation. No mutation is retried automatically. Configure normal HTTP upload/time limits at the host ingress; the vault's own Unix API has a five-second body deadline.

## Scope

No TCP API, dashboard, identity service, MCP, command runner, offline cache, dynamic credentials, automatic migration, replication, or audit pruning. Encryption does not protect a compromised service identity, kernel, root, OR3 principal, or a plugin already authorized to read a value. Metadata in the live database is authenticated, not encrypted. Whole snapshots require independent encryption/custody.
