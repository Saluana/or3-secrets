# Architecture

The service owns a private SQLite vault and exposes a bounded API over a Unix socket. The Node client and optional Nuxt provider never open the database or load its master key.

| Module                                        | Responsibility                                                                                                                                           |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `protocol.ts`                                 | Wire limits, scope/context validation, operation allowlists and shared result types. Every remote result is validated before it reaches a client caller. |
| `server.ts`                                   | Socket lifecycle, admission before body reads, request bounds and bounded rejection telemetry.                                                           |
| `store.ts`                                    | Key lifetime, authentication/authorization, exclusive transactions, operations, audit append and fail-stop state.                                        |
| `schema.ts`                                   | Exact SQLite schema, permitted indexes, integrity checks and required SQLite settings.                                                                   |
| `records.ts`                                  | Stored row shapes, canonical MAC fields, row authentication and public metadata.                                                                         |
| `history.ts`                                  | Streaming audit-chain verification and reconstruction of authenticated inventory commitments.                                                            |
| `crypto.ts`                                   | Domain-separated keys/MACs, envelope encryption and temporary plaintext wiping.                                                                          |
| `files.ts`                                    | Private path/ownership checks, exclusive output creation, complete writes and disk headroom.                                                             |
| `maintenance.ts`                              | Authenticated backups and fresh-key restore/rekey into new paths.                                                                                        |
| `cli.ts`, `cli-help.ts`                       | Command validation, explicit plaintext outputs, cleanup, help and fixed error guidance.                                                                  |
| `client.ts`, `module.ts`, `runtime/plugin.ts` | Node transport and private Nitro registration against the pinned OR3 host.                                                                               |

## Rules that cross module boundaries

- Validate complete scope and request context at the protocol boundary. Authenticate before reading request bodies; authenticate and authorize again within the operation transaction.
- A successful secret mutation and its audit record commit together. Record MACs authenticate contents; the audit chain binds the exact current row, revision/tombstone state, token revocation state and wrapping count. Row authentication alone cannot detect removal or replay.
- Verify schema, header, complete streamed audit history, current rows and live ciphertext before accepting a vault. Keep verification order and fail-stop behavior explicit in `Vault.verify()`.
- The vault owns derived-key buffers and wipes them on close or failed open. Crypto helpers wipe temporary buffers. Never put secret values, bearer tokens or key material in logs, error guidance or receipts.
- Maintenance requires exclusive offline custody, authenticated input and new destination paths. It preserves the source, uses a fresh master key and revokes copied credentials. Retained receipts detect rollback only when stored outside the vault's rollback domain.
- Output files are private and never overwrite existing paths. Failed online outputs remove only the inode reserved by that command; successful plaintext disclosure requires an explicit CLI output choice.
- The provider keeps configuration server-side and fails closed during outages or identity mismatch. Existing device-local credentials are a separate owner and are not implicitly imported.

## Development and qualification

`bun run format:check` enforces one style. `bun run typecheck` checks production code separately from all TypeScript scripts, fixtures and tests, without putting tooling declarations into the published package. `scripts/lib/` owns concrete process/environment fixtures; command-specific qualification behavior stays in its owning script. Checked Node fixture files are executed by the actual Node runtime.

Only runtime output, the launcher and operating/security documentation ship in the package. Planning, historical review records, qualification scripts and receipts remain in the source repository. See [operations](operations.md) for commands and [security](security.md) for formats and limits. Local qualification does not establish production acceptance.
