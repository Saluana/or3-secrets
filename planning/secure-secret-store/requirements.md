# Requirements

## Introduction

Build `or3-secrets`: a small Bun service and CLI that store application secrets securely and expose an optional OR3 provider. Prefer a narrow, reviewable implementation over feature parity with a general secrets platform. This document specifies the initial release; it does not authorize production deployment or credential migration.

## Context

OR3 currently has several separate credential stores rather than a general secret-store provider. Trusted-plugin `host.secrets` defaults to plaintext browser localStorage; the user OpenRouter key is held in device-local Dexie KV and excluded from sync. Server plugin connections already encrypt credentials with an environment-supplied key, while Connect, webhooks, and background jobs have their own encryption paths. Existing connection persistence follows the selected sync provider and is not a pluggable secret backend. The first new consumer will be persistent secrets for authenticated, package-backed trusted plugins, using existing session, activation, package, and grant authority. Research reviewed secretctl at `2de7b68d61dae81988ca96161e2a65b11badc618` and Dopbase at `df4c02def17d5186088b245cc98d7e229992bebb`; see [source analysis](source-analysis.md).

## Assumptions

- Repository: `/Users/brendon/Documents/or3/or3-secrets`; Git was initialized on `main` before planning files were created.
- Bun runs the service, CLI, and tests. The server SDK/provider must also run in OR3's Node 24 runtime without importing `bun:*`.
- Linux is the production target; macOS is supported for development. One local service process owns one SQLite database on a local filesystem.
- Service and OR3 communicate through a shared Unix socket. They can run as separate users/containers; only the socket and OR3 token are shared with OR3.
- The host administrator, kernel, secret-service process, and authorized plaintext consumers are trusted. A stolen database alone must not reveal values. A fully compromised host or authorized OR3 server can access secrets within its authority.
- The master key is random, supplied through a protected file, and backed up separately. There is no human-password unlock flow in this release.
- The service is optional. Configuring it explicitly changes the selected consumer's persistence behavior; existing deployments keep their current behavior until configured.
- Proposed package name: `@or3/secrets`; availability and publication are future release checks, not assumptions about registry ownership.

## Out of Scope

- Public/TCP listeners, remote administration, TLS termination, Windows, multi-node replication, HA, and network filesystems.
- Dashboard, user accounts, SSO, policy language, dynamic credentials, PKI, KMS integrations, and multi-cloud backends.
- MCP, arbitrary command execution, environment injection, generic HTTP proxying, or claims that output redaction prevents exfiltration.
- Offline plaintext caches, automatic availability fallbacks, plaintext export, bulk import, and automatic migration from existing stores.
- Replacing connection credential persistence, the OpenRouter user-key flow, Connect tokens, webhook signing keys, or background-job snapshots in this release.
- A guarantee of JavaScript memory zeroization, protection against host compromise, perfect secure deletion from SSDs/snapshots, or rollback detection without a separately trusted checkpoint.

## Requirements

### R1 — Explicit, safe initialization and startup

**User story:** As an operator, I want startup to refuse unsafe or incomplete storage so a configuration error cannot create a new empty vault or expose key material.

- R1.AC1: WHEN `init` targets an existing vault, key, or bootstrap-token path, THEN the system SHALL refuse without overwriting any existing file.
- R1.AC2: WHEN initializing, THEN the system SHALL generate keys and identifiers with the platform CSPRNG, create private directories/files with restrictive modes at creation, and place the master key outside the database directory.
- R1.AC3: WHEN opening key, token, database, or socket paths, THEN the system SHALL reject unsupported symlinks, unexpected ownership/types, or permissions that expose private material beyond the declared service identity.
- R1.AC4: WHEN the database, key, schema, authenticated metadata, or audit chain is absent, incompatible, or invalid, THEN `serve` SHALL fail before accepting requests; it SHALL never initialize or replace them implicitly.
- R1.AC5: WHEN another service or maintenance operation owns the vault, THEN a second owner SHALL fail without altering its database or socket.

### R2 — Authenticated encryption and key separation

**User story:** As an owner, I want copied or modified storage to protect my secret values and fail safely on tampering.

- R2.AC1: WHEN persisting a value, THEN the system SHALL encrypt it using a fresh random per-write 256-bit data key and AES-256-GCM with a full authentication tag; the data key SHALL be wrapped with a separately derived key.
- R2.AC2: WHEN encrypting or resolving, THEN both encryption layers SHALL authenticate an unambiguous encoding of the vault, format, record ID, complete scope, secret name, and revision.
- R2.AC3: WHEN ciphertext, wrapped keys, authenticated record metadata, or token policy is altered, THEN use of the altered material SHALL fail without returning plaintext or expanding authority.
- R2.AC4: WHEN deriving wrapping, record-authentication, audit, verification, and backup keys, THEN the system SHALL use standard HKDF-SHA-256 with distinct purpose labels; it SHALL implement no custom cipher or password-derived master key.
- R2.AC5: WHEN handling plaintext, THEN the system SHALL avoid persistent plaintext copies and best-effort clear owned mutable buffers, while documenting the limits of Bun/JavaScript strings and garbage collection.

### R3 — Explicit, scoped machine authority

**User story:** As an operator, I want each client to have only the secret operations and scope it needs.

- R3.AC1: WHEN a request lacks a valid, unexpired, unrevoked bearer token, THEN the service SHALL deny it before accessing secret records.
- R3.AC2: WHEN issuing a service token, THEN the system SHALL return the random 256-bit credential only to a newly created private output file, persist only its digest and authenticated policy, and require explicit namespace, capabilities, and expiration.
- R3.AC3: WHEN authorizing any secret operation, THEN the system SHALL enforce namespace plus any exact owner/workspace/consumer restrictions in the token, separately from the requested record identity.
- R3.AC4: WHEN a token has only metadata or write authority, THEN it SHALL NOT resolve plaintext; references and knowledge of IDs SHALL NOT confer authority.
- R3.AC5: WHEN a service token requests token administration, THEN the service SHALL deny it. Only the operator credential may issue, list, or revoke service tokens; it SHALL NOT be accepted as a normal secret-use token.
- R3.AC6: WHEN revocation commits, THEN requests authorized afterward SHALL fail. Operations admitted before that commit may finish; this boundary SHALL be documented and tested.

### R4 — Small, bounded local API

**User story:** As an integrating application, I want a predictable API with a limited attack surface.

- R4.AC1: WHEN serving, THEN the service SHALL bind only a Unix socket with declared owner/group access and SHALL expose no TCP listener.
- R4.AC2: WHEN processing a request, THEN the service SHALL validate the exact operation schema, reject unknown fields and unsupported media types, bound body size/time and concurrency, and reject browser-origin requests.
- R4.AC3: WHEN receiving secret values, THEN the service SHALL accept at most 32 KiB of UTF-8 value data in a JSON body of at most 256 KiB; names and scope fields SHALL have documented bounds.
- R4.AC4: WHEN responding, THEN the service SHALL use stable sanitized error codes, disable caching, and omit values, raw credentials, and internal filesystem/SQL details from errors and routine diagnostics.
- R4.AC5: WHEN a request or authorization check fails, THEN the service SHALL NOT report success or retry a mutation automatically.

### R5 — Consistent secret lifecycle

**User story:** As a client, I want writes and references to survive concurrency without overwriting newer credentials or reviving stale references.

- R5.AC1: WHEN creating, replacing, or deleting a secret, THEN the service SHALL require an expected revision and perform the change atomically; a stale revision SHALL return a conflict.
- R5.AC2: WHEN deleting or recreating a name, THEN the service SHALL retain an authenticated tombstone and monotonically advance its revision so an old reference never becomes current again.
- R5.AC3: WHEN resolving a versioned reference, THEN the service SHALL return only the current matching live revision within the authorized scope; when resolving by name it SHALL atomically select the current live record.
- R5.AC4: WHEN listing or inspecting metadata, THEN the service SHALL return no plaintext or ciphertext and SHALL bound/paginate the result.
- R5.AC5: WHEN a mutation returns success, THEN its data and required audit event SHALL have committed durably together. An interrupted response SHALL be treated as an unknown outcome and resolved by inspecting metadata.

### R6 — Auditable access that fails closed

**User story:** As an operator, I want evidence of secret access without creating another secret leak.

- R6.AC1: WHEN committing a mutation, THEN its audit event SHALL commit in the same SQLite transaction. WHEN returning plaintext, THEN a corresponding audit event SHALL commit before plaintext is released.
- R6.AC2: WHEN required audit persistence fails, THEN the operation SHALL fail without returning plaintext or committing a mutation.
- R6.AC3: WHEN recording events, THEN the system SHALL include sequence, previous MAC, time, operation, token ID, opaque record/scope identity, revision, and outcome, and SHALL exclude values, raw tokens, keys, and arbitrary request text.
- R6.AC4: WHEN verifying a vault, THEN the system SHALL verify its authenticated audit chain and emit a receipt containing vault ID, sequence, and head MAC that an operator can keep separately.
- R6.AC5: WHEN presenting audit guarantees, THEN documentation SHALL distinguish alteration detection from deletion, valid-history truncation, and full-vault rollback; only a separately trusted receipt can establish an earlier observed head.

### R7 — CLI without accidental secret disclosure

**User story:** As an operator, I want everyday CLI usage to avoid shell history, process-list, and terminal leaks.

- R7.AC1: WHEN writing a secret, THEN the CLI SHALL read its value from stdin without trimming or interpreting it and SHALL reject value-bearing command-line flags/arguments.
- R7.AC2: WHEN resolving a secret, THEN the CLI SHALL require explicit `--stdout` or a new private output file; list, inspect, and mutation responses SHALL never print values.
- R7.AC3: WHEN loading master/client credentials, THEN the CLI SHALL read protected files rather than raw command-line or environment values; shell examples SHALL use this contract.
- R7.AC4: WHEN using ordinary CLI commands, THEN all data operations SHALL use the authenticated API; only initialization and stopped-vault maintenance SHALL open SQLite directly.
- R7.AC5: WHEN a CLI operation fails, THEN it SHALL return a documented nonzero exit status without including secret material in output.

### R8 — Recoverable backup and key rotation

**User story:** As an operator, I want to recover or rotate a vault without risking the live source.

- R8.AC1: WHEN backing up a stopped vault, THEN the CLI SHALL acquire exclusive ownership, verify the source, and create an authenticated encrypted snapshot that excludes the master key and raw client credentials.
- R8.AC2: WHEN restoring, THEN the CLI SHALL authenticate the complete backup before opening the restored SQLite file, verify database/key/audit integrity, write only to a new private destination, revoke recovered tokens, and create fresh operator authority.
- R8.AC3: WHEN rekeying, THEN the CLI SHALL verify the source and create a separate destination with a fresh master key, freshly encrypted values and authenticated state, and fresh operator authority; all previous service tokens SHALL be revoked in the destination.
- R8.AC4: WHEN maintenance fails or is interrupted, THEN the original vault/key SHALL remain usable and incomplete destinations SHALL NOT be treated as valid vaults.
- R8.AC5: WHEN documenting recovery, THEN the system SHALL require separately protected key recovery material and explain that restoring an older snapshot restores older secret values/revisions that must be reconciled, while recovered tokens remain revoked.

### R9 — Optional OR3 provider with a real first consumer

**User story:** As an OR3 operator, I want persistent trusted-plugin secrets to use the vault without changing unrelated providers or weakening host authority.

- R9.AC1: WHEN installing the optional Nuxt module, THEN it SHALL register a distinct server-side secret provider using OR3's existing registry pattern; it SHALL NOT replace sync, auth, or connection-metadata providers.
- R9.AC2: WHEN configuring the provider, THEN OR3 SHALL read only socket path, token-file path, namespace, and expected vault ID from private runtime configuration; no raw token, key, or secret SHALL enter generated/public config or browser bundles.
- R9.AC3: WHEN a package-backed trusted-plugin secret request reaches OR3, THEN the host SHALL derive user/workspace/plugin scope from the authenticated session and live sealed activation, enforce current package/grant authority, and never accept owner or workspace IDs as authority from the browser.
- R9.AC4: WHEN using `host.secrets`, THEN `secrets.read`, `secrets.write`, and `secrets.use` SHALL retain their existing distinction; explicit session persistence SHALL stay in activation memory, while remembered secrets SHALL use the configured provider.
- R9.AC5: WHEN a request crosses an account/workspace/activation change, THEN the client SHALL discard stale results and SHALL NOT expose the previous scope's values to the new context. Already admitted server work may finish only in its original scope.
- R9.AC6: WHEN the configured provider is unavailable, invalid, or unsupported for that activation, THEN OR3 SHALL return an unavailable/error result without falling back to browser storage or an in-memory persistent store.
- R9.AC7: WHEN enabling the provider, THEN OR3 SHALL leave existing browser/server credentials untouched and document explicit re-entry for remembered secrets; no implicit upload, deletion, or other credential migration SHALL occur.
- R9.AC8: WHEN a trusted plugin is granted `secrets.read`, THEN documentation SHALL state that it can receive plaintext. This service SHALL NOT be advertised as preventing an authorized consumer from leaking it.

### R10 — Small, inspectable implementation

**User story:** As a maintainer, I want to understand the security boundary without operating another platform.

- R10.AC1: WHEN building the core, THEN it SHALL use Bun HTTP/SQLite and standard Node cryptography, avoid a web framework/ORM/custom cryptographic implementation, and add dependencies only for a demonstrated requirement.
- R10.AC2: WHEN building the SDK and Nuxt provider, THEN their dependency graph SHALL exclude Bun-only modules from the Node client and all server secrets from the browser graph.
- R10.AC3: WHEN selecting runtime versions, THEN the implementation SHALL qualify and pin an exact Bun version compatible with OR3's `bun@1.3.14` toolchain and test the client on Node 24; the currently installed Bun 1.3.6 SHALL NOT be assumed sufficient.
- R10.AC4: WHEN public API, CLI, configuration, or provider behavior changes, THEN the implementation SHALL update its README/security/operations documentation and OR3's public documentation via `docmap.json`.

### R11 — Security evidence before use

**User story:** As an owner, I want repeatable evidence for the important failure modes before trusting real credentials to the store.

- R11.AC1: BEFORE implementation of each security boundary, THEN the work SHALL enumerate credible failures and add failing, externally observable checks; use end-to-end tests primarily and independent cryptographic vectors where isolation is necessary.
- R11.AC2: WHEN qualifying the release, THEN tests SHALL cover cross-scope access, policy/ciphertext tampering, replay/stale revisions, token expiry/revocation, missing/wrong keys, unsafe files, audit/storage failure, process interruption, backup/rekey recovery, and provider isolation/unavailability.
- R11.AC3: WHEN tests run, THEN they SHALL use synthetic secrets and disposable storage and produce a repeatable redacted security receipt; the suite SHALL verify that deliberate negative controls are actually detected.
- R11.AC4: WHEN reporting readiness, THEN results SHALL identify tested runtime/platform versions, unresolved risks, and the absence of an independent security audit; planned tests SHALL never be described as passed tests.
