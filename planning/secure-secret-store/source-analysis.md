# Source analysis

Reviewed 2026-10-17 from shallow public source checkouts. Revisions are pinned below so later upstream changes do not alter this assessment. This is a targeted architecture/security review, not an independent security audit, penetration test, or certification. Neither project was built or executed, and dependency vulnerability scanning was not performed.

## secretctl

Source revision: [`2de7b68d61dae81988ca96161e2a65b11badc618`](https://github.com/forest6511/secretctl/tree/2de7b68d61dae81988ca96161e2a65b11badc618). Go CLI, SQLite vault, password-derived wrapping key, audit/backup facilities, plus MCP/command execution and desktop functionality beyond our needs.

| Observed implementation | Useful idea / decision for OR3 |
| --- | --- |
| [Crypto](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/pkg/crypto/crypto.go) uses Argon2id for a human password and AES-GCM with random nonces. The reviewed `Seal`/`Open` calls pass `nil` AAD (lines 123/168). | Keep standard authenticated encryption. Our random master key needs no password KDF. Bind our ciphertext to the complete record scope/revision; do not port this primitive unchanged. This observation alone is not a demonstrated exploit of secretctl. |
| [Vault operations](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/pkg/vault/vault.go) separate key wrapping from data encryption. Several `LogSuccess` results are explicitly discarded, including set/get (lines 1263/1390). | Keep separation of custody; require audit persistence before releasing plaintext and atomically with mutations. Do not inherit ignored audit failures. |
| [Audit verifier](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/pkg/audit/audit.go#L478) checks sequence, previous hash, and HMAC through the available JSONL files. | Use authenticated sequence chaining, with honest limits: removing a complete valid suffix or restoring an older valid snapshot needs an externally retained observation to detect. Put our audit in the data transaction rather than a second file stream. |
| [CLI](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/cmd/secretctl/root.go) separates get/list and provides interactive value handling; it also includes value-bearing field options. [Backup CLI](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/cmd/secretctl/backup.go) requires an explicit output choice. | Make disclosure deliberate. Our contract is stricter: exact stdin writes, no value-bearing argv, and explicit stdout or exclusive private output files for reads. Do not imply all upstream CLI defaults have these properties. |
| [MCP security documentation](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/website/docs/guides/mcp/security-model.md#L150) describes exact-string output sanitization and explicitly lists transformed/partial values it misses. | Do not treat output scrubbing as containment. A command with a secret can encode it or send it elsewhere. Exclude MCP, shell execution, and “AI cannot leak secrets” claims. |
| [Backup cryptography](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/pkg/backup/crypto.go) separates cryptographic purposes in backup protection. | Use domain-separated backup keys and authenticated recovery, but keep one streaming format instead of copying the broader feature set. |

Its password/unlock lifecycle, desktop UI, templates/folders, import/export, and command mediation would add complexity without serving the initial OR3 use case. Go's buffer wiping patterns do not establish an equivalent guarantee for Bun's managed strings.

## Dopbase

Source revision: [`df4c02def17d5186088b245cc98d7e229992bebb`](https://github.com/dopbase/dopbase/tree/df4c02def17d5186088b245cc98d7e229992bebb). Rust service/CLI with SQLite, admin identity, projects/environments, browser UI, runner tokens, and optional offline execution cache.

| Observed implementation | Useful idea / decision for OR3 |
| --- | --- |
| [Crypto service](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/app/src/services/crypto.rs) uses fresh per-value data keys, XChaCha20-Poly1305, separate master-key custody, and startup key verification. `aad()` binds environment/key/version; the source also has a rewrapping helper. | This is the strongest architectural match. Adopt envelope encryption, explicit context binding, and verification before listening. Use Node's AES-GCM implementation rather than porting XChaCha. Use unambiguous fixed-array AAD rather than delimiter concatenation. |
| The same [crypto file](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/app/src/services/crypto.rs#L334) writes a key via a predictable temporary path with create/truncate and rename. | Do not copy filesystem code mechanically: our new-output contract needs exclusive creation, no-follow/type/owner checks, and private validated directories. This is a narrower operational requirement, not a claim of an exploitable upstream flaw. |
| [Token primitive](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/app/src/services/token.rs) generates 32 random bytes and stores SHA-256 digests. [Token issuance](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/app/src/modules/tokens/service.rs) scopes runners to an environment and defaults an omitted expiry to `never`. | Adopt high-entropy machine tokens, digest-only persistence, and narrow scope. Require expiry for our service tokens and authenticate the stored policy so a database edit cannot broaden it. No human password hashing is needed for these random credentials. |
| [Secret mutations](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/app/src/modules/secrets/service.rs) put writes/deletes and audit records in transactions. Its single-write path increments the stored version; other flows have additional concurrency checks. | Adopt transaction-local audit. Require explicit CAS on our writes/deletes and tombstones to invalidate stale references. Do not characterize all upstream flows as lacking concurrency control. |
| [Security documentation](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/docs/reference/security.md) distinguishes metadata access, explicit plaintext disclosure, and offline-cache availability/revocation tradeoffs. | Preserve the honest exposure model and protect metadata access. Exclude offline caches and editor/export workflows so revocation does not silently defer to a local copy. |
| [September 2026 review](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/docs/security/audits/2026-09.md) describes an internal review; its security documentation says public source is not the same as an independent audit. | Treat upstream designs as evidence to study, not security certification inherited by our implementation. We also must describe our own testing/review accurately. |

Do not adopt Dopbase's UI, login/session system, projects/roles, editor integration, or offline cache. OR3 already owns user/workspace/plugin authority; the new store should authenticate applications and enforce their storage scope, not become a second identity system.

## OR3 integration findings

Inspected `or3-chat` at `1d6318235e289b041dcdda5e92faed12b60493bc`, plus current uncommitted state. Three existing modified image files were left untouched. File paths below are relative to that repository.

| Area | Current behavior | Initial-release decision |
| --- | --- | --- |
| `app/composables/plugins/trusted-production-stores.ts` and `trusted-mediation.ts` | Synchronous store seam backed by raw localStorage by default; public mediation methods are async and check separate secret grants. | First real consumer. Add an awaited provider adapter for remembered values; retain explicit session memory and real grant checks. |
| `packages/plugin-sdk/src/capabilities.ts` | Public async `get/set/delete/ref/status/unlock`; trusted `get` can return plaintext. | Preserve the shape and honest trusted-plugin exposure; return actual revision/availability/error behavior. |
| `server/utils/plugins/isolation/activation-authorization.ts` | Re-derives user/workspace/plugin/package/current grants from a sealed activation and live host state. | Reuse it for the new authenticated host routes. Browser input is not authority. |
| `server/utils/plugins/connections/` | Already encrypted server credentials, owner/workspace/plugin scope, revisions and CAS. Persistence registry follows sync provider. | Leave this storage intact. A new secret registry is separate; migrating credentials later needs schema and cross-store consistency work. |
| `app/core/auth/useUserApiKey.ts` and `shared/sync/local-only-kv.ts` | OpenRouter key in device-local Dexie KV, intentionally excluded from sync. | Leave unchanged; server custody would change browser request and identity behavior. |
| `server/connect/crypto.ts`, webhook/background-job crypto | Existing independent encryption and lifetime requirements; Connect already demonstrates context binding. | Reuse architectural lessons, not a blanket migration. Background execution/recovery needs its own design. |
| `server/utils/registry/create-runtime-config-registry.ts`, `server/plugins/99.validate-providers.ts`, sibling provider modules | Established registration, private runtime config, and selected-provider validation patterns. | Extend those patterns with one optional secret-provider kind and thin Nuxt module. |

The project manifests use Bun 1.3.14 while the inspected shell has Bun 1.3.6; the runtime must be explicitly qualified. OR3's server client cannot assume it runs under Bun, so the SDK uses standard Node socket HTTP.

## What we will build

| Take | Adapt | Leave out |
| --- | --- | --- |
| Explicit disclosure and authenticated backups | Stricter stdin/private-file CLI contract | Shell execution, MCP, plaintext export |
| Envelope encryption and separate key custody | Standard Node AES-GCM, full OR3 scope/revision AAD | Custom cryptography or password/unlock product |
| Scoped random tokens with digest-only storage | Expiry required; authenticated policy; separate operator authority | Second user/SSO/RBAC platform |
| Transactional audit and versioned writes | Fail-closed reads, CAS, tombstones, external receipts | “Immutable” audit or automatic rollback-detection claims |
| Small service plus CLI | Local Unix socket and optional Node-safe Nuxt provider | TCP/TLS/HA/UI/cache and automatic migrations |

Both repositories use Apache-2.0 licenses: [secretctl license](https://github.com/forest6511/secretctl/blob/2de7b68d61dae81988ca96161e2a65b11badc618/LICENSE), [Dopbase license](https://github.com/dopbase/dopbase/blob/df4c02def17d5186088b245cc98d7e229992bebb/LICENSE). No implementation code was copied. If later work copies or adapts source rather than independently applying ideas, preserve the applicable license/notice obligations and review the specific files first. Select this new project's license explicitly before publication.

The security benefit is a smaller custody boundary with testable access rules. It does not follow merely from being new, small, written in Bun, or inspired by these projects.

## 2026-10-17 plan review supplement

The pinned implementation observations above remain historical findings. This supplement clarifies proposed OR3 decisions, not upstream behavior or completed validation. The [planned production security profile](security-profile.md) defines required isolation, administrative access, audit collection, capacity/recovery qualification, and control ownership. All implementation, independent review, and compliance evidence remain pending.

- **Runtime assurance.** Earlier references to “Node AES-GCM” identify the `node:crypto` API, not an assurance that Bun uses Node's cryptographic implementation. The [current Bun compatibility guide](https://bun.com/docs/runtime/nodejs-compat#node-crypto) identifies a BoringSSL backend and describes `setFips()` as a no-op. Recheck the exact pinned build; this guide is not qualification evidence for Bun 1.3.14. Decide any validated-module requirement before runtime lock-in. [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) distinguishes algorithm validation from module validation.
- **SQLite durability.** The proposed rollback-journal deployment needs `synchronous=EXTRA`, verified with `journal_mode=DELETE`, plus tested filesystem/storage sync behavior. [SQLite's primary documentation](https://www.sqlite.org/pragma.html#pragma_synchronous) explains the additional directory sync and why `FULL` alone may lose the last acknowledged transaction after power loss in rollback mode; `FULL` and `EXTRA` are equivalent in WAL mode. This updates the proposed durability choice, not the reviewed upstream facts.
- **Backup bounds.** [NIST SP 800-38D section 5.2.1.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) bounds plaintext per GCM invocation to `2^39 - 256` bits, or `2^36 - 32` bytes. The proposed 1 GiB snapshot ceiling is deliberately smaller and still requires workload qualification. Bound the envelope, require complete authentication and exact end of input, and reserve staging/destination disk space; streaming alone does not establish those properties.
- **Deployment evidence.** Use the profile's primary PCI SSC, AICPA, NIST, EUR-Lex, and HHS/eCFR references for control applicability. The upstream inspiration is not evidence of compliance. Inherited human MFA, independently protected audit custody, recovery drills, and independent review remain explicit deployment/release gates rather than new platform features in the core.
