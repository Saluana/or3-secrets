# Tasks

Implementation has not started. These are dependency-ordered, reviewable work units, estimated at 1–4 focused hours each; estimates are not a delivery commitment. Write the relevant failing checks **before** production code. Use the design's fixed scope and remove speculative abstractions in every implementation pass.

Completed preparation: initialized this repository on `main`, inspected OR3's current stores/provider/activation boundaries, and reviewed the two upstream projects at pinned commits. No existing credentials, deployments, or OR3 files were changed.

## Implementation checklist

- [ ] **1. Record security failure cases and executable acceptance scenarios** — 2–3h. Depends on: planning review. Requirements: R1–R11.
  - Turn each acceptance criterion into a concrete scenario or explicit manual/release check; enumerate corruption, disclosure, concurrency, authority, filesystem, and recovery failures before writing implementation.
  - Define fixture identity/scope pairs, independent crypto vectors, process lifecycle controls, real disk-write failure environment, and receipt schema. Apply the repository's test-audit authoring gate; avoid tests duplicating implementation helpers.
  - **Done when:** every criterion maps to a scenario, the highest-risk scenarios have deliberate negative controls, and there is a documented command/environment for reproducing each class.

- [ ] **2. Qualify the runtime and create the minimal project/test harness** — 2–3h. Depends on: 1. Requirements: R4, R10, R11.
  - Qualify and pin Bun 1.3.14 if its required APIs pass; do not upgrade the operator's global runtime. Record the present local Bun 1.3.6 mismatch. Verify Unix serving, `node:http` socket access, SQLite exclusive transactions, Node crypto, and disabled automatic `.env` loading with tiny disposable probes.
  - Create the exact-version manifest/lockfile, TypeScript configuration, ignore rules, and process E2E harness. Ignore vaults, key/token files, `.env`, backups, and test artifacts by default; never rely on Git ignore as the custody boundary.
  - **Done when:** clean pinned-runtime installation and the harness work on macOS/Linux, the probes leave no listener/files behind, and initial init/API/CLI acceptance tests fail because the product is not implemented yet.

- [ ] **3. Implement the fixed cryptographic format** — 3–4h. Depends on: 2. Requirements: R2.
  - Before crypto code, add independent AES-GCM/HKDF vectors and external storage-tamper scenarios for both layers, every scope/AAD field, tombstones, and token policy.
  - Implement purpose-separated keys, canonical arrays, fresh per-write data keys/nonces, row/policy MACs, verification marker, and authenticated wrapping-count limit. Use full tag verification and bounded encodings.
  - **Done when:** known vectors match, each deliberate alteration fails without plaintext, the wrong key is rejected, and buffer cleanup does not claim guaranteed zeroization.

- [ ] **4. Implement safe files, exclusive ownership, and explicit init** — 3–4h. Depends on: 3. Requirements: R1, R7.
  - Add failing tests for existing outputs, symlinks/nonregular files, unsafe modes/ownership, key inside vault directory, partial init, second owner, and existing sockets.
  - Implement private creation, key/bootstrap-token generation, authenticated genesis/header initialization, and completion markers using the qualified crypto primitives. `serve` must never initialize. Inspect failure cleanup; preserve pre-existing files.
  - **Done when:** initialization succeeds only on safe new paths, every negative fixture preserves its source, and no key/token is printed or exposed through argv.

- [ ] **5. Implement SQLite revisions and required audit transactions** — 3–4h. Depends on: 4. Requirements: R5, R6.
  - First add API/store-boundary scenarios for CAS races, delete/recreate, pagination bounds, tampered rows, audit failure, and mutation/audit atomicity.
  - Implement strict prepared SQL, constraints, rollback journal/FULL synchronization, authenticated tombstones, audit chain, and full-chain verification. Keep transactions synchronous with no awaited work inside.
  - **Done when:** one concurrent CAS wins, stale refs stay invalid after recreation, reads release nothing before a successful audit commit, and a failed audit write cannot leave a committed mutation.

- [ ] **6. Implement scoped tokens and administrative separation** — 3–4h. Depends on: 5. Requirements: R3, R6.
  - First add a capability/scope matrix covering every field, expiry, revocation, guessed IDs, operator-vs-service boundaries, modified policy, and bad credential encoding.
  - Implement random tokens, digest lookup/constant-time comparison, authenticated policy, explicit expiry, and atomic token administration/audit. Keep operator authority out of secret operations.
  - **Done when:** all cross-scope and capability denials are externally observed, policy tampering cannot grant authority, and authorization after committed revocation fails without cached permissions.

- [ ] **7. Implement the bounded Unix HTTP API** — 3–4h. Depends on: 6. Requirements: R1, R4, R5, R6.
  - First add malformed/unknown-field/oversized/slow-body/Origin/media-type/concurrency tests, plus port and socket-mode checks.
  - Implement only the designed routes, sanitized errors, authenticated status, no-store responses, resource limits, and owned-socket shutdown. No TCP binding or permissive fallback configuration.
  - **Done when:** real API lifecycle works through the Unix socket; rejected requests stay bounded; failure startup exposes no listener; all externally visible errors are free of fixture canaries, SQL, and paths.

- [ ] **8. Implement the Node-compatible client** — 2–3h. Depends on: 7. Requirements: R4, R7, R9, R10.
  - First add Node 24 process tests against the real service for every operation, missing/replaced token file, wrong vault, abort/timeout, oversized response, and lost mutation response.
  - Implement `/client` with `node:http`, exact schemas, private credential-file reads, expected-vault validation, capped responses, and no automatic mutation retries or redirects.
  - **Done when:** Node 24 and pinned Bun run the same client contract, token replacement takes effect on the next request, and its import graph includes no `bun:*` or browser code.

- [ ] **9. Implement ordinary CLI commands with explicit disclosure** — 3–4h. Depends on: 8. Requirements: R3, R5, R7.
  - First write process-level tests for exact stdin bytes/newlines, default `get` refusal, explicit stdout/file output, existing/symlink output refusal, broken pipes, credential issuance, and nonzero errors.
  - Implement CLI commands over the client; token issuance writes only to an exclusive protected file. List/inspect/write/delete output metadata only.
  - **Done when:** a repeatable CLI lifecycle passes and canary scans find no secret values or raw credentials in incidental stdout/stderr/argv/artifacts.

- [ ] **10. Implement audit receipts and stopped-vault encrypted backup** — 3–4h. Depends on: 9. Requirements: R6, R8.
  - First add running-vault refusal, invalid-source, incomplete output, unauthorized path, truncated history, and separately held receipt scenarios.
  - Implement `audit verify` and the fixed streaming encrypted snapshot format, excluding key/token files. Authenticate the complete bounded header and payload; do not introduce archives or a second storage engine.
  - **Done when:** backup works only under exclusive ownership, outputs are private and contain no raw fixture values/metadata, altered chains fail, and documented unanchored rollback limitations match observations.

- [ ] **11. Implement restore to a fresh destination** — 3–4h. Depends on: 10. Requirements: R1, R8.
  - First add wrong key, altered header/tag, truncated file, existing destination, interruption, and receipt mismatch scenarios. Prove that unauthenticated payloads are not opened as SQLite.
  - Restore to private temporary storage; verify the complete AEAD tag, then database/schema/all records/audit. Revoke restored tokens and create fresh operator authority before marking complete.
  - **Done when:** the restored vault serves known synthetic values with newly issued authority, all old tokens fail, and every failed restore preserves the source and refuses incomplete destinations.

- [ ] **12. Implement offline rekey to a fresh destination** — 3–4h. Depends on: 11. Requirements: R2, R8.
  - First add source corruption, wrong key, interrupted rotation, old-token rejection, preserved ID/revision, and source-preservation scenarios.
  - Re-encrypt live data under fresh keys, re-authenticate records/header, rebuild and link audit receipts, reset wrapping count, and replace operator/service authority in the destination.
  - **Done when:** source and destination independently verify with their own keys, old tokens fail at the destination, new tokens resolve the original synthetic data, and interruption leaves the source usable.

- [ ] **13. Qualify service recovery and resource limits on Linux** — 2–4h. Depends on: 12. Requirements: R1, R4, R5, R6, R8, R11.
  - Run the previously authored crash and actual filesystem write-failure scenarios in disposable Linux storage; add no test-only failure flags to production code.
  - Verify owner/group socket deployment separately from database/key access. Record idle RSS, startup, and latency for the documented small workload; inspect growing audit/database behavior without adding caching.
  - **Done when:** durability/audit failure checks pass on Linux, no TCP port is opened, and the redacted receipt records actual resource measurements and recovery outcomes.

- [ ] **14. Add OR3's distinct secret-provider seam** — 2–3h. Depends on: 8, 13. Requirements: R9, R10.
  - Work only on relevant OR3 server config/registry files; preserve existing dirty files. Use the runtime-config registry helper and add private selection/config validation.
  - Before implementation, add integration checks for absent provider, selected missing provider, invalid runtime config, server-only imports, and no interference with selected sync/connection stores.
  - **Done when:** a fake registration can be resolved through the real registry for contract checking, configured invalid selection fails closed, and private paths/credentials are absent from public config. Production behavior must not depend on the fake.

- [ ] **15. Add the thin Nuxt module and real service provider** — 2–3h. Depends on: 14. Requirements: R9, R10.
  - First add a real-service provider roundtrip, wrong-vault/outage, static build, package export, and Node import checks.
  - Add `/nuxt` and Nitro registration using `/client`; configure file/socket paths and namespace only. Document explicit socket sharing without vault/key sharing.
  - **Done when:** OR3 resolves the installed provider and executes the contract through the real socket, outages produce unavailable errors, and the packaged module works without sibling source aliases.

- [ ] **16. Add authenticated trusted-plugin secret routes** — 3–4h. Depends on: 15. Requirements: R3, R9.
  - Before route code, add authenticated package-activation scenarios for scope substitution, missing grants, disabled/stale packages, changed grant review, revoked activation, and signed-out users.
  - Reuse OR3 session/internal user ID, package selection, live activation/grant checks, `can()` where required, intent/origin checks, and bounded bodies. Derive scope server-side; never treat `requirePluginAccess` alone as secret-grant approval.
  - **Done when:** an approved live trusted activation can use its own persisted secrets; cross-scope, stale, unsupported, and unapproved requests fail before service access. In-flight admission semantics are explicit.

- [ ] **17. Connect `host.secrets` with correct persistence/lifecycle semantics** — 3–4h. Depends on: 16. Requirements: R5, R9.
  - First add host E2E checks for async errors, account/workspace changes, activation teardown, session shadows, default/remember persistence, CAS conflicts, refs/status, and unavailable unlock.
  - Extend the internal store seam to awaited operations without changing the already-async SDK shape. Preserve grant separation, real revisions, one-attempt CAS writes, and explicit session memory.
  - **Done when:** remembered values roundtrip via the service without localStorage copies; session values vanish on teardown; stale responses never reach a new context; a selected failed provider never falls back to old storage.

- [ ] **18. Qualify OR3 integration and unchanged credential boundaries** — 2–4h. Depends on: 17. Requirements: R9, R10, R11.
  - Run the real package-backed activation scenarios against a disposable OR3 instance. Inspect generated server/public config and browser bundles for service credentials/Bun-only server imports.
  - Check that disabling selection retains existing deployment behavior and that enabling it does not upload/delete localStorage/Dexie keys or change connection, webhook, Connect, or background-job persistence.
  - **Done when:** the repeatable OR3 artifact demonstrates scope/grant/lifecycle checks, private runtime boundaries, fail-closed outages, and no implicit migration.

- [ ] **19. Write operational and public provider documentation** — 2–3h. Depends on: 12, 18. Requirements: R7, R8, R9, R10, R11.
  - Update README, threat model, supported platforms/runtime, API/CLI examples, socket ownership, token renewal, key backup, audit receipts, disk monitoring, crash-left sockets, restore/rekey, and limitations.
  - Update `or3-chat/public/_documentation/` through `docmap.json`, the trusted-plugin secrets documentation, cloud provider setup, and provider README. State that old remembered secrets require explicit re-entry and `secrets.read` can return plaintext to a trusted plugin.
  - **Done when:** a clean disposable operator walkthrough works using only docs, including token expiry/replacement and recovery; no example puts raw credentials in argv/env; readiness claims match evidence.

- [ ] **20. Perform final security review, simplification, and package qualification** — 3–4h. Depends on: 19. Requirements: R1–R11.
  - Inspect final diffs across both repositories and all package contents; remove needless options, indirection, test-only seams, unused APIs, and dependencies. Review each trusted boundary against the original failure catalog.
  - Run all relevant security E2E suites and typechecks once, build/package the CLI/client/module, and qualify the clean tarball with the fixed supported runtime. Re-run only checks affected by final corrections.
  - Record full commands, actual results, commit/version/platform, remaining issues, and the redacted receipt. Publication/deployment and real credential migration are separate work; do not consume an immutable version merely to run qualification.
  - **Done when:** every acceptance criterion is evidenced, deterministic failures are resolved, package contents contain no real secrets/developer state, and the limitations include no independent audit claim. Block real credential use if recovery/security checks fail.

## Traceability matrix

| Requirement | Acceptance criteria | Tasks | Primary evidence |
| --- | --- | --- | --- |
| R1 | AC1–AC5 | 1–2, 4, 7, 11, 13, 20 | Unsafe path/startup/ownership and recovery scenarios |
| R2 | AC1–AC5 | 1, 3, 12, 20 | Independent vectors, record/policy tampering, rekey |
| R3 | AC1–AC6 | 1, 6, 9, 16, 20 | Real API capability/scope/expiry/revocation matrix |
| R4 | AC1–AC5 | 1–2, 7–8, 13, 20 | Bounded malformed requests, socket-only and client failures |
| R5 | AC1–AC5 | 1, 5, 7, 9, 13, 17, 20 | Concurrent CAS, tombstones, reference and lost-response checks |
| R6 | AC1–AC5 | 1, 5–7, 10, 13, 20 | Real audit persistence failure, verification, external receipts |
| R7 | AC1–AC5 | 1, 4, 8–9, 19–20 | CLI process/output/argv/disclosure checks and operator walkthrough |
| R8 | AC1–AC5 | 1, 10–13, 19–20 | Tampered/interrupted backup, new-destination restore/rekey |
| R9 | AC1–AC8 | 1, 8, 14–19, 20 | Real OR3 activation/provider lifecycle and bundle inspection |
| R10 | AC1–AC4 | 1–2, 8, 14–15, 18–20 | Runtime/import/tarball qualification and public docs |
| R11 | AC1–AC4 | 1–2, 13, 18–20 | Failure catalog, negative controls, redacted security receipt |

## Definition of done

- All checklist items and R1–R11 acceptance criteria are satisfied with recorded evidence; planned checks are not presented as completed ones.
- The service/CLI/client run on the qualified exact Bun version; the provider/client run on Node 24. Linux production and macOS development results are distinguished.
- Core remains one service, one SQLite database, one fixed crypto format, and a Unix socket. No dashboard, remote API, cache, implicit fallback, or unrelated credential migration was added.
- Backup/restore/rekey and fail-closed audit behavior pass against real process/filesystem failures before any real credential use.
- OR3 scope/grant/lifecycle semantics and server/browser boundaries are verified; existing unrelated data/providers and user changes remain untouched.
- Public/provider/operator docs are current. Final diffs and clean package contents are inspected. No publication, production deployment, real secret transfer, or independent audit is implied by completing implementation.
