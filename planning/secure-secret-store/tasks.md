# Tasks

Code implementation is complete; internal qualification results and remaining external/deployment gates are recorded in [the implementation receipt](../../docs/implementation-receipt.md). These are dependency-ordered work units, not delivery-time commitments. Write the relevant failing checks **before** production code. Use the design's fixed scope and remove speculative abstractions in every implementation pass. The [production security profile](security-profile.md) records inherited controls and assurance gates; external review and deployment evidence are not implied by completing code.

Completed preparation: initialized this repository on `main`, inspected OR3's current stores/provider/activation boundaries, and reviewed the two upstream projects at pinned commits. No existing credentials or deployments were changed. The implementation extends the identified OR3 host boundaries; unrelated image changes are preserved.

## Implementation checklist

- [x] **1. Record the assurance target, failure cases, and acceptance scenarios.** Depends on: planning review. Requirements: R1–R12.
  - Record intended deployment/data scope, applicable standards/assessment targets, and whether FIPS-validated cryptography is required before fixing the runtime. Map product, inherited operational, and independent-review controls to owners and evidence in the security profile.
  - Turn each acceptance criterion into a concrete scenario or explicit manual/release check; enumerate corruption, disclosure, concurrency, authority, filesystem, audit collection, and recovery failures before writing implementation.
  - Define fixture identity/scope pairs, independent crypto vectors, process lifecycle controls, real disk-write failure environment, and receipt schema. Apply any applicable repository test-authoring instructions; avoid tests duplicating implementation helpers.
  - **Done when:** the target decision is recorded, every criterion maps to a scenario or named evidence owner, the highest-risk scenarios have deliberate negative controls, and reproduction environments are documented. Unperformed external/deployment checks remain pending.

- [x] **2. Qualify the runtime and create the minimal project/test harness.** Depends on: 1. Requirements: R4, R5, R10, R11, R12.
  - If validation is required, verify the exact cryptographic module/version, supported operating environment, and approved configuration before selecting the runtime. Do not infer validation from AES, OpenSSL, or Node-compatible API names. Otherwise qualify and pin the proposed Bun 1.3.14 or a justified exact replacement; do not upgrade the operator's global runtime or assume the previously observed Bun 1.3.6 is sufficient.
  - Probe Unix serving, Node 24 `node:http` socket access, standard crypto, disabled automatic `.env` loading, and file/directory synchronization. Explicitly set rollback-journal mode and `synchronous=EXTRA`; inspect effective SQLite journal/locking behavior, including any retained journal under exclusive ownership, on the target platform.
  - Create the exact-version manifest/lockfile, TypeScript configuration, ignore rules, and process E2E harness. Ignore vaults, key/token files, `.env`, backups, and test artifacts by default; never rely on Git ignore as the custody boundary.
  - **Done when:** the selected runtime matches the recorded assurance target, clean pinned installation and the harness work on supported macOS/Linux profiles, probes leave no listener/files behind, and initial init/API/CLI acceptance tests fail because the product is not implemented yet. Any validated profile has actual module/configuration evidence.

- [x] **3. Implement the fixed cryptographic format.** Depends on: 2. Requirements: R2, R8, R11.
  - Before crypto code, add independent AES-GCM/HKDF vectors and external storage-tamper scenarios for both layers, every scope/AAD field, tombstones, and token policy.
  - Implement purpose-separated keys, canonical arrays, fresh per-write data keys/nonces, row/policy MACs, verification marker, and authenticated wrapping-count limit. Count fresh-key destination work during restore/rekey; test limit boundaries without representing a restored/cloned local counter as a lifetime bound for reused keys. Use full tag verification and bounded encodings.
  - **Done when:** known vectors match, each deliberate alteration fails without plaintext, the wrong key is rejected, destination work consumes the correct wrapping budget, and buffer cleanup does not claim guaranteed zeroization or metadata encryption.

- [x] **4. Implement safe files, exclusive ownership, and explicit init.** Depends on: 3. Requirements: R1, R7, R8, R12.
  - Add failing tests for existing outputs, symlinks/nonregular files, unsafe modes/ownership, key inside vault directory, partial init, second owner, and existing sockets.
  - Implement private creation, key/bootstrap-token generation, authenticated audit genesis event and header initialization, and completion markers using the qualified crypto primitives. Synchronize new file contents and directory entries before success, including renamed outputs. `serve` must never initialize. Inspect failure cleanup; preserve pre-existing files.
  - **Done when:** initialization succeeds only on safe new paths, every negative fixture preserves its source, and no key/token is printed or exposed through argv. Production fixtures use distinct effective OR3/service identities and demonstrate that socket access does not provide database/key access.

- [x] **5. Implement SQLite revisions and required audit transactions.** Depends on: 4. Requirements: R1, R5, R6.
  - First add API/store-boundary scenarios for CAS races, delete/recreate, pagination bounds, tampered rows, unexpected/changed schema objects, audit failure, and mutation/audit atomicity. Include malicious trigger/view/virtual-table fixtures; `quick_check` and schema version alone must not admit them.
  - Implement the exact schema allowlist, strict prepared SQL/constraints, verified rollback journal/EXTRA synchronization, authenticated tombstones, audit chain, and full-chain verification. Disable unsupported extension mechanisms and keep transactions synchronous with no awaited work inside.
  - Add fixed-schema request and actor/activation correlation fields; label host actor claims as application-asserted and keep them outside authorization. Preserve the difference between acting identity and secret ownership.
  - **Done when:** one concurrent CAS wins, stale refs stay invalid after recreation, altered schema fails before secret operations, reads release nothing before a successful audit commit, and a failed audit write cannot leave a committed mutation.

- [x] **6. Implement scoped tokens and administrative separation.** Depends on: 5. Requirements: R3, R6, R12.
  - First add a capability/scope matrix covering every field, expiry, revocation, guessed IDs, operator/service/audit-reader boundaries, modified policy, and bad credential encoding. Prove audit-only credentials cannot read secrets or administer tokens and that secret-use credentials cannot export audit history.
  - Implement random tokens, digest lookup/constant-time comparison, authenticated policy, explicit expiry, and atomic token administration/audit. Keep operator authority out of direct secret operations, while documenting that token issuance still gives it full administrative authority.
  - **Done when:** all cross-scope and capability denials are externally observed, policy tampering cannot grant authority, authorization after committed revocation fails without cached permissions, and no bearer credential is represented as human MFA or individual attribution.

- [x] **7. Implement the bounded Unix HTTP API.** Depends on: 6. Requirements: R1, R4, R5, R6.
  - First add malformed/unknown-field/oversized/slow-body/Origin/media-type/concurrency tests, plus port and socket-mode checks. Use a valid socket/token pair for one vault with another expected vault ID and prove no requested operation is applied.
  - Implement only the designed routes, mandatory expected-vault checks before operations, sanitized errors, authenticated status, no-store responses, resource limits, and owned-socket shutdown. No TCP binding or permissive fallback configuration.
  - Implement bounded sanitized failed-access diagnostics, aggregation/drop counters, and fixed operational codes without attacker-controlled text. Document behavior when audit storage or the diagnostic collector is unavailable.
  - **Done when:** real API lifecycle works through the Unix socket; rejected requests and rejection evidence stay bounded; wrong-vault mutations leave state unchanged; failure startup exposes no listener; externally visible errors contain no fixture canaries, SQL, or paths.

- [x] **8. Implement the Node-compatible client.** Depends on: 7. Requirements: R4, R7, R9, R10.
  - First add Node 24 process tests against the real service for every operation, missing/replaced token file, wrong vault, abort/timeout, oversized response, and lost mutation response.
  - Implement `/client` with `node:http`, exact schemas, private credential-file reads, expected vault ID in every request plus response verification, bounded correlation fields, capped responses, and no automatic mutation retries or redirects.
  - **Done when:** Node 24 and the selected service runtime run the same client contract, token replacement takes effect on the next request, wrong-vault requests fail before mutation, and the client import graph includes no `bun:*` or browser code.

- [x] **9. Implement ordinary CLI commands with explicit disclosure.** Depends on: 8. Requirements: R3, R5, R7.
  - First write process-level tests for exact stdin bytes/newlines, interactive TTY refusal, default `get` refusal, explicit stdout/file output, existing/symlink output refusal, broken pipes, credential issuance, and nonzero errors.
  - Implement CLI commands over the client; token issuance writes only to an exclusive protected file. List/inspect/write/delete output metadata only. Document protected-file input preparation without secret literals in shell commands.
  - **Done when:** a repeatable CLI lifecycle passes, TTY input cannot echo an entered secret, and canary scans find no secret values or raw credentials in incidental stdout/stderr/argv/artifacts.

- [x] **10. Implement bounded audit export, receipts, and encrypted backup.** Depends on: 9. Requirements: R3, R4, R6, R8, R12.
  - First add live audit-reader authorization/expiry/revocation, bounded pagination, collector retry/progress, checkpoint, and polling-feedback scenarios. Cover the required genesis event, `limit` bounds, `after` beyond `through`, and empty-page cursor preservation. Separately test running-vault backup refusal, invalid source, incomplete output, unauthorized path, truncated history, and independently held receipts.
  - Implement one API/client/CLI audit export over a fixed captured head with sequence cursors and authenticated checkpoint data. Commit the required export-access event before releasing results; bound fresh polling so exporting audit-read events cannot create an uncontrolled feedback loop. Use the existing audit table and an external collector, not a new queue or monitoring platform.
  - Implement stopped-vault `audit verify` and the fixed streaming encrypted snapshot format, excluding key/token files. Enforce the provisional 1 GiB snapshot limit and bounded envelope/header; authenticate the complete payload, synchronize file/directory state, and avoid archives or another storage engine.
  - **Done when:** live export remains bounded and read-only, collector retries preserve independently recorded progress, backup succeeds only under exclusive ownership and size limits, private backup outputs contain no raw secret values or record metadata, and observed rollback limits match documentation.

- [x] **11. Implement authenticated restore and one shared fresh-key copy routine.** Depends on: 10. Requirements: R1, R2, R6, R8.
  - First add wrong key, altered header/tag, truncated/oversized file, dishonest size header, existing destination, interruption, and receipt mismatch scenarios. Enforce both actual encrypted-envelope and decrypted-snapshot byte limits; prove unauthenticated payloads are never opened as SQLite.
  - Decrypt into private temporary storage, verify the complete AEAD tag and exact EOF, then exact schema, database, all records, and audit history. Introduce one verified fresh-key destination-copy routine in maintenance and use it before any restored vault becomes writable; preserve vault/record IDs and revisions, re-encrypt values, rebuild authenticated history, and count all new wraps. The maintenance event contains the prior receipt; derive the new receipt only after its event commits.
  - Revoke recovered credentials and create fresh operator authority. Mark the destination complete only after verification and durable file/directory synchronization; retain separately protected old recovery material for old snapshots.
  - **Done when:** the restored vault serves known synthetic values under a fresh key and newly issued authority, old tokens fail, over-limit input never produces a valid destination, wrap accounting includes restoration work, and failed restores preserve the source and refuse incomplete destinations.

- [x] **12. Implement offline rekey through the shared destination-copy routine.** Depends on: 11. Requirements: R2, R6, R8.
  - First add source corruption, wrong key, interrupted rotation, old-token rejection, preserved ID/revision, wrapping-limit, and source-preservation scenarios.
  - Reuse task 11's verified fresh-key copy for a stopped source vault, without a second encryption/copy implementation. Re-authenticate records/header/history, link receipts, count actual destination wraps, and replace operator/service/audit authority. Do not reset a populated destination's wrapping count to zero.
  - **Done when:** source and destination independently verify with their own keys, old tokens fail at the destination, new tokens resolve the original synthetic data, interrupted output never replaces the source, and documentation distinguishes custody rekey from issuer-side credential revocation.

- [ ] **13. Qualify core recovery, audit growth, and resource limits on Linux.** Depends on: 12. Requirements: R1, R2, R4, R5, R6, R8, R11, R12.
  - Run the previously authored crash and actual filesystem write-failure scenarios in disposable Linux storage; add no test-only failure flags to production code. Record effective journal/locking/EXTRA modes and file/directory sync behavior. Distinguish process-crash evidence from any separately performed power-loss durability check.
  - Verify separate effective OR3/service identities and socket permissions without database/key access. Exercise bounded failed-access evidence, collector interruption/recovery and lag/drop alerts, time assumptions, and disk thresholds using existing operational tooling.
  - Record numeric resource and recovery budgets before qualification. Measure idle RSS, startup, and latency for the small workload, then verification/startup/backup/restore/rekey costs and disk growth for aged audit fixtures through the supported maximum snapshot size. Include maintenance headroom and oversize refusal; qualify the supported operating volume against those budgets and revise the declared envelope if measurements fail, without adding caching or automatic pruning.
  - **Done when:** the core qualification evidence records actual Linux security/recovery outcomes, no TCP listener, deployment isolation, resource/maintenance bounds, and monitoring responsibilities. Unsupported or untested profiles are identified rather than called qualified.

- [x] **14. Add OR3's distinct secret-provider seam.** Depends on: 8, 13. Requirements: R9, R10.
  - Work only on relevant OR3 server config/registry files; preserve existing dirty files. Use the runtime-config registry helper and add private selection/config validation.
  - Before implementation, add integration checks for absent provider, selected missing provider, invalid runtime config, server-only imports, and no interference with selected sync/connection stores.
  - **Done when:** a fake registration can be resolved through the real registry for contract checking, configured invalid selection fails closed, and private paths/credentials are absent from public config. Production behavior must not depend on the fake.

- [x] **15. Add the thin Nuxt module and real service provider.** Depends on: 14. Requirements: R9, R10.
  - First add a real-service provider roundtrip, wrong-vault/outage, static build, package export, and Node import checks.
  - Add `/nuxt` and Nitro registration using `/client`; configure file/socket paths, namespace, and expected vault ID only. Document explicit socket sharing across distinct production identities without vault/key sharing.
  - **Done when:** OR3 resolves the installed provider and executes the contract through the real socket, outages produce unavailable errors, and the packaged module works without sibling source aliases.

- [x] **16. Add authenticated trusted-plugin secret routes.** Depends on: 15. Requirements: R3, R6, R9, R12.
  - Before route code, add authenticated package-activation scenarios for scope substitution, missing grants, disabled/stale packages, changed grant review, revoked activation, and signed-out users.
  - Reuse OR3 session/internal user ID, package selection, live activation/grant checks, `can()` where required, intent/origin checks, and bounded bodies. Derive scope and actor/activation audit fields server-side, share a bounded request ID with host authorization logs, and never treat `requirePluginAccess` or claimed actor fields as secret-grant approval.
  - **Done when:** an approved live trusted activation can use its own persisted secrets; cross-scope, stale, unsupported, and unapproved requests fail before service access; host/vault evidence correlates the acting identity without substituting secret ownership. In-flight admission semantics are explicit.

- [x] **17. Connect `host.secrets` with correct persistence/lifecycle semantics.** Depends on: 16. Requirements: R5, R9.
  - First add host E2E checks for async errors, account/workspace changes, activation teardown, session shadows, default/remember persistence, CAS conflicts, refs/status, and unavailable unlock.
  - Extend the internal store seam to awaited operations without changing the already-async SDK shape. Preserve grant separation, real revisions, one-attempt CAS writes, and explicit session memory.
  - **Done when:** remembered values roundtrip via the service without localStorage copies; session values vanish on teardown; stale responses never reach a new context; a selected failed provider never falls back to old storage.

- [ ] **18. Qualify OR3 integration and unchanged credential boundaries.** Depends on: 17. Requirements: R6, R9, R10, R11, R12.
  - Run the real package-backed activation scenarios against a disposable OR3 instance. Inspect generated server/public config and browser bundles for service credentials/Bun-only server imports.
  - Check that disabling selection retains existing deployment behavior and that enabling it does not upload/delete localStorage/Dexie keys or change connection, webhook, Connect, or background-job persistence.
  - **Done when:** the repeatable OR3 artifact demonstrates scope/grant/lifecycle checks, host-to-vault actor/request correlation, private runtime boundaries, wrong-vault protection, fail-closed outages, and no implicit migration. Its claim is remembered trusted-plugin secrets, not all OR3 credential storage.

- [ ] **19. Write and exercise the production profile and operator documentation.** Depends on: 12, 18. Requirements: R6, R7, R8, R9, R10, R11, R12.
  - Update README, threat model, supported platforms/runtime/assurance target, API/CLI examples, separate identities and socket ownership, crash-left sockets, and the production security profile. Explain that the operator credential can mint secret-use authority and that a local key file or encrypted values do not make metadata or whole-host snapshots confidential.
  - Document named administrators, inherited MFA and alternate/break-glass paths, actor correlation, token renewal, separately controlled key backups, online audit export/checkpoints, collector lag/drop/time/disk alerts, retention/deletion, and measured maintenance/recovery objectives. Keep monitoring and human identity controls in existing deployment tooling.
  - Separate service-token rotation, master-key rekey, and upstream credential revocation/rotation. Walk through fresh-key restore, old-value reconciliation, retained backup keys, and recovery after interrupted maintenance without exposing real credentials.
  - Update `or3-chat/public/_documentation/` through `docmap.json`, the trusted-plugin secrets documentation, cloud provider setup, and provider README. State that old remembered secrets require explicit re-entry and `secrets.read` can return plaintext to a trusted plugin.
  - **Done when:** a clean disposable operator walkthrough works using only docs, including expiry/replacement, audit export, and recovery; no example puts raw credentials in argv/env/echoing TTY input; deployment control owners and evidence gaps are explicit; readiness claims match evidence.

- [ ] **20. Perform final security review, simplification, and release qualification.** Depends on: 19. Requirements: R1–R12.
  - Inspect final diffs across both repositories and all package contents; remove needless options, indirection, test-only seams, unused APIs, and dependencies. Review each trusted boundary against the original failure catalog.
  - Run relevant security E2E suites and typechecks once, build/package the CLI/client/module, and qualify the clean tarball with the selected exact runtime. Re-run only checks affected by corrections. Record the SBOM, pinned build/dependency inputs, secret/dependency scans, assessed findings, package contents, and artifact checksums/provenance; review workflow permissions and signing/verification steps.
  - Before high-value or regulated use, obtain independent application-security and cryptographic design/implementation review of the qualified release and deployment/recovery boundary; resolve and recheck required findings. Record scope, reviewer, version, and residual decisions. Internal review, tests, and upstream audits do not satisfy this gate.
  - Record full commands, actual results, commit/version/platform, remaining issues, control evidence, and the redacted receipt. Publication/deployment and real credential migration are separate work; do not consume an immutable version merely to run qualification.
  - **Done when:** applicable release criteria have evidence, deterministic failures are resolved, artifacts contain no real secrets/developer state, and pending external/deployment gates remain explicitly blocked. Block any real credential use if recovery/security checks fail, and block high-value/regulated use until the independent-review and required deployment gates pass.

## Qualification status after implementation

Tasks 1–12 and 14–17 have product implementations and executable evidence in the receipt. The remaining unchecked tasks contain broader gates, not missing API/CLI/provider code:

- **13:** Linux security, ENOSPC, distinct identities and exact 1 GiB audit-history recovery pass. Target-host numeric budgets, mixed-secret aged workload and storage/power-loss acceptance remain unperformed.
- **18:** Actual packaged Nuxt/Nitro provider, private bundle scan, Node/service outage, and 129 tests across ten affected OR3 suites pass. The repeatable full-app browser/package/session walkthrough now passes through real upload/review/canary/promotion and Chat activation, including persistence, session cleanup, workspace/grant fencing and live vault restart. See `scripts/qualify-host.ts` and ignored `test-results/host-browser.json`; production deployment acceptance remains separate.
- **19:** Operator/provider/public docs are written and CLI/recovery commands exercised with disposable fixtures. Production human administration/MFA, external collector/alerts, retention and separately controlled recovery custody are not evidenced.
- **20:** Internal review/simplification, builds/typechecks, clean tarball, SBOM/advisory/material scans and local artifact provenance pass. Independent security/crypto review, release signing and target deployment acceptance remain external gates. No publication is authorized by these checkmarks.

## Traceability matrix

| Requirement | Acceptance criteria | Tasks | Primary evidence |
| --- | --- | --- | --- |
| R1 | AC1–AC5 | 1–2, 4–5, 7, 11, 13, 20 | Unsafe paths, exact schema, ownership, synchronized output and recovery |
| R2 | AC1–AC5 | 1–3, 11–13, 20 | Independent vectors, record/policy tampering, fresh-key copies and wrap accounting |
| R3 | AC1–AC6 | 1, 6–10, 16, 20 | Secret/operator/audit-reader capability, scope, expiry and revocation matrix |
| R4 | AC1–AC5 | 1–2, 7–8, 10, 13, 20 | Bounded local requests/exports, wrong-vault rejection before operations |
| R5 | AC1–AC5 | 1–2, 5, 7, 9, 13, 17, 20 | Concurrent CAS, references, effective journal/EXTRA durability, lost responses |
| R6 | AC1–AC6 | 1, 5–7, 10–13, 16, 18–20 | Audit failure, bounded export, independent checkpoints, failed-access and actor correlation |
| R7 | AC1–AC5 | 1, 4, 8–9, 19–20 | CLI process/output/argv/disclosure checks and operator walkthrough |
| R8 | AC1–AC5 | 1, 3–4, 10–13, 19–20 | Size-bounded backup, synchronized fresh-key restore/rekey, separate rotation lifecycles |
| R9 | AC1–AC8 | 1, 8, 14–19, 20 | Real OR3 activation/provider lifecycle and bundle inspection |
| R10 | AC1–AC4 | 1–2, 8, 14–15, 18–20 | Recorded crypto/runtime target, import/tarball qualification and public docs |
| R11 | AC1–AC5 | 1–3, 13, 18–20 | Negative controls, aged maximum-size fixtures, security receipt, supply-chain evidence |
| R12 | AC1–AC5 | 1–2, 4, 6, 10, 13, 16, 18–20 | Control ownership, inherited MFA/identity, separate custody, operating evidence, independent review |

## Definition of done

- All checklist items and applicable R1–R12 acceptance criteria have recorded evidence; planned tests and unperformed deployment/external reviews are not presented as completed. Conditional release gates remain explicit until their conditions are satisfied.
- The assurance target is recorded before implementation. The selected exact runtime/cryptographic configuration is qualified against that target, with actual validated-module evidence if required; the provider/client run on Node 24. Linux production and macOS development results are distinguished.
- Core remains one service, one SQLite database, one fixed crypto format, and a Unix socket. No dashboard, remote API, cache, implicit fallback, or unrelated credential migration was added.
- Backup/restore/rekey, synchronized file/directory output, effective rollback-journal/EXTRA behavior, and fail-closed audit behavior pass the relevant real process/filesystem failure checks before any real credential use. Process-crash evidence is not mislabeled as power-loss testing.
- The 1 GiB snapshot/envelope bounds, fresh-key restored admission, correct wrapping counts, aged audit growth, startup/recovery duration, and operating headroom are qualified. Maintenance, retention, and monitoring obligations have named owners.
- OR3 scope/grant/lifecycle semantics, expected-vault checks, actor/request audit correlation, and server/browser boundaries are verified; existing unrelated data/providers and user changes remain untouched. Production uses distinct effective identities and key custody.
- Online audit export is bounded, requires audit-only authority, and supports independently retained collector progress/checkpoints without uncontrolled polling feedback. Human MFA and individual administrator attribution are demonstrated through the inherited management boundary, not inferred from a token file.
- Public/provider/operator docs and the security profile are current. Release evidence includes inspected package contents, SBOM, assessed scans, reviewed build inputs/permissions, and artifact provenance/signing verification. Independent application-security/crypto review and required deployment controls block high-value or regulated use until evidenced.
- Completing implementation does not itself publish a package, deploy the service, transfer real secrets, certify compliance, or imply an independent audit has occurred.
