# Implementation receipt

This is the original implementation qualification record. The subsequent [task 13 Linux x86_64 qualification](linux-qualification.md) records preset numeric budgets and the current mixed-inventory capacity profile. See the subsequent [security review](security-review.md) for findings, repairs, changed development-vault compatibility and current verification; the earlier counts and capacity measurements below remain historical.

Implemented from the updated plan on 2026-10-18. Source base: `or3-secrets` `57035eef0b8205d0c49c00eba66e077e37693e50`, OR3 host `1d6318235e289b041dcdda5e92faed12b60493bc`. Changes remain in the working trees; no release commit/tag, registry publication, deployment or real credential migration occurred. The user's three pre-existing modified OR3 images were preserved.

## Delivered

One Bun Unix service/CLI and SQLite format; envelope encryption and authenticated state; full startup schema/chain/cipher verification; scoped expiring service/audit credentials; explicit disclosure and CAS/tombstones; bounded transactional audit/export; whole-snapshot encrypted backup; one fresh-key restore/rekey copy path; a Node client and optional Nuxt provider; an OR3 registry, live session/activation/grant route and asynchronous remembered `host.secrets` integration. Session-only values have activation-owned cleanup. Configured outages fail closed; existing unrelated credential stores are unchanged.

The default assurance decision is nonvalidated Bun 1.3.14, not regulated/FIPS use. The operator's global Bun 1.3.6 was not upgraded. Node client qualification uses actual Node 24.13.0, distinct from Bun's emulated `process.versions.node`.

## Executed evidence

| Check | Actual result |
| --- | --- |
| Bun 1.3.14 `test --timeout 30000 tests` | 14 passed, 207 assertions, macOS arm64 and non-root Linux arm64 |
| Independent primitives | NIST AES-256-GCM and RFC 5869 vectors; wrong key/AAD/tag negative controls |
| Encryption/state | Scope/capability matrix; expiry/revocation; concurrent CAS and stale refs; hostile schema/policy/header/history; independently reauthenticated row substitutions reach both GCM layers and every record context field |
| API/CLI | Exact stdin/output, no implicit disclosure, protected outputs before reads/issuance, wrong vault, input bounds, 16-in-flight saturation and five-second slow-body deadline, actual Node cancellation |
| Recovery | SIGKILL/restart, exclusive owner, encrypted backup and fresh-key restore/rekey, old credential refusal, bad/trailing envelope/source preservation, last committed wrapping-budget boundary |
| Real Linux ENOSPC | 8 MiB tmpfs, UID 1000: required-audit read failure released no plaintext; failed write left no partial record; both recovered after freeing space |
| Distinct effective identities | Service UID 1000, client UID 1001, socket GID 2000: real Node roundtrip; database/master/operator reads denied; foreign-owned ancestry refused |
| OR3 targeted suite | 113 tests passed across 10 files, including host secret route/mediation, existing activation mint/revoke/capability contracts, trusted lifecycle/files, provider validation and session bootstrap |
| OR3 typecheck | Supported `bun run type-check` wrapper passed; existing duplicate-auto-import warnings remain |
| OR3 public docs | `bun run check:docs` passed (115 files, 103 routes, 20 existing typechecked examples) |
| Package type/build | Strict TypeScript, unused-symbol check, CLI/client/module build, clean tarball imports and Node launcher/service/client roundtrip passed |
| Actual Nuxt provider | Built isolated Nuxt app from tarball with OR3's installed toolchain; Node Nitro socket write/read, selected outage and public-bundle private-input scan passed |
| Dependency/material scan | Pinned Bun `audit --json` returned `{}` / exit 0; 43 build dependency entries in CycloneDX inventory; package credential/private-file patterns and contents checked |

OR3's test configuration loads developer `.env` by default. An existing capability test expecting no model credential initially failed because that environment supplies one. Re-running with `OPENROUTER_API_KEY=''` and Bun `--no-env-file` passed all 113 tests. No credential values were printed and no `.env` was changed. The first Linux recovery run with a 64 MiB tmpfs correctly refused the required 64 MiB-plus headroom; the successful full-suite profile uses 256 MiB. Intentional red tests also exposed/fixed output reservation order, startup cipher verification, foreign ancestor ownership, and conflict/cancellation semantics. Required Nitro registration stays an unbundled entry to avoid virtual-import transformation collisions.

Commands/fixtures are in `docs/qualification.md`, `scripts/qualify*.ts`, `scripts/qualify-isolation.sh`, `scripts/Qualification.Dockerfile`, and the test suite. Machine receipts, package SHA-256/integrity, contents, lockfile hash, SBOM, advisory output and disposable tarball live under ignored `test-results/`. The package receipt identifies the uncommitted source base and is local provenance, not a signed release. No automated deployment/signing workflow was added.

## Exact 1 GiB aged history

Both profiles used **1,568,868** authenticated aged events, a **1,073,741,824-byte** database and a **1,073,741,936-byte** backup (exact 112-byte overhead). The Linux container ran with a 1 GiB memory limit. These are measurements on this machine/VM, not production SLOs.

| Operation | macOS arm64 | Linux arm64 |
| --- | ---: | ---: |
| Generate aged fixture | 6.17 s | 13.53 s |
| Open + full verify (includes repeated verification) | 15.52 s | 16.56 s |
| Backup | 16.13 s | 20.89 s |
| Fresh-key restore | 34.29 s | 56.52 s |
| Fresh-key rekey | 37.49 s | 58.10 s |

Runtime-reported maximum RSS is retained raw because Bun's platform units differ; Linux reported 139,516 KiB, macOS reported 257,294,336 bytes. RSS at completion was about 115 MiB/80 MiB respectively. Do not treat this single aged audit workload as a mixed-secret workload benchmark or a production memory guarantee. Recovery adds audit evidence and can grow a destination by pages; operate with capacity margin below the hard **backup input** bound. A live/recovered file above that bound is deliberately refused by backup. The capacity script now additionally records destination sizes on subsequent runs.

## Remaining gates

Code implementation is complete; the broader plan's qualification/release gates are deliberately not all checked off. The subsequent full browser/package/session qualification passed through the actual OR3 app; its command and receipt are recorded in [qualification](qualification.md) and [security review](security-review.md). Preset numeric budgets and a mixed-secret aged workload are now exercised in the linked internal Linux profile. Each deploying operator must still establish and verify its own target-storage budgets and intended inventory. No actual power-loss/filesystem-stack qualification has occurred. External audit forwarding/retention and attributable human MFA/break-glass administration, time/disk/expiry/drop alerts, independently controlled backup-key custody, deployment RPO/RTO and production permissions must be evidenced by the deploying operator.

Independent application-security and cryptographic implementation review, required findings/rechecks, target runtime/OS advisory scanning and release signing/provenance verification remain gates before high-value or regulated use. No compliance or FIPS validation is claimed. A full-source dedicated secret scanner was not substituted by the narrower package pattern scan. This record is internal implementation/testing evidence; it does not grant production acceptance.
