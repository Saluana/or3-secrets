# Disposable local qualification

The remaining implementation tasks were qualified on 2026-10-18. The agreed scope is disposable local qualification; production acceptance stays separate. No real credentials, deployment, npm version or release tag are part of this work. The [original implementation receipt](implementation-receipt.md) remains historical.

| Task | Repeatable evidence |
| --- | --- |
| 13: Linux recovery and resource bounds | Process security suite, twelve interruption stages, real 8 MiB ENOSPC, separate service/client/foreign UIDs, mixed operating profile and exact 1 GiB mixed-inventory recovery. Receipts: `interruptions.json`, `isolation.json`, `disk-full.json`, `profile-linux.json`, `capacity.json`. |
| 18: OR3 boundaries | Packaged Node/Nuxt provider and real browser package upload, review, canary, promotion and Chat activation; scope/grant/context fencing, outage/restart, wrong vault, audit correlation, unchanged localStorage/Dexie and disabled-provider behavior. Receipts: `provider.json`, `host-browser.json` and screenshot; 153 passing checks across 16 host suites, including existing credential owners. |
| 19: Operator workflow | Checksum-verified packaged CLI under actual Node: exact private output, authority separation, expiry, atomic token replacement/revocation, collector interruption/resume, retained checkpoint, backup, fresh-key restore/rekey, old-token rejection and source preservation. Receipt: `operator.json`, including metadata-only command transcript and Linux no-TCP/UDP assertion. |
| 20: Final internal qualification | Strict types, build, 26 passing security tests with 367 assertions, clean committed tarball, public/server import checks, dependency inventory, advisory/material/OS scans, checksum and source/host pins. The read-only CI workflow retains evidence; it neither signs nor publishes a release. |

Run the commands in [qualification](qualification.md). Scripts select synthetic fixtures and remove their own successful temporary data; they never use a deployed vault. `test-results/` is ignored. Its receipts identify the actual environment and artifact; CI retains them under the tested commit. These checks do not qualify every Linux filesystem or target host.

## Measured local capacity

The Linux ARM64 Docker profile used Bun 1.3.14, actual Node 24.13.0, a 1 GiB container memory limit, no network and no capabilities. The fixture contained 1,500 live secrets, 500 tombstones, 500 updated secrets, 250 expired and 250 revoked tokens, and 1,564,699 authenticated events. Budgets were fixed in the script before measuring.

| Operation | Local budget | Observed |
| --- | --- | --- |
| Full verification/admission | 45 s | 18.38 s |
| Encrypted backup | 60 s | 22.75 s |
| Fresh-key restore | 120 s | 57.51 s |
| Fresh-key rekey | 120 s | 57.06 s |
| Peak maintenance RSS | 512 MiB | 177.2 MiB |

The database was exactly 1,073,741,824 bytes, and its encrypted envelope exactly 112 bytes larger. Live admission correctly returned `capacity_reached`. Recovered databases were 1,073,094,656 bytes, still above the 960 MiB live high-water mark. Successful offline recovery therefore does **not** authorize starting those destinations for live work. Preserve their source, keys and history and review capacity explicitly. No automatic pruning or raised limit was added. The qualifier requires at least 6 GiB free disposable storage; production headroom and recovery objectives require measurement on the intended host.

These numbers describe ARM64. The [initial x64 CI run](https://github.com/Saluana/or3-secrets/actions/runs/39140855005) completed recovery but failed the 45 s verification gate. The x64-baseline Bun build has a separately declared CI ceiling and must also pass a same-host verification comparison against commit `0888b45cea9428e9daf769a976b45d082187c3e1` on the same fixture, within 20%. See [reproduction and ceilings](qualification.md). Failure timings are retained, and neither the ARM64 budgets nor the job timeout were increased. A passing comparison and full capacity receipt are required before accepting that CI profile.

## Separate production and release acceptance

Repository maintainers own executable local checks and their receipts. A deployment owner must assign actual people and obtain the following evidence before claiming production acceptance. No production owner or named host was supplied for this local work.

| Pending gate | Required owner and evidence |
| --- | --- |
| Runtime and OS findings | Release/security owner: assess and resolve material Bun, Node, embedded SQLite and OS findings for the exact deployed stack. The pinned test image is not an approved production image. |
| Human administration | Deployment/identity administrator: named operators, MFA, alternate access and tested break-glass controls. Token files do not establish individual human attribution. |
| Independent audit collection | Monitoring owner: durable independently retained pages/checkpoints, retention/access policy and exercised collector lag, missing progress, dropped diagnostics, clock and disk alerts. Local resume checks do not prove an external collector is operated. |
| Keys and backup custody | Recovery custodian: separate service/OR3 identities and permissions on the target host, independently controlled key/backup copies, access review and tested recovery authority. |
| Target storage and recovery | Deployment/storage owner: actual filesystem and power-loss qualification, capacity/headroom, accepted RPO/RTO, restore reconciliation and interrupted-maintenance procedure. Process kills and ENOSPC are distinct evidence. |
| Independent security review | Security owner: external application-security and cryptographic review of the exact release and deployment/recovery boundary before high-value or regulated use; resolve/recheck findings and record residual decisions. |
| Release provenance | Release owner: authorized unused version, reviewed signing/verification and registry/artifact availability. Local checksums and CI success are not independent signatures. |

The [security profile](../planning/secure-secret-store/security-profile.md) and [task checklist](../planning/secure-secret-store/tasks.md) retain these gates. Existing operational tools own collection, identity and alerting; this service adds no monitoring platform or identity system.
