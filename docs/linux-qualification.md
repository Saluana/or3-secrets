# Linux core qualification — 2026-10-18

Task 13 qualifies the disposable core workload on this computer. It does not deploy the service or approve a production environment. The machine receipts in `test-results/` accompany this record; the historical arm64 results in `implementation-receipt.md` are separate evidence.

## Profile and budgets selected before measurement

Profile `linux-x64-local-v1`: Debian Linux 6.12.63+deb13-cloud-amd64, four AMD EPYC-Rome virtual CPUs, approximately 7.7 GiB RAM, ext4 (`rw,relatime,stripe=128`), Bun 1.3.14, actual Node 24.13.0. Node was downloaded and checksum-verified in the workspace; the system Node 20 and global Bun were not changed. This shared VPS had other workloads running; the measurements describe this run, not dedicated-machine SLOs.

The preselected `scripts/linux-budgets.json` is the input to both runners. The small workload has 100 live 1 KiB values, with 200 sequential reads and 200 CAS writes. Budgets: startup at most 2 seconds, p95 per operation at most 50 ms, idle service RSS at most 128 MiB. The closed-loop measurements are single-client latency observations, not a concurrent throughput guarantee.

The aged workload contains 1,000 live secrets (evenly distributed 128 B, 1 KiB, 8 KiB and 32 KiB values, each rewritten to revision 2), 100 authenticated tombstones, and 32 service credentials plus operator authority. Offline authenticated status events age that inventory to exact 64 MiB, 256 MiB, 768 MiB and 1 GiB SQLite inputs. Their deliberately historical timestamps exercise sequence ordering; they do not represent a claim of elapsed retention time. Production code has no fixture-generation or failure-injection option.

At each stage: actual service startup at most 120 seconds; open plus full verification at most 240 seconds; backup at most 240 seconds; restore and rekey each at most 600 seconds; maximum operation RSS at most 512 MiB. Each operation runs in a fresh process. Linux `ru_maxrss` is converted from KiB; the startup worker also reads the service's actual `/proc` high-water mark. Restore/rekey measurements conservatively include destination reopening, fresh authority issuance, old operator denial, independent expected-value/revision checks, tombstone and wrapping-count checks, and another full verification. No production cache or pruning was added.

Require at least 8 GiB free before the capacity run, in addition to the maintenance tool's actual 3×/4× snapshot plus 64 MiB headroom checks. The live operating policy warns at 512 MiB and requires stopping growth and arranging maintenance by 768 MiB. The exact 1 GiB fixture tests the backup format boundary; it is not an appropriate steady operating target. Recovery can add pages. Neither SQLite nor secret writes enforce the lower operational thresholds; the operator must enforce the policy externally.

The disposable crash target is zero lost acknowledged commits, and the fixture restore RTO budget is ten minutes. Snapshot recovery reaches the independently retained backup checkpoint. No backup schedule or production RPO was configured or inferred from this test.

## Reproduction

Use a local Bun 1.3.14 and actual Node 24.13.0 first in `PATH`. The vault correctly refuses the workspace's group-writable ancestors, so use a private temporary directory on the target filesystem. On this machine `/var/tmp` is on ext4; `/tmp` is tmpfs and is unsuitable for the multi-GiB capacity run.

```sh
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run typecheck
bun test --timeout 30000 tests
OR3_QUALIFY_TMPDIR=/var/tmp bun --no-env-file scripts/qualify-linux.ts
OR3_QUALIFY_TMPDIR=/var/tmp bun --no-env-file scripts/qualify-capacity.ts
# Only Docker needs privilege. It creates no host users or host mounts.
sudo sh scripts/qualify-privileged.sh
```

The privileged wrapper builds the pinned existing Dockerfile, drops capabilities, disables container networking and runs disposable tmpfs fixtures. ENOSPC runs as the non-root owner of the receipt directory with an exact 8 MiB `/tmp`; a separate private 128 MiB staging mount permits creating a genuine backup before testing restore's low-space refusal. A guard refuses to fill any other filesystem. Isolation provisions service UID 1000 and client UID 1001 sharing GID 2000 only inside the disposable container. The actual vault and Node client are unprivileged. Only the synthetic receipts are written back to the checkout. The unique image is removed afterward.

`qualify-linux.ts` checks file/directory fsync, the retained zeroed rollback journal under exclusive ownership, socket mode, this service's socket inodes against Linux TCP listen tables, and acknowledged-value recovery after SIGKILL. Service startup itself verifies the effective DELETE/EXCLUSIVE/EXTRA pragmas before returning status. Power failure, hypervisor cache loss and physical-device durability are unperformed.

The collector fixture runs actual Node 24, durably writes a page, then receives SIGKILL before advancing its independent checkpoint. A resumed reader reloads that checkpoint, receives the identical frozen-head page and drains consecutive pages without gaps. A batch of 512 bad credentials must produce bounded sanitized coalesced stderr evidence. Expiry is observed using the actual clock. `timedatectl` records the NTP state and measured offset. No production time configuration is changed.

## Monitoring responsibilities and remaining boundaries

| Owner | Required signal and response |
| --- | --- |
| Service operator | Check service exit/errors and health at 30-second cadence. Alert if the collector's durable cursor lags more than 60 seconds. Retain checkpoints independently, forward before advancing, deduplicate retries and never reset a mismatched cursor. |
| Log/monitoring operator | Ship rejection summaries and alert on any `droppedIntervals > 0`. The no-drop summary was observed; a representative dropped-summary input exercises the alert threshold. Sustained blocked-stderr backpressure was not forced. Rejection summaries are emitted only for rejected traffic, so silence alone is not a heartbeat; use service/collector liveness to detect missing collection within 60 seconds. |
| Infrastructure operator | Keep measured absolute NTP offset at most 1 second. Use sequences for ordering despite wall-clock changes. Alert below 8 GiB free, at 512 MiB database size, on nearing 1,000,000 wraps, or with under 24 hours of credential lifetime. Stop growth by 768 MiB and verify maintenance headroom on source and destination filesystems. |
| Recovery/custody operator | Retain encrypted backups and keys under independently controlled custody, choose and prove the actual backup RPO, issue replacement service/audit authority after restore, reconcile upstream credential validity, and perform target power-loss qualification if required. |

Healthy observed signals and adverse lag, drop, clock, expiry and disk inputs exercise the qualification assertions. These are fixture alert evaluations, not an installed production monitor or evidence that this VPS's existing alerting service delivered an incident notification. External retention, named human administration, independently protected keys, production RPO/RTO, power-loss evidence and independent security review remain deployment/release gates.

## Results

The core process/security suite passed **19 tests, 285 assertions** after the fixture changes; the build, production typecheck, strict qualification-script typecheck, shell syntax and whitespace checks passed. The packaged Node 24 client and launcher roundtrip also passed.

| Small-workload observation | Measured | Preset budget |
| --- | ---: | ---: |
| Initial empty-vault readiness | 79.35 ms | 2,000 ms |
| Populated-vault SIGKILL restart | 151.22 ms | 2,000 ms |
| Read p95, 200 requests | 10.11 ms | 50 ms |
| CAS write p95, 200 requests | 8.47 ms | 50 ms |
| Service idle RSS after workload | 65.93 MiB | 128 MiB |

DELETE journal, EXCLUSIVE locking and EXTRA synchronization passed admission. While the service owned the vault it retained a 25,136-byte journal with a zeroed header, consistent with the observed exclusive rollback-journal behavior. File and directory fsync succeeded, acknowledged data and the sync probe survived process restart, and the service owned no TCP listener. The private socket was `0600`; the separate-identity profile independently verified a `0660` service-owned/GID-2000 socket in a `0750` directory.

The non-root UID-1001 ENOSPC run used exactly 8,388,608 bytes of disposable tmpfs. 5 reads fit existing allocations before the required audit write failed; that failed read released no plaintext. The first new large mutation failed without a partial record. Both modes recovered the pre-existing synthetic value after space was freed and the service restarted. Backup, restore and rekey each refused insufficient maintenance headroom before creating their requested output/destination.

Service UID 1000 and actual Node client UID 1001 shared only GID 2000 socket access. The real write/read roundtrip passed; database, master key and operator-token reads were denied to the client, and a foreign-owned ancestor was rejected. `disk-full.json.node` is Bun's emulated Node compatibility version; `isolation.json.node` records the actual Node v24.13.0 executable.

The real Node collector was killed after fsync of a forwarded batch and before progress advancement. The resumed reader replayed identical events and drained 6 pages through captured sequence 504 without gaps. A 512-request bad-credential burst produced one 174-byte fixed rejection summary, zero observed drops and no raw supplied credential. Expiry refusal passed. NTP reported synchronized status and -0.058 ms offset against the 1,000 ms budget. Healthy and adverse monitoring inputs produced their expected no-alert/alert decisions, subject to the operational boundaries above.

| SQLite input | Audit events | Startup (s) | Verify (s) | Backup (s) | Restore (s) | Rekey (s) | Peak RSS (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 MiB | 66,504 | 1.42 | 2.58 | 2.91 | 8.57 | 8.53 | 171.32 |
| 256 MiB | 360,678 | 5.49 | 10.89 | 12.48 | 35.81 | 40.35 | 172.03 |
| 768 MiB | 1,145,124 | 16.92 | 32.59 | 37.44 | 246.75 | 136.06 | 175.88 |
| 1024 MiB | 1,537,356 | 57.84 | 44.18 | 51.34 | 224.23 | 220.96 | 175.16 |

All stage timing and memory budgets passed without raising them. The exact 1 GiB fixture contained **1,537,356 authenticated events**, produced a **1,073,741,936-byte envelope** (exact 112-byte overhead), and restored/rekeyed to 1,073,684,480-byte databases after the verification/reconnection checks. Startup lifecycle timing conservatively includes shutdown; verify includes both opening validation and a repeated full verification.

Filesystem free space was sampled every 25 ms during each maintenance worker. The largest observed decrease from the pre-fixture baseline was 4,869,273,600 bytes (4.53 GiB), below the 8 GiB reservation. This shared-filesystem observation includes concurrent unrelated writes and can miss shorter peaks; it is not an exclusive-allocation guarantee. The tools' conservative headroom checks and the 8 GiB external reserve remain mandatory.

The original four-stage receipt preserves these measurements. A separate `capacity-oversize.json` records the selective rerun of the oversize refusal after correcting the fixture's artificial page ceiling. That correction changes qualification storage generation only. Use `OR3_QUALIFY_TMPDIR=/var/tmp bun --no-env-file scripts/qualify-capacity.ts --oversize-only` to reproduce just that check.


A **1,073,750,016-byte authenticated SQLite input** (8 KiB above the snapshot limit) was refused with `too_large` before backup output creation. The complete result is summarized in `test-results/task13-manifest.json`; raw stage and selective-refusal receipts are retained separately. **Task 13 is complete for this internal Linux profile.**
