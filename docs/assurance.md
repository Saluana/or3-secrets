# Implementation assurance record

Target: application secret custody for local OR3 development and a separately qualified Linux deployment. No regulated deployment or FIPS-validated cryptographic module has been specified. Select the plan's default **nonvalidated Bun profile**, pinned to Bun 1.3.14, with Node 24 client compatibility. This is an implementation choice, not a compliance or production-readiness decision. A deployment requiring validated cryptography must not use this profile as evidence of validation.

Product controls and executable evidence belong to this repository's maintainers. Named human administrators, MFA, time, external audit custody/collection/alerts, host isolation, independent key backups, capacity/retention and recovery objectives belong to the deploying operator. Independent application-security/cryptographic review belongs to a reviewer independent of this implementation. All unperformed deployment/independent-review gates in the security profile remain pending.

The revised plan is implementable without broadening it. Review clarifications: a backup restores through the same fresh-key copy as rekey; SQLite schema text is allowlisted before data statements; a vault ID is checked before dispatch as well as in responses; operator authority can mint secret-use credentials; audit export freezes its head before auditing access; process interruption is not evidence of power-loss durability. No automatic import or production mutation is part of this work.

## Failure catalog and primary test owners

| Requirement | Credible failures / external evidence owner |
| --- | --- |
| R1 | Existing outputs overwritten, symlinks/unsafe files admitted, wrong/missing key, second owner, incomplete marker, hostile schema: CLI/service E2E. File/directory sync is exercised by lifecycle operations; power loss remains a deployment qualification. |
| R2 | Wrong AES/HKDF encoding, altered AAD/tags/wrapped keys, row/policy/header tampering, wrong destination wrap count: independent-vector crypto checks plus offline tamper/recovery E2E. |
| R3 | Scope substitution, missing capability, operator/audit misuse, expired/revoked credentials: real API authorization matrix. |
| R4 | Wrong-vault side effect, Origin/unknown fields/malformed input, limits, socket mode, accidental TCP: real transport E2E and Linux qualification. |
| R5 | Lost concurrent update, reference ABA, incorrect pagination, audit-less mutation: concurrent real API and storage-failure checks. |
| R6 | Plaintext or audit export before audit commit, chain modification, divergent cursor, export self-draining, unbounded invalid-input evidence: real API/maintenance and Linux write-failure checks. |
| R7 | Value in argv, echoing TTY, implicit stdout, trimmed stdin, unsafe output, leaked error: CLI process E2E. |
| R8 | Unauthenticated SQLite opened, overlarge/trailing/truncated backup, same-key writable restore, source overwritten, recovered token reuse: maintenance E2E and maximum-envelope qualification. |
| R9 | Browser-supplied authority, stale activation/grants/workspace, persistent fallback, server bundle exposure: OR3 host integration checks and package qualification. |
| R10 | Bun dependency in Node client, developer-only resolution, unpinned runtime, missing docs: Node client, clean package build and documented runtime probes. |
| R11 | Tests miss deliberate corruptions, evidence leaks canaries, unassessed dependencies, falsely claimed qualification: negative controls, redacted receipt, SBOM/scans and artifact checksums. |
| R12 | Unattributed administration, shared custody, missing monitoring or independent review: named operator/reviewer evidence; never inferred from passing application tests. |

Tests are written before their production boundaries. Each assertion owns externally observable behavior or an independent byte-level crypto contract; no test-only runtime failure switches are permitted. Existing coverage is empty, so these contracts currently have no stronger owner. Fault injection uses actual corrupt files, SQLite limits or constrained filesystems and disposable process termination, not a mock claiming the result. Synthetic fixture canaries are the only secret-like material in tests.
