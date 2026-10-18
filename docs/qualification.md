# Reproducing qualification

Use exactly Bun 1.3.14 and Node 24.13.0; no global runtime changes are needed. `docs/assurance.md` records the default nonvalidated profile and failure catalog. `test-results/` is ignored and contains synthetic, redacted machine receipts. Tests run actual CLI/service processes and Unix HTTP; crypto vectors are independently specified NIST/RFC values. OR3 route tests supply host infrastructure fixtures and test server-derived scope/liveness; they are not evidence of a production browser deployment.

```sh
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run typecheck
bun test --timeout 30000 tests
bun run qualify
```

`qualify` records a clean package artifact, SHA-256, contents/import boundaries, dependency inventory and build input identities. Its receipt distinguishes dirty working sources from a clean committed revision and includes the exact companion host pin. It performs no publishing/signing. Run a dependency advisory scan separately (`bun audit --json`) and assess its actual output. Artifact checksums and local build provenance do not establish an independently signed release. The read-only [qualification workflow](../.github/workflows/qualify.yml) runs frozen lifecycle-disabled installs, build, types, regressions, interruption and mixed profiles, package/provider checks, Linux custody/ENOSPC checks and scans. Sanitized JSON/XML receipts and the tarball are retained under the tested source SHA for 30 days. It publishes no package, tag or deployment; a successful workflow does not approve unresolved runtime advisories.

The full suite must have permission to bind local Unix sockets. Its CLI/Node roundtrip covers exact bytes/private output, capability/scope isolation, expiry/revocation, concurrency/tombstones, hostile schema/state, wrong vault, audit cursor/frozen-head semantics, crash/restart and fresh-key recovery. Never run tests against real credentials.

## Linux qualification

The pinned Dockerfile combines Bun 1.3.14 and actual Node 24.13.0; Bun's own `process.versions.node` is an emulation version and is not the Node client version. Docker Desktop's Linux VM is the measured environment, not a claim about every Linux filesystem or production hardware.

```sh
docker build -f scripts/Qualification.Dockerfile -t or3-secrets-qualification:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
  -v "$PWD:/work:ro" -v "$PWD/test-results:/work/test-results" \
  or3-secrets-qualification:local bun test --timeout 30000 tests
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=8m,mode=1777 \
  -v "$PWD:/work:ro" -v "$PWD/test-results:/receipts" \
  or3-secrets-qualification:local bun --no-env-file scripts/qualify-disk.ts
```

The second command fills a real 8 MiB filesystem under non-root UID 1000, observes a refused plaintext read when its audit cannot allocate and a failed mutation with no partial record, then frees space/restarts and verifies retained data. Before fixture creation it requires a dedicated `/tmp` tmpfs of at most 8 MiB and caps filler writes at 8 MiB. Running it on ordinary storage must fail. Operations fitting preallocated SQLite/journal space may succeed before allocation fails. This is ENOSPC qualification, not a mocked error. Power loss is unperformed; SIGKILL/restart is a different test.

`bun --no-env-file scripts/qualify-provider.ts` builds an isolated Nuxt app from the local tarball with the existing OR3 host toolchain. Registry sources come from the exact revision in `host-compatibility.json` using `git show`, rather than uncommitted sibling files. It clears ambient application/provider overrides, deliberately poisons them with a second synthetic vault, checks effective fixture identity, and requires zero ambient-vault calls. The same prepared read must succeed, fail with exactly `503 unavailable` while stopped, and succeed after restart. It also scans the public bundle for private fixture inputs. This is a provider packaging check, not a full browser activation walkthrough.

`bun --no-env-file scripts/qualify-host.ts` runs the full OR3 source app with disposable Basic Auth, SQLite and filesystem storage, an empty dotenv file, and the checksum-verified local vault tarball. It requires a clean host checkout at exactly the revision in `host-compatibility.json`, installed dependencies, Node 24, the pinned Bun runtime first in `PATH`, and `agent-browser` with Chromium installed. Both provider and browser qualifiers accept `OR3_SECRETS_HOST_DIR` to select that checkout; otherwise they use the sibling `or3-chat`. The browser qualifier refuses a different HEAD or modified tracked sources. It binds only loopback and a private Unix socket. No published package, real credential, existing database or application configuration is changed.

The host qualification uploads a synthetic trusted-host package through the real admin API, approves its exact authority, runs the normal UI browser canary and promotion, then exercises the actual Chat plugin loader and `host.secrets`. It checks remembered/session storage, page reload, delete/recreate revisions and stale refs, server-derived scope, scope injection, unauthenticated refusal, workspace-switch and grant-revocation fencing, live vault outage/restart, no device fallback, and absence of synthetic plaintext in vault files or private provider configuration in Nuxt hydration data. The separate provider qualification owns the compiled public-bundle scan. Receipts and a screenshot are saved as `test-results/host-browser.json` and `test-results/host-browser.png`; the successful fixture and child processes are removed. Failed synthetic fixtures are retained at the reported private temporary path for diagnosis. This is full-app development-server qualification, not production deployment acceptance.

The browser qualifier exports committed host sources with `git archive` into its private fixture and generates fresh Nuxt state there. Only the explicitly installed dependency toolchain is reused. It cannot depend on ignored generated files or local application inputs from the developer checkout.

`sh scripts/qualify-isolation.sh` is run as root only inside a disposable Linux container to provision service UID 1000 and client UID 1001 sharing GID 2000; the actual service/client run unprivileged. It proves socket access while database/master/operator reads are denied, refuses foreign-owned ancestors, and requires zero credential requests to a leaf directory/socket owned by UID 1002.

`bun --no-env-file scripts/qualify-interruptions.ts` externally stops/kills init, restore and rekey at observable key/database/operator/completion stages, without production fault switches. Each incomplete destination refuses admission; each completed destination verifies and serves with its saved key/operator. Same-path retries cannot overwrite custody; fresh-path retries verify and source bytes remain unchanged. Interrupted backup staging must remain on live storage. The receipt is `test-results/interruptions.json`.

`bun --no-env-file scripts/qualify-profile.ts` declares budgets before measuring a mixed inventory: 1,500 live secrets, 500 tombstones, 250 expired and 250 revoked tokens, and audit from reads/status/denials/collection. Budgets are 5 s startup, 512 MiB steady-state service RSS, 100 ms HTTP read p95, 30 s backup, 60 s restore and 60 s rekey. Recovered destinations must remain below the supported live mark. Results are in `test-results/profile.json`; these development budgets do not define deployment RPO/RTO or peak maintenance memory.

The full-source Trivy secret scan includes a project bearer-token rule and excludes dependencies, build output, Git metadata and generated receipts. The OS scan examines the pinned qualification image, records every severity and does not assert exploitability. It does not identify embedded Bun/Node native vulnerabilities reliably; inventory those versions and consult their upstream advisories separately. See [review remediation](review-remediation.md) for the known open runtime gate. The image is a test environment, not an approved production image.

`bun --no-env-file scripts/qualify-capacity.ts` builds an authenticated aged history at the exact declared 1 GiB boundary, measures full verification/backup/fresh-key restore/rekey, records envelope size, timings and runtime-reported RSS, then removes only its own disposable fixture. It needs several GiB of temporary space. Compare actual results with numeric budgets selected **before** production qualification. Do not call a near-limit history an exact-limit fixture or infer every workload's capacity from it.

The OR3 host verification commands and measured results are recorded in `docs/implementation-receipt.md`. Remaining release/deployment/independent-review gates are explicitly retained there and in the planning checklist. A repeatable application test suite does not certify a deployment or high-value use.
