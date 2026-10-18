# Reproducing qualification

Use exactly Bun 1.3.14 and Node 24.13.0; no global runtime changes are needed. `docs/assurance.md` records the default nonvalidated profile and failure catalog. `test-results/` is ignored and contains synthetic, redacted machine receipts. Tests run actual CLI/service processes and Unix HTTP; crypto vectors are independently specified NIST/RFC values. OR3 route tests supply host infrastructure fixtures and test server-derived scope/liveness; they are not evidence of a production browser deployment.

```sh
bun install --frozen-lockfile --ignore-scripts
bun run build
bun run typecheck
bun test --timeout 30000 tests
bun run qualify
```

`qualify` records a clean package artifact, SHA-256, contents/import boundaries, dependency inventory and build input identities. It performs no publishing/signing. Run a dependency advisory scan separately (`bun audit --json`) and assess its actual output. Artifact checksums and local build provenance do not establish an independently signed release. No workflows or signing credentials are added by this implementation.

The full suite must have permission to bind local Unix sockets. Its CLI/Node roundtrip covers exact bytes/private output, capability/scope isolation, expiry/revocation, concurrency/tombstones, hostile schema/state, wrong vault, audit cursor/frozen-head semantics, crash/restart and fresh-key recovery. Never run tests against real credentials.

## Linux qualification

The current x86_64 task 13 profile, preselected budgets, mixed-inventory stages, results and monitoring boundaries are recorded in [Linux core qualification](linux-qualification.md).

The pinned Dockerfile combines Bun 1.3.14 and actual Node 24.13.0; Bun's own `process.versions.node` is an emulation version and is not the Node client version. The original arm64 measurements used Docker Desktop's Linux VM. The current x86_64 run uses this computer's native Linux/ext4 profile plus disposable Docker tmpfs isolation checks; neither profile qualifies every Linux filesystem or production host.

```sh
docker build -f scripts/Qualification.Dockerfile -t or3-secrets-qualification:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
  -v "$PWD:/work:ro" -v "$PWD/test-results:/work/test-results" \
  or3-secrets-qualification:local bun test --timeout 30000 tests
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=8m,mode=1777 \
  --tmpfs /staging:rw,nosuid,nodev,size=128m,mode=700,uid=1000,gid=1000 \
  -v "$PWD:/work:ro" -v "$PWD/test-results:/receipts" \
  or3-secrets-qualification:local bun --no-env-file scripts/qualify-disk.ts
```

The second command fills a real 8 MiB filesystem under non-root UID 1000, observes a refused plaintext read when its audit cannot allocate and a failed mutation with no partial record, then frees space/restarts and verifies retained data. Operations fitting preallocated SQLite/journal space may succeed before allocation fails. This is ENOSPC qualification, not a mocked error. Power loss is unperformed; SIGKILL/restart is a different test.

`bun --no-env-file scripts/qualify-provider.ts` builds an isolated Nuxt app from the local tarball with the existing OR3 host toolchain, runs its Node server against the real vault, checks a selected outage, and scans its public bundle for private fixture inputs. It is a provider packaging check, not a full browser activation walkthrough.

`bun --no-env-file scripts/qualify-host.ts` runs the full OR3 source app with disposable Basic Auth, SQLite and filesystem storage, an empty dotenv file, and the checksum-verified local vault tarball. It requires the sibling `or3-chat` checkout with installed dependencies, Node 24, the pinned Bun runtime first in `PATH`, and `agent-browser` with its Chromium browser installed. It binds only loopback and a private Unix socket. No published package, real credential, existing database or application configuration is changed.

The host qualification uploads a synthetic trusted-host package through the real admin API, approves its exact authority, runs the normal UI browser canary and promotion, then exercises the actual Chat plugin loader and `host.secrets`. It checks remembered/session storage, page reload, delete/recreate revisions and stale refs, server-derived scope, scope injection, unauthenticated refusal, workspace-switch and grant-revocation fencing, live vault outage/restart, no device fallback, and absence of synthetic plaintext in vault files or private provider configuration in Nuxt hydration data. The separate provider qualification owns the compiled public-bundle scan. Receipts and a screenshot are saved as `test-results/host-browser.json` and `test-results/host-browser.png`; the successful fixture and child processes are removed. Failed synthetic fixtures are retained at the reported private temporary path for diagnosis. This is full-app development-server qualification, not production deployment acceptance.

`sh scripts/qualify-isolation.sh` is run as root only inside a disposable Linux container to provision service UID 1000 and client UID 1001 sharing GID 2000; the actual service/client run unprivileged. It proves socket access while database/master/operator reads are denied and refuses foreign-owned ancestors.

`bun --no-env-file scripts/qualify-capacity.ts` builds the declared mixed secret/token/tombstone inventory with authenticated aged histories at 64 MiB, 256 MiB, 768 MiB and the exact declared 1 GiB boundary, measures full verification/backup/fresh-key restore/rekey, records envelope size, timings and runtime-reported RSS, then removes only its own disposable fixture. It requires at least 8 GiB free; set `OR3_QUALIFY_TMPDIR` to a safe parent on the target persistent filesystem. It enforces the numeric budgets in `scripts/linux-budgets.json`, selected before measurement. Do not call a near-limit history an exact-limit fixture or infer every workload's capacity from it.

The OR3 host verification commands and measured results are recorded in `docs/implementation-receipt.md`. Remaining release/deployment/independent-review gates are explicitly retained there and in the planning checklist. A repeatable application test suite does not certify a deployment or high-value use.
