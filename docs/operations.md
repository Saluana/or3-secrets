# Operator walkthrough

Use a disposable development directory first. Bun 1.3.14 must be on PATH. Build with `bun install --frozen-lockfile --ignore-scripts && bun run build`. The package CLI is `node bin/or3-secrets.mjs`; commands below abbreviate it as `or3-secrets`. Values/credentials never belong in argv, environment values, terminal history or `echo` input. Use protected files or a non-echoing producer on stdin.

Run `or3-secrets --help` to choose a command, then use `put --help`, `help token issue`, or `restore -h` for required/optional flags, a complete example and relevant safety notes. `token` and `audit` also show their subcommands. Missing required flags are listed together; validation errors name the option without reflecting its supplied value. Terminal metadata is formatted JSON and terminal errors include a next step. Scripts receive compact JSON on stdout and `{error:{code,message,hint}}` on stderr; branch on `error.code`, not the prose. `get --stdout` remains exact plaintext with no added newline or status text.

Stop the foreground service with Ctrl-C, or send SIGINT/SIGTERM to its launcher. Successful graceful shutdown drains active requests, closes the vault, removes its socket and exits 0. Shutdown failures retain a nonzero exit status.

## Private development setup

```sh
umask 077
mkdir -m 700 ./example-private
mkdir -m 700 ./example-private/run
or3-secrets init --vault-dir ./example-private/vault \
  --key-file ./example-private/master.key --operator-file ./example-private/operator.token
or3-secrets serve --vault-dir ./example-private/vault \
  --key-file ./example-private/master.key --socket ./example-private/run/api.sock
```

The parent path must have no symlink or group/other-writable component (root-owned sticky temporary directories are allowed). Client/provider paths must be absolute and normalized, with no `.` or `..` components; validation must inspect the same path the kernel opens. The final key/token/output directories must be owned by the caller and exactly `0700`; private files exactly `0600`, regular and single-link. Do not use a symlink such as macOS `/tmp`; use `/private/tmp`. Copy the non-secret `vaultId` from initialization into `VAULT_ID` below. Never put key/token contents in that variable.

In a second terminal, issue a narrowly scoped expiring service token:

```sh
or3-secrets token issue --socket ./example-private/run/api.sock \
  --vault-id "$VAULT_ID" --token-file ./example-private/operator.token \
  --kind service --namespace example --owner-user-id internal-user \
  --workspace-id workspace --consumer-id fixture \
  --capabilities metadata,read,write,delete --expires-in 1h \
  --out-file ./example-private/service.token
```

There is no value argument. The value input file must itself be privately prepared; stdout disclosure requires an explicit flag:

```sh
or3-secrets put --socket ./example-private/run/api.sock --vault-id "$VAULT_ID" \
  --token-file ./example-private/service.token --namespace example \
  --owner-user-id internal-user --workspace-id workspace --consumer-id fixture \
  --name api --expected-revision 0 < ./example-private/input-value
or3-secrets get --socket ./example-private/run/api.sock --vault-id "$VAULT_ID" \
  --token-file ./example-private/service.token --namespace example \
  --owner-user-id internal-user --workspace-id workspace --consumer-id fixture \
  --name api --out-file ./example-private/recovered-value
```

`get --stdout` deliberately releases plaintext; redirect it only to an authorized consumer. `get --ref ID:REVISION` reads exactly that revision if still current. `inspect --name`, `list --after ID --limit 100`, and `delete --name --expected-revision N` use the same transport/scope flags. A delete/recreate keeps its record ID and advances revisions. Deleting a current tombstone returns `not_found` without advancing its revision; a stale expected revision still returns `revision_conflict`. Conflicts return exit 75; inspect before an explicit new attempt. No automatic retry is safe after a lost mutation response. Output files are exclusively reserved before disclosure/token issuance; failed or interrupted commands remove their own incomplete output, allowing a retry at the same path. An existing or concurrently replaced file is never overwritten or removed. A hard crash (SIGKILL or power loss) can leave an incomplete private file; inspect it before removing it manually.

For repeated commands, Bash/zsh arrays can hold the non-secret connection paths and scope. Keep operator and service credentials explicit and separate:

```sh
service=(--socket "$PWD/example-private/run/api.sock" --vault-id "$VAULT_ID" \
  --token-file "$PWD/example-private/service.token")
scope=(--namespace example --owner-user-id internal-user \
  --workspace-id workspace --consumer-id fixture)
or3-secrets inspect "${service[@]}" "${scope[@]}" --name api
or3-secrets get "${service[@]}" "${scope[@]}" --name api --out-file ./example-private/another-new-output
```

`status` uses just `--socket`, `--vault-id`, `--token-file`. `token list` takes `--after` and `--limit`; `token revoke --id ID` uses operator authority. Expiry is explicit seconds or a `s/m/h/d` suffix, maximum 90 days. Exit codes: 64 invalid usage/input or an existing output path, 65 integrity/invalid backup, 75 temporary/unavailable/conflict/throttle, 77 unauthorized/forbidden. Existing output paths return `output_exists` with a new-path hint; no credential is issued and no secret is read for a refused get/token output. Error text is fixed guidance or validated option names, never raw input, secret values or internal filesystem/SQL errors.

## Separate production identities

The development setup intentionally shares an identity; production **must not**. Provision service-owned `0700` database and key directories in separate custody/snapshot scopes. Provision a service-owned `0750` socket directory with a dedicated client GID; grant only that GID to OR3. Start `serve --socket-group NUMERIC_GID`; the directory GID must already match and the service must be allowed to assign the socket GID. It creates a `0660` socket. Put only the scoped service token in an OR3-owned `0700` credential directory as `0600`. Database, master key, operator credential and maintenance/backup staging stay inaccessible to OR3. Match effective numeric UIDs/GIDs when using containers.

Use the existing MFA-protected administrative path with named operators and recorded actions, including controlled break-glass access; keep the operator token off OR3. It can mint reading authority and is equivalent to vault administration. Choose namespace per deployment and only broaden owner/workspace/plugin restrictions when the application genuinely needs them. Check `status` expiry, disk size and wrap count externally. Schedule renewal before expiry; issue into a **new** private output, verify it, atomically replace the application's token file within its protected directory, then revoke the old ID. The client rereads on the next request; it caches no permission. Service-token renewal, fresh master-key rekey, and upstream API credential rotation/revocation are different procedures.

Stop through SIGTERM and wait for exit. The launcher forwards SIGTERM/SIGINT. Never automatically remove an existing socket on startup. After a crash, verify the prior owner is dead, inspect ownership/path, remove only the stale socket, then start on the unchanged vault/key. Do not delete SQLite journals or substitute an empty vault. Protect core dumps, process inspection and host snapshots externally.

## Audit collection

Issue `--kind audit-reader --capabilities audit --expires-in 1h` without scope fields into a new collector-owned credential file. A collector is sensitive: audit can disclose actor IDs, timing and operation relationships across the vault. Use a different identity/destination from the service's writable data.

```sh
or3-secrets audit read --socket ./example-private/run/api.sock --vault-id "$VAULT_ID" \
  --token-file ./example-private/audit.token --limit 100 \
  --out-file ./example-private/audit-page-1.json
```

First read omits `--after`; subsequent pages use `--after SEQ:MAC` and the returned `--through SEQ:MAC`. Forward a batch durably before advancing externally retained progress. After reaching `through`, wait at least 30 seconds before capturing another head; respect the shared five-operation/second reader budget. This avoids continuously chasing collection's own audit events. Empty pages still require an access audit commit. Offline `audit verify --vault-dir ... --key-file ... --receipt-file ...` verifies the full keyed chain and an independently retained `{vaultId,seq,mac}` receipt. The collector cannot independently compute keyed MACs from its bearer credential; it retains server receipts to detect later divergence. Never silently reset a mismatched checkpoint.

Ship fixed stderr rejection summaries and host `plugin_secret_authorized` records to protected existing monitoring. Correlate request ID, actor ID and the hashed activation correlation ID with vault events. Treat these as application assertions; operator-token use alone does not identify an individual. Alert on service exit/errors, collector lag, missing summaries/time drift, expiry, audit growth, disk headroom and wrap budget. Counter aggregation can lose detail and stderr is not a durable audit ledger. Define retention, deletion and response ownership externally; there is no hidden audit pruning or internal log shipper.

## Stopped-vault backup, restore and rekey

Stop the service. Maintenance requires exclusive ownership. Keep at least the source plus journal, staging and destination: backup checks one snapshot of headroom on live storage, then checks the encrypted output (including its 112-byte envelope) after staging exists. This accounts for both allocations when they share a filesystem. Rekey checks 3× logical database size and restore checks 4× snapshot size, each with a 64 MiB margin. Monitor both source and destination filesystems and reserve operational margin. These checks observe free space; they do not reserve it against concurrent writers. Fresh copies add recovery audit evidence and can grow by pages: the 1 GiB bound is the encrypted snapshot input limit, not a promise that a live or recovered vault cannot exceed it. Do not operate at the hard limit; a larger recovered database cannot be backed up through this format until an explicitly reviewed capacity/retention change is made. The 1 GiB cap includes all audit history; plan capacity well before it. Internal measurements are in the qualification receipt; they are not your deployment's RPO/RTO.

```sh
or3-secrets audit verify --vault-dir ./example-private/vault --key-file ./example-private/master.key
or3-secrets backup --vault-dir ./example-private/vault --key-file ./example-private/master.key \
  --out-file ./example-private/snapshot.backup
or3-secrets restore --backup-file ./example-private/snapshot.backup \
  --key-file ./example-private/master.key --destination ./example-private/restored \
  --new-key-file ./example-private/restored.key --operator-file ./example-private/restored.token
or3-secrets rekey --vault-dir ./example-private/vault --key-file ./example-private/master.key \
  --destination ./example-private/rekeyed --new-key-file ./example-private/rekeyed.key \
  --operator-file ./example-private/rekeyed.token
```

Add `--receipt-file` containing a separately retained private receipt to backup/restore/rekey to reject a snapshot that cannot contain it. Restore authenticates the whole outer envelope before opening SQLite, verifies its exact schema/state, then uses the same fresh-key copy as rekey. Both preserve vault/record IDs and revisions, reencrypt live values, revoke **all** copied service/audit/operator credentials, mint a fresh operator credential and rebuild the chain linked to the source receipt. Issue new scoped consumer/collector credentials, verify, and explicitly reconnect consumers to the new key/path/identity. The old source is preserved. Keep old keys for old retained backups under separately controlled custody.

Restore and rekey revoke previously active local credentials and preserve the original timestamps of credentials already revoked. An authenticated old snapshot still contains old upstream credentials. Reconcile restored values against issuance/revocation records and rotate/revoke upstream credentials as required; encryption does not make an old value valid. Interrupted destinations without `complete` cannot serve. Preserve source and failed private staging/outputs for controlled diagnosis; choose wholly new output paths for a retry. Never replace/delete a live deployment or recovery key automatically.

The current unpublished format requires a row-content binding (`detail.recordMac`) on each successful secret mutation. Earlier fixtures missing it fail verification, service admission and maintenance. Preserve any needed old fixture and key for a separately reviewed recovery procedure; no automatic conversion is attempted. Deploy matching service/audit-client builds because older strict audit clients cannot parse the added event field. Ordinary OR3 secret calls keep the same contract.

Before real deployment, name control owners, numeric latency/memory/downtime/RPO/RTO/retention budgets, storage/power-loss qualification and independent review gates in the security profile. No publication, live deployment or credential migration is part of this walkthrough.

## Post-review operating invariants

Provision the socket's service-owned directory before admitting clients. Clients default to their own UID; for separate custody set `--service-uid UID`, Node `serviceUid`, or private Nuxt `NUXT_SECRETS_SERVICE_UID`. Directory and socket ownership must both match that explicit service identity, before any credential is sent. A discovered foreign UID is never treated as trust.

Store backup outputs outside the source vault and new key/operator files outside both source and destination vaults. Internal unencrypted snapshot staging stays within live vault custody, including orphaned staging after interruption. The backup medium receives only authenticated encrypted output. Preserve incomplete private outputs for diagnosis; retry with fresh paths.

`put` preserves a leading or embedded UTF-8 BOM and all newlines. Invalid UTF-8 still fails. File-based `audit read` reserves the private destination before contacting the service; an existing path consumes no reader budget or audit checkpoint. Reader status, export and forbidden requests all share the five-per-second credential admission limit; fresh-head capture retains its separate 30-second restriction. Rejections before admission use bounded telemetry and add no durable event.

The live high-water mark is **960 MiB**, with an additional **1 MiB** per-operation growth margin. `capacity_reached` (503 / CLI exit 75) refuses ordinary work before consuming the **64 MiB** reserve below the 1 GiB backup envelope ceiling. Stop and perform offline backup/rekey before resuming. Read the file size and offline verification receipt when online status is refused. Row-wise rekey has no envelope-size cutoff and reconstructs actual rows, preserving history while removing free/trailing pages. A history that still exceeds the live mark after reconstruction remains blocked; rotate its key offline, retain all artifacts, and arrange a reviewed capacity change. Do not prune history or delete source custody to make it fit.

The mixed-workload qualification defines development budgets before measuring them. It does not choose deployment RPO/RTO, peak maintenance memory, power-loss durability or compliance controls for the operator.

## Disposable operator qualification

With exactly Bun 1.3.14 and Node 24.13.0 on PATH, run `bun run qualify`, then `bun --no-env-file scripts/qualify-operator.ts`. The packaged CLI walkthrough exercises the procedures above, including expiry, atomic token replacement, revocation, collector restart/checkpoint, backup and fresh-key restore/rekey. It writes only synthetic fixture data and a metadata-only `test-results/operator.json` receipt. Linux additionally checks that the service owns no TCP/UDP sockets. The [local qualification record](https://github.com/Saluana/or3-secrets/blob/main/docs/local-qualification.md) lists measured capacity budgets, control responsibilities and separate production gates. An independently operated collector, working alerts, named MFA-protected administrators and separate key custody need target-environment evidence.
