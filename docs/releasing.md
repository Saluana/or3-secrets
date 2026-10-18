# Publishing @or3/secrets

The initial candidate is **0.1.0**. Preparing it does not publish it. Production acceptance remains separate from disposable qualification.

## License

The package is licensed under MIT. Keep the root LICENSE and `package.json` license metadata aligned. npm includes the root LICENSE automatically.

## npm account setup

An npm owner with publish permission for the `@or3` scope must configure trusted publishing for `@or3/secrets`: GitHub owner **Saluana**, repository **or3-secrets**, workflow filename **qualify.yml**, no environment name, direct publishing allowed. Require 2FA for maintainer accounts. Do not add npm write tokens to repository secrets. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

If npm cannot configure trust before the first version exists, the first publication requires an explicit operator bootstrap decision using the exact qualified tarball and an authenticated 2FA session. Do not publish a placeholder, silently bypass qualification, or commit credentials. Configure OIDC immediately afterward. A successful local dry run does not prove npm account permissions or trusted-publisher configuration.

## Prepare and qualify

1. Record the source branch and commit. Use a clean isolated worktree, no `.env`, shared `node_modules`, sibling aliases, or generated leftovers. Use Node 24.13.0 and Bun 1.3.14. Install with `bun install --frozen-lockfile --ignore-scripts`.
2. Choose an unused version and update `package.json` and current installation examples. Confirm both the exact npm version and `v<version>` Git tag are absent; connectivity/authentication errors do not prove absence. Never reuse a version or move a release tag.
3. Run `bun --no-env-file run build`, `bun --no-env-file run typecheck`, `bun --no-env-file run format:check`, `bun --no-env-file test --timeout 30000 tests`, and `bun --no-env-file run qualify`. Run the operator and provider qualification against the immutable host from `host-compatibility.json`. Inspect the final diff and `test-results/package-receipt.json`, SBOM, and tarball contents. The package whitelist excludes source, planning, test state, and credentials.
4. Commit the candidate, then repeat package qualification from the clean commit so its receipt records that exact SHA. Merge/push reviewed source to main and verify its remote SHA. The ordinary main workflow must pass its full Linux custody, recovery, capacity, dependency, and source secret scan gates. Do not waive deterministic failures.

## Publish after operator authorization

Push only `v<version>` pointing to the verified remote main commit. The tag runs the full qualification again and publishes the exact checksummed tarball from that run. Both jobs check tag/version alignment, clean committed sources, unused npm version, and that main still points to the candidate. Publishing has a separate OIDC permission boundary; pull requests, branch pushes, and manual dispatch never publish. Pinned Node 24.13.0 includes npm 11.6.2, which supports OIDC. No package lifecycle scripts run during publication.

If the tag workflow fails, keep the tag immutable, fix the problem, and prepare a new patch version. Do not publish locally to bypass a failed gate.

After success, separately verify `npm view @or3/secrets@<version> version dist.integrity dist.shasum`, compare integrity with the qualification receipt, and run `npx --yes --cache <new-empty-directory> @or3/secrets@<version> --help` with qualified Bun on PATH. Preserve a release receipt containing version, source SHA, workflow URL, npm integrity, and clean-cache CLI result. Update consuming OR3 dependencies only after npm serves the exact version.

npm publication does not complete production runtime/advisory review, backups, host hardening, monitoring, or operator acceptance. Those gates remain in the existing qualification and production control records.
