# Publishing @or3/secrets

The initial candidate is **0.1.0**. Preparing it does not publish it. Production acceptance remains separate from disposable qualification.

## License

The package is licensed under MIT. Keep the root LICENSE and `package.json` license metadata aligned. npm includes the root LICENSE automatically.

## npm account setup

An npm owner with publish permission for the `@or3` scope must configure trusted publishing for `@or3/secrets`: GitHub owner **Saluana**, repository **or3-secrets**, workflow filename **qualify.yml**, no environment name, direct publishing allowed. Require 2FA for maintainer accounts. Do not add npm write tokens to repository secrets. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).

## Manual publishing

Use a clean checkout on `main` matching remote main, with successful Security qualification for the exact commit. Use Node 24 or newer and Bun 1.3.14 on PATH. No extra worktree is required.

```sh
npm login
npm publish --dry-run
npm publish
```

`prepublishOnly` checks the runtime, clean committed source, remote main, exact-commit CI, and unused npm version. It installs frozen build dependencies with lifecycle scripts disabled, rebuilds and qualifies the package, and runs typechecks, formatting, and all tests. It rechecks source, registry, CI, and package integrity before returning control to npm. A missing/stale `dist` is rebuilt automatically. npm uses the package's public access configuration. Failed checks stop publication; registry/GitHub errors fail closed. No custom npm token or GitHub CLI is required by the hook.

Keep lifecycle scripts enabled: `--ignore-scripts` bypasses the manual gate. Do not add `prepack`, `prepare`, or `postpack` hooks that mutate the qualified payload. Ordinary consumer installs do not run `prepublishOnly`. Receipts under `test-results/` remain internal evidence; users publish from the package root.

For the first publication, use the commands above with an authenticated npm owner/2FA session, then configure trusted publishing on npm's website. The dry run cannot prove npm write permission. Do not push the same version's release tag after publishing manually: it would attempt to republish an immutable version. Use the tag workflow for a later unused version.

## Prepare and qualify

1. Record the source branch and commit. Use a clean checkout, no `.env`, shared `node_modules`, sibling aliases, or generated leftovers. Do not create a worktree unless explicitly requested. Use Node 24.13.0 and Bun 1.3.14. Install with `bun install --frozen-lockfile --ignore-scripts`.
2. Choose an unused version and update `package.json` and current installation examples. Confirm both the exact npm version and `v<version>` Git tag are absent; connectivity/authentication errors do not prove absence. Never reuse a version or move a release tag.
3. Run `bun --no-env-file run build`, `bun --no-env-file run typecheck`, `bun --no-env-file run format:check`, `bun --no-env-file test --timeout 30000 tests`, and `bun --no-env-file run qualify`. Run the operator and provider qualification against the immutable host from `host-compatibility.json`. Inspect the final diff and `test-results/package-receipt.json`, SBOM, and tarball contents. The package whitelist excludes source, planning, test state, and credentials.
4. Commit the candidate, then repeat package qualification from the clean commit so its receipt records that exact SHA. Merge/push reviewed source to main and verify its remote SHA. The ordinary main workflow must pass its full Linux custody, recovery, capacity, dependency, and source secret scan gates. Do not waive deterministic failures.

## Automated publishing after operator authorization

Push only `v<version>` pointing to the verified remote main commit. The tag runs the full qualification again and publishes the exact checksummed tarball from that run. Both jobs check tag/version alignment, clean committed sources, unused npm version, and that main still points to the candidate. Publishing has a separate OIDC permission boundary; pull requests, branch pushes, and manual dispatch never publish. Pinned Node 24.13.0 includes npm 11.6.2, which supports OIDC. No package lifecycle scripts run during publication.

If the tag workflow fails, keep the tag immutable, fix the problem, and prepare a new patch version. Do not use manual publishing to bypass a failed gate.

After success, separately verify `npm view @or3/secrets@<version> version dist.integrity dist.shasum`, compare integrity with the qualification receipt, and run `npx --yes --cache <new-empty-directory> @or3/secrets@<version> --help` with qualified Bun on PATH. Preserve a release receipt containing version, source SHA, workflow URL, npm integrity, and clean-cache CLI result. Update consuming OR3 dependencies only after npm serves the exact version.

npm publication does not complete production runtime/advisory review, backups, host hardening, monitoring, or operator acceptance. Those gates remain in the existing qualification and production control records.
