# or3-secrets

Planning-stage Bun secret service, CLI, and optional OR3 provider. Git is initialized; application implementation has not started.

- [Requirements](planning/secure-secret-store/requirements.md)
- [Design and security boundaries](planning/secure-secret-store/design.md)
- [Dependency-ordered implementation tasks](planning/secure-secret-store/tasks.md)
- [secretctl, Dopbase, and OR3 source analysis](planning/secure-secret-store/source-analysis.md)

Initial scope: a local Unix-socket API, authenticated encrypted SQLite storage, scoped expiring machine tokens, explicit CLI disclosure, tested recovery, and remembered trusted-plugin secrets in OR3. No production credentials have been moved or created.
