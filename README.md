# or3-secrets

Planning-stage secret service and CLI, with a Node-compatible client and optional OR3 provider. Bun is the proposed core runtime, subject to the documented cryptographic assurance decision. Application implementation has not started.

- [Requirements](planning/secure-secret-store/requirements.md)
- [Design and security boundaries](planning/secure-secret-store/design.md)
- [Dependency-ordered implementation tasks](planning/secure-secret-store/tasks.md)
- [Production security profile and control responsibilities](planning/secure-secret-store/security-profile.md)
- [secretctl, Dopbase, and OR3 source analysis](planning/secure-secret-store/source-analysis.md)

Initial scope: a local Unix-socket API, authenticated encrypted secret values in SQLite, scoped expiring machine tokens, explicit CLI disclosure, durable audit with bounded read-only export, tested fresh-key recovery, and remembered trusted-plugin secrets in OR3. Production requires separate service/key custody and externally supplied human administration, audit retention, and monitoring controls. No production credentials have been moved or created.

The plan targets testable controls that support applicable security assessments when deployed according to the security profile. It does not claim FIPS validation, PCI DSS compliance, a SOC 2 report, or GDPR/HIPAA compliance for the software alone. Qualification and independent review evidence remain pending.
