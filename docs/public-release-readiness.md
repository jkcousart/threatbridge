# Public release readiness

ThreatBridge is not yet ready for publication or production deployment.

## Phase 1 controls present

- Central named-permission policy across browser, REST, services, commands, and admin.
- Session-only API authentication with CSRF on unsafe requests.
- Pending-only ATT&CK imports and append-only review history.
- Permissioned assessment execution with actor/origin and active-evidence provenance.
- Permissioned evidence deletion/restoration and default-hidden deleted records.
- Structured redacted security events.
- Bounded connector responses and hostile-file limits.
- Fail-closed production settings and generic readiness failures.
- SSRF, DNS-pinning, same-origin redirect, TLS-hostname, private-CIDR, and proxy controls.

## Publication blockers

- Select and review a license; this repository intentionally contains no license.
- Replace placeholder CODEOWNERS teams with verified repository identities.
- Configure and test a private vulnerability and conduct reporting channel.
- Independently verify immutable commit SHAs before adding any CI workflow actions.
- Lock dependencies, pin base images by digest, produce an SBOM, and define update ownership.
- Complete legal, privacy, trademark, export, data-retention, and sample-data review.
- Perform an independent security review and clean-environment release rehearsal.

Dependabot configuration describes intended update checks but has not run. No GitHub Actions
workflow is included because immutable third-party action SHAs were not independently verified in
this environment.

## Deferred product work

Multi-tenancy, organization scoping, Entra ID/enterprise SSO, full TLP enforcement, automatic policy
decisions, connector write-back, and automatic remediation remain future phases and must not be
inferred from Phase 1 controls.
