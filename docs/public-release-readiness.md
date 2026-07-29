# Public release readiness

The source candidate completed technical and owner review and is authorized for
public source publication. Prebuilt container publication remains blocked by
the unresolved High and Critical findings documented in
`release-validation.md`.

## Release preparation present

- Canonical Apache-2.0 text, notice, package metadata, and contribution references are prepared,
  approved by the project owner.
- Hashed build, runtime, and development locks are generated from `pyproject.toml`.
- The exact Python 3.13.14 slim Docker base is pinned to an immutable manifest digest. The production
  Compose profile resolves publicly pullable base tags to digests by default, so a third party can
  reproduce the documented deployment without a private registry subscription.
- GitHub test/security, CodeQL, dependency-review, lock-freshness, container-scan, and SBOM workflows
  use verified full action SHAs, minimal permissions, explicit timeouts, and concurrency controls, and
  no workflow consumes a secret or uses `pull_request_target`.
- Dependency review fails a pull request at MODERATE severity for runtime and development scopes and
  denies network-copyleft and source-available licences.
- A reproducible CycloneDX runtime SBOM and supply-chain verification guidance are included.
- The wheel-authoritative image has reproducible local operating-system-aware CycloneDX SBOM
  generation and a pinned, unsuppressed Trivy validation procedure. Digest-bound image evidence is
  retained only in the ignored release-evidence directory.
- A public-release checklist covers history, archive, private-file, legal, scan, and provenance
  review.

## Phase 1 controls present

- Central named-permission policy across browser, REST, services, commands, and admin.
- Session-only API authentication with CSRF on unsafe requests.
- Pending-only ATT&CK imports and append-only review history.
- Permissioned assessment execution with actor/origin and active-evidence provenance.
- Permissioned evidence deletion/restoration and default-hidden deleted records.
- Structured redacted security events.
- Bounded connector responses and hostile-file limits.
- Fail-closed production settings and generic readiness failures, including rejection of weak or
  placeholder secret keys, a required explicit `DJANGO_DEBUG` decision at the WSGI/ASGI entry points,
  and a `deploy-check` gate that runs `manage.py check --deploy --fail-level ERROR` before serving.
- SSRF, DNS-pinning, same-origin redirect, TLS-hostname, private-CIDR, cloud-metadata,
  IPv4-embedding-tunnel, and proxy controls with separate connect and read timeouts.
- Credential redaction on every logging handler, including the Gunicorn access log.
- REST API throttling for anonymous and authenticated callers, and Django request/upload limits
  aligned with the application's own import limits.
- Container confinement aligned with the CIS Docker Benchmark: non-root numeric UID, all capabilities
  dropped, `no-new-privileges`, read-only root filesystem, bounded `noexec` tmpfs, per-service
  CPU/memory/PID limits, log rotation, no host namespace or Docker socket, and no published database
  port.

## Residual risks and limits

- ThreatBridge is not a malware sandbox, and Docker is defence in depth rather than an isolation
  boundary for hostile code.
- Authorization is role-based and global rather than per-object.
- Imports are not one end-to-end atomic transaction.
- The bundled PostgreSQL container retains five capabilities its entrypoint requires and keeps a
  writable root filesystem; a separately administered PostgreSQL service is the recommended topology.
- The bundled database volume has no replication, point-in-time recovery, or automated backup
  schedule.
- No release signing or provenance attestation exists yet.

The full list, with the split between what the repository enforces and what the Docker host
administrator must enforce, is in [`deployment-hardening.md`](deployment-hardening.md). The most
recent audit is [`security/public-release-hardening-audit.md`](security/public-release-hardening-audit.md).

## Source-repository publication blockers

- Complete: the project owner approved Apache-2.0 selection, copyright and notice text, contribution terms, and public source distribution.
- Complete: CODEOWNERS uses the verified public repository owner `@jkcousart`.
- Complete: GitHub Private Vulnerability Reporting was selected for activation at publication, and the owner verified the dedicated private conduct mailbox.
- Independently review this complete preparation change set and run the workflows on the intended
  public host; local validation cannot prove hosted permissions or feature availability.
- Re-resolve package, action, and base-image provenance immediately before release.
- Complete a clean-environment release rehearsal from the intended signed tag.

The current container findings do not block publication of reviewed source. They do block a
prebuilt container artifact, and no risk was accepted or suppressed. Signing and attestations are
future work, not an MVP source-repository requirement.

Dependabot configuration describes intended update checks but has not run. Workflows are prepared
but have not run on GitHub, and no artifact, package, image, signature, or release has been
published.

## Deferred product work

Multi-tenancy, organization scoping, Entra ID/enterprise SSO, full TLP enforcement, automatic policy
decisions, connector write-back, and automatic remediation remain future phases and must not be
inferred from Phase 1 controls.
