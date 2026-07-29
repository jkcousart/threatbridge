# Public release readiness

The source candidate completed technical and owner review and is authorized for
public source publication. Source publication and prebuilt-image publication are
separate release decisions.

Prebuilt container publication is not yet approved. The blocking HIGH and CRITICAL findings recorded
in `release-validation.md` came from the previous Debian base; the default is now the Alpine 3.24
candidate that recorded zero HIGH or CRITICAL findings under the reviewed Trivy 0.70.0 policy.

That default has since been rebuilt with no `--build-arg` override, revalidated, SBOM-generated, and
rescanned as that exact artifact, and the production Compose stack has been exercised end to end
against it — `deploy-check`, migrations, PostgreSQL, and readiness all confirmed, with runtime
confinement read off live containers. That run also uncovered six deployment defects that static
review had not, all since fixed; `security/public-release-hardening-audit.md` records them in full.

Publication of a prebuilt image nonetheless remains blocked, because publishing an image is a durable
claim about vulnerability status while a clean scan is a single point-in-time observation. The base
digests must be re-resolved and rescanned immediately before release, and the rebuild plus
integration test must be repeated against the actual release commit.

## Release preparation present

- Canonical Apache-2.0 text, notice, package metadata, and contribution references are prepared,
  approved by the project owner.
- Hashed build, runtime, and development locks are generated from `pyproject.toml`.
- The exact Python 3.13.14 Alpine 3.24 Docker base is pinned to an immutable manifest digest. It was
  selected on recorded evidence: that candidate built from the committed hash-locked requirements,
  passed complete container validation, and produced zero HIGH or CRITICAL Trivy 0.70.0 findings,
  where the Debian `slim` and `slim-bookworm` candidates built and validated but had 23 and 24
  blocking findings. This is point-in-time evidence, not a durable guarantee. The production Compose
  profile resolves publicly pullable base tags to digests by default, so a third party can reproduce
  the documented deployment without a private registry subscription, and hardened or private
  registries remain available as overrides.
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
- The default base's clean scan is point-in-time. Operating-system packages acquire advisories over
  time, so the image must be rebuilt and rescanned rather than assumed clean, and ThreatBridge is
  neither certified nor claimed to be free of vulnerabilities.
- Alpine uses musl libc. Compatibility was validated for the current locked runtime dependency set;
  adding or upgrading a dependency with compiled artifacts is also a base-compatibility change.

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
