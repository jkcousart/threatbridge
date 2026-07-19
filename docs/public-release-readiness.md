# Public release readiness

The source candidate completed technical and owner review and is authorized for
public source publication. Prebuilt container publication remains blocked by
the unresolved High and Critical findings documented in
`release-validation.md`.

## Release preparation present

- Canonical Apache-2.0 text, notice, package metadata, and contribution references are prepared,
  approved by the project owner.
- Hashed build, runtime, and development locks are generated from `pyproject.toml`.
- The exact Python 3.13.14 slim Docker base is pinned to an immutable manifest digest.
- GitHub test/security, CodeQL, dependency-review, and SBOM workflows use verified full action
  SHAs, minimal permissions, explicit timeouts, and concurrency controls.
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
- Fail-closed production settings and generic readiness failures.
- SSRF, DNS-pinning, same-origin redirect, TLS-hostname, private-CIDR, and proxy controls.

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
