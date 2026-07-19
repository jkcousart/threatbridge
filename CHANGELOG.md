# Changelog

## Unreleased

- Fixed GitHub-hosted workflow portability by invoking workflow validation through Python and resolving SBOM tools from either the configured virtual environment or the runner PATH.
- Approved Apache-2.0 licensing and contributor guidance for public source distribution.
- Added fully hashed build, runtime, and development dependency locks generated from
  `pyproject.toml`, plus lock consistency and CycloneDX SBOM tooling.
- Pinned the exact Python 3.13.14 slim Docker base to an immutable multi-platform manifest digest
  and changed the image build to use locked dependencies and an isolated wheel builder.
- Added full-SHA-pinned GitHub workflows for tests/security, CodeQL, dependency review, and SBOM
  verification without publishing packages, images, or release artifacts.
- Added supply-chain, provenance, signing, archive-safety, and public-release checklist guidance.
- Made the installed wheel authoritative in the final image, excluded source/test/development
  material, and added runtime import-path validation.
- Separated hermetic committed-lock validation from scheduled/manual public-index freshness checks.
- Added CPython 3.12/3.13/3.14 CI coverage and YAML 1.2-aware workflow-policy regression tests.
- Added checksum-pinned Trivy image scanning, an operating-system-aware CycloneDX image SBOM, and
  explicit high/critical blocking policy without suppressions or risk acceptance; exact-image
  evidence is generated only in an ignored release-evidence directory.
- Enforced exact workflow permissions and runtime/development lock parity for package versions and
  compatible hashes.
- Hardened the supported OpenCTI connector as a least-privilege, read-only MVP boundary and removed
  Microsoft Defender from the registered adapter catalog for this release.
- Replaced staff-based workflow authorization with centralized named permissions across browser,
  REST, services, management origins, and Django admin; removed HTTP Basic Authentication while
  retaining session CSRF protection.
- Forced all imported and reprojected ATT&CK mappings to pending and added permissioned centralized
  approval/rejection with append-only review history.
- Added permissioned assessment execution with actor/origin and active-evidence provenance.
- Added recoverable source-evidence deletion/restoration services, default-hidden deleted records,
  projection/assessment exclusion, and connector non-resurrection behavior.
- Added structured append-only security audit events with bounded recursive redaction.
- Added bounded connector response reads, sanitized operator errors and metadata, non-rendered
  secret references, credential-free configuration validation, safe cursor handling, and hostile-file
  limits.
- Added fail-closed production settings, generic readiness failures, and explicit proxy trust.
- Added public governance and security documentation.
- Upgraded the development test dependency to a non-vulnerable pytest 9 release.
- Replaced the static Django development key with a persistent, ignored, restrictively stored local secret while retaining production fail-closed behavior.
- Prevented Docker builds from generating or retaining the local Django secret during `collectstatic`; builds now use a random command-scoped key and verify that `/app/.secrets` is absent.
- Centralized outbound URL validation with exact host allowlists, explicit private CIDR permissions, prohibited-address checks, URL-userinfo rejection, production HTTPS enforcement, proxy disabling, DNS revalidation, and connection pinning.
- Restricted redirects to the same scheme, normalized hostname, and effective port, including explicit rejection of invalid and zero-valued ports.
- Corrected public documentation to distinguish latest-record storage and normalized projections from immutable or append-only source history, and documented malware scanning and quarantine as production requirements rather than implemented features.

## 0.3.0

- Added the `import_source_file` management command for scheduled CSV, JSON, JSONL, and NDJSON ingestion.
- Improved JSON auto-mapping for camelCase, kebab-case, and nested dotted fields.
- Expanded OpenCTI normalization to retain linked ATT&CK techniques, CVEs, and markings.
- Normalized timezone-less vendor timestamps as UTC for deterministic evidence ordering.
- Added connector configuration examples and production boundary guidance.
- Added verified CSV, JSON, JSON Lines, NDJSON, and mixed-envelope ingestion paths.
- Added automatic discovery for common JSON collection wrappers such as `reports`, `assets`, `devices`, `findings`, and nested `data.results` payloads.
- Added reusable import profiles, schema preview, field-map suggestions, and composite identifiers.
- Added sample JSON and JSON Lines asset inventories.
- Added end-to-end import coverage for wrapped JSON and dotted-path JSON Lines records.

## 0.2.0

- Added the integration adapter contract, source-evidence store, canonical catalog, and explainable assessment engine.
