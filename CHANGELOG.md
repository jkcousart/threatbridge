# Changelog

## Unreleased

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
- Added public governance and security documentation; license selection remains a publication
  blocker.
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
