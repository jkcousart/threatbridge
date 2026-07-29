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
- Rejected weak, short, low-entropy, and placeholder production `SECRET_KEY` values, and required an explicit `DJANGO_DEBUG` decision at the WSGI and ASGI entry points so a production process can never inherit the development default.
- Refused to enable HSTS preload or subdomain inclusion before the corresponding rollout is complete.
- Redacted `Authorization` and `Cookie` headers, bearer/basic/token credentials, URL userinfo, and sensitive query parameters on every logging handler, including the Gunicorn access and error logs, and added a deployment check that fails if any handler omits the filter.
- Added Django REST Framework anonymous and authenticated throttling, configurable through `THREATBRIDGE_ANON_THROTTLE_RATE` and `THREATBRIDGE_USER_THROTTLE_RATE`, with a deployment check that requires both rates.
- Aligned Django request limits with the application's import limits, capped form fields and uploaded files per request, restricted stored upload permissions, and stopped trusting forwarded host and port headers.
- Refused cloud-metadata hostnames even when allowlisted, and refused 6to4, Teredo, and NAT64 prefixes that embed an inner IPv4 address behind a globally routable prefix.
- Separated the connector connect timeout from the read timeout through `THREATBRIDGE_OUTBOUND_CONNECT_TIMEOUT`, declared an explicit redirect ceiling, and replaced the default `urllib` user agent with a fixed `ThreatBridge/0.3` identity that discloses no host or interpreter detail.
- Hardened both Compose profiles: the development profile now binds only `127.0.0.1`, runs unprivileged with all capabilities dropped, and rotates logs; the production profile gates startup behind `manage.py check --deploy --fail-level ERROR`, stops trusting `X-Forwarded-Proto` by default, and adds `init`, PID, CPU, and memory limits to every service, with a minimal capability set for PostgreSQL.
- Mounted the optional step-ca trust anchor through explicit long-syntax Compose configuration with a pinned in-container path, owner, and read-only mode, and extended it to the deployment-check and migration services.
- Defaulted the production image resolver to publicly pullable base images so a third party can reproduce the documented deployment without a private registry, keeping hardened bases available as an override.
- Added OpenContainers provenance labels to the runtime image and extended image validation to assert the exposed port, the complete label set, and a hardened second run proving a non-root UID, read-only root filesystem, empty capability set, `NoNewPrivs`, a writable `/tmp`, and no Docker socket.
- Added a container and filesystem scanning workflow, denied network-copyleft and source-available dependency licences in dependency review, and made base-image comparison exit non-zero unless every candidate scan passes.
- Ignored private security work products by default in both `.gitignore` and `.dockerignore`, requiring an explicit exception to publish one.
- Added regression tests for secret strength, HSTS staging, upload limits, throttling, log redaction, entry-point debug enforcement, SSRF metadata and tunnel rejection, timeout separation, authorization denials on every state-changing endpoint, Compose confinement, and workflow failure handling.

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
