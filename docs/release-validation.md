# ThreatBridge release-candidate validation

> **Status: point-in-time evidence, superseded in part.** This document records the 0.3.0
> release-candidate validation run performed on 2026-07-19, before the public-release hardening
> audit. It is retained as historical evidence and is deliberately not rewritten. Two classes of
> statement here no longer describe the current tree:
>
> - **Runtime user and interpreter paths.** The runtime image now runs as numeric UID/GID
>   `65532:65532` with no named account, and the application resolves from a runtime-only virtual
>   environment under `/opt/runtime-venv`, not `/usr/local/lib/python3.13/site-packages`. The
>   observations below are superseded; `scripts/validate_container_image.sh` asserts the current
>   contract.
> - **Scan counts and image identity.** The image ID, SBOM digests, report digests, and
>   critical/high counts below belong to that build and that scanner database. They are not evidence
>   about any later build. Prebuilt-image publication remains blocked under the policy in
>   [`container-image-security.md`](container-image-security.md) until a fresh unsuppressed scan of a
>   fresh image ID is reviewed.
>
> Controls added after this run — weak-secret rejection, the explicit `DJANGO_DEBUG` requirement at
> the WSGI/ASGI entry points, log redaction, API throttling, request and upload limits, the
> `deploy-check` gate, per-service resource and PID limits, the expanded SSRF denylist, and separate
> connect and read timeouts — are validated in
> [`security/public-release-hardening-audit.md`](security/public-release-hardening-audit.md), not here.

Validated locally on 2026-07-19 (America/Edmonton) with Python 3.14.4 on the host and Python
3.13.14 in the container. Both environments resolved Django 6.0.7 and Django REST Framework
3.17.1. The supported source range remains `Django>=5.2,<7`.

Host validation tooling resolved from the development lock: pytest 9.1.1, Ruff 0.15.22, Bandit
1.9.4, pip-audit 2.10.1, pip-tools 7.6.0, and cyclonedx-bom 7.3.0.

## Dependency and packaging checks

- `scripts/validate_dependency_locks.py` — statically confirmed exact pins, SHA-256 hashes,
  generated-file metadata, direct-dependency coverage, and the absence of URL, VCS, alternate
  index, trusted-host, and include directives. It also confirmed that all runtime packages and
  versions are identical in the development lock and that the development lock retains every
  runtime artifact hash. The committed locks contain 3 build, 11 runtime, and 73 development
  packages.
- `./scripts/check_dependency_locks.sh` — the separate, network-enabled freshness check re-resolved
  build, runtime, and development locks against the public Python Package Index and found no
  drift. Required push and pull-request CI does not run this command or resolve dependencies.
- A new empty Python 3.14 virtual environment installed the build and development locks with
  `--require-hashes`, then installed the built ThreatBridge wheel with dependency resolution
  disabled. The wheel contains no project test packages.
- The preceding candidate's compatibility run established hashed-lock installation, Django
  checks, migration drift, 128 tests and 63 subtests, and `pip check` on Python 3.12.13, 3.13.14,
  and 3.14.4. That matrix was not repeated because this scoped pass did not change dependency
  versions, lock contents, packaging metadata, or the supported-version policy. Required CI still
  executes the complete current suite on all three versions.
- `.venv/bin/python -m pip check` — no broken requirements.
- `.venv/bin/python -m pip_audit --require-hashes --disable-pip -r requirements/runtime.txt` — no
  known vulnerabilities; dependency resolution and pip invocation were disabled.
- `.venv/bin/python -m pip_audit --require-hashes --disable-pip -r requirements/development.txt` — no
  known vulnerabilities; dependency resolution and pip invocation were disabled.
- `./scripts/generate_sbom.sh` — generated reproducible CycloneDX 1.6 JSON with ThreatBridge as the
  root application, its Apache-2.0 declaration, and 11 resolved runtime components.
- SBOM regeneration compared byte-for-byte with `sbom/threatbridge.cdx.json`.
- `LICENSE` matched the canonical local Apache License 2.0 text byte-for-byte. Package metadata and
  the built image contain `LICENSE` and `NOTICE`.

## Application and security checks

- `.venv/bin/ruff check .` — passed.
- `.venv/bin/python manage.py check` — no issues.
- `.venv/bin/python manage.py makemigrations --check --dry-run` — no changes detected.
- `.venv/bin/pytest -q` — 154 tests and 70 subtests passed.
- `.venv/bin/python -m bandit -r catalog integrations threatbridge -x
  '*/tests/*,*/migrations/*'` — no issues, suppressions, or skipped files.
- The working-tree Gitleaks check scanned every Git-tracked and non-ignored candidate path and found
  no leaks. Ignored exact-image release evidence was separately retained for Trivy review and was
  not treated as source.
- `$HOME/go/bin/gitleaks git . --redact --verbose --max-archive-depth=2 --log-opts=--all` — no
  leaks across all three local commits.
- `scripts/validate_workflows.py` — five workflows and eleven action uses passed YAML 1.2 trigger,
  allowed-trigger, concurrency, timeout, and full-SHA policy validation. Top-level permissions are
  exactly `contents: read`; only CodeQL adds exactly `security-events: write` at job level.
- `git diff --check` — passed.
- `scripts/security_check.sh` — passed, including lock, SBOM, application, dependency, scanner,
  workflow-policy, and diff checks.

The development-default `manage.py check --deploy` completed with the expected five warnings for
HSTS, HTTPS redirect, secure cookies, and `DEBUG`. With the documented synthetic production
variables, host and container checks completed with only Django `security.W005` and
`security.W021`; subdomain HSTS and preload remain deliberate operator decisions. ThreatBridge's
fail-closed production checks reported no errors, and neither command connected to the synthetic
database or an integration.

## Source and history safety

Tracked and candidate public file names, ignored-file names, Git attributes, historical path names,
and archive contents were inspected. The candidate source archive was built only from tracked and
non-ignored candidate files. It contains no `.env`, `.secrets`, private security reports, TMKB
material, internal paths, employer references, credentials, databases, caches, uploads, or runtime
data. `.env.example` contains only empty placeholders and reserved synthetic examples. No archive
file was present in Git history.

## Docker validation

The no-cache build uses both the exact readable tag and immutable multi-platform digest
`python:3.13.14-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91`.
The builder installs the hashed build lock and creates the local wheel without dependency
resolution; the final stage installs only the hashed runtime lock and that wheel.

The selected no-cache local image ID was
`sha256:f3b460c347f81e9ea3f05d1043392646d993dda51ed4a1b08ebfaf2a4dd64f31`.
The final image runs as `threatbridge` (UID 100). `/app/data` is owned by
`threatbridge:threatbridge` with mode `0750`; application files are root-owned, ordinary
directories are `0755`, ordinary files are `0644`, and `/app/manage.py` is `0755`. No
world-writable application path is present.

`collectstatic` uses `DJANGO_DEBUG=false` and a cryptographically random, command-scoped
`DJANGO_SECRET_KEY`; neither the value nor a secret environment variable persists. Inspection
found no `.env`, `.secrets`, private security report, TMKB artifact, build directory, egg-info,
incoming runtime directory, database, upload, or other excluded private/runtime material. Static
files plus Apache licensing files remain present. Source directories, tests, development scripts,
GitHub files, locks, and SBOMs are deliberately absent from the runtime image.

Runtime import inspection proved the wheel is authoritative:

```text
threatbridge=/usr/local/lib/python3.13/site-packages/threatbridge/__init__.py
catalog=/usr/local/lib/python3.13/site-packages/catalog/__init__.py
integrations=/usr/local/lib/python3.13/site-packages/integrations/__init__.py
```

All migrations, including both Phase 1 migrations, applied against a disposable SQLite database
inside the image. `pip check` passed, and the synthetic production deployment check produced only
the two staged-HSTS warnings described above. No live database or integration was contacted.

Trivy 0.70.0 generated a valid CycloneDX 1.6 image SBOM for the exact image ID. It contains 101
components: the Debian 13.6 operating system, 87 Debian packages, and 13 Python packages. The SBOM
SHA-256 is `cc71532df4abd35ff72d0253d680de33d13daeb86da083b795df1c1742c909fb`.
The SBOM is generated under ignored `release-evidence/` for this image ID and is not part of the
source candidate.

The unsuppressed Trivy scan of that image ID found 3 critical and 19 high package findings. The
report SHA-256 is `120c9933b9a1810fc46570fa6f71ae74f7c97502010668819352e713dc9a9e4b`.
No finding had a published fixed version in the scanner database used for this validation:

| Severity | Vulnerability | Installed package or packages |
| --- | --- | --- |
| Critical | CVE-2026-13221 | `perl-base` 5.40.1-6 |
| Critical | CVE-2026-42496 | `perl-base` 5.40.1-6 |
| Critical | CVE-2026-8376 | `perl-base` 5.40.1-6 |
| High | CVE-2025-69720 | `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` 6.5+20250216-2 |
| High | CVE-2026-41992 | `gzip` 1.13-1 |
| High | CVE-2026-42497 | `perl-base` 5.40.1-6 |
| High | CVE-2026-48962 | `perl-base` 5.40.1-6 |
| High | CVE-2026-53615 | `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` |
| High | CVE-2026-54369 | `libacl1` 2.3.2-2+b1 |
| High | CVE-2026-57432 | `perl-base` 5.40.1-6 |
| High | CVE-2026-9538 | `perl-base` 5.40.1-6 |

These are package-presence results, not exploitability determinations. They block publication of a
prebuilt container image. They do not by themselves block publication of the reviewed source
repository. No suppression or risk acceptance was added.

### Bounded base comparison

The current exact slim base was compared only with the current official immutable
`python:3.13.14-slim-bookworm` digest. The same wheel, hashed runtime lock, runtime user, and
security configuration were used:

| Candidate | Base digest | Final image ID | Size | OS packages | Critical | High |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `python:3.13.14-slim` | `sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91` | `sha256:f3b460c347f81e9ea3f05d1043392646d993dda51ed4a1b08ebfaf2a4dd64f31` | 61,068,537 bytes | 87 | 3 | 19 |
| `python:3.13.14-slim-bookworm` | `sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64` | `sha256:bf801e491c5ba793eafc43f5ba8dc409ee4e2a4a1e5b0f1d7f7bbde41a196c78` | 62,431,249 bytes | 97 | 5 | 18 |

Both images started Gunicorn as `threatbridge`, passed Django checks, applied both Phase 1
migrations to disposable databases, imported all application packages from site-packages, and
passed identical ownership and permissions inspection. Bookworm did not materially reduce the
blocking findings; it increased the critical and total counts and was larger. The reviewed current
slim digest was therefore retained.

## Remaining release boundaries

The locks, base digest, action SHAs, and SBOM make inputs reviewable and repeatable for the tested
Linux/Python environments; they do not guarantee bit-for-bit builds across platforms or mutable
runner images. GitHub workflows, dependency review, and CodeQL have not run on a public host.
Images, archives, SBOMs, attestations, signatures, and releases have not been published or signed.

The project owner approved Apache-2.0 public source distribution, verified
`@jkcousart` as the CODEOWNERS identity, selected GitHub Private Vulnerability
Reporting, and verified the dedicated private conduct-reporting mailbox. These
owner decisions no longer block source publication. Prebuilt container
publication remains blocked by the documented Trivy policy.
