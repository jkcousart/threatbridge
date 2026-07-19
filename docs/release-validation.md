# ThreatBridge Phase 1 validation

Validated on 2026-07-18 (America/Edmonton) with Python 3.14.4 on the host and
Python 3.13.14 in the tested container. Both environments use Django 6.0.7 and
Django REST Framework 3.17.1. The supported dependency range remains
`Django>=5.2,<7`.

Host validation tooling used pytest 9.1.1, Ruff 0.15.22, Bandit 1.9.4, and
pip-audit 2.10.1.

## Automated checks

- `.venv/bin/ruff check .` — passed
- `.venv/bin/python manage.py check` — no issues
- `.venv/bin/python manage.py check --deploy` — development defaults produced the expected five
  warnings for HSTS, HTTPS redirect, secure cookies, and `DEBUG`; this is not the production check
- `.venv/bin/python manage.py makemigrations --check --dry-run` — no changes detected
- `.venv/bin/pytest -q` — 89 tests and 63 subtests passed
- `.venv/bin/python -m pip check` — no broken requirements
- `.venv/bin/python -m pip_audit` — no known vulnerabilities; the local unpublished
  `threatbridge` package was skipped because it is not on PyPI
- `.venv/bin/python -m bandit -r catalog integrations threatbridge -x '*/tests/*,*/migrations/*'` — no issues and no suppressions
- `$HOME/go/bin/gitleaks dir . --redact --verbose --max-archive-depth=2` — no leaks
- `git diff --check` — passed

With the documented synthetic production variables, `manage.py check --deploy` exited successfully
with only Django `security.W005` and `security.W021`. Those warnings are intentional until an
operator verifies that every subdomain is HTTPS-only and deliberately enables HSTS subdomains and
preload. ThreatBridge's production checks reported no errors.

The tests cover the browser/REST authorization matrix, CSRF, centralized ATT&CK review, assessment
and evidence provenance, deletion/restoration, append-only/redacted events, integration secret and
cursor handling, synchronization, adapters, bounded CSV/JSON/JSONL/NDJSON ingestion, management
origins, persistent development-secret behavior, validation-outcome aliases, and outbound URL
controls.
Outbound coverage includes exact host and private-CIDR policy, prohibited destinations,
mixed DNS answers, DNS revalidation and connection pinning, TLS SNI, URL userinfo, schemes,
redirect origins, and malformed, zero, default, and non-default ports.

## Docker build-secret review

The Dockerfile runs `collectstatic` with `DJANGO_DEBUG=false` and a cryptographically random,
command-scoped `DJANGO_SECRET_KEY`. The value is neither a build argument nor a persistent image
environment variable. After package installation and static collection, the build removes
`/app/build`, top-level `/app/*.egg-info`, and `/app/data/incoming` while retaining
`/app/staticfiles`.

Only `/app/data` remains as the runtime data mount point. It is owned by
`threatbridge:threatbridge` with mode `0750`; application code remains root-owned, other directories
are normalized to `0755`, ordinary files to `0644`, and `/app/manage.py` to `0755`. Defensive build
assertions require that
`/app/.secrets`, `/app/build`, `/app/data/incoming`, top-level `/app/*.egg-info`, and all
world-writable files or directories are absent before the image switches to the existing non-root
runtime user. `.dockerignore` excludes local secret and runtime material from the build context.

The Phase 1 image was built locally and uses Python 3.13.14, Django 6.0.7, and Django REST Framework
3.17.1. Runtime identity is `threatbridge` (UID 100). The final filesystem check confirmed that
static files remain, the private Phase 1 report is absent, and no `.env`, `.secrets`, private report,
build directory, egg-info path, incoming upload directory, or world-writable application path is
present. Image configuration and history contain only the literal random-key generation command,
not its generated value or a persistent secret environment variable.

All migrations, including both Phase 1 migrations, applied successfully against a disposable
SQLite database inside a short-lived container. The synthetic production deployment check also ran
inside the final image and produced only the two staged-HSTS warnings described above. No live
database or integration was contacted.

## Supply-chain work remaining

The project does not yet use a fully locked dependency set, and the `python:3.13-slim` base image
is not pinned to an immutable digest. Dependency locking and immutable base-image pinning remain
release and supply-chain work; the current build should not be described as reproducible.

## Boundaries not exercised

No external connector, live database, deployment tenant, development server, or external security
product was exercised. Live connector validation still requires deployment-specific endpoints,
credentials, permissions, certificates, and approved outbound policy.
