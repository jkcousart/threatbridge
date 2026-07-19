# ThreatBridge pre-commit validation

Validated on 2026-07-18 (America/Edmonton) with Python 3.14.4 on the host and
Python 3.13.14 in the tested container. Both environments use Django 6.0.7 and
Django REST Framework 3.17.1. The supported dependency range remains
`Django>=5.2,<7`.

Host validation tooling used pytest 9.1.1, Ruff 0.15.22, Bandit 1.9.4, and
pip-audit 2.10.1.

## Automated checks

- `.venv/bin/ruff check .` — passed
- `.venv/bin/python manage.py check` — no issues
- `.venv/bin/python manage.py makemigrations --check --dry-run` — no changes detected
- `.venv/bin/pytest -q` — 50 tests and 26 subtests passed
- `.venv/bin/python -m pip check` — no broken requirements
- `.venv/bin/python -m pip_audit` — invoked but could not complete because external access was prohibited and the network-restricted process could not resolve PyPI
- `.venv/bin/python -m bandit -r catalog integrations threatbridge -x '*/tests/*,*/migrations/*'` — no issues and no suppressions
- `$HOME/go/bin/gitleaks dir . --redact --verbose --max-archive-depth=2` — no leaks
- `git diff --check` — passed

The tests cover integration synchronization, adapters, CSV/JSON/JSONL/NDJSON ingestion,
normalization and projection, authenticated ingestion endpoints, management commands,
persistent development-secret behavior, validation-outcome aliases, and outbound URL controls.
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
`threatbridge:threatbridge` with mode `0750`; other directories are normalized to `0755`, ordinary
files to `0644`, and `/app/manage.py` to `0755`. Defensive build assertions require that
`/app/.secrets`, `/app/build`, `/app/data/incoming`, top-level `/app/*.egg-info`, and all
world-writable files or directories are absent before the image switches to the existing non-root
runtime user. `.dockerignore` excludes local secret and runtime material from the build context.

The previously tested container uses Python 3.13.14, Django 6.0.7, and Django REST Framework
3.17.1. The image was not rebuilt after this final source-only cleanup, as requested.

## Supply-chain work remaining

The project does not yet use a fully locked dependency set, and the `python:3.13-slim` base image
is not pinned to an immutable digest. Dependency locking and immutable base-image pinning remain
release and supply-chain work; the current build should not be described as reproducible.

## Boundaries not exercised

No external connector, live tenant, development server, fresh database migration, or Docker image
build was exercised in this pass. Defender and OpenCTI still require organization-specific
endpoints, credentials, permissions, certificates, and approved outbound policy before a live
validation can be performed.
