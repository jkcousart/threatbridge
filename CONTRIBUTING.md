# Contributing

ThreatBridge accepts narrowly scoped, reviewable changes. Public contribution intake is not open
until repository ownership, licensing, and private security reporting are finalized.

## Development setup

Use Python 3.12 or newer and an isolated virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python manage.py migrate
pytest -q
```

Do not add credentials, `.env` files, databases, uploaded evidence, private audit reports, internal
hostnames, or customer data. Use `example.invalid` names and documentation address ranges.

## Change expectations

- Add negative tests for authorization and validation changes.
- Keep authorization in `threatbridge.authorization` and workflow services rather than view-local
  staff checks.
- Preserve session-authentication CSRF enforcement.
- Keep connector operations read-only and preserve outbound URL/DNS protections.
- Add migrations for model changes and document compatibility concerns.
- Run `bash scripts/security_check.sh` before requesting review.
- Update public documentation without claiming production readiness or unimplemented controls.

Do not add a license, third-party workflow action, or new external service without explicit
maintainer approval and independent verification of provenance and immutable versions.
