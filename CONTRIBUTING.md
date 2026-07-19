# Contributing

ThreatBridge accepts public contributions through GitHub pull requests. Before
submitting, review this guide, `SECURITY.md`, and `CODE_OF_CONDUCT.md`. Report
vulnerabilities only through GitHub Private Vulnerability Reporting.

## Development setup

Use a supported CPython 3.12, 3.13, or 3.14 interpreter and an isolated virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/build.txt
python -m pip install --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation -e .
python manage.py migrate
pytest -q
```

`pyproject.toml` is the human-maintained dependency source. Do not hand-edit generated lock files;
follow [`docs/dependency-locking.md`](docs/dependency-locking.md) and include regenerated locks in
the same review as any dependency-range change.

Required CI validates committed locks statically and does not re-resolve them. Dependency updates
belong in the explicit lock-update workflow; do not edit generated locks or add URLs, VCS sources,
index directives, or trusted hosts.

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

Third-party workflow actions must use independently verified full commit SHAs with an adjacent
release-tag comment. Do not add an external service without explicit maintainer approval.

## Contribution licensing

Contributions are submitted for inclusion under the Apache License, Version
2.0. Contributors must have the right to submit their work and must preserve
applicable notices. The project owner approved the repository licensing,
contribution terms, and notices for public source contributions.
