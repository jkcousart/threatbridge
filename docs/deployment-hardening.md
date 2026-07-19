# Deployment hardening

ThreatBridge is not production-ready. This document describes required controls and the fail-closed
settings contract; it is not a deployment certification.

## Required production settings

When `DJANGO_DEBUG=false`, startup requires:

- an explicit `DJANGO_SECRET_KEY`;
- exact, non-wildcard `DJANGO_ALLOWED_HOSTS`;
- explicit HTTPS `DJANGO_CSRF_TRUSTED_ORIGINS`;
- an explicit PostgreSQL `DATABASE_URL`;
- an exact `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS` policy; and
- an explicit non-negative `DJANGO_SECURE_HSTS_SECONDS`.

Secure session/CSRF cookies, HTTPS redirect, MIME-sniffing protection, frame denial, and a
strict-origin referrer policy are enabled in production. Forwarded-protocol headers are ignored
unless `DJANGO_TRUST_X_FORWARDED_PROTO=true` is deliberately set behind a trusted proxy that strips
untrusted inbound forwarding headers.

Fail-closed setting errors occur before the database-backed audit service can initialize. They emit
a structured `production_configuration.failed` event to the `threatbridge.security` process logger
without configuration values. Production log collection must retain and alert on these startup
events.

Start HSTS at a short reviewed duration, verify every HTTPS route and subdomain, increase toward one
year, and only then consider subdomain inclusion or preload. The deployment check warns below one
year; never enable preload before operational verification.

Synthetic deployment-check example:

```bash
DJANGO_DEBUG=false \
DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
DJANGO_ALLOWED_HOSTS=threatbridge.example.invalid \
DJANGO_CSRF_TRUSTED_ORIGINS=https://threatbridge.example.invalid \
DJANGO_SECURE_HSTS_SECONDS=31536000 \
DATABASE_URL=postgresql://threatbridge@database.example.invalid/threatbridge \
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid \
python manage.py check --deploy
```

The generated key is command-scoped and not printed. The database URL is synthetic and contains no
password; the check does not connect to it.

## Operational requirements

Use a managed secret provider, TLS-terminating reverse proxy, supported PostgreSQL service,
encrypted backups with restore tests, centralized logs, restricted data-volume permissions,
malware scanning/quarantine, retention procedures, and monitored asynchronous workers before
production use. Health responses disclose no debug details; readiness failures are generic.

Dependency locking, software-bill-of-materials generation, signed artifacts, immutable base-image
digest pinning, and verified CI action SHAs remain supply-chain work. Current builds are not fully
reproducible.
