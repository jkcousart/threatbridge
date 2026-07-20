# Deployment hardening

ThreatBridge is not production-ready. This document describes required controls and the fail-closed
settings contract; it is not a deployment certification.

## Required production settings

When `DJANGO_DEBUG=false`, startup requires:

- an explicit `DJANGO_SECRET_KEY` or `DJANGO_SECRET_KEY_FILE`;
- exact, non-wildcard `DJANGO_ALLOWED_HOSTS`;
- explicit HTTPS `DJANGO_CSRF_TRUSTED_ORIGINS`;
- an explicit PostgreSQL `DATABASE_URL` or `DATABASE_URL_FILE`;
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


## Production Compose profile

`compose.production.yml` is the supported deployment starting point. The local `compose.yml` is
not a production profile. The production profile:

- builds from separately configurable builder and runtime image digests;
- supports the shell-free Docker Hardened Images Python runtime;
- runs as numeric UID/GID `65532:65532`;
- installs and executes the reviewed wheel from a runtime-only virtual environment under
  `/opt/runtime-venv`, without build tooling or `pip`;
- loads the Django key and database URL from Docker secret files;
- runs migrations in a one-shot service before starting Gunicorn;
- gives PostgreSQL no published port and places it on an internal network;
- drops all Linux capabilities from application services, enables `no-new-privileges`, and uses a
  read-only root filesystem with a bounded `/tmp` tmpfs; and
- publishes the application only on an explicitly configured host address and port.

Generate local secret material with `scripts/prepare_production_deployment.py`, authenticate to
`dhi.io`, and resolve the discovery tags to immutable manifest digests with
`scripts/resolve_production_images.sh`. The resolver deliberately updates only the three image
references. It does not deploy, publish, suppress findings, or accept risk.

The application accepts `DJANGO_SECRET_KEY_FILE` and `DATABASE_URL_FILE` only as absolute, regular,
non-symlink files that are not group- or world-writable. Direct and file-backed forms are mutually
exclusive. Connector tokens continue to use each integration's existing `secret_reference`
contract.

An optional `compose.production.step-ca.yml` overlay mounts one reviewed internal CA certificate and
sets `THREATBRIDGE_EXTRA_CA_FILE`. The outbound client starts from Python's default TLS context and
adds that certificate with `load_verify_locations`; it does not disable hostname verification or
replace public trust.

## OpenCTI MVP boundary

The supported live connector boundary is a read-only outbound OpenCTI connection. Configure an
exact HTTPS base URL and outbound-host allowlist entry; privately hosted OpenCTI also requires an
explicit private CIDR covering every DNS answer. Keep TLS verification enabled and do not configure
a proxy. ThreatBridge revalidates DNS at connection time, pins the connection to a validated
address, preserves TLS verification against the original hostname, and rejects cross-origin
redirects.

Use a dedicated non-administrator OpenCTI user with only the minimum report, marking, ATT&CK, and
vulnerability read permissions needed by the reviewed GraphQL query. Supply its API token through
an environment reference or a non-symlink absolute secret file readable only by the ThreatBridge
account. Never place it in the integration JSON, database, URL, logs, audit metadata, or command
line. Keep the configured timeout, page size, maximum pages per sync, and maximum response bytes
bounded. Rotation and revocation steps are documented in
[`integration-setup.md`](integration-setup.md).

Microsoft Defender is outside this MVP. Its production incidents, devices, users, tenant telemetry,
Entra credentials, and potential response actions require a separate trust-boundary review; no
Defender adapter is registered or supported here.

## Operational requirements

Use a managed secret provider, TLS-terminating reverse proxy, supported PostgreSQL service,
encrypted backups with restore tests, centralized logs, restricted data-volume permissions,
malware scanning/quarantine, and retention procedures before production use. The current
management-command scheduler does not require an asynchronous worker; add one only after a separate
trust-boundary and authorization review. Health responses disclose no debug details; readiness
failures are generic.

Hashed build/runtime/development locks, CycloneDX SBOM generation, immutable base-image digest
pinning, and full-SHA-pinned CI actions are part of the release candidate. They reduce dependency
drift but do not make builds bit-for-bit reproducible across runner images or platforms. Release
signing, provenance attestations, runner-image pinning, and independent verification of all build
inputs remain publication work; see [`supply-chain.md`](supply-chain.md).
