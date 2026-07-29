# Deployment hardening

ThreatBridge is not production-ready. This document describes required controls and the fail-closed
settings contract. The configuration here is *aligned with* and *informed by* the CIS Docker
Benchmark, OWASP container and Django guidance, and OpenSSF open-source project practices. It is
not a certification, an audit opinion, or a claim of full compliance with any of them.

## Scope boundaries

- **ThreatBridge is not a malware sandbox.** It ingests, normalises, and correlates threat-intel
  and inventory *records*. It does not detonate, emulate, unpack, or analyse samples, and uploaded
  files are never executed. Do not upload live malware. Scan and quarantine uploads before they
  reach an import directory.
- **Docker reduces deployment risk but is not an absolute security boundary.** The Compose profile
  drops capabilities, forbids privilege escalation, and uses a read-only root filesystem, which
  raises the cost of exploiting an application bug. It does not defend against a container escape, a
  host kernel vulnerability, a permissive host Docker daemon, or anyone with access to the Docker
  socket. Treat the container as a defence-in-depth layer, not as an isolation guarantee.
- ThreatBridge does not terminate TLS and has no built-in authentication beyond Django sessions.

## Required production settings

When `DJANGO_DEBUG=false`, startup requires:

- a `DJANGO_SECRET_KEY` or `DJANGO_SECRET_KEY_FILE` of at least 50 characters with at least 16
  distinct characters and no placeholder marker (`changeme`, `example`, `insecure`,
  `django-insecure`, `placeholder`, `replace`, and similar are rejected);
- exact, non-wildcard `DJANGO_ALLOWED_HOSTS`;
- explicit HTTPS `DJANGO_CSRF_TRUSTED_ORIGINS`;
- an explicit PostgreSQL `DATABASE_URL` or `DATABASE_URL_FILE`;
- an exact `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS` policy; and
- an explicit non-negative `DJANGO_SECURE_HSTS_SECONDS`.

`DJANGO_DEBUG` itself has a development-friendly default of true, so the WSGI and ASGI entry points
refuse to start unless it is set explicitly to `true` or `false`. A production server can therefore
never inherit the permissive default and silently skip every check above.

Secure session/CSRF cookies, HTTPS redirect, MIME-sniffing protection, frame denial, a same-origin
cross-origin-opener policy, and a strict-origin referrer policy are enabled in production. Forwarded
host and port headers are never trusted (`USE_X_FORWARDED_HOST` and `USE_X_FORWARDED_PORT` are
false). Forwarded-protocol headers are ignored unless `DJANGO_TRUST_X_FORWARDED_PROTO=true` — set in
Compose through `THREATBRIDGE_TRUST_X_FORWARDED_PROTO`, which defaults to false. Enable it only
behind a proxy that overwrites `X-Forwarded-Proto` and only when clients cannot reach the published
container port directly; `manage.py check --deploy` reports `threatbridge.W002` while it is on.

Request and API limits applied in production:

| Control | Setting | Default |
| --- | --- | --- |
| Request body Django will buffer | `DATA_UPLOAD_MAX_MEMORY_SIZE` | `THREATBRIDGE_MAX_UPLOAD_BYTES` + 1 MiB |
| Form fields per request | `THREATBRIDGE_MAX_REQUEST_FIELDS` | 200 |
| Files per request | `THREATBRIDGE_MAX_REQUEST_FILES` | 10 |
| Anonymous API rate | `THREATBRIDGE_ANON_THROTTLE_RATE` | 30/minute |
| Authenticated API rate | `THREATBRIDGE_USER_THROTTLE_RATE` | 600/minute |
| Outbound connect timeout | `THREATBRIDGE_OUTBOUND_CONNECT_TIMEOUT` | 10 seconds |

All application logging passes through `threatbridge.log_redaction.SensitiveDataFilter`, which
removes `Authorization`, `Cookie`, `Set-Cookie`, and API-key header values, `Bearer`/`Basic`/`Token`
credentials, URL userinfo, and sensitive query parameters such as `token`, `secret`, `password`, and
`signature`. The filter is attached to the handler, so Gunicorn access and error lines are covered
as well. `manage.py check --deploy` fails with `threatbridge.E003` if any handler is configured
without it and `threatbridge.E004` if API throttle rates are missing.

Fail-closed setting errors occur before the database-backed audit service can initialize. They emit
a structured `production_configuration.failed` event to the `threatbridge.security` process logger
without configuration values. Production log collection must retain and alert on these startup
events.

Start HSTS at a short reviewed duration, verify every HTTPS route and subdomain, increase toward one
year, and only then consider subdomain inclusion or preload. The deployment check warns below one
year (`threatbridge.W001`). Preload cannot be turned on prematurely: startup rejects
`DJANGO_SECURE_HSTS_PRELOAD=true` unless `DJANGO_SECURE_HSTS_SECONDS` is at least 31536000 and
`DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=true`, and it rejects subdomain inclusion while the duration
is still zero.

Synthetic deployment-check example:

```bash
DJANGO_DEBUG=false \
DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
DJANGO_ALLOWED_HOSTS=threatbridge.example.invalid \
DJANGO_CSRF_TRUSTED_ORIGINS=https://threatbridge.example.invalid \
DJANGO_SECURE_HSTS_SECONDS=31536000 \
DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=true \
DATABASE_URL=postgresql://threatbridge@database.example.invalid/threatbridge \
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid \
python manage.py check --deploy --fail-level ERROR
```

The generated key is command-scoped and not printed. The database URL is synthetic and contains no
password; the check does not connect to it.


## Production Compose profile

`compose.production.yml` is the supported deployment starting point. The local `compose.yml` is
not a production profile; it runs with `DJANGO_DEBUG=true` and a well-known database password, and it
publishes only on `127.0.0.1:8000`. The production profile:

- builds from separately configurable builder and runtime image digests;
- resolves publicly pullable base images by default (`python:3.13.14-alpine3.24`, the validated
  candidate that recorded zero HIGH or CRITICAL Trivy findings), with hardened, mirrored, or private
  registries available through `THREATBRIDGE_BUILDER_TAG` and `THREATBRIDGE_RUNTIME_TAG`;
- runs as numeric UID/GID `65532:65532`;
- installs and executes the reviewed wheel from a runtime-only virtual environment under
  `/opt/runtime-venv`, without build tooling or `pip`;
- loads the Django key and database URL from Docker secret files;
- runs `manage.py check --deploy --fail-level ERROR` in a `deploy-check` service, then migrations in
  a one-shot `migrate` service, before starting Gunicorn;
- gives PostgreSQL no published port and places it on an internal network;
- runs the `deploy-check` gate with `network_mode: none`, because it reads configuration only.
  Omitting the `networks` key is not sufficient: Compose would attach the service to the implicit
  default bridge and give the gate outbound access it never uses;
- drops all Linux capabilities from application services, enables `no-new-privileges`, and uses a
  read-only root filesystem whose only writable paths are a bounded `noexec,nosuid,nodev` `/tmp`
  tmpfs and the named `threatbridge-data` volume at `/app/data`;
- sets `init: true` and CPU/memory limits on every service, and declares each PID ceiling as both
  `pids_limit` and `deploy.resources.limits.pids` from a single YAML anchor. Both keys are required:
  Compose rejects the project outright when `pids_limit` sits beside `deploy.resources.limits`
  without a matching `pids` entry, and Compose releases that ignore `deploy` outside Swarm would
  otherwise drop the limit silently;
- caps container log size and rotation with the `json-file` driver;
- shares no host namespace, mounts no Docker socket, no host root, and no `/proc`, `/sys`, or
  `/dev` path, and adds no device, sysctl, or `extra_hosts` entry; and
- publishes the application only on an explicitly configured host address and port, with no
  Compose default, so `0.0.0.0` is never reached by accident.

Runtime writable paths are exactly `/tmp` (ephemeral tmpfs, 64 MiB, non-executable) and `/app/data`
(named volume, mode `0750`, owned by `65532`). `PYTHONDONTWRITEBYTECODE=1` is set in the image so
Python never attempts to write `__pycache__` under the read-only root.

Generate local secret material with `scripts/prepare_production_deployment.py`, then resolve the
discovery tags to immutable manifest digests with `scripts/resolve_production_images.sh`. A
`docker login` is needed only if you override the tags to a private registry. The resolver
deliberately updates only the three image references. It does not deploy, publish, suppress
findings, or accept risk.

The application accepts `DJANGO_SECRET_KEY_FILE` and `DATABASE_URL_FILE` only as absolute, regular,
non-symlink files that are not group- or world-writable, and it reads each one at startup so an
unreadable file fails closed instead of surfacing later as an unexplained failure. Direct and
file-backed forms are mutually exclusive. Connector tokens continue to use each integration's
existing `secret_reference` contract. See [`../deploy/README.md`](../deploy/README.md) for the full
list of supported secret injection methods.

### Secret file modes and the Compose bind-mount

Outside Swarm, Compose bind-mounts a file-backed secret with the host file's ownership and mode and
ignores the `uid`, `gid`, and `mode` options, warning `config uid, gid and mode are not supported,
they will be ignored`. The container runs as UID 65532 and cannot be granted ownership of an
operator-owned file without root, so an owner-only secret mounts unreadable and startup aborts.

`scripts/prepare_production_deployment.py` therefore writes secrets mode `0444` inside a `0700`
directory. The directory is the boundary that matters: no unprivileged host user can traverse into
it, so the permissive file mode is unreachable, and a read-only file also prevents the container from
rewriting its own credentials. Keep the secrets directory `0700`; the script verifies this on every
run. If you inject secrets by another mechanism, the same requirement applies — the file must be
readable by UID 65532 and its directory must not be world-traversable.

### Health checks and the HTTPS redirect

`SECURE_SSL_REDIRECT` is enabled in production, with `SECURE_REDIRECT_EXEMPT` limited to `^healthz$`
and `^readyz$`. The container health check probes `http://127.0.0.1:8000/readyz` over loopback and
cannot follow a redirect to the public hostname, so without those two exemptions the container
answers `301` to its own probe and never reports healthy. Both endpoints return a fixed status
string and no configuration detail, and every path that carries data still redirects.

The probe sends the first entry of `DJANGO_ALLOWED_HOSTS` as its `Host` header. `ALLOWED_HOSTS`
remains authoritative and is never widened to accept loopback, so an unrecognised `Host` is still
answered with `400`. Both Compose profiles omit `test` from their `healthcheck` blocks and override
only the timings, which keeps the probe defined once in the `Dockerfile`.

An optional `compose.production.step-ca.yml` overlay mounts one reviewed internal CA certificate
read-only at `/run/configs/threatbridge_extra_ca` for the `deploy-check`, `migrate`, and `web`
services and sets `THREATBRIDGE_EXTRA_CA_FILE`. The outbound client starts from Python's default TLS
context and adds that certificate with `load_verify_locations`; it does not disable hostname
verification, replace public trust, or grant access to a host certificate directory.

The certificate must be mode `0444` on the host for the same reason as the secret files: Compose
ignores the overlay's `uid`, `gid`, and `mode` options and mounts the host file as-is. A CA
certificate is public material, so a readable mode costs nothing.
`scripts/prepare_production_deployment.py` refuses an unreadable certificate, and the `deploy-check`
gate fails closed if one reaches the container, rather than starting with the private CA silently
missing from the trust store.

### PostgreSQL container residual risk

The official PostgreSQL entrypoint starts as root and drops to the `postgres` user, so its container
cannot use the same confinement as the application services. It runs with all capabilities dropped
except `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, and `SETUID`, with `no-new-privileges` enabled, a
`pids_limit`, resource limits, no published port, and an internal-only network. Its root filesystem
is writable because the entrypoint requires it. Operators who need stricter confinement should run
PostgreSQL as a managed service outside Docker, which is the recommended production topology.

## Repository responsibilities versus host administrator responsibilities

| Enforced by this repository | Must be enforced by the Docker host administrator |
| --- | --- |
| Fail-closed production settings validation and `deploy-check` gate | Keeping the Docker engine and host kernel patched |
| Non-root numeric UID, dropped capabilities, `no-new-privileges`, read-only root | Restricting Docker socket and `docker` group membership |
| No published database port; internal Compose network | Host firewall rules around the published application port |
| Loopback-oriented bind defaults and an explicitly required bind address | TLS certificates, renewal, and reverse-proxy configuration |
| File-backed secret contract with permission validation | Secret storage, distribution, and rotation |
| Outbound host and CIDR allowlisting, SSRF policy, TLS verification | Egress firewall policy and DNS integrity |
| Log redaction filter on every handler | Log shipping, retention, access control, and alerting |
| Backup and restore scripts with confirmation tokens | Backup encryption, off-host copies, retention, restore testing |
| Container CPU, memory, and PID limits | Host capacity, disk monitoring, and volume durability |
| Dependency locks, SBOM, image validation, scanners | Acting on scanner findings and scheduling upgrades |
| No malware execution path | Scanning and quarantining uploads before import |

## Residual risks

These are known and accepted for the current candidate rather than fixed:

1. Authorization is role-based and global, not per-object ownership. Any user holding a named
   permission can act on every object of that type. Denied users receive `403` for both existing and
   missing identifiers, so object existence is not disclosed.
2. Imports are not one atomic transaction end to end. A strict import that fails midway can leave
   accepted records persisted alongside a failed run record; the audit trail shows this.
3. Imported records are validated against shape, size, depth, and count limits and per-type field
   heuristics, not a formal JSON Schema.
4. The PostgreSQL container retains the five capabilities listed above.
5. The prebuilt container image is not published. Source publication and prebuilt-image publication
   are separate release decisions. The default Alpine 3.24 base recorded zero HIGH or CRITICAL
   findings when it was validated, but base-image operating-system packages acquire advisories over
   time, so that is point-in-time evidence rather than a durable property; see
   [`container-image-security.md`](container-image-security.md) for the finding policy and the
   rescanning requirement.
6. No release signing or provenance attestation exists yet; see [`supply-chain.md`](supply-chain.md).
7. Docker is a defence-in-depth layer, not an isolation boundary, as stated above.

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

### Database durability

Production must use PostgreSQL. When `DJANGO_DEBUG=false`, a non-PostgreSQL `DATABASE_URL` is
rejected at startup and `manage.py check --deploy` also reports `threatbridge.E001`. SQLite is a
development convenience only: it is not suitable for multi-user or concurrent production use, and
ThreatBridge does not represent it as such anywhere.

The bundled `db` service is a convenience for evaluation. It stores data in a Docker named volume
with no replication, no point-in-time recovery, no connection pooling, and no automated backup
schedule. Durability is therefore limited to whatever the host provides for that volume plus the
manual backups described in [`../deploy/README.md`](../deploy/README.md). For any deployment holding
data you cannot lose, point `DATABASE_URL` at a managed or separately administered PostgreSQL
service with its own backup, retention, monitoring, and upgrade policy.

Upgrade and rollback expectations, including the fact that Django migrations are not automatically
reversible, are documented in [`../deploy/README.md`](../deploy/README.md).

Hashed build/runtime/development locks, CycloneDX SBOM generation, immutable base-image digest
pinning, and full-SHA-pinned CI actions are part of the release candidate. They reduce dependency
drift but do not make builds bit-for-bit reproducible across runner images or platforms. Release
signing, provenance attestations, runner-image pinning, and independent verification of all build
inputs remain publication work; see [`supply-chain.md`](supply-chain.md).
