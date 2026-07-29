# Production Docker deployment

This deployment profile is separate from `compose.yml`, which remains a local-development stack.
It uses a non-root application image (numeric UID/GID `65532:65532`), a deployment-check gate, a
one-shot migration service, PostgreSQL on an internal-only network, file-backed secrets, a
read-only application root filesystem, and a host port that binds to loopback by default.

Docker reduces deployment risk. It is not an absolute security boundary: a container escape,
a kernel vulnerability, a permissive host Docker configuration, or an administrator with Docker
socket access all bypass everything described here. See
[`../docs/deployment-hardening.md`](../docs/deployment-hardening.md) for the split between what this
repository enforces and what the Docker host administrator must enforce.

## Default network exposure

| Component | Default published address | Notes |
| --- | --- | --- |
| `web` (production) | `${THREATBRIDGE_BIND_ADDRESS}:${THREATBRIDGE_PORT}` → container `8000` | The example file sets `127.0.0.1:8020`. The variable has no default in Compose, so a value must be chosen deliberately. |
| `db` (production) | not published | Reachable only on the internal `database` Compose network. |
| `deploy-check`, `migrate` | not published | One-shot services with no network exposure beyond the database network. |
| `web` (local `compose.yml`) | `127.0.0.1:8000` | Development only, runs with `DJANGO_DEBUG=true`. |

Nothing in either profile binds `0.0.0.0`. If you change `THREATBRIDGE_BIND_ADDRESS` to a routable
interface, the host firewall becomes the control that keeps ThreatBridge reachable only from the
reverse proxy and the administration network.

## 1. Prepare configuration and secrets

Generate the local deployment files. Replace the documentation values with your own public
hostname, the interface your reverse proxy connects to, and the approved connector destinations:

```bash
python scripts/prepare_production_deployment.py \
  --hostname threatbridge.example.invalid \
  --bind-address 127.0.0.1 \
  --outbound-host opencti.example.invalid \
  --private-cidr 192.0.2.0/24
```

The command creates a mode-`0600` `deploy/.env.production` and three mode-`0444` secret files
inside a mode-`0700` `deploy/secrets/` directory. Existing secrets are preserved unless `--force`
is explicitly supplied; re-running the command re-applies the mode so a deployment prepared before
this policy is repaired in place without rotating the values.

The secret files are read-only to everyone rather than owner-only for a specific reason. Outside
Swarm, Compose bind-mounts a file-backed secret with the host file's ownership and mode and ignores
the `uid`, `gid`, and `mode` options, printing `config uid, gid and mode are not supported, they
will be ignored`. The container runs as UID 65532, which cannot be granted ownership without root,
so an owner-only file mounts unreadable and the application aborts at startup with
`Unable to read DJANGO_SECRET_KEY_FILE`. Confidentiality therefore rests on the `0700` secrets
directory: no unprivileged host user can traverse into it, so the permissive file mode is never
reachable. Keep that directory `0700` and owned by the deploying account, and do not relocate the
secrets into a world-traversable path. The preparation script verifies the directory mode on every
run and refuses any secret file that is group- or world-writable.

Use `--bind-address 127.0.0.1` when the reverse proxy runs on the same host. Use a specific host
interface address only when the proxy is remote, and firewall that port.

Resolve the selected mutable discovery tags to immutable multi-platform manifest digests:

```bash
bash scripts/resolve_production_images.sh
```

The resolver updates only the three image keys in `deploy/.env.production`. By default it resolves
publicly pullable Docker Hub images (`python:3.13.14-alpine3.24` for the builder and runtime,
`postgres:17-alpine` for the database), so any third party can complete this step without a
registry subscription. The Python default names an exact patch level, matching the Dockerfile's
committed default, so preparing a deployment never silently advances the base. To build from a
hardened, mirrored, or otherwise private base, export `THREATBRIDGE_BUILDER_TAG`,
`THREATBRIDGE_RUNTIME_TAG`, or `THREATBRIDGE_POSTGRES_TAG` and run `docker login` for that registry
first. Digest pinning and image validation are identical either way.

Alpine 3.24 is the default because that exact candidate built from the committed hash-locked
requirements, passed complete runtime confinement validation, and recorded zero HIGH or CRITICAL
findings in the reviewed Trivy 0.70.0 scan. That is point-in-time evidence about one image and one
scanner database, not a promise that a future scan stays clean, and it is not a claim that
ThreatBridge is free of vulnerabilities. Debian `slim` and `slim-bookworm` bases were also built and
validated successfully but had more blocking findings; see
[`../docs/container-image-security.md`](../docs/container-image-security.md) for the comparison, the
musl compatibility scope, and the procedure for upgrading the base.

### Supported secret injection methods

Only these methods are supported. Do not place secrets in `compose.production.yml`, image layers,
build arguments, shell history, or the integration configuration JSON.

| Secret | Method |
| --- | --- |
| Django signing key | `DJANGO_SECRET_KEY_FILE` via the `django_secret_key` Docker secret |
| Database URL | `DATABASE_URL_FILE` via the `database_url` Docker secret |
| PostgreSQL password | `POSTGRES_PASSWORD_FILE` via the `postgres_password` Docker secret |
| Connector tokens | each integration's `secret_reference`, either `env://PREFIX` or `file:/absolute/path` |

`DJANGO_SECRET_KEY_FILE` and `DATABASE_URL_FILE` are accepted only as absolute, regular,
non-symlink files that are not group- or world-writable. The direct and file-backed forms of the
same value are mutually exclusive. In production the signing key must also be at least 50
characters with at least 16 distinct characters and must not contain a placeholder marker such as
`changeme`, `example`, or `django-insecure`.

### Private CA configuration

For an internal Step CA or another reviewed private trust anchor, pass the reviewed certificate
when preparing the deployment:

```bash
python scripts/prepare_production_deployment.py \
  --hostname threatbridge.example.invalid \
  --bind-address 127.0.0.1 \
  --outbound-host opencti.example.invalid \
  --private-cidr 192.0.2.0/24 \
  --extra-ca-path /absolute/path/to/internal-root-ca.crt
```

The certificate file must be readable by UID 65532 — mode `0444` — and must not be group- or
world-writable. The preparation script refuses an owner-only certificate and tells you the `chmod`
to run. This is the same Compose limitation described under the secret files: the overlay declares
`uid`, `gid`, and `mode` on the mount, and Compose ignores all three outside Swarm, mounting the
host file as-is. A CA certificate is public material, so a readable mode costs nothing. If the file
is unreadable the `deploy-check` gate now fails closed with
`Unable to read THREATBRIDGE_EXTRA_CA_FILE` rather than starting with the private CA silently
absent from the trust store.

This sets `THREATBRIDGE_USE_EXTRA_CA=true`. The `scripts/production_compose.sh` wrapper then applies
`compose.production.step-ca.yml` automatically to every operation. The overlay mounts that one
certificate read-only at `/run/configs/threatbridge_extra_ca` for the `deploy-check`, `migrate`, and
`web` services, and sets `THREATBRIDGE_EXTRA_CA_FILE`. It extends Python's default public trust store
with `load_verify_locations`; it does not disable TLS or hostname verification, does not replace the
public CA bundle, and does not mount a host certificate directory. Do not source
`deploy/.env.production` in a shell.

## 2. Validate and compare the image

Render Compose before making changes:

```bash
bash scripts/production_compose.sh config --quiet
```

Build and validate the selected production image:

```bash
bash scripts/production_compose.sh build --no-cache web
bash scripts/validate_container_image.sh threatbridge:local
```

`validate_container_image.sh` asserts the runtime identity, file ownership and permissions, absence
of `pip`, source directories, secrets and private material, the complete set of OCI provenance
labels, that the only exposed port is `8000/tcp`, and that the image still works under the same
confinement Compose applies: read-only root filesystem, all capabilities dropped,
`no-new-privileges`, a writable `/tmp` only, and no Docker socket.

To compare the Dockerfile's pinned Docker Official Image baseline against whatever builder and
runtime digests `deploy/.env.production` currently records, run:

```bash
bash scripts/compare_base_images.sh
```

The comparison never suppresses vulnerability findings and never selects a base automatically. It
exits non-zero unless every candidate's Trivy scan passes the documented HIGH/CRITICAL policy, so a
blocked or skipped scan cannot be mistaken for a pass.

## 3. Start the stack

```bash
bash scripts/production_compose.sh up -d
bash scripts/production_compose.sh ps
```

`deploy-check` runs `manage.py check --deploy --fail-level ERROR` and must exit successfully, then
`migrate` must exit successfully, before `web` starts. A misconfigured production environment
therefore fails before anything serves traffic or touches schema. PostgreSQL has no published host
port. The application is published on `THREATBRIDGE_BIND_ADDRESS` (loopback in the example file) and
`THREATBRIDGE_PORT` (default `8020`); if you move it off loopback, restrict that port with the host
firewall to the reverse proxy and administration network.

Create the first administrator interactively so its password is not placed in Git, environment
files, or shell arguments:

```bash
bash scripts/production_compose.sh \
  exec web python manage.py createsuperuser
```

Do not seed demonstration data in a real deployment unless that is explicitly desired.

## 4. Reverse proxy and health checks

ThreatBridge serves plain HTTP inside the container and does not terminate TLS. A TLS-terminating
reverse proxy in front of it is required for any deployment that is not purely local. Terminate TLS
at that proxy, preserve the original `Host`, and forward to `THREATBRIDGE_BIND_ADDRESS` on
`THREATBRIDGE_PORT`. Never expose the container port to the internet.

Forwarded-protocol trust is **off by default**. Django ignores `X-Forwarded-Proto` unless you set:

```bash
THREATBRIDGE_TRUST_X_FORWARDED_PROTO=true
```

Only set it when all three of the following hold. Otherwise a client that reaches the published port
directly can assert `X-Forwarded-Proto: https`, and Django will treat a plaintext request as secure.

1. The reverse proxy terminates TLS.
2. The proxy unconditionally *overwrites* `X-Forwarded-Proto` rather than passing a client value
   through.
3. Clients cannot reach the published container port without going through the proxy.

`manage.py check --deploy` emits `threatbridge.W002` whenever this trust is enabled, as a reminder to
re-confirm those three conditions. The forwarded `Host` and `Port` headers are never trusted:
`USE_X_FORWARDED_HOST` and `USE_X_FORWARDED_PORT` are both false, and `DJANGO_ALLOWED_HOSTS` is
authoritative.

Probe:

- `/healthz` for process liveness;
- `/readyz` for application and database readiness.

Neither endpoint requires authentication and neither returns configuration, version, or secret
detail; readiness failures are generic.

These two paths are the only ones exempt from the production HTTPS redirect, via
`SECURE_REDIRECT_EXEMPT`. The container's own health check probes `http://127.0.0.1:8000/readyz` on
loopback and cannot follow a redirect to the public hostname, so without the exemption the container
would answer `301` to its own probe and never report healthy. Every path that carries data still
redirects. The probe also sends the first entry of `DJANGO_ALLOWED_HOSTS` as its `Host` header,
because `ALLOWED_HOSTS` is authoritative and a literal `Host: 127.0.0.1` would be rejected with
`400`; loopback is never added to `ALLOWED_HOSTS` to accommodate the probe. Both Compose profiles
deliberately omit `test` from their `healthcheck` blocks and tune only the timings, so the probe is
defined once in the `Dockerfile` and cannot be overridden into a stale copy.

Start HSTS at the generated short duration. Increase it only after the HTTPS route, certificate
renewal, proxy headers, backups, and restore procedure have been verified. Startup refuses
`DJANGO_SECURE_HSTS_PRELOAD=true` unless `DJANGO_SECURE_HSTS_SECONDS` is at least one year and
`DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=true`, so preload cannot be enabled before the rollout is
complete.

## 5. Back up and restore

Backups are the operator's responsibility. This repository provides the mechanism, not a retention,
encryption, or off-host policy.

Create a database and application-data backup:

```bash
bash scripts/backup_production.sh
```

Validate the resulting dump and archive before transferring them to encrypted backup storage.
A destructive restore requires an explicit confirmation token:

```bash
CONFIRM=RESTORE_THREATBRIDGE \
  bash scripts/restore_production.sh backups/threatbridge/YYYYMMDDTHHMMSSZ
```

Perform a scheduled restore test on a disposable deployment before treating backups as reliable.
`scripts/backup_production.sh` writes to the local `backups/` directory, which is git-ignored and
unencrypted; copying it to encrypted, access-controlled, off-host storage and choosing a retention
period are host-administrator tasks. No recovery point or recovery time objective is implied.

## 6. Upgrade and rollback

ThreatBridge has no automated rollback. Plan an upgrade as follows.

1. Read `CHANGELOG.md` for the target version and note any migration that removes or rewrites data.
2. Take a fresh backup and confirm it restores on a disposable deployment.
3. Update the image references, re-resolve digests, and re-validate:

   ```bash
   bash scripts/resolve_production_images.sh
   bash scripts/production_compose.sh build --no-cache web
   bash scripts/validate_container_image.sh threatbridge:local
   bash scripts/production_compose.sh config --quiet
   ```

4. Apply it. `deploy-check` and `migrate` gate the new `web` container:

   ```bash
   bash scripts/production_compose.sh up -d
   ```

5. Verify `/readyz`, a login, and one connector test before considering the upgrade complete.

To roll back, restore the previous immutable image digest in `deploy/.env.production` and bring the
stack up again. Django migrations are not automatically reversible: if the new version applied a
migration, rolling the image back also requires restoring the database backup taken in step 2.
Record the previous digest before every upgrade so this is possible.
