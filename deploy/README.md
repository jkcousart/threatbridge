# Production Docker deployment

This deployment profile is separate from `compose.yml`, which remains a local-development stack.
It uses a shell-free, non-root application image, a one-shot migration service, PostgreSQL on an
internal-only network, file-backed secrets, a read-only application root filesystem, and a host
port intended to be restricted to the reverse proxy and administration network.

## 1. Prepare configuration and secrets

Authenticate to the Docker Hardened Images registry before resolving its images:

```bash
docker login dhi.io
```

Generate the local deployment files. Replace the documentation addresses with the dedicated
ThreatBridge host, public hostname, and approved connector destinations:

```bash
python scripts/prepare_production_deployment.py \
  --hostname threatbridge.example.invalid \
  --bind-address 192.0.2.10 \
  --outbound-host opencti.example.invalid \
  --private-cidr 192.0.2.0/24
```

The command creates `deploy/.env.production` and three mode-`0600` secret files beneath
`deploy/secrets/`. Existing secrets are preserved unless `--force` is explicitly supplied.

Resolve the selected mutable discovery tags to immutable multi-platform manifest digests:

```bash
bash scripts/resolve_production_images.sh
```

The resolver updates only the three image keys in `deploy/.env.production`.

For an internal Step CA or another reviewed private trust anchor, pass the reviewed certificate
when preparing the deployment:

```bash
python scripts/prepare_production_deployment.py \
  --hostname threatbridge.example.invalid \
  --bind-address 192.0.2.10 \
  --outbound-host opencti.example.invalid \
  --private-cidr 192.0.2.0/24 \
  --extra-ca-path /absolute/path/to/internal-root-ca.crt
```

This sets `THREATBRIDGE_USE_EXTRA_CA=true`. The `scripts/production_compose.sh` wrapper then applies
`compose.production.step-ca.yml` automatically to every operation. The overlay extends Python's
default public trust store; it does not disable TLS verification or replace the public CA bundle.
Do not source `deploy/.env.production` in a shell.

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

To compare the existing Docker Official Image baseline with the resolved Docker Hardened Images
candidate, run:

```bash
bash scripts/compare_base_images.sh
```

The comparison never suppresses vulnerability findings or selects a winner automatically.

## 3. Start the stack

```bash
bash scripts/production_compose.sh up -d
bash scripts/production_compose.sh ps
```

The `migrate` service must exit successfully before `web` starts. PostgreSQL has no published host
port. The application is published on the configured LAN address and port `8020`; restrict that
port with the host firewall to the reverse proxy and administration network.

Create the first administrator interactively so its password is not placed in Git, environment
files, or shell arguments:

```bash
bash scripts/production_compose.sh \
  exec web python manage.py createsuperuser
```

Do not seed demonstration data in a real deployment unless that is explicitly desired.

## 4. Reverse proxy and health checks

Terminate TLS at the trusted reverse proxy and forward to the dedicated host on port `8020`.
Preserve the original host and set `X-Forwarded-Proto: https`; the production profile explicitly
opts into Django's forwarded-protocol handling. Do not expose the container directly to the
internet.

Probe:

- `/healthz` for process liveness;
- `/readyz` for application and database readiness.

Start HSTS at the generated short duration. Increase it only after the HTTPS route, certificate
renewal, proxy headers, backups, and restore procedure have been verified.

## 5. Back up and restore

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
