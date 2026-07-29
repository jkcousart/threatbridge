#!/usr/bin/env bash
#
# Authoritative production Compose integration gate.
#
# This exists because six deployment defects reached a committed state after passing a
# full static audit: an invalid pids_limit pairing that made the project unloadable,
# secret files the container user could not read, a health probe that Django answered 400
# and then 301, a Compose healthcheck that silently overrode the image's, a private CA
# that mounted unreadable while the stack still reported healthy, and a deployment gate on
# an implicit egress-capable network. Parsing YAML cannot see any of those. Only running
# the stack can, so running the stack is now a gate rather than a manual exercise.
#
# Everything here is disposable: generated test-only secrets, a loopback-only published
# port, `.localhost`/`.invalid` names, and a temporary directory removed on exit. The
# repository's own .env, .secrets/, database, and deployment state are never read.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

mode="${1:-all}"
case "${mode}" in
    all | base | step-ca) ;;
    *)
        echo "usage: validate_production_compose.sh [all|base|step-ca]" >&2
        exit 2
        ;;
esac

venv_python="${THREATBRIDGE_VENV:-${root}/.venv}/bin/python"
trivy_bin="${TRIVY_BIN:-/tmp/threatbridge-trivy-0.70.0/trivy}"
keep_artifacts="${THREATBRIDGE_KEEP_INTEGRATION_ARTIFACTS:-0}"
image_tag="threatbridge-compose-integration:${RANDOM}${RANDOM}"

# Every application service, in the order the profile starts them.
APP_SERVICES=(deploy-check migrate web)
ONE_SHOT_SERVICES=(deploy-check migrate)
EXPECTED_APP_PIDS_LIMIT=256
EXPECTED_DB_PIDS_LIMIT=512
HEALTH_TIMEOUT_SECONDS="${THREATBRIDGE_HEALTH_TIMEOUT_SECONDS:-180}"

log() { printf '\n== %s\n' "$*"; }
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}
# Without this, a non-zero exit from any checked command ends the run with no explanation,
# which is the least useful possible outcome for a CI gate.
report_unexpected_failure() {
    printf 'FAIL: command exited %s at %s:%s\n' "$1" "${BASH_SOURCE[0]}" "$2" >&2
}
trap 'report_unexpected_failure "$?" "${LINENO}"' ERR

# Compose rejects a duplicate environment key outright, so a value that already exists in
# the generated file has to be replaced rather than appended.
set_env_value() {
    "${venv_python}" - "${env_file}" "$1" "$2" <<'PY'
import sys
from pathlib import Path

path, key, value = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = [
    line
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.partition("=")[0] != key
]
lines.append(f"{key}={value}")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
}

require_prerequisites() {
    log "Checking prerequisites"
    local missing=0
    for binary in docker python3 curl awk; do
        command -v "${binary}" >/dev/null 2>&1 || {
            echo "Missing required command: ${binary}" >&2
            missing=1
        }
    done
    docker compose version >/dev/null 2>&1 || {
        echo "Missing Docker Compose v2 ('docker compose')" >&2
        missing=1
    }
    docker buildx version >/dev/null 2>&1 || {
        echo "Missing docker buildx" >&2
        missing=1
    }
    docker info >/dev/null 2>&1 || {
        echo "The Docker daemon is not reachable" >&2
        missing=1
    }
    [[ -x "${venv_python}" ]] || {
        echo "Missing project interpreter ${venv_python}; create it or set THREATBRIDGE_VENV" >&2
        missing=1
    }
    [[ -x "${trivy_bin}" ]] || {
        echo "Missing Trivy at ${trivy_bin}; run scripts/install_trivy.sh or set TRIVY_BIN" >&2
        missing=1
    }
    if [[ "${mode}" != "base" ]]; then
        command -v openssl >/dev/null 2>&1 || {
            echo "Missing openssl, required to generate the disposable test CA" >&2
            missing=1
        }
    fi
    ((missing == 0)) || fail "unmet prerequisites; nothing was started"
    printf 'docker %s / compose %s / trivy %s\n' \
        "$(docker version --format '{{.Server.Version}}')" \
        "$(docker compose version --short)" \
        "$("${trivy_bin}" --version | awk '/^Version:/ {print $2; exit}')"
}

# Redact through the application's own filter rather than a bespoke pattern, so gate
# output cannot disclose something the application would have redacted.
redact_stream() {
    PYTHONPATH="${root}" "${venv_python}" -c '
import sys
from threatbridge.log_redaction import redact

for line in sys.stdin:
    sys.stdout.write(redact(line.rstrip("\n")) + "\n")
'
}

compose() {
    THREATBRIDGE_ENV_FILE="${env_file}" \
        "${root}/scripts/production_compose.sh" -p "${project}" "$@"
}

dump_failure_diagnostics() {
    printf '\n-- redacted service state --\n' >&2
    compose ps -a 2>&1 | redact_stream >&2 || true
    local service
    for service in db "${APP_SERVICES[@]}"; do
        printf '\n-- redacted logs: %s (last 60 lines) --\n' "${service}" >&2
        compose logs --no-color --tail 60 "${service}" 2>&1 | redact_stream >&2 || true
    done
}

cleanup() {
    local status=$?
    if ((status != 0)) && [[ -n "${stack_started:-}" ]]; then
        dump_failure_diagnostics
    fi
    if [[ -n "${stack_started:-}" ]]; then
        printf '\n== Tearing down the disposable stack\n'
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
        docker network rm "${project}_default" >/dev/null 2>&1 || true
    fi
    docker image rm --force "${image_tag}" >/dev/null 2>&1 || true
    if [[ "${keep_artifacts}" == "1" ]]; then
        printf 'Preserved integration artifacts in %s\n' "${test_root}"
    elif [[ -n "${test_root:-}" ]]; then
        rm -rf "${test_root}"
    fi
    return "${status}"
}

require_prerequisites

test_root="$(mktemp -d /tmp/threatbridge-compose-integration-XXXXXXXX)"
chmod 700 "${test_root}"
# Unique per run so concurrent or interrupted runs never share containers, volumes, or
# networks. Compose project names allow lowercase alphanumerics only.
project="tb-compose-it-$(
    basename "${test_root}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | tail -c 9
)"
env_file="${test_root}/.env.production"
secrets_dir="${test_root}/secrets"
stack_started=""

# Installed before anything is created, so an early failure still tears down.
trap cleanup EXIT INT TERM

log "Selecting a free loopback port"
published_port="$(
    "${venv_python}" - <<'PY'
import socket

with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    print(probe.getsockname()[1])
PY
)"
[[ "${published_port}" =~ ^[0-9]+$ ]] && ((published_port >= 1024)) ||
    fail "could not select a usable high port"
if "${venv_python}" -c "
import socket, sys
with socket.socket() as probe:
    sys.exit(0 if probe.connect_ex(('127.0.0.1', ${published_port})) else 1)
"; then
    printf 'Using 127.0.0.1:%s\n' "${published_port}"
else
    fail "port ${published_port} is already in use"
fi

log "Generating disposable deployment settings and secrets"
# --hostname/--outbound-host stay inside reserved test namespaces, and the bind address is
# loopback, so nothing here can reach or name a real system.
"${venv_python}" scripts/prepare_production_deployment.py \
    --hostname threatbridge.localhost \
    --bind-address 127.0.0.1 \
    --outbound-host opencti.example.invalid \
    --port "${published_port}" \
    --hsts-seconds 0 \
    --env-file "${env_file}" \
    --secrets-dir "${secrets_dir}"

log "Checking generated secret permissions"
# Compose ignores secret uid/gid/mode outside Swarm, so the file must be readable by the
# container user and the 0700 directory is the boundary that keeps it confidential.
directory_mode="$(stat -c '%a' "${secrets_dir}")"
[[ "${directory_mode}" == "700" ]] || fail "secrets directory mode is ${directory_mode}, expected 700"
for secret_name in django-secret-key database-url postgres-password; do
    secret_mode="$(stat -c '%a' "${secrets_dir}/${secret_name}")"
    [[ "${secret_mode}" == "444" ]] ||
        fail "secret ${secret_name} mode is ${secret_mode}, expected 444"
done
printf 'secrets directory 0700, secret files 0444\n'

log "Confirming the repository's own deployment state is untouched"
for private_path in "${root}/deploy/.env.production" "${root}/deploy/secrets" "${root}/.env" \
    "${root}/.secrets" "${root}/db.sqlite3"; do
    [[ "${env_file}" == "${private_path}"* ]] && fail "refusing to use ${private_path}"
done
[[ "${THREATBRIDGE_ENV_FILE:-}" == "" || "${THREATBRIDGE_ENV_FILE}" == "${env_file}" ]] ||
    fail "THREATBRIDGE_ENV_FILE points outside the disposable environment"
printf 'using only %s\n' "${test_root}"

log "Resolving immutable image digests"
THREATBRIDGE_ENV_FILE="${env_file}" bash scripts/resolve_production_images.sh

log "Confirming the resolved base matches the committed Dockerfile default"
# The image under test has to be the one a third party gets from a plain `docker build`.
# A substituted Python base would make every result below evidence about something else.
"${venv_python}" - "${env_file}" "${root}/Dockerfile" <<'PY'
import re
import sys
from pathlib import Path

env_file, dockerfile = (Path(argument) for argument in sys.argv[1:3])
environment = dict(
    line.split("=", 1)
    for line in env_file.read_text(encoding="utf-8").splitlines()
    if "=" in line and not line.startswith("#")
)
source = dockerfile.read_text(encoding="utf-8")
for argument, key in (
    ("PYTHON_BUILDER_IMAGE", "THREATBRIDGE_PYTHON_BUILDER_IMAGE"),
    ("PYTHON_RUNTIME_IMAGE", "THREATBRIDGE_PYTHON_RUNTIME_IMAGE"),
):
    match = re.search(rf"^ARG {argument}=(\S+)$", source, re.MULTILINE)
    if match is None:
        raise SystemExit(f"Dockerfile has no default for ARG {argument}")
    committed_digest = match.group(1).partition("@")[2]
    resolved_digest = environment.get(key, "").partition("@")[2]
    if not committed_digest.startswith("sha256:"):
        raise SystemExit(f"ARG {argument} default is not digest-pinned")
    if resolved_digest != committed_digest:
        raise SystemExit(
            f"{key} resolved to {resolved_digest or 'nothing'}, but the committed "
            f"ARG {argument} default is {committed_digest}; the gate must test the "
            "committed base, not a substituted one"
        )
print("resolved builder and runtime digests match the committed Dockerfile defaults")
PY

log "Building from the committed Dockerfile defaults"
# No --build-arg for either base: this is a plain build of the committed Dockerfile.
docker build \
    --build-arg "THREATBRIDGE_REVISION=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
    --build-arg "THREATBRIDGE_CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --tag "${image_tag}" \
    "${root}"
base_label="$(
    docker image inspect \
        --format '{{index .Config.Labels "org.opencontainers.image.base.name"}}' "${image_tag}"
)"
printf 'base label: %s\n' "${base_label}"

log "Validating image identity, contents, and confinement"
bash scripts/validate_container_image.sh "${image_tag}"

log "Generating the image SBOM"
bash scripts/generate_image_sbom.sh "${image_tag}" "${test_root}/image.cdx.json"

log "Scanning the image with no suppressions"
bash scripts/scan_container_image.sh "${image_tag}" "${test_root}/image-vulnerabilities.json"

# Point the profile at the image just built and validated, rather than letting Compose
# build a second, unvalidated one.
set_env_value THREATBRIDGE_IMAGE "${image_tag}"

log "Rendering and validating the production Compose configuration"
compose config --quiet
rendered="${test_root}/compose.rendered.json"
compose config --format json >"${rendered}"
"${venv_python}" - "${rendered}" "${published_port}" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_port = int(sys.argv[2])
services = configuration["services"]
if set(services) != {"db", "deploy-check", "migrate", "web"}:
    raise SystemExit(f"unexpected services: {sorted(services)}")

for name in ("deploy-check", "migrate", "web"):
    service = services[name]
    if service["user"] != "65532:65532":
        raise SystemExit(f"{name} runs as {service['user']}")
    if service.get("read_only") is not True:
        raise SystemExit(f"{name} does not request a read-only root filesystem")
    if service.get("cap_drop") != ["ALL"]:
        raise SystemExit(f"{name} does not drop all capabilities")
    if service.get("security_opt") != ["no-new-privileges:true"]:
        raise SystemExit(f"{name} does not set no-new-privileges")
    if service.get("privileged", False):
        raise SystemExit(f"{name} is privileged")
    limits = service["deploy"]["resources"]["limits"]
    if limits["pids"] != service["pids_limit"]:
        raise SystemExit(f"{name} has mismatched PID limits")

if services["deploy-check"].get("network_mode") != "none":
    raise SystemExit("deploy-check must run with network_mode: none")
if services["db"].get("ports"):
    raise SystemExit("the database must not publish a port")
if configuration["networks"]["database"].get("internal") is not True:
    raise SystemExit("the database network must be internal")

published = services["web"]["ports"]
if len(published) != 1:
    raise SystemExit(f"web publishes {len(published)} ports")
binding = published[0]
if binding["host_ip"] != "127.0.0.1":
    raise SystemExit(f"web is published on {binding['host_ip']}, not loopback")
if int(binding["published"]) != expected_port or binding["target"] != 8000:
    raise SystemExit(f"unexpected port mapping: {binding}")

# A `test` here would override the image's HEALTHCHECK, which is how the two previously
# drifted apart.
if "test" in services["web"]["healthcheck"]:
    raise SystemExit("web must inherit the image healthcheck rather than redefining it")
print("rendered configuration satisfies the documented policy")
PY

log "Starting the disposable stack"
stack_started=1
compose up -d

log "Waiting for one-shot services to complete"
for service in "${ONE_SHOT_SERVICES[@]}"; do
    container="$(compose ps -a -q "${service}")"
    [[ -n "${container}" ]] || fail "${service} was never created"
    deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
    while :; do
        state="$(docker inspect --format '{{.State.Status}}' "${container}")"
        [[ "${state}" == "exited" ]] && break
        ((SECONDS < deadline)) || fail "${service} did not finish within ${HEALTH_TIMEOUT_SECONDS}s"
        sleep 2
    done
    exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${container}")"
    ((exit_code == 0)) || fail "${service} exited ${exit_code}"
    printf '%s completed successfully\n' "${service}"
done

log "Waiting for web to become healthy"
web_container="$(compose ps -q web)"
[[ -n "${web_container}" ]] || fail "web is not running"
deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
while :; do
    health="$(docker inspect --format '{{.State.Health.Status}}' "${web_container}")"
    case "${health}" in
        healthy) break ;;
        unhealthy) fail "web reported unhealthy" ;;
    esac
    ((SECONDS < deadline)) || fail "web stayed ${health} for ${HEALTH_TIMEOUT_SECONDS}s"
    sleep 2
done
printf 'web is healthy, so the image healthcheck succeeded on its internal probe path\n'

log "Checking the loopback-published HTTP surface"
http_status() {
    curl --silent --show-error --output /dev/null --max-time 10 \
        --write-out '%{http_code}' \
        --header "Host: $2" "http://127.0.0.1:${published_port}$1"
}
redirect_target() {
    curl --silent --show-error --output /dev/null --max-time 10 \
        --write-out '%{redirect_url}' \
        --header "Host: threatbridge.localhost" "http://127.0.0.1:${published_port}$1"
}

for path in /healthz /readyz; do
    status="$(http_status "${path}" threatbridge.localhost)"
    [[ "${status}" == "200" ]] || fail "${path} returned ${status}, expected 200"
    printf '%s -> 200\n' "${path}"
done

# The health exemption has to stay narrow: everything that carries data still redirects.
for path in / /admin/; do
    status="$(http_status "${path}" threatbridge.localhost)"
    [[ "${status}" == "301" ]] || fail "${path} returned ${status}, expected 301"
    target="$(redirect_target "${path}")"
    [[ "${target}" == "https://threatbridge.localhost${path}" ]] ||
        fail "${path} redirected to ${target}, expected https://threatbridge.localhost${path}"
    printf '%s -> 301 %s\n' "${path}" "${target}"
done

# ALLOWED_HOSTS must remain authoritative; it is never widened to accommodate a probe.
status="$(http_status /readyz evil.example.invalid)"
[[ "${status}" == "400" ]] || fail "an unapproved Host returned ${status}, expected 400"
printf 'unapproved Host -> 400\n'

log "Verifying the internal probe path directly"
compose exec -T web python -c "
import os, urllib.request
host = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')[0].strip()
for path in ('healthz', 'readyz'):
    request = urllib.request.Request(f'http://127.0.0.1:8000/{path}', headers={'Host': host})
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200, (path, response.status)
print('internal loopback probe reached both endpoints with status 200')
"

log "Verifying the database is unpublished and isolated"
db_container="$(compose ps -q db)"
db_ports="$(docker inspect --format '{{json .NetworkSettings.Ports}}' "${db_container}")"
[[ "${db_ports}" != *"HostPort"* ]] || fail "the database publishes a host port: ${db_ports}"
if "${venv_python}" -c "
import socket, sys
with socket.socket() as probe:
    sys.exit(1 if probe.connect_ex(('127.0.0.1', 5432)) == 0 else 0)
"; then
    printf 'no PostgreSQL listener on the host\n'
else
    fail "something is listening on 127.0.0.1:5432"
fi
if docker exec "${db_container}" getent hosts example.com >/dev/null 2>&1; then
    fail "the database container resolved an external name; its network is not internal"
fi
printf 'database has no external DNS resolution\n'
compose exec -T web python -c "
import socket
socket.create_connection(('db', 5432), timeout=5).close()
print('web reaches db:5432 on the internal network')
"

log "Verifying no container has access to the Docker socket"
for service in db "${APP_SERVICES[@]}"; do
    container="$(compose ps -a -q "${service}")"
    mounts="$(docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "${container}")"
    [[ "${mounts}" != *docker.sock* ]] || fail "${service} mounts the Docker socket"
done
compose exec -T web sh -c '! test -e /var/run/docker.sock' ||
    fail "the Docker socket exists inside the web container"
printf 'no Docker socket in any container\n'

log "Inspecting live container confinement"
for service in "${APP_SERVICES[@]}"; do
    container="$(compose ps -a -q "${service}")"
    read -r user read_only privileged pids network <<<"$(
        docker inspect --format \
            '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}} {{.HostConfig.PidsLimit}} {{.HostConfig.NetworkMode}}' \
            "${container}"
    )"
    [[ "${user}" == "65532:65532" ]] || fail "${service} runs as ${user}"
    [[ "${read_only}" == "true" ]] || fail "${service} has a writable root filesystem"
    [[ "${privileged}" == "false" ]] || fail "${service} is privileged"
    ((pids == EXPECTED_APP_PIDS_LIMIT)) ||
        fail "${service} PidsLimit is ${pids}, expected ${EXPECTED_APP_PIDS_LIMIT}"
    security_opt="$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "${container}")"
    [[ "${security_opt}" == *no-new-privileges:true* ]] ||
        fail "${service} does not set no-new-privileges: ${security_opt}"
    cap_drop="$(docker inspect --format '{{json .HostConfig.CapDrop}}' "${container}")"
    [[ "${cap_drop}" == '["ALL"]' ]] || fail "${service} cap_drop is ${cap_drop}"
    cap_add="$(docker inspect --format '{{json .HostConfig.CapAdd}}' "${container}")"
    [[ "${cap_add}" == "null" || "${cap_add}" == "[]" ]] ||
        fail "${service} adds capabilities: ${cap_add}"
    printf '%-13s user=%s read_only=%s pids=%s net=%s\n' \
        "${service}" "${user}" "${read_only}" "${pids}" "${network}"
done

deploy_check_network="$(
    docker inspect --format '{{.HostConfig.NetworkMode}}' "$(compose ps -a -q deploy-check)"
)"
[[ "${deploy_check_network}" == "none" ]] ||
    fail "deploy-check network is ${deploy_check_network}, expected none"

db_pids="$(docker inspect --format '{{.HostConfig.PidsLimit}}' "${db_container}")"
((db_pids == EXPECTED_DB_PIDS_LIMIT)) ||
    fail "database PidsLimit is ${db_pids}, expected ${EXPECTED_DB_PIDS_LIMIT}"

log "Verifying the running process has no capabilities and cannot escalate"
compose exec -T web sh -c 'grep -E "^(NoNewPrivs|CapEff|CapPrm|CapBnd):" /proc/1/status' |
    "${venv_python}" -c '
import sys

fields = dict(
    line.split(":", 1) for line in sys.stdin.read().splitlines() if ":" in line
)
fields = {key.strip(): value.strip() for key, value in fields.items()}
if fields.get("NoNewPrivs") != "1":
    raise SystemExit(f"NoNewPrivs is {fields.get('NoNewPrivs')!r}, expected 1")
for capability_set in ("CapEff", "CapPrm", "CapBnd"):
    raw = fields.get(capability_set, "ffffffffffffffff")
    if int(raw, 16) != 0:
        raise SystemExit(f"{capability_set} is not empty: {raw}")
print("NoNewPrivs=1 and CapEff/CapPrm/CapBnd are all empty")
'

log "Verifying only the documented paths are writable"
compose exec -T web python -c "
import os

writable = {'/tmp', '/app/data'}
read_only = {'/', '/app', '/opt/runtime-venv', '/etc', '/usr/local/lib'}
for path in sorted(writable | read_only):
    probe = os.path.join(path, '.threatbridge-integration-probe')
    try:
        with open(probe, 'w') as handle:
            handle.write('x')
        os.unlink(probe)
    except OSError:
        if path in writable:
            raise SystemExit(f'{path} must be writable')
    else:
        if path in read_only:
            raise SystemExit(f'{path} must not be writable')
print('writable paths are exactly /tmp and /app/data')
"
tmpfs_options="$(docker inspect --format '{{index .HostConfig.Tmpfs "/tmp"}}' "${web_container}")"
for option in noexec nosuid nodev size=; do
    [[ "${tmpfs_options}" == *"${option}"* ]] ||
        fail "/tmp tmpfs is missing ${option}: ${tmpfs_options}"
done
printf '/tmp tmpfs options: %s\n' "${tmpfs_options}"

log "Recording the baseline trust store size"
# Captured without the overlay so the step-ca phase can prove the private CA is *added*
# to public trust rather than replacing it.
baseline_trust_anchors="$(
    compose exec -T web python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatbridge.settings')
django.setup()
from integrations.outbound import _build_tls_context
print(len(_build_tls_context().get_ca_certs()))
" | tr -d '\r'
)"
[[ "${baseline_trust_anchors}" =~ ^[0-9]+$ ]] && ((baseline_trust_anchors > 1)) ||
    fail "expected a populated public trust store, got '${baseline_trust_anchors}'"
printf 'public trust anchors without the overlay: %s\n' "${baseline_trust_anchors}"

if [[ "${mode}" == "base" ]]; then
    log "Base phase passed"
    printf 'Production Compose integration gate passed (base phase only).\n'
    exit 0
fi

log "Tearing down before the private-CA phase"
compose down --volumes --remove-orphans >/dev/null
stack_started=""

# ---------------------------------------------------------------------------
# Private-CA phase: compose.production.step-ca.yml
#
# Verifies the overlay actually works, which it did not before: Compose ignores the
# mount's uid/gid/mode outside Swarm, so an operator-only certificate mounted unreadable
# and the stack still reported healthy with the CA absent from the trust store.
# ---------------------------------------------------------------------------
log "Generating a disposable test CA"
ca_certificate="${test_root}/test-ca.crt"
ca_private_key="${test_root}/test-ca.key"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${ca_private_key}" -out "${ca_certificate}" \
    -days 1 -subj "/CN=ThreatBridge Disposable Integration CA" 2>/dev/null
# The application never needs the key, and nothing mounts it. Remove it immediately so it
# cannot be mounted by accident.
rm -f "${ca_private_key}"
grep -q "BEGIN CERTIFICATE" "${ca_certificate}" || fail "the generated CA is not a certificate"
! grep -q "PRIVATE KEY" "${ca_certificate}" ||
    fail "the generated CA file contains a private key"
chmod 0444 "${ca_certificate}"
printf 'certificate at mode 0444, private key discarded\n'

log "Re-preparing the deployment with the private CA enabled"
"${venv_python}" scripts/prepare_production_deployment.py \
    --hostname threatbridge.localhost \
    --bind-address 127.0.0.1 \
    --outbound-host opencti.example.invalid \
    --port "${published_port}" \
    --hsts-seconds 0 \
    --extra-ca-path "${ca_certificate}" \
    --env-file "${env_file}" \
    --secrets-dir "${secrets_dir}" \
    --force
THREATBRIDGE_ENV_FILE="${env_file}" bash scripts/resolve_production_images.sh >/dev/null
set_env_value THREATBRIDGE_IMAGE "${image_tag}"
grep -q '^THREATBRIDGE_USE_EXTRA_CA=true$' "${env_file}" ||
    fail "the overlay was not enabled in the disposable environment"

log "Confirming the overlay renders and does not disable verification"
compose config --quiet
compose config --format json >"${test_root}/compose.step-ca.json"
"${venv_python}" - "${test_root}/compose.step-ca.json" <<'PY'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for name in ("deploy-check", "migrate", "web"):
    service = configuration["services"][name]
    environment = service["environment"]
    if environment.get("THREATBRIDGE_EXTRA_CA_FILE") != "/run/configs/threatbridge_extra_ca":
        raise SystemExit(f"{name} does not receive the overlay trust anchor")
    for variable, value in environment.items():
        if "VERIFY" in variable.upper() and str(value).lower() in {"0", "false", "no"}:
            raise SystemExit(f"{name} disables verification through {variable}")
rendered = json.dumps(configuration).lower()
for forbidden in ("insecure", "verify=false", "verify_ssl", "no_verify"):
    if forbidden in rendered:
        raise SystemExit(f"rendered overlay contains {forbidden!r}")
print("overlay adds trust material only")
PY

log "Starting the stack with the private CA"
stack_started=1
compose up -d
web_container="$(compose ps -q web)"
deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
while :; do
    health="$(docker inspect --format '{{.State.Health.Status}}' "${web_container}")"
    case "${health}" in
        healthy) break ;;
        unhealthy) fail "web reported unhealthy with the private CA mounted" ;;
    esac
    ((SECONDS < deadline)) || fail "web stayed ${health} for ${HEALTH_TIMEOUT_SECONDS}s"
    sleep 2
done

log "Confirming the application loads the CA and keeps public trust"
compose exec -T web python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatbridge.settings')
django.setup()
from django.conf import settings
from integrations.outbound import _build_tls_context

path = settings.THREATBRIDGE_EXTRA_CA_FILE
assert path == '/run/configs/threatbridge_extra_ca', path
with open(path, 'rb') as handle:
    assert b'BEGIN CERTIFICATE' in handle.read(), 'mounted file is not a certificate'

context = _build_tls_context()
assert context.verify_mode.name == 'CERT_REQUIRED', context.verify_mode
assert context.check_hostname is True, 'hostname verification is disabled'
anchors = context.get_ca_certs()
subjects = [
    value
    for anchor in anchors
    for rdn in anchor.get('subject', ())
    for _, value in rdn
]
assert 'ThreatBridge Disposable Integration CA' in subjects, 'private CA is absent'
print(f'{len(anchors)} trust anchors, private CA present, verification required')
" | tee "${test_root}/trust-store.txt"
overlay_trust_anchors="$(awk '{print $1; exit}' "${test_root}/trust-store.txt")"
((overlay_trust_anchors == baseline_trust_anchors + 1)) ||
    fail "trust anchors went from ${baseline_trust_anchors} to ${overlay_trust_anchors}; the private CA must extend public trust, not replace it"
printf 'trust store grew from %s to %s: public trust retained\n' \
    "${baseline_trust_anchors}" "${overlay_trust_anchors}"

log "Confirming an unreadable CA fails closed"
compose down --volumes --remove-orphans >/dev/null
stack_started=""
chmod 0600 "${ca_certificate}"
stack_started=1
if compose up -d >/dev/null 2>&1; then
    fail "the stack started with an unreadable private CA"
fi
deploy_check_container="$(compose ps -a -q deploy-check)"
[[ -n "${deploy_check_container}" ]] || fail "deploy-check was never created"
unreadable_exit="$(docker inspect --format '{{.State.ExitCode}}' "${deploy_check_container}")"
((unreadable_exit != 0)) || fail "deploy-check accepted an unreadable private CA"
if ! compose logs --no-color deploy-check 2>&1 |
    grep -q "Unable to read THREATBRIDGE_EXTRA_CA_FILE"; then
    fail "deploy-check failed for the wrong reason"
fi
printf 'deploy-check refused an unreadable CA with exit %s\n' "${unreadable_exit}"
web_state="$(docker inspect --format '{{.State.Status}}' "$(compose ps -a -q web)" 2>/dev/null || echo absent)"
[[ "${web_state}" != "running" ]] || fail "web served despite the failed deployment gate"
chmod 0444 "${ca_certificate}"

log "Production Compose integration gate passed"
printf 'Verified: committed-default build, image validation, SBOM, unsuppressed scan,\n'
printf 'rendered policy, full stack startup, loopback-only HTTP surface, internal probe,\n'
printf 'database isolation, runtime confinement, and private-CA readable and unreadable\n'
printf 'cases. Nothing was published and no production credential was used.\n'
