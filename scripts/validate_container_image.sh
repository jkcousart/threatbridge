#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: validate_container_image.sh IMAGE" >&2
    exit 2
fi

image_ref="$1"
configured_user="$(docker image inspect --format '{{.Config.User}}' "${image_ref}")"
if [[ "${configured_user}" != "65532:65532" ]]; then
    echo "Unexpected runtime user: ${configured_user}" >&2
    exit 1
fi
if docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${image_ref}" \
    | grep -qE '^(DJANGO_SECRET_KEY|DATABASE_URL)='; then
    echo "Runtime secrets must not persist in the image environment" >&2
    exit 1
fi

# The Go template emits a trailing blank record, which sorts ahead of every port. Drop
# empty records before sorting so the comparison below stays an exact match.
exposed_ports="$(
    docker image inspect \
        --format '{{range $port, $_ := .Config.ExposedPorts}}{{println $port}}{{end}}' \
        "${image_ref}" | awk 'NF {print $1}' | LC_ALL=C sort | paste -sd ' ' -
)"
if [[ "${exposed_ports}" != "8000/tcp" ]]; then
    echo "Unexpected exposed ports: ${exposed_ports:-none}" >&2
    exit 1
fi

for label in \
    org.opencontainers.image.title \
    org.opencontainers.image.description \
    org.opencontainers.image.version \
    org.opencontainers.image.revision \
    org.opencontainers.image.created \
    org.opencontainers.image.licenses \
    org.opencontainers.image.source \
    org.opencontainers.image.base.name
do
    value="$(
        docker image inspect \
            --format "{{index .Config.Labels \"${label}\"}}" "${image_ref}"
    )"
    if [[ -z "${value}" ]]; then
        echo "Missing OCI label: ${label}" >&2
        exit 1
    fi
done

validation_script="$(cat <<'PY'
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import stat
import sysconfig

import catalog
import integrations
import threatbridge

app = pathlib.Path('/app')
expected = {'LICENSE', 'NOTICE', 'data', 'manage.py', 'staticfiles'}
actual = {path.name for path in app.iterdir()}
if actual != expected:
    raise SystemExit(f'unexpected /app contents: {sorted(actual)}')
if os.getuid() != 65532 or os.getgid() != 65532:
    raise SystemExit(f'unexpected identity: {os.getuid()}:{os.getgid()}')
checks = {
    '/app': 0o755,
    '/app/data': 0o750,
    '/app/manage.py': 0o755,
    '/app/LICENSE': 0o644,
    '/app/NOTICE': 0o644,
}
for raw_path, expected_mode in checks.items():
    path = pathlib.Path(raw_path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != expected_mode:
        raise SystemExit(f'{path} mode is {mode:o}, expected {expected_mode:o}')
if app.joinpath('data').stat().st_uid != 65532:
    raise SystemExit('/app/data is not owned by runtime UID 65532')
for path in app.rglob('*'):
    if stat.S_IMODE(path.lstat().st_mode) & 0o002:
        raise SystemExit(f'world-writable runtime path: {path}')
for forbidden in (
    '.secrets', '.env', 'catalog', 'integrations', 'threatbridge', 'requirements',
    'scripts', '.github', 'build', 'data/incoming'
):
    if app.joinpath(forbidden).exists():
        raise SystemExit(f'forbidden runtime path: /app/{forbidden}')
if not app.joinpath('staticfiles/admin/css/base.css').is_file():
    raise SystemExit('Django admin static files are missing')
if importlib.util.find_spec('pip') is not None:
    raise SystemExit('pip must not be present in the runtime environment')
site_packages = pathlib.Path(sysconfig.get_paths()['purelib']).resolve()
for package_name in ('catalog', 'integrations', 'threatbridge'):
    package_root = site_packages / package_name
    if any(path.name == 'tests' for path in package_root.rglob('tests')):
        raise SystemExit(f'test package present in runtime wheel: {package_name}')
for module in (threatbridge, catalog, integrations):
    module_path = pathlib.Path(module.__file__).resolve()
    if not module_path.is_relative_to(site_packages):
        raise SystemExit(f'{module.__name__} is not imported from the installed wheel: {module_path}')
    if '/opt/runtime-venv/' not in str(module_path):
        raise SystemExit(f'{module.__name__} is outside the runtime virtual environment: {module_path}')
print(json.dumps({
    'uid': os.getuid(),
    'gid': os.getgid(),
    'site_packages': str(site_packages),
    'modules': {
        module.__name__: str(pathlib.Path(module.__file__).resolve())
        for module in (threatbridge, catalog, integrations)
    },
}, sort_keys=True))
PY
)"

docker run --rm --network none --entrypoint python "${image_ref}" \
    -c "${validation_script}"

# Confirm the image actually operates under the confinement compose.production.yml
# applies: read-only root, all capabilities dropped, and no privilege escalation.
confinement_script="$(cat <<'PY'
from __future__ import annotations

import json
import pathlib

status = pathlib.Path('/proc/self/status').read_text(encoding='utf-8')
fields = {}
for line in status.splitlines():
    name, _, value = line.partition(':')
    fields[name.strip()] = value.strip()

if fields.get('NoNewPrivs') != '1':
    raise SystemExit('no-new-privileges is not active')
for capability_set in ('CapEff', 'CapPrm', 'CapBnd'):
    raw = fields.get(capability_set, 'ffffffffffffffff')
    if int(raw, 16) != 0:
        raise SystemExit(f'{capability_set} is not empty: {raw}')

for read_only_path in ('/', '/app', '/opt/runtime-venv', '/etc'):
    probe = pathlib.Path(read_only_path) / 'threatbridge-write-probe'
    try:
        probe.write_text('x', encoding='utf-8')
    except OSError:
        continue
    probe.unlink(missing_ok=True)
    raise SystemExit(f'{read_only_path} is writable under a read-only root filesystem')

writable = pathlib.Path('/tmp/threatbridge-write-probe')
writable.write_text('x', encoding='utf-8')
writable.unlink()

if pathlib.Path('/var/run/docker.sock').exists():
    raise SystemExit('the Docker socket is present inside the container')

print(json.dumps({'no_new_privs': True, 'capabilities': 'none', 'root_fs': 'read-only'}))
PY
)"

docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user 65532:65532 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
    --entrypoint python "${image_ref}" -c "${confinement_script}"

printf 'Container validation passed for %s\n' "${image_ref}"
