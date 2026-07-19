#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: validate_container_image.sh IMAGE" >&2
    exit 2
fi

image_ref="$1"
configured_user="$(docker image inspect --format '{{.Config.User}}' "${image_ref}")"
if [[ "${configured_user}" != "threatbridge" ]]; then
    echo "Unexpected runtime user: ${configured_user}" >&2
    exit 1
fi
if docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${image_ref}" \
    | grep -q '^DJANGO_SECRET_KEY='; then
    echo "DJANGO_SECRET_KEY must not persist in the image environment" >&2
    exit 1
fi

expected_contents=$'LICENSE\nNOTICE\ndata\nmanage.py\nstaticfiles'
actual_contents="$(
    docker run --rm --network none "${image_ref}" \
        sh -c "find /app -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort"
)"
if [[ "${actual_contents}" != "${expected_contents}" ]]; then
    echo "Unexpected /app contents:" >&2
    printf '%s\n' "${actual_contents}" >&2
    exit 1
fi

docker run --rm --network none "${image_ref}" sh -c '
set -eu
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_CACHE_DIR=1
test "$(id -u)" -ne 0
test "$(id -u)" -eq 100
test "$(stat -c %U:%G /app/data)" = threatbridge:threatbridge
test "$(stat -c %a /app)" = 755
test "$(stat -c %a /app/data)" = 750
test "$(stat -c %a /app/manage.py)" = 755
test -z "$(find /app -xdev \( -type f -o -type d \) -perm -0002 -print -quit)"
test ! -e /app/.secrets
test ! -e /app/.env
test ! -e /app/catalog
test ! -e /app/integrations
test ! -e /app/threatbridge
test ! -e /app/requirements
test ! -e /app/scripts
test ! -e /app/.github
test ! -e /app/build
test ! -e /app/data/incoming
test -z "$(find /app -name "*.egg-info" -print -quit)"
test -z "$(find /usr/local/lib/python*/site-packages/catalog /usr/local/lib/python*/site-packages/integrations /usr/local/lib/python*/site-packages/threatbridge -type d -name tests -print -quit)"
test -f /app/LICENSE
test -f /app/NOTICE
test -f /app/staticfiles/admin/css/base.css
python -m pip check
python - <<"PY"
import pathlib
import sysconfig

import catalog
import integrations
import threatbridge

site_packages = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
for module in (threatbridge, catalog, integrations):
    module_path = pathlib.Path(module.__file__).resolve()
    if not module_path.is_relative_to(site_packages):
        raise SystemExit(f"{module.__name__} is not imported from the wheel: {module_path}")
    print(f"{module.__name__}={module_path}")
PY
'
