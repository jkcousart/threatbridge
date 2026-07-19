#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

temporary_root="$(mktemp -d)"
trap 'rm -rf "${temporary_root}"' EXIT
public_source="${temporary_root}/source"
mkdir -p "${public_source}"

# Copy only tracked and intended non-ignored public files. Ignored local configuration and private
# review material never enter the compatibility containers.
git ls-files --cached --others --exclude-standard -z \
    | tar --null --files-from=- -cf - \
    | tar -xf - -C "${public_source}"

images=(
    "python:3.12.13-slim"
    "python:3.13.14-slim"
    "python:3.14.4-slim"
)

for image in "${images[@]}"; do
    printf 'Testing ThreatBridge with %s\n' "${image}"
    docker run --rm \
        --volume "${public_source}:/src:ro" \
        --workdir /src \
        --env PIP_CONFIG_FILE=/dev/null \
        --env PIP_EXTRA_INDEX_URL= \
        --env PIP_INDEX_URL=https://pypi.org/simple \
        "${image}" sh -c '
            set -eu
            python -m venv /tmp/venv
            /tmp/venv/bin/python -m pip install --require-hashes -r requirements/build.txt
            /tmp/venv/bin/python -m pip install --require-hashes -r requirements/development.txt
            export DATABASE_URL=sqlite:////tmp/compatibility.sqlite3
            export DJANGO_SECRET_KEY="$(/tmp/venv/bin/python -c "import secrets; print(secrets.token_urlsafe(64))")"
            export PYTHONDONTWRITEBYTECODE=1
            export THREATBRIDGE_DATA_DIR=/tmp/data
            /tmp/venv/bin/python --version
            /tmp/venv/bin/python scripts/validate_dependency_locks.py
            /tmp/venv/bin/python manage.py check
            /tmp/venv/bin/python manage.py makemigrations --check --dry-run
            /tmp/venv/bin/python -m pytest -q -p no:cacheprovider
            /tmp/venv/bin/python -m pip check
        '
done
