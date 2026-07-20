#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${THREATBRIDGE_ENV_FILE:-${root}/deploy/.env.production}"

if [[ ! -f "${env_file}" ]]; then
    echo "Missing ${env_file}; run scripts/prepare_production_deployment.py first." >&2
    exit 1
fi

command -v docker >/dev/null 2>&1 || {
    echo "docker is required" >&2
    exit 1
}

docker buildx version >/dev/null 2>&1 || {
    echo "docker buildx is required" >&2
    exit 1
}

builder_tag="${THREATBRIDGE_DHI_BUILDER_TAG:-dhi.io/python:3.13-dev}"
runtime_tag="${THREATBRIDGE_DHI_RUNTIME_TAG:-dhi.io/python:3.13}"
postgres_tag="${THREATBRIDGE_POSTGRES_TAG:-postgres:17-alpine}"

resolve_ref() {
    local tagged_ref="$1"
    local repository digest
    repository="${tagged_ref%:*}"
    digest="$(
        docker buildx imagetools inspect "${tagged_ref}" 2>/dev/null |
            awk '/^Digest:/ {print $2; exit}'
    )"
    if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "Unable to resolve an immutable digest for ${tagged_ref}." >&2
        if [[ "${tagged_ref}" == dhi.io/* ]]; then
            echo "Run 'docker login dhi.io' and retry." >&2
        fi
        exit 1
    fi
    printf '%s@%s\n' "${repository}" "${digest}"
}

builder_ref="$(resolve_ref "${builder_tag}")"
runtime_ref="$(resolve_ref "${runtime_tag}")"
postgres_ref="$(resolve_ref "${postgres_tag}")"

python3 - "${env_file}" "${builder_ref}" "${runtime_ref}" "${postgres_ref}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

path = Path(sys.argv[1])
replacements = {
    "THREATBRIDGE_PYTHON_BUILDER_IMAGE": sys.argv[2],
    "THREATBRIDGE_PYTHON_RUNTIME_IMAGE": sys.argv[3],
    "THREATBRIDGE_POSTGRES_IMAGE": sys.argv[4],
}
lines = path.read_text(encoding="utf-8").splitlines()
seen = set()
for index, line in enumerate(lines):
    key = line.partition("=")[0]
    if key in replacements:
        lines[index] = f"{key}={replacements[key]}"
        seen.add(key)
missing = sorted(set(replacements) - seen)
if missing:
    raise SystemExit(f"Missing image keys in {path}: {', '.join(missing)}")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

printf 'Pinned builder: %s\n' "${builder_ref}"
printf 'Pinned runtime: %s\n' "${runtime_ref}"
printf 'Pinned PostgreSQL: %s\n' "${postgres_ref}"
printf 'Updated %s\n' "${env_file}"
