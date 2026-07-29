#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${THREATBRIDGE_ENV_FILE:-${root}/deploy/.env.production}"
base_file="${THREATBRIDGE_COMPOSE_FILE:-${root}/compose.production.yml}"

if [[ ! -f "${env_file}" ]]; then
    echo "Missing production environment file: ${env_file}" >&2
    exit 1
fi

use_extra_ca="$(python3 "${root}/scripts/production_env.py" "${env_file}" THREATBRIDGE_USE_EXTRA_CA)"
compose=(docker compose --env-file "${env_file}" -f "${base_file}")
if [[ "${use_extra_ca}" == "true" ]]; then
    overlay="${THREATBRIDGE_COMPOSE_OVERLAY:-${root}/compose.production.step-ca.yml}"
    compose+=(-f "${overlay}")
elif [[ -n "${use_extra_ca}" && "${use_extra_ca}" != "false" ]]; then
    echo "THREATBRIDGE_USE_EXTRA_CA must be true or false" >&2
    exit 1
fi

exec "${compose[@]}" "$@"
