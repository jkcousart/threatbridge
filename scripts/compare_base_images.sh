#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

env_file="${THREATBRIDGE_ENV_FILE:-deploy/.env.production}"
if [[ ! -f "${env_file}" ]]; then
    echo "Missing ${env_file}; prepare and resolve production images first." >&2
    exit 1
fi

read_env() {
    python3 scripts/production_env.py "${env_file}" "$1" "$2"
}

builder_image="$(read_env THREATBRIDGE_PYTHON_BUILDER_IMAGE --required)"
runtime_image="$(read_env THREATBRIDGE_PYTHON_RUNTIME_IMAGE --required)"

current_ref="python:3.13.14-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91"
output_dir="${THREATBRIDGE_BASE_COMPARISON_DIR:-release-evidence/base-comparison}"
mkdir -p "${output_dir}"

build_candidate() {
    local name="$1" builder="$2" runtime="$3" image="threatbridge:base-${name}"
    echo "===== BUILD ${name} ====="
    docker build --no-cache --pull=false \
        --build-arg "PYTHON_BUILDER_IMAGE=${builder}" \
        --build-arg "PYTHON_RUNTIME_IMAGE=${runtime}" \
        --tag "${image}" .
    bash scripts/validate_container_image.sh "${image}"
    docker image inspect "${image}" \
        --format '{{.Id}} {{.Size}} {{.Config.User}}' \
        > "${output_dir}/${name}.image.txt"
    if [[ -x "${TRIVY_BIN:-/tmp/threatbridge-trivy-0.70.0/trivy}" ]]; then
        if bash scripts/scan_container_image.sh \
            "${image}" "${output_dir}/${name}.trivy.json";
        then
            printf 'scan_policy=pass\n' >> "${output_dir}/${name}.image.txt"
        else
            printf 'scan_policy=blocked\n' >> "${output_dir}/${name}.image.txt"
        fi
    else
        printf 'scan_policy=not-run\n' >> "${output_dir}/${name}.image.txt"
    fi
}

# "official" is the digest recorded in the Dockerfile; "pinned" is whatever
# deploy/.env.production resolved, which may point at a different registry.
build_candidate official "${current_ref}" "${current_ref}"
build_candidate pinned \
    "${builder_image}" \
    "${runtime_image}"

{
    echo "candidate image_id size_bytes configured_user scan_policy"
    for name in official pinned; do
        read -r image_id size_bytes configured_user < "${output_dir}/${name}.image.txt"
        scan_policy="$(awk -F= '/^scan_policy=/{print $2}' "${output_dir}/${name}.image.txt")"
        printf '%s %s %s %s %s\n' \
            "${name}" "${image_id}" "${size_bytes}" "${configured_user}" "${scan_policy}"
    done
} | tee "${output_dir}/summary.txt"

cat <<EOF2
Comparison evidence written to ${output_dir}.
Do not select or publish a base solely from package counts. Review application compatibility,
exact findings, fix availability, runtime reachability, and operational support first.
EOF2

# Evidence collection must still fail closed: a blocked or skipped scan is not a pass.
blocked=0
for name in official pinned; do
    scan_policy="$(awk -F= '/^scan_policy=/{print $2}' "${output_dir}/${name}.image.txt")"
    if [[ "${scan_policy}" != "pass" ]]; then
        echo "Candidate ${name} scan_policy=${scan_policy}; not eligible for publication." >&2
        blocked=1
    fi
done
if [[ "${blocked}" -ne 0 ]]; then
    echo "Base-image comparison completed with blocking findings." >&2
    exit 1
fi
