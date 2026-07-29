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

# Must stay identical to the Dockerfile's committed default so "default" really compares
# what a plain `docker build` produces. tests/test_deployment_tooling.py enforces that.
current_ref="python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
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

# "default" is the digest recorded in the Dockerfile; "pinned" is whatever
# deploy/.env.production resolved, which may name a different distribution or registry.
build_candidate default "${current_ref}" "${current_ref}"
build_candidate pinned \
    "${builder_image}" \
    "${runtime_image}"

{
    echo "candidate image_id size_bytes configured_user scan_policy"
    for name in default pinned; do
        read -r image_id size_bytes configured_user < "${output_dir}/${name}.image.txt"
        scan_policy="$(awk -F= '/^scan_policy=/{print $2}' "${output_dir}/${name}.image.txt")"
        printf '%s %s %s %s %s\n' \
            "${name}" "${image_id}" "${size_bytes}" "${configured_user}" "${scan_policy}"
    done
} | tee "${output_dir}/summary.txt"

cat <<EOF2
Comparison evidence written to ${output_dir}.
Do not select or publish a base solely from package or finding counts, and do not read a
lower count as evidence that a base is secure. A candidate is eligible only after
application compatibility, exact findings, fix availability, runtime reachability, and
operational support are reviewed. A passing scan describes this scanner database at this
moment; it does not predict the next scan.
EOF2

# Evidence collection must still fail closed: a blocked or skipped scan is not a pass.
blocked=0
for name in default pinned; do
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
