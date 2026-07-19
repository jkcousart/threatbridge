#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: scan_container_image.sh IMAGE [REPORT_FILE]" >&2
    exit 2
fi

image_ref="$1"
report_file="${2:-release-evidence/threatbridge-image-vulnerabilities.json}"
trivy_bin="${TRIVY_BIN:-/tmp/threatbridge-trivy-0.70.0/trivy}"
trivy_cache_dir="${TRIVY_CACHE_DIR:-/tmp/threatbridge-trivy-cache}"
expected_version="0.70.0"

"${trivy_bin}" --version | grep -Fxq "Version: ${expected_version}"
image_id="$(docker image inspect --format '{{.Id}}' "${image_ref}")"
mkdir -p "$(dirname "${report_file}")" "${trivy_cache_dir}"
"${trivy_bin}" image \
    --cache-dir "${trivy_cache_dir}" \
    --ignorefile /dev/null \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --format json \
    --output "${report_file}" \
    "${image_id}"
printf 'Scanned exact local image %s with Trivy %s\n' "${image_id}" "${expected_version}"
"${THREATBRIDGE_VENV:-.venv}/bin/python" scripts/evaluate_trivy_report.py "${report_file}"
