#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: generate_image_sbom.sh IMAGE [OUTPUT_FILE]" >&2
    exit 2
fi

image_ref="$1"
output_file="${2:-release-evidence/threatbridge-image.cdx.json}"
trivy_bin="${TRIVY_BIN:-/tmp/threatbridge-trivy-0.70.0/trivy}"
expected_version="0.70.0"

"${trivy_bin}" --version | grep -Fxq "Version: ${expected_version}"
image_id="$(docker image inspect --format '{{.Id}}' "${image_ref}")"
mkdir -p "$(dirname "${output_file}")"
"${trivy_bin}" image --quiet --format cyclonedx --output "${output_file}" "${image_id}"
printf 'Generated CycloneDX image SBOM for %s at %s\n' "${image_id}" "${output_file}"
