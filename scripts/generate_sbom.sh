#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

project_venv="${THREATBRIDGE_VENV:-.venv}"
output_file="${1:-sbom/threatbridge.cdx.json}"

mkdir -p "$(dirname "${output_file}")"
PYTHONWARNINGS="ignore:The Component this BOM is describing" \
"${project_venv}/bin/cyclonedx-py" requirements \
    requirements/runtime.txt \
    --pyproject pyproject.toml \
    --mc-type application \
    --output-format JSON \
    --output-reproducible \
    --output-file "${output_file}"
"${project_venv}/bin/python" scripts/finalize_sbom.py "${output_file}"

echo "Generated CycloneDX SBOM: ${output_file}"
