#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

project_venv="${THREATBRIDGE_VENV:-.venv}"
output_file="${1:-sbom/threatbridge.cdx.json}"

resolve_tool() {
  local venv_candidate="$1"
  local command_name="$2"
  local path_candidate

  if [[ -x "${venv_candidate}" ]]; then
    printf '%s\n' "${venv_candidate}"
    return 0
  fi

  if path_candidate="$(command -v "${command_name}" 2>/dev/null)" &&
     [[ -x "${path_candidate}" ]]; then
    printf '%s\n' "${path_candidate}"
    return 0
  fi

  printf 'Required tool not found: %s; checked %s and PATH\n' \
    "${command_name}" "${venv_candidate}" >&2
  return 127
}

python_bin="$(
  resolve_tool "${project_venv}/bin/python" "python"
)"
cyclonedx_bin="$(
  resolve_tool "${project_venv}/bin/cyclonedx-py" "cyclonedx-py"
)"

mkdir -p "$(dirname "${output_file}")"
PYTHONWARNINGS="ignore:The Component this BOM is describing" \
"${cyclonedx_bin}" requirements \
    requirements/runtime.txt \
    --pyproject pyproject.toml \
    --mc-type application \
    --output-format JSON \
    --output-reproducible \
    --output-file "${output_file}"
"${python_bin}" scripts/finalize_sbom.py "${output_file}"

echo "Generated CycloneDX SBOM: ${output_file}"
