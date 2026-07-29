#!/usr/bin/env bash
set -euo pipefail

project_venv="${THREATBRIDGE_VENV:-.venv}"
python_bin="${project_venv}/bin/python"
comparison_dir="$(mktemp -d)"
public_candidate_dir="$(mktemp -d)"
trap 'rm -rf "${comparison_dir}" "${public_candidate_dir}"' EXIT

"${python_bin}" scripts/validate_dependency_locks.py
"${python_bin}" scripts/validate_workflows.py
"${project_venv}/bin/ruff" check .
"${python_bin}" manage.py check
"${python_bin}" manage.py makemigrations --check --dry-run
"${project_venv}/bin/pytest" -q
"${python_bin}" -m pip check
"${python_bin}" -m pip_audit --require-hashes --disable-pip -r requirements/runtime.txt
"${python_bin}" -m pip_audit --require-hashes --disable-pip -r requirements/development.txt
"${python_bin}" -m bandit -r catalog integrations threatbridge -x '*/tests/*,*/migrations/*'

./scripts/generate_sbom.sh "${comparison_dir}/threatbridge.cdx.json"
cmp sbom/threatbridge.cdx.json "${comparison_dir}/threatbridge.cdx.json"

trivy_bin="${TRIVY_BIN:-/tmp/threatbridge-trivy-0.70.0/trivy}"
if [[ ! -x "${trivy_bin}" ]]; then
    echo "Trivy is missing. Run scripts/install_trivy.sh, or set" >&2
    echo "THREATBRIDGE_SKIP_TRIVY=1 to record an explicit, documented exception." >&2
    if [[ "${THREATBRIDGE_SKIP_TRIVY:-0}" != "1" ]]; then
        exit 1
    fi
else
    "${trivy_bin}" config \
        --cache-dir "${TRIVY_CACHE_DIR:-/tmp/threatbridge-trivy-cache}" \
        --ignorefile /dev/null \
        --skip-version-check \
        --severity MEDIUM,HIGH,CRITICAL \
        --exit-code 1 \
        --skip-dirs .venv \
        .
fi

gitleaks_bin="${GITLEAKS_BIN:-${HOME}/go/bin/gitleaks}"
mkdir -p "${public_candidate_dir}/source"
git ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' candidate_path; do
        if [[ -e "${candidate_path}" || -L "${candidate_path}" ]]; then
            printf '%s\0' "${candidate_path}"
        fi
    done \
    | tar --null --verbatim-files-from -T - -cf - \
    | tar -xf - -C "${public_candidate_dir}/source"
"${gitleaks_bin}" dir "${public_candidate_dir}/source" \
    --redact --verbose --max-archive-depth=2
git diff --check
