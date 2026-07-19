#!/usr/bin/env bash
set -euo pipefail

project_venv="${THREATBRIDGE_VENV:-.venv}"
python_bin="${project_venv}/bin/python"

"${project_venv}/bin/ruff" check .
"${python_bin}" manage.py check
"${python_bin}" manage.py makemigrations --check --dry-run
"${project_venv}/bin/pytest" -q
"${python_bin}" -m pip check
"${python_bin}" -m pip_audit
"${python_bin}" -m bandit -r catalog integrations threatbridge -x '*/tests/*,*/migrations/*'

gitleaks_bin="${GITLEAKS_BIN:-${HOME}/go/bin/gitleaks}"
"${gitleaks_bin}" dir . --redact --verbose --max-archive-depth=2
git diff --check
