#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

comparison_dir="$(mktemp -d)"
trap 'rm -rf "${comparison_dir}"' EXIT
generated_dir="${comparison_dir}/requirements"
generation_log="${comparison_dir}/pip-compile.log"

if ! ./scripts/update_dependency_locks.sh "${generated_dir}" >"${generation_log}" 2>&1; then
    cat "${generation_log}" >&2
    exit 1
fi

for lock_file in build.in build.txt runtime.txt development.txt; do
    if ! cmp -s "requirements/${lock_file}" "${generated_dir}/${lock_file}"; then
        echo "requirements/${lock_file} is stale; run ./scripts/update_dependency_locks.sh" >&2
        exit 1
    fi
done

echo "Dependency locks match pyproject.toml."
