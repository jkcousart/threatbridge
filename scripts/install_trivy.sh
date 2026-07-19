#!/usr/bin/env bash
set -euo pipefail

trivy_version="0.70.0"
archive_sha256="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
destination="${1:-/tmp/threatbridge-trivy-${trivy_version}}"
binary="${destination}/trivy"

if [[ -x "${binary}" ]] && "${binary}" --version | grep -Fxq "Version: ${trivy_version}"; then
    printf 'Trivy %s is already installed at %s\n' "${trivy_version}" "${binary}"
    exit 0
fi

download_dir="$(mktemp -d)"
trap 'rm -rf "${download_dir}"' EXIT
archive="${download_dir}/trivy.tar.gz"
url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/trivy_${trivy_version}_Linux-64bit.tar.gz"

mkdir -p "${destination}"
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
    --output "${archive}" "${url}"
printf '%s  %s\n' "${archive_sha256}" "${archive}" | sha256sum --check --status
tar -xzf "${archive}" -C "${destination}" trivy
chmod 0755 "${binary}"
"${binary}" --version | grep -Fx "Version: ${trivy_version}"
printf 'Installed checksum-verified Trivy %s at %s\n' "${trivy_version}" "${binary}"
