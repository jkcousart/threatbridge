#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

env_file="${THREATBRIDGE_ENV_FILE:-deploy/.env.production}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${THREATBRIDGE_BACKUP_DIR:-backups/threatbridge/${timestamp}}"
mkdir -p "${backup_dir}"
chmod 0700 "${backup_dir}"

compose=(env THREATBRIDGE_ENV_FILE="${env_file}" bash scripts/production_compose.sh)
running_services="$("${compose[@]}" ps --status running --services | sort)"
expected_services=$'db\nweb'
if [[ "${running_services}" != "${expected_services}" ]]; then
    echo "Expected running services db and web; found:" >&2
    printf '%s\n' "${running_services}" >&2
    exit 1
fi

"${compose[@]}" exec -T db \
    pg_dump -U threatbridge -d threatbridge --format=custom --compress=9 \
    > "${backup_dir}/database.dump"

"${compose[@]}" exec -T web python -c '
import sys
import tarfile
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as archive:
    archive.add("/app/data", arcname="data", recursive=True)
' > "${backup_dir}/application-data.tar.gz"

"${compose[@]}" config > "${backup_dir}/compose.resolved.yml"
web_container="$("${compose[@]}" ps -q web)"
test -n "${web_container}"
docker inspect "${web_container}" > "${backup_dir}/application-container.json"
sha256sum \
    "${backup_dir}/database.dump" \
    "${backup_dir}/application-data.tar.gz" \
    "${backup_dir}/compose.resolved.yml" \
    "${backup_dir}/application-container.json" \
    > "${backup_dir}/SHA256SUMS"

"${compose[@]}" exec -T db \
    pg_restore --list < "${backup_dir}/database.dump" >/dev/null
python3 - "${backup_dir}/application-data.tar.gz" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("application data archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or member.issym()
            or member.islnk()
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(f"unsafe archive member: {member.name}")
PY

printf 'Backup created and structurally validated: %s\n' "${backup_dir}"
