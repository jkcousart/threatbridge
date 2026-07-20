#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: CONFIRM=RESTORE_THREATBRIDGE restore_production.sh BACKUP_DIRECTORY" >&2
    exit 2
fi
if [[ "${CONFIRM:-}" != "RESTORE_THREATBRIDGE" ]]; then
    echo "Refusing destructive restore without CONFIRM=RESTORE_THREATBRIDGE" >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"
backup_dir="$(realpath "$1")"
env_file="${THREATBRIDGE_ENV_FILE:-deploy/.env.production}"

for required in database.dump application-data.tar.gz SHA256SUMS; do
    test -f "${backup_dir}/${required}" || {
        echo "Missing ${backup_dir}/${required}" >&2
        exit 1
    }
done
(cd "${backup_dir}" && sha256sum --check SHA256SUMS)

compose=(env THREATBRIDGE_ENV_FILE="${env_file}" bash scripts/production_compose.sh)
"${compose[@]}" stop web

"${compose[@]}" exec -T db dropdb --force --if-exists -U threatbridge threatbridge
"${compose[@]}" exec -T db createdb -U threatbridge -O threatbridge threatbridge
"${compose[@]}" exec -T db \
    pg_restore -U threatbridge -d threatbridge --no-owner --exit-on-error \
    < "${backup_dir}/database.dump"
"${compose[@]}" run --rm migrate

"${compose[@]}" run --rm --no-deps --entrypoint python web -c '
import pathlib
import shutil
import sys
import tarfile
from pathlib import PurePosixPath

root = pathlib.Path("/app/data")
root.mkdir(parents=True, exist_ok=True)
for child in root.iterdir():
    if child.is_dir() and not child.is_symlink():
        shutil.rmtree(child)
    else:
        child.unlink()
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|gz") as archive:
    for member in archive:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or member.issym()
            or member.islnk()
            or not (member.isfile() or member.isdir())
        ):
            raise SystemExit(f"unsafe archive member: {member.name}")
        archive.extract(member, "/app", filter="data")
' < "${backup_dir}/application-data.tar.gz"

"${compose[@]}" up -d web
for attempt in $(seq 1 30); do
    if "${compose[@]}" exec -T web python -c \
        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).read()";
    then
        echo "Restore completed and readiness passed."
        exit 0
    fi
    sleep 2
done

echo "Restore completed, but readiness did not pass within 60 seconds." >&2
exit 1
