#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import secrets
import stat
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_ENV = ROOT / "deploy" / ".env.production.example"
DEFAULT_ENV = ROOT / "deploy" / ".env.production"
DEFAULT_SECRETS = ROOT / "deploy" / "secrets"


# Compose outside swarm bind-mounts a file-backed secret with the host file's ownership
# and mode, and ignores the `uid`, `gid`, and `mode` options. The container runs as
# 65532, which cannot be chowned to without root, so the file itself has to be
# world-readable for the application to read its own secret. Confidentiality therefore
# rests on the 0700 secrets directory: no unprivileged host user can traverse into it, so
# the permissive file mode is unreachable. SECRET_FILE_MODE is read-only for everyone,
# which also stops the container from rewriting its own credentials.
SECRET_DIRECTORY_MODE = 0o700
SECRET_FILE_MODE = 0o444


def ensure_secret_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=SECRET_DIRECTORY_MODE)
    directory.chmod(SECRET_DIRECTORY_MODE)
    mode = stat.S_IMODE(directory.stat().st_mode)
    if mode != SECRET_DIRECTORY_MODE:
        raise SystemExit(f"Refusing secrets directory {directory} with mode {mode:o}; expected 700")


def ensure_secret(path: Path, value: str, *, force: bool) -> str:
    ensure_secret_directory(path.parent)
    if path.is_symlink():
        raise SystemExit(f"Refusing symlink secret path: {path}")
    if path.exists() and not force:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"Refusing non-regular secret path: {path}")
        mode = stat.S_IMODE(metadata.st_mode)
        # Readable is required; writable by anyone other than the owner is not.
        if mode & 0o022:
            raise SystemExit(f"Refusing writable existing secret permissions on {path}: {mode:o}")
        existing = path.read_text(encoding="utf-8").strip()
        if not existing:
            raise SystemExit(f"Refusing empty existing secret: {path}")
        # Re-mode an existing secret created before the container-readable policy so an
        # in-place upgrade does not silently keep failing at startup.
        path.chmod(SECRET_FILE_MODE)
        return existing
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    descriptor = os.open(path, open_flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
        secret_file.write(value)
        secret_file.write("\n")
    path.chmod(SECRET_FILE_MODE)
    return value


def replace_env_value(source: str, key: str, value: str) -> str:
    prefix = f"{key}="
    lines = source.splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(matches) != 1:
        raise SystemExit(f"Expected one {key} entry in {EXAMPLE_ENV}; found {len(matches)}")
    lines[matches[0]] = f"{key}={value}"
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--outbound-host", action="append", required=True)
    parser.add_argument("--private-cidr", action="append", default=[])
    parser.add_argument("--port", type=int, default=8020)
    parser.add_argument("--hsts-seconds", type=int, default=3600)
    parser.add_argument("--time-zone", default="America/Edmonton")
    parser.add_argument("--extra-ca-path", type=Path)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--secrets-dir", type=Path, default=DEFAULT_SECRETS)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.port < 1 or args.port > 65535:
        raise SystemExit("--port must be between 1 and 65535")
    if args.hsts_seconds < 0:
        raise SystemExit("--hsts-seconds must be non-negative")
    hostname = args.hostname.strip().rstrip(".")
    if (
        not hostname
        or any(character.isspace() for character in hostname)
        or any(character in hostname for character in "*/@:")
        or hostname.startswith(".")
    ):
        raise SystemExit("--hostname must be one exact hostname without a scheme or port")
    try:
        hostname.encode("idna")
    except UnicodeError as exc:
        raise SystemExit("--hostname is not a valid hostname") from exc
    try:
        bind_address = ip_address(args.bind_address)
    except ValueError as exc:
        raise SystemExit("--bind-address must be one IP address") from exc
    if bind_address.is_unspecified or bind_address.is_multicast:
        raise SystemExit("--bind-address must identify a usable host interface")
    outbound_hosts = []
    for value in args.outbound_host:
        candidate = value.strip().rstrip(".")
        if (
            not candidate
            or "," in candidate
            or any(character.isspace() for character in candidate)
            or any(character in candidate for character in "*/@")
            or candidate.startswith(".")
        ):
            raise SystemExit("Each --outbound-host must be one exact host or IP literal")
        try:
            ip_address(candidate.strip("[]"))
        except ValueError:
            if ":" in candidate:
                raise SystemExit("Outbound hostnames must not include a port") from None
            try:
                candidate.encode("idna")
            except UnicodeError as exc:
                raise SystemExit("Invalid --outbound-host") from exc
        outbound_hosts.append(candidate)
    private_cidrs = []
    for value in args.private_cidr:
        try:
            private_cidrs.append(str(ip_network(value, strict=True)))
        except ValueError as exc:
            raise SystemExit(f"Invalid strict --private-cidr: {value}") from exc
    try:
        ZoneInfo(args.time_zone)
    except ZoneInfoNotFoundError as exc:
        raise SystemExit(f"Unknown --time-zone: {args.time_zone}") from exc

    env_file = args.env_file.expanduser().resolve()
    secrets_dir = args.secrets_dir.expanduser().resolve()
    if env_file.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing {env_file}; use --force intentionally")

    ensure_secret(
        secrets_dir / "django-secret-key",
        secrets.token_urlsafe(64),
        force=args.force,
    )
    postgres_password = ensure_secret(
        secrets_dir / "postgres-password",
        secrets.token_urlsafe(48),
        force=args.force,
    )
    database_url = (
        "postgresql://threatbridge:"
        f"{quote(postgres_password, safe='')}@db:5432/threatbridge"
    )
    stored_database_url = ensure_secret(
        secrets_dir / "database-url",
        database_url,
        force=args.force,
    )
    if stored_database_url != database_url:
        raise SystemExit(
            "Existing database-url does not match the preserved postgres-password; "
            "repair the pair explicitly or use --force to rotate both"
        )

    source = EXAMPLE_ENV.read_text(encoding="utf-8")
    replacements = {
        "THREATBRIDGE_SECRETS_DIR": str(secrets_dir),
        "THREATBRIDGE_BIND_ADDRESS": str(bind_address),
        "THREATBRIDGE_PORT": str(args.port),
        "DJANGO_ALLOWED_HOSTS": hostname,
        "DJANGO_CSRF_TRUSTED_ORIGINS": f"https://{hostname}",
        "DJANGO_SECURE_HSTS_SECONDS": str(args.hsts_seconds),
        "DJANGO_TIME_ZONE": args.time_zone,
        "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS": ",".join(outbound_hosts),
        "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS": ",".join(private_cidrs),
        "THREATBRIDGE_USE_EXTRA_CA": "true" if args.extra_ca_path else "false",
    }
    if args.extra_ca_path:
        extra_ca_path = args.extra_ca_path.expanduser().resolve()
        if not extra_ca_path.is_file() or extra_ca_path.is_symlink():
            raise SystemExit("--extra-ca-path must be an existing regular non-symlink file")
        # Compose mounts this file with the host mode and ignores the overlay's uid/gid/
        # mode, so an operator-only mode leaves the container unable to load the trust
        # anchor. A CA certificate is public material, so world-readable costs nothing.
        ca_mode = stat.S_IMODE(extra_ca_path.stat().st_mode)
        if not ca_mode & 0o004:
            raise SystemExit(
                f"--extra-ca-path {extra_ca_path} has mode {ca_mode:o} and would not be "
                "readable by the container user 65532; run "
                f"chmod 0444 {extra_ca_path} (a CA certificate is not secret)"
            )
        if ca_mode & 0o022:
            raise SystemExit(
                f"--extra-ca-path {extra_ca_path} has mode {ca_mode:o}; it must not be "
                "group- or world-writable"
            )
        replacements["THREATBRIDGE_EXTRA_CA_PATH"] = str(extra_ca_path)
    for key, value in replacements.items():
        source = replace_env_value(source, key, value)

    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text(source, encoding="utf-8")
    env_file.chmod(0o600)

    print(f"Created production environment: {env_file}")
    print(f"Created or preserved secret directory: {secrets_dir}")
    print("Next: bash scripts/resolve_production_images.sh")


if __name__ == "__main__":
    main()
