#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import stat
from pathlib import Path

KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def read_environment(path: Path) -> dict[str, str]:
    if path.is_symlink():
        raise ValueError(f"{path}: environment file must not be a symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ValueError(f"{path}: unable to inspect environment file") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{path}: environment file must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(f"{path}: environment file must not be group- or world-writable")

    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"{path}: unable to read environment file") from exc
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        if not KEY_PATTERN.fullmatch(key):
            raise ValueError(f"{path}:{line_number}: invalid environment key")
        if key in values:
            raise ValueError(f"{path}:{line_number}: duplicate environment key {key}")
        if any(character in value for character in ("\x00", "\r", "\n")):
            raise ValueError(f"{path}:{line_number}: invalid control character")
        values[key] = value
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("key")
    parser.add_argument("--required", action="store_true")
    args = parser.parse_args()

    if not KEY_PATTERN.fullmatch(args.key):
        raise SystemExit("Requested key is invalid")
    try:
        values = read_environment(args.path)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    value = values.get(args.key, "")
    if args.required and not value:
        raise SystemExit(f"Missing required {args.key} in {args.path}")
    print(value)


if __name__ == "__main__":
    main()
