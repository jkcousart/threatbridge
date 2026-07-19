#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

NORMALIZE_NAME = re.compile(r"[-_.]+")
REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalized_name(value: str) -> str:
    return NORMALIZE_NAME.sub("-", value).lower()


def direct_dependency_names(pyproject: dict[str, object]) -> set[str]:
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml does not contain [project]")

    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("pyproject.toml project.dependencies must be a list")

    names: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, str):
            raise ValueError("pyproject.toml contains a non-string dependency")
        match = REQUIREMENT_NAME.match(dependency)
        if match is None:
            raise ValueError(f"Cannot parse dependency name: {dependency!r}")
        names.add(normalized_name(match.group(1)))
    return names


def add_root_dependencies(sbom_path: Path) -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    document = json.loads(sbom_path.read_text(encoding="utf-8"))

    component_refs: dict[str, str] = {}
    for component in document.get("components", []):
        if not isinstance(component, dict):
            continue
        name = component.get("name")
        reference = component.get("bom-ref")
        if isinstance(name, str) and isinstance(reference, str):
            component_refs[normalized_name(name)] = reference

    direct_names = direct_dependency_names(pyproject)
    missing = sorted(direct_names - component_refs.keys())
    if missing:
        raise ValueError(
            "Runtime SBOM is missing direct dependencies: " + ", ".join(missing)
        )

    dependencies = document.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("CycloneDX dependencies must be a list")
    dependencies[:] = [
        dependency
        for dependency in dependencies
        if not isinstance(dependency, dict)
        or dependency.get("ref") != "root-component"
    ]
    dependencies.append(
        {
            "dependsOn": sorted(component_refs[name] for name in direct_names),
            "ref": "root-component",
        }
    )
    dependencies.sort(
        key=lambda dependency: str(dependency.get("ref", ""))
        if isinstance(dependency, dict)
        else ""
    )

    sbom_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: finalize_sbom.py SBOM_PATH")
    add_root_dependencies(Path(sys.argv[1]))


if __name__ == "__main__":
    main()
