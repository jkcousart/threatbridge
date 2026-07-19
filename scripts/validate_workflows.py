#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW_DIRECTORY = Path(".github/workflows")
ALLOWED_TRIGGERS = frozenset({"pull_request", "push", "schedule", "workflow_dispatch"})
TOP_LEVEL_PERMISSIONS = {"contents": "read"}
CODEQL_JOB_PERMISSIONS = {"contents": "read", "security-events": "write"}
ACTION_LINE = re.compile(
    r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)"
    r"@([0-9a-f]{40})\s+#\s+(v[0-9][A-Za-z0-9_.-]*)\s*$"
)
YAML_BOOLEAN = re.compile(r"^(?:true|false)$", re.IGNORECASE)


class YAML12SafeLoader(yaml.SafeLoader):
    """Safe loader whose boolean behavior matches YAML 1.2 for workflow keys."""


YAML12SafeLoader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern)
        for tag, pattern in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
YAML12SafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", YAML_BOOLEAN, list("tTfF")
)


def workflow_triggers(document: dict[object, object], path: Path) -> set[str]:
    if "on" not in document:
        raise ValueError(f"{path}: workflow requires an actual 'on' trigger key")
    value = document["on"]
    if isinstance(value, str):
        triggers = {value}
    elif isinstance(value, list):
        if not value or not all(isinstance(trigger, str) for trigger in value):
            raise ValueError(f"{path}: workflow trigger list must contain strings")
        triggers = set(value)
    elif isinstance(value, dict):
        if not value or not all(isinstance(trigger, str) for trigger in value):
            raise ValueError(f"{path}: workflow trigger mapping is invalid")
        triggers = set(value)
        for trigger, configuration in value.items():
            if trigger == "schedule":
                valid_schedule = (
                    isinstance(configuration, list)
                    and bool(configuration)
                    and all(
                        isinstance(entry, dict)
                        and set(entry) == {"cron"}
                        and isinstance(entry["cron"], str)
                        and bool(entry["cron"].strip())
                        for entry in configuration
                    )
                )
                if not valid_schedule:
                    raise ValueError(f"{path}: schedule must contain cron mappings")
            elif configuration is not None and not isinstance(configuration, dict):
                raise ValueError(f"{path}: trigger {trigger!r} configuration is invalid")
    else:
        raise ValueError(f"{path}: workflow triggers must be a string, list, or mapping")

    unapproved = sorted(triggers - ALLOWED_TRIGGERS)
    if unapproved:
        raise ValueError(f"{path}: unapproved workflow triggers: {', '.join(unapproved)}")
    return triggers


def validate_permissions(
    document: dict[object, object],
    jobs: dict[object, object],
    path: Path,
) -> None:
    permissions = document.get("permissions")
    if permissions != TOP_LEVEL_PERMISSIONS:
        raise ValueError(
            f"{path}: top-level permissions must be exactly contents: read"
        )

    codeql_expansions = 0
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValueError(f"{path}: job {job_name!r} must be a mapping")
        job_permissions = job.get("permissions")
        if job_permissions is None:
            continue
        if path.name not in {"codeql.yml", "codeql.yaml"}:
            raise ValueError(
                f"{path}: job-level permissions are allowed only for CodeQL"
            )
        if job_permissions != CODEQL_JOB_PERMISSIONS:
            raise ValueError(
                f"{path}: CodeQL job permissions must be exactly contents: read "
                "and security-events: write"
            )
        codeql_expansions += 1

    if path.name in {"codeql.yml", "codeql.yaml"} and codeql_expansions != 1:
        raise ValueError(
            f"{path}: CodeQL requires exactly one approved job-level permission expansion"
        )


def validate_workflow(path: Path) -> int:
    source = path.read_text(encoding="utf-8")
    document = yaml.load(source, Loader=YAML12SafeLoader)
    if not isinstance(document, dict):
        raise ValueError(f"{path}: workflow must contain a YAML mapping")

    workflow_triggers(document, path)
    concurrency = document.get("concurrency")
    if not isinstance(concurrency, (str, dict)) or not concurrency:
        raise ValueError(f"{path}: concurrency controls are required")

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError(f"{path}: at least one job is required")
    validate_permissions(document, jobs, path)
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValueError(f"{path}: job {job_name!r} must be a mapping")
        timeout = job.get("timeout-minutes")
        if type(timeout) is not int or timeout <= 0:
            raise ValueError(
                f"{path}: job {job_name!r} requires a positive integer timeout-minutes"
            )

    action_count = 0
    for line_number, line in enumerate(source.splitlines(), start=1):
        if "uses:" not in line:
            continue
        match = ACTION_LINE.match(line)
        if not match:
            raise ValueError(
                f"{path}:{line_number}: action must use a full SHA and release-tag comment"
            )
        action_count += 1
    return action_count


def validate_workflow_directory(directory: Path = WORKFLOW_DIRECTORY) -> tuple[int, int]:
    workflows = sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    if not workflows:
        raise ValueError("No GitHub workflows found")
    action_count = sum(validate_workflow(path) for path in workflows)
    return len(workflows), action_count


def main() -> None:
    workflow_count, action_count = validate_workflow_directory()
    print(f"Validated {workflow_count} workflows and {action_count} pinned action uses.")


if __name__ == "__main__":
    main()
