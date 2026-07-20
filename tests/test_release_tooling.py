from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.evaluate_trivy_report import blocking_findings
from scripts.validate_dependency_locks import validate_locks
from scripts.validate_workflows import validate_workflow, validate_workflow_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VALID_WORKFLOW = """\
name: Test
on:
  push:
  pull_request:
permissions:
  contents: read
concurrency:
  group: test
  cancel-in-progress: true
jobs:
  validate:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
"""


def write_workflow(tmp_path: Path, source: str, *, name: str = "workflow.yml") -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_current_workflows_are_valid() -> None:
    workflow_count, action_count = validate_workflow_directory(
        PROJECT_ROOT / ".github" / "workflows"
    )
    assert workflow_count == 5
    assert action_count == 11


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (VALID_WORKFLOW.replace("on:\n  push:\n  pull_request:\n", ""), "actual 'on'"),
        (
            VALID_WORKFLOW.replace("  pull_request:\n", "  pull_request_target:\n"),
            "unapproved workflow triggers",
        ),
        (VALID_WORKFLOW.replace("permissions:\n  contents: read\n", ""), "permissions"),
        (
            VALID_WORKFLOW.replace(
                "concurrency:\n  group: test\n  cancel-in-progress: true\n", ""
            ),
            "concurrency",
        ),
        (VALID_WORKFLOW.replace("    timeout-minutes: 10\n", ""), "timeout-minutes"),
        (
            VALID_WORKFLOW.replace(
                "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
                "actions/checkout@v6 # v6.0.2",
            ),
            "full SHA",
        ),
        (
            VALID_WORKFLOW.replace(
                "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
                "actions/checkout@not-a-reference",
            ),
            "full SHA",
        ),
    ],
)
def test_invalid_workflow_policy_is_rejected(
    tmp_path: Path, source: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_workflow(write_workflow(tmp_path, source))


def test_yaml_12_loader_preserves_on_as_trigger_key(tmp_path: Path) -> None:
    assert validate_workflow(write_workflow(tmp_path, VALID_WORKFLOW)) == 1


@pytest.mark.parametrize(
    "permissions_source",
    [
        "permissions: read-all",
        "permissions: write-all",
        "permissions:\n  contents: write",
        "permissions:\n  contents: read\n  issues: read",
        "permissions:\n  contents: true",
        "permissions:\n  unknown-scope: read",
    ],
)
def test_invalid_top_level_workflow_permissions_are_rejected(
    tmp_path: Path, permissions_source: str
) -> None:
    source = VALID_WORKFLOW.replace(
        "permissions:\n  contents: read", permissions_source
    )
    with pytest.raises(ValueError, match="top-level permissions"):
        validate_workflow(write_workflow(tmp_path, source))


def codeql_workflow(job_permissions: str) -> str:
    return VALID_WORKFLOW.replace(
        "  validate:\n    runs-on:",
        f"  validate:\n    permissions:\n{job_permissions}\n    runs-on:",
    )


def test_only_codeql_may_add_security_event_write_permission(tmp_path: Path) -> None:
    source = codeql_workflow("      contents: read\n      security-events: write")
    assert validate_workflow(write_workflow(tmp_path, source, name="codeql.yml")) == 1


def test_non_codeql_job_level_permissions_are_rejected(tmp_path: Path) -> None:
    source = codeql_workflow("      contents: read\n      security-events: write")
    with pytest.raises(ValueError, match="only for CodeQL"):
        validate_workflow(write_workflow(tmp_path, source))


@pytest.mark.parametrize(
    "job_permissions",
    [
        "      contents: write\n      security-events: write",
        "      contents: read\n      security-events: read",
        "      contents: read\n      security-events: write\n      actions: read",
        "      contents: read\n      security-events: invalid",
        "      write-all: true",
    ],
)
def test_codeql_cannot_expand_other_job_permissions(
    tmp_path: Path, job_permissions: str
) -> None:
    with pytest.raises(ValueError, match="CodeQL job permissions"):
        validate_workflow(
            write_workflow(
                tmp_path,
                codeql_workflow(job_permissions),
                name="codeql.yml",
            )
        )


def copy_lock_inputs(tmp_path: Path) -> Path:
    shutil.copy(PROJECT_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copytree(PROJECT_ROOT / "requirements", tmp_path / "requirements")
    return tmp_path


def remove_locked_package(path: Path, package_name: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith(f"{package_name}==")
    )
    end = start + 1
    while end < len(lines) and lines[end][0].isspace():
        end += 1
    path.write_text("".join(lines[:start] + lines[end:]), encoding="utf-8")


def test_committed_dependency_locks_are_statically_valid() -> None:
    counts = validate_locks(PROJECT_ROOT)
    assert counts["build"] > 0
    assert counts["runtime"] > 0
    assert counts["development"] >= counts["runtime"]


@pytest.mark.parametrize(
    ("relative_path", "old", "new", "message"),
    [
        ("requirements/runtime.txt", "asgiref==", "asgiref>=", "exactly pinned"),
        (
            "requirements/runtime.txt",
            "--hash=sha256:",
            "--hash=sha512:",
            "malformed hash",
        ),
        (
            "requirements/runtime.txt",
            "\nasgiref==",
            "\n--index-url https://packages.example.invalid/simple\nasgiref==",
            "prohibited dependency source",
        ),
        (
            "requirements/runtime.txt",
            "# Generated by scripts/update_dependency_locks.sh",
            "# Hand edited",
            "generated-file metadata",
        ),
        (
            "pyproject.toml",
            'dependencies = [\n  "Django>=5.2,<7",',
            'dependencies = [\n  "missing-example-package>=1",\n  "Django>=5.2,<7",',
            "missing direct dependencies",
        ),
    ],
)
def test_invalid_dependency_lock_is_rejected(
    tmp_path: Path,
    relative_path: str,
    old: str,
    new: str,
    message: str,
) -> None:
    root = copy_lock_inputs(tmp_path)
    path = root / relative_path
    source = path.read_text(encoding="utf-8")
    assert old in source
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        validate_locks(root)


def test_development_lock_cannot_omit_runtime_transitive_dependency(
    tmp_path: Path,
) -> None:
    root = copy_lock_inputs(tmp_path)
    remove_locked_package(root / "requirements/development.txt", "asgiref")
    with pytest.raises(ValueError, match="missing runtime packages: asgiref"):
        validate_locks(root)


def test_development_lock_runtime_version_must_match(tmp_path: Path) -> None:
    root = copy_lock_inputs(tmp_path)
    path = root / "requirements/development.txt"
    source = path.read_text(encoding="utf-8")
    path.write_text(source.replace("asgiref==3.12.1", "asgiref==3.12.0", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime package asgiref has version 3.12.0"):
        validate_locks(root)


def test_development_lock_retains_runtime_artifact_hashes(tmp_path: Path) -> None:
    root = copy_lock_inputs(tmp_path)
    path = root / "requirements/development.txt"
    source = path.read_text(encoding="utf-8")
    hash_to_remove = (
        "    --hash=sha256:59dcb51c272ad209d59bed5708a64a333083e86017"
        "d7fcdd67498eeab7784340 \\\n"
    )
    path.write_text(
        source.replace(hash_to_remove, "", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing compatible SHA-256 hashes"):
        validate_locks(root)


def test_docker_final_stage_uses_only_the_installed_wheel() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG PYTHON_BUILDER_IMAGE=" in dockerfile
    assert "ARG PYTHON_RUNTIME_IMAGE=" in dockerfile
    marker = "FROM ${PYTHON_RUNTIME_IMAGE} AS runtime"
    assert marker in dockerfile
    final_stage = dockerfile.split(marker, 1)[1]
    assert "COPY . ." not in final_stage
    assert (
        "COPY --from=builder --chown=65532:65532 "
        "/opt/runtime-venv /opt/runtime-venv"
    ) in final_stage
    assert "COPY --from=builder --chown=65532:65532 /runtime/app /app" in final_stage
    assert "USER 65532:65532" in final_stage
    assert "ENTRYPOINT []" in final_stage
    assert "\nRUN " not in final_stage
    assert "sysconfig.get_paths()" in dockerfile

    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'exclude = ["*.tests", "*.tests.*"]' in pyproject


def test_generated_image_evidence_stays_out_of_source_candidate() -> None:
    assert not (PROJECT_ROOT / "sbom" / "threatbridge-image.cdx.json").exists()

    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "release-evidence/" in gitignore.splitlines()
    assert "release-evidence" in dockerignore.splitlines()

    image_sbom_script = (PROJECT_ROOT / "scripts/generate_image_sbom.sh").read_text(
        encoding="utf-8"
    )
    image_scan_script = (PROJECT_ROOT / "scripts/scan_container_image.sh").read_text(
        encoding="utf-8"
    )
    assert "release-evidence/threatbridge-image.cdx.json" in image_sbom_script
    assert "release-evidence/threatbridge-image-vulnerabilities.json" in image_scan_script

    security_check = (PROJECT_ROOT / "scripts/security_check.sh").read_text(
        encoding="utf-8"
    )
    assert "git ls-files -z --cached --others --exclude-standard" in security_check
    assert '"${gitleaks_bin}" dir "${public_candidate_dir}/source"' in security_check


def test_trivy_report_without_high_findings_is_not_blocking(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        '{"Results":[{"Target":"image","Vulnerabilities":'
        '[{"Severity":"MEDIUM","VulnerabilityID":"CVE-example"}]}]}',
        encoding="utf-8",
    )
    assert blocking_findings(report) == []


def test_trivy_report_retains_fixed_and_unfixed_blockers(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        """{
          "Results": [{
            "Target": "debian",
            "Vulnerabilities": [
              {
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-fixed",
                "PkgName": "package-a",
                "InstalledVersion": "1",
                "FixedVersion": "2"
              },
              {
                "Severity": "CRITICAL",
                "VulnerabilityID": "CVE-unfixed",
                "PkgName": "package-b",
                "InstalledVersion": "3"
              }
            ]
          }]
        }""",
        encoding="utf-8",
    )
    findings = blocking_findings(report)
    assert {finding["id"] for finding in findings} == {"CVE-fixed", "CVE-unfixed"}
    assert next(finding for finding in findings if finding["id"] == "CVE-fixed")[
        "fixed"
    ] == "2"
    assert next(finding for finding in findings if finding["id"] == "CVE-unfixed")[
        "fixed"
    ] == "none published"
