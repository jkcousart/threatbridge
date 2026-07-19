import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBOM_GENERATOR = ROOT / "scripts" / "generate_sbom.sh"


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _install_fake_tools(bin_dir: Path) -> None:
    _write_executable(
        bin_dir / "cyclonedx-py",
        """#!/usr/bin/env bash
set -euo pipefail

printf 'cyclonedx=%s\\n' "$0" >> "${TRACE_FILE:?}"

output_file=""

while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output-file" ]]; then
    output_file="$2"
    shift 2
    continue
  fi

  shift
done

test -n "${output_file}"
printf '{"components":[]}\\n' > "${output_file}"
""",
    )

    _write_executable(
        bin_dir / "python",
        """#!/usr/bin/env bash
set -euo pipefail

printf 'python=%s\\n' "$0" >> "${TRACE_FILE:?}"

test "$1" = "scripts/finalize_sbom.py"
test -f "$2"
""",
    )


def _run_generator(
    tmp_path: Path,
    *,
    project_venv: Path,
    path_bin: Path,
) -> list[str]:
    trace_file = tmp_path / "tool-trace.txt"
    output_file = tmp_path / "generated.cdx.json"

    environment = os.environ.copy()
    environment["THREATBRIDGE_VENV"] = str(project_venv)
    environment["TRACE_FILE"] = str(trace_file)
    environment["PATH"] = (
        f"{path_bin}{os.pathsep}{environment.get('PATH', '')}"
    )

    result = subprocess.run(
        ["bash", str(SBOM_GENERATOR), str(output_file)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, (
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert output_file.exists()

    return trace_file.read_text(encoding="utf-8").splitlines()


def test_workflow_validator_is_run_through_python() -> None:
    workflows = sorted(
        (ROOT / ".github" / "workflows").glob("*.y*ml")
    )
    contents = [
        path.read_text(encoding="utf-8")
        for path in workflows
    ]

    assert all(
        "./scripts/validate_workflows.py" not in text
        for text in contents
    )
    assert any(
        "python scripts/validate_workflows.py" in text
        for text in contents
    )


def test_sbom_generator_prefers_virtual_environment_tools(
    tmp_path: Path,
) -> None:
    project_venv = tmp_path / "project-venv"
    path_bin = tmp_path / "path-bin"

    _install_fake_tools(project_venv / "bin")
    _install_fake_tools(path_bin)

    trace = _run_generator(
        tmp_path,
        project_venv=project_venv,
        path_bin=path_bin,
    )

    assert trace == [
        f"cyclonedx={project_venv / 'bin' / 'cyclonedx-py'}",
        f"python={project_venv / 'bin' / 'python'}",
    ]


def test_sbom_generator_uses_hosted_path_tools(
    tmp_path: Path,
) -> None:
    missing_venv = tmp_path / "missing-venv"
    path_bin = tmp_path / "hosted-path-bin"

    _install_fake_tools(path_bin)

    trace = _run_generator(
        tmp_path,
        project_venv=missing_venv,
        path_bin=path_bin,
    )

    assert trace == [
        f"cyclonedx={path_bin / 'cyclonedx-py'}",
        f"python={path_bin / 'python'}",
    ]


def test_sbom_generator_documents_clear_missing_tool_error() -> None:
    text = SBOM_GENERATOR.read_text(encoding="utf-8")

    assert "Required tool not found: %s" in text
    assert "checked %s and PATH" in text
