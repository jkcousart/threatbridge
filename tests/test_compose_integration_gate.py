"""Policy tests for the production Compose integration gate.

The gate itself is the thing that proves the deployment works; these tests prove the gate
cannot quietly stop checking something. They therefore assert the presence of specific
checks rather than re-running the stack, which is what `scripts/validate_production_compose.sh`
does and what CI invokes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from scripts.validate_workflows import YAML12SafeLoader

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_production_compose.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "compose-integration.yml"


@pytest.fixture(scope="module")
def script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow() -> dict:
    # YAML 1.1 resolves the `on:` key to the boolean True, which is not what GitHub reads.
    # The project already carries a 1.2-compatible loader for exactly this.
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=YAML12SafeLoader)


def test_script_is_executable_and_fails_closed(script: str) -> None:
    assert SCRIPT.stat().st_mode & 0o111, "the gate must be executable"
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    # A bare failure with no message is the least useful outcome for a gate.
    assert "trap 'report_unexpected_failure" in script
    for suppression in ("|| true\nlog", "set +e", "continue-on-error"):
        assert suppression not in script, suppression


def test_cleanup_trap_is_installed_before_anything_is_started(script: str) -> None:
    """An interrupted run must not leave containers, volumes, or secrets behind."""

    trap_position = script.index("trap cleanup EXIT INT TERM")
    for later_action in (
        '--tag "${image_tag}"',
        "compose up -d",
        "prepare_production_deployment.py",
    ):
        assert script.index(later_action) > trap_position, later_action

    # The temporary directory necessarily comes first, because cleanup removes it. Nothing
    # else may: between creating it and arming the trap there must be no container, image,
    # or secret, or a failure in that window would leak one.
    setup_window = script[script.index("mktemp -d") : trap_position]
    for premature in ("docker ", "compose ", "prepare_production_deployment", "openssl "):
        assert premature not in setup_window, premature

    assert "down --volumes --remove-orphans" in script
    # Teardown must not depend on reaching the end of the happy path.
    assert "cleanup() {" in script
    assert script.index("cleanup() {") < trap_position


def test_teardown_removes_volumes_orphans_and_the_disposable_directory(script: str) -> None:
    assert "compose down --volumes --remove-orphans" in script
    assert 'rm -rf "${test_root}"' in script
    # Preserving artifacts has to be an explicit opt-in, never the default.
    assert "THREATBRIDGE_KEEP_INTEGRATION_ARTIFACTS:-0" in script
    assert 'if [[ "${keep_artifacts}" == "1" ]]' in script


def test_gate_uses_a_disposable_environment_and_never_the_repository_state(
    script: str,
) -> None:
    assert "mktemp -d /tmp/threatbridge-compose-integration-XXXXXXXX" in script
    assert 'chmod 700 "${test_root}"' in script
    assert 'env_file="${test_root}/.env.production"' in script
    assert 'secrets_dir="${test_root}/secrets"' in script
    # Each of these is repository or host state the gate must never read.
    for private_path in (
        "deploy/.env.production",
        "deploy/secrets",
        "/.env",
        "/.secrets",
        "db.sqlite3",
    ):
        assert private_path in script, private_path
    assert "refusing to use" in script


def test_gate_publishes_only_on_loopback_with_test_only_names(script: str) -> None:
    assert "--bind-address 127.0.0.1" in script
    assert "--hostname threatbridge.localhost" in script
    assert "--outbound-host opencti.example.invalid" in script
    # No routable name may appear as a target.
    assert re.search(r"--hostname\s+\S*\.(?:com|net|org)\b", script) is None
    assert 'binding["host_ip"] != "127.0.0.1"' in script
    assert "not loopback" in script
    assert 'probe.bind(("127.0.0.1", 0))' in script


def test_gate_requires_its_prerequisites_rather_than_skipping(script: str) -> None:
    for binary in ("docker", "python3", "curl", "openssl"):
        assert binary in script, binary
    assert "docker compose version" in script
    assert "docker buildx version" in script
    assert "unmet prerequisites; nothing was started" in script
    # Missing tooling must fail, never silently skip a phase.
    assert "skip" not in script.lower().replace("skip-version-check", "")


def test_gate_builds_the_committed_default_and_refuses_a_substituted_base(
    script: str,
) -> None:
    assert "ARG {argument}" in script or "ARG PYTHON" in script
    assert "the gate must test the" in script
    assert "committed base, not a substituted one" in script
    # A --build-arg for either base would defeat the purpose of the comparison above.
    assert "--build-arg PYTHON_BUILDER_IMAGE" not in script
    assert "--build-arg PYTHON_RUNTIME_IMAGE" not in script


def test_image_validation_sbom_and_unsuppressed_scan_are_mandatory(script: str) -> None:
    for required in (
        "bash scripts/validate_container_image.sh",
        "bash scripts/generate_image_sbom.sh",
        "bash scripts/scan_container_image.sh",
    ):
        assert required in script, required
    # The scan script fails on any HIGH or CRITICAL; the gate must not route around it.
    assert "--severity" not in script
    assert "ignorefile" not in script


def test_gate_bounds_every_wait(script: str) -> None:
    assert "HEALTH_TIMEOUT_SECONDS" in script
    assert "THREATBRIDGE_HEALTH_TIMEOUT_SECONDS:-180" in script
    assert script.count("deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))") >= 3
    assert "did not finish within" in script
    assert "stayed ${health} for" in script
    # An unhealthy verdict must fail immediately rather than waiting out the timeout.
    assert "unhealthy) fail" in script


def test_gate_reports_redacted_diagnostics_on_failure(script: str) -> None:
    assert "dump_failure_diagnostics" in script
    assert "redact_stream" in script
    # Reuses the application's own redaction rather than a bespoke pattern.
    assert "from threatbridge.log_redaction import redact" in script
    assert "compose logs --no-color --tail 60" in script


@pytest.mark.parametrize(
    "requirement",
    [
        # Runtime identity and confinement.
        '[[ "${user}" == "65532:65532" ]]',
        '[[ "${read_only}" == "true" ]]',
        '[[ "${privileged}" == "false" ]]',
        "no-new-privileges:true",
        'cap_drop}" == \'["ALL"]\'',
        "adds capabilities",
        "EXPECTED_APP_PIDS_LIMIT=256",
        "EXPECTED_DB_PIDS_LIMIT=512",
        "NoNewPrivs",
        "CapEff",
        "CapPrm",
        "CapBnd",
        # Writable surface.
        "writable paths are exactly /tmp and /app/data",
        "tmpfs is missing",
        # Networking and exposure.
        "network_mode: none",
        "mounts the Docker socket",
        "/var/run/docker.sock",
        "the database must not publish a port",
        "the database network must be internal",
        "no external DNS resolution",
        # HTTP contract.
        "expected 200",
        "expected 301",
        "expected 400",
        "inherit the image healthcheck rather than redefining it",
    ],
)
def test_required_runtime_assertions_are_present(script: str, requirement: str) -> None:
    assert requirement in script, requirement


def test_private_ca_phase_covers_readable_and_unreadable_cases(script: str) -> None:
    assert "openssl req -x509" in script
    # The application never needs the key, so it must not survive to be mounted.
    assert 'rm -f "${ca_private_key}"' in script
    assert "the generated CA file contains a private key" in script
    assert 'chmod 0444 "${ca_certificate}"' in script
    assert "--extra-ca-path" in script
    # Readable: loads, and extends public trust rather than replacing it.
    assert "private CA is absent" in script
    assert "baseline_trust_anchors + 1" in script
    assert "must extend public trust, not replace it" in script
    # Verification stays on throughout.
    assert "CERT_REQUIRED" in script
    assert "context.check_hostname is True" in script
    assert "disables verification through" in script
    # Unreadable: the gate must refuse to start.
    assert 'chmod 0600 "${ca_certificate}"' in script
    assert "the stack started with an unreadable private CA" in script
    assert "Unable to read THREATBRIDGE_EXTRA_CA_FILE" in script
    assert "web served despite the failed deployment gate" in script


def test_gate_never_disables_tls_verification(script: str) -> None:
    """The gate may name insecure settings only to reject them, never to use them."""

    forbidden_terms = ("verify=false", "--insecure", "curl -k ", "cert_none", "verify_ssl")
    for number, line in enumerate(script.splitlines(), start=1):
        lowered = line.lower()
        # Lines that build the rejection list are the point of the check, not a violation.
        if "forbidden" in lowered or "raise systemexit" in lowered:
            continue
        for term in forbidden_terms:
            assert term not in lowered, (number, term, line.strip())


def test_gate_offers_a_base_only_mode_without_weakening_the_default(script: str) -> None:
    assert "all | base | step-ca)" in script
    assert 'mode="${1:-all}"' in script
    # Default must be the complete run, and the base phase must say it was partial.
    assert "base phase only" in script


def test_workflow_runs_on_pull_requests_and_main(workflow: dict) -> None:
    triggers = workflow["on"]
    assert set(triggers) == {"push", "pull_request", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    # An unfiltered pull_request trigger keeps the gate on every proposed change.
    assert triggers["pull_request"] is None


def test_workflow_has_minimal_permissions_and_no_privileged_trigger(
    workflow: dict,
) -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert workflow["permissions"] == {"contents": "read"}
    for job in workflow["jobs"].values():
        assert "permissions" not in job
    assert "pull_request_target" not in source
    assert "secrets." not in source
    assert workflow["concurrency"]["cancel-in-progress"] is True


def test_workflow_pins_every_action_to_a_full_sha() -> None:
    uses = [
        line.strip()
        for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
        if "uses:" in line
    ]
    assert uses, "the workflow must use at least one action"
    for line in uses:
        assert re.fullmatch(
            r"-?\s*uses:\s*[\w.-]+/[\w.-]+(?:/[\w.-]+)?@[0-9a-f]{40}\s+#\s+v[\w.-]+",
            line,
        ), line


def test_workflow_invokes_the_authoritative_script_and_bounds_the_run(
    workflow: dict,
) -> None:
    job = workflow["jobs"]["integration"]
    assert job["timeout-minutes"] > 0
    assert job["runs-on"].startswith("ubuntu-")
    steps = job["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    # CI must run the same entry point a developer runs, not a reimplementation.
    assert "bash scripts/validate_production_compose.sh" in commands
    assert "scripts/validate_dependency_locks.py" in commands
    assert "scripts/validate_workflows.py" in commands
    assert "scripts/install_trivy.sh" in commands
    # Building is expected; publishing is not.
    for forbidden in ("docker push", "docker login", "ghcr.io", "registry", "--push"):
        assert forbidden not in commands, forbidden


def test_workflow_uploads_diagnostics_only_on_failure(workflow: dict) -> None:
    steps = workflow["jobs"]["integration"]["steps"]
    diagnostic_steps = [step for step in steps if "diagnostics" in step.get("name", "").lower()]
    assert diagnostic_steps, "failure diagnostics should be collected"
    for step in diagnostic_steps:
        assert step.get("if") == "failure()", step.get("name")
    upload = next(step for step in diagnostic_steps if "uses" in step)
    assert upload["with"]["retention-days"] <= 7
    # Container logs are redacted by the script on stdout; re-collecting them into an
    # artifact would risk uploading an unredacted copy.
    collect = next(step for step in diagnostic_steps if "run" in step)
    assert "docker compose logs" not in collect["run"]
    assert "docker logs" not in collect["run"]
