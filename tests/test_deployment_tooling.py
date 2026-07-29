from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


APP_SERVICES = ("deploy-check", "migrate", "web")


def load_production_compose() -> dict:
    return yaml.safe_load((ROOT / "compose.production.yml").read_text(encoding="utf-8"))


def test_production_compose_separates_database_and_edge_networks() -> None:
    compose = load_production_compose()
    services = compose["services"]
    assert set(services) == {"db", *APP_SERVICES}
    assert "ports" not in services["db"]
    assert services["db"]["networks"] == ["database"]
    assert compose["networks"]["database"]["internal"] is True
    assert services["web"]["networks"] == ["database", "edge"]
    # deploy-check never needs network access; it only reads configuration.
    assert "networks" not in services["deploy-check"]


def test_production_compose_runs_django_deployment_checks_before_serving() -> None:
    services = load_production_compose()["services"]
    assert services["deploy-check"]["command"] == [
        "python",
        "manage.py",
        "check",
        "--deploy",
        "--fail-level",
        "ERROR",
    ]
    assert services["migrate"]["depends_on"]["deploy-check"]["condition"] == (
        "service_completed_successfully"
    )


def test_production_compose_applies_runtime_confinement_to_every_app_service() -> None:
    services = load_production_compose()["services"]
    for name in APP_SERVICES:
        service = services[name]
        assert service["read_only"] is True, name
        assert service["cap_drop"] == ["ALL"], name
        assert service["security_opt"] == ["no-new-privileges:true"], name
        assert service["user"] == "65532:65532", name
        assert service["init"] is True, name
        assert service["pids_limit"] > 0, name
        assert "cap_add" not in service, name
        assert "privileged" not in service, name
        limits = service["deploy"]["resources"]["limits"]
        assert limits["cpus"] and limits["memory"], name
        tmpfs = service["tmpfs"]
        assert len(tmpfs) == 1, name
        assert tmpfs[0].startswith("/tmp:"), name
        for option in ("noexec", "nosuid", "nodev", "size="):
            assert option in tmpfs[0], (name, option)


def test_production_compose_grants_the_database_only_the_capabilities_it_needs() -> None:
    database = load_production_compose()["services"]["db"]
    assert database["cap_drop"] == ["ALL"]
    assert database["security_opt"] == ["no-new-privileges:true"]
    assert set(database["cap_add"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "SETGID",
        "SETUID",
    }
    assert database["pids_limit"] > 0
    assert database["deploy"]["resources"]["limits"]["memory"]


def test_production_compose_shares_no_host_namespace_or_privileged_path() -> None:
    source = (ROOT / "compose.production.yml").read_text(encoding="utf-8")
    forbidden = (
        "privileged: true",
        "/var/run/docker.sock",
        "docker.sock",
        "network_mode: host",
        "pid: host",
        "ipc: host",
        "userns_mode: host",
        "/proc",
        "/sys",
        "/dev",
        "extra_hosts",
        "sysctls",
        "devices:",
    )
    for entry in forbidden:
        assert entry not in source, entry
    compose = load_production_compose()
    for name, service in compose["services"].items():
        assert service.get("privileged") is not True, name
        assert "devices" not in service, name
        assert "sysctls" not in service, name
        assert "extra_hosts" not in service, name
        assert service["logging"]["options"]["max-size"], name


def test_production_compose_publishes_only_an_explicit_bound_port() -> None:
    services = load_production_compose()["services"]
    assert services["web"]["ports"] == [
        "${THREATBRIDGE_BIND_ADDRESS:?Set the dedicated host LAN address}"
        ":${THREATBRIDGE_PORT:-8020}:8000"
    ]
    for name in ("db", "deploy-check", "migrate"):
        assert "ports" not in services[name], name


def test_production_compose_does_not_trust_forwarded_proto_by_default() -> None:
    compose = load_production_compose()
    trust = compose["x-app-environment"]["DJANGO_TRUST_X_FORWARDED_PROTO"]
    assert trust == "${THREATBRIDGE_TRUST_X_FORWARDED_PROTO:-false}"
    example = (ROOT / "deploy" / ".env.production.example").read_text(encoding="utf-8")
    assert "THREATBRIDGE_TRUST_X_FORWARDED_PROTO=false" in example


def test_development_compose_stays_on_loopback_and_drops_capabilities() -> None:
    compose = yaml.safe_load((ROOT / "compose.yml").read_text(encoding="utf-8"))
    web = compose["services"]["web"]
    assert web["ports"] == ["127.0.0.1:8000:8000"]
    assert web["cap_drop"] == ["ALL"]
    assert web["security_opt"] == ["no-new-privileges:true"]
    assert web["user"] == "65532:65532"
    assert web["environment"]["DJANGO_DEBUG"] == "true"


# The validated Alpine candidate: it built from the committed hash-locked requirements,
# passed runtime confinement validation, and recorded zero HIGH or CRITICAL Trivy findings.
# Changing it requires repeating that evidence, so the value is asserted rather than derived.
DEFAULT_BASE_IMAGE = (
    "python:3.13.14-alpine3.24@sha256:"
    "399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
)


def test_dockerfile_defaults_to_the_validated_alpine_base() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for argument in ("PYTHON_BUILDER_IMAGE", "PYTHON_RUNTIME_IMAGE"):
        assert f"ARG {argument}={DEFAULT_BASE_IMAGE}" in dockerfile, argument

    # Both stages must consume the arguments, so an override reaches the build.
    assert "FROM ${PYTHON_BUILDER_IMAGE} AS builder" in dockerfile
    assert "FROM ${PYTHON_RUNTIME_IMAGE} AS runtime" in dockerfile

    # A tag without a digest would let the base drift underneath a reviewed build.
    for line in dockerfile.splitlines():
        if line.startswith(("ARG PYTHON_BUILDER_IMAGE=", "ARG PYTHON_RUNTIME_IMAGE=")):
            assert "@sha256:" in line, line

    # Alpine is a deliberate distribution choice, not a reason to relax the image contract.
    assert "USER 65532:65532" in dockerfile
    assert "EXPOSE 8000" in dockerfile
    # apk would reintroduce the package surface the Alpine base exists to avoid.
    assert "apk" not in dockerfile


def test_production_image_resolution_defaults_to_the_validated_alpine_release() -> None:
    resolver = (ROOT / "scripts" / "resolve_production_images.sh").read_text(encoding="utf-8")
    expected_tag = DEFAULT_BASE_IMAGE.split("@", 1)[0]
    for argument in ("BUILDER", "RUNTIME"):
        assert f"THREATBRIDGE_{argument}_TAG:-" in resolver, argument
    assert resolver.count(f":-{expected_tag}}}") == 2, resolver

    # An exact patch level, because docs/supply-chain.md requires a reviewed selection
    # rather than silent advancement when a deployment is prepared.
    assert expected_tag.count(".") >= 2
    # The resolver must still convert whichever tag it is given into an immutable digest.
    assert "sha256:[0-9a-f]{64}" in resolver
    assert "Unable to resolve an immutable digest" in resolver
    # Private and mirrored registries stay reachable through the override variables.
    assert "docker login" in resolver


def test_base_comparison_measures_the_committed_dockerfile_default() -> None:
    comparison = (ROOT / "scripts" / "compare_base_images.sh").read_text(encoding="utf-8")
    assert f'current_ref="{DEFAULT_BASE_IMAGE}"' in comparison

    # A blocked or skipped scan must never read as an approval.
    assert 'if [[ "${scan_policy}" != "pass" ]]; then' in comparison
    assert "not eligible for publication" in comparison
    assert "scan_policy=not-run" in comparison
    assert "exit 1" in comparison
    # Fewer findings is not the same as secure, and the script must say so.
    assert "do not read a" in comparison and "lower count as evidence" in comparison
    # Naming describes what is compared rather than assuming a distribution.
    assert "build_candidate default" in comparison
    assert "slim" not in comparison


def test_container_image_declares_opencontainers_provenance_labels() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for label in (
        "org.opencontainers.image.title",
        "org.opencontainers.image.description",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.created",
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.source",
        "org.opencontainers.image.base.name",
    ):
        assert label in dockerfile, label
    assert 'org.opencontainers.image.licenses="Apache-2.0"' in dockerfile
    # A secret must never be baked in through a build argument or environment default.
    for forbidden in ("DJANGO_SECRET_KEY_FILE", "ARG DJANGO_SECRET_KEY", "ENV DJANGO_SECRET_KEY"):
        assert forbidden not in dockerfile, forbidden
    assert "USER 65532:65532" in dockerfile
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile
    assert "runserver" not in dockerfile


def run_image_validator(tmp_path: Path, port_output: str) -> subprocess.CompletedProcess[str]:
    """Run the validator against a stub `docker` that emits `port_output` verbatim.

    Docker's Go template ends its port list with a blank record, so the validator has to
    normalize its own input before comparing. The stub reproduces that shape exactly and
    fails on the first `docker run`, which is past every metadata check.
    """

    stub_directory = tmp_path / "bin"
    stub_directory.mkdir()
    stub = stub_directory / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$1" == "image" && "$2" == "inspect" ]]; then\n'
        '    case "$4" in\n'
        "        *Config.User*) printf '65532:65532\\n' ;;\n"
        "        *Config.Env*) printf 'PATH=/opt/runtime-venv/bin\\n\\n' ;;\n"
        '        *ExposedPorts*) printf %s "${THREATBRIDGE_STUB_PORTS}" ;;\n'
        "        *Config.Labels*) printf 'present\\n' ;;\n"
        "    esac\n"
        "    exit 0\n"
        "fi\n"
        "echo 'stub reached docker run' >&2\n"
        "exit 42\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "validate_container_image.sh"), "threatbridge:test"],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{stub_directory}:{os.environ['PATH']}",
            "THREATBRIDGE_STUB_PORTS": port_output,
        },
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    "port_output",
    [
        # The bytes Docker actually emits: the port, then the template's blank record.
        "8000/tcp\n\n",
        # A blank record ahead of the port, which is where sorting puts it.
        "\n8000/tcp\n",
        "8000/tcp\n",
    ],
)
def test_exposed_port_inspection_tolerates_blank_records(tmp_path: Path, port_output: str) -> None:
    result = run_image_validator(tmp_path, port_output)
    # The validator compares for equality with "8000/tcp", so reaching `docker run`
    # proves normalization produced exactly that, with no surrounding whitespace.
    assert "Unexpected exposed ports" not in result.stderr, result.stderr
    assert "stub reached docker run" in result.stderr
    assert result.returncode == 42


@pytest.mark.parametrize(
    ("port_output", "message"),
    [
        # Deterministically sorted and space-joined, whatever order Docker reports.
        ("9000/tcp\n8000/tcp\n\n", "Unexpected exposed ports: 8000/tcp 9000/tcp"),
        ("8000/tcp\n8000/udp\n\n", "Unexpected exposed ports: 8000/tcp 8000/udp"),
        ("\n\n", "Unexpected exposed ports: none"),
    ],
)
def test_exposed_port_inspection_rejects_anything_but_the_single_expected_port(
    tmp_path: Path, port_output: str, message: str
) -> None:
    result = run_image_validator(tmp_path, port_output)
    assert result.returncode == 1
    assert message in result.stderr
    assert "stub reached docker run" not in result.stderr


def test_image_validator_still_demands_every_runtime_control() -> None:
    """Changing the base distribution must not quietly relax the image contract."""

    validator = (ROOT / "scripts" / "validate_container_image.sh").read_text(encoding="utf-8")
    for requirement in (
        # Identity and exposure.
        '"${configured_user}" != "65532:65532"',
        '"${exposed_ports}" != "8000/tcp"',
        "os.getuid() != 65532 or os.getgid() != 65532",
        # The installed wheel is authoritative and pip is gone.
        "is not imported from the installed wheel",
        "is outside the runtime virtual environment",
        "pip must not be present in the runtime environment",
        "test package present in runtime wheel",
        # Confinement, proven by running the image under it.
        "no-new-privileges is not active",
        "is not empty",
        "is writable under a read-only root filesystem",
        "the Docker socket is present inside the container",
        # Nothing that leaks secrets or ships source into the runtime layer.
        "Runtime secrets must not persist in the image environment",
        "forbidden runtime path",
        "world-writable runtime path",
        "Missing OCI label",
    ):
        assert requirement in validator, requirement

    assert "--read-only" in validator
    assert "--cap-drop ALL" in validator
    assert "--security-opt no-new-privileges:true" in validator
    assert "--user 65532:65532" in validator
    for capability_set in ("CapEff", "CapPrm", "CapBnd"):
        assert capability_set in validator, capability_set


def test_production_compose_runs_migrations_without_a_shell() -> None:
    compose = yaml.safe_load((ROOT / "compose.production.yml").read_text(encoding="utf-8"))
    migrate = compose["services"]["migrate"]
    web = compose["services"]["web"]
    assert migrate["command"] == ["python", "manage.py", "migrate", "--noinput"]
    assert web["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert web["healthcheck"]["test"][0] == "CMD"
    assert migrate["read_only"] is True
    assert web["read_only"] is True
    assert migrate["cap_drop"] == ["ALL"]
    assert web["cap_drop"] == ["ALL"]
    assert migrate["user"] == "65532:65532"
    assert web["user"] == "65532:65532"


def test_step_ca_overlay_adds_trust_without_disabling_verification() -> None:
    source = (ROOT / "compose.production.step-ca.yml").read_text(encoding="utf-8")
    overlay = yaml.safe_load(source)
    for service_name in APP_SERVICES:
        service = overlay["services"][service_name]
        assert service["environment"]["THREATBRIDGE_EXTRA_CA_FILE"] == (
            "/run/configs/threatbridge_extra_ca"
        )
        # Long syntax pins the mount point and a non-writable mode rather than relying
        # on the Compose default target.
        assert service["configs"] == [
            {
                "source": "threatbridge_extra_ca",
                "target": "/run/configs/threatbridge_extra_ca",
                "uid": "65532",
                "gid": "65532",
                "mode": 0o444,
            }
        ], service_name
    assert "THREATBRIDGE_EXTRA_CA_PATH" in overlay["configs"][
        "threatbridge_extra_ca"
    ]["file"]
    # Trust material only: no verification switches, no volume mounts, no host CA
    # directories, and no extra capabilities.
    for forbidden in (
        "insecure",
        "verify=false",
        "verify_ssl",
        "volumes:",
        "/etc/ssl",
        "/usr/local/share/ca-certificates",
        "cap_add",
        "privileged",
    ):
        assert forbidden not in source.lower(), forbidden
    assert set(overlay["services"]) == set(APP_SERVICES)
    assert set(overlay) == {"x-extra-ca-config", "services", "configs"}


def test_production_compose_uses_file_backed_secrets() -> None:
    source = (ROOT / "compose.production.yml").read_text(encoding="utf-8")
    assert "DJANGO_SECRET_KEY_FILE: /run/secrets/django_secret_key" in source
    assert "DATABASE_URL_FILE: /run/secrets/database_url" in source
    assert "POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password" in source
    assert "POSTGRES_PASSWORD:" not in source
    assert "DATABASE_URL:" not in source
    assert "DJANGO_SECRET_KEY:" not in source


def test_production_environment_requires_immutable_images() -> None:
    source = (ROOT / "deploy" / ".env.production.example").read_text(encoding="utf-8")
    image_lines = [line for line in source.splitlines() if "_IMAGE=" in line]
    assert len(image_lines) == 4
    for line in image_lines[:3]:
        assert "@sha256:" in line
    assert "THREATBRIDGE_PORT=8020" in source
    assert "THREATBRIDGE_USE_EXTRA_CA=false" in source


def run_prepare(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "prepare_production_deployment.py"),
            "--hostname",
            "threatbridge.example.invalid",
            "--bind-address",
            "192.0.2.10",
            "--outbound-host",
            "opencti.example.invalid",
            "--private-cidr",
            "192.0.2.0/24",
            "--env-file",
            str(tmp_path / "deployment.env"),
            "--secrets-dir",
            str(tmp_path / "secrets"),
            *extra,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_prepare_production_deployment_creates_restricted_files(tmp_path: Path) -> None:
    result = run_prepare(tmp_path)
    assert result.returncode == 0, result.stderr
    env_file = tmp_path / "deployment.env"
    secrets_dir = tmp_path / "secrets"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700
    for name in ("django-secret-key", "database-url", "postgres-password"):
        path = secrets_dir / name
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_text(encoding="utf-8").strip()
    environment = env_file.read_text(encoding="utf-8")
    assert "DJANGO_ALLOWED_HOSTS=threatbridge.example.invalid" in environment
    assert "THREATBRIDGE_BIND_ADDRESS=192.0.2.10" in environment
    assert "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid" in environment
    assert "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=192.0.2.0/24" in environment
    assert "THREATBRIDGE_USE_EXTRA_CA=false" in environment


def test_prepare_production_deployment_enables_reviewed_extra_ca(tmp_path: Path) -> None:
    ca_file = tmp_path / "root-ca.crt"
    ca_file.write_text("reviewed test CA\n", encoding="utf-8")
    result = run_prepare(tmp_path, "--extra-ca-path", str(ca_file))
    assert result.returncode == 0, result.stderr
    environment = (tmp_path / "deployment.env").read_text(encoding="utf-8")
    assert "THREATBRIDGE_USE_EXTRA_CA=true" in environment
    assert f"THREATBRIDGE_EXTRA_CA_PATH={ca_file.resolve()}" in environment


def test_prepare_production_deployment_refuses_overwrite(tmp_path: Path) -> None:
    env_file = tmp_path / "deployment.env"
    env_file.write_text("preserve\n", encoding="utf-8")
    result = run_prepare(tmp_path)
    assert result.returncode != 0
    assert "Refusing to overwrite" in result.stderr
    assert env_file.read_text(encoding="utf-8") == "preserve\n"


@pytest.mark.parametrize(
    "arguments, message",
    [
        (("--hostname", "https://bad.example"), "--hostname"),
        (("--bind-address", "0.0.0.0"), "usable host interface"),
        (("--private-cidr", "192.0.2.4/24"), "Invalid strict --private-cidr"),
    ],
)
def test_prepare_production_deployment_rejects_ambiguous_values(
    tmp_path: Path, arguments: tuple[str, str], message: str
) -> None:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "prepare_production_deployment.py"),
        "--hostname",
        "threatbridge.example.invalid",
        "--bind-address",
        "192.0.2.10",
        "--outbound-host",
        "opencti.example.invalid",
        "--env-file",
        str(tmp_path / "deployment.env"),
        "--secrets-dir",
        str(tmp_path / "secrets"),
    ]
    key = arguments[0]
    if key in command:
        index = command.index(key)
        command[index : index + 2] = list(arguments)
    else:
        command.extend(arguments)
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    assert result.returncode != 0
    assert message in result.stderr


def test_production_environment_parser_rejects_duplicates(tmp_path: Path) -> None:
    env_file = tmp_path / "duplicate.env"
    env_file.write_text("KEY=one\nKEY=two\n", encoding="utf-8")
    env_file.chmod(0o600)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "production_env.py"),
            str(env_file),
            "KEY",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "duplicate environment key KEY" in result.stderr


def test_production_environment_parser_rejects_symlink(tmp_path: Path) -> None:
    real_file = tmp_path / "real.env"
    real_file.write_text("KEY=value\n", encoding="utf-8")
    real_file.chmod(0o600)
    link = tmp_path / "linked.env"
    link.symlink_to(real_file)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "production_env.py"),
            str(link),
            "KEY",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must not be a symlink" in result.stderr


def test_production_compose_wrapper_never_sources_environment() -> None:
    source = (ROOT / "scripts" / "production_compose.sh").read_text(encoding="utf-8")
    compare_source = (ROOT / "scripts" / "compare_base_images.sh").read_text(
        encoding="utf-8"
    )
    assert "source " not in source
    assert "source " not in compare_source
    assert "production_env.py" in source
    assert "production_env.py" in compare_source


def test_restore_requires_explicit_confirmation() -> None:
    source = (ROOT / "scripts" / "restore_production.sh").read_text(encoding="utf-8")
    assert '"${CONFIRM:-}" != "RESTORE_THREATBRIDGE"' in source
    assert "sha256sum --check SHA256SUMS" in source
    assert "dropdb --force" in source


def test_generated_deployment_material_is_ignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "deploy/.env.production" in gitignore
    assert "deploy/secrets/" in gitignore
    assert "deploy/ca/" in gitignore
    assert "backups/" in gitignore
    assert "deploy/.env.production" in dockerignore
    assert "deploy/secrets" in dockerignore
    assert "deploy/ca" in dockerignore
    assert "backups" in dockerignore


def test_private_security_documents_are_ignored_by_a_committed_rule() -> None:
    """docs/security/ must fail closed through .gitignore, not a local exclude file.

    A private internal report protected only by .git/info/exclude would be committed by
    anyone who cloned the repository fresh, so the rule has to be in the tree.
    """

    candidates = (
        "docs/security/hardening-phase-1-report.md",
        "docs/security/some-new-internal-report.md",
        "docs/security/private-notes.md",
        "docs/security/tmkb/nested/finding.md",
    )
    for candidate in candidates:
        result = subprocess.run(
            ["git", "check-ignore", "-v", "--no-index", candidate],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, candidate
        assert result.stdout.startswith(".gitignore:"), (candidate, result.stdout)

    published = subprocess.run(
        [
            "git",
            "check-ignore",
            "-v",
            "--no-index",
            "docs/security/public-release-hardening-audit.md",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert "!docs/security/public-release-hardening-audit.md" in published.stdout
    assert "docs/security" in (ROOT / ".dockerignore").read_text(encoding="utf-8")


def test_deployment_scripts_have_no_windows_line_endings() -> None:
    expected = {
        "backup_production.sh",
        "compare_base_images.sh",
        "prepare_production_deployment.py",
        "production_compose.sh",
        "production_env.py",
        "resolve_production_images.sh",
        "restore_production.sh",
    }
    for name in expected:
        path = ROOT / "scripts" / name
        assert path.is_file()
        assert b"\r\n" not in path.read_bytes()
        assert os.access(path, os.X_OK)
