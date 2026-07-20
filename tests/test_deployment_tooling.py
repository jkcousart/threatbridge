from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_production_compose_separates_database_and_edge_networks() -> None:
    compose = yaml.safe_load((ROOT / "compose.production.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert set(services) == {"db", "migrate", "web"}
    assert "ports" not in services["db"]
    assert services["db"]["networks"] == ["database"]
    assert compose["networks"]["database"]["internal"] is True
    assert services["web"]["networks"] == ["database", "edge"]


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
    overlay = yaml.safe_load(
        (ROOT / "compose.production.step-ca.yml").read_text(encoding="utf-8")
    )
    for service_name in ("migrate", "web"):
        service = overlay["services"][service_name]
        assert service["environment"]["THREATBRIDGE_EXTRA_CA_FILE"] == (
            "/run/configs/threatbridge_extra_ca"
        )
        assert service["configs"] == ["threatbridge_extra_ca"]
    assert "THREATBRIDGE_EXTRA_CA_PATH" in overlay["configs"][
        "threatbridge_extra_ca"
    ]["file"]
    assert "insecure" not in (ROOT / "compose.production.step-ca.yml").read_text(
        encoding="utf-8"
    ).lower()


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
