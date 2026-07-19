# Dependency locking

`pyproject.toml` is the only human-maintained source for build, runtime, and development dependency
ranges. Files under `requirements/` are generated and must not be edited by hand.

## Lock layout

- `requirements/build.in` is generated from `[build-system].requires`.
- `requirements/build.txt` hashes the isolated wheel-build toolchain.
- `requirements/runtime.txt` hashes the resolved application dependencies.
- `requirements/development.txt` hashes runtime dependencies plus the `dev` extra used by local
  development and CI.

Every resolved package is pinned and includes hashes accepted by pip's `--require-hashes` mode.
The runtime lock is the dependency input used by Docker and by the release SBOM.
Static validation also requires every runtime package, including transitive dependencies, to
appear in the development lock at the identical version. Every artifact hash accepted by the
runtime lock must remain accepted for that package in the development lock. This prevents local and
CI development installs from silently testing a different runtime dependency graph.

## Installation

Create a fresh virtual environment, then install the build and development locks before installing
the local project without dependency resolution:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/build.txt
python -m pip install --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation -e .
```

For a runtime-only installation, substitute `requirements/runtime.txt` for the development lock
and omit editable mode. Installing the local project with `--no-deps --no-build-isolation` ensures
that pip cannot silently resolve packages outside the reviewed locks.

## Controlled update procedure

1. Review and edit dependency ranges only in `pyproject.toml`.
2. Install an approved `pip-tools` version from the current development lock.
3. Run `./scripts/update_dependency_locks.sh`.
4. Review every version and hash change in all generated lock files.
5. Run `./scripts/check_dependency_locks.sh`.
6. Install the locks in a new empty virtual environment.
7. Run `python -m pip check` and `python -m pip_audit --require-hashes --disable-pip -r
   requirements/runtime.txt`.
8. Regenerate `sbom/threatbridge.cdx.json` and complete the release checklist.

Normal push and pull-request CI does not invoke pip-compile and does not compare against a live
resolution. It installs the committed files with `--require-hashes` and runs
`scripts/validate_dependency_locks.py`, which statically requires exact pins, SHA-256 hashes,
stable generated-file metadata, direct dependency coverage, and the absence of URLs, VCS sources,
index configuration, trusted hosts, or included constraint/requirement files. It also enforces the
runtime/development package, version, and compatible-artifact-hash parity described above.

Live re-resolution is isolated to `lock-freshness.yml`, which runs on a schedule or explicit manual
dispatch against `https://pypi.org/simple`. It only compares generated files and cannot commit,
publish, or open a pull request. A maintainer must run the controlled update procedure and submit
all changes for review.

The update script suppresses environment-specific package-index URLs so private mirror addresses
cannot enter committed locks. Lock regeneration still requires approved public package-index
access. A lock update is incomplete until tests, vulnerability scanning, the SBOM comparison, and
the no-cache Docker build pass.

## Compatibility boundary

The supported interpreter policy is CPython 3.12 through 3.14 (`>=3.12,<3.15`). Required CI installs
the hashed locks and runs Django checks, migration drift, and the complete test suite on Python
3.12.13, 3.13.14, and 3.14.4. The production image remains fixed to Python 3.13.14 and its reviewed
image digest. A patch-version change requires the same lock, application, and image validation.

Run the same matrix locally with `./scripts/test_python_compatibility.sh`. The script creates a
temporary source tree from tracked and non-ignored public files so ignored local configuration and
private review material are never mounted into its disposable containers.
