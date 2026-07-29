# Container image security validation

ThreatBridge treats the final image as a separate release artifact from the Python application
lock. Image validation therefore covers the installed wheel, Python dependencies, and operating-
system packages in the exact locally built image. It does not infer exploitability from package
presence alone.

## Pinned scanner

Release validation uses Trivy 0.70.0 from the official immutable release. The reviewed release tag
resolves to commit `8a3177aedf7ee0864920eb1852eef031cd3742b8`. The official checksum manifest has SHA-256
`c45281240bb9211ea9e830fc0bf5cf8acf7c0ca830feb64ac8a0aa932c5c92d9`; the Linux 64-bit archive
has SHA-256 `8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9`.

Install the scanner into a temporary local path without piping downloaded code to a shell:

```bash
./scripts/install_trivy.sh
```

The installer downloads the exact archive and verifies its embedded expected checksum before
extracting the binary. Before a release, independently verify the upstream tag, release signature
or attestation, checksum manifest, and scanner security notices again. The scanner and its database
are validation inputs; neither is copied into the application image.

## Exact-image scan and SBOM

Build and tag the candidate locally, then resolve and scan its immutable local image ID:

```bash
docker build --no-cache -t threatbridge-release-candidate:local .
./scripts/validate_container_image.sh threatbridge-release-candidate:local
./scripts/generate_image_sbom.sh threatbridge-release-candidate:local
./scripts/scan_container_image.sh threatbridge-release-candidate:local
```

The scan script resolves the tag with `docker image inspect`, passes that `sha256:` image ID to
Trivy, forces `/dev/null` as the ignore file, and retains both fixed and unfixed high/critical
findings. The generated `release-evidence/threatbridge-image.cdx.json` is a CycloneDX inventory for
that exact image and includes operating-system and Python packages. `release-evidence/` is ignored
and must not be committed because the document is tied to a local image digest. It is distinct from
the reproducible application SBOM at `sbom/threatbridge.cdx.json`. Regenerate the image SBOM and
scan report after every final image rebuild; timestamps and artifact identity make byte-for-byte
comparison inappropriate across different image builds.

The vulnerability database changes over time. Release evidence must record the Trivy version,
database update metadata, image ID, scan time, report checksum, and the full unsuppressed report.
Reports may be retained outside the public source tree, but their critical/high disposition must be
recorded in reviewed release documentation.

Generated reports can contain public base-image metadata that resembles a credential. The source
secret scan therefore operates on Git-tracked and non-ignored candidate files, not ignored local
release evidence. The complete Trivy report itself remains unsuppressed and separately reviewed.

## MVP finding policy

- Every critical or high finding blocks publication of the prebuilt container image, whether or
  not a fix is currently published. A finding in a locally built image does not by itself block
  publication of the separately reviewed source repository.
- When a fixed version is available, rebuild on the fixed base or dependency and rescan the new
  image ID. Do not carry the old scan result forward.
- Package detection is evidence of presence, not proof that ThreatBridge is exploitable. This MVP
  preparation does not attempt exhaustive reachability research or implement a formal risk-
  acceptance system.
- Trivy ignore files, command-line suppressions, severity downgrades, and `ignore-unfixed` are not
  permitted silently.
- When no fix is available, leave prebuilt-image publication blocked and repeat the bounded base
  review when the official image or scanner database changes. Do not create a suppression or infer
  acceptance from source-repository publication.
- Medium and low findings are reviewed and tracked according to release risk, but are not automatic
  publication blockers under this preparation policy.

There are no suppressions or accepted risks in the current candidate. The default base was changed
because it satisfies this policy on its own evidence, not by relaxing the policy. Source-repository
publication and prebuilt-image publication remain separate release decisions with separate gates.

## Default base image

The default builder and runtime base is the Docker Official Image

```text
python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
```

It is the default because that exact candidate was built and validated, not because Alpine is assumed
to be safer. In the recorded evaluation the candidate:

- built from the committed hash-locked `requirements/*.txt` with no added `apk` package;
- passed the installed-wheel check, so `catalog`, `integrations`, and `threatbridge` resolve inside
  `/opt/runtime-venv` site-packages and `pip` is absent;
- passed runtime confinement validation as UID/GID `65532:65532` with `NoNewPrivs=1`, empty
  `CapEff`/`CapPrm`/`CapBnd`, a read-only root filesystem, and `8000/tcp` as the only exposed port;
- produced **0 CRITICAL and 0 HIGH** findings under the unsuppressed Trivy 0.70.0 scan policy.

**This is point-in-time evidence, not a property of the image.** It describes one image ID against one
scanner database on one date. A later scan of the same digest can report new findings as advisories
are published, and nothing here promises a clean result. ThreatBridge is not certified and is not
claimed to be free of vulnerabilities.

### Bases that were evaluated and not selected

| Candidate | Build | Container validation | Trivy 0.70.0 policy |
| --- | --- | --- | --- |
| `python:3.13.14-alpine3.24` (selected) | Pass | Pass | **Pass** — 0 CRITICAL, 0 HIGH |
| `python:3.13.14-slim` (Debian 13) | Pass | Pass | Blocked — 23 findings: 4 CRITICAL, 19 HIGH |
| `python:3.13.14-slim-bookworm` (Debian 12) | Pass | Pass | Blocked — 24 findings: 6 CRITICAL, 18 HIGH |

All three built successfully and all three passed the full container validation, so this was not a
compatibility decision. The two Debian candidates were rejected because the finding policy below
blocks a prebuilt image on any unfixed HIGH or CRITICAL, and both exceeded that. A lower finding count
by itself is not evidence that a base is secure; it is one reviewed input among build success, runtime
validation, fix availability, reachability, and operational support.

### musl compatibility

Alpine uses musl libc rather than glibc. Compatibility was tested for the **current locked runtime
dependency set only**: the image installs `requirements/runtime.txt` under `--require-hashes`, and
`psycopg-binary` is the one component with compiled artifacts. That install succeeded in the validated
build, and the resulting image passed Django checks, `collectstatic`, and the installed-wheel
validation.

Two limits follow from that. Adding or upgrading a dependency with compiled artifacts can fail or
change behaviour on musl, so a lock change is also a base-compatibility change. Development, CI, and
the `scripts/test_python_compatibility.sh` matrix continue to run on glibc against the supported
CPython range, so musl is exercised by the image build rather than by the test suite.

### Upgrading the base

Advancing the Python patch level, the Alpine release, or the distribution is a reviewed change, not a
bump. Repeat the whole evidence chain and record the result:

1. Resolve the new tag to an immutable digest and update both `ARG` lines together, keeping the
   readable tag beside the digest.
2. Build with `--no-cache` and run the complete test suite.
3. Run `scripts/validate_container_image.sh` against the exact new image.
4. Regenerate the image SBOM with `scripts/generate_image_sbom.sh`.
5. Run `scripts/scan_container_image.sh` and review every finding without suppression.
6. Update `scripts/compare_base_images.sh`, the tests that pin the default, and this document.

### Overrides

The Dockerfile accepts `PYTHON_BUILDER_IMAGE` and `PYTHON_RUNTIME_IMAGE` build arguments, and
`scripts/resolve_production_images.sh` accepts `THREATBRIDGE_BUILDER_TAG` and
`THREATBRIDGE_RUNTIME_TAG`. Operators who must build from a hardened, mirrored, or private registry —
for example a Docker Hardened Images subscription — set those and change nothing else. Digest
resolution, digest pinning, image validation, and the finding policy are identical either way. The
mutable tags are discovery inputs only and must not remain in the deployed environment file.

Separate build and runtime virtual environments prevent build tooling from entering the final image;
`pip` is removed from the copied runtime environment after the locked installation is checked. The
final stage performs no shell command and runs as UID/GID `65532:65532`, so the same application
artifact can be evaluated against an alternative or hardened runtime.

The runtime stage carries OpenContainers provenance labels for title, description, version,
revision, creation time, licence, source, documentation, and base image name. `THREATBRIDGE_VERSION`,
`THREATBRIDGE_REVISION`, and `THREATBRIDGE_CREATED` build arguments supply the variable values; they
are descriptive metadata and never secrets.

The Alpine base is not distroless: the runtime layer still contains a shell and `apk`. That is a
deliberate trade-off for supportability and debuggability. The Dockerfile installs no `apk` package,
the application virtual environment contains no build tooling and no `pip`, the container runs
unprivileged with a read-only root filesystem and no capabilities, and `validate_container_image.sh`
proves those properties on every build. Changing the base purely to reduce a scanner's package count
is explicitly not a goal.

## Base comparison tooling

Use `scripts/compare_base_images.sh` to build and validate both the `default` candidate recorded in
the Dockerfile and the `pinned` candidate resolved into `deploy/.env.production`. When Trivy is
installed at the approved path, the script retains an unsuppressed report for each exact image. It
records evidence and never chooses a base or changes the finding policy, and it exits non-zero unless
every candidate's scan passes, so a blocked or skipped scan cannot be read as a pass. A candidate is
acceptable only after application checks, PostgreSQL migrations, readiness, connector TLS behavior,
runtime permissions, backup/restore, and all exact-image findings are reviewed.

## Live deployment validation

Validating and scanning the image proves the image is sound. It does not prove the deployment
works, and the distinction is not academic: six defects in the production Compose path reached a
committed state after the image validation and scan above both passed cleanly.

`scripts/validate_production_compose.sh` closes that gap and is the authoritative gate:

```bash
bash scripts/validate_production_compose.sh
```

It builds the committed Dockerfile default with no base substitution — it fails if the resolved
builder and runtime digests do not match the committed `ARG` defaults, so the artifact under test is
the one a third party gets from a plain `docker build` — then runs `validate_container_image.sh`,
`generate_image_sbom.sh`, and `scan_container_image.sh` against it, and finally starts the whole
production stack on a disposable loopback-only deployment to assert the live runtime contract,
network isolation, HTTP behaviour, and private-CA handling.

The scan inside the gate is the same unsuppressed scan described above and carries the same
limitation: a clean result describes one image ID against one vulnerability database at one moment.
A clean run today is not evidence that the next build is clean. Publication of a prebuilt image
therefore still requires a fresh unsuppressed scan of the exact image being published, reviewed
under the finding policy below, and the release commit must itself pass the integration gate before
any tag or image is published.

## Continuous scanning

`.github/workflows/compose-integration.yml` runs the integration gate on every pull request and
every push to `main`, on `ubuntu-24.04`, with `contents: read`, a 45-minute job timeout, and
concurrency cancellation. It builds and exercises the stack; it never logs in to a registry, pushes
an image, or consumes a secret. Prebuilt-image publication remains a separate explicit release
action, not a CI side effect.

`.github/workflows/container-scan.yml` runs on relevant pushes and pull requests and weekly. It
installs the checksum-verified Trivy build, scans the repository for committed secrets, scans the
Dockerfile for misconfiguration at MEDIUM and above, builds the image from the pinned base digests,
runs `scripts/validate_container_image.sh`, and then runs `scripts/scan_container_image.sh`, which
fails the job on any HIGH or CRITICAL image finding. No step uses `continue-on-error` or otherwise
swallows a failure. Python dependency vulnerabilities are covered separately by `pip-audit` in
`ci.yml`, which understands the `requirements/*.txt` lock layout.
