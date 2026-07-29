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

There are no suppressions or accepted risks in the current candidate.

## Hardened base comparison

The Dockerfile accepts `PYTHON_BUILDER_IMAGE` and `PYTHON_RUNTIME_IMAGE` build arguments. Separate
build and runtime virtual environments prevent build tooling from entering the final image; `pip`
is removed from the copied runtime environment after the locked installation is checked. The final
stage performs no shell command and runs as UID/GID `65532:65532`, allowing the same application
artifact to be evaluated against an alternative or hardened runtime. Production configuration
resolves `THREATBRIDGE_BUILDER_TAG` and `THREATBRIDGE_RUNTIME_TAG` to immutable manifest digests
before building. Both default to the publicly pullable `python:3.13-slim`, so a third party can
reproduce the documented build without a registry subscription; overriding them to a hardened,
mirrored, or private base is supported and changes nothing about digest pinning or validation. The
mutable tags are discovery inputs only and must not remain in the deployed environment file.

The runtime stage carries OpenContainers provenance labels for title, description, version,
revision, creation time, licence, source, documentation, and base image name. `THREATBRIDGE_VERSION`,
`THREATBRIDGE_REVISION`, and `THREATBRIDGE_CREATED` build arguments supply the variable values; they
are descriptive metadata and never secrets.

Because the default base is `python:3.13-slim` rather than a distroless or shell-free image, the
runtime layer still contains a shell and `apt`. That is a deliberate, documented trade-off for
supportability and compatibility: the application virtual environment contains no build tooling and
no `pip`, the container runs unprivileged with a read-only root filesystem and no capabilities, and
`validate_container_image.sh` proves those properties on every build. Changing the base purely to
reduce a scanner's package count is explicitly not a goal.

Use `scripts/compare_base_images.sh` to build and validate both the `official` baseline recorded in
the Dockerfile and the `pinned` candidate resolved into `deploy/.env.production`. When Trivy is
installed at the approved path, the script retains an unsuppressed report for each exact image. It
records evidence and never chooses a base or changes the finding policy, and it exits non-zero unless
every candidate's scan passes, so a blocked or skipped scan cannot be read as a pass. A candidate is
acceptable only after application checks, PostgreSQL migrations, readiness, connector TLS behavior,
runtime permissions, backup/restore, and all exact-image findings are reviewed.

## Continuous scanning

`.github/workflows/container-scan.yml` runs on relevant pushes and pull requests and weekly. It
installs the checksum-verified Trivy build, scans the repository for committed secrets, scans the
Dockerfile for misconfiguration at MEDIUM and above, builds the image from the pinned base digests,
runs `scripts/validate_container_image.sh`, and then runs `scripts/scan_container_image.sh`, which
fails the job on any HIGH or CRITICAL image finding. No step uses `continue-on-error` or otherwise
swallows a failure. Python dependency vulnerabilities are covered separately by `pip-audit` in
`ci.yml`, which understands the `requirements/*.txt` lock layout.
