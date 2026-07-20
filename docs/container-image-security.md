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
artifact to be evaluated against a shell-free hardened runtime. Production configuration resolves
`dhi.io/python:3.13-dev` and `dhi.io/python:3.13` to immutable manifest digests before building.
The mutable tags are discovery inputs only and must not remain in the deployed environment file.

Use `scripts/compare_base_images.sh` to build and validate both the recorded Docker Official Image
baseline and the resolved hardened candidate. When Trivy is installed at the approved path, the
script retains an unsuppressed report for each exact image. It records evidence but never chooses a
base or changes the finding policy. A candidate is acceptable only after application checks,
PostgreSQL migrations, readiness, connector TLS behavior, runtime permissions, backup/restore, and
all exact-image findings are reviewed.
