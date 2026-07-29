# Supply-chain preparation

ThreatBridge records immutable build inputs and produces a reviewable SBOM, but it does not yet
publish signed artifacts or provenance attestations.

## Container base image

Both Docker stages use the readable exact tag and immutable multi-platform manifest digest:

```text
python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
```

To update it:

1. Select an exact Python patch tag and an exact Alpine release; never use `latest`, `3`, or a
   floating major/minor tag.
2. Resolve it with `docker buildx imagetools inspect docker.io/library/python:VERSION-alpineRELEASE`.
3. Record the top-level manifest-list digest, not an architecture-specific attestation manifest.
4. Update both `FROM` lines together, preserving the readable tag beside the digest.
5. Build with `--no-cache`, inspect the resulting base and runtime Python version, and repeat the
   filesystem, secret, ownership, migration, and synthetic production checks.
6. Rerun the test suite, `scripts/validate_container_image.sh`, `scripts/generate_image_sbom.sh`, and
   `scripts/scan_container_image.sh` against the exact new image, and update
   `scripts/compare_base_images.sh` and the tests that pin the default.

A release reviewer must independently resolve the digest again and review upstream provenance before
publication.

Alpine 3.24 is the default because that exact candidate built from the committed hash-locked
requirements, passed complete container validation, and recorded zero HIGH or CRITICAL findings under
the unsuppressed Trivy 0.70.0 policy. `python:3.13.14-slim` (23 blocking findings) and
`python:3.13.14-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64`
(24 blocking findings) both built and validated successfully but were rejected by that policy. The
result is point-in-time evidence about specific image IDs and one scanner database, not a claim that
Alpine is inherently secure or will stay clean. Rationale, the musl compatibility scope, and the
upgrade procedure are in [`container-image-security.md`](container-image-security.md).

Exact comparison evidence is regenerated under the ignored `release-evidence/` directory.
`scripts/compare_base_images.sh` exits non-zero unless every candidate's scan passes, so a blocked
or skipped comparison cannot be mistaken for an approval.

The production Compose profile resolves its own digests separately from these Dockerfile defaults.
`scripts/resolve_production_images.sh` defaults both `THREATBRIDGE_BUILDER_TAG` and
`THREATBRIDGE_RUNTIME_TAG` to the publicly pullable `python:3.13.14-alpine3.24`, naming an exact patch
level so preparation cannot silently advance it, and so any third party can reproduce the documented
deployment without a registry subscription. Override either variable to build from a hardened,
mirrored, or private base; digest pinning and image validation are unchanged.

## Dependency locks

`requirements/runtime.txt`, `requirements/development.txt`, and `requirements/build.txt` are separate,
fully pinned, and hash-locked; every install uses `--require-hashes`.
`scripts/validate_dependency_locks.py` fails closed: it rejects a lock without hashes, an unpinned or
range-specified requirement, a missing hash algorithm, or drift between `pyproject.toml` and the
locks. Runtime and development dependencies never share a lock, so development tooling cannot reach
the container image. `ci.yml` audits both locks with `pip-audit --require-hashes --disable-pip`, and
`lock-freshness.yml` re-resolves them weekly without modifying the repository.

`.github/dependabot.yml` covers `pip` and `github-actions`. `dependency-review.yml` fails a pull
request at MODERATE severity or above for both runtime and development scopes, and denies AGPL, SSPL,
and BUSL licences so that a change to ThreatBridge's redistribution obligations must be an explicit,
reviewed decision rather than a transitive surprise.

## GitHub actions

Workflow actions are pinned to full commit SHAs with adjacent release-tag comments. Update an action
only after checking the official release, resolving the release tag with `git ls-remote --tags`, and
using the peeled commit for an annotated tag. Run `./scripts/validate_workflows.py` after every
workflow change. Dependabot may propose updates, but its output is not trusted until the tag, SHA,
release notes, permissions, and workflow behavior are independently reviewed.

The validator requires top-level permissions to be exactly `contents: read`; `read-all`,
`write-all`, unknown scopes, malformed values, and every write permission are rejected. No job may
expand permissions except the single CodeQL job, whose exact job-level permissions are
`contents: read` plus `security-events: write`. Workflows also use explicit job timeouts and
concurrency and only approved unprivileged triggers; `pull_request_target` is rejected. Dependency
Review v5 uses its Node 24 runtime on the supported
`ubuntu-24.04` GitHub-hosted runner. No workflow publishes packages, containers, signatures, or
release artifacts.

Because every workflow runs on `pull_request` rather than `pull_request_target`, a pull request from a
fork executes with a read-only token in the fork's context and receives no repository secret. No
workflow consumes a secret, so no generated artifact can contain one.

The workflow set is `ci.yml`, `codeql.yml`, `compose-integration.yml`, `container-scan.yml`,
`dependency-review.yml`, `lock-freshness.yml`, and `sbom.yml`. `tests/test_release_tooling.py`
asserts that the security-relevant workflows exist, validates whatever is on disk rather than a
hard-coded count, and asserts that no step uses `continue-on-error` or otherwise swallows a failure.

`compose-integration.yml` runs `scripts/validate_production_compose.sh`, which builds the
production image and runs the documented production Compose profile end to end. It exists because
six deployment defects reached a committed state after passing a full static audit; reading YAML
cannot detect an unloadable project, an unreadable mounted secret, a rejected health probe, an
overridden image healthcheck, a trust anchor that fails to load, or an implicit network. It builds
and exercises the stack but publishes nothing: it holds only `contents: read`, consumes no secret,
uses `pull_request` rather than `pull_request_target`, generates and discards every credential it
needs, and performs no registry login or push. On failure it uploads container names, states, and
Docker versions for seven days; container logs are excluded from the artifact because the script
already emits them through the application's redaction filter. Publishing a prebuilt image remains a
separate, explicit release action governed by
[`container-image-security.md`](container-image-security.md), never a side effect of CI.

## SBOM

`sbom/threatbridge.cdx.json` is a reproducible CycloneDX JSON SBOM generated from the hashed runtime
lock:

```bash
./scripts/generate_sbom.sh
```

The SBOM workflow regenerates and compares the document but deliberately does not upload it. A
future release process may attach the reviewed SBOM beside source and container artifacts only after
repository ownership and release permissions are approved.

The separately generated `release-evidence/threatbridge-image.cdx.json` inventories the exact
locally built container, including operating-system packages. The ignored release-evidence
directory is regenerated for the exact final image and reviewed outside the source candidate;
image-specific evidence is not committed. Image scanning, scanner pinning, finding policy, and
prebuilt-image blocking behavior are documented in
[`container-image-security.md`](container-image-security.md).

## Wheel-authoritative container

The final image installs the reviewed wheel and does not copy the source package directories over
it. Only the `manage.py` runtime management entry point, `LICENSE`, and `NOTICE` are copied from the
source tree; static files are collected by importing the installed wheel. Runtime validation proves
that `threatbridge`, `catalog`, and `integrations` resolve below the interpreter's `site-packages`
directory. Tests, development scripts, workflows, source locks, and repository metadata are absent
from the final image.

## Future signing and provenance

Future releases should use keyless Sigstore/Cosign signing with a protected GitHub environment and
OIDC, not repository-stored private keys. The release process should produce:

- a signed source archive checksum;
- signatures and attestations for container digests;
- the CycloneDX SBOM and its signature;
- build provenance binding the Git commit, dependency locks, workflow identity, runner image, base
  image digest, and output digest; and
- verification commands and certificate-identity constraints for consumers.

Do not create signing keys or publish signatures during preparation. Before enabling keyless
signing, legal and repository owners must approve the identity, issuer, certificate subject,
retention, transparency-log policy, and incident/revocation procedure.

Signing is future supply-chain work and is not a requirement for publishing the reviewed MVP source
repository. This candidate implements no Sigstore or Cosign workflow.

## Consumer verification guidance

A future release must identify one signed Git tag as its source of truth. Consumers should verify
the tag, compare the source archive SHA-256 digest, inspect the SBOM, verify Cosign certificates
against the documented issuer and repository workflow identity, and confirm that an image resolves
to the signed digest rather than trusting a mutable tag.
