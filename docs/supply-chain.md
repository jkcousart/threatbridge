# Supply-chain preparation

ThreatBridge records immutable build inputs and produces a reviewable SBOM, but it does not yet
publish signed artifacts or provenance attestations.

## Container base image

Both Docker stages use the readable exact tag and immutable multi-platform manifest digest:

```text
python:3.13.14-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91
```

To update it:

1. Select an exact Python patch tag; never use `latest`, `3`, or a floating major/minor tag.
2. Resolve it with `docker buildx imagetools inspect docker.io/library/python:VERSION-slim`.
3. Record the top-level manifest-list digest, not an architecture-specific attestation manifest.
4. Update both `FROM` lines together, preserving the readable tag beside the digest.
5. Build with `--no-cache`, inspect the resulting base and runtime Python version, and repeat the
   filesystem, secret, ownership, migration, and synthetic production checks.

The digest was resolved from the Docker Official Image on 2026-07-19. A release reviewer must
independently resolve it again and review upstream provenance before publication.

A bounded comparison against the official immutable
`python:3.13.14-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64`
base retained the current slim image. Both candidates passed identical startup, Django, migration,
installed-wheel import, ownership, and permissions checks. The current slim result was smaller,
contained fewer operating-system packages, and had fewer Trivy critical/high findings. Exact
comparison evidence is regenerated under the ignored `release-evidence/` directory.

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
