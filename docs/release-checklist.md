# Public release checklist

This checklist prepares a release candidate; completing it does not itself authorize publication.

## Ownership and legal

- [x] The project owner approved Apache-2.0 selection, copyright ownership, contribution terms, notices, and public source distribution.
- [x] CODEOWNERS entries use the verified public identity `@jkcousart`.
- [x] GitHub Private Vulnerability Reporting is selected for activation at publication, and the owner verified the dedicated private conduct-reporting mailbox.
- [ ] The release owner and independent approver are identified.

## Source and history safety

- [ ] The release commit is reviewed, clean, and reachable from the intended signed tag.
- [ ] `git ls-files` contains no `.env`, secret, database, upload, runtime data, private report,
      TMKB material, local path, employer reference, credential, or generated cache.
- [ ] Ignored-file names and `.dockerignore` are reviewed without adding private material.
- [ ] `git check-attr --all` and archive contents are reviewed.
- [ ] Gitleaks passes against the working tree and complete Git history.
- [ ] A source archive is created only from reviewed Git content and its file list and SHA-256
      digest are recorded.

## Dependencies and build inputs

- [ ] `scripts/validate_dependency_locks.py` passes without network access in required CI.
- [ ] The scheduled/manual lock-freshness comparison passes against the approved public index.
- [ ] Build, runtime, and development locks install with `--require-hashes` in a fresh environment.
- [ ] `pip check` and `pip-audit --require-hashes --disable-pip -r requirements/runtime.txt`
  pass.
- [ ] The exact Docker patch tag and Alpine release, and their immutable digest, are independently
      re-resolved and match the Dockerfile default, `scripts/compare_base_images.sh`, and the tests
      that pin them.
- [ ] Every workflow action SHA is independently matched to its documented release tag.
- [ ] Dependabot changes, if any, are independently reviewed; do not claim Dependabot has run when
      it has not.

## Quality and security

- [ ] Ruff check, Ruff format check, Django checks, `manage.py check --deploy --fail-level ERROR`
      against a synthetic production environment, migration drift, and the complete pytest suite pass.
- [ ] Bandit and Gitleaks pass without broad exclusions.
- [ ] `scripts/security_check.sh` passes, including its Trivy configuration scan at MEDIUM and above
      and its Gitleaks scan of the Git-tracked and non-ignored candidate tree.
- [ ] `docker compose -f compose.production.yml config` and the same command with
      `-f compose.production.step-ca.yml` both validate.
- [ ] A fresh no-cache image passes runtime-user, ownership, permissions, secret, private-file,
      migration, and synthetic production checks.
- [ ] `scripts/validate_container_image.sh` passes, including its hardened second run that proves a
      non-root UID, a read-only root filesystem, an empty capability set, `NoNewPrivs=1`, a writable
      `/tmp`, no Docker socket, the single expected exposed port, and the complete OCI label set.
- [ ] The application starts with safe throwaway test secrets and fails closed when a required
      production secret, host allowlist, or database URL is absent.
- [ ] Runtime imports prove the installed wheel is authoritative and no source/test/development
      material shadows it.
- [ ] The exact final image ID has an unsuppressed Trivy high/critical scan and a reviewed CycloneDX
      image SBOM containing operating-system packages.
- [ ] Every image high/critical finding is fixed or recorded as a publication blocker; any accepted
      risk requires a separate future process. The MVP candidate does not accept or suppress risk.
- [ ] The image is rebuilt from the committed Dockerfile default, not from a locally overridden base,
      and that rebuild is the artifact that was validated, SBOM-generated, and scanned.
- [ ] A base-image change is accompanied by a fresh build, the full test suite, container validation,
      image SBOM, and an unsuppressed scan of the new image ID. A previous base's evidence is never
      carried forward.
- [ ] **`bash scripts/validate_production_compose.sh` passes on the actual release commit.** This is
      the mandatory live-deployment gate and it subsumes the checks listed immediately below. A
      passing run on an earlier commit is not evidence about the release, because a clean run
      describes one commit, one image ID, and one scanner database.

      The gate asserts all of the following, so they no longer need separate manual confirmation.
      Confirm them by reading its output rather than by repeating the commands:

  - [ ] `docker compose config` exits zero for the production profile and for the step-ca overlay.
        Compose enforces semantics that parsing the YAML cannot, so a profile that only passes the
        unit tests may still be an invalid project.
  - [ ] `deploy-check` and `migrate` both exit zero and `web` reaches `healthy` through the image's
        own probe. A container stuck at `starting` or reaching `unhealthy` is a release blocker, not
        a timing artefact.
  - [ ] Generated secret files are readable by UID 65532 and their directory is mode `0700`; a
        private CA certificate is mode `0444`. Compose ignores `uid`, `gid`, and `mode` outside
        Swarm, so an owner-only file mounts unreadable.
  - [ ] A configured private CA is actually present in the running container's trust store, is
        *added* to public trust rather than replacing it, and an unreadable certificate fails
        `deploy-check` instead of degrading silently. Verification is never disabled to make this
        pass.
  - [ ] `/readyz` and `/healthz` return `200` over plain HTTP with a configured `Host`, a
        data-carrying path such as `/admin/` still returns `301`, and an unrecognised `Host` still
        returns `400`.
  - [ ] Every application service runs as `65532:65532` with a read-only root filesystem, empty
        effective/permitted/bounding capability sets, `NoNewPrivs=1`, and `PidsLimit=256`; only
        `/tmp` and `/app/data` are writable; no container holds a Docker socket; PostgreSQL is
        unpublished with no egress; `deploy-check` runs with `network_mode: none`; and the published
        port is bound to `127.0.0.1` only.

- [ ] The GitHub **Validate the production Compose stack** check passes on the pushed release commit,
      in addition to the local run. CI builds and exercises the stack but never publishes it;
      publishing a prebuilt image remains a separate explicit action.
- [ ] CodeQL and dependency review have run successfully on the intended public host where
      supported.

## Release materials

- [ ] `CHANGELOG.md`, README, deployment, integration, authorization, and release validation
      documents match the candidate.
- [ ] `LICENSE` and `NOTICE` are present in source, package metadata, wheel, and source archive.
- [ ] `sbom/threatbridge.cdx.json` is regenerated, reviewed, and matches the runtime lock.
- [ ] Source archive, SBOM, image digest, and checksums are associated with one commit/tag.
- [ ] Image-specific SBOM and vulnerability reports are regenerated under ignored release evidence
      for the exact final image and are not committed as source.

## Repository configuration on GitHub

These cannot be set from the source tree and must be configured by the repository owner after
publication.

- [ ] Private Vulnerability Reporting is enabled.
- [ ] Secret scanning and push protection are enabled.
- [ ] Dependabot alerts, security updates, and version updates are enabled.
- [ ] CodeQL default or advanced setup is active and its alerts are triaged.
- [ ] Branch protection on the default branch requires pull requests, review, passing status checks
      including `Test, lint, and security`, `Container and filesystem scan`,
      `Validate the production Compose stack`, `CodeQL`, and `Dependency review`, and blocks force
      pushes and deletion.
- [ ] Actions permissions are restricted to selected actions, and `GITHUB_TOKEN` defaults to
      read-only with pull-request write disabled.
- [ ] Workflows from forked pull requests require approval from a maintainer.
- [ ] Tag protection or a protected release environment guards release tags.

## Final authorization

- [ ] An independent reviewer confirms private-file exclusion and validation evidence.
- [ ] Legal and repository owners explicitly authorize repository creation and publication.
- [ ] Publication occurs through an approved account with least-privilege release permissions.
