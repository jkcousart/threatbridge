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
- [ ] The exact Docker patch tag and immutable digest are independently re-resolved.
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
      including `Test, lint, and security`, `Container and filesystem scan`, `CodeQL`, and
      `Dependency review`, and blocks force pushes and deletion.
- [ ] Actions permissions are restricted to selected actions, and `GITHUB_TOKEN` defaults to
      read-only with pull-request write disabled.
- [ ] Workflows from forked pull requests require approval from a maintainer.
- [ ] Tag protection or a protected release environment guards release tags.

## Final authorization

- [ ] An independent reviewer confirms private-file exclusion and validation evidence.
- [ ] Legal and repository owners explicitly authorize repository creation and publication.
- [ ] Publication occurs through an approved account with least-privilege release permissions.
