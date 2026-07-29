# Public release hardening audit

**Date:** 2026-07-29 (America/Edmonton)
**Baseline commit:** `b1f0e22` — `feat(deploy): add hardened production Docker profile`
**Branch:** `security/public-release-hardening-audit`
**Recommendation:** READY WITH DOCUMENTED CONDITIONS (see [Recommendation](#recommendation))

This audit is aligned with, and informed by, the CIS Docker Benchmark, OWASP Docker and container
security guidance, OpenSSF open-source repository and supply-chain practices, and Django deployment
security guidance. It is not a certification and asserts no formal compliance.

## Scope

- Repository and Git history hygiene for public release.
- `Dockerfile`, `compose.yml`, `compose.production.yml`, `compose.production.step-ca.yml`,
  `deploy/.env.production.example`, `deploy/README.md`.
- `threatbridge/settings.py`, `threatbridge/checks.py`, `threatbridge/wsgi.py`,
  `threatbridge/asgi.py`, and related tests.
- Outbound and import paths: `integrations/outbound.py`, `integrations/http.py`,
  `integrations/adapters/http_client.py`, the OpenCTI, MITRE ATT&CK, and Trivy adapters,
  `integrations/file_imports.py`, `integrations/import_limits.py`, `integrations/import_schemas.py`,
  `integrations/secrets.py`, `integrations/views.py`, `integrations/services.py`, and
  `threatbridge/authorization.py`.
- `pyproject.toml`, `requirements/`, `.github/workflows/`, `.github/dependabot.yml`, and the
  release, scan, lock, SBOM, and image-validation scripts.
- Public documentation: `README.md`, `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, and `docs/`.

Out of scope: penetration testing, formal threat modelling of deferred features, and any change to
the deferred product roadmap.

## Methods

- Read every file in scope rather than sampling.
- Static analysis with Ruff, Bandit, and Trivy configuration scanning.
- Secret scanning of the working tree, the Git-tracked and non-ignored candidate tree, and all 14
  reachable commits, with redacted output only.
- Behavioural verification of fail-closed startup paths by launching `manage.py` under synthetic
  production environments with throwaway secrets. No live credential, live database, or production
  connector was used.
- Regression tests added with each behavioural change, then the complete suite re-run.
- Structural verification of the Compose profiles by parsing them and asserting the confinement
  contract in `tests/test_deployment_tooling.py`.

**Limitation.** The Docker daemon was unavailable in the WSL 2 distribution used for the audit pass
(`docker version` reported the CLI could not reach a daemon). At that point no image was built, no
container was run, and `docker compose config` was not executed. Every Docker and Compose statement
in this document is a static or test-asserted claim rather than observed runtime behaviour, except
where the follow-up below says otherwise. The commands an operator must run on a Docker host to close
this gap are listed under [Conditions before publication](#conditions-before-publication).

### Follow-up: live build attempt (2026-07-29)

A live build was attempted on a host with a working Docker daemon after the audit commit. It failed
in the builder stage, at the installed-wheel validation:

```text
/opt/runtime-venv/bin/python -c 'import ... catalog, integrations, threatbridge ...'
```

The builder `WORKDIR` is `/build`, and `catalog`, `integrations`, and `threatbridge` are copied there
earlier in the stage. For `python -c`, CPython prepends the current directory to `sys.path`, so those
source trees were imported instead of the wheel installed under
`/opt/runtime-venv/lib/python3.13/site-packages`, and the assertion that every module originates from
site-packages failed.

**The validation behaved exactly as designed.** It is there to prove the wheel is authoritative, and
it correctly refused a build in which the packages resolved somewhere else. The defect was in the
invocation, not the check: the interpreter was allowed to see the build directory at all.

The fix is one flag. The invocation now uses `python -P`, CPython's safe-path mode, which omits the
script directory and the current directory from `sys.path`. Both assertions are unchanged: every
ThreatBridge package must resolve inside the runtime virtual environment's site-packages, and `pip`
must be absent from that environment. Nothing was relaxed, no path was added to the allowed set, and
the check still fails closed.

`tests/test_release_tooling.py::test_wheel_validation_cannot_be_satisfied_by_the_build_directory`
guards the regression. It asserts that the source trees really are copied into the builder working
directory, that the single validation invocation enables safe-path mode, that both assertions are
still present, and — by running the real interpreter against a decoy package — that safe-path mode
actually suppresses the shadowing it is relied upon to suppress.

### Follow-up: live image validation (2026-07-29)

With the safe-path fix in place, the release-candidate image **built successfully on Docker Desktop**,
and the builder stage's installed-wheel validation **passed**: every ThreatBridge package resolved
inside `/opt/runtime-venv/.../site-packages` and `pip` was absent from the runtime environment. The
wheel is authoritative in the built image.

`scripts/validate_container_image.sh` then failed, but not because of anything in the image. Docker
reported the image metadata correctly:

```text
User='65532:65532'
ExposedPorts={'8000/tcp': {}}
Entrypoint=None
Cmd=<expected Gunicorn command>
```

**The image exposes only `8000/tcp`, which is the intended state.** The defect was host-side, in the
validator's parsing. Docker's Go template emits a trailing blank record, so the raw bytes were
`38 30 30 30 2f 74 63 70 0a 0a` — `8000/tcp\n\n`. The old pipeline sorted before discarding empty
records, and an empty line sorts ahead of every port, so `tr '\n' ' '` produced a leading space that
`sed 's/ $//'` did not remove. The comparison received `" 8000/tcp"` and reported:

```text
Unexpected exposed ports:  8000/tcp
```

That is a false positive from a parser bug, not a confinement failure.

The parser now drops empty records before sorting, sorts under a fixed collation, and joins the
remaining exact port records with a single space:

```text
| awk 'NF {print $1}' | LC_ALL=C sort | paste -sd ' ' -
```

**The security requirement is unchanged and was not weakened.** The check is still an exact string
equality against `8000/tcp`. It was not relaxed to a substring or `grep` match, no additional port was
allowed, and empty output is still rejected. Only the whitespace normalization feeding that
comparison changed.

Two parameterised regression tests in `tests/test_deployment_tooling.py` run the real validator
against a stub `docker` that reproduces Docker's byte-for-byte output.
`test_exposed_port_inspection_tolerates_blank_records` covers a trailing blank record, a blank record
ahead of the port, and a bare port line, and proves normalization yields exactly `8000/tcp` by the
fact that the equality check passes.
`test_exposed_port_inspection_rejects_anything_but_the_single_expected_port` proves an extra TCP port,
an extra UDP port on the same number, and an empty port set are all still rejected, with
deterministically sorted, single-space-joined output in the message. Both tests fail against the old
pipeline, reproducing the reported `Unexpected exposed ports:  8000/tcp` symptom.

### Follow-up: confinement validation, scanning, and base-image selection (2026-07-29)

With the port parsing corrected, `scripts/validate_container_image.sh` ran to completion against the
Debian 13 slim release candidate and **passed in full**. That closes the confinement evidence gap that
had been open since the audit pass. Observed on the live image:

- effective UID and GID `65532:65532`, and `Config.User` of `65532:65532`;
- `8000/tcp` as the only exposed port;
- `catalog`, `integrations`, and `threatbridge` resolving inside `/opt/runtime-venv` site-packages,
  with no `pip` and no test packages in the runtime wheel;
- `NoNewPrivs=1` and empty `CapEff`, `CapPrm`, and `CapBnd` under `--cap-drop ALL`;
- a read-only root filesystem, with `/`, `/app`, `/opt/runtime-venv`, and `/etc` all refusing writes
  and only `/tmp` writable;
- no Docker socket inside the container;
- expected `/app` contents and permissions, no world-writable path, and no source, test, secret, or
  build material in the runtime layer;
- the complete OCI label set present.

`scripts/generate_image_sbom.sh` also **succeeded**, producing a CycloneDX image SBOM covering
operating-system and Python packages for that exact image ID.

`scripts/scan_container_image.sh` then **blocked the candidate**: 23 blocking findings, 4 CRITICAL and
19 HIGH. That is the finding policy working as intended — it blocks a prebuilt image on any unfixed
HIGH or CRITICAL regardless of reachability, and no suppression was created.

#### Base-image comparison

Because the application layer was proven clean and the blocking findings were all base-image
operating-system packages, the comparison moved to the base. Every candidate was built with the same
committed hash-locked requirements and put through the same complete validation.

| Candidate | Resolved digest | Build | Container validation | Trivy 0.70.0 policy |
| --- | --- | --- | --- | --- |
| `python:3.13.14-slim` (Debian 13) | `sha256:6771159c…0e1a91` | Pass | Pass | **Blocked** — 23 findings: 4 CRITICAL, 19 HIGH |
| `python:3.13.14-slim-bookworm` (Debian 12) | `sha256:9d7f2875…0e8d64` | Pass | Pass | **Blocked** — 24 findings: 6 CRITICAL, 18 HIGH |
| `python:3.13.14-alpine3.24` | `sha256:399babc8…83f4b0` | Pass | Pass | **Pass** — 0 CRITICAL, 0 HIGH |

The Alpine candidate built from the existing hash-locked requirements with no added `apk` package,
passed the installed-wheel check, and passed every confinement assertion individually: non-root
identity, `no-new-privileges`, empty capability sets, read-only root filesystem, and the exact
exposed-port policy.

#### Selection rationale

`python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0` is
now the committed default builder and runtime base.

It was selected because it is the only evaluated candidate that satisfies the existing finding policy
on its own evidence. All three candidates built and passed identical runtime validation, so this was
not a compatibility or functionality decision, and the policy was not relaxed to accommodate any of
them. The two Debian candidates were rejected because they exceeded a gate that already existed.

Three qualifications are recorded deliberately:

1. **This is point-in-time evidence.** It describes three image IDs against one scanner database on
   one date. A later scan of the same Alpine digest can report new findings, and nothing here promises
   otherwise. A lower finding count is not proof that a base is secure.
2. **musl compatibility was tested for the current locked dependency set only.** `psycopg-binary` is
   the sole component with compiled artifacts, and it installed and ran under `--require-hashes` on
   musl in the validated build. Adding or upgrading a dependency with compiled artifacts is therefore
   also a base-compatibility change. Development and CI remain on glibc.
3. **Alpine is not distroless.** The runtime layer still has a shell and `apk`. The Dockerfile installs
   no `apk` package, and the confinement controls are what constrain the runtime, not the absence of
   tooling.

Hardened, mirrored, and private registry overrides are unchanged and still supported through
`PYTHON_BUILDER_IMAGE`, `PYTHON_RUNTIME_IMAGE`, `THREATBRIDGE_BUILDER_TAG`, and
`THREATBRIDGE_RUNTIME_TAG`. `scripts/resolve_production_images.sh` now defaults to the same exact
patch-level Alpine tag rather than a floating `python:3.13-slim`, which also brings it in line with the
documented requirement in `docs/supply-chain.md` to select an exact patch tag.

#### What this does not yet establish

The Alpine evidence comes from a locally built comparison candidate, not from the committed default.
Two things must happen before a prebuilt image can be called ready:

1. **Rebuild from the committed default** — `docker build --no-cache` with no `--build-arg` override —
   and rerun validation, SBOM generation, and scanning against that exact image ID. Evidence from a
   comparison build is not evidence about the committed artifact.
2. **Exercise the production Compose stack end to end** against that image, confirming the
   `deploy-check` gate, migrations, PostgreSQL connectivity, and readiness.

Generated reports for these runs stay in the ignored `release-evidence/` directory and are not
committed. Source-repository publication and prebuilt-image publication remain separate decisions.

## Findings by severity

No finding was a live secret, a credential in history, or an exploitable remote vulnerability. The
baseline was already substantially hardened; these are the gaps found and closed.

### High

| ID | Finding | Resolution |
| --- | --- | --- |
| H-1 | The documented production deployment resolved its base images from a subscription registry, so no third party could follow the documented path. Public users would have improvised an unreviewed base. | `scripts/resolve_production_images.sh` and `deploy/.env.production.example` now default to a publicly pullable Docker Official Image, resolved to a digest. The follow-up above settled that default on the exact patch-level `python:3.13.14-alpine3.24`. A hardened, mirrored, or private base remains available through `THREATBRIDGE_BUILDER_TAG` and `THREATBRIDGE_RUNTIME_TAG`. |
| H-2 | `DJANGO_TRUST_X_FORWARDED_PROTO` was hard-coded to `true` in the production profile. A deployment published without a stripping reverse proxy would treat any attacker-supplied `X-Forwarded-Proto: https` as proof of TLS, satisfying secure-cookie and redirect logic over plaintext. | The value now defaults to `false` and must be opted into. `threatbridge.W002` warns when it is on, and `test_production_compose_does_not_trust_forwarded_proto_by_default` locks the default. |
| H-3 | `DJANGO_DEBUG` defaults to `true`. A production process that failed to set it would serve with `DEBUG=True`, exposing stack traces and settings. | `threatbridge/runtime.py` requires an explicit `true`/`false`, and `wsgi.py` and `asgi.py` refuse to construct an application without it. Development and `manage.py` are unaffected. |
| H-4 | `SECRET_KEY` was required in production but unvalidated. A short, repeated, or copy-pasted placeholder key was accepted, undermining session and CSRF signing. | Production keys must be at least 50 characters with at least 16 distinct characters and must not contain any of 15 placeholder markers. |
| H-5 | Credentials could reach logs. No handler redacted anything, and Gunicorn's access log records full request lines, so a token in a query string was written verbatim. | `threatbridge/log_redaction.SensitiveDataFilter` is attached to every handler, including explicit `gunicorn.access` and `gunicorn.error` loggers. It removes URL userinfo, `Authorization` and `Cookie` header values, `Bearer`/`Basic`/`Token` credentials, and sensitive query parameters. `threatbridge.E003` fails the deployment check if any handler omits it. |
| H-6 | The development profile published `8000` on every host interface, so `docker compose up` on a laptop or lab host exposed a `DEBUG=True` instance with a well-known database password to the whole network. | The port is now bound to `127.0.0.1`, and the service runs unprivileged with all capabilities dropped and `no-new-privileges`. |

### Medium

| ID | Finding | Resolution |
| --- | --- | --- |
| M-1 | Cloud metadata services were blocked by address but not by name. An operator who allowlisted `metadata.google.internal` for a legitimate-looking reason would have reached the metadata API, and provider metadata addresses beyond `169.254.169.254` were not enumerated. | Metadata hostnames and their subdomains are refused before allowlist evaluation, and the Alibaba, AWS ECS, and IPv6 EC2 metadata addresses are refused explicitly. |
| M-2 | 6to4, Teredo, and NAT64 prefixes embed an inner IPv4 address behind a globally routable prefix, so `is_global` reported them safe and they bypassed the private-CIDR requirement. | `_TUNNEL_NETWORKS` refuses `192.88.99.0/24`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, and `2001::/32` unconditionally. |
| M-3 | A single timeout covered connect and read, so an unreachable host consumed the entire read budget before failing. | `THREATBRIDGE_OUTBOUND_CONNECT_TIMEOUT` (default 10 s) bounds the connect phase and is capped by the read timeout. |
| M-4 | The redirect ceiling was inherited from `urllib`'s default of 10. | `MAX_REDIRECTS = 3` is declared on the validated redirect handler. |
| M-5 | Outbound requests advertised `Python-urllib/3.13`, disclosing the interpreter version, and did not pin `Accept-Encoding`, so a bounded read depended on the server not compressing. | A fixed `ThreatBridge/0.3` user agent and `Accept-Encoding: identity` are shared by every outbound path. |
| M-6 | Django's own request limits were left at defaults, well above the application's `THREATBRIDGE_MAX_UPLOAD_BYTES`, and neither form fields nor uploaded files per request were capped. | `DATA_UPLOAD_MAX_MEMORY_SIZE`, `FILE_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_NUMBER_FIELDS`, and `DATA_UPLOAD_MAX_NUMBER_FILES` are derived from the application limits, and stored uploads are written `0600` inside `0700` directories. |
| M-7 | The REST API had no rate limiting, so credential stuffing against session login and repeated expensive sync or assessment calls were unbounded. | Anonymous (30/minute) and authenticated (600/minute) throttles are configured and required by `threatbridge.E004`. |
| M-8 | `manage.py check --deploy` was documented but nothing ran it, so a misconfigured production stack started and served. | A `deploy-check` service runs `check --deploy --fail-level ERROR`; `migrate` requires it to complete successfully, and `web` requires `migrate`, so nothing serves until the check passes. |
| M-9 | HSTS preload and subdomain inclusion could be enabled while the duration was short or zero, committing browsers to HTTPS for a deployment that had not proven it. | Startup rejects preload below a full year or without subdomain inclusion, and rejects subdomain inclusion at zero duration. |
| M-10 | No workflow scanned the container image or the repository for secrets or Dockerfile misconfiguration. | `.github/workflows/container-scan.yml` runs a Trivy secret scan, a Trivy configuration scan, an image build, `validate_container_image.sh`, and `scan_container_image.sh`, which fails on any HIGH or CRITICAL image finding. |
| M-11 | `scripts/compare_base_images.sh` recorded a blocked or skipped scan and still exited zero, so evidence collection could be mistaken for approval. | It now exits non-zero unless every candidate's scan policy is `pass`. |
| M-12 | Authorization tests covered successful paths and a subset of denials. Several state-changing endpoints had no test proving they refuse an authenticated caller without the required permission. | Three parameterised denial tests now cover every state-changing endpoint on both the browser and API surfaces, restricted-evidence reads, and anonymous mutations. |

### Low

| ID | Finding | Resolution |
| --- | --- | --- |
| L-1 | The image carried no OpenContainers labels, so a pulled image could not be traced to a commit or licence. | Title, description, version, revision, creation time, licence, source, documentation, and base-image labels are set, and `validate_container_image.sh` asserts all of them. |
| L-2 | No service set `init: true`, so a zombie-reaping gap existed, and no service had CPU, memory, or PID limits, so one container could starve the host. | Both are set on every service in the production profile, with `pids_limit` and log rotation in the development profile as well. |
| L-3 | The PostgreSQL container kept the default capability set. | All capabilities are dropped except the five its root-then-drop entrypoint requires, with `no-new-privileges` enabled. The residual risk is documented. |
| L-4 | The step-ca overlay relied on Compose's default config target, leaving the in-container path, owner, and mode implicit, and covered only some services. | Long syntax pins `/run/configs/threatbridge_extra_ca`, owner `65532:65532`, mode `0444`, applied to `deploy-check`, `migrate`, and `web`. |
| L-5 | `USE_X_FORWARDED_HOST` and `USE_X_FORWARDED_PORT` were unset, so a future change could enable them silently. | Both are explicitly `False`, `SECURE_CROSS_ORIGIN_OPENER_POLICY` is `same-origin`, and a test locks the values. |
| L-6 | Private security work products under `docs/security/` were protected only by individual filenames, so a new internal report was committable by accident. | `.gitignore` and `.dockerignore` ignore the directory by default and require an explicit exception per published document. A regression test enforces the rule. |
| L-7 | Dependency review did not consider licences, so a transitive AGPL or SSPL dependency could silently change ThreatBridge's redistribution obligations. | AGPL, SSPL, and BUSL are denied, and the check now fails at MODERATE severity for runtime and development scopes. |
| L-8 | `tests/test_release_tooling.py` asserted a hard-coded workflow count, so adding a security workflow broke it and removing one did not. | It validates whatever is on disk, asserts the security-relevant workflows exist, and asserts no step swallows a failure. |
| L-9 | `docs/release-validation.md` described a runtime user and interpreter paths that no longer match the image, and its scan counts read as current. | A status header marks it as point-in-time evidence and identifies exactly which statements are superseded. The historical numbers were not rewritten. |
| L-10 | Public documentation did not state the malware-sandbox boundary, the limits of container isolation, or the split between repository-enforced and host-enforced controls. | All three are stated in `README.md`, `SECURITY.md`, `docs/security-architecture.md`, and `docs/deployment-hardening.md`, which now carries a responsibility matrix and a residual-risk list. |

### Informational — verified, no change required

The following were checked and found already correct: multi-stage build with no build tooling or
`pip` in the runtime environment; digest-pinned bases with no floating tag; numeric non-root final
`USER`; explicit `COPY` ownership with no group- or world-writable runtime path; no secret in any
`ARG` or `ENV`; `.dockerignore` excluding `.env`, `.git`, databases, caches, and release evidence;
hash-locked deterministic installs; a health check that discloses nothing; exec-form entrypoint with
Gunicorn receiving signals; `PYTHONDONTWRITEBYTECODE=1` for read-only operation; no Django
development server in production; no Docker socket, host namespace, host root, `/proc`, `/sys`, or
`/dev` mount anywhere; no published database port; `_FILE` secret support with permission and symlink
validation; DNS revalidation inside the connection factory; same-origin redirect validation; TLS SNI
retained under connection pinning; credential-bearing URL rejection; production HTTPS enforcement;
bounded response reads; import byte, record, depth, field, scalar, column, line, preview, and error
limits; random storage filenames with the original name kept only as metadata; no `pickle`,
`yaml.load`, `eval`, or `exec` on imported data; no CSV export and therefore no formula-injection
sink; no shell execution on any outbound or import path; session-only API authentication with CSRF
retained; bounded redacted audit metadata; `contents: read` top-level workflow permissions with
full-SHA action pins; and no `pull_request_target` and no workflow consuming a secret.

## Fixes applied

37 files changed, 4 added. Grouped by area:

**Django configuration and runtime** — `threatbridge/settings.py`, `threatbridge/checks.py`,
`threatbridge/runtime.py` (new), `threatbridge/log_redaction.py` (new), `threatbridge/wsgi.py`,
`threatbridge/asgi.py`.

**Outbound and integrations** — `integrations/outbound.py`, `integrations/http.py`,
`integrations/adapters/http_client.py`.

**Container and Compose** — `Dockerfile`, `compose.yml`, `compose.production.yml`,
`compose.production.step-ca.yml`, `deploy/.env.production.example`.

**Scripts** — `scripts/resolve_production_images.sh`, `scripts/compare_base_images.sh`,
`scripts/security_check.sh`, `scripts/validate_container_image.sh`,
`scripts/prepare_production_deployment.py`.

**Supply chain** — `.github/workflows/container-scan.yml` (new),
`.github/workflows/dependency-review.yml`, `.gitignore`, `.dockerignore`.

**Tests** — `threatbridge/tests/test_settings.py`, `threatbridge/tests/test_authorization.py`,
`integrations/tests/test_http.py`, `tests/test_deployment_tooling.py`,
`tests/test_release_tooling.py`.

**Documentation** — `README.md`, `SECURITY.md`, `SUPPORT.md`, `CHANGELOG.md`,
`docs/security-architecture.md`, `docs/deployment-hardening.md`,
`docs/container-image-security.md`, `docs/supply-chain.md`, `docs/public-release-readiness.md`,
`docs/release-checklist.md`, `docs/release-validation.md`, `deploy/README.md`, and this document.

### Compatibility impact

- A production process started through a WSGI or ASGI server must now set `DJANGO_DEBUG` explicitly.
  Existing deployments that relied on the default will fail to start with a specific message.
- A production `SECRET_KEY` shorter than 50 characters, with fewer than 16 distinct characters, or
  containing a placeholder marker is now rejected. Rotating the key invalidates existing sessions.
- `DJANGO_TRUST_X_FORWARDED_PROTO` must be set to `true` explicitly for deployments behind a
  stripping reverse proxy. Leaving it unset behind a proxy causes secure-cookie and redirect logic to
  treat requests as plaintext.
- API clients exceeding 600 requests per minute per user now receive `429`.
- A request larger than roughly the upload limit, or with more than 200 form fields or 10 files, is
  now rejected by Django before application code runs.
- The production profile fails to start until `THREATBRIDGE_BIND_ADDRESS` is set; there is no
  default.
- An outbound integration reached through a NAT64, 6to4, or Teredo address, or through a metadata
  hostname, no longer connects. No supported adapter uses such a destination.
- No test was changed to accept less secure behaviour. One test constant was rewritten to derive its
  value instead of embedding a high-entropy literal, which removed four Gitleaks findings in the
  candidate tree without weakening any assertion.

## Test and scanner outcomes

Tool versions: Python 3.14.4 (host), Django 6.0.7, pytest 9.1.1, Ruff 0.15.22, Bandit 1.9.4,
pip-audit 2.10.1, Trivy 0.70.0, Gitleaks (build-stamped version string).

| Check | Result |
| --- | --- |
| `python -m pytest` | **Pass** — 213 passed, 130 subtests passed (baseline: 180 passed) |
| `python manage.py check` | **Pass** — no issues |
| `python manage.py makemigrations --check --dry-run` | **Pass** — no changes detected |
| `manage.py check --deploy --fail-level ERROR` (synthetic production) | **Pass** — exit 0, one informational `security.W021` HSTS-preload notice |
| `python -m ruff check .` | **Pass** |
| `python -m ruff format --check .` | **Pass at baseline parity** — 37 pre-existing files differ, unchanged by this work; every file touched here is format-clean |
| `python scripts/validate_dependency_locks.py` | **Pass** — build 3, runtime 11, development 73 |
| `python scripts/validate_workflows.py` | **Pass** — 6 workflows, 13 pinned action uses |
| `python -m pip check` | **Pass** |
| `pip-audit --require-hashes --disable-pip` on both locks | **Pass** — no known vulnerabilities |
| `python -m bandit -r catalog integrations threatbridge` | **Pass** — 0 issues across 9,850 lines, 0 `#nosec` |
| `bash scripts/security_check.sh` | **Pass** — exit 0 end to end |
| Trivy configuration scan, MEDIUM and above | **Pass** — 0 misconfigurations |
| Trivy filesystem secret scan | **Pass** — 0 secrets |
| Gitleaks, candidate tree | **Pass** — no leaks |
| Gitleaks, all 14 reachable commits | **Pass** — no leaks |
| SBOM regeneration byte-comparison | **Pass** — matches `sbom/threatbridge.cdx.json` |
| `docker compose config` (both profiles) | **Not run** — no Docker daemon available during the audit pass |
| Image build | **Pass, after one fix** — the first attempt failed because the builder working directory shadowed the installed wheel and the wheel validation correctly refused it. With `python -P` the image builds on Docker Desktop and the installed-wheel validation passes. See [Follow-up: live build attempt](#follow-up-live-build-attempt-2026-07-29). |
| `validate_container_image.sh` | **Pass, after one fix** — a blank-record parsing bug produced a false `" 8000/tcp"` mismatch. With the parser corrected and the exact-port policy intact, the validator runs to completion and every confinement assertion passes on the live image. |
| `generate_image_sbom.sh` | **Pass** — CycloneDX image SBOM produced for the exact image ID |
| `scan_container_image.sh` | **Blocked on Debian, passes on Alpine** — the Debian 13 candidate recorded 23 blocking findings (4 CRITICAL, 19 HIGH) and Debian 12 Bookworm 24 (6 CRITICAL, 18 HIGH); the Alpine 3.24 candidate recorded 0 CRITICAL and 0 HIGH and is now the committed default. See [Follow-up: confinement validation, scanning, and base-image selection](#follow-up-confinement-validation-scanning-and-base-image-selection-2026-07-29). |
| Rebuild from the committed default; production Compose stack | **Pending** — the Alpine evidence comes from a comparison build, not from the committed default |

### Fail-closed behaviour verified by execution

Each of these was run against a synthetic production environment with throwaway values and produced
an `ImproperlyConfigured` refusal at startup:

- missing `DJANGO_SECRET_KEY`;
- a placeholder key ("looks like a placeholder value");
- a key under 50 characters;
- a key with fewer than 16 distinct characters;
- `DJANGO_ALLOWED_HOSTS=*`;
- a non-PostgreSQL `DATABASE_URL`;
- an empty `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS`;
- `DJANGO_SECURE_HSTS_PRELOAD=true` with a 300-second duration;
- importing `threatbridge.wsgi` with `DJANGO_DEBUG` unset.

Because these run at settings import, they pre-empt `manage.py check`, which is the stronger
outcome: the process cannot reach a serving state at all.

## Docker runtime controls

Asserted statically and by `tests/test_deployment_tooling.py`, and asserted at runtime by
`scripts/validate_container_image.sh` when a Docker daemon is available:

| Control | Production profile | Verified by |
| --- | --- | --- |
| Non-root numeric user | `65532:65532` on every app service | Compose test; image `Config.User` assertion |
| `cap_drop: [ALL]` | Every app service; database keeps five required capabilities | Compose test; `CapEff` assertion on a hardened run |
| `no-new-privileges:true` | Every service | Compose test; `NoNewPrivs=1` assertion |
| Read-only root filesystem | Every app service | Compose test; `HostConfig.ReadonlyRootfs` assertion |
| Writable paths | `/tmp` tmpfs (64 MiB, `noexec,nosuid,nodev`) and the `/app/data` named volume only | Compose test; write probes |
| No Docker socket, host namespace, host root, `/proc`, `/sys`, `/dev` | Absent everywhere | Compose test; mount inspection |
| `init: true` | Every service | Compose test |
| `pids_limit`, CPU and memory limits | Every service | Compose test |
| Health check | `web` and `db` | Compose test |
| Exposed ports | `8000/tcp` only in the image; published only on an explicitly configured host address | Compose test; `Config.ExposedPorts` assertion |
| No published database port; internal network | Enforced | Compose test |
| Log rotation | `json-file` with size and file caps | Compose test |
| OCI labels | Complete set | Label assertion |
| Fails closed without production secrets | Verified by execution outside Docker | Fail-closed section above |

The runtime column is a contract the validation script enforces on a Docker host, not an observation
made during this audit.

## Git history and public-data review

- 14 reachable commits and the full candidate tree scanned with Gitleaks: **no leaks found**. No
  secret value was printed at any point.
- No `.env`, `.secrets/`, private key, certificate, `db.sqlite3`, virtual environment, `__pycache__`,
  `.pytest_cache`, or `.ruff_cache` has ever been added in any reachable commit. The only
  environment files ever tracked are `.env.example` and `deploy/.env.production.example`, both
  placeholder templates.
- Local `.env`, `.secrets/`, `db.sqlite3`, `.venv/`, `release-evidence/`, and all runtime data under
  `data/` are present on disk, untracked, and ignored. Their contents were never read.
- Every address in tracked content is RFC 1918 or `.invalid` documentation material used as a test
  fixture (`10.20.0.0/16`, `10.21.1.10`). No real internal hostname, private address, or home
  infrastructure name is present.
- Every email address in tracked content is `@example.invalid` except the intentional public conduct
  mailbox. No employer, customer, or CES Energy Solutions reference exists in the tree or in history.
- `sbom/threatbridge.cdx.json` is tracked and correct: it is reproducible from the runtime lock,
  regenerates byte-for-byte, and contains no host path or local metadata. `release-evidence/` is
  correctly untracked because it is bound to a local image digest.
- Private security work products under `docs/security/` remain ignored and untracked; only this
  document is published, through an explicit exception.

**No historical secret incident was found. No history rewrite is required or was performed.**

## Remaining risks

1. **The committed default has not been rebuilt and revalidated.** Container confinement is now
   observed rather than asserted, but on a comparison build. The Alpine default must be rebuilt with
   no `--build-arg` override and put through validation, SBOM generation, and scanning as that exact
   artifact, and the production Compose stack must be exercised end to end against it. This is the
   primary condition on the recommendation.
2. **The clean base scan is point-in-time.** The Alpine 3.24 default recorded 0 CRITICAL and 0 HIGH
   under Trivy 0.70.0 on 2026-07-29. Operating-system packages acquire advisories over time, so that
   result must be reproduced by rescanning rather than assumed. ThreatBridge is not certified and is
   not claimed to be free of vulnerabilities. Prebuilt-image publication remains governed by the
   policy in `docs/container-image-security.md`; publishing the reviewed source repository is a
   separate decision.
3. **musl compatibility is proven only for the current locked dependency set.** `psycopg-binary` is
   the one component with compiled artifacts and it installed and ran on musl in the validated build.
   A future dependency addition or upgrade with compiled artifacts is also a base-compatibility
   change, and development and CI still run on glibc.
4. **Authorization is role-based and global**, not per-object. Any holder of a named permission can
   act on every object of that type. Denials return `403` for both existing and missing identifiers.
5. **Imports are not one end-to-end atomic transaction.** A strict import failing midway can leave
   accepted records persisted alongside a failed run record; the audit trail records this.
6. **Import validation is heuristic**, not schema-driven: shape, size, depth, and count limits plus
   per-type field heuristics rather than a formal JSON Schema.
7. **The PostgreSQL container retains five capabilities** and a writable root filesystem, because its
   entrypoint starts as root and drops privileges. A separately administered PostgreSQL service is
   the recommended topology.
8. **The bundled database volume has no replication, point-in-time recovery, or automated backup
   schedule.** Durability is whatever the host gives that volume plus the documented manual backups.
9. **No release signing or provenance attestation** exists yet; `docs/supply-chain.md` records it as
   future work rather than claiming it.
10. **No malware scanning or quarantine.** ThreatBridge parses files as data and never executes them,
    but an operator accepting untrusted uploads must add both.
11. **Container isolation is defence in depth, not a boundary.** A host kernel or runtime
    vulnerability can defeat the profile.
12. **The workflows have never run on GitHub.** Hosted permissions, CodeQL availability, and
    Dependabot behaviour cannot be proven locally.

## Items requiring repository-owner configuration in GitHub

None of these can be set from the source tree.

1. Enable Private Vulnerability Reporting (`SECURITY.md` already directs reporters to it).
2. Enable secret scanning and push protection.
3. Enable Dependabot alerts, security updates, and version updates (`.github/dependabot.yml` is
   present but has never run).
4. Enable CodeQL code scanning and triage its alerts.
5. Protect the default branch: require a pull request, require review, require the `Test, lint, and
   security`, `Container and filesystem scan`, `CodeQL`, and `Dependency review` checks, and block
   force pushes and branch deletion.
6. Set Actions permissions to selected actions only, and set the default `GITHUB_TOKEN` to read-only
   with pull-request write disabled.
7. Require maintainer approval for workflows on pull requests from forks.
8. Add tag protection or a protected release environment before any release tag.
9. Confirm the CODEOWNERS identity and the private conduct mailbox resolve on the public repository.

## Verification commands

Run from the repository root with the project virtual environment active.

```bash
# Provenance
git log --oneline -1
git diff --stat b1f0e22..HEAD
git diff --name-status b1f0e22..HEAD
git status --short
git diff --check

# Tests, lint, and locks
python -m pytest
python -m ruff check .
python manage.py check
python manage.py makemigrations --check --dry-run
python scripts/validate_dependency_locks.py
python scripts/validate_workflows.py

# Full security gate: locks, workflows, Ruff, Django, pytest, pip check,
# pip-audit, Bandit, SBOM comparison, Trivy config scan, Gitleaks
bash scripts/security_check.sh

# Deployment checks against a synthetic production environment
DJANGO_DEBUG=false \
DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
DJANGO_ALLOWED_HOSTS=threatbridge.example.invalid \
DJANGO_CSRF_TRUSTED_ORIGINS=https://threatbridge.example.invalid \
DJANGO_SECURE_HSTS_SECONDS=31536000 \
DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=true \
DATABASE_URL=postgresql://threatbridge@database.example.invalid/threatbridge \
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid \
python manage.py check --deploy --fail-level ERROR

# Fail-closed proof: each must refuse to start
env -u DJANGO_DEBUG python -c 'import threatbridge.wsgi'
DJANGO_DEBUG=false DJANGO_SECRET_KEY='changeme-changeme-changeme-changeme-changeme-changeme-x' \
  DJANGO_ALLOWED_HOSTS=tb.example.invalid \
  DJANGO_CSRF_TRUSTED_ORIGINS=https://tb.example.invalid \
  DJANGO_SECURE_HSTS_SECONDS=31536000 \
  DATABASE_URL=postgresql://tb@db.example.invalid/tb \
  THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=o.example.invalid \
  python manage.py check

# History and public-data review
gitleaks git --redact --verbose --log-opts="--all" .
git log --all --pretty=format: --name-only --diff-filter=A | sort -u
git check-ignore -v .env .secrets db.sqlite3 .venv release-evidence
git status --porcelain --untracked-files=all
```

On a host with a working Docker daemon, additionally:

```bash
docker compose -f compose.production.yml config
docker compose -f compose.production.yml -f compose.production.step-ca.yml config
# Rebuild from the committed Alpine default: no --build-arg override, so the image
# under test is the one a third party gets from a plain `docker build`.
docker build --no-cache -t threatbridge-release-candidate:local .
docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.base.name"}}' \
    threatbridge-release-candidate:local
./scripts/validate_container_image.sh threatbridge-release-candidate:local
./scripts/generate_image_sbom.sh threatbridge-release-candidate:local
./scripts/scan_container_image.sh threatbridge-release-candidate:local
```

## Recommendation

**READY WITH DOCUMENTED CONDITIONS** for publication of the reviewed source repository.

Everything verifiable in this environment passes: the full test suite, lint, Django checks,
deployment checks under a synthetic production environment, dependency-lock and workflow validation,
`pip check`, `pip-audit`, Bandit, the SBOM byte comparison, the Trivy configuration and secret scans,
and Gitleaks against both the candidate tree and all reachable history. No secret exists in the tree
or in history, no history rewrite is needed, and every fail-closed guard was proven by execution.

Container runtime confinement is now **observed rather than asserted**: the validator ran to completion
against a live image and proved the non-root identity, read-only root filesystem, empty capability
sets, `NoNewPrivs=1`, `/tmp`-only writability, absent Docker socket, authoritative installed wheel, and
single exposed port. The default base was moved to the Alpine 3.24 candidate that recorded zero HIGH or
CRITICAL findings under the reviewed Trivy 0.70.0 policy.

READY is withheld because that evidence belongs to comparison builds rather than to the committed
default. **A prebuilt image is explicitly not READY.** Two outstanding items are gaps in evidence
rather than known defects, and both are mechanical.

### Conditions before publication

1. On a host with Docker, rebuild from the committed default — `docker build --no-cache` with no
   `--build-arg` override — then run `scripts/validate_container_image.sh`,
   `scripts/generate_image_sbom.sh`, and `scripts/scan_container_image.sh` against that exact image ID.
   All must pass, including the hardened validation run that proves a non-root UID, read-only root
   filesystem, empty capability set, `NoNewPrivs=1`, a writable `/tmp`, no Docker socket, and the
   single expected exposed port.
2. Start the production Compose stack end to end against that image and confirm the `deploy-check`
   gate, migrations, PostgreSQL connectivity, and readiness, plus the Compose commands above.
3. Re-resolve the base-image digests and rerun the unsuppressed image scan immediately before release,
   since the clean Alpine result is point-in-time. Prebuilt-image publication stays blocked while any
   HIGH or CRITICAL finding is unfixed; source publication is a separate decision.
4. Apply the GitHub repository settings listed above, then confirm every workflow succeeds on the
   public host.
5. Have an independent reviewer confirm private-file exclusion and this evidence, per
   `docs/release-checklist.md`.

No risk was accepted silently, no scanner finding was suppressed, and no test was weakened.
