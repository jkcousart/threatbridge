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

#### What this did not yet establish

At the time of the base-image change, the Alpine evidence came from a locally built comparison
candidate rather than from the committed default. Two things were still outstanding: a rebuild from
the committed default with no `--build-arg` override, and an end-to-end run of the production Compose
stack. Both were then carried out and are recorded in the following section.

Generated reports for these runs stay in the ignored `release-evidence/` directory and are not
committed. Source-repository publication and prebuilt-image publication remain separate decisions.

### Follow-up: production Compose integration test (2026-07-29)

Docker Desktop 29.6.1 with Compose v5.3.0 became available, so the committed default was rebuilt and
the production profile was run end to end for the first time. **The rebuild and image validation
passed, and the Compose run then exposed six defects that no amount of static review had caught.**
Three of them made the documented deployment path unusable, and one silently disabled a security
feature. All six are fixed and re-verified below.

#### Committed-default rebuild

`docker build --no-cache` with no `--build-arg` override, followed by
`scripts/validate_container_image.sh`, `scripts/generate_image_sbom.sh`, and
`scripts/scan_container_image.sh` against that exact image ID:

| Step | Result |
| --- | --- |
| Build from committed default | Pass. `org.opencontainers.image.base.name` reads `python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0`. |
| Installed-wheel and confinement validation | Pass. UID/GID 65532, all three packages resolved under `/opt/runtime-venv/lib/python3.13/site-packages`, `pip` absent, `NoNewPrivs` set, capability sets empty, read-only root, only `8000/tcp` exposed. |
| CycloneDX image SBOM | Generated for the exact image ID, including OS packages. |
| Trivy 0.70.0 image scan | Pass. Zero HIGH and zero CRITICAL. Alpine 3.24.1, 29 OS packages. |

This closes the first outstanding condition: the scanned artifact is now the one a third party gets
from a plain `docker build`, not a comparison candidate.

#### Defect 1 — the production profile was not a loadable Compose project

`docker compose config` failed outright:

```
services.db: can't set distinct values on 'pids_limit' and 'deploy.resources.limits.pids'
```

Every application service and the database set `pids_limit` alongside `deploy.resources.limits`
without a `pids` entry. Compose treats the absent `deploy.resources.limits.pids` as `0`, compares it
against `pids_limit`, and rejects the project. **The documented production deployment could not
start at all.** The PID limits added during this audit introduced it, and the existing tests could
not see it because they parse the YAML directly and never invoke Compose.

Three variants were measured against Compose v5.3.0. `pids_limit` beside `deploy.resources.limits`
with no `pids` is rejected; `deploy.resources.limits.pids` alone is accepted; both keys with equal
values are accepted. Inspecting a running container confirmed that either accepted form applies
`HostConfig.PidsLimit` in plain non-Swarm `compose up`.

Both keys are now declared from a single YAML anchor per service. Keeping `pids_limit` matters
because Compose releases that ignore `deploy` outside Swarm would otherwise drop the limit silently,
and losing a security limit is worse than writing the number in two places; the anchor makes drift
impossible.

#### Defect 2 — secret files were unreadable by the container user

With the project loadable, the `deploy-check` gate failed:

```
django.core.exceptions.ImproperlyConfigured: Unable to read DJANGO_SECRET_KEY_FILE
```

`scripts/prepare_production_deployment.py` created secrets mode `0600` owned by the operator, and the
container runs as UID 65532. Outside Swarm, Compose bind-mounts a file-backed secret with the host
file's ownership and mode and **ignores the `uid`, `gid`, and `mode` options**, printing `config uid,
gid and mode are not supported, they will be ignored`. This was verified directly: inside the
container the files appeared as `-rw------- 1000 1000` and reading one returned `Permission denied`.
The whole documented secret-injection flow was therefore incompatible with the non-root image.

Secrets are now written mode `0444` inside the `0700` secrets directory. The directory is the real
boundary — no unprivileged host user can traverse into it, so the permissive file mode is
unreachable — and a read-only file also stops the container from rewriting its own credentials. The
script verifies the directory mode on every run, refuses any group- or world-writable secret, and
re-applies the mode to existing secrets so an in-place upgrade is repaired without rotating values.

The gate behaving this way is itself the fail-closed evidence: an unreadable secret stopped
`deploy-check`, which stopped `migrate`, which stopped `web`. Nothing served with a broken
configuration.

#### Defect 3 — the container could never report healthy

With secrets readable, the stack started and `web` went `unhealthy`. The probe requested
`http://127.0.0.1:8000/readyz`, which sends `Host: 127.0.0.1`, and `ALLOWED_HOSTS` contains the
operator's hostname, so Django answered `400` and logged `DisallowedHost`. Correcting the `Host`
header then surfaced a second layer: `SECURE_SSL_REDIRECT` answered `301` to
`https://<hostname>/readyz`, which a loopback probe cannot follow.

Both layers are fixed without weakening either control:

- The image probe sends the first entry of `DJANGO_ALLOWED_HOSTS` as its `Host` header. `ALLOWED_HOSTS`
  was **not** widened to accept loopback; an unrecognised `Host` is still answered with `400`.
- `SECURE_REDIRECT_EXEMPT` is limited to `^healthz$` and `^readyz$`. Both return a fixed status
  string and no configuration detail. Verified live: `/readyz` and `/healthz` return `200` over plain
  HTTP while `/` and `/admin/` still return `301` to `https://<hostname>/`.

#### Defect 4 — the Compose health check silently overrode the image probe

Fixing the `Dockerfile` changed nothing at first, because both Compose profiles redefined
`healthcheck.test` with their own copy of the probe. The image's `HEALTHCHECK` was never used, so the
two definitions had drifted apart unnoticed.

Both profiles now omit `test` and override only the timings. Compose was measured to inherit the
image's probe command in that configuration, so the probe is defined once in the `Dockerfile` and a
fix there cannot be shadowed. After this change `web` reported healthy in about nine seconds in both
the production and development profiles.

#### Defect 5 — the private-CA overlay mounted a certificate the application could not read

This is the one that failed silently. Running with `THREATBRIDGE_USE_EXTRA_CA=true` and a mode-`0600`
certificate, the stack reported **healthy** while the mounted file was unreadable:
`UNREADABLE: [Errno 13] Permission denied: '/run/configs/threatbridge_extra_ca'`. The overlay
declares `uid`, `gid`, and `mode`, and Compose ignores all three for configs exactly as it does for
secrets. `_configured_file_path` validated the path's metadata — which succeeds on a file the process
cannot read — but never read it, so the private CA was simply absent from the trust store with no
error anywhere. An operator would have believed private-CA verification was active.

Two changes:

- `_configured_file_path` now reads one byte from every configured file, so an unreadable secret or
  trust anchor fails at startup instead of degrading silently. Verified live: the `deploy-check` gate
  now refuses with `Unable to read THREATBRIDGE_EXTRA_CA_FILE`.
- `scripts/prepare_production_deployment.py` refuses a certificate that UID 65532 could not read and
  names the `chmod` to run. A CA certificate is public material, so a readable mode costs nothing.

With the certificate at `0444`, the trust store was confirmed to contain 120 entries including the
test CA, so the private CA is genuinely loaded and public trust is extended rather than replaced.

#### Defect 6 — the deployment gate was attaching to an implicit network

Rendering the configuration also showed `deploy-check` on a Compose-created `default` bridge with
outbound access, because omitting the `networks` key does not mean "no network". The service reads
configuration only, so it now sets `network_mode: none`. Verified live: the gate runs with `net=none`,
exits `0`, and the implicit `default` network is no longer created.

#### Live verification after the fixes

The full production profile was brought up against the committed-default image. `deploy-check` exited
`0`, migrations applied, PostgreSQL reported healthy, and `web` reported healthy.

| Property | Observed |
| --- | --- |
| Effective user | `65532:65532` |
| Root filesystem | `ReadonlyRootfs=true`; `/` mounted `ro`; writes to `/app`, `/opt/runtime-venv`, `/etc`, `/usr/local/lib`, and `/` all refused |
| Writable paths | Exactly `/tmp` and `/app/data` |
| `/tmp` mount options | `rw,nosuid,nodev,noexec,size=65536k` |
| Capabilities | `CapPrm`, `CapEff`, `CapBnd` all `0000000000000000` |
| Privilege escalation | `NoNewPrivs: 1`; `Seccomp: 2` |
| Limits applied | `PidsLimit=256`, `NanoCpus=2000000000`, `Memory=1073741824` |
| Namespaces | No host PID, IPC, UTS, or network namespace; `IpcMode=private` |
| Docker socket | Absent |
| Mounts | Only `threatbridge-data:/app/data`; both secrets mounted `ro` |
| Published port | `127.0.0.1:18020->8000/tcp`; host listener bound to `127.0.0.1` only |
| Database exposure | No published port; not reachable from the host |
| Network segmentation | `database` network `internal=true`, and the database container has no external DNS resolution; `web` reaches `db:5432` internally and retains egress for connectors |
| `deploy-check` network | `none` |
| Logging | `json-file`, `max-size=10m`, `max-file=5` |
| Restart policy | `unless-stopped` |
| Host `Host`-header policy | Configured host returns `200`; `Host: evil.example.com` returns `400` |

#### What this establishes and what it does not

Both previously outstanding conditions are now met: the committed default was rebuilt, validated,
SBOM'd, and scanned clean, and the production Compose stack ran end to end with confinement verified
against live containers. The scan result remains point-in-time evidence about one image and one
scanner database on 2026-07-29.

This run used a disposable environment file, throwaway secrets, a `.invalid` outbound host, and a
self-signed test CA. No live credential or production connector was involved, and no connector
synchronisation was exercised against a real endpoint. Restore-from-backup was not exercised.

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
| H-7 | Found by live execution. The PID limits added by this audit made `compose.production.yml` an invalid Compose project: `pids_limit` beside `deploy.resources.limits` without a `pids` entry is rejected, so the documented production deployment could not start at all. | Each PID ceiling is declared as both keys from one YAML anchor. `test_production_compose_is_a_valid_compose_project` now runs `docker compose config` and reproduces the original error when either key is removed. |
| H-8 | Found by live execution. `prepare_production_deployment.py` wrote secrets mode `0600` owned by the operator, but Compose ignores `uid`/`gid`/`mode` outside Swarm and mounts host ownership as-is, so UID 65532 could not read them and startup aborted. The documented secret-injection flow was incompatible with the non-root image. | Secrets are written `0444` inside the `0700` secrets directory, which is the actual host boundary. The directory mode is verified on every run, group- or world-writable secrets are refused, and existing secrets are re-moded without rotation. |
| H-9 | Found by live execution. The container health check requested `http://127.0.0.1:8000/readyz`, so Django rejected `Host: 127.0.0.1` with `400`; correcting that exposed a `301` from `SECURE_SSL_REDIRECT` that a loopback probe cannot follow. The container could never report healthy. | The probe sends the first `DJANGO_ALLOWED_HOSTS` entry as its `Host` header, and `SECURE_REDIRECT_EXEMPT` covers only `^healthz$` and `^readyz$`. `ALLOWED_HOSTS` was not widened and every data-carrying path still redirects. |

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
| M-13 | Found by live execution. The private-CA overlay mounted the certificate with the host's owner-only mode, so the application could not read it, and `_configured_file_path` validated metadata without reading the file. The stack reported healthy while the private CA was silently absent from the trust store, so an operator would have believed private-CA verification was active. | Every configured file is now read at startup, so an unreadable trust anchor or secret fails closed at the `deploy-check` gate. `prepare_production_deployment.py` refuses a certificate UID 65532 could not read and names the required `chmod`. |
| M-14 | Found by live execution. Both Compose profiles redefined `healthcheck.test`, overriding the image's `HEALTHCHECK`, so the two copies had drifted and a fix in the `Dockerfile` had no effect. | Both profiles omit `test` and tune only the timings, so the probe is defined once in the image. A test asserts `test` stays absent. |

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
| L-11 | Found by live execution. `deploy-check` declared no networks, which attaches a service to the implicit Compose default bridge rather than isolating it, so the configuration-only gate had outbound access it never uses. | The service sets `network_mode: none`, and the implicit `default` network is no longer created. |

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

From the Compose integration test:

- Secret files are now created mode `0444` rather than `0600`, inside the same `0700` directory.
  Re-running `prepare_production_deployment.py` repairs an existing deployment's modes in place
  without rotating the values. An operator who injects secrets by another mechanism must ensure the
  files are readable by UID 65532 and that the containing directory is not world-traversable.
- A private CA certificate passed through `--extra-ca-path` must be mode `0444`. The preparation
  script now refuses an unreadable certificate instead of producing a configuration that mounts one
  the application cannot read.
- Any configured `*_FILE` path that the application cannot read now fails at startup rather than
  being silently ignored. A deployment that was unknowingly running without its private CA in the
  trust store will begin refusing to start, which is the intended correction.
- `/healthz` and `/readyz` are no longer redirected to HTTPS in production. Every other path is
  unchanged. A reverse proxy that relied on receiving a `301` from these two paths will now receive
  `200`.

## Test and scanner outcomes

Tool versions: Python 3.14.4 (host), Django 6.0.7, pytest 9.1.1, Ruff 0.15.22, Bandit 1.9.4,
pip-audit 2.10.1, Trivy 0.70.0, Gitleaks (build-stamped version string).

| Check | Result |
| --- | --- |
| `python -m pytest` | **Pass** — 232 passed, 130 subtests passed (baseline: 180 passed) |
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
| `docker compose config` (both profiles) | **Pass, after one fix** — the first live run rejected the project because `pids_limit` sat beside `deploy.resources.limits` without a matching `pids` entry. With both keys anchored to one value, the base profile and the step-ca overlay both render. See [Follow-up: production Compose integration test](#follow-up-production-compose-integration-test-2026-07-29). |
| Image build | **Pass, after one fix** — the first attempt failed because the builder working directory shadowed the installed wheel and the wheel validation correctly refused it. With `python -P` the image builds on Docker Desktop and the installed-wheel validation passes. See [Follow-up: live build attempt](#follow-up-live-build-attempt-2026-07-29). |
| `validate_container_image.sh` | **Pass, after one fix** — a blank-record parsing bug produced a false `" 8000/tcp"` mismatch. With the parser corrected and the exact-port policy intact, the validator runs to completion and every confinement assertion passes on the live image. |
| `generate_image_sbom.sh` | **Pass** — CycloneDX image SBOM produced for the exact image ID |
| `scan_container_image.sh` | **Blocked on Debian, passes on Alpine** — the Debian 13 candidate recorded 23 blocking findings (4 CRITICAL, 19 HIGH) and Debian 12 Bookworm 24 (6 CRITICAL, 18 HIGH); the Alpine 3.24 candidate recorded 0 CRITICAL and 0 HIGH and is now the committed default. See [Follow-up: confinement validation, scanning, and base-image selection](#follow-up-confinement-validation-scanning-and-base-image-selection-2026-07-29). |
| Rebuild from the committed default | **Pass** — built with no `--build-arg` override; base label confirms the committed Alpine digest; validation, SBOM, and scan all run against that exact image ID, with zero HIGH and zero CRITICAL |
| Production Compose stack, end to end | **Pass, after six fixes** — `deploy-check` exit 0, migrations applied, PostgreSQL healthy, `web` healthy in about nine seconds, and every confinement property verified against live containers. The six defects found are recorded as H-7, H-8, H-9, M-13, M-14, and L-11. |
| Development Compose profile | **Pass** — `web` healthy, `/readyz` returns 200, image probe inherited |

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

Asserted statically and by `tests/test_deployment_tooling.py`, asserted at runtime by
`scripts/validate_container_image.sh`, and — as of the Compose integration test above — observed on
live containers running the committed default:

| Control | Production profile | Verified by |
| --- | --- | --- |
| Non-root numeric user | `65532:65532` on every app service | Compose test; image `Config.User` assertion |
| `cap_drop: [ALL]` | Every app service; database keeps five required capabilities | Compose test; `CapEff` assertion on a hardened run |
| `no-new-privileges:true` | Every service | Compose test; `NoNewPrivs=1` assertion |
| Read-only root filesystem | Every app service | Compose test; `HostConfig.ReadonlyRootfs` assertion |
| Writable paths | `/tmp` tmpfs (64 MiB, `noexec,nosuid,nodev`) and the `/app/data` named volume only | Compose test; write probes |
| No Docker socket, host namespace, host root, `/proc`, `/sys`, `/dev` | Absent everywhere | Compose test; mount inspection |
| `init: true` | Every service | Compose test |
| `pids_limit`, CPU and memory limits | Every service | Compose test; `HostConfig.PidsLimit`, `NanoCpus`, and `Memory` observed on a running container |
| Health check | `web` and `db` | Compose test; `web` observed healthy |
| Network isolation of the deployment gate | `deploy-check` runs with `network_mode: none` | Compose test; `HostConfig.NetworkMode=none` observed |
| Exposed ports | `8000/tcp` only in the image; published only on an explicitly configured host address | Compose test; `Config.ExposedPorts` assertion |
| No published database port; internal network | Enforced | Compose test |
| Log rotation | `json-file` with size and file caps | Compose test |
| OCI labels | Complete set | Label assertion |
| Fails closed without production secrets | Verified by execution outside Docker, and by the `deploy-check` gate refusing an unreadable secret inside Docker | Fail-closed section above |

Every row in this table has now been observed on a live container built from the committed default,
rather than only asserted.

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

1. **Static review did not predict how the deployment would behave.** Six defects survived a full
   static audit and were found only by running the stack, three of which prevented it from starting
   and one of which silently disabled private-CA trust. Two lessons are now encoded in tests — the
   Compose project is validated by Compose itself rather than by parsing YAML, and configured files
   are read rather than merely stat'ed — but the general point stands: for this project, a change to
   the Compose profile, the image, or the secret contract is not verified until it has been run. The
   CI container workflow builds and validates the image; it does not bring up the Compose stack.
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
13. **Secret confidentiality depends on a directory mode, not a file mode.** Because Compose ignores
    `uid`, `gid`, and `mode` outside Swarm, the secret files are world-readable and the `0700` secrets
    directory is what protects them. An operator who relocates the secrets into a world-traversable
    path, loosens the directory, or copies the files elsewhere loses that protection. Swarm, Kubernetes,
    or an external secret manager avoids the trade-off entirely.
14. **The integration test used synthetic inputs.** No live credential, real connector endpoint, or
    production dataset was involved, and connector synchronisation and restore-from-backup were not
    exercised against a real system.

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

To reproduce the production Compose integration test, in a disposable directory outside the
repository. Nothing below uses a live credential or a real connector endpoint:

```bash
test_root="$(mktemp -d)"; chmod 700 "${test_root}"

python scripts/prepare_production_deployment.py \
    --hostname threatbridge.localhost \
    --bind-address 127.0.0.1 \
    --outbound-host opencti.example.invalid \
    --port 18020 \
    --hsts-seconds 0 \
    --env-file "${test_root}/.env.production" \
    --secrets-dir "${test_root}/secrets"

# Expect 0700 on the directory and 0444 on each secret: the container user must be able
# to read them, and the directory is what keeps them confidential.
stat -c '%a %n' "${test_root}/secrets" "${test_root}"/secrets/*

THREATBRIDGE_ENV_FILE="${test_root}/.env.production" \
    bash scripts/resolve_production_images.sh

# Must exit 0. A non-zero exit here means the profile is not a loadable project.
THREATBRIDGE_ENV_FILE="${test_root}/.env.production" \
    ./scripts/production_compose.sh -p tb-it config --quiet

THREATBRIDGE_ENV_FILE="${test_root}/.env.production" \
    ./scripts/production_compose.sh -p tb-it up -d

# deploy-check and migrate must both exit 0, and web must reach "healthy".
THREATBRIDGE_ENV_FILE="${test_root}/.env.production" \
    ./scripts/production_compose.sh -p tb-it ps -a

# Health endpoints answer over plain HTTP; every data path still redirects to HTTPS;
# an unrecognised Host is still refused.
curl -si -H 'Host: threatbridge.localhost' http://127.0.0.1:18020/readyz | head -1
curl -si -H 'Host: threatbridge.localhost' http://127.0.0.1:18020/admin/ | head -1
curl -si -H 'Host: evil.example.com'       http://127.0.0.1:18020/readyz | head -1

# Live confinement of the serving container.
docker inspect --format 'ro={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}}
caps={{.HostConfig.CapDrop}} opt={{.HostConfig.SecurityOpt}}
pids={{.HostConfig.PidsLimit}} net={{.HostConfig.NetworkMode}}' tb-it-web-1
docker exec tb-it-web-1 grep -E 'NoNewPrivs|CapEff' /proc/1/status

THREATBRIDGE_ENV_FILE="${test_root}/.env.production" \
    ./scripts/production_compose.sh -p tb-it down -v
rm -rf "${test_root}"
```

## Recommendation

**READY WITH DOCUMENTED CONDITIONS** for publication of the reviewed source repository.

Everything verifiable in this environment passes: the full test suite, lint, Django checks,
deployment checks under a synthetic production environment, dependency-lock and workflow validation,
`pip check`, `pip-audit`, Bandit, the SBOM byte comparison, the Trivy configuration and secret scans,
and Gitleaks against both the candidate tree and all reachable history. No secret exists in the tree
or in history, no history rewrite is needed, and every fail-closed guard was proven by execution.

Container runtime confinement is now **observed rather than asserted, on the committed default**. The
image was rebuilt with no `--build-arg` override, validated, SBOM'd, and scanned clean, and the
production Compose stack ran end to end with every confinement property read off live containers: the
non-root identity, read-only root filesystem, `/tmp`-and-`/app/data`-only writability, empty
capability sets, `NoNewPrivs=1`, applied PID and resource limits, absent Docker socket, loopback-only
published port, unpublished and egress-free database, and authoritative installed wheel. The default
base is the Alpine 3.24 candidate that recorded zero HIGH or CRITICAL findings under the reviewed
Trivy 0.70.0 policy.

That run also found six defects, three of which prevented the documented deployment from starting and
one of which silently disabled private-CA trust. All are fixed and re-verified, and the two most
significant gaps in the test strategy are now closed — Compose validates its own project, and
configured files are read rather than stat'ed.

READY is withheld for the reasons below, none of which is a known defect in the reviewed code. **A
prebuilt image is explicitly not READY**, because publishing an image is a durable claim about
vulnerability status and the clean scan is a single point-in-time observation.

### Conditions before publication

1. Re-resolve the base-image digests and rerun the unsuppressed image scan immediately before
   release, since the clean Alpine result is point-in-time evidence from 2026-07-29. Prebuilt-image
   publication stays blocked while any HIGH or CRITICAL finding is unfixed; source publication is a
   separate decision.
2. Repeat the committed-default rebuild and the Compose integration test on the release commit, using
   the commands above. The integration test recorded here ran on the working tree that became this
   commit, and five of the defects it found were fixed after the stack first came up, so the release
   commit should be exercised as a whole rather than inheriting this result.
3. Apply the GitHub repository settings listed above, then confirm every workflow succeeds on the
   public host. The container workflow builds and validates the image but does not bring up the
   Compose stack, so the integration test stays a release-time manual step.
4. Have an independent reviewer confirm private-file exclusion and this evidence, per
   `docs/release-checklist.md`.

No risk was accepted silently, no scanner finding was suppressed, and no test was weakened.
