# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (current development line) | Yes |
| `0.3.x` pre-release candidates | Only through the current development line |
| Anything older | No |

Security fixes are developed against the current default development line and are not backported.
There is no long-term support branch, no published release schedule, and no prebuilt container image;
publication of a prebuilt image remains blocked by the finding policy in
[`docs/container-image-security.md`](docs/container-image-security.md). Run the current development
line and upgrade forward to receive fixes.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting for this repository. From the
repository, open **Security**, then **Advisories**, then
**Report a vulnerability**.

Do not disclose suspected vulnerabilities, credentials, source records, or
deployment details in a public issue, discussion, pull request, or commit.

Include the affected version, reproduction steps, expected impact, and any
suggested remediation that can be shared safely. The maintainer will coordinate
validation, remediation, disclosure, and credit through the private advisory.

## Response expectations

No response-time service level is promised before a maintained public release exists. Reporters
should receive an acknowledgement, a safe coordination path, and disclosure guidance once the
private channel is operational.

## Security boundaries

ThreatBridge is not currently production-ready. Read these boundaries before deploying it.

- **ThreatBridge is not a malware sandbox.** Imported files are parsed as data. Nothing is executed,
  detonated, unpacked, or emulated, and no malware scanning or quarantine exists. Scan and quarantine
  untrusted files before importing them.
- **Docker reduces deployment risk but is not an absolute security boundary.** The container profile
  is aligned with CIS Docker Benchmark and OWASP container guidance — non-root numeric UID, all
  capabilities dropped, `no-new-privileges`, read-only root filesystem, no Docker socket, no host
  namespaces — but a container shares the host kernel. A kernel or runtime vulnerability can defeat
  it. Do not rely on it to contain hostile code.
- **The deployment is not exposed to the internet by design.** Both Compose profiles publish only to
  an explicit host address, and the production profile requires you to set one. Terminate TLS in a
  reverse proxy you control.
- **Authorization is role-based and global, not per-object.** A user holding a named permission can
  act on every object of that type.
- **Outbound connectors are deny-by-default.** They reach only exactly allowlisted hosts, and a
  private destination additionally requires an allowlisted CIDR. Certificate verification is never
  disabled.

The security model, the SSRF policy, the split between what this repository enforces and what the
Docker host administrator must enforce, and the full residual-risk list are documented in
[`docs/security-architecture.md`](docs/security-architecture.md),
[`docs/deployment-hardening.md`](docs/deployment-hardening.md), and
[`docs/public-release-readiness.md`](docs/public-release-readiness.md). The most recent audit is
[`docs/security/public-release-hardening-audit.md`](docs/security/public-release-hardening-audit.md).

ThreatBridge is aligned with, and informed by, the CIS Docker Benchmark, OWASP container security
guidance, OpenSSF repository practices, and Django deployment guidance. It is not certified against
any of them and makes no compliance claim.
