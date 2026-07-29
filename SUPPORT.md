# Support

ThreatBridge currently has no commercial support channel, response-time commitment, or maintained
public release.

Use a public bug report only for non-sensitive defects that contain no deployment data, source
evidence, credentials, or security impact. Use the feature-request template for proposals.

Security-sensitive reports must follow [`SECURITY.md`](SECURITY.md) and must not be filed publicly.
Deployment design, connector credentials, identity-provider setup, and incident response remain the
operator's responsibility.

Only the current default development line receives fixes; see the supported-versions table in
[`SECURITY.md`](SECURITY.md). Before opening a deployment question, read
[`deploy/README.md`](deploy/README.md) for the supported procedure, secret injection, backup and
restore, and upgrade and rollback expectations, and
[`docs/deployment-hardening.md`](docs/deployment-hardening.md) for the controls this repository
enforces versus those the Docker host administrator must enforce.
