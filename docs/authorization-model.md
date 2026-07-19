# Authorization model

## Current scope

ThreatBridge Phase 1 is a single-deployment authorization model. Authentication identifies a
deployment-local Django user. It does not provide tenant or organization isolation, Entra ID,
enterprise SSO, TLP policy enforcement, or a cross-organization role model.

Browser and REST requests use Django sessions. Unsafe REST requests authenticated by a session are
CSRF protected. HTTP Basic Authentication is disabled. There is no production-ready unattended
API authentication method in this release.

## Policy

- Anonymous users cannot access application data.
- Authenticated users can read ordinary catalog and assessment data.
- Restricted or deleted source evidence requires explicit evidence permissions.
- Every mutation requires a named permission.
- `is_staff` only permits entry to Django admin; it grants no application workflow.
- Superusers satisfy all application policy checks.
- Management commands identify a `management:*` origin and use a system identity rather than
  pretending to be a human actor.

| Capability | Django permission |
|---|---|
| View integrations | `integrations.view_integration` |
| Configure integrations | `integrations.configure_integration` |
| Test integrations | `integrations.test_integration` |
| Synchronize integrations | `integrations.synchronize_integration` |
| Import source files | `integrations.import_source_file` |
| Run or recalculate assessments | `catalog.run_assessment` |
| Approve or reject ATT&CK mappings | `catalog.review_attack_mapping` |
| View restricted evidence | `integrations.view_restricted_source_evidence` |
| View deleted evidence | `integrations.view_deleted_source_evidence` |
| Delete evidence | `integrations.delete_source_evidence` |
| Restore evidence | `integrations.restore_deleted_source_evidence` |
| Administer security configuration | `catalog.administer_security_configuration` |
| View security audit events | `catalog.view_securityauditevent` |

Permissions are evaluated through `threatbridge.authorization` before target lookup for restricted
workflows. This produces a 403 response without disclosing whether a restricted identifier exists.
Django user and group administration additionally requires
`catalog.administer_security_configuration`; ordinary staff or Django auth-model permissions do not
bypass that policy.

## Workflow integrity

Imported, synchronized, manually entered, API-created, and reprojected ATT&CK mappings always start
pending. Only the centralized review transition service can approve or reject them, and every
transition records an append-only review event and security audit event.

Assessments require `catalog.run_assessment`, record actor and origin, and retain the active evidence
identifiers used. Deleted evidence is excluded and makes older dependent assessments unavailable to
ordinary readers. Assessments created before the complete Phase 1 provenance manifest are hidden
until they are explicitly recalculated.

Evidence deletion and restoration are separate, reasoned service operations. Deletion is soft at
the source-record layer, hidden by default managers and public querysets, excluded from projection
and assessment, and not reversed by synchronization. Restoration requires its own permission.
