# Vendor Control Plane external-connector surface

Vendor Control Plane adopts the Governance-owned schema-9 ratchet from
accepted ADR 0011 at immutable canonical-main commit
`a19259b10568d29dc0a9617347498fea7f1e7a97`.

The ratchet freezes measured direct connector surface while integrations move
behind Dotmac Integrator. It is transitional defence in depth, not runtime
isolation. Deployment policy must ultimately remove provider credentials and
external egress from this assembly regardless of how connector code is named.

The repository declares no measurement roots and copies no detector. The
Governance engine derives scope from Git-tracked Python, proves test-only
reachability centrally, and reports every untracked Python file as an error.

## Accepted baseline

Measured on 2026-08-16 with the accepted schema-9 engine: 96 tracked Python
sources measured, 37 proven test-only sources excluded, no untracked Python,
no conserved findings, and no syntax errors. The assembly has no direct
external connector surface; its only provider is the side-effect-free local
simulation provider required by AGENTS.md rule 4.

| Category | Baseline | Files behind it |
| --- | ---: | --- |
| `outbound_transport` | 0 | — |
| `webhook_surface` | 0 | — |
| `provider_credential` | 0 | — |
| `connector_task` | 0 | — |
| `sync_checkpoint` | 0 | — |
| `delivery_retry` | 0 | — |

There are no conserved exclusions. A future finding cannot be hidden by
adopter-owned scope or suppression; it must be removed, or reviewed as a
baseline change under the accepted Governance contract.

## Review rule

A count rising fails. A count falling also fails until the profile and this
record are lowered in the same change. Every reduction must show deletion or a
cutover to a named connector distribution behind Dotmac Integrator.

Zero means only that the accepted detector saw zero measured spellings. It
does not prove that the assembly lacks external connectivity. The ratchet
reaches its sunset only with ADR 0011's runtime package, secret, egress,
ingress, and inbox/outbox conditions.

It also does not assign semantic ownership of the existing Vendor delivery
attempts or retry state. Those logging/offline paths are temporary and frozen:
ADR-0010 schedules their transfer to `dotmac-integration` in Dotmac Integrator
after Deployment Control and before Brand Profiles. No connected transport,
provider credential, schedule, checkpoint, lease, backoff policy or new retry
owner may be added here while that cutover is pending.
