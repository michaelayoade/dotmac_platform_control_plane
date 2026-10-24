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
no conserved findings, and no syntax errors. At that measurement, the detector reported no direct external connector
surface. The side-effect-free local simulation provider remains the only
product integration provider required by AGENTS.md rule 4.

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
after Deployment Control and before Brand Profiles. No product/provider integration transport, provider credential, schedule,
checkpoint, lease, backoff policy or new retry owner may be added here while
that cutover is pending. The finite host deployment operations described below
are governed by the separately authorized D16 transition contract.

## Native transition operator transport (2026-10-24 source integration)

The D16 host operator performs actual HTTP readiness checks against the fixed
`https://platform.dotmac.io/health/ready` endpoint and bounded loopback candidate
and runtime readiness and signed-ledger availability endpoints. Its authorization owner invokes the pinned GitHub CLI to verify the
protected workflow's GitHub/Sigstore attestation. These operations implement
the authorized transition's maintenance, candidate and authorization proofs;
they add no product integration provider, provider credential or retry owner.
The operator is a one-shot root host tool, separate from the application runtime.
Its source authorization does not authorize an artifact publication or live run.

The pinned schema-9 detector does not recognize `urllib.request` opener calls
or classify GitHub CLI subprocess verification as outbound transport. Its zero
count therefore coexists with these explicitly disclosed network operations.
The baseline remains detector-derived, with no exclusions, alternate detector
or transport renaming. Review must assess this semantic surface in addition to
the unchanged numeric ratchet.
