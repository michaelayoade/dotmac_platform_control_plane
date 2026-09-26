# Protected rehearsal-issuer composition source

The sibling module `vendor_cp.deployment.protected_rehearsal_issuer` composes
Control and Approvals for the issuer's own operation. Both producers have
published: Control `0.1.0a15` (tag object `466f48d2…`, peeled `cd887722…`,
record Control PR #68) and Approvals `0.1.0a7` (tag object `d59ee6f2…`, peeled
`7cab65c5…`, record Starter PR #756). Since CP PR #204 (the Gate-0 composition
adoption) the application pins exactly those versions, so the isolated lane
below verifies the same bytes the assembly composes. Mounted routes are
unchanged; there is no operator CLI in this slice.

The sequence has two caller-owned transactions. In the first, Control freezes
the plan with purpose `rehearsal_issuer_operation`, explicit operation `deploy`,
descriptor digest and Foundation execution-plan digest. Approvals opens its
real platform request. The subject is the versioned, canonical text
`v1|<plan UUID>|rehearsal_issuer_operation|deploy|<sha256 execution digest>`;
Approvals' `content_hash` separately holds Control's plan digest. A genuine
Approvals decision is checked against that exact subject and digest, then its
evidence is carried into Control `approve_plan`. No rollout or dispatch call is
made. The caller commits that transaction before issuance.

In a later transaction, the existing three-field
`RehearsalIssuerInvocation` reaches Control's real
`issue_rehearsal_issuer_authorization_for_plan`. The harness evidence is
opaque to this assembly; Control verifies it, checks plan standing and derives
the signed issuer terms. The caller commits Control's issuer ledger write.
Neither the subject nor the command accepts caller-supplied signed A6.4 terms.

Approvals emits its durable `approval.withdrawn` platform outbox row with the
withdrawal UUID as the row ID. The existing kernel relay claims that row and
passes the `ClaimedPlatformEvent` to the composed transport. Its issuer
consumer checks that the row ID equals the payload withdrawal ID and checks
the subject, policy, plan digest and request ID against the frozen Control plan
and its recorded decision reference. It then calls Control
`revoke_plan_approval` with a command ID and revocation reference derived from
the claimed row ID. Control's idempotency ledger makes replay one revocation.
The kernel commits the delivery transaction before settling the outbox row;
delivery failure rolls it back and enters the existing retry/dead-letter path.
Other event types continue to the existing contract activation consumer.

The signer custody reference is purpose `deployment_rehearsal_issuer` at
OpenBao path `secret/dotmac/platform-cp/rehearsal-issuer/signing-key`. This
source records the pointer only. Key creation, materialization, startup
installation, runner identity, and operational Gate-0 acceptance belong to
later packets.

The checked-in `protected_issuer_conformance/release-evidence.json` is the
lane's sole successor coordinate source. Each row names the producing GitHub
repository, its publication-record path and immutable record commit, release
version, annotated tag object, peeled source commit, and wheel SHA-256. The
coordinates were filled, in a reviewed commit, from each producer's completed
publication (Control record commit `6edb376f…`, Starter record commit
`0bff1b7a…`), and an architecture test holds their versions equal to the
application pins. The workflow fetches each
producer's pinned record commit and tag, checks the record is on `main`, the
tag is annotated and peels to the same source, and the producing record binds
the same version, source commit and wheel hash. It derives exact pins and wheel
paths from the manifest, downloads Dotmac wheels solely from private Forgejo,
checks their bytes before installation, then tests installed public signatures
in an isolated venv. The kernel wheel stays governed by the existing harness
lock, `rehearsal_issuer_harness/artifacts.json`.

Control already writes `docs/published-versions.json` with these publication
facts. Starter's current module release recorder does not persist a wheel hash
for Approvals. The future a7 release must add a checked-in
`docs/inventories/module-release-verifications.json` with schema
`ModuleReleaseVerifications.v1` and one `releases` row containing
`distribution`, `version`, `tag`, `tag_object`, `peeled_commit`, `status`,
`pinnable`, and `sha256` keyed by the exact wheel filename. Until that record
exists on Starter `main` at the pinned record commit, this lane refuses even if
an a7 wheel and tag exist. This lane tests the composition boundary; it is not
a protected run or a Gate-0 receipt.
