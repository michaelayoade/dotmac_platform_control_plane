# Gate-0 E: partial report-consumer source

This source slice implements `inspect_case_report`, a strict offline inspector
of retained case bytes. It is **not a completed E harness**, an authenticated
readiness receipt verifier, or a protected execution entry point. It never
returns readiness acceptance and has no signer, storage writer, runtime route,
transport, custody reader or target action. Hash equality detects changed
bytes; it authenticates neither the producer nor the reported outcome.

The caller supplies the frozen source-bundle digest and repository/run/attempt
coordinate independently of the report. Inspection requires exact top-level
and nested field sets, unique JSON keys, bounded input/evidence, exact case-set
and outcome equality, and matching retained nonempty case bytes. Unknown,
duplicate, omitted and extra cases refuse. Interrupted completion refuses.
Unknown B/C1/C2/D states remain unknown in synthetic reports and refuse a
report asserting protected live provenance. Even self-asserted accepted
prerequisites cannot make `readiness_accepted` true. Receipt authentication
and independent prerequisite-oracle verification remain required.

`Gate0CaseReport.v1` is a new **non-authorizing report**, not a Control evidence
schema. It has `schema`, `evidence_class` (`synthetic_ci` or `protected_live`),
`source_bundle_digest`, decimal-string `repository_id`, `run_id`, `run_attempt`,
`prerequisites`, `cases` and `completion`. Each prerequisite has `state`
(`accepted`, `unknown`, `blocked`) and `evidence_digest`; each case has `case`,
`outcome`, `evidence_digest`. Accepted references require canonical SHA-256;
unknown/blocked references are null. Digests cover exact supplied bytes,
including whitespace. No canonical reserialization hides changed artifact
bytes. Every unknown field refuses, including candidate and ExecutionGrant
fields. Reports are untrusted assertions even after byte inspection.

`docs/inventories/e-requirements.json` maps existing owner seams, tests and
concrete finalization gaps. Its grouped cases are a provisional source-slice
inventory, **not** the closed ADR A7.7/D §7 acceptance matrix. Subcases, measured
reason codes, each positive control, lease separation and exact ordered
protected evidence must be enumerated before adopting a production receipt
schema. No production-shaped passing E fixture is created by these tests.

## Owners and remaining integration

The existing `protected_rehearsal_issuer` service already composes real Control
plan proposal, Approvals request, held approval, issuance and consumption.
Its approval barrier locks the durable Approvals decision in the caller-owned
transaction; approval must commit before issuance. The withdrawal relay owns
durable propagation. `issuer_receipts` records command retries inside those
transactions; those rows do not replace E receipts. `RehearsalIssuerTrustState`
already owns public refresh/floor/standing decisions. Preserve these owners.

Control a17 is the pinned cross-lease controller nonreuse owner. The disposable
harness supplies owner-shaped evidence but not authentic human approval,
OpenSSH possession or real custody. The CP invocation deliberately leaves
signed Control evidence opaque. The existing authenticated
`POST /platform/vendor/approvals/decisions` derives the approver from kernel
platform-admin authentication and records the durable decision; the hosted
runtime must compose this existing route/auth/DB/profile, not invent an API.
A production attester must verify
controller possession and independent repository/run/attempt provenance, then
bind its exact Control canonical bytes, lease, target, plan and CA standing in
a signed companion transcript. Control a17 accepts the signed attester-chosen lease ID and records uniqueness
transactionally; a separate reservation API is not required. No substitute
ledger or guessed owner field is added.

Protected execution/finalization remains unavailable pending hosted composition
of the existing human decision route, actual possession verification, adopted
transport, hosted bootstrap/custody,
approved CP producer trust anchor, atomic immutable receipt destination and
accepted B/C1/C2/D oracles. A GitHub Environment approval cannot become the
Approvals decision. Pull remains proposed; no default enables W1–W5. Each
service receives only its own startup-held signer; runner receives neither.

## Ordered operational handoff (not executed)

1. Owners provide accepted B/C1/C2/D immutable evidence; resolve every gap in the
   inventory and adopt the complete per-case matrix/receipt schema.
2. Verify bootstrap manifest, exact published wheels using
   `protected_issuer_conformance/check.py`, floor/CA public pins, separate
   custody, protected identities, online-role rights and scoped database.
3. Freeze the issuer-operation plan through the existing composition. A human
   reviews the exact subject/digest and decides through authenticated Approvals.
   Commit approval before a new held issuance transaction.
4. Run protected positives/refusals using independent attester provenance and
   actual controller possession. Use a fresh controller for the separate
   revocation lease; prove live withdrawal convergence, replay refusal and
   real database races. Retain exact bytes and measured owner reasons.
5. Independently authenticate all evidence and producer identity. Publish E's
   receipt with first-create/atomic conflict refusal to the configured immutable
   destination. Never finalize partial/cancelled/expired runs; stop and report.
6. Record cleanup and no-reuse state, including cancellation/restart handling.
   A compromise requires role-specific revocation and a forward trust floor;
   never restore an older floor or replace missing custody with generated keys.

All automated tests run only on Git-hosted CI, including disposable database
and OpenBao integration. Local AST/Ruff checks are static evidence only.
E does not close B8's SSH matrix, populate Lane 3 `admission_evidence`, allocate
a Foundation candidate, create an ExecutionGrant or establish production fault
isolation. Hosted placement retains Observe/OpenBao as a shared dependency.

## Functional public-verifier adapter slice

`gate0_runtime.ProtectedHarnessVerifier` implements Control a17's unchanged
`verify_rehearsal_harness_evidence` protocol. It receives a fixed enrolled
attester public key, the existing `RehearsalIssuerTrustState`, a frozen
`AttestationContext`, expiry and a read-only companion lookup at startup. It
authenticates the exact owner canonical bytes and a domain-separated signed
CP companion over their SHA-256 plus repository/run/attempt, lease, OpenSSH
controller fingerprint, target, plan/digests, certificate digest and CA pin.
Control v1 receives no extra fields. Context must be derived independently
from admitted provenance and the real frozen Control plan, never from a request.

The adapter checks current trust standing before and after lookup and refuses
expired/unconfigured/unavailable transport, changed owner identity, invalid
signatures and companion substitution. It holds no signing key, does not
generate a controller, and does not reserve or consume a lease. Control still
validates timestamps/canonical form, derives standing and enforces single-use
and cross-lease controller nonreuse. Install through the existing Control
security installation owner only after the complete operational packet is
approved. No installation or protected run is performed by this source.

The companion is a proposed CP-owned attestation format, not a new Control API.
Its producer must first perform actual SSH proof, certificate/CA/time checks
and independent provenance verification. The adapter verifies the enrolled
attester's assertion; it does not itself establish those underlying facts.
The issuer signer cannot satisfy this fixed attester identity. Receipt
authentication, E finalization and the real composition driver remain absent.

Attester enrollment uses CP's `sha256:<hex>` fingerprint of the raw Ed25519
public key, matched to the existing public trust record. Controller and CA
fingerprints use canonical OpenSSH `SHA256:<unpadded base64>` over their SSH
public-key representation. These are distinct conventions; the adapter never
normalizes one into the other. Installed-owner CI compares the public verifier
signature and evidence constants against the exact pinned Control wheel.

Runtime expiry has two independent checks: an aware wall-clock interval and a
finite monotonic deadline initialized once from the positive startup duration
(at most 600 seconds). A wall read earlier than startup, invalid clock readback
or elapsed deadline refuses. Verification and public trust refresh never renew
that cap. Both clocks and public trust are checked again after companion lookup
and signature verification, before returning true. The transport adapter must
enforce its own bounded I/O deadline and cancellation: a blocking synchronous
lookup cannot be interrupted by this verifier. Post-lookup checks prevent late
acceptance; they do not claim to bound callback execution time.
