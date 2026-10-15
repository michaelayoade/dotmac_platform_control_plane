# Gate-0 E: proof producer, verifier and partial case report

This source slice implements an actual SSH possession proof producer, the
published Control public-verifier adapter and `inspect_case_report`, a strict
offline inspector of retained case bytes. It is **not a completed E harness**,
an authenticated readiness receipt verifier or a protected execution entry
point. No production signer, custody loader, listener, transport, receipt
writer or target action is configured. The report inspector never accepts
readiness: hash equality detects changed bytes but authenticates neither the
producer nor the reported outcome.

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
of the existing human decision route, independent admitted provenance, actual
controller-session identity observation, deployed transport and hosted custody,
approved CP producer trust anchor, atomic immutable receipt destination and
accepted B/C1/C2/D oracles. A GitHub Environment approval cannot become the
Approvals decision. Private WireGuard plus constrained SSH is selected for
design development; activation is a separately reviewed operational packet.
Pull remains proposed; no default enables W1–W5. Each
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
controller fingerprint, target, plan/digests, certificate digest and CA pin,
window, issue/consume phase, actual issued-authorization digest/time for
consumption, challenge digest and retained public-proof transcript digest.
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
The sibling producer now performs actual SSH proof and certificate/CA/time
checks before signing. Its immutable `AdmittedOperation` input must still come
from an independent authenticated provenance/plan/window authority. A frozen
dataclass alone is not that authority. The consumer authenticates the enrolled
attester's signed assertion and fixed context.
The issuer signer cannot satisfy this fixed attester identity. Receipt
authentication and E finalization remain absent. The bounded composition source
below delegates phases to the existing owners; it does not supply live admission.

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

## Transport-independent proof producer

`gate0_attester.AttesterProofProducer` receives an independently admitted
operation, fixed CA public key and enrolled attester public identity/trust. Its
role-local signing callback is injected with the dedicated attester purpose;
there is no default signer or private-key loader. It validates cryptography
50.0.0's public `SSHCertificate` signature, then separately requires its signer
key equal the immutable CA. The initial profile accepts Ed25519 USER
certificates, the sole `dotmac-gate0-controller` principal, empty critical
options/extensions, exact run/attempt key ID, current validity and positive TTL
no greater than 600 seconds. Key ID is a cross-check, never possession proof.
Certificate digest means SHA-256 of the library's canonical `public_bytes()`,
so input comments/whitespace cannot change the digest convention.

`begin_challenge` creates unpredictable instance/challenge IDs and a 32-byte
nonce. Exact challenge bytes bind admitted run/attempt/window, lease/target,
plan/purpose/digests, certificate/controller, phase, expiry and the actual
authorization digest/time for consumption. `complete_challenge` accepts only
the producer's ID plus SSHSIG; no caller-replacement message or state is read.
Under a lock it takes the pending record before verification/signing; concurrent
completion and replay refuse. Inflight records prevent another active challenge
for this producer's fixed lease/phase. Success and every failure are terminal.
Up to 16 total records are retained without eviction in the bounded process
window; each challenge lasts at most 30 seconds. Restart has new unpredictable
identity and empty state: old responses cannot be imported or resumed. This is
a small nonresumable proof protocol, not a durable authorization/lease ledger.

Actual possession uses fixed `/usr/bin/ssh-keygen -Y verify`, fixed signer
`gate0-controller` and namespace `dotmac-gate0-possession-v1`. The allowed-signers
line contains only the reconstructed raw certificate public key and exact
namespace restriction. No wildcard, CA-trust directive, caller path, shell,
agent or private-key flag is accepted. Two public files are created exclusively
with no-follow in an owned private temporary directory and removed afterward.
Output is discarded. Timeout is at most two seconds and is further limited by
remaining challenge/window duration. The fixed child deadline starts before
public-file staging; remaining budget is rechecked immediately before launch. The subprocess owner kills/reaps its
direct child on timeout. The operational supervisor must terminate cancelled
services; this source supplies no restart/resumption facility.

After proof, time/certificate/trust are rechecked. Control's unchanged v1 bytes
use the real key fingerprint, frozen lease/target and bounded times; consume
evidence requires a real clock reading strictly later than actual authorization
issuance. No future timestamp is fabricated. The retained public transcript
contains canonical certificate, exact challenge and SSHSIG; its digest and the
challenge digest join the signed companion. Both owner and companion signatures
are verified against the enrolled attester key before any bundle is returned.
Invalid proof invokes no signing callback. Signer failure returns no partial
bundle and never rearms a challenge. The bounded process-local state also
reserves each exact Control evidence hash before the first signing callback,
retaining that reservation on failure. Two valid proofs at an identical wall
instant cannot publish different companions under the same resolver key; a
new real clock reading is required for fresh owner bytes. This local constraint
does not replace immutable publication conflict checks across authorized
process lifetimes. Another instance or restart at the same wall instant may
still produce the same owner hash with a different companion; the future
immutable companion publisher must reject that conflict. External key use and durable publication
cannot be made atomic by this process-local protocol; signer callbacks must
bound their own execution and cancellation.

Hosted-CI tests author real synthetic certificate/SSHSIG round trips through
the producer and public verifier, refusal/concurrency/replay/privacy/deadline
plants and public tool identity recording. Test-only keys never form a passing
E receipt. No tests, key generation, private-key loading or subprocess probes
were executed on a workstation or host during source authoring. Runtime
bootstrap must separately pin/measure the deployed OpenSSH binary/version.
Proof establishes that the certified key signed this admitted operation's
challenge; it does not observe GitHub OIDC, human approval or the key's later
controller session. Those live composition observations remain E obligations.


## Bounded phase composition source

`gate0_composition.Gate0Composition` consumes independent `AdmissionExpectation`
and `ProducedAttestation` ports, compares every admitted operation against public
Control plan/target fields, and delegates issuance/consumption to the existing CP
held-approval wrappers. It uses the injected kernel session factory, closes
preflight before opening a clean standing session, and explicitly commits or
rolls back each mutation. An ambiguous commit or cleanup returns the typed
`CompositionIncomplete` outcome. No automatic recovery or second spend ledger is
introduced. Phase results always report `readiness_accepted=False`.

`BoundedHarnessVerifier` implements the unchanged public Control verifier
protocol and authenticates registration through the existing immutable leaf.
It retains at most four proofs, each at most 128 KiB, with a 512 KiB aggregate
cap. It keys entries by the hash of exact Control canonical bytes and preserves
original envelope bytes, signature metadata, companion, context and public
transcript. Equal registration is idempotent; any retained-byte/context change
under the same hash refuses. There is no eviction, reset, phase-switch flag or
callback under the registry lock. Every lookup reruns the leaf, current public
trust and the original startup wall/monotonic deadline; creating a later leaf
cannot renew that enclosing window. Registration is private to the driver.
These process-local entries are neither durable publication nor lease authority.

Consumption binds the full public parsed authorization envelope: strict bounded
JSON, `RehearsalIssuerAuthorizationV1.parse`, then `as_mapping`, serialized with
sorted keys, comma/colon separators, ASCII escapes and nonfinite values refused.
SHA-256 includes the signature and key metadata; transport whitespace does not
change it. The companion also binds the actual statement issuance time in UTC
ISO format with `Z`, preserving microseconds. Control v1 remains unchanged.

Trusted startup may use `assemble_gate0_composition` to install the existing
Control security port once with explicit signer/verifier and bounded TTL. There
is no default signer, admission oracle, controller-session observer, custody
loader, transport or receipt publisher. The resolver must bound its wire response
and callback duration before construction; postchecks cannot interrupt an
arbitrarily blocking synchronous callback. Independent admitted provenance,
authenticated human route exposure, actual later controller action, accepted
B/C1/C2/D and immutable receipt publication remain operational obligations.

Focused unit tests author registry conflict/concurrency/cap/deadline/trust and
phase/public-plan/transaction sensitivity checks. The isolated migration test
authors one real owner installation, migrated PostgreSQL roles, synthetic
Approvals actors/custody, actual certificate/SSHSIG producer, issue/standing/
consume/replay, and a separate-controller withdrawal/relay/revocation path.
These new tests have not been executed locally; execution is Git-hosted CI only.
Synthetic CI evidence cannot close protected E readiness.
