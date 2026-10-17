# Gate-0 runtime provider source

This source supplies role-local custody/signing and GitHub workload verification.
It does not configure a production runtime, approve a window, provision an
AppRole, rotate keys, access a host, or qualify Gate 0. IDP3 issuer and NS3
attester remain the selected source targets; their shared Contabo residual and
host installation gates remain open. No key version or floor is guessed.

`RoleCustody` accepts only an issuer or attester role, measured role ID, measured
key ID/public pin, independently immutable minimum public-trust versions, a
fixed HTTPS OpenBao origin, and the original finite expiry. It derives the
adopted AppRole and own signing-key path internally; it cannot accept a seed
path from a request. It reads both public trust records but only its own seed.
Construction without transport, expiry, floor or explicit seed-format binding
refuses. The baseline is at most 300 seconds, nonrenewable and 32 token uses.

Bootstrap first looks up the wrapper and checks its exact role-specific
creation path, creation time and TTL, unwraps once, checks single-use SecretID
metadata, logs in once, verifies returned token metadata through lookup-self,
then loads and pins the own seed. Every attempt is terminal: failure cannot
rebootstrap or renew. Public trust refresh is explicit and failure closes both
trust gates. Token use exhaustion and original wall/monotonic expiry refuse.
Token strings, seeds and SecretIDs are never argv, environment, logs or files.
Python does not guarantee secure erasure of temporary/private-key objects;
process isolation and exclusion from dumps/snapshots remain installation duties.
Closing the object closes local signing eligibility; it does not claim server
revocation. Server-side retirement remains an operational custody-owner duty.

The existing A4 generator source establishes the provisional document encoding
`{key_id, private_key_b64url}` with an unpadded canonical base64url raw 32-byte
Ed25519 seed, and the fingerprint `sha256:hex(sha256(raw32 public key))`.
The generator labels that format explicitly approved by Michael on 2026-10-08
but pending CP confirmation. Consequently `seed_format` defaults to unset;
`a4-provisional-private-key-b64url` is an explicit trusted startup binding, not
a request option, new schema, or claim of current production acceptance.
No key-generation implementation or harness signer is reused here.

`RoleMaterial.issuer_signer` and `.issuer_verifier` implement Control's public
purpose-specific ports. `.attester_sign` is available only on attester material
for binding into the actual proof producer and fixed session-observation owner.
These Python callbacks are local signing operations; no generic signing route
is exposed. The verifier uses public key material and current trust eligibility,
checks the exact identity, fingerprint, algorithm and purpose, and stays within
the original expiry. Neither local signer may approve a plan or replace CP's
held Approvals/Control transition.

`BoundedJSONTransport` performs HTTP in a dedicated spawned child using memory
pipes. It permits HTTPS only, system certificate/hostname validation, no
redirects or environment proxy, bounded request/response bytes, at most five
seconds per operation and the caller's original overall deadline. Each header and body read uses nonblocking POSIX I/O and the original deadline;
pipe readiness does not establish complete-message availability. Unsupported
extended lengths and oversized/empty frames refuse. Parent expiration kills
the child and accepts no late result, including after cleanup or JSON parsing;
cleanup waits at most
0.2 seconds. No arbitrary blocking reader/transport callback is described as
bounded. Process spawning and scheduler availability remain operating-system
assumptions; this is an external-I/O cancellation bound, not real-time kernel
scheduling. A TLS origin must be supplied by an approved installation binding;
this source does not reinterpret the current Observe HTTP endpoint as TLS or
perform the separate transport migration.

The frozen Control-spec window and the dedicated trusted SSH-worker boundary
were adopted on 2026-10-15 against proposal SHA-256
`55b86daabc2f9c99713ba287821fc49ca20089411ad7a8d6c1c9ac21682c3bf8`.
This adopts the source contract, not a window, target, policy, database or host
installation. `WorkloadAdmission()` remains UNCONFIGURED; the earlier static
snapshot adapter is retained for explicitly synthetic mechanism tests and
cannot be promoted into the issuer production assembly.

`OwnerWindowReader` is IDP3's concrete CP provider. It requires the actual kernel
`DatabaseRuntime`, an explicitly selected rehearsal target UUID, issuer public
identity/verifier, original expiry and database-I/O qualification. It reads only
public Control `get_plan`/`get_target` and immutable
`PlanView.snapshot['spec']['gate0_window_v1']`; it never uses current mutable
desired spec as authority. It checks target, operation, descriptor/execution
bindings and policy against the owner views, then calls the existing CP
`held_transition` with CP's single canonical issuer subject and actual Control
plan digest. The real Approvals hold validates exact subject/content in that
short preflight transaction. A reread checks the same frozen bytes while the
hold is open; closing the session releases it. No held object or boolean is a
surviving approval grant.

The reader has native PostgreSQL statement/lock timeouts, original
wall/monotonic bounds and absolute window checks. Actual kernel-runtime pool
and driver connect bounds, same-database roles and external worker supervision
remain deployment qualification duties. `database_io_qualified=True` is a
trusted installation assertion, not evidence that those duties were met; all
defaults refuse. No blocking callback is described as bounded transport.

The original startup mapping of each window end is retained as immutable
process-local `WindowFreshness` metadata in the admission expectation. The
reader retains at most four original mappings; rereads, rollback and consume
derivation preserve them. Detaching an expectation for proof does not replace
its mapping. Production composition requires this metadata and checks it
immediately before the owner transition and immediately before commit, as well
as during frozen-plan checks. Wall-clock correction cannot extend a shorter
window while the global service lifetime remains open. This metadata is absent
from the namespace JSON, signed operation and wire proof; a runner cannot supply
it. NS3 ignores sender monotonic coordinates and maps the authenticated absolute
window end once against its own startup clocks, clamped to its own lifetime.

`OwnerWorkloadAdmission` repeats that owner read/hold for every issuer phase,
then verifies fresh fixed-origin GitHub JWKS and RS256 signatures. Exact
repository/owner IDs, repository, Environment name/node identity, ref, workflow
reference/SHA, event, audience, subject, run ID and attempt must match the
frozen document. Header key URLs, unexpected JOSE extensions, reusable-workflow
claims, unknown/duplicate keys, alternate algorithms and stale tokens refuse.
There is no JWT/JWKS/authority success cache or retry loop. At most 16 calls are
allowed and the first refusal closes the provider. The production issuer
assembly and installed issuer entry reject an NS3/static provider and require
the frozen-window binding; no request field can disable it.

`AdmissionExpectation` now carries exact canonical frozen-window bytes and
their separately named CP window digest. Production `Gate0Composition` compares
those bytes/digest with the mutation session's actual public frozen snapshot
before the owner transition and again before commit. Its existing issue/consume
wrappers independently reacquire the real Approvals hold in that mutation
transaction. Withdrawal between preflight and mutation therefore refuses even
before relay convergence. Control owns standing, durable consumption/replay
state and revocation; CP neither copies those owners nor creates a new ledger.

Consumption uses the actual submitted Control envelope, not a preapproved
future digest. The shared narrow derivation calls the public Control parser and
`verify_rehearsal_issuer_authorization` against the installed trusted issuer
verifier and frozen plan/target/descriptor/images/execution/controller/lease
terms. It checks issuance/validity against the window, then derives the full
parsed canonical envelope digest (including signature/key metadata) and the
actual UTC issuance time. A forged or substituted envelope refuses before a
new consume proof. The existing composition requires that proof's issuance
time to be strictly later. Signature validity alone is not current standing or
unspent authority; the actual Control ledger remains authoritative.

`ApprovedWindowBinding` is the immutable public capture produced during CP's
real preflight hold. NS3's distinct `ApprovedAtStartAdmission` requires this
binding, independently authenticated management delivery, public issuer
verification and original expiry. It derives actual consume bindings by the
same verified rule and authenticates the GitHub tuple. It may produce
channel/key possession evidence after withdrawal within that approved-at-start
window; it never asserts current Approvals standing. IDP3's current read and
point-of-use hold still refuse authority. NS3 receives no CP database or human
approval credentials. The actual authenticated handoff/installation factory is
unconfigured; constructing an arbitrary local JSON file does not supply it.

The adopted closed `Gate0IssuerWindow.v1` fields are:

- `schema`, `window_id`, canonical UTC `not_before`/`expires_at` (<=300 seconds),
  fixed `purpose`, exactly `allowed_phases=['issue','consume']`, and fixed
  `authorization_binding='control_parsed_full_envelope_v1'`.
- `github`: all fixed issuer/audience/repository/owner/environment/ref/workflow/
  event terms plus exact `run_id`, `run_attempt`, `sub`, `workflow_sha` and
  `environment_node_id`. No dynamic key URL or caller override.
- `target`: `id`, `ref`, `environment='rehearsal'`, `operation='deploy'`;
  `approval_policy`: actual `code` and positive integer `version`.
- `plan_inputs`: public passive `source_ref`, `config_ref`, actual
  `descriptor_digest` and Foundation-owned `execution_plan_digest`;
  `prerequisite_evidence_refs`: one to sixteen unique public SHA-256 references.
- `controller`: exact `lease_id`, controller `fingerprint`, `certificate_digest`,
  `ca_fingerprint`, fixed principal and 600-second certificate ceiling.

All objects have exact keys, bounded canonical ASCII JSON and no floats, unknown
fields, duplicate keys or cyclic future plan/approval/authorization coordinates.
Control's actual plan digest covers the spec; CP does not reconstruct it. The CP
window digest never replaces Foundation's execution-plan digest. The dedicated
plan input producer, real target/policy values, human-readable review of the
frozen content and live prerequisite evidence remain external owner inputs.
No Foundation candidate, image choice, target action or Lane-3 broker grant is
introduced by this namespace.

Synthetic hosted-only tests cover own-seed separation, no missing defaults,
wrapper origin/age/TTL/use count, token TTL/renewability/budget, pin mismatch,
trust-floor rollback, cancellation, JWT claims/attempt/algorithm/key URL,
key-cache removal, duplicate keys, phase/plan/window substitution and original
expiry. Both positive sign/verify and positive JWT/window cases are sensitive
to subsequent mutations. The extended hosted PostgreSQL fixture uses actual public Control desired-state
and plan commands, real Approvals holds, genuine issuer/attester crypto and
synthetic GitHub JWT/JWKS. It checks snapshot/digest changes, stale revisions,
signature-based consume derivation, frozen-window substitution and a real
withdrawal between preflight and mutation. These authored tests were not run
locally and do not qualify the deployed OpenBao server or a live authority. Hosted real transport/API and installed-service integration
remain necessary before operational acceptance; no local tests, dependency
installation, package imports, Docker, host calls or custody ceremony were run.

API basis: [OpenBao AppRole API](https://openbao.org/api-docs/auth/approle/),
[OpenBao wrapper lookup](https://openbao.org/api-docs/system/wrapping-lookup/),
[GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc),
and [GitHub's fixed discovery document](https://token.actions.githubusercontent.com/.well-known/openid-configuration).
Discovery confirms the fixed issuer, `/.well-known/jwks` and RS256; discovery
itself is not fetched from a bearer-supplied URL. Current API documentation is
source guidance, not evidence of the deployed server's pinned behavior.

The combined service regression exercises concrete JWT/window verification,
`IssuerWorker` and the real `Gate0Composition` issue → standing → consume
methods with one security installation and retained phase contexts. Owner DB
effects, the proof registry and signatures are explicitly synthetic in that
unit regression. The separate extended PostgreSQL fixture exercises actual
public owners, holds and cryptographic proofs; hosted execution is still required. Standing forwards its actual envelope to
admission only when its retained proof phase is consume, while composition
always checks that actual envelope. The issue admission rule is unchanged.
Partial IPC header/body stalls, valid frames and invalid lengths have dedicated
hosted-only cases; these tests were authored, not executed locally.

The current accepted Bao path remains HTTP over the separately approved
WireGuard design. This TLS-only source adapter has no currently qualified HTTPS
endpoint. It remains unconfigured until a concrete TLS or separately verified
WG transport binding is reviewed; no public proxy, DNS name, TLS CA or generic
HTTP fallback is invented here. The installed service factory still defaults to
None, so an image containing this source is not deployable/runtime-ready.

Pinned public owner API evidence is Control a17 commit
[`574418944d35ddf3559d17e59e9184b5f545ebe4`](https://github.com/michaelayoade/dotmac_deployment_control/tree/574418944d35ddf3559d17e59e9184b5f545ebe4),
recorded by `protected_issuer_conformance/release-evidence.json`: public
`PlanView.snapshot`/`authorized_images`, `SetDesiredStateCommand`,
`ProposePlanCommand` and `verify_rehearsal_issuer_authorization`. CP reuses
`approval_barrier.held_transition` and the exposed alias
`protected_rehearsal_issuer.issuer_approval_subject`; it does not duplicate the
canonical subject or Approvals hold implementation.

The new source uses complete function/port annotations, closed typed window and
claim records, checked JSON leaf projections and published owner view/crypto
interfaces. Local verification is limited to AST and pinned Ruff; required
hosted strict mypy and synthetic/owner/sshd tests must pass before source
acceptance. No local test, project import, mypy or build result is claimed.


## WG transport consumes sealed launch measurement

The fixed non-root transport no longer executes privileged `wg` queries. Root's
finite preflight measures the entire closed peer-/32 inventory, selected Bao
peer, source route and nft rules; after all privileged helpers/guardian are
reaped, root irreversibly seals its capability profile before publishing the
protected measurement/context. Every request loads the concrete installed
context again, binds measurement/endpoint/original deadline/supervisor facts,
and retains direct actual namespace/interface and socket device/source/peer
readbacks before sending any secret. No request or JSON flag supplies authority.

This relies on measured-at-launch plus enforced network immutability, not live
per-request netlink remeasurement. Signing workers and transport spawn require
E=P=I=A=0, NNP1 and inherited bounding K=0x400e3; K is not an effective grant.
Native fresh `SO_BINDTODEVICE`, pinned sshd UID changes, source/route isolation
and whole-boundary cleanup must pass the hosted/native qualification. A denied
socket operation refuses; no capability fallback, automatic network repair,
new broker or public HTTP path is added. See the finite launch operations for
exact fixed P0/K profiles and the deliberately partial native proof boundary.
