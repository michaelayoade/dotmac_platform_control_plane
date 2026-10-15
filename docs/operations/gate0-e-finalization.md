# Gate 0 retained E evidence verification

`gate0_e_finalization.verify_retained_collection(raw, selection)` checks the exact
private `collection.json` against an independently supplied, inert `ESelection`.
Its `VerifiedCollection` result means `retained_bytes_verified` and always exposes
`readiness_accepted=False`. It grants no current eligibility or publication
permission. Construction of a Python selection is not installation provenance.

The selection retains original A/B shared packets, frozen windows, command IDs,
four expected root bindings, original public trust records and durable floors,
qualification/source references, a source bundle pin, campaign/policy digests and
B's withdrawal correlation reference. A/B must use the same run coordinates,
distinct plan/approval/window/command/controller/lease/certificate coordinates,
and ordered independent intervals of at most 300 seconds. Original public trust
is independently pinned; evidence cannot enroll its own signer or defeat a
revoked key with a matching trusted entry.

Verification preserves all original collection bytes. It checks the closed
collection/evidence schema and original selections/trust, exactly four proof
bundles (128 KiB each, 512 KiB total), nine actual owner outcomes, reconstructed
credential-free request identities, the actual closed eight-field issuer receipt,
and direct equality between each issued authorization ID and its signed Control
statement ID. Receipt UUID, digest and original-window time bounds are checked;
JSON receipt fields alone confer no owner provenance. Verification also checks signed
owner/companion/session evidence and the original controller possession proof.
A's replay uses the identical authorization/proof and the exact Control refusal;
B's third standing uses its issue proof. B's withdrawal refusal preserves either
the exact consume digest pair or two absent digests when admission refused before
proof evaluation. Mixed or foreign pairs fail.

Historical proof verification uses immutable original windows and signed times.
It never creates a `WindowFreshness`, `RunnerProjectionCase`, live harness
verifier, database session, owned service process, or owned SSH session.
Public SSHSIG verification uses the existing fixed, bounded verification child;
its independent timeout of at most two seconds grants no historical operation
eligibility. The holder-verifier installation must qualify the exact native
verification binary and execution context independently; selection construction
does not measure or authenticate that installation. This path has no network,
database, custody or live operation I/O. Elapsed cleanup claims
are checked against their original anchors. An archive read cannot restart or
extend a window, register another proof, reconsume an authorization or refresh
trust. All cryptographic, purpose, certificate and refusal semantics remain with
the existing owners' shared helpers.

The root byte checks consume exactly fourteen envelopes/terminals in two finite
case rosters, preserve phase/process bindings and compare root terminals,
transcripts, capture readbacks and joins. The existing owner supplies mechanics,
removal, daemon/guardian/cgroup and capture predicates. These byte checks cannot
recover historical `SO_PEERCRED`, actual EOF or child wait observations. Qualified
protected producer provenance must supply those historical origin claims. A
JSON `stdout_eof` field or matching transcript hash alone cannot authenticate a
root. The collector join also omits some live sampled timing fields; no
completion DTO or timestamp is fabricated to fill them.

Approval and withdrawal projection checks share the existing owner predicates
using inert original coordinates. Raw polls are bounded to sixteen, observations
are ordered inside the original window, states cannot regress or follow the
terminal applied read, and the final applied projection must match the retained
withdrawal bytes. The exact event/relay revokes precisely the issued B
authorization, and the consume proof predates the real withdrawal event.

This source layer deliberately has no `AcceptedE`, accepted-prerequisite flag,
installed policy loader, producer oracle, five-file archive preparation or final
readiness receipt writer. B and C1 have existing adopted decisions, immutable
source revisions and successful hosted checks: CP #200, Starter #753, and CP
#201/#204. Their source acceptance must be bound to those actual owner artifacts;
the historical undecided C1 wording does not reopen that decision. A new
acceptance lifecycle must not be invented. Concrete GitHub producer verification, complete
prerequisite evidence/acceptance, installed source/runtime qualification, actual
runner key cleanup, B custody verification and immutable publication remain
coordinator integration work. The proposed digest-bound B verification and
publication-review provenance contract still requires Michael's design adoption.
A successful retained-byte result does not discharge any of those requirements.

The focused test sources use historical real-schema signed evidence, actual
synthetic controller certificates/SSHSIGs, one-field tampering and revoked/floor
checks. A coherent authorization-ID rebind negative updates the unsigned issuer
result, receipt, root transcript/digests, join and withdrawal relay while retaining
the original signed envelope; it must still refuse. They are hosted source qualification, not protected E acceptance. Local
validation for this change is restricted to AST parsing and pinned Ruff 0.6.9;
project imports, tests, builds, installation and operational execution are not
part of this source step.
