"""The Approvals cutover contract, in the form tests can enforce (ADR-0004).

The prose lives in `docs/adr/0004-approvals-authority-cutover.md`. This module
holds the parts a guard must be able to read: who the two authorities are, which
facts a pre-watermark record does and does not have, the six properties the
shadow comparison covers, and the exact set of modules allowed to call the legacy
decision surface.

Nothing here imports `dotmac_approvals`. The module is not a dependency of this
assembly yet — the contract precedes the composition, deliberately — so every
reference to it is a NAME, checked as a string. That is also what keeps this file
honest: it cannot accidentally start using the thing it is describing.

Nothing here is executable cutover machinery either. There is no watermark
writer, no comparison runner and no disposition tool; those belong to the cutover
change, and building them now would be composing by instalments.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

# ── The two authorities ─────────────────────────────────────────────────────

#: Authoritative today, and until the watermark row is committed.
OLD_AUTHORITY: Final[str] = "vendor_cp.approvals.service"

#: Authoritative after it. Named, never imported: not a dependency yet.
NEW_AUTHORITY: Final[str] = "dotmac_approvals"

#: The legacy package. Files inside it ARE the owner and are not "call sites".
LEGACY_PACKAGE: Final[str] = "vendor_cp.approvals"

#: The legacy decision surface — what an external caller reaches for when it
#: wants an approval answer. The ratchet is about THIS, not about the package's
#: own internal wiring.
LEGACY_DECISION_MODULE: Final[str] = "vendor_cp.approvals.service"


# ── Ruling 2, as data ───────────────────────────────────────────────────────


class LegacyFact(StrEnum):
    """What a pre-watermark `ApprovalRecord` carries, and what it does not."""

    #: Its own primary key. Survives the cutover untouched.
    SOURCE_RECORD_ID = "source_record_id"
    #: `(policy_code, policy_version, subject_type, subject_id, content_hash)` —
    #: the composite the legacy quorum was always counted over.
    IMPLICIT_GROUP_KEY = "implicit_group_key"
    #: Never persisted. Assigning one now would be a migration artefact dressed
    #: as a recorded fact.
    REQUEST_ID = "request_id"
    #: `submitter_id` lives on the SUBJECT, not on the approval group. Where the
    #: subject is gone or the column is null, the requester is simply unknown.
    REQUESTER = "requester"
    #: Legacy satisfaction is recomputed on read, so no row records that a group
    #: was ever approved — and none records a rejection at all.
    TERMINAL_STATE = "terminal_state"


#: Facts a pre-watermark record really has.
RECOVERABLE_FACTS: Final[frozenset[LegacyFact]] = frozenset(
    {LegacyFact.SOURCE_RECORD_ID, LegacyFact.IMPLICIT_GROUP_KEY}
)

#: Facts it does not have, and which the cutover will NOT invent. Unknown facts
#: stay unknown; new request identity begins at the watermark.
UNRECOVERABLE_FACTS: Final[frozenset[LegacyFact]] = frozenset(
    {LegacyFact.REQUEST_ID, LegacyFact.REQUESTER, LegacyFact.TERMINAL_STATE}
)


# ── The six shared safety properties ────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SharedSafetyProperty:
    """One property BOTH systems genuinely express, and how each enforces it.

    `module_mechanism` names a function or error in `dotmac_approvals` as a
    string. It is not imported: the module is not installed here, and a contract
    that only compiles once its subject is composed would have to be written
    after the thing it is supposed to gate.
    """

    code: str
    summary: str
    legacy_mechanism: str
    module_mechanism: str


SHARED_SAFETY_PROPERTIES: Final[tuple[SharedSafetyProperty, ...]] = (
    SharedSafetyProperty(
        code="immutable_policy_versions",
        summary="A published policy version is never rewritten.",
        legacy_mechanism="uq_approval_policies_code_ver; no UPDATE path exists",
        module_mechanism="PolicyRevision (frozen); PolicyVersionExists",
    ),
    SharedSafetyProperty(
        code="content_digest_binding",
        summary="An approval binds to the exact content it approved.",
        legacy_mechanism="content_hash inside uq_approval_records_unique",
        module_mechanism="ContentChanged",
    ),
    SharedSafetyProperty(
        code="fail_closed_missing_policy",
        summary="A missing policy or version refuses; it never permits.",
        legacy_mechanism="evaluate() returns satisfied=False, reason=policy_not_found",
        module_mechanism="PolicyNotFound",
    ),
    SharedSafetyProperty(
        code="distinct_actor_quorum",
        summary="Quorum counts PEOPLE, so one actor cannot satisfy it alone.",
        legacy_mechanism="count(distinct approver_id)",
        module_mechanism="policy.distinct_approvers / policy.level_satisfied",
    ),
    SharedSafetyProperty(
        code="self_approval_excluded",
        summary="The requester's own approval does not count unless permitted.",
        legacy_mechanism="submitter_id filtered out of the distinct count",
        module_mechanism="policy.check_self_approval (refuses by default)",
    ),
)

#: Spelled out rather than derived from `len()`. A number someone must edit is a
#: number someone must think about.
SHARED_SAFETY_PROPERTY_COUNT: Final[int] = 5

#: NOT a shared property, and the reason is behavioural rather than pedantic.
#: Vendor REPLAYS a duplicate command — `process_once_platform` returns the
#: existing row's id and the caller gets the original answer. The module REFUSES
#: it — `check_not_duplicate` raises `DuplicateDecision`. Both stop
#: double-counting, which is why they look alike, but "succeeds identically" and
#: "raises" are different observable behaviours: a retried HTTP request gets 200
#: from one and an error from the other. Comparing them as one property would
#: report an agreement that does not exist.
#:
#: At-most-once execution is kernel-owned (ADR-0014), so bridging the difference
#: is an obligation on the NEW ADAPTER, not a property of either engine.
ADAPTER_OBLIGATIONS: Final[tuple[str, ...]] = (
    "wrap_the_module_decision_in_the_kernel_platform_at_most_once_primitive",
    "preserve_replay_semantics_so_a_retried_command_returns_the_original_outcome",
)

#: Module capabilities Vendor never expressed, and which are therefore compared
#: against NOTHING. Named so the omission is a decision on the record: inventing
#: a legacy expectation to compare against is the same fabrication Ruling 2
#: refuses, one layer up.
#: NARROWED. An earlier draft declared approver eligibility wholly uncompared,
#: which overstated the gap: Vendor expresses a coarse rule and it is mapped
#: above. Only the genuinely richer capabilities remain uncompared.
UNCOMPARED_MODULE_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "fine_grained_approver_eligibility",
        "separation_of_duties",
        "mfa_requirement",
        "multi_level_sequencing",
        "delegation",
    }
)


# ── The coarse eligibility mapping (assembly-owned) ─────────────────────────

#: Vendor's eligibility rule, in Vendor's own terms: `approvals/router.py` guards
#: every approval with `require_platform_admin` and records `admin.id` as the
#: approver. So the rule is real — "any authenticated platform admin may
#: approve" — it is simply enforced by an authentication guard rather than by
#: data, and it is COARSE rather than absent.
COARSE_ELIGIBILITY_RULE: Final[str] = "any_authenticated_platform_admin"

#: The module's `ApprovalLevel.approver_kind` / `approver_id` are REQUIRED — no
#: defaults, and a blank `approver_id` is refused in `__post_init__` — so the
#: mapping cannot be left implicit. This assembly therefore NAMES the role.
#:
#: Stable and arbitrary, in that order. It is not recovered from anywhere and
#: does not pretend to be: it is the name this assembly assigns to a rule Vendor
#: enforced through a guard. It must never change, because a value that differed
#: between shadow runs would silently change what was compared.
PLATFORM_ADMIN_ROLE_ID: Final[str] = "6f1d2a7c-9b34-4f5e-8c21-0d7a5e3b41f9"

#: How a legacy approver becomes a module `Actor`. Every legacy approver held the
#: role by construction: appearing in `approval_records` at all means they passed
#: `require_platform_admin` at the time.
ACTOR_MAPPING: Final[tuple[str, ...]] = (
    "actor_id := approval_records.approver_id",
    f"role_ids := {{{PLATFORM_ADMIN_ROLE_ID}}}",
    "mfa_verified := False (never recorded; no level requires it)",
)


# ── Digest translation ──────────────────────────────────────────────────────

#: Vendor stores `hashlib.sha256(...).hexdigest()` — bare lowercase hex.
VENDOR_DIGEST_LENGTH: Final[int] = 64

#: The module requires `sha256:` + 64 lowercase hex, enforced by
#: `validate_digest`, which raises `ContentChanged` on anything else.
MODULE_DIGEST_PREFIX: Final[str] = "sha256:"


#: Deterministic and total in one direction. Nothing is normalised on the way
#: through: an uppercase or short value is NOT lowercased or padded into
#: validity, because a digest that needed repairing is a digest whose provenance
#: is unknown.
def translate_digest(vendor_content_hash: str) -> str:
    """`<64 lowercase hex>` -> `sha256:<64 lowercase hex>`, or raise.

    Pure and dependency-free — it names no module type — so the preflight can
    run before anything is composed.
    """
    reason = digest_rejection_reason(vendor_content_hash)
    if reason is not None:
        raise ValueError(
            f"legacy content_hash is not translatable ({reason}); an approval "
            "whose bound content cannot be expressed in the new system must "
            "stop the cutover, not be skipped"
        )
    return f"{MODULE_DIGEST_PREFIX}{vendor_content_hash}"


#: Every way a legacy digest can fail to translate. Reported per row by the
#: preflight so an operator resolves the ROW, rather than someone widening the
#: accepted format.
DIGEST_REJECTION_REASONS: Final[tuple[str, ...]] = (
    "empty",
    "already_prefixed",
    "wrong_length",
    "uppercase",
    "non_hex",
)

_HEX_LOWER: Final[frozenset[str]] = frozenset("0123456789abcdef")


def digest_rejection_reason(vendor_content_hash: str) -> str | None:
    """Why this digest cannot translate, or `None` when it can.

    FAIL CLOSED: every branch that is not a clean 64-character lowercase hex
    string returns a reason. There is no tolerant path.
    """
    if not vendor_content_hash:
        return "empty"
    if vendor_content_hash.startswith(MODULE_DIGEST_PREFIX):
        return "already_prefixed"
    if len(vendor_content_hash) != VENDOR_DIGEST_LENGTH:
        return "wrong_length"
    if any(character.isupper() for character in vendor_content_hash):
        return "uppercase"
    if any(character not in _HEX_LOWER for character in vendor_content_hash):
        return "non_hex"
    return None


# ── Disposition of incomplete legacy groups ─────────────────────────────────


class Disposition(StrEnum):
    """What happens to a pre-watermark group that never met its quorum."""

    #: Subject still live, still pending, digest unchanged: the legacy owner
    #: finishes it BEFORE the watermark. Preferred wherever possible — the
    #: approvers already gave a real opinion about that exact content.
    DRAIN = "drain"
    #: Everything else becomes a genuine module request AFTER cutover, with a
    #: real requester and a real idempotency key. Legacy rows stay as evidence.
    RESTART = "restart"


#: The conditions that force RESTART. Evaluated in order; the first that holds
#: decides. If none holds, the group DRAINS. Stated as data so the rule cannot
#: quietly become case-by-case judgement about a particular customer.
RESTART_CONDITIONS: Final[tuple[str, ...]] = (
    "subject_content_digest_changed_since_the_approvals_were_recorded",
    "subject_is_terminal_or_cancelled",
    "policy_version_no_longer_exists",
    "not_drained_before_the_scheduled_watermark",
)


# ── The watermark ───────────────────────────────────────────────────────────

#: One row, insert-only, written inside the sealing transaction. Created by the
#: cutover change, not by this one.
SEAL_TABLE: Final[str] = "approval_cutover_seal"

#: An earlier draft used `max(approval_records.id)` as a boundary cursor. That is
#: INVALID: `ApprovalRecord.id` comes from the kernel's `uuid_pk()`, which is
#: `default=uuid4` — random. A high-water mark over random values orders
#: nothing. The argument against clocks was right; the substitute was not.
#:
#: The seal removes the boundary question instead of answering it: online DML is
#: revoked first, so every legacy row is pre-cutover BY CONSTRUCTION, and the
#: count and digest are evidence that the set compared is the set sealed.
SEAL_COLUMNS: Final[tuple[str, ...]] = (
    "sealed_at",
    "alembic_revision",
    "legacy_policy_count",
    "legacy_record_count",
    "evidence_digest",
    "digest_algorithm",
    "operator_ref",
)

#: Revoked from the ONLINE roles before the seal is taken, which is what makes
#: "no later legacy row can exist" a property of the database rather than a
#: promise.
SEALED_LEGACY_TABLES: Final[tuple[str, ...]] = (
    "approval_policies",
    "approval_records",
)

#: Fields hashed into `evidence_digest`, in order. `id` is deliberately absent:
#: it is random, carries no meaning, and including it would make the digest
#: depend on a value nothing else in this contract trusts.
EVIDENCE_DIGEST_FIELDS: Final[tuple[str, ...]] = (
    "policy_code",
    "policy_version",
    "subject_type",
    "subject_id",
    "content_hash",
    "approver_id",
)

#: Revoked from every online role once written, so the sealed set cannot be
#: restated afterwards to make a parity report agree.
SEAL_IMMUTABLE_AFTER_WRITE: Final[bool] = True

#: If a scalar cursor is ever genuinely needed, add an enforced monotonic BIGINT
#: to the legacy table first. Never a cursor over UUID primary keys.
SCALAR_CURSOR_REQUIREMENT: Final[str] = "enforced_monotonic_bigint_column"


# ── The ratchet ─────────────────────────────────────────────────────────────

#: Every module OUTSIDE the legacy package that reaches the legacy decision
#: surface. Exactly one today.
#:
#: Two-directional. A NEW caller fails: new work must not deepen a dependency
#: scheduled for retirement, and each added caller is one more migration to
#: perform later. A REMOVED caller fails too — that is cutover progress, and the
#: declaration must be lowered in the same change. This set reaching empty is
#: retirement gate 3 in ADR-0004 § 8.
LEGACY_DECISION_CALL_SITES: Final[frozenset[str]] = frozenset(
    {"vendor_cp/contracts/service.py"}
)

#: Composition sites are not call sites: `assembly.py` mounts the feature
#: manifest and never asks it for a decision. Named so the ratchet above stays
#: about DECISIONS, which is the dependency the cutover has to move.
LEGACY_COMPOSITION_SITES: Final[frozenset[str]] = frozenset({"vendor_cp/assembly.py"})


__all__ = [
    "LEGACY_COMPOSITION_SITES",
    "LEGACY_DECISION_CALL_SITES",
    "LEGACY_DECISION_MODULE",
    "LEGACY_PACKAGE",
    "NEW_AUTHORITY",
    "OLD_AUTHORITY",
    "RECOVERABLE_FACTS",
    "RESTART_CONDITIONS",
    "SHARED_SAFETY_PROPERTIES",
    "SHARED_SAFETY_PROPERTY_COUNT",
    "UNCOMPARED_MODULE_CAPABILITIES",
    "UNRECOVERABLE_FACTS",
    "ACTOR_MAPPING",
    "ADAPTER_OBLIGATIONS",
    "COARSE_ELIGIBILITY_RULE",
    "DIGEST_REJECTION_REASONS",
    "EVIDENCE_DIGEST_FIELDS",
    "MODULE_DIGEST_PREFIX",
    "PLATFORM_ADMIN_ROLE_ID",
    "SCALAR_CURSOR_REQUIREMENT",
    "SEALED_LEGACY_TABLES",
    "SEAL_COLUMNS",
    "SEAL_IMMUTABLE_AFTER_WRITE",
    "SEAL_TABLE",
    "VENDOR_DIGEST_LENGTH",
    "digest_rejection_reason",
    "translate_digest",
    "Disposition",
    "LegacyFact",
    "SharedSafetyProperty",
]
