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
        code="command_idempotency",
        summary="Replaying one command records one decision.",
        legacy_mechanism="process_once_platform + uq_approval_records_unique",
        module_mechanism="policy.check_not_duplicate + the module unique constraint",
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
SHARED_SAFETY_PROPERTY_COUNT: Final[int] = 6

#: Module capabilities Vendor never expressed, and which are therefore compared
#: against NOTHING. Named so the omission is a decision on the record: inventing
#: a legacy expectation to compare against is the same fabrication Ruling 2
#: refuses, one layer up.
UNCOMPARED_MODULE_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "per_level_approver_eligibility",
        "separation_of_duties",
        "mfa_requirement",
        "multi_level_sequencing",
        "delegation",
    }
)


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

#: One row, insert-only, written inside the cutover transaction. Created by the
#: cutover change, not by this one.
WATERMARK_TABLE: Final[str] = "approval_cutover_watermark"

#: The boundary is an id high-water mark, NOT wall-clock time: a retried
#: transaction can commit a legacy row whose timestamp precedes a watermark
#: written moments earlier, and an id is unambiguous under exactly that race.
WATERMARK_BOUNDARY_COLUMN: Final[str] = "last_legacy_record_id"

#: Revoked from every online role once written, so the boundary cannot be moved
#: afterwards to make a parity report look better.
WATERMARK_IMMUTABLE_AFTER_WRITE: Final[bool] = True


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
    "WATERMARK_BOUNDARY_COLUMN",
    "WATERMARK_IMMUTABLE_AFTER_WRITE",
    "WATERMARK_TABLE",
    "Disposition",
    "LegacyFact",
    "SharedSafetyProperty",
]
