"""The conditions for retiring the incumbent writer and granting target DML.

Nothing in this repository opens either gate, and this module takes no authority
decision. It follows `AGENTS.md` rule 12 — an authority cutover is contracted
before it is composed, and its premise is checked — by writing the premise down
first, in the shape a later change can be held to.

## Gate 1 — incumbent-writer retirement

Vendor's incumbent commercial writer is
`vendor_cp.offers.service.publish_offer_version`, the one owner of the immutable
priced `offer_versions` rows. It is a real, current authority over price, and
retiring it is what a commercial backfill eventually implies. It is NOT retired
here and this gate does not retire it.

## Gate 2 — the final DML grant

The last step of any backfill is the grant that lets the target's runtime role
write the tables it has just been given. That grant is a separate decision from
the data movement, and this gate keeps it separate. It also carries the
invariant this work runs under from the Vendor side: **this change grants Vendor's
runtime role nothing.** The rehearsal reconciler repairs shadow rows through the
migrator role in a disposable database and issues no `GRANT` at all.

## Evidence kinds, and why a test cannot close a gate on its own

`AGENTS.md` rule 17. A condition derived from what this repository CONTAINS —
a symbol's call sites, a declared table set, a function that does or does not
exist — is `LOCAL_FACT`, and a test here can discharge it. A condition about a
release, a registry, another product's cutover or a production database needs an
authoritative external oracle carrying immutable coordinates, and no test in this
repository can discharge it. Those conditions are named with their oracle KIND
and their owner, and `discharged` stays `False` for them by construction:
`tests/architecture/test_commercial_backfill.py` fails if a non-local condition
is ever recorded as discharged.

The failure this shape exists to prevent is the one `AWAITING_RELEASE_TAG`
already caused in this repository — a declaration whose SHAPE implied a check it
could not perform, which stayed green through the event it claimed to gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Final


class EvidenceKind(Enum):
    """How a condition is discharged.

    `LOCAL_FACT` is the only kind a test in this repository can settle. The
    other four are the oracle kinds accepted `dotmac_governance` ADR 0013
    defines for the fleet.
    """

    LOCAL_FACT = auto()
    RELEASE_RUN = auto()
    PEELED_TAG = auto()
    DEPLOYMENT_RUN = auto()
    ADOPTION_EVIDENCE = auto()


class GateState(Enum):
    """A gate is CLOSED until every one of its conditions is discharged."""

    CLOSED = auto()
    OPEN = auto()


@dataclass(frozen=True, slots=True)
class GateCondition:
    """One condition, its evidence kind, its owner, and whether it is settled.

    `owner` names who discharges it. A condition with an oracle kind and no
    named owner is an obligation nobody holds, which is how a gate quietly
    becomes a formality.
    """

    code: str
    evidence: EvidenceKind
    owner: str
    statement: str
    discharged: bool = False

    def __post_init__(self) -> None:
        if not self.code.isupper() or " " in self.code:
            raise ValueError("a condition code is an upper-case identifier")
        if not self.owner.strip():
            raise ValueError(f"{self.code} names no owner")
        if len(self.statement) < 40:
            raise ValueError(f"{self.code} states no reviewable condition")
        if self.discharged and self.evidence is not EvidenceKind.LOCAL_FACT:
            raise ValueError(
                f"{self.code} needs an external oracle and cannot be discharged "
                "from inside this repository"
            )


@dataclass(frozen=True, slots=True)
class Gate:
    """A named gate. `state()` is derived, never declared."""

    name: str
    conditions: tuple[GateCondition, ...]

    def state(self) -> GateState:
        if self.conditions and all(c.discharged for c in self.conditions):
            return GateState.OPEN
        return GateState.CLOSED

    def outstanding(self) -> tuple[str, ...]:
        return tuple(c.code for c in self.conditions if not c.discharged)


#: What must hold before Vendor's incumbent commercial price writer may retire.
INCUMBENT_WRITER_RETIREMENT_GATE: Final[Gate] = Gate(
    name="incumbent_commercial_writer_retirement",
    conditions=(
        GateCondition(
            code="TYPED_PAGINATED_AGREEMENT_READER_RELEASED",
            evidence=EvidenceKind.RELEASE_RUN,
            owner="dotmac-commercial-agreements release owner",
            statement=(
                "a dotmac-commercial-agreements release publishes and verifies "
                "an installable typed paginated agreement reader; repository "
                "source or a local replacement is not release evidence."
            ),
        ),
        GateCondition(
            code="COHORT_FULLY_ENUMERABLE",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "every source kind is enumerable through Vendor's adapter over "
                "an exactly pinned typed paginated owner reader, without raw "
                "module-table access or a locally invented reader."
            ),
        ),
        GateCondition(
            code="ZERO_BLOCKED_ROWS",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "the dry-run plan over the full cohort reports no blocked rows, "
                "and every excluded row carries a reason a reviewer accepted."
            ),
        ),
        GateCondition(
            code="SEMANTIC_PARITY_PROVEN",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "the comparator reports TARGET_SEMANTIC MATCHED, not merely "
                "ROW_COUNT MATCHED, across every dimension. Equal counts with "
                "unequal meaning is the failure this condition exists for."
            ),
        ),
        GateCondition(
            code="TARGET_AUTHORITY_ACCEPTED",
            evidence=EvidenceKind.ADOPTION_EVIDENCE,
            owner="the owning repository's extraction dossier",
            statement=(
                "an accepted, checked-in contract names the owner of "
                "subscription and billing decisions after the move. THIS "
                "REPOSITORY DOES NOT CHOOSE IT and cannot observe it."
            ),
        ),
        GateCondition(
            code="BACKFILL_EXECUTED_IN_PRODUCTION",
            evidence=EvidenceKind.DEPLOYMENT_RUN,
            owner="the operator, against a host Michael names explicitly",
            statement=(
                "the backfill has actually run against production, evidenced by "
                "a deploy run id and an immutable image digest. No test in this "
                "repository discharges it and none pretends to."
            ),
        ),
    ),
)

#: What must hold before the target's runtime role is granted DML on the
#: backfilled tables — and what this change grants, which is nothing.
FINAL_DML_GRANT_GATE: Final[Gate] = Gate(
    name="final_dml_grant",
    conditions=(
        GateCondition(
            code="INCUMBENT_RETIREMENT_GATE_OPEN",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "the incumbent-writer retirement gate is OPEN. Granting the "
                "runtime role DML while a second writer is still live is how a "
                "cutover acquires two authorities instead of moving one."
            ),
        ),
        GateCondition(
            code="NO_VENDOR_RUNTIME_DML_ADDED",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "this work grants Vendor's runtime role no privilege it did not "
                "already hold. The rehearsal reconciler emits no GRANT at all "
                "and runs through the migrator role in a disposable database."
            ),
            discharged=True,
        ),
        GateCondition(
            code="REHEARSAL_REPLAY_PROVEN",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "the reconciler has been replayed in a disposable PostgreSQL "
                "and left identical state and an identical report, so a "
                "half-finished run can be repeated rather than reasoned about."
            ),
        ),
        GateCondition(
            code="EFFECTIVE_PRIVILEGES_VERIFIED_BOTH_WAYS",
            evidence=EvidenceKind.LOCAL_FACT,
            owner="vendor control plane",
            statement=(
                "the grant is verified as an EFFECTIVE outcome in both "
                "directions — the role holds what it needs and nothing beyond "
                "it — the shape ADR-0006 s 3 used for mod_ealloc."
            ),
        ),
        GateCondition(
            code="GRANT_APPLIED_IN_PRODUCTION",
            evidence=EvidenceKind.DEPLOYMENT_RUN,
            owner="the operator, against a host Michael names explicitly",
            statement=(
                "the grant has been applied to production, evidenced by a "
                "deploy run id and an immutable image digest. A privilege claim "
                "about a database this repository cannot see needs an oracle."
            ),
        ),
    ),
)

GATES: Final[tuple[Gate, ...]] = (
    INCUMBENT_WRITER_RETIREMENT_GATE,
    FINAL_DML_GRANT_GATE,
)


__all__ = [
    "FINAL_DML_GRANT_GATE",
    "GATES",
    "INCUMBENT_WRITER_RETIREMENT_GATE",
    "EvidenceKind",
    "Gate",
    "GateCondition",
    "GateState",
]
