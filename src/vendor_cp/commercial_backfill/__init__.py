"""Commercial backfill: cohort, mapping, dry-run, comparison and gate contracts.

This package moves no authority, chooses no billing owner, and runs no backfill.
It is the CONTRACTING step `AGENTS.md` rule 12 requires before a cutover is
composed: the cohort is stated, the five transformations are named with their
edge cases, and the premise each gate would need is written down where a later
change can be held to it.

Read `docs/commercial-backfill-dossier.md` first. The declarations here are the
machine-readable half; where the two disagree,
`tests/architecture/test_commercial_backfill.py` is the one that fails.

## The one property everything else is arranged around

**No report emits an identifier, an amount, a label or a timestamp.** Counts,
categories and blocker reasons only. `vocabulary.py` declares the closed set of
categories, `report.py` builds reports out of those and cardinalities and
nothing else, and its renderer refuses any token outside that alphabet. The
planner and the comparator have no way to reach around it, because the only
report type they can return is `Report`.

## Module map

* `vocabulary` — every category a report may name, as closed enums.
* `report` — `Count`, `Tally`, `Report`, and the render-time egress check.
* `transforms` — the five transformations, each returning a category not a value.
* `cohort` — the cohort definition, the source projection, and the total
  classifier that puts every row in exactly one of three buckets.
* `planner` — the dry-run planner. No session, no clock, no output path.
* `comparator` — row-count parity and target semantic parity, kept apart.
* `shadow` — idempotent, grant-free repair SQL for a rehearsal database.
* `gates` — the incumbent-writer retirement gate and the final-DML-grant gate.
"""

from __future__ import annotations

from vendor_cp.commercial_backfill.cohort import (
    CohortRules,
    RowVerdict,
    SourceRow,
    SourceRowError,
    classify,
)
from vendor_cp.commercial_backfill.comparator import (
    TargetObservation,
    compare,
    observe,
)
from vendor_cp.commercial_backfill.gates import (
    FINAL_DML_GRANT_GATE,
    GATES,
    INCUMBENT_WRITER_RETIREMENT_GATE,
    EvidenceKind,
    Gate,
    GateCondition,
    GateState,
)
from vendor_cp.commercial_backfill.planner import (
    PlanOutcome,
    PlanTotalityError,
    is_complete_cohort,
    plan,
)
from vendor_cp.commercial_backfill.report import (
    Report,
    Tally,
    UnsafeReportValue,
    render,
)
from vendor_cp.commercial_backfill.shadow import repair_statements
from vendor_cp.commercial_backfill.vocabulary import (
    Bucket,
    CadenceOutcome,
    CurrencyOutcome,
    Dimension,
    ExclusionReason,
    FrozenContentOutcome,
    ParitySubject,
    ParityVerdict,
    ProductIdentityOutcome,
    ProrationOutcome,
    SourceCoverage,
    SourceKind,
)

__all__ = [
    "FINAL_DML_GRANT_GATE",
    "GATES",
    "INCUMBENT_WRITER_RETIREMENT_GATE",
    "Bucket",
    "CadenceOutcome",
    "CohortRules",
    "CurrencyOutcome",
    "Dimension",
    "EvidenceKind",
    "ExclusionReason",
    "FrozenContentOutcome",
    "Gate",
    "GateCondition",
    "GateState",
    "ParitySubject",
    "ParityVerdict",
    "PlanOutcome",
    "PlanTotalityError",
    "ProductIdentityOutcome",
    "ProrationOutcome",
    "Report",
    "RowVerdict",
    "SourceCoverage",
    "SourceKind",
    "SourceRow",
    "SourceRowError",
    "Tally",
    "TargetObservation",
    "UnsafeReportValue",
    "classify",
    "compare",
    "is_complete_cohort",
    "observe",
    "plan",
    "render",
    "repair_statements",
]
