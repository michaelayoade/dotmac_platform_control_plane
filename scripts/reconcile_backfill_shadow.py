#!/usr/bin/env python
"""Repair a rehearsal's commercial-backfill shadow rows. Emits SQL; applies none.

    poetry run python scripts/reconcile_backfill_shadow.py \\
        --source-export rehearsal-rows.json \\
        --product-code acme \\
        --confirm-disposable > repair.sql

## What it does, and the three things it deliberately does not

It reads a projected source export, classifies every row through the same
planner a dry run uses, writes the value-free plan report to STDERR, and writes
idempotent repair SQL for the rehearsal shadow to STDOUT.

**It does not connect.** No engine, no session, no DSN, no database environment
variable. Deny case D1 makes the kernel the one owner of a connection in this
assembly and the connection allowlist in `tests/architecture/test_deny_cases.py`
is empty; this command keeps it empty. An operator applies the SQL with `psql`
under the MIGRATOR role, which is the same role every privileged statement in
this repository already runs as.

**It does not grant.** There is no `GRANT` in anything it emits. The repair
REVOKEs from Vendor's online role on the rehearsal schema instead, guarded so it
is a no-op where that role does not exist. Vendor's runtime role gains no
privilege from this work — which is one of the conditions the final-DML-grant
gate carries.

**It does not touch production.** `--confirm-disposable` is required, and it is
required because this command cannot check the premise itself: it never sees a
database, so it cannot read a host marker. Making the operator STATE the premise
is honest; inferring it from a DSN this command does not have would not be.

## Why the source arrives as a file

This command deliberately owns no session or connection. `public.offer_versions`
is a real table with a real model here, and `vendor_cp.commercial_backfill.shadow
.OFFER_VERSION_EXPORT_SQL` is its read-only projection. Agreement lines are read
through the exactly pinned Commercial Agreements owner's bounded UUID-keyset
reader and translated by `vendor_cp.contracts.adapter`; no raw module-table query
or locally invented reader exists. The separate export boundary records which
sources actually reached their final page. A partial export reports
`NOT_ENUMERABLE`; the mere presence of a reader never turns unknown rows into
zero.

## Replay-safety

Running the emitted SQL twice leaves identical state and produces an identical
report. The shadow table has no timestamp column and no surrogate key on
purpose; see `vendor_cp.commercial_backfill.shadow`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Final

from vendor_cp.commercial_backfill.cohort import CohortRules, SourceRow, SourceRowError
from vendor_cp.commercial_backfill.planner import plan
from vendor_cp.commercial_backfill.report import render
from vendor_cp.commercial_backfill.shadow import repair_statements
from vendor_cp.commercial_backfill.vocabulary import SourceKind

#: Every field the export may carry, so an unrecognised key is refused rather
#: than ignored. A silently dropped field is a row classified on less
#: information than the exporter thought it sent.
_KNOWN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "kind",
        "fingerprint",
        "amount",
        "currency_code",
        "product_code",
        "sibling_product_codes",
        "sibling_currency_codes",
        "quantity",
        "referenced_by_cohort_line",
        "agreement_status",
        "is_superseded",
        "content_hash",
        "activation_content_hash",
        "term_start",
        "term_end_exclusive",
    }
)


class ExportError(ValueError):
    """The export does not satisfy the source projection contract."""


def _text(entry: Mapping[str, object], name: str) -> str | None:
    """A field NARROWED, never coerced. `str(value)` would turn a JSON number
    into a plausible-looking product code, and a JSON `null` into `"None"`."""
    value = entry.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExportError(f"{name} is a string")
    return value


def _flag(entry: Mapping[str, object], name: str, *, default: bool) -> bool:
    value = entry.get(name, default)
    if not isinstance(value, bool):
        raise ExportError(f"{name} is a boolean")
    return value


def _whole(entry: Mapping[str, object], name: str, *, default: int) -> int:
    value = entry.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExportError(f"{name} is an integer")
    return value


def _codes(entry: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = entry.get(name, ())
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ExportError(f"{name} is a list of strings")
    for item in value:
        if not isinstance(item, str):
            raise ExportError(f"{name} is a list of strings")
    return tuple(str(item) for item in value)


def _day(entry: Mapping[str, object], name: str) -> date | None:
    value = _text(entry, name)
    return None if value is None else date.fromisoformat(value)


def _required_text(entry: Mapping[str, object], name: str) -> str:
    value = _text(entry, name)
    if value is None:
        raise ExportError(f"{name} is required")
    return value


def _row(entry: Mapping[str, object]) -> SourceRow:
    """One export entry, narrowed field by field. No `Any` at this boundary: a
    wrong shape is refused here rather than becoming a plausible source row."""
    unknown = sorted(set(entry) - _KNOWN_FIELDS)
    if unknown:
        raise ExportError(f"unrecognised field(s): {unknown}")
    try:
        kind = SourceKind[_required_text(entry, "kind")]
    except KeyError as exc:
        raise ExportError("kind is OFFER_VERSION or AGREEMENT_LINE") from exc
    return SourceRow(
        kind=kind,
        fingerprint=_required_text(entry, "fingerprint"),
        amount=_required_text(entry, "amount"),
        currency_code=_required_text(entry, "currency_code"),
        product_code=_text(entry, "product_code"),
        sibling_product_codes=_codes(entry, "sibling_product_codes"),
        sibling_currency_codes=_codes(entry, "sibling_currency_codes"),
        quantity=_whole(entry, "quantity", default=1),
        referenced_by_cohort_line=_flag(
            entry, "referenced_by_cohort_line", default=True
        ),
        agreement_status=_text(entry, "agreement_status"),
        is_superseded=_flag(entry, "is_superseded", default=False),
        content_hash=_text(entry, "content_hash"),
        activation_content_hash=_text(entry, "activation_content_hash"),
        term_start=_day(entry, "term_start"),
        term_end_exclusive=_day(entry, "term_end_exclusive"),
    )


def read_export(path: Path) -> tuple[SourceRow, ...]:
    """Parse the export STRICTLY. A malformed row stops the run.

    Not "skip the bad rows and carry on": a skipped row is a row that reaches
    neither the cohort nor the blocker count, which is the one outcome the
    three-bucket rule forbids.
    """
    payload = json.loads(path.read_text())
    if not isinstance(payload, list):
        raise ExportError("the export is a JSON list of source rows")
    rows: list[SourceRow] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise ExportError("every export entry is a JSON object")
        rows.append(_row(entry))
    return tuple(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-export", required=True, type=Path)
    parser.add_argument(
        "--product-code",
        action="append",
        default=[],
        help="a declared product code; repeat for each. Empty means none is "
        "declared, and every row blocks on CODE_UNDECLARED.",
    )
    parser.add_argument(
        "--enumerated",
        action="append",
        default=[],
        choices=[kind.name for kind in SourceKind],
        help="a source kind this export genuinely covers. A kind left out is "
        "reported as NOT_ENUMERABLE, which is not the same as zero rows.",
    )
    parser.add_argument(
        "--confirm-disposable",
        action="store_true",
        help="state that the target is a disposable test or development "
        "database. Required, because this command never sees a database and "
        "cannot check the premise itself.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="write the plan report and emit no SQL.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.confirm_disposable:
        print(
            "refusing: pass --confirm-disposable. The rehearsal shadow is for "
            "test and development databases only, and this command cannot "
            "check that for you.",
            file=sys.stderr,
        )
        return 2

    try:
        rows = read_export(args.source_export)
    except (ExportError, SourceRowError, ValueError) as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        return 3

    rules = CohortRules(declared_product_codes=frozenset(args.product_code))
    outcome = plan(
        rows,
        rules,
        enumerated=frozenset(SourceKind[name] for name in args.enumerated),
    )
    print(render(outcome.report), file=sys.stderr)

    if args.report_only:
        return 0
    for statement in repair_statements(outcome.verdicts):
        print(f"{statement};")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
