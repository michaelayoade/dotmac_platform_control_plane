#!/usr/bin/env python3
"""Promote a candidate descriptor into accepted truth, licensed by a receipt.

`deploy/product.toml` is never edited. A change is authored as a candidate under
`deploy/candidates/`, and becomes accepted only when a promotion is appended to
`deploy/descriptor-promotions.json` and the candidate's exact bytes are copied
over the accepted file. Until now that was a human following the failure message
of `tests/architecture/test_descriptor_promotion.py` -- a procedure, not a
mechanism, on the path where a receipt is supposed to license exact bytes.

## What licenses a promotion, and what does not

**The licence is the heads.** A deployment receipt records `migration_heads`
measured AFTER the migrate, and a candidate declares `migration.expected_heads`.
If those disagree, the candidate does not describe what the run produced and
must not become accepted truth. The promotion ledger's own reconciliation entry
says nothing diffs the recorded heads against a declaration; this is that diff.

**The receipt's descriptor field is recorded and NOT trusted.**
`product_descriptor_sha256` is a literal fixed at authorship naming
`deploy/product.toml` at the revision the run STARTED from, so every descriptor
coordinate in a receipt points backwards. It was tempting to bind on it -- and
measuring the only receipt that exists shows its digest appears nowhere in the
ledger chain at all, so a writer that required the binding could never have run
against a real receipt. It is carried into the entry as provenance, beside the
reason it cannot close the question.

## Exercisable before there is a receipt to run it with

The receipt is a PARAMETER. Every check above is a real comparison against the
document supplied, so the writer runs, refuses and is tested today, with no
deployment and no window. A mechanism whose first execution is inside a window
has never been executed.

## What is derived and what a human must still say

Derived, because a human typing them is where the errors are: the superseded
digest, the candidate digest, `changed_sections` (diffed from the files), and
the carried-forward application half. Stated by a human, because no file knows
them: the promotion `kind`, its `summary`, and why the application half was
carried.

Default is a DRY RUN that prints the entry it would append. `--apply` writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = ROOT / "deploy" / "product.toml"
LEDGER = ROOT / "deploy" / "descriptor-promotions.json"

#: The halves of the descriptor that describe the running APPLICATION. A
#: promotion that does not deploy must carry them across unchanged, and record
#: the values it carried so a later promotion that moves one has to say so.
_ISO_DATE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}$")

APPLICATION_HALF: Final = (
    "image.reference",
    "image.source_revision",
    "assembly.manifest_digest",
)


class PromotionRefusal(StrEnum):
    """Why a promotion was refused, as a value rather than a sentence.

    A caller distinguishing "these bytes are already accepted" from "these bytes
    were accepted once and have since been superseded" by matching prose is one
    rewording away from a test that stops discriminating -- and the ordering
    defect that made the first of those unreachable was found by a regex and
    would have been PINNED by one. The refusals carry codes so a test asserts
    which one answered.
    """

    MISSING_FILE = "MISSING_FILE"
    UNREADABLE = "UNREADABLE"
    BAD_DATE = "BAD_DATE"
    LEDGER_EMPTY = "LEDGER_EMPTY"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    ALREADY_ACCEPTED = "ALREADY_ACCEPTED"
    ALREADY_PROMOTED = "ALREADY_PROMOTED"
    NO_MEASURED_HEADS = "NO_MEASURED_HEADS"
    NO_DECLARED_HEADS = "NO_DECLARED_HEADS"
    HEADS_MISMATCH = "HEADS_MISMATCH"
    NOTHING_CHANGED = "NOTHING_CHANGED"
    CARRY_REASON_MISSING = "CARRY_REASON_MISSING"


class Refused(SystemExit):
    """A promotion that must not be written, and why.

    Carries the machine-readable `refusal`; the message explains it to an
    operator and is not the thing to assert on.
    """

    refusal: PromotionRefusal

    def __init__(self, refusal: PromotionRefusal, reason: str) -> None:
        super().__init__(f"refused[{refusal}]: {reason}")
        self.refusal = refusal


def raw_digest(path: Path) -> str:
    """Raw-BYTES sha256, the convention this ledger and the receipts use.

    Deliberately not the canonical-bytes digest `assembly.manifest_digest` uses.
    Two digest conventions over one file is exactly the confusion that makes a
    chain unverifiable, so the one in use here is named at every call site.
    """
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _document(path: Path, *, what: str) -> dict[str, Any]:
    if not path.is_file():
        raise Refused(
            PromotionRefusal.MISSING_FILE, f"the {what} {path} does not exist"
        )
    try:
        if path.suffix == ".toml":
            return tomllib.loads(path.read_text(encoding="utf-8"))
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
        raise Refused(
            PromotionRefusal.UNREADABLE, f"the {what} {path} is unreadable: {e}"
        ) from e


def _at(document: dict[str, Any], dotted: str) -> object:
    section, _, key = dotted.partition(".")
    block = document.get(section)
    return block.get(key) if isinstance(block, dict) else None


def receipt_heads(receipt: dict[str, Any]) -> tuple[str, ...]:
    """The heads a receipt MEASURED, normalised.

    Written by the bootstrap as `select version_num ... order by 1` joined with
    commas, so it arrives as one string rather than a list. Sorted here because
    a head set is unordered and a promotion must not turn on the order two
    tools happened to emit.
    """
    raw = receipt.get("migration_heads")
    if isinstance(raw, str):
        parts = [item.strip() for item in raw.split(",")]
    elif isinstance(raw, list):
        parts = [str(item).strip() for item in raw]
    else:
        raise Refused(
            PromotionRefusal.NO_MEASURED_HEADS,
            "the receipt records no migration_heads, so it cannot say what the "
            "run produced and cannot license anything",
        )
    heads = tuple(sorted(part for part in parts if part))
    if not heads:
        raise Refused(
            PromotionRefusal.NO_MEASURED_HEADS,
            "the receipt records an empty migration_heads",
        )
    return heads


def declared_heads(descriptor: dict[str, Any]) -> tuple[str, ...]:
    migration = descriptor.get("migration")
    if not isinstance(migration, dict) or not migration.get("expected_heads"):
        raise Refused(
            PromotionRefusal.NO_DECLARED_HEADS,
            "the candidate declares no migration.expected_heads",
        )
    return tuple(sorted(str(h).strip() for h in migration["expected_heads"]))


def changed_sections(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Diffed from the files, never typed.

    `tests/architecture/test_descriptor_promotion.py` checks this claim against
    the candidates in both directions. Deriving it here means the mechanism
    cannot get it wrong in the way a human can, and that test remains the
    independent check -- it still covers the two entries written by hand before
    this script existed, and any entry written after it by anything else.
    """
    return sorted(
        section
        for section in set(before) | set(after)
        if before.get(section) != after.get(section)
    )


def build_entry(
    *,
    candidate: Path,
    receipt_path: Path,
    kind: str,
    summary: str,
    carry_why: str,
    promoted_at: str,
) -> dict[str, Any]:
    if not _ISO_DATE.fullmatch(promoted_at):
        raise Refused(
            PromotionRefusal.BAD_DATE,
            f"--promoted-at {promoted_at!r} is not a YYYY-MM-DD date",
        )
    accepted_doc = _document(ACCEPTED, what="accepted descriptor")
    candidate_doc = _document(candidate, what="candidate descriptor")
    receipt = _document(receipt_path, what="receipt")
    ledger = _document(LEDGER, what="promotion ledger")

    promotions = ledger.get("promotions")
    if not isinstance(promotions, list) or not promotions:
        raise Refused(
            PromotionRefusal.LEDGER_EMPTY, "the promotion ledger holds no promotions"
        )

    superseded = raw_digest(ACCEPTED)
    candidate_digest = raw_digest(candidate)

    if promotions[-1].get("descriptor_sha256") != superseded:
        raise Refused(
            PromotionRefusal.CHAIN_BROKEN,
            "the ledger's last promotion does not name the accepted descriptor "
            "on disk, so the chain is already broken and this would extend it",
        )
    # ORDER IS THE RULE HERE, not a preference. The chain check above
    # guarantees the ledger's last entry names `superseded`, so `superseded` is
    # always IN the ledger -- and with the two checks the other way round,
    # "already promoted" answered every candidate identical to the accepted
    # descriptor and the identity refusal below could never execute. Present in
    # the source, unreachable in the process, and its own test passed because
    # something refused. Specific first.
    if candidate_digest == superseded:
        raise Refused(
            PromotionRefusal.ALREADY_ACCEPTED,
            "the candidate is the accepted descriptor; nothing to promote",
        )
    if any(entry.get("descriptor_sha256") == candidate_digest for entry in promotions):
        raise Refused(
            PromotionRefusal.ALREADY_PROMOTED,
            "these exact bytes have been promoted before, and are not what is "
            "accepted now -- promoting them again would record a change that "
            "already happened",
        )

    # THE LICENCE. Everything else checks the chain; this checks the deployment.
    measured = receipt_heads(receipt)
    declared = declared_heads(candidate_doc)
    if measured != declared:
        raise Refused(
            PromotionRefusal.HEADS_MISMATCH,
            "the receipt measured heads the candidate does not declare -- "
            f"receipt {list(measured)}, candidate {list(declared)}. A candidate "
            "that does not describe what the run produced must not become "
            "accepted truth",
        )

    sections = changed_sections(accepted_doc, candidate_doc)
    if not sections:
        raise Refused(
            PromotionRefusal.NOTHING_CHANGED, "the candidate changes no section"
        )

    # A key that MOVED is simply absent from `carried_forward`; there is no
    # refusal for "moved but its section was not declared", because
    # `changed_sections` is derived from the same two documents a line above --
    # if a key moved, its section differs, so it is in `sections` by
    # construction. A branch for it would read like a guard and could never
    # execute, which is the shape this repository has already paid to remove
    # once. The independent check on that claim is the promotion test, which
    # compares declared against actual over the committed ledger.
    carried: dict[str, Any] = {
        dotted: _at(accepted_doc, dotted)
        for dotted in APPLICATION_HALF
        if _at(accepted_doc, dotted) == _at(candidate_doc, dotted)
    }
    if carried and not carry_why:
        entry_keys = ", ".join(sorted(carried))
        raise Refused(
            PromotionRefusal.CARRY_REASON_MISSING,
            f"this promotion carries {entry_keys} across unchanged and no "
            "--carry-why says why the application half did not move",
        )

    entry: dict[str, Any] = {
        "promoted_at": promoted_at,
        "kind": kind,
        "candidate": candidate.relative_to(ROOT).as_posix(),
        "descriptor_sha256": candidate_digest,
        "summary": summary,
        "supersedes": superseded,
        "changed_sections": sections,
        "licensed_by": {
            "receipt_sha256": raw_digest(receipt_path),
            "measured_migration_heads": list(measured),
            "receipt_bound_descriptor_sha256": receipt.get("product_descriptor_sha256"),
            "why_the_bound_descriptor_is_not_the_binding": (
                "product_descriptor_sha256 is a literal fixed at authorship "
                "naming deploy/product.toml at the revision the run STARTED "
                "from, so it points backwards and its digest need not appear in "
                "this chain at all. The licence is the measured heads above, "
                "compared with the candidate's declaration."
            ),
        },
    }
    if carried:
        entry["carried_forward"] = {"why": carry_why, **carried}
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--carry-why", default="")
    parser.add_argument(
        "--promoted-at",
        required=True,
        help="ISO date (YYYY-MM-DD). Stated rather than read out of the receipt: "
        "receipt date fields have not been measured across the kinds of receipt "
        "this will meet, and guessing one writes a wrong date into an "
        "append-only ledger",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the ledger and copy the candidate over the accepted file",
    )
    args = parser.parse_args(argv)

    candidate = args.candidate.resolve()
    entry = build_entry(
        candidate=candidate,
        receipt_path=args.receipt.resolve(),
        kind=args.kind,
        summary=args.summary,
        carry_why=args.carry_why,
        promoted_at=args.promoted_at,
    )
    print(json.dumps(entry, indent=2, sort_keys=True))
    if not args.apply:
        print("\ndry run: nothing written. Re-run with --apply.", file=sys.stderr)
        return 0

    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    ledger["promotions"].append(entry)
    LEDGER.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(candidate, ACCEPTED)
    print(f"\npromoted {entry['candidate']} -> deploy/product.toml", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
