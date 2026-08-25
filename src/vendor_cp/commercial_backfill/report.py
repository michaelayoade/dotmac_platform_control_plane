"""Report types whose alphabet is finite, and a renderer that proves it.

The hard constraint on this work: **no backfill report may emit an identifier,
an amount, a label or a timestamp.** Counts, categories and blocker reasons
only.

That is enforced structurally rather than by review discipline, in three layers.
Each is weaker than the next is strong, and they are stacked because the first
two are about what a report CAN hold and the third is about what actually left.

1. **A report holds only two kinds of value.** A `Count`, which is a
   cardinality, and a member of a `ReportEnum`, which is one of a fixed set of
   names declared in `vocabulary.py`. `Tally` validates every key against
   `TALLY_DOMAIN`, so a tally cannot hold a stray object, a string, or a member
   of the wrong domain. There is no field anywhere in this module annotated
   `str`, `Decimal`, `datetime` or `UUID`, and
   `tests/architecture/test_commercial_backfill.py` scans the annotations to
   keep it that way.

2. **Counts are cardinalities, obtained by counting.** `tally()` takes an
   ITERABLE OF MEMBERS and counts them; the planner and the comparator never
   construct a `Count` at all, and an architecture ratchet holds `Count(` to
   this module. `counted()` is the one place an externally observed cardinality
   enters, and it exists because a target observation arrives already reduced to
   counts — Vendor never receives target rows, which is what keeps this a
   description of a transformation rather than a second copy of the target's
   data.

3. **The render is checked against the vocabulary.** `render()` tokenises what
   it produced and refuses anything that is not a declared member name, a
   declared subject name, or a decimal integer. Given layers 1 and 2 this is
   redundant — which is the point: it converts "the types make it impossible"
   from an argument into a check, and it is what a sensitivity test can plant an
   identifier against.

## What layer 2 does NOT claim

A caller of `counted()` could pass an amount in minor units where a row count
belongs. Nothing here can tell those apart — an integer is an integer. The
guarantee is that a report's ALPHABET is closed, not that every integer in it is
meaningful; a misused count is a wrong report, not a leaked value. Recorded as
weaker rather than described as a seal it is not.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from vendor_cp.commercial_backfill.vocabulary import (
    REPORT_ENUMS,
    TALLY_DOMAIN,
    ParitySubject,
    ParityVerdict,
    ReportEnum,
    TallySubject,
)


class UnsafeReportValue(ValueError):
    """Raised when a value outside the closed vocabulary reaches a report.

    FAIL CLOSED, always. There is no tolerant path and no sanitising path: a
    value that had to be scrubbed to be reportable is a value whose provenance
    is unknown, and scrubbing it is how an identifier survives as a suffix.
    """


@dataclass(frozen=True, slots=True, order=True)
class Count:
    """A cardinality. Non-negative, and never a bool.

    `bool` is rejected explicitly because `isinstance(True, int)` is true in
    Python, and a report that rendered `True` as `1` would be answering a
    different question than the one it was asked.
    """

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise UnsafeReportValue("a count is an int")
        if self.value < 0:
            raise UnsafeReportValue("a count is never negative")

    def __add__(self, other: Count) -> Count:
        return Count(self.value + other.value)


ZERO: Final[Count] = Count(0)


def counted(value: int) -> Count:
    """The one entry for a cardinality observed OUTSIDE this assembly.

    Used by `TargetObservation`, whose counts are read from the target's own
    versioned API by an operator and arrive already reduced. Kept here rather
    than in the comparator so the `Count(` ratchet stays confined to one file.
    """
    return Count(value)


@dataclass(frozen=True, slots=True)
class Tally:
    """A histogram over ONE closed enum domain.

    This is the whole no-emission property in one type. The keys come from a
    fixed set declared in `vocabulary.py`; the values are cardinalities of the
    input. A histogram over a closed domain has nowhere to put an identifier, an
    amount, a label or a timestamp — there is no free slot.
    """

    subject: TallySubject
    counts: tuple[tuple[ReportEnum, Count], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.subject, TallySubject):
            raise UnsafeReportValue("a tally subject is a TallySubject member")
        domain = TALLY_DOMAIN[self.subject]
        seen: set[ReportEnum] = set()
        for member, count in self.counts:
            if not isinstance(member, domain):
                raise UnsafeReportValue(
                    f"{self.subject.name} tallies {domain.__name__} members only"
                )
            if not isinstance(count, Count):
                raise UnsafeReportValue("a tally value is a Count")
            if member in seen:
                raise UnsafeReportValue("a tally names each member once")
            seen.add(member)

    def total(self) -> Count:
        """The number of inputs this tally counted."""
        result = ZERO
        for _, count in self.counts:
            result = result + count
        return result

    def nonzero(self) -> tuple[tuple[ReportEnum, Count], ...]:
        """The counts, with explicit zeroes dropped.

        Two tallies that differ only in whether a category was written down as
        zero or left out are the same histogram, and a comparison that called
        them different would report a reporting style as a divergence.
        """
        return tuple((m, c) for m, c in self.counts if c.value)

    def of(self, member: ReportEnum) -> Count:
        """This member's count, or zero. Never a `KeyError`: an absent category
        genuinely counted nothing, and making the caller branch on that is how a
        totality check ends up with a hole in it."""
        for candidate, count in self.counts:
            if candidate is member:
                return count
        return ZERO


def tally(subject: TallySubject, members: Iterable[ReportEnum]) -> Tally:
    """Count `members`, in the declared order of their domain.

    Ordering by the DOMAIN rather than by first appearance is deliberate: two
    runs over the same rows in a different order must render identically, or a
    reviewer diffing two reports reads a reordering as a change.
    """
    domain = TALLY_DOMAIN[subject]
    tallied = list(members)
    if any(not isinstance(candidate, domain) for candidate in tallied):
        raise UnsafeReportValue(
            f"{subject.name} tallies {domain.__name__} members only"
        )
    counts: list[tuple[ReportEnum, Count]] = []
    for member in domain:
        hits = [candidate for candidate in tallied if candidate is member]
        if hits:
            counts.append((member, Count(len(hits))))
    return Tally(subject=subject, counts=tuple(counts))


def counted_tally(subject: TallySubject, counts: Mapping[ReportEnum, int]) -> Tally:
    """A tally from cardinalities observed outside this assembly.

    Same validation as `tally`, different input: the caller has already counted.
    See the module docstring for what this does and does not guarantee.
    """
    domain = TALLY_DOMAIN[subject]
    return Tally(
        subject=subject,
        counts=tuple(
            (member, counted(counts[member])) for member in domain if member in counts
        ),
    )


@dataclass(frozen=True, slots=True)
class ParityLine:
    """One parity claim: which claim, and how it came out.

    `ROW_COUNT` and `TARGET_SEMANTIC` are separate lines rather than one
    combined verdict, because they are separate claims and collapsing them lets
    a matching count vouch for a meaning nobody checked.
    """

    subject: ParitySubject
    verdict: ParityVerdict

    def __post_init__(self) -> None:
        if not isinstance(self.subject, ParitySubject):
            raise UnsafeReportValue("a parity subject is a ParitySubject member")
        if not isinstance(self.verdict, ParityVerdict):
            raise UnsafeReportValue("a parity verdict is a ParityVerdict member")


@dataclass(frozen=True, slots=True)
class Report:
    """A whole report: parity lines and tallies, and nothing else.

    Deliberately has no title, no note field and no free-text slot of any kind.
    A `note: str` would be the single field through which every value this type
    exists to exclude could travel, and it would be added for the best of
    reasons on the first day someone wanted context.
    """

    parity: tuple[ParityLine, ...]
    tallies: tuple[Tally, ...]

    def __post_init__(self) -> None:
        for line in self.parity:
            if not isinstance(line, ParityLine):
                raise UnsafeReportValue("a report's parity holds ParityLine only")
        subjects: set[TallySubject] = set()
        for item in self.tallies:
            if not isinstance(item, Tally):
                raise UnsafeReportValue("a report's tallies hold Tally only")
            if item.subject in subjects:
                raise UnsafeReportValue("a report names each tally subject once")
            subjects.add(item.subject)

    def tally_for(self, subject: TallySubject) -> Tally:
        """The tally for `subject`, or an empty one for the same subject."""
        for item in self.tallies:
            if item.subject is subject:
                return item
        return Tally(subject=subject, counts=())


# ── Rendering, and the egress check that proves the alphabet is closed ─────


#: Every word a rendered report is allowed to contain. Derived from the declared
#: enums rather than listed, so a category added to `vocabulary.py` is renderable
#: and one that is not declared there is not.
def render_vocabulary() -> frozenset[str]:
    words = {subject.name for subject in TallySubject}
    words.update(subject.name for subject in ParitySubject)
    for enum_type in REPORT_ENUMS:
        words.update(member.name for member in enum_type)
    return frozenset(words)


#: A rendered line is one or two declared NAMES and at most one integer. The
#: grammar matters as much as the vocabulary: a token-wise check passes
#: `2026-08-25` because a date is three integers, and a timestamp is exactly one
#: of the four things a report may never emit. Checking the LINE shape refuses
#: it, because a report line never carries three numbers.
_LINE = re.compile(r"[A-Z][A-Z_]*(?: [A-Z][A-Z_]*)(?: [0-9]+)?")
_NAME = re.compile(r"[A-Z][A-Z_]*")


def render(report: Report) -> str:
    """Render, then CHECK what was rendered.

    The check is redundant given the types — and that is exactly why it is here.
    It turns the structural claim into an executable one, and gives a
    sensitivity test something to plant an identifier, an amount, a label and a
    timestamp against.
    """
    lines = [f"{line.subject.name} {line.verdict.name}" for line in report.parity]
    for item in report.tallies:
        for member, count in item.counts:
            lines.append(f"{item.subject.name} {member.name} {count.value}")
    text = "\n".join(lines)
    refuse_unless_in_vocabulary(text)
    return text


def refuse_unless_in_vocabulary(text: str) -> None:
    """Raise unless every LINE matches the grammar and names declared members.

    Two conditions, and both are load-bearing. The grammar bounds the shape of a
    line — two names and at most one number — and the vocabulary bounds which
    names. Dropping either one lets something through: without the grammar a
    timestamp passes as a run of integers, and without the vocabulary any
    upper-case token does.

    The refusal deliberately reports HOW MANY lines were refused and not WHICH.
    An exception message is an emission too, and quoting the offending line
    would put the value into a log, which is the one place a scrubbed report is
    most likely to be read.
    """
    allowed = render_vocabulary()
    refused = 0
    for line in text.splitlines():
        if not line:
            continue
        if not _LINE.fullmatch(line):
            refused += 1
            continue
        if any(name not in allowed for name in _NAME.findall(line)):
            refused += 1
    if refused:
        raise UnsafeReportValue(f"{refused} line(s) outside the report vocabulary")


__all__ = [
    "ZERO",
    "Count",
    "ParityLine",
    "Report",
    "Tally",
    "UnsafeReportValue",
    "counted",
    "counted_tally",
    "refuse_unless_in_vocabulary",
    "render",
    "render_vocabulary",
    "tally",
]
