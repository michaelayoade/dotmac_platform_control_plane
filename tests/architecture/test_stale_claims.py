"""Canonical prose may not outlive the phase it describes.

Every phase of the approvals work left true sentences behind that the next phase
made false: "the selection tuple is empty", "do not compose or pin
`dotmac-approvals`", "four lineages". None of them broke anything, and that is
the problem — a document that confidently states last month's arrangement is
worse than one that says nothing, because a reader trusts it.

So the claims are checked against COMPUTED FACT rather than against a list of
today's stale sentences. A guard that greps for the sentences currently wrong
passes forever once they are edited, and catches nothing at the next transition:
it is a changelog wearing a test's clothes.

Two derivations do the work:

* the composed lineage COUNT comes from `composed_version_locations()`, so every
  stated count is compared against what the assembly actually composes;
* the "nothing is selected" and "do not pin approvals" claims are gated on
  `ASSEMBLY_MODULE_PLANES` being empty and on the pin being absent. While those
  facts hold, the sentences are required to exist; the moment they stop holding,
  the same sentences are forbidden.

That second shape is the important one. It is not "these words are banned" — it
is "this claim is allowed exactly while it is true", which keeps working through
transitions nobody has thought of yet.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from vendor_cp.migration_bindings import ASSEMBLY_MODULE_PLANES
from vendor_cp.migrations import composed_version_locations

ROOT = Path(__file__).resolve().parents[2]

#: Where canonical claims live. Prose elsewhere is UNMONITORED rather than
#: exempt (ADR-0018): these are the files a reader treats as authoritative.
PROSE_ROOTS = ("AGENTS.md", "README.md", "docs", "src", "alembic", "scripts")
PROSE_SUFFIXES = frozenset({".md", ".py"})

NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}

_COUNT = r"(one|two|three|four|five|six|seven|eight|nine|ten|\d+)"

#: "five lineages", "five-lineage", "five separately-owned lineages".
LINEAGE_CLAIM = re.compile(
    rf"\b{_COUNT}\b(?:[ -][\w'-]+){{0,2}}[ -]lineages?\b", re.IGNORECASE
)

#: `lineage` is also a DOMAIN word here — a licence lineage, a revocation
#: lineage — so a count near it means nothing unless the sentence is about
#: migrations. Requiring a signal in context is what keeps this derived rather
#: than needing a hand-maintained list of files to skip.
MIGRATION_SIGNALS = (
    "migrat",
    "composed",
    "composes",
    "alembic",
    "revision",
    "version_locations",
)
CONTEXT_WINDOW = 120

#: Claims that are true only while no selectable module is selected.
EMPTY_SELECTION_CLAIMS = (
    "no selectable module is composed",
    "the selection tuple is legitimately empty",
    "it is EMPTY until a selectable module is composed",
    "empty**, because no selectable module is composed",
)

#: Claims that are true only while the module is unpinned.
UNPINNED_CLAIMS = (
    "do not compose, pin or plane-select `dotmac-approvals`",
    "It is **not composed here**",
    "authorises no composition",
    "Blocks:** shadow composition",
)


def _prose_files() -> list[Path]:
    files: list[Path] = []
    for root in PROSE_ROOTS:
        path = ROOT / root
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.suffix in PROSE_SUFFIXES
                and "__pycache__" not in candidate.parts
            )
    return files


def _flattened(path: Path) -> str:
    """Whitespace collapsed, so a claim wrapped across lines is still one
    claim. Every earlier prose guard in this repo learned that the hard way."""
    return " ".join(path.read_text().split())


def stated_lineage_counts(text: str) -> list[int]:
    """Every MIGRATION lineage count a piece of prose states."""
    counts: list[int] = []
    for match in LINEAGE_CLAIM.finditer(text):
        window = text[
            max(0, match.start() - CONTEXT_WINDOW) : match.end() + CONTEXT_WINDOW
        ].lower()
        if not any(signal in window for signal in MIGRATION_SIGNALS):
            continue
        token = match.group(1).lower()
        counts.append(NUMBER_WORDS.get(token, int(token) if token.isdigit() else 0))
    return counts


def _approvals_is_pinned() -> bool:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return "dotmac-approvals" in config["tool"]["poetry"]["dependencies"]


# ── Derived claim: how many lineages this assembly composes ─────────────────


def test_every_stated_lineage_count_matches_what_is_composed() -> None:
    """Derived from `composed_version_locations()`, so composing a sixth lineage
    fails every document that still says five — including ones nobody thought to
    grep."""
    expected = len(composed_version_locations().split())
    wrong = [
        f"{path.relative_to(ROOT)}: says {count}, composes {expected}"
        for path in _prose_files()
        for count in stated_lineage_counts(_flattened(path))
        if count != expected
    ]
    assert not wrong, wrong


def test_the_lineage_claim_detector_is_not_vacuous() -> None:
    """NON-VACUITY. The assertion above is "no wrong counts", which an empty
    scan satisfies. Some document must actually state the count."""
    stated = [
        count
        for path in _prose_files()
        for count in stated_lineage_counts(_flattened(path))
    ]
    assert stated, "no document states a composed lineage count at all"
    assert len(stated) >= 3


@pytest.mark.parametrize(
    ("text", "found"),
    [
        pytest.param(
            "one revision graph, four separately-owned lineages, composed here",
            [4],
            id="hyphenated-adjective",
        ),
        pytest.param("runs the four-lineage migrate script", [4], id="compound"),
        pytest.param("composes all four lineages;", [4], id="plain"),
        pytest.param(
            "one licence lineage per customer, appended on revocation",
            [],
            id="domain-word-not-migrations",
        ),
        pytest.param(
            "Kernel, three independent modules and vendor migration lineages",
            [],
            id="counts-modules-not-lineages",
        ),
    ],
)
def test_the_lineage_claim_detector_sees_what_it_should(
    text: str, found: list[int]
) -> None:
    """SENSITIVITY, one case per phrasing the repo actually uses — plus the two
    ways a naive version misfires: `lineage` as a licence-domain word, and a
    count that belongs to MODULES rather than lineages."""
    assert stated_lineage_counts(text) == found


# ── Gated claims: true exactly while the fact they assert holds ─────────────


def test_no_empty_selection_claim_survives_a_non_empty_selection() -> None:
    """The claim is allowed exactly while it is true.

    Not a banned-words list: if `ASSEMBLY_MODULE_PLANES` were emptied again by a
    later phase, these sentences would become correct and permitted once more.
    """
    prose = {path: _flattened(path) for path in _prose_files()}
    offenders = [
        f"{path.relative_to(ROOT)}: {claim!r}"
        for path, text in prose.items()
        for claim in EMPTY_SELECTION_CLAIMS
        if claim in text
    ]
    if ASSEMBLY_MODULE_PLANES:
        assert not offenders, (
            "these documents say nothing is plane-selected, but "
            f"{[s.module for s in ASSEMBLY_MODULE_PLANES]} is: {offenders}"
        )
    else:
        assert offenders, (
            "no selection is declared and no document says so — the guard has "
            "nothing to hold, and the next phase gets no warning"
        )


def test_no_unpinned_claim_survives_a_pinned_module() -> None:
    """Same shape, on the pin."""
    prose = {path: _flattened(path) for path in _prose_files()}
    offenders = [
        f"{path.relative_to(ROOT)}: {claim!r}"
        for path, text in prose.items()
        for claim in UNPINNED_CLAIMS
        if claim in text
    ]
    if _approvals_is_pinned():
        assert not offenders, (
            "`dotmac-approvals` is pinned, but these documents still forbid or "
            f"deny it: {offenders}"
        )
    else:
        assert offenders, "the module is unpinned and no document says so"


def test_the_gated_claim_detector_would_catch_a_planted_claim(
    tmp_path: Path,
) -> None:
    """SENSITIVITY for both gated guards.

    Both assert "no offenders" while the facts hold, which a reader that finds
    nothing would also satisfy. So plant each claim in a file and prove the same
    matcher reports it.
    """
    planted = tmp_path / "stale.md"
    for claim in (*EMPTY_SELECTION_CLAIMS, *UNPINNED_CLAIMS):
        planted.write_text(f"Some context.\n{claim}\nMore context.\n")
        assert claim in _flattened(planted), claim

    planted.write_text("nothing stale here at all\n")
    assert not any(
        claim in _flattened(planted)
        for claim in (*EMPTY_SELECTION_CLAIMS, *UNPINNED_CLAIMS)
    )


def test_the_gated_claims_are_declared_and_non_empty() -> None:
    """A gate over an empty claim list passes for the wrong reason forever."""
    assert EMPTY_SELECTION_CLAIMS
    assert UNPINNED_CLAIMS
    assert len(_prose_files()) > 30, "the prose sweep found almost no files"
