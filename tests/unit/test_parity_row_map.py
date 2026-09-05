"""The row-by-row half of Foundation's § 11 parity map, held to the fixtures.

Foundation's map is two-directional and declined to COPY these rows, on the
grounds that a copy is a second authority that drifts. That is right, and it
leaves Platform holding the join: `docs/inventories/platform-parity-row-map.json`
is the Platform-owned half, keyed by stable identifiers, and Foundation joins on
it rather than restating it.

A map that has drifted from the fixtures it claims to describe is worse than no
map, because the successor is measured against it and the drift is invisible
from the other repository. So every claim in the JSON is checked here against
the matrix, in both directions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from profile_refusal_matrix import (
    BUILDER_CASES,
    FOUNDATION_ADDED_CASES,
    FOUNDATION_REFUSAL_CODES,
    FROZEN_ROW_IDS,
    RETIRED_ROW_IDS,
    ROW_IDS,
    TYPE_BOUNDARY_CASES,
    UNMAPPED_ROWS_BLOCKING_DELETION,
    VERIFIER_CASES,
    all_case_names,
)

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "docs" / "inventories" / "platform-parity-row-map.json"
COMPANION = ROOT / "docs" / "inventories" / "foundation-parity-row-map-2026-09-05.md"

MAP_STATES = frozenset({"mapped", "migrates", "retires", "unmapped"})
ADDED_KINDS = frozenset({"no_counterpart", "has_counterpart", "approximated"})
ROW_ID = re.compile(r"^PCP-[VBT]-\d{2}$")


def _map() -> dict[str, object]:
    return json.loads(MAP.read_text(encoding="utf-8"))


# ── stable identity ─────────────────────────────────────────────────────────


def test_every_row_has_an_identifier_and_every_identifier_has_a_row() -> None:
    """Both directions. A row added without an identifier cannot be joined on
    from another repository; an identifier with no row is a foreign reference
    pointing at nothing."""
    assert set(ROW_IDS) == set(all_case_names())
    assert tuple(sorted(ROW_IDS.values())) == tuple(sorted(FROZEN_ROW_IDS))
    assert len(FROZEN_ROW_IDS) == len(set(FROZEN_ROW_IDS))


def test_identifiers_are_well_formed_contiguous_and_never_reused() -> None:
    """An ordinal allocated twice would silently re-point a reference in another
    repository at a different property, and nothing on that side would notice."""
    assert all(ROW_ID.match(row_id) for row_id in FROZEN_ROW_IDS), FROZEN_ROW_IDS
    for prefix, cases in (
        ("V", VERIFIER_CASES),
        ("B", BUILDER_CASES),
        ("T", TYPE_BOUNDARY_CASES),
    ):
        expected = tuple(
            f"PCP-{prefix}-{index:02d}" for index in range(1, len(cases) + 1)
        )
        actual = tuple(
            row_id for row_id in FROZEN_ROW_IDS if row_id.startswith(f"PCP-{prefix}-")
        )
        assert actual == expected, (prefix, actual)
    assert not set(FROZEN_ROW_IDS) & RETIRED_ROW_IDS


def test_the_identifier_set_is_stated_twice_and_the_two_must_agree() -> None:
    """`FROZEN_ROW_IDS` is written out rather than derived from `ROW_IDS`.

    Deriving it would make this check a statement that one dict agrees with
    itself, and the whole point of a frozen set is that a row cannot move
    without an explicit edit on this side.
    """
    derived = {ROW_IDS[case] for case in all_case_names()}
    assert derived == set(FROZEN_ROW_IDS)


# ── the map agrees with the fixtures ────────────────────────────────────────


def test_the_map_covers_every_row_exactly_once() -> None:
    document = _map()
    rows = document["rows"]
    assert isinstance(rows, list)
    ids = [row["row_id"] for row in rows]
    assert len(ids) == len(set(ids))
    assert set(ids) == set(FROZEN_ROW_IDS)
    assert document["legacy_total"] == len(FROZEN_ROW_IDS)


def test_every_mapped_row_describes_the_fixture_it_claims_to() -> None:
    """The identifier, the case name and the surface must agree with the matrix.

    A map row that named the right identifier and the wrong case would join
    correctly and mean something else.
    """
    surfaces = {case.case: "verifier" for case in VERIFIER_CASES}
    surfaces.update({case.case: "builder" for case in BUILDER_CASES})
    surfaces.update({name: "type_boundary" for name, _f, _w in TYPE_BOUNDARY_CASES})

    for row in _map()["rows"]:
        case = row["case"]
        assert ROW_IDS[case] == row["row_id"], case
        assert surfaces[case] == row["surface"], case


def test_every_map_state_is_from_the_closed_set() -> None:
    for row in _map()["rows"]:
        assert row["map_state"] in MAP_STATES, row


def test_no_map_row_invents_a_foundation_code() -> None:
    """A code that is not in Foundation's closed vocabulary joins against
    nothing, and a typo in this file is invisible from the other repository."""
    for row in _map()["rows"]:
        code = row["foundation_code"]
        if code:
            assert code in FOUNDATION_REFUSAL_CODES, row


def test_an_unmapped_row_names_no_code_and_a_mapped_row_names_a_reference() -> None:
    """`unmapped` means exactly that: no code AND no stated mechanism. A row
    carrying a code while claiming to be unmapped would understate the gate."""
    for row in _map()["rows"]:
        if row["map_state"] == "unmapped":
            assert not row["foundation_code"], row
        else:
            assert row["foundation_reference"], row
        assert row["note"].strip(), row


# ── the gate ────────────────────────────────────────────────────────────────


def test_the_rows_that_block_deletion_are_frozen_in_both_directions() -> None:
    """THE GATE. An unmapped row blocks deletion of this dialect.

    Closing one requires lowering the declared tuple in the same change, and a
    row that quietly became unmapped fails rather than reading as a gap that was
    always there. A count that can move on its own is not a gate.
    """
    observed = tuple(
        row["row_id"] for row in _map()["rows"] if row["map_state"] == "unmapped"
    )
    assert observed == UNMAPPED_ROWS_BLOCKING_DELETION, observed


def test_nothing_has_been_deleted_while_the_gate_is_open() -> None:
    """The hard constraint on this lane, made checkable beside the fixtures.

    The dialect comes out only when the generic replacement goes in, in one
    composed change. While any row is unmapped, both modules must still be here.
    """
    if UNMAPPED_ROWS_BLOCKING_DELETION:
        assert (ROOT / "src" / "vendor_cp" / "deployment" / "profile.py").exists()
        assert (
            ROOT / "src" / "vendor_cp" / "deployment" / "profile_readback.py"
        ).exists()


# ── the ceiling: what the successor adds ────────────────────────────────────


def test_the_added_cases_are_the_nine_foundation_declares() -> None:
    """EIGHT was the count in the brief handed to this lane, and it omitted
    `answers_everything` — the refusal revision 2 exists to add. Held as nine,
    because a two-directional map cannot be built on a count that is wrong on
    either side."""
    added = _map()["added"]
    assert [entry["case"] for entry in added] == list(FOUNDATION_ADDED_CASES)
    assert len(added) == 9


def test_every_added_case_says_whether_a_legacy_row_exists() -> None:
    """The second list is the evidence the successor is STRONGER, and it is
    worth as much as the first. A case claiming a legacy counterpart must name a
    real row; one claiming none must name nothing."""
    for entry in _map()["added"]:
        assert entry["legacy"] in ADDED_KINDS, entry
        if entry["legacy"] == "no_counterpart":
            assert not entry["legacy_row"], entry
        else:
            assert entry["legacy_row"] in ROW_IDS, entry
        assert entry["note"].strip(), entry


def test_the_cases_with_no_counterpart_are_the_ones_the_dialect_cannot_state() -> None:
    """Not a judgement call: each names a fact Platform's dialect has no place
    to put. It collapses provider, binding and verification into one declaration
    plus an import probe, so an injection site, a battery outcome, a second
    assembly and a retirement round trip are all unstateable."""
    without = {
        entry["case"]
        for entry in _map()["added"]
        if entry["legacy"] == "no_counterpart"
    }
    assert without == {
        "wrong_site",
        "nonce_only",
        "all_negative",
        "answers_everything",
        "wrong_assembly",
        "retirement_round_trip",
    }


def test_two_added_cases_are_not_actually_new_and_the_map_says_so() -> None:
    """`foreign_inventory` and `unknown_key` both have legacy rows. Recording it
    keeps the added list from overstating what the successor gains, which is the
    same discipline the unmapped list applies in the other direction."""
    with_legacy = {
        entry["case"]: entry["legacy_row"]
        for entry in _map()["added"]
        if entry["legacy"] == "has_counterpart"
    }
    assert set(with_legacy) == {"foreign_inventory", "unknown_key"}
    for row_id in with_legacy.values():
        assert row_id in ROW_IDS


# ── the companion document ──────────────────────────────────────────────────


def test_the_companion_names_every_row_and_invents_none() -> None:
    text = COMPANION.read_text(encoding="utf-8")
    missing = [row_id for row_id in FROZEN_ROW_IDS if row_id not in text]
    assert not missing, missing
    quoted = set(ROW_ID.findall(text)) | {
        token for token in re.findall(r"PCP-[VBT]-\d{2}", text)
    }
    assert quoted <= set(FROZEN_ROW_IDS), sorted(quoted - set(FROZEN_ROW_IDS))


def test_the_companion_states_the_gate() -> None:
    text = COMPANION.read_text(encoding="utf-8")
    for row_id in UNMAPPED_ROWS_BLOCKING_DELETION:
        assert row_id in text
    assert "blocks deletion" in text.lower()
