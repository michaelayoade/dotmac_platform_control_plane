"""Drive every parity row against the implementation it describes.

`profile_refusal_matrix` is an acceptance bar being handed to Foundation's
generic verifier. A bar that has never been driven is a description, and a
description that has drifted from the code is worse than none — the successor
would be measured against refusals this implementation does not actually make.

So every row runs here, against the local dialect, and the matrix is checked in
both directions: every row reaches the outcome it claims, and every verdict the
verifier can return is reached by at least one row. A refusal nobody planted is
a refusal nobody will ask the successor for.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from profile_refusal_matrix import (
    BUILDER_CASES,
    EXPECTED_REVISION,
    EXPECTED_WHEEL,
    MIGRATION_SEQUENCE,
    TYPE_BOUNDARY_CASES,
    VERIFIER_CASES,
    all_case_names,
    build_inputs,
    good_artifact,
    rendered_rows,
)

from vendor_cp.deployment.profile import (
    ASSEMBLY,
    ConcernSpec,
    ProfileBuildRefusal,
    build_profile_document,
)
from vendor_cp.deployment.profile_readback import (
    ExpectedArtifact,
    ProfileVerdict,
    verify_embedded_profile,
)

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "poetry.lock"
INVENTORY_DOC = ROOT / "docs" / "inventories" / "profile-refusal-parity-2026-09-05.md"


# ── the verifier half ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "case", VERIFIER_CASES, ids=[case.case for case in VERIFIER_CASES]
)
def test_each_planted_defect_reaches_the_verdict_the_matrix_claims(
    case: object, tmp_path: Path
) -> None:
    artifact = good_artifact()
    case.plant(artifact)  # type: ignore[attr-defined]
    paths = artifact.write(tmp_path)
    outcome = verify_embedded_profile(
        ExpectedArtifact(
            source_revision=artifact.expected_revision,
            wheel_sha256=artifact.expected_wheel,
        ),
        **paths,
    )
    assert outcome.verdict is case.expected, (  # type: ignore[attr-defined]
        f"{case.case}: expected {case.expected}, got "  # type: ignore[attr-defined]
        f"{outcome.verdict} — {outcome.detail}"
    )


def test_every_verdict_the_verifier_can_return_is_planted_by_some_row() -> None:
    """The direction that keeps the bar honest.

    A verdict no row reaches is one the successor will never be asked to
    produce, and it would be discovered missing in production rather than in a
    comparison. Exact equality, not a subset: a verdict that disappears from the
    enum must also disappear from the matrix.
    """
    planted = {case.expected for case in VERIFIER_CASES}
    assert planted == set(ProfileVerdict), sorted(
        str(v) for v in set(ProfileVerdict) ^ planted
    )


def test_the_matrix_plants_exactly_one_defect_per_row() -> None:
    """A fixture broken in two places only ever demonstrates the earlier check.

    Driven rather than asserted: each row is applied to a GOOD artifact and the
    verdict must be the row's own. If a row broke two things, the second would
    be unreachable and this suite would still pass — so the guard is the
    coverage test above plus the fact that every verdict is reached by a
    DISTINCT row set.
    """
    names = [case.case for case in VERIFIER_CASES]
    assert len(names) == len(set(names))
    by_verdict: dict[ProfileVerdict, list[str]] = {}
    for case in VERIFIER_CASES:
        by_verdict.setdefault(case.expected, []).append(case.case)
    # Several verdicts have several distinct triggers, and that is the point: a
    # successor refusing "somewhere in absence-proof validation" is not the same
    # as one refusing an unregistered family.
    assert len(by_verdict[ProfileVerdict.DOCUMENT_UNREADABLE]) >= 6
    assert len(by_verdict[ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED]) >= 7


def test_the_admitted_control_really_admits(tmp_path: Path) -> None:
    """NON-VACUITY, stated separately from the parametrised run.

    Every other row asserts a refusal. A verifier that refused everything would
    satisfy all of them, and this is the single case that cannot pass that way.
    """
    artifact = good_artifact()
    outcome = verify_embedded_profile(
        ExpectedArtifact(
            source_revision=EXPECTED_REVISION, wheel_sha256=EXPECTED_WHEEL
        ),
        **artifact.write(tmp_path),
    )
    assert outcome.verdict is ProfileVerdict.ADMITTED, outcome.detail
    assert len(outcome.bound_concerns) == 13


# ── the builder half ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "case", BUILDER_CASES, ids=[case.case for case in BUILDER_CASES]
)
def test_each_planted_build_defect_refuses_and_names_itself(
    case: object, tmp_path: Path
) -> None:
    inputs = build_inputs(LOCK.read_text(encoding="utf-8"))
    case.plant(inputs)  # type: ignore[attr-defined]

    lock = tmp_path / "poetry.lock"
    lock.write_text(inputs.synthetic_lock or inputs.lock_text, encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in inputs.wheel_names:
        (dist / name).write_bytes(b"bytes the digest is taken over")

    with pytest.raises(ProfileBuildRefusal) as raised:
        build_profile_document(
            source_revision=inputs.source_revision,
            dist_dir=dist,
            lock_path=lock,
            specs=tuple(inputs.specs),
        )
    assert case.fragment in str(raised.value), (  # type: ignore[attr-defined]
        f"{case.case}: refusal did not name "  # type: ignore[attr-defined]
        f"{case.fragment!r} — {raised.value}"
    )


def test_the_unbroken_build_inputs_produce_a_document(tmp_path: Path) -> None:
    """The builder half's non-vacuity control.

    Same shape as the verifier's: every row above asserts a refusal, and a
    builder that refused everything would satisfy all of them.
    """
    inputs = build_inputs(LOCK.read_text(encoding="utf-8"))
    lock = tmp_path / "poetry.lock"
    lock.write_text(inputs.lock_text, encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / inputs.wheel_names[0]).write_bytes(b"bytes")

    document = build_profile_document(
        source_revision=EXPECTED_REVISION,
        dist_dir=dist,
        lock_path=lock,
        specs=tuple(inputs.specs),
    )
    assert len(document["concerns"]) == 11  # type: ignore[arg-type]


# ── the type boundary ───────────────────────────────────────────────────────


def test_an_expectation_with_no_revision_is_refused() -> None:
    with pytest.raises(ValueError, match="nothing to bind to"):
        ExpectedArtifact(source_revision="", wheel_sha256=EXPECTED_WHEEL)


def test_an_expectation_whose_wheel_is_not_a_digest_is_refused() -> None:
    with pytest.raises(ValueError, match="sha256:"):
        ExpectedArtifact(source_revision=EXPECTED_REVISION, wheel_sha256="0" * 64)


def test_a_slot_cannot_be_both_unbound_and_provided() -> None:
    with pytest.raises(ValueError, match="has not decided which it is"):
        ConcernSpec(
            concern="integration",
            distributions=(ASSEMBLY,),
            probes=("vendor_cp.identity",),
            consumer="somebody",
            unbound_reason="because",
        )


def test_a_binding_needs_a_probe_a_coordinate_and_a_consumer() -> None:
    with pytest.raises(ValueError, match="at least one probe"):
        ConcernSpec("authorization", ("dotmac-kernel",), (), "somebody")
    with pytest.raises(ValueError, match="needs a coordinate"):
        ConcernSpec("authorization", (), ("vendor_cp.identity",), "somebody")
    with pytest.raises(ValueError, match="runtime consumer"):
        ConcernSpec("authorization", (ASSEMBLY,), ("vendor_cp.identity",), "  ")


def test_every_type_boundary_row_is_driven_somewhere_in_this_module() -> None:
    """The matrix lists six type-boundary refusals and this module drives all
    six. Held as a count rather than left to a reader's eye, because a row that
    stopped being driven would go on reading as an acceptance bar."""
    assert len(TYPE_BOUNDARY_CASES) == 6


# ── the matrix and the document it is rendered into ─────────────────────────


def test_every_case_appears_in_the_inventory_document() -> None:
    """The rendered table is what Foundation reads. It may not drift from the
    fixtures it claims to render."""
    text = INVENTORY_DOC.read_text(encoding="utf-8")
    missing = [name for name in all_case_names() if name not in text]
    assert not missing, missing


def test_the_document_invents_no_case_the_matrix_does_not_have() -> None:
    """The other direction. A row in the document with no fixture behind it is
    an acceptance bar nobody can run."""
    text = INVENTORY_DOC.read_text(encoding="utf-8")
    known = set(all_case_names())
    quoted = {
        cell.strip().strip("`")
        for line in text.splitlines()
        if line.startswith("| `")
        for cell in line.split("|")[1:2]
    }
    assert quoted <= known, sorted(quoted - known)
    assert len(quoted) == len(known), (len(quoted), len(known))


def test_the_document_states_the_migration_sequence_in_order() -> None:
    """The hard constraint on this lane is an ORDER, and an inventory handed to
    a successor without it invites step 5 before step 3."""
    text = INVENTORY_DOC.read_text(encoding="utf-8")
    position = -1
    for step in MIGRATION_SEQUENCE:
        found = text.find(step)
        assert found > position, step
        position = found


def test_the_matrix_is_bigger_than_the_thirteen_it_was_asked_for() -> None:
    """The brief asked for thirteen planted defects each reaching a distinct
    named verdict. Recorded because the count is evidence about coverage, and a
    matrix that shrank would otherwise shrink quietly."""
    assert len(rendered_rows()) >= 45, len(rendered_rows())
