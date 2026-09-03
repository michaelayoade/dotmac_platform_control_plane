"""The refusal, built before the happy path, because today it is the answer.

Two terms cannot exist until Michael mints the signing identities, so every real
packet refuses right now. A validator that refuses without naming which term is
absent would send an operator round the loop once per missing term — so the
load-bearing assertion in this file is not that it refused, it is WHICH terms it
named.
"""

from __future__ import annotations

from typing import Any

import pytest

from vendor_cp.deployment.foundation_candidate import (
    FOUNDATION_CANDIDATE,
    coordinate_fields,
)
from vendor_cp.deployment.readiness_packet import (
    ABORT_PROCEDURE,
    HELD_PENDING_MINT,
    PacketRefusal,
    PacketRefused,
    PacketTerm,
    validate_readiness_packet,
)

#: Every refusal code this file drives, maintained beside the tests that drive
#: it and ratcheted against the enum in both directions.
EXERCISED_REFUSALS = frozenset(
    {
        PacketRefusal.MISSING_TERMS,
        PacketRefusal.UNKNOWN_TERMS,
        PacketRefusal.EMPTY_TERMS,
        PacketRefusal.ROLLBACK_NOT_STATED,
        PacketRefusal.RESTORATION_CLAIMED_EXECUTABLE,
        PacketRefusal.ABORT_PROCEDURE_UNSUPPORTED,
        PacketRefusal.ARTIFACT_COORDINATE_MISMATCH,
    }
)

#: Transcribed by hand from `docs/inventories/foundation-candidate-0.3.0a5.json`
#: on `michaelayoade/dotmac_starter_mt` at `d096e64c13fe3cd8ab89f4a15edd1ce1bc046e2a`.
#: Deliberately NOT built from `FOUNDATION_CANDIDATE`: a fixture that asks the
#: pin what it contains proves only that the pin agrees with itself, and a typo
#: in the pin would be invisible.
RECORDED_FOUNDATION_COORDINATE = {
    "facility": "dotmac-deployment-foundation",
    "version": "0.3.0a5",
    "source_sha": "27bee8fc43919a5ed7f4853ccdedc2f996ad8d86",
    "run_id": "33780438726",
    "artifact_id": "9903418260",
    "wheel_sha256": (
        "17b3464ede04a182958753b493d08c5f06e2b5643960c113ecf6584d4ed56e1b"
    ),
    "sdist_sha256": (
        "df9753e0ab6dddbfbbbaa6f468d3d633fa66088fb3b89d0d9f4cc7c7d969ab18"
    ),
    "published": False,
    "tagged": False,
}


def complete_packet() -> dict[str, Any]:
    """A packet with every term present and non-empty.

    Deliberately hand-built rather than produced by an emitter: a fixture that
    asks the code under test what it wants proves only that it agrees with
    itself. The values are placeholders — this module validates SHAPE, and the
    oracles that make each value trustworthy are a separate obligation.
    """
    packet: dict[str, Any] = {
        term.value: f"placeholder-for-{term.value}" for term in PacketTerm
    }
    packet[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = dict(
        RECORDED_FOUNDATION_COORDINATE
    )
    packet[PacketTerm.ROLLBACK_AND_ABORT.value] = {
        "restoration_executable": False,
        "abort_procedure": ABORT_PROCEDURE,
        "command": "stop and report to Michael",
    }
    return packet


def test_a_complete_packet_validates() -> None:
    """POSITIVE CONTROL. Every other test here is a refusal, and a validator
    only ever observed refusing might refuse everything."""
    packet = validate_readiness_packet(complete_packet())
    assert set(packet.terms) == set(PacketTerm)


def test_no_refusal_code_ships_without_a_test() -> None:
    """A vocabulary ratchet in both directions."""
    assert set(PacketRefusal) == EXERCISED_REFUSALS


@pytest.mark.parametrize("planted", tuple(PacketTerm), ids=lambda t: t.value)
def test_each_missing_term_is_named_individually(planted: PacketTerm) -> None:
    """THE test. Every term, planted absent one at a time, must be NAMED.

    Parametrized over the enum rather than a hand list, so a term added
    tomorrow is covered the moment it is declared.
    """
    document = complete_packet()
    del document[planted.value]

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.MISSING_TERMS
    assert refused.value.terms == (
        planted,
    ), "the refusal must name exactly the absent term"
    assert planted.value in str(refused.value)


def test_every_missing_term_is_named_at_once_not_one_per_round_trip() -> None:
    """An operator fixing one term per refusal is the operator-surface defect.
    An empty packet must name all fourteen, not the first."""
    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet({})
    assert set(refused.value.terms) == set(PacketTerm)


def test_the_two_terms_awaiting_the_mint_say_so_and_are_still_refused() -> None:
    """They cannot exist until the identities are minted. That explains the
    absence; it does not waive it."""
    document = complete_packet()
    for term in HELD_PENDING_MINT:
        del document[term.value]

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert set(refused.value.terms) == set(HELD_PENDING_MINT)
    message = str(refused.value)
    assert "minted" in message
    assert "signing-identity-mint-dossier" in message
    assert "refused rather than waived" in message


@pytest.mark.parametrize("hollow", (None, "", {}, []))
def test_a_term_filled_in_with_nothing_is_absent_not_satisfied(
    hollow: object,
) -> None:
    """The failure mode is a script that filled every key and found no value."""
    document = complete_packet()
    document[PacketTerm.IMAGE_DIGEST.value] = hollow

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.EMPTY_TERMS
    assert refused.value.terms == (PacketTerm.IMAGE_DIGEST,)


def test_a_misspelled_term_is_refused_as_unknown_not_reported_as_missing() -> None:
    """Reporting it as missing would send the reader hunting for a value they
    already supplied, one character away from where they are looking."""
    document = complete_packet()
    document["image_digests"] = document.pop(PacketTerm.IMAGE_DIGEST.value)

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.UNKNOWN_TERMS
    assert "image_digests" in str(refused.value)


def test_a_packet_may_not_claim_restoration_is_executable() -> None:
    """There is no authorized restore executor and no deadman. That is an
    accepted residual risk, and a packet must not overwrite it."""
    document = complete_packet()
    document[PacketTerm.ROLLBACK_AND_ABORT.value] = {
        "restoration_executable": True,
        "abort_procedure": ABORT_PROCEDURE,
    }

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.RESTORATION_CLAIMED_EXECUTABLE


def test_a_truthy_non_false_restoration_flag_does_not_slip_through() -> None:
    """SENSITIVITY. `0`, `""` and `None` are falsey but are not `false`; a
    packet that says nothing must not read as a packet that says no."""
    for slippery in (0, "", None, "false"):
        document = complete_packet()
        document[PacketTerm.ROLLBACK_AND_ABORT.value] = {
            "restoration_executable": slippery,
            "abort_procedure": ABORT_PROCEDURE,
        }
        with pytest.raises(PacketRefused) as refused:
            validate_readiness_packet(document)
        assert refused.value.refusal is PacketRefusal.RESTORATION_CLAIMED_EXECUTABLE


def test_the_abort_procedure_must_be_stop_and_report() -> None:
    document = complete_packet()
    document[PacketTerm.ROLLBACK_AND_ABORT.value] = {
        "restoration_executable": False,
        "abort_procedure": "roll back automatically",
    }

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.ABORT_PROCEDURE_UNSUPPORTED


def test_an_unstructured_rollback_term_is_refused() -> None:
    """A sentence cannot be checked. The residual risk has to be STATED in
    fields, or a packet could carry prose that says the opposite."""
    document = complete_packet()
    document[PacketTerm.ROLLBACK_AND_ABORT.value] = "stop and report"

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.ROLLBACK_NOT_STATED


# --- the one term that is value-checked today -------------------------------


def test_the_pin_matches_the_record_transcribed_independently() -> None:
    """A typo in the pin would otherwise make every coordinate test agree with
    the wrong value in unison."""
    assert set(coordinate_fields()) == set(RECORDED_FOUNDATION_COORDINATE)
    for name, expected in RECORDED_FOUNDATION_COORDINATE.items():
        assert getattr(FOUNDATION_CANDIDATE, name) == expected, name


def test_the_foundation_coordinate_is_admitted_on_the_real_values() -> None:
    """POSITIVE CONTROL for the coordinate check. A comparison only ever
    observed refusing would refuse the real record too."""
    validate_readiness_packet(complete_packet())


def test_the_candidate_is_pinned_unpublished_and_untagged() -> None:
    """`published` and `tagged` are false and load-bearing: the cutover runs on
    candidate bytes, and publication is a later step. A packet asserting the
    build is published is naming something that does not exist."""
    assert FOUNDATION_CANDIDATE.published is False
    assert FOUNDATION_CANDIDATE.tagged is False

    document = complete_packet()
    document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = {
        **RECORDED_FOUNDATION_COORDINATE,
        "published": True,
    }
    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)
    assert refused.value.refusal is PacketRefusal.ARTIFACT_COORDINATE_MISMATCH
    assert "published" in str(refused.value)


@pytest.mark.parametrize(
    ("field", "mutated"),
    (
        ("wheel_sha256", "0" * 64),
        ("sdist_sha256", "f" * 64),
        ("artifact_id", "9903418261"),
        ("run_id", "33780438727"),
        ("source_sha", "0" * 40),
        ("version", "0.3.0a6"),
        ("facility", "dotmac-deployment-control"),
    ),
)
def test_a_mutated_coordinate_is_refused_and_the_field_is_named(
    field: str, mutated: object
) -> None:
    """The check that makes this term worth having. A digest that is present
    but wrong must not pass for a digest that is present."""
    document = complete_packet()
    document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = {
        **RECORDED_FOUNDATION_COORDINATE,
        field: mutated,
    }

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)

    assert refused.value.refusal is PacketRefusal.ARTIFACT_COORDINATE_MISMATCH
    assert refused.value.terms == (PacketTerm.FOUNDATION_ARTIFACT_COORDINATE,)
    assert field in str(refused.value)


def test_every_disagreeing_field_is_named_not_only_the_first() -> None:
    """One mismatch per round trip is the operator-surface defect again."""
    document = complete_packet()
    document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = {
        **RECORDED_FOUNDATION_COORDINATE,
        "wheel_sha256": "0" * 64,
        "artifact_id": "0",
    }
    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)
    message = str(refused.value)
    assert "wheel_sha256" in message
    assert "artifact_id" in message


def test_a_coordinate_missing_a_field_is_refused() -> None:
    """A partial coordinate is not a coordinate. `.get` returning None must not
    read as agreement."""
    partial = dict(RECORDED_FOUNDATION_COORDINATE)
    del partial["wheel_sha256"]
    document = complete_packet()
    document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = partial

    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)
    assert refused.value.refusal is PacketRefusal.ARTIFACT_COORDINATE_MISMATCH
    assert "wheel_sha256" in str(refused.value)


def test_an_unstructured_coordinate_is_refused() -> None:
    document = complete_packet()
    document[PacketTerm.FOUNDATION_ARTIFACT_COORDINATE.value] = (
        "dotmac-deployment-foundation 0.3.0a5"
    )
    with pytest.raises(PacketRefused) as refused:
        validate_readiness_packet(document)
    assert refused.value.refusal is PacketRefusal.ARTIFACT_COORDINATE_MISMATCH
