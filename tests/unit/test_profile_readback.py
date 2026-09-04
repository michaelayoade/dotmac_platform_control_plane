"""The profile readback refuses before the document exists, and admits after.

That transition is the point of the whole file. A verifier written AFTER the
document it checks can only confirm what is already there; this one ships first,
refuses the artifact as it stands today, and the document that follows has to
turn the refusal into an admission. If embedding the document does not change
this verifier's answer, the document is not being consumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vendor_cp.deployment.profile_readback import (
    DISTRIBUTIONS_CONTRACT,
    FOUNDATION_CONCERNS,
    PROFILE_CONTRACT,
    ExpectedArtifact,
    ProfileVerdict,
    canonical_profile_digest,
    verify_embedded_profile,
)

REVISION = "a" * 40
WHEEL = "sha256:" + "b" * 64
OTHER_WHEEL = "sha256:" + "c" * 64
EXPECTED = ExpectedArtifact(source_revision=REVISION, wheel_sha256=WHEEL)


def _document(
    *,
    revision: str = REVISION,
    wheel: str = WHEEL,
    concerns: tuple[str, ...] = FOUNDATION_CONCERNS,
    absence_proofs: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """A complete, self-consistent document. Digest computed last, as a builder
    would — and by the SPECIFICATION, not by importing anything that writes one.
    """
    document: dict[str, object] = {
        "contract": PROFILE_CONTRACT,
        "source_revision": revision,
        "wheel_sha256": wheel,
        "concerns": {
            name: {"implementation": f"provider.{name}", "version": "1.0"}
            for name in concerns
        },
        "absence_proofs": absence_proofs or [],
    }
    document["profile_digest"] = canonical_profile_digest(document)
    return document


def _write(tmp_path: Path, document: object, *, wheel: str = WHEEL) -> dict[str, Path]:
    profile = tmp_path / "application_foundation_profile.json"
    profile.write_text(json.dumps(document, indent=2), encoding="utf-8")
    distributions = tmp_path / "distributions.json"
    distributions.write_text(
        json.dumps(
            {
                "contract": DISTRIBUTIONS_CONTRACT,
                "files": [
                    {"filename": "vendor_cp-0.1.0.tar.gz", "sha256": OTHER_WHEEL},
                    {"filename": "vendor_cp-0.1.0-py3-none-any.whl", "sha256": wheel},
                ],
            }
        ),
        encoding="utf-8",
    )
    return {"profile_path": profile, "distributions_path": distributions}


def _verify(tmp_path: Path, document: object, *, wheel: str = WHEEL) -> object:
    return verify_embedded_profile(EXPECTED, **_write(tmp_path, document, wheel=wheel))


# ── the transition that proves consumption ──────────────────────────────────


def test_the_artifact_is_refused_today_and_admitted_once_the_document_lands(
    tmp_path: Path,
) -> None:
    """One verifier, one expectation, two artifacts. This is the evidence."""
    paths = _write(tmp_path, _document())
    paths["profile_path"].unlink()

    before = verify_embedded_profile(EXPECTED, **paths)
    assert before.verdict is ProfileVerdict.DOCUMENT_ABSENT
    assert not before.admitted

    paths["profile_path"].write_text(json.dumps(_document()), encoding="utf-8")

    after = verify_embedded_profile(EXPECTED, **paths)
    assert after.verdict is ProfileVerdict.ADMITTED
    assert after.bound_concerns == FOUNDATION_CONCERNS


def test_an_absent_document_is_the_honest_state_of_the_artifact_today(
    tmp_path: Path,
) -> None:
    paths = _write(tmp_path, _document())
    paths["profile_path"].unlink()
    outcome = verify_embedded_profile(EXPECTED, **paths)
    assert outcome.verdict is ProfileVerdict.DOCUMENT_ABSENT
    assert "makes no profile claim" in outcome.detail


# ── unreadable is not mismatched ────────────────────────────────────────────


def test_unreadable_and_mismatched_are_different_verdicts(tmp_path: Path) -> None:
    """Different repairs — a broken build versus an unauthorized artifact — so
    reporting one as the other sends the reader to the wrong place."""
    paths = _write(tmp_path, _document())
    # AFTER `_write`, which writes a valid document to this same path.
    paths["profile_path"].write_text("{not json", encoding="utf-8")
    unreadable = verify_embedded_profile(EXPECTED, **paths)
    assert unreadable.verdict is ProfileVerdict.DOCUMENT_UNREADABLE

    mismatched = _verify(tmp_path, _document(revision="f" * 40))
    assert mismatched.verdict is ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED
    assert unreadable.verdict is not mismatched.verdict


def test_a_document_that_is_not_an_object_is_unreadable_not_mismatched(
    tmp_path: Path,
) -> None:
    assert (
        _verify(tmp_path, ["a", "list"]).verdict is ProfileVerdict.DOCUMENT_UNREADABLE
    )


# ── the four refusals ───────────────────────────────────────────────────────


def test_an_unknown_contract_is_refused_rather_than_guessed_at(tmp_path: Path) -> None:
    document = _document()
    document["contract"] = "something-else/9"
    document["profile_digest"] = canonical_profile_digest(document)
    assert _verify(tmp_path, document).verdict is ProfileVerdict.CONTRACT_UNKNOWN


def test_wrong_artifact_coordinates_are_refused(tmp_path: Path) -> None:
    outcome = _verify(tmp_path, _document(revision="9" * 40))
    assert outcome.verdict is ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED


def test_a_tampered_document_fails_its_own_digest(tmp_path: Path) -> None:
    """The digest covers the content, and excludes itself — a field cannot be an
    input to its own value."""
    document = _document()
    concerns = document["concerns"]
    assert isinstance(concerns, dict)
    concerns["authorization"] = {"implementation": "attacker", "version": "1.0"}
    assert (
        _verify(tmp_path, document).verdict is ProfileVerdict.PROFILE_DIGEST_MISMATCHED
    )


def test_the_wheel_claim_needs_the_independent_second_witness(tmp_path: Path) -> None:
    """A profile claiming the right wheel is refused when the image carries a
    different one. An artifact that describes itself is not evidence about
    itself, so the distribution record — produced by another mechanism in the
    builder stage — has to agree."""
    outcome = _verify(tmp_path, _document(), wheel=OTHER_WHEEL)
    assert outcome.verdict is ProfileVerdict.WHEEL_DIGEST_MISMATCHED
    assert "the image carries" in outcome.detail


def test_a_profile_bound_to_the_wrong_wheel_is_refused(tmp_path: Path) -> None:
    document = _document(wheel=OTHER_WHEEL)
    assert _verify(tmp_path, document).verdict is ProfileVerdict.WHEEL_DIGEST_MISMATCHED


def test_a_missing_distribution_record_is_unreadable_not_a_mismatch(
    tmp_path: Path,
) -> None:
    paths = _write(tmp_path, _document())
    paths["distributions_path"].unlink()
    outcome = verify_embedded_profile(EXPECTED, **paths)
    assert outcome.verdict is ProfileVerdict.DOCUMENT_UNREADABLE
    assert "second witness" in outcome.detail


# ── the cross-target case a naive digest comparison passes ──────────────────


def test_another_images_absence_proof_is_refused_although_well_formed(
    tmp_path: Path,
) -> None:
    """The one that matters. This proof is well-formed, internally consistent,
    and carried inside a document whose own digest verifies — everything a naive
    check looks at. It is still inadmissible, because a proof that concern X is
    absent from image A says nothing whatever about image B.
    """
    foreign = {
        "concern": "integration",
        "source_revision": "e" * 40,
        "statement": "no integration provider is installed",
    }
    document = _document(absence_proofs=[foreign])

    # The document itself is internally valid: its digest verifies. The refusal
    # is therefore about provenance, not about corruption.
    assert document["profile_digest"] == canonical_profile_digest(document)

    outcome = _verify(tmp_path, document)
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_FOREIGN
    assert "still say nothing about THIS image" in outcome.detail


def test_this_images_own_absence_proof_is_accepted(tmp_path: Path) -> None:
    """SENSITIVITY for the test above: the refusal is about the coordinates and
    not about the presence of an absence proof at all."""
    own = {
        "concern": "integration",
        "source_revision": REVISION,
        "statement": "no integration provider is installed",
    }
    assert _verify(tmp_path, _document(absence_proofs=[own])).verdict is (
        ProfileVerdict.ADMITTED
    )


# ── completeness ────────────────────────────────────────────────────────────


def test_twelve_of_thirteen_is_refused_and_names_the_missing_one(
    tmp_path: Path,
) -> None:
    """No partial admission. A concern with no owner is what blocks a candidate,
    which is the entire reason the slots are closed."""
    outcome = _verify(tmp_path, _document(concerns=FOUNDATION_CONCERNS[:12]))
    assert outcome.verdict is ProfileVerdict.CONCERNS_INCOMPLETE
    assert "integration" in outcome.detail
    assert len(outcome.bound_concerns) == 12


def test_an_empty_binding_does_not_count_as_bound(tmp_path: Path) -> None:
    """A placeholder is not an owner — Michael's gate, as an assertion."""
    document = _document()
    concerns = document["concerns"]
    assert isinstance(concerns, dict)
    concerns["data_governance"] = {}
    document["profile_digest"] = canonical_profile_digest(document)
    outcome = _verify(tmp_path, document)
    assert outcome.verdict is ProfileVerdict.CONCERNS_INCOMPLETE
    assert "data_governance" in outcome.detail


# ── independence from the builder ───────────────────────────────────────────


def test_the_verifier_imports_nothing_that_writes_a_profile(tmp_path: Path) -> None:
    """ "Reads independently of the builder", as a check rather than a claim.

    A verifier that imported the producer would be asking the producer whether
    the producer was right. The module may read JSON and hash bytes; it may not
    reach for anything that constructs or serializes a profile.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src/vendor_cp/deployment/profile_readback.py"
    ).read_text(encoding="utf-8")
    imports = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith(("import ", "from "))
    ]
    assert imports, "no imports found; the check would be vacuous"
    for line in imports:
        assert "builder" not in line
        assert "candidate" not in line
        assert "evidence_producer" not in line
        assert "signers" not in line


def test_the_expectation_cannot_be_empty_or_unpinned() -> None:
    """The expectation comes from the release receipt. One that carries no
    revision, or a wheel that is not a digest, cannot bind anything."""
    with pytest.raises(ValueError, match="source_revision is empty"):
        ExpectedArtifact(source_revision="", wheel_sha256=WHEEL)
    with pytest.raises(ValueError, match="sha256"):
        ExpectedArtifact(source_revision=REVISION, wheel_sha256="latest")


def test_the_defaults_point_into_the_artifact_not_into_a_checkout() -> None:
    """A readback that defaulted to a repository path would verify the SOURCE
    TREE and report it as a fact about the image — which is precisely the error
    that produced "ten of thirteen bound" for an artifact carrying no profile at
    all. Both defaults are the in-image paths, beside each other.
    """
    from vendor_cp.deployment.profile_readback import (
        DEFAULT_DISTRIBUTIONS_PATH,
        DEFAULT_PROFILE_PATH,
    )

    assert DEFAULT_PROFILE_PATH == Path("/app/application_foundation_profile.json")
    assert DEFAULT_DISTRIBUTIONS_PATH == Path("/app/distributions.json")
    assert DEFAULT_PROFILE_PATH.parent == DEFAULT_DISTRIBUTIONS_PATH.parent
