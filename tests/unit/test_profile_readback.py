"""The profile readback refuses before the document exists, and admits after.

That transition is the point of the whole file. A verifier written AFTER the
document it checks can only confirm what is already there; this one ships first,
refuses the artifact as it stands today, and the document that follows has to
turn the refusal into an admission. If embedding the document does not change
this verifier's answer, the document is not being consumed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vendor_cp.deployment.profile_readback import (
    ABSENCE_PROOF_CONCERNS,
    DISTRIBUTIONS_CONTRACT,
    FOUNDATION_CONCERNS,
    INTEGRATION_ABSENCE_SCHEMA,
    INTEGRATION_SURFACE_FAMILIES,
    PROFILE_CONTRACT,
    ExpectedArtifact,
    ProfileVerdict,
    canonical_inventory_digest,
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


# ── an absence proof SATISFIES, and only when it ESTABLISHES ────────────────
#
# Ruled 2026-09-04: absence is approved only through
# `IntegrationSurfaceAbsenceProofV1`, bound to the exact installed artifact and a
# closed surface inventory — "this is not a general 'nothing applies' escape
# hatch". The tests below are two halves of one property. The first says a real
# proof counts, because a gate nothing can satisfy gets waived rather than met.
# Every other one says a proof that establishes nothing does not, because a gate
# anything can satisfy is not a gate.


def _inventory_pairs(wheel: str = WHEEL) -> list[tuple[str, str]]:
    """The exact `(filename, sha256)` pairs `_write` puts in the image."""
    return [
        ("vendor_cp-0.1.0.tar.gz", OTHER_WHEEL),
        ("vendor_cp-0.1.0-py3-none-any.whl", wheel),
    ]


def _inventory_digest(wheel: str = WHEEL) -> str:
    """THE SPECIFICATION, re-implemented here rather than imported.

    Importing `canonical_inventory_digest` would make every assertion below a
    statement that one function agrees with itself — the same reason the module
    calls its own encoding a spec for a producer to implement separately. This is
    the second implementation that makes the comparison mean something.
    """
    body = sorted(_inventory_pairs(wheel))
    encoded = json.dumps(
        [[name, digest] for name, digest in body],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _proof(**over: object) -> dict[str, object]:
    """A proof that ESTABLISHES, unless a test breaks exactly one thing."""
    proof: dict[str, object] = {
        "schema": INTEGRATION_ABSENCE_SCHEMA,
        "state": "absent_proven",
        "concern": "integration",
        "source_revision": REVISION,
        "image_digest": WHEEL,
        "observed_inventory_digest": _inventory_digest(),
        "families": {name: [] for name in sorted(INTEGRATION_SURFACE_FAMILIES)},
        "method": "entry-point metadata + AST walk over the installed image",
        "positive_control": ["dotmac_integration.connectors:paystack"],
        "established_at": "2026-09-04T12:00:00Z",
        "established_by": "platform-cp-profile-job",
    }
    proof.update(over)
    return proof


def _with_proof(proof: dict[str, object], *, concern: str = "integration") -> dict:
    """Twelve declared bindings, and one concern left to the proof."""
    return _document(
        concerns=tuple(name for name in FOUNDATION_CONCERNS if name != concern),
        absence_proofs=[proof],
    )


def test_an_established_absence_proof_satisfies_integration(tmp_path: Path) -> None:
    """The half that keeps the gate REACHABLE.

    Twelve concerns declared, the thirteenth proven absent against this image's
    own distribution inventory. If a proven absence could not satisfy a concern,
    a product with genuinely no integration surface could never reach 13/13 —
    and an unmeetable gate gets waived rather than met.
    """
    outcome = _verify(tmp_path, _with_proof(_proof()))
    assert outcome.verdict is ProfileVerdict.ADMITTED
    assert outcome.bound_concerns == FOUNDATION_CONCERNS
    assert "1 proven absent" in outcome.detail


def test_a_manufactured_inventory_digest_establishes_nothing(tmp_path: Path) -> None:
    """The half that keeps the gate from being BYPASSABLE — the planted defect.

    Everything else about this proof is perfect: right schema, right concern,
    right revision, five families all empty, a positive control. The only change
    is a digest a caller wrote instead of one derived from the image. Writing a
    string is free; making it equal a digest an independent reader computed is
    not, and that asymmetry is the entire load-bearing half.
    """
    forged = _proof(observed_inventory_digest="sha256:" + "e" * 64)
    outcome = _verify(tmp_path, _with_proof(forged))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "cannot manufacture" in outcome.detail


def test_the_near_miss_is_admitted_so_the_check_is_not_refusing_everything(
    tmp_path: Path,
) -> None:
    """The sensitivity proof's other half.

    A check that refuses every proof would pass the test above for the wrong
    reason. This is the SAME proof with the SAME everything, differing only in
    that the inventory digest is the derived one — and it is admitted. The
    refusal above therefore bites on the digest and on nothing else.
    """
    outcome = _verify(tmp_path, _with_proof(_proof()))
    assert outcome.verdict is ProfileVerdict.ADMITTED


def test_the_absence_route_is_closed_to_data_governance(tmp_path: Path) -> None:
    """The escape hatch, planted directly.

    `data_governance` was ruled to need a real implementation, and an earlier
    ruling already refused an `inapplicable` for it. A proof of the one approved
    schema, otherwise perfect, relabelled to certify it must be REFUSED rather
    than ignored — ignoring it would let the document carry a certification
    nobody rejected.
    """
    hijacked = _proof(concern="data_governance")
    outcome = _verify(tmp_path, _with_proof(hijacked, concern="data_governance"))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE
    assert "may only prove 'integration' absent" in outcome.detail


def test_an_unknown_absence_schema_certifies_nothing(tmp_path: Path) -> None:
    """A second proof type invented later does not inherit this one's approval."""
    outcome = _verify(
        tmp_path, _with_proof(_proof(schema="DataGovernanceAbsenceProofV1"))
    )
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE
    assert "certifies nothing here" in outcome.detail


def test_the_approved_absence_map_has_exactly_one_entry() -> None:
    """Stated as a value, so widening it is a visible edit rather than a drift.

    Read off the module dict itself — a plain module-level mapping, so `.values()`
    is the mapping's values and not a descriptor standing in for them.
    """
    assert ABSENCE_PROOF_CONCERNS == {INTEGRATION_ABSENCE_SCHEMA: "integration"}
    assert "data_governance" not in ABSENCE_PROOF_CONCERNS.values()
    assert "request_evidence_context" not in ABSENCE_PROOF_CONCERNS.values()


def test_a_proof_that_visited_four_of_five_families_establishes_nothing(
    tmp_path: Path,
) -> None:
    """The producing type refused this AT CONSTRUCTION, in another process.

    What arrives here is JSON, and a constructor's refusals do not travel in a
    document. A family never looked at is not a family found empty.
    """
    partial = dict(_proof()["families"])  # type: ignore[arg-type]
    partial.pop("message_consumer")
    outcome = _verify(tmp_path, _with_proof(_proof(families=partial)))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "message_consumer" in outcome.detail


def test_a_proof_reporting_an_unregistered_family_is_refused(tmp_path: Path) -> None:
    """A surface nobody registered silently satisfies 'none present'."""
    widened = dict(_proof()["families"])  # type: ignore[arg-type]
    widened["grpc_stream"] = []
    outcome = _verify(tmp_path, _with_proof(_proof(families=widened)))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "grpc_stream" in outcome.detail


def test_a_proof_that_found_a_surface_is_unbound_rather_than_absent(
    tmp_path: Path,
) -> None:
    """Found something is a THIRD answer, not a weaker absence."""
    occupied = dict(_proof()["families"])  # type: ignore[arg-type]
    occupied["outbound_connector"] = ["vendor_cp.relay:dispatch"]
    outcome = _verify(tmp_path, _with_proof(_proof(families=occupied)))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "UNBOUND" in outcome.detail


def test_a_proof_with_no_positive_control_cannot_say_which_it_is(
    tmp_path: Path,
) -> None:
    """Without the instrument shown finding something, a scan that never finds
    anything and an artifact that has nothing are the same colour."""
    outcome = _verify(tmp_path, _with_proof(_proof(positive_control=[])))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "positive control" in outcome.detail


def test_a_document_not_declaring_absent_proven_is_not_making_the_claim(
    tmp_path: Path,
) -> None:
    outcome = _verify(tmp_path, _with_proof(_proof(state="inapplicable")))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "not making this claim" in outcome.detail


def test_a_proof_bound_to_another_artifact_establishes_nothing(
    tmp_path: Path,
) -> None:
    """Same revision, same image, a different installed artifact."""
    outcome = _verify(tmp_path, _with_proof(_proof(image_digest=OTHER_WHEEL)))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED
    assert "binds to artifact" in outcome.detail


def test_the_foreign_check_still_precedes_establishment(tmp_path: Path) -> None:
    """A cross-target proof is refused as FOREIGN, not as unestablished.

    Two different repairs — a proof produced for another build versus one that
    proves nothing — so they keep two verdicts. Collapsing them would report an
    honest proof of the wrong artifact as a failed scan.
    """
    outcome = _verify(tmp_path, _with_proof(_proof(source_revision="f" * 40)))
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_FOREIGN


def test_a_concern_cannot_be_both_bound_and_proven_absent(tmp_path: Path) -> None:
    """Two of the four states at once is a document that has not decided.

    Accepting either would be this verifier deciding for it.
    """
    document = _document(concerns=FOUNDATION_CONCERNS, absence_proofs=[_proof()])
    outcome = _verify(tmp_path, document)
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE
    assert "declared bound AND proven absent" in outcome.detail


def test_without_a_proof_integration_is_simply_unsatisfied(tmp_path: Path) -> None:
    """The state before any of this: twelve concerns and no thirteenth."""
    document = _document(
        concerns=tuple(n for n in FOUNDATION_CONCERNS if n != "integration")
    )
    outcome = _verify(tmp_path, document)
    assert outcome.verdict is ProfileVerdict.CONCERNS_INCOMPLETE
    assert "integration" in outcome.detail


# ── the inventory digest is over the IMAGE's record ─────────────────────────


def test_the_derived_inventory_digest_matches_an_independent_encoder() -> None:
    """Two implementations of one spec, agreeing. If they ever disagree, the
    producer's third implementation would disagree with one of them too."""
    assert canonical_inventory_digest(_inventory_pairs()) == _inventory_digest()


def test_the_inventory_digest_moves_when_the_inventory_does() -> None:
    """A digest that did not change when a distribution changed would bind a
    proof to nothing, which is the same as not checking it."""
    assert canonical_inventory_digest(_inventory_pairs()) != canonical_inventory_digest(
        _inventory_pairs(wheel=OTHER_WHEEL)
    )


def test_the_inventory_digest_does_not_depend_on_file_order() -> None:
    """The builder emits sorted; a reader must not depend on it having done so."""
    pairs = _inventory_pairs()
    assert canonical_inventory_digest(pairs) == canonical_inventory_digest(
        list(reversed(pairs))
    )


def test_a_narrowed_distribution_record_is_unusable_not_a_smaller_inventory(
    tmp_path: Path,
) -> None:
    """An entry missing its digest makes the WHOLE record unusable.

    Skipping it would still produce a digest — over a set that is not the
    artifact's — and a silently narrowed second witness is exactly what the
    second witness exists to prevent. Unreadable is not mismatched.
    """
    paths = _write(tmp_path, _with_proof(_proof()))
    paths["distributions_path"].write_text(
        json.dumps(
            {
                "contract": DISTRIBUTIONS_CONTRACT,
                "files": [
                    {"filename": "vendor_cp-0.1.0.tar.gz"},
                    {"filename": "vendor_cp-0.1.0-py3-none-any.whl", "sha256": WHEEL},
                ],
            }
        ),
        encoding="utf-8",
    )
    outcome = verify_embedded_profile(EXPECTED, **paths)
    assert outcome.verdict is ProfileVerdict.DOCUMENT_UNREADABLE


def test_two_wheels_are_no_single_second_witness(tmp_path: Path) -> None:
    """Picking one of several would be choosing which witness to believe."""
    paths = _write(tmp_path, _with_proof(_proof()))
    paths["distributions_path"].write_text(
        json.dumps(
            {
                "contract": DISTRIBUTIONS_CONTRACT,
                "files": [
                    {"filename": "vendor_cp-0.1.0-py3-none-any.whl", "sha256": WHEEL},
                    {"filename": "vendor_cp-0.1.0-py2-none-any.whl", "sha256": WHEEL},
                ],
            }
        ),
        encoding="utf-8",
    )
    outcome = verify_embedded_profile(EXPECTED, **paths)
    assert outcome.verdict is ProfileVerdict.DOCUMENT_UNREADABLE
    assert "exactly one wheel" in outcome.detail


# ── request_evidence_context: expressible and verifiable when it arrives ────
#
# The implementation is `dotmac-kernel`'s, extracted product-first from ERP's
# trusted-proxy behaviour, with Foundation owning the profile/verifier contract.
# That work is not this lane's. What IS this lane's is that the profile can
# express the binding and this verifier can judge it the day it lands — and that
# it cannot be reached by the absence route in the meantime.


def test_request_evidence_context_is_a_slot_this_verifier_already_judges(
    tmp_path: Path,
) -> None:
    """Unbound it blocks by name; bound it satisfies. No change needed here when
    the kernel implementation arrives — only a binding in the document."""
    owed = "request_evidence_context"
    without = _document(concerns=tuple(n for n in FOUNDATION_CONCERNS if n != owed))
    blocked = _verify(tmp_path, without)
    assert blocked.verdict is ProfileVerdict.CONCERNS_INCOMPLETE
    assert owed in blocked.detail
    assert owed not in blocked.bound_concerns

    admitted = _verify(tmp_path, _document())
    assert admitted.verdict is ProfileVerdict.ADMITTED
    assert owed in admitted.bound_concerns


def test_request_evidence_context_cannot_be_reached_by_the_absence_route(
    tmp_path: Path,
) -> None:
    """It has an owner and an adopter; it is owed, not absent."""
    outcome = _verify(
        tmp_path,
        _with_proof(
            _proof(concern="request_evidence_context"),
            concern="request_evidence_context",
        ),
    )
    assert outcome.verdict is ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE


def test_every_verdict_has_a_place_in_the_precedence_order() -> None:
    """A verdict added without a precedence slot is a verdict nobody ordered.

    `VERDICT_PRECEDENCE` states which refusal wins when several apply. A member
    missing from it is not "last"; it is unstated, and the next reader has to
    infer an order from the function body — which is where the order stops being
    a contract. The same property `relay.health` holds its own verdicts to.
    """
    from vendor_cp.deployment.profile_readback import VERDICT_PRECEDENCE

    assert set(VERDICT_PRECEDENCE) == set(ProfileVerdict)
    assert len(VERDICT_PRECEDENCE) == len(ProfileVerdict)
