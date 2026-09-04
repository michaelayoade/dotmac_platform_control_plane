"""The builder, and the round trip through the verifier that shipped first.

Every test here fails before `src/vendor_cp/deployment/profile.py` exists. The
ones worth reading are not the import-error ones: they are the cases that
separate "a concern is bound because a provider answered" from "a concern is
bound because a literal said so", and the round trip that shows the document
this builder emits is the one `verify_embedded_profile` reads.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vendor_cp.deployment.profile import (
    ASSEMBLY,
    CONCERN_SPECS,
    ConcernSpec,
    ProfileBuildRefusal,
    build_profile_document,
    profile_digest,
    render,
    resolve_probe,
)
from vendor_cp.deployment.profile_readback import (
    FOUNDATION_CONCERNS,
    PROFILE_CONTRACT,
    ExpectedArtifact,
    ProfileVerdict,
    canonical_profile_digest,
    verify_embedded_profile,
)

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "poetry.lock"

#: A real peeled commit — this repository's `main` when the builder landed.
REVISION = "8dc945f4b55b4fca0eb28eadbe763de5a3995291"

#: Ruled, not chosen. `request_evidence_context` is `dotmac-kernel`'s to
#: implement and must not be declared from this side; `integration` needs
#: Foundation's proof type, which is deliberately not in this image.
DELIBERATELY_UNBOUND = frozenset({"request_evidence_context", "integration"})


@pytest.fixture
def dist_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "dist"
    directory.mkdir()
    (directory / "dotmac_vendor_control_plane-0.1.0-py3-none-any.whl").write_bytes(
        b"not really a wheel, but it is the bytes the digest is taken over"
    )
    return directory


def _wheel_digest(dist_dir: Path) -> str:
    wheel = next(dist_dir.glob("*.whl"))
    return "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest()


# ── the thirteen slots ──────────────────────────────────────────────────────


def test_every_foundation_concern_has_a_spec_and_no_spec_invents_one() -> None:
    """Both directions. A slot with no spec produces a document short by one and
    silent about why; a spec naming a concern the verifier has no slot for
    writes a claim nobody reads."""
    declared = [spec.concern for spec in CONCERN_SPECS]
    assert len(declared) == len(set(declared))
    assert set(declared) == set(FOUNDATION_CONCERNS)


def test_exactly_the_ruled_slots_are_left_unbound_and_each_says_why() -> None:
    unbound = {spec.concern for spec in CONCERN_SPECS if spec.unbound_reason}
    assert unbound == DELIBERATELY_UNBOUND
    for spec in CONCERN_SPECS:
        if spec.unbound_reason:
            assert len(spec.unbound_reason) > 80, spec.concern


def test_a_bound_spec_with_no_probe_is_refused() -> None:
    """Without a probe a binding is bound because this table says so, which is
    the literal-in-a-fixture shape the whole builder exists to rule out."""
    with pytest.raises(ValueError, match="at least one probe"):
        ConcernSpec(
            concern="authorization",
            distributions=("dotmac-kernel",),
            probes=(),
            consumer="somebody",
        )


def test_a_bound_spec_with_no_consumer_is_refused() -> None:
    """A provider nothing discovers is inert — the gate's own definition."""
    with pytest.raises(ValueError, match="runtime consumer"):
        ConcernSpec(
            concern="authorization",
            distributions=("dotmac-kernel",),
            probes=("dotmac_kernel.audit:write_platform_audit_event",),
            consumer="   ",
        )


def test_a_slot_cannot_be_both_unbound_and_provided() -> None:
    with pytest.raises(ValueError, match="has not decided which it is"):
        ConcernSpec(
            concern="integration",
            distributions=("dotmac-kernel",),
            probes=("dotmac_kernel.audit",),
            consumer="somebody",
            unbound_reason="because",
        )


# ── a provider ANSWERS, or the build refuses ────────────────────────────────


def test_a_probe_whose_symbol_is_gone_refuses_the_build(dist_dir: Path) -> None:
    """THE point of the builder, driven.

    A kernel repin that removed `write_platform_audit_event` must not produce a
    profile claiming `audit_telemetry`; it must fail the image build, by name.
    """
    broken = tuple(
        ConcernSpec(
            concern=spec.concern,
            distributions=spec.distributions,
            probes=(
                ("dotmac_kernel.audit:write_platform_audit_event_REMOVED",)
                if spec.concern == "audit_telemetry"
                else spec.probes
            ),
            consumer=spec.consumer,
            unbound_reason=spec.unbound_reason,
        )
        for spec in CONCERN_SPECS
    )
    with pytest.raises(ProfileBuildRefusal, match="write_platform_audit_event_REMOVED"):
        build_profile_document(
            source_revision=REVISION,
            dist_dir=dist_dir,
            lock_path=LOCK,
            specs=broken,
        )


def test_the_same_build_succeeds_with_the_real_symbol(dist_dir: Path) -> None:
    """The near-miss for the test above. Without it, the refusal could be a
    builder that refuses everything."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    assert "audit_telemetry" in document["concerns"]  # type: ignore[operator]


def test_a_module_that_does_not_import_refuses_by_name() -> None:
    with pytest.raises(ProfileBuildRefusal, match="does not import"):
        resolve_probe("vendor_cp.this_module_does_not_exist:anything")


def test_a_probe_that_resolves_returns_the_object() -> None:
    assert resolve_probe("vendor_cp.deployment.profile:ASSEMBLY") == ASSEMBLY


# ── coordinates: read, cross-checked, never invented ────────────────────────


def test_a_lock_that_disagrees_with_the_installed_version_refuses(
    dist_dir: Path, tmp_path: Path
) -> None:
    """A coordinate is only useful if it names the wheel that is actually here.

    A lock recording a version the environment does not have would hand every
    binding a hash for some other build, and every check downstream would then
    be comparing this image against a different one while reporting agreement.
    """
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        LOCK.read_text(encoding="utf-8").replace(
            'name = "dotmac-kernel"\nversion = "0.1.0a98"',
            'name = "dotmac-kernel"\nversion = "0.1.0a97"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileBuildRefusal, match="0.1.0a97"):
        build_profile_document(
            source_revision=REVISION, dist_dir=dist_dir, lock_path=lock
        )


def test_an_empty_coordinate_source_refuses_rather_than_producing_no_coordinates(
    dist_dir: Path, tmp_path: Path
) -> None:
    """A lock with nothing in it yields a document with no coordinates and no
    complaint — a vacuous pass wearing a green tick."""
    lock = tmp_path / "poetry.lock"
    lock.write_text('lock-version = "2.1"\n', encoding="utf-8")
    with pytest.raises(ProfileBuildRefusal, match="no single-wheel package"):
        build_profile_document(
            source_revision=REVISION, dist_dir=dist_dir, lock_path=lock
        )


def test_every_emitted_coordinate_is_immutable(dist_dir: Path) -> None:
    """A `sha256:` digest or a peeled commit. A version alone is not a
    coordinate — it can be re-pointed."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    seen = 0
    for binding in document["concerns"].values():  # type: ignore[union-attr]
        for provider in binding["providers"]:  # type: ignore[index]
            coordinate = provider["coordinate"]
            kind = provider["coordinate_kind"]
            if kind == "wheel_sha256":
                assert coordinate.startswith("sha256:") and len(coordinate) == 71
            elif kind == "peeled_commit":
                assert coordinate == REVISION
            else:  # pragma: no cover - a new kind must be looked at
                raise AssertionError(f"unknown coordinate kind {kind!r}")
            seen += 1
    assert seen >= 11, seen


def test_a_branch_name_is_not_a_source_revision(dist_dir: Path) -> None:
    """`scripts/deploy_production.sh` refuses anything but a peeled commit when
    it reads the revision back off the image, so a document built from `main`
    would describe an artifact the deploy then rejects."""
    for bad in ("main", "unknown", "8dc945f", REVISION + "0"):
        with pytest.raises(ProfileBuildRefusal, match="peeled"):
            build_profile_document(
                source_revision=bad, dist_dir=dist_dir, lock_path=LOCK
            )


def test_two_wheels_refuse_rather_than_one_being_chosen(dist_dir: Path) -> None:
    (dist_dir / "another-0.2.0-py3-none-any.whl").write_bytes(b"second")
    with pytest.raises(ProfileBuildRefusal, match="exactly one"):
        build_profile_document(
            source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
        )


# ── the digest: two implementations, and they must agree ────────────────────


def test_the_two_digest_implementations_agree_on_documents_built_to_separate_them(
    dist_dir: Path,
) -> None:
    """`profile_readback.canonical_profile_digest` is a SPECIFICATION and this
    is a second implementation of it. Agreement on one easy document proves
    nothing, so these are chosen for the places two encoders diverge: non-ASCII
    (`ensure_ascii`), key order, nesting, and empty containers.
    """
    real = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    cases: list[dict[str, object]] = [
        real,
        {"b": 1, "a": 2, "profile_digest": "sha256:" + "0" * 64},
        {"note": "réédition — naïve, 日本語", "nested": {"z": [1, {"y": None}]}},
        {"empty_map": {}, "empty_list": [], "false": False, "zero": 0},
        {"profile_digest": "ignored", "only": "field"},
    ]
    for case in cases:
        assert profile_digest(case) == canonical_profile_digest(case), case


def test_the_digest_excludes_its_own_field_and_covers_everything_else(
    dist_dir: Path,
) -> None:
    """A field cannot be an input to its own value — and the other direction
    matters more: a digest that ignored a field would let that field be edited
    in a shipped document without detection."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    baseline = profile_digest(document)
    assert document["profile_digest"] == baseline

    rewritten = dict(document)
    rewritten["profile_digest"] = "sha256:" + "f" * 64
    assert profile_digest(rewritten) == baseline

    for field in ("contract", "source_revision", "wheel_sha256", "concerns"):
        tampered = dict(document)
        tampered[field] = "tampered"
        assert profile_digest(tampered) != baseline, field


def test_the_builder_reads_no_clock(dist_dir: Path) -> None:
    """Two builds of identical inputs produce identical bytes. A timestamp would
    make the digest — the only handle anyone has on which profile this is —
    differ for artifacts that are the same."""
    first = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    second = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    assert render(first) == render(second)
    assert first["profile_digest"] == second["profile_digest"]


# ── the round trip: what this builder emits is what that verifier reads ─────


def test_the_emitted_document_is_the_one_the_merged_verifier_reads(
    dist_dir: Path, tmp_path: Path
) -> None:
    """The whole point, end to end.

    The verifier shipped first and has only ever been driven against documents a
    test wrote. This drives it against one the BUILDER produced, and the verdict
    is the honest one for this artifact: eleven concerns satisfied, and the two
    ruled-unbound slots named.
    """
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    profile_path = tmp_path / "application_foundation_profile.json"
    profile_path.write_text(render(document), encoding="utf-8")

    digest = _wheel_digest(dist_dir)
    distributions = tmp_path / "distributions.json"
    distributions.write_text(
        json.dumps(
            {
                "contract": "dotmac-distribution-digests/1",
                "files": [
                    {
                        "filename": next(dist_dir.glob("*.whl")).name,
                        "size_bytes": 1,
                        "sha256": digest,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    outcome = verify_embedded_profile(
        ExpectedArtifact(source_revision=REVISION, wheel_sha256=digest),
        profile_path=profile_path,
        distributions_path=distributions,
    )
    assert outcome.verdict is ProfileVerdict.CONCERNS_INCOMPLETE, outcome.detail
    assert len(outcome.bound_concerns) == len(FOUNDATION_CONCERNS) - 2
    assert (
        set(outcome.bound_concerns) == set(FOUNDATION_CONCERNS) - DELIBERATELY_UNBOUND
    )
    for concern in sorted(DELIBERATELY_UNBOUND):
        assert concern in outcome.detail


def test_the_verifier_refuses_the_same_document_against_another_artifact(
    dist_dir: Path, tmp_path: Path
) -> None:
    """SENSITIVITY for the round trip. A well-formed document that verifies for
    this artifact must not verify for a different one, or the check above is
    satisfied by anything the builder emits."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    profile_path = tmp_path / "application_foundation_profile.json"
    profile_path.write_text(render(document), encoding="utf-8")
    distributions = tmp_path / "distributions.json"
    distributions.write_text(
        json.dumps(
            {
                "contract": "dotmac-distribution-digests/1",
                "files": [
                    {
                        "filename": "x-0.1.0-py3-none-any.whl",
                        "size_bytes": 1,
                        "sha256": _wheel_digest(dist_dir),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    outcome = verify_embedded_profile(
        ExpectedArtifact(
            source_revision="a" * 40, wheel_sha256=_wheel_digest(dist_dir)
        ),
        profile_path=profile_path,
        distributions_path=distributions,
    )
    assert outcome.verdict is ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED


def test_the_document_declares_the_contract_the_verifier_knows(
    dist_dir: Path,
) -> None:
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    assert document["contract"] == PROFILE_CONTRACT


def test_the_unbound_slots_travel_in_the_document_with_their_reasons(
    dist_dir: Path,
) -> None:
    """A short document that explains its own shortfall is reviewable; one that
    is simply short is a mystery the next reader has to reconstruct."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    unbound = document["unbound_concerns"]
    assert set(unbound) == DELIBERATELY_UNBOUND  # type: ignore[arg-type]
    assert "dotmac-kernel" in unbound["request_evidence_context"]  # type: ignore[index]
    assert "dotmac-deployment-foundation" in unbound["integration"]  # type: ignore[index]


def test_an_unbound_slot_cannot_satisfy_a_concern(
    dist_dir: Path, tmp_path: Path
) -> None:
    """The verifier counts `concerns`, never `unbound_concerns`. Asserted rather
    than assumed, because a document that explained its shortfall INTO the
    satisfied set would be the worst possible reading of this design."""
    document = build_profile_document(
        source_revision=REVISION, dist_dir=dist_dir, lock_path=LOCK
    )
    assert not set(document["concerns"]) & DELIBERATELY_UNBOUND  # type: ignore[arg-type]
