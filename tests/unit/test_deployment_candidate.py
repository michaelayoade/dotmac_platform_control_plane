"""The candidate is derived from the accepted descriptor and a verified receipt.

Six properties, and each one is a way the derivation could look correct and
authorize the wrong bytes. What these tests do NOT do is re-derive a digest:
canonicalization belongs to `dotmac-deployment-foundation`, a second
implementation of it would be a second answer to what was authorized, and the
Foundation proves its own byte-level rules in its own suite. What is proven here
is everything this assembly owns — which inputs reach the renderer, and which
inputs are refused before they get there.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from vendor_cp.deployment.candidate import (
    CandidateImage,
    CandidateRefused,
    RegistryObservation,
    ReleaseReceiptV1,
    RenderedCandidate,
    admit_candidate_image,
    render_candidate,
)

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / "deploy" / "product.toml"

#: The real receipt `production-image.yml` emitted for `320037e8`, trimmed to
#: the fields this parser reads. Real values, so a shape that only works on
#: invented data fails here rather than in a window.
RECEIPT = {
    "contract": "dotmac-candidate-release-receipt/1",
    "source_revision": "320037e8ea78118f2cd371b0396e6972e057350e",
    "ci_run_id": "33530646875",
    "release_run_id": "33530877905",
    "registry_digest": (
        "sha256:10d8836015f3b9c9c68c8735cad10f6df75147e0e50edec7ddf1fb90a09405f8"
    ),
    "reference": (
        "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:"
        "10d8836015f3b9c9c68c8735cad10f6df75147e0e50edec7ddf1fb90a09405f8"
    ),
    "config_digest": (
        "sha256:54694d8f6743d505fa7be87bad60c327cf4856d13376a27db7be07033345cc4b"
    ),
    "registry_config_digest": (
        "sha256:54694d8f6743d505fa7be87bad60c327cf4856d13376a27db7be07033345cc4b"
    ),
    "rootfs_chain": (
        "sha256:da83f38fd1af97fe9301a83023d510fedc5db189037bdd4b4be14c60fc890ff5"
    ),
}


def _observation(receipt: ReleaseReceiptV1) -> RegistryObservation:
    return RegistryObservation(
        manifest_digest=receipt.registry_digest,
        revision_label=receipt.source_revision,
    )


@dataclass
class _Spy:
    """Records what crossed the port. NOT a canonicalizer.

    It computes nothing and hashes nothing; it exists so a test can assert which
    values were handed to the Foundation without this repository acquiring a
    second opinion about what those values mean.
    """

    calls: list[dict[str, object]] = field(default_factory=list)

    def __call__(
        self,
        *,
        descriptor_path: str,
        image: CandidateImage,
        target: str,
        operation: str,
        prestate: Mapping[str, object],
    ) -> RenderedCandidate:
        self.calls.append(
            {
                "descriptor_path": descriptor_path,
                "image_reference": image.reference,
                "source_revision": image.source_revision,
                "target": target,
                "operation": operation,
                "prestate": dict(prestate),
            }
        )
        return RenderedCandidate("sha256:" + "0" * 64, "sha256:" + "1" * 64, b"{}")


def _render(receipt_document: dict[str, str], spy: _Spy) -> None:
    receipt = ReleaseReceiptV1.from_document(receipt_document)
    image = admit_candidate_image(receipt, _observation(receipt))
    render_candidate(
        str(DESCRIPTOR),
        image,
        target="vendor-cp-prod",
        operation="deploy",
        prestate={
            "roles": [
                {
                    "role": "app",
                    "image_digest": "sha256:" + "9" * 64,
                }
            ]
        },
        renderer=spy,
    )


# ── 1 ───────────────────────────────────────────────────────────────────────


def test_the_same_descriptor_and_receipt_derive_the_same_candidate() -> None:
    """Determinism is what makes recomputing before execution a CHECK.

    If the derivation could differ between the authorization and the execution,
    a mismatch at execution time would mean nothing, and the whole recompute
    step would be ceremony.
    """
    spy = _Spy()
    _render(dict(RECEIPT), spy)
    _render(dict(RECEIPT), spy)

    assert len(spy.calls) == 2
    assert spy.calls[0] == spy.calls[1]


# ── 2 ───────────────────────────────────────────────────────────────────────


def test_a_different_image_or_revision_derives_a_different_candidate() -> None:
    """BOTH halves, because they fail independently.

    A rebuilt artifact from the same source and the same artifact claimed for a
    different source are different mistakes, and a derivation that noticed only
    one of them would authorize the other.
    """
    spy = _Spy()
    _render(dict(RECEIPT), spy)

    other_digest = "sha256:" + "b" * 64
    rebuilt = dict(RECEIPT)
    rebuilt["registry_digest"] = other_digest
    rebuilt["reference"] = (
        "ghcr.io/michaelayoade/dotmac_vendor_control_plane@" + other_digest
    )
    _render(rebuilt, spy)

    relabelled = dict(RECEIPT)
    relabelled["source_revision"] = "a" * 40
    _render(relabelled, spy)

    baseline, changed_image, changed_revision = spy.calls
    assert changed_image["image_reference"] != baseline["image_reference"]
    assert changed_image["source_revision"] == baseline["source_revision"]
    assert changed_revision["source_revision"] != baseline["source_revision"]
    assert changed_revision["image_reference"] == baseline["image_reference"]
    # Three distinct inputs to the canonicalizer, which is the property this
    # assembly owns. That distinct inputs yield distinct digests is the
    # Foundation's own rule, proven where that rule lives.
    assert len({tuple(sorted(call.items())) for call in spy.calls}) == 3


# ── 3 ───────────────────────────────────────────────────────────────────────


def test_a_receipt_whose_reference_does_not_name_its_digest_is_refused() -> None:
    """One deployment would run the reference and the record would name the digest."""
    forged = dict(RECEIPT)
    forged["reference"] = (
        "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "c" * 64
    )
    with pytest.raises(CandidateRefused, match="does not name its own digest"):
        ReleaseReceiptV1.from_document(forged)


def test_a_receipt_in_an_unknown_contract_is_refused() -> None:
    """A receipt this code cannot read is not one it may act on."""
    alien = dict(RECEIPT)
    alien["contract"] = "some-other-receipt/9"
    with pytest.raises(CandidateRefused, match="unknown release receipt contract"):
        ReleaseReceiptV1.from_document(alien)


# ── 4 ───────────────────────────────────────────────────────────────────────


def test_a_registry_read_back_that_disagrees_with_the_receipt_is_refused() -> None:
    """Both directions of the read-back, because they catch different substitutions."""
    receipt = ReleaseReceiptV1.from_document(dict(RECEIPT))

    with pytest.raises(CandidateRefused, match="different bytes"):
        admit_candidate_image(
            receipt,
            RegistryObservation(
                manifest_digest="sha256:" + "d" * 64,
                revision_label=receipt.source_revision,
            ),
        )

    with pytest.raises(CandidateRefused, match="describes a different build"):
        admit_candidate_image(
            receipt,
            RegistryObservation(
                manifest_digest=receipt.registry_digest,
                revision_label="e" * 40,
            ),
        )


def test_a_matching_read_back_is_admitted() -> None:
    """SENSITIVITY. Every assertion above is a refusal, and a validator only ever
    observed refusing might refuse everything."""
    receipt = ReleaseReceiptV1.from_document(dict(RECEIPT))
    image = admit_candidate_image(receipt, _observation(receipt))
    assert image.reference == receipt.reference
    assert image.source_revision == receipt.source_revision


# ── 5 ───────────────────────────────────────────────────────────────────────


def test_deriving_a_candidate_never_writes_the_accepted_descriptor() -> None:
    """`deploy/product.toml` is unchanged before a successful execution.

    Checked on the bytes rather than on the module's intent: the file is read,
    a candidate is derived, and the file is compared with what it was. Git
    records the deployed image AFTER the fact, as a projection of a completed
    deployment rather than as permission for one (ADR-0017 s 2).
    """
    before = DESCRIPTOR.read_bytes()
    spy = _Spy()
    _render(dict(RECEIPT), spy)
    assert DESCRIPTOR.read_bytes() == before
    assert spy.calls, "the derivation did not run, so this proves nothing"


def test_the_derivation_module_contains_no_write_of_the_descriptor() -> None:
    """The property above, stated over the code as well as over one run.

    A single run leaving the file alone is consistent with a write on a branch
    that run did not take.
    """
    source = (ROOT / "src" / "vendor_cp" / "deployment" / "candidate.py").read_text(
        encoding="utf-8"
    )
    for forbidden in ("write_text", "write_bytes", "open(", "shutil.copy"):
        assert forbidden not in source, f"the derivation writes: {forbidden}"


# ── 6 ───────────────────────────────────────────────────────────────────────


def test_no_operator_supplied_image_reference_can_reach_the_plan() -> None:
    """The override is a SHAPE, not a rule somebody remembers.

    `CandidateImage` needs a witness only `admit_candidate_image` holds, so a
    caller with a reference string has nothing to construct one with.
    """
    with pytest.raises(CandidateRefused, match="only be produced by"):
        CandidateImage(
            object(),  # type: ignore[arg-type]
            "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "f" * 64,
            "f" * 40,
        )


def test_a_candidate_with_no_target_is_refused() -> None:
    """A plan with no target authorizes every host."""
    receipt = ReleaseReceiptV1.from_document(dict(RECEIPT))
    image = admit_candidate_image(receipt, _observation(receipt))
    with pytest.raises(CandidateRefused, match="authorizes every host"):
        render_candidate(
            str(DESCRIPTOR),
            image,
            target="  ",
            operation="deploy",
            prestate={"roles": []},
            renderer=_Spy(),
        )
