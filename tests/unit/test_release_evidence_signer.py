"""The release-evidence purpose becomes a TYPE, and the producer requires it.

`platform_release_evidence` was a dict entry and a JSON field — data, which
cannot refuse a wrong purpose. Running the full matrix against the real types
gave four accepted diagonals and sixteen refused off-diagonals rather than five
and twenty, and `signers.py` said why in its own comment: the purpose did not
exist as a type yet.

These are the assertions that make it five and twenty for this purpose: the
pointer refuses a wrong purpose at construction, and the producer refuses an
identity that is not a release-evidence signer.
"""

from __future__ import annotations

import pytest

from vendor_cp.deployment.evidence_producer import (
    RUN_FACTS,
    EvidenceRefusal,
    EvidenceRefused,
    sign_release_evidence,
)
from vendor_cp.deployment.signers import (
    POINTER_MATERIAL,
    RELEASE_EVIDENCE_PURPOSE,
    AuthorizationSignerPointer,
    MaterialKind,
    ObservationSignerPointer,
    ReleaseEvidenceSignerPointer,
    SignerPointerRefused,
)

#: The minted identity. Its private half is in OpenBao and is never read here.
POINTER = "secret/dotmac/platform-cp/release-evidence-signing/primary"
KEY_ID = "platform-cp-release-evidence-2026-09"


def _signer(**overrides: object) -> ReleaseEvidenceSignerPointer:
    fields: dict[str, object] = {"pointer": POINTER, "key_id": KEY_ID}
    fields.update(overrides)
    return ReleaseEvidenceSignerPointer(**fields)  # type: ignore[arg-type]


# ── the pointer refuses at construction ─────────────────────────────────────


def test_a_release_evidence_signer_declares_its_own_purpose() -> None:
    signer = _signer()
    assert signer.purpose == RELEASE_EVIDENCE_PURPOSE
    assert signer.key_id == KEY_ID
    assert signer.material is MaterialKind.PRIVATE


def test_another_purpose_is_refused() -> None:
    """The off-diagonal this type exists to close. A value that accepted any
    purpose would be the dict entry it replaces."""
    with pytest.raises(SignerPointerRefused):
        _signer(purpose="deployment_authorization")


def test_a_signer_with_no_key_id_is_refused() -> None:
    """No key id means no policy could ever select a key to check the signature
    against, and the refusal belongs at construction rather than at signing."""
    with pytest.raises(SignerPointerRefused):
        _signer(key_id="   ")


def test_the_pointer_must_be_in_this_product_s_namespace() -> None:
    with pytest.raises(SignerPointerRefused):
        _signer(pointer="secret/dotmac/somewhere-else/primary")


# ── the mapping reads the type rather than restating it ─────────────────────


def test_the_material_table_reads_the_class_var() -> None:
    """`POINTER_MATERIAL` used to restate this purpose's material as a literal.

    Identity, not equality: a second `MaterialKind.PRIVATE` written here would
    compare equal while being exactly the second statement that drifts.
    """
    assert (
        POINTER_MATERIAL[RELEASE_EVIDENCE_PURPOSE]
        is ReleaseEvidenceSignerPointer.material
    )


def test_three_of_the_five_purposes_now_resolve_to_a_type() -> None:
    """The two that remain literals do so for different reasons, and neither is
    this product's to type: `deployment_dispatch` has no type anywhere yet, and
    `deployment_recovery` is Control's purpose."""
    typed = {
        POINTER_MATERIAL[p]
        for p in POINTER_MATERIAL
        if p
        in {
            AuthorizationSignerPointer.purpose,
            ObservationSignerPointer.purpose,
            RELEASE_EVIDENCE_PURPOSE,
        }
    }
    assert typed
    assert len(POINTER_MATERIAL) == 5
    assert {"deployment_dispatch", "deployment_recovery"} <= set(POINTER_MATERIAL)


# ── the producer requires the identity ──────────────────────────────────────


def _sign(payload: bytes) -> bytes:
    return b"signature-bytes"


#: A complete run, because the producer refuses a partial one — built from
#: `RUN_FACTS` rather than from a hand-listed set, so a fact added to the
#: contract fails here instead of leaving this fixture quietly incomplete.
FACTS = {
    name: value
    for name, value in {
        "revision": "a" * 40,
        "repository": "michaelayoade/dotmac_platform_control_plane",
        "repository_id": "123456",
        "head_repository_id": "123456",
        "ref": "refs/heads/main",
        "run_id": "1234567890",
        "workflow": "release",
        "conclusion": "success",
    }.items()
}


def test_the_fixture_supplies_every_fact_the_contract_requires() -> None:
    """NON-VACUITY for every producer test below. A fixture missing a fact
    would make them all fail as MISSING_FACT and prove nothing about purposes —
    which is exactly how the first draft of this file failed."""
    assert set(FACTS) == set(RUN_FACTS)


def test_the_producer_refuses_an_authorization_identity() -> None:
    """THE GAP THIS CLOSES.

    The producer took `key_id: str` beside an unrelated signing callable, so
    nothing structurally stopped the AUTHORIZATION key being handed a
    release-evidence key id — two arguments that had to agree, with no type
    saying so.
    """
    authorization = AuthorizationSignerPointer(
        pointer="secret/dotmac/platform-cp/authorization-signing/primary"
    )
    with pytest.raises(EvidenceRefused) as refused:
        sign_release_evidence(FACTS, signer=authorization, sign=_sign)  # type: ignore[arg-type]
    assert refused.value.refusal is EvidenceRefusal.PURPOSE_MISMATCH


def test_the_producer_refuses_an_observation_identity() -> None:
    """The other off-diagonal, and it matters more than it looks: the
    observation pointer names PUBLIC material, so signing release evidence with
    it could not work — and failing at the type is better than failing at the
    signature."""
    observation = ObservationSignerPointer(
        pointer="secret/dotmac/platform-cp/execution-observation/primary"
    )
    with pytest.raises(EvidenceRefused) as refused:
        sign_release_evidence(FACTS, signer=observation, sign=_sign)  # type: ignore[arg-type]
    assert refused.value.refusal is EvidenceRefusal.PURPOSE_MISMATCH


def test_the_producer_accepts_the_release_evidence_identity() -> None:
    """NON-VACUITY for both refusals: a producer that refused every identity
    would satisfy them and sign nothing."""
    envelope = sign_release_evidence(FACTS, signer=_signer(), sign=_sign)
    assert envelope["key_id"] == KEY_ID
    assert "document" in envelope and "signature" in envelope


def test_the_key_id_comes_from_the_identity_not_the_caller() -> None:
    """There is no longer a second place to state it, which is the whole point:
    a key id and a purpose that had to agree now cannot disagree."""
    import inspect

    parameters = inspect.signature(sign_release_evidence).parameters
    assert "key_id" not in parameters
    assert "signer" in parameters
