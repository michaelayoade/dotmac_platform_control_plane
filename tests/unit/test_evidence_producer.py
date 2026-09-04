"""The producer, exercised against a throwaway key before the real one exists.

Every refusal is asserted by CODE. This module has six of them, and asserting
prose on a module with more than one refusal is how four unreachable branches
shipped in this repository already -- the regex finds them and cannot pin them.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vendor_cp.deployment.evidence_producer import (
    RELEASE_EVIDENCE_SCHEMA,
    RUN_FACTS,
    EvidenceRefusal,
    EvidenceRefused,
    canonical_bytes,
    release_evidence_document,
    sign_release_evidence,
)
from vendor_cp.deployment.signers import ReleaseEvidenceSignerPointer

EXERCISED_REFUSALS = frozenset(
    {
        EvidenceRefusal.MISSING_FACT,
        EvidenceRefusal.NOT_A_COMMIT,
        EvidenceRefusal.FOREIGN_RUN,
        EvidenceRefusal.UNUSABLE_KEY_ID,
        EvidenceRefusal.UNUSABLE_SIGNATURE,
        EvidenceRefusal.PURPOSE_MISMATCH,
    }
)

KEY_ID = "platform-cp-release-evidence-2026-09"

#: The typed identity the producer now requires. Built once from the same key
#: id, so every call below names the key through the value that has already
#: refused a wrong purpose rather than through a bare string beside a callable.
SIGNER = ReleaseEvidenceSignerPointer(
    pointer="secret/dotmac/platform-cp/release-evidence-signing/primary",
    key_id=KEY_ID,
)


def _blank_key_id_signer() -> ReleaseEvidenceSignerPointer:
    """A well-formed identity that names no key.

    The pointer deliberately does not refuse this — the producer owns that
    check and has since before the type existed. Building it here is what keeps
    `UNUSABLE_KEY_ID` a reachable refusal rather than a code for a branch that
    cannot execute.
    """
    return ReleaseEvidenceSignerPointer(
        pointer="secret/dotmac/platform-cp/release-evidence-signing/primary",
        key_id="  ",
    )


def facts(**overrides: str) -> dict[str, str]:
    """A run this repository's own CI could have produced."""
    base = {
        "revision": "a" * 40,
        "repository": "michaelayoade/dotmac_platform_control_plane",
        "repository_id": "1317527604",
        "head_repository_id": "1317527604",
        "ref": "refs/heads/main",
        "run_id": "33802773801",
        "workflow": "CI",
        "conclusion": "success",
    }
    return {**base, **overrides}


def _refusal(call: Any) -> EvidenceRefusal:
    with pytest.raises(EvidenceRefused) as raised:
        call()
    return raised.value.refusal


def _verifier_decode(value: str) -> bytes:
    """The decoder on the far side, replicated so interop is PROVED not assumed.

    `bindings.Ed25519EvidenceVerifier` refuses padding, surrounding whitespace,
    and any encoding that does not round-trip to itself. A producer that emits
    padded base64 would look correct here and be rejected on the target.
    """
    if not value or value != value.strip() or "=" in value:
        raise ValueError("not canonical unpadded base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("not canonical unpadded base64url")
    return raw


def test_a_produced_envelope_verifies_with_the_matching_public_key() -> None:
    """POSITIVE CONTROL, and the only test here that proves the thing works.

    Everything else is a refusal, and a producer only ever observed refusing
    might refuse everything.
    """
    private = Ed25519PrivateKey.generate()
    envelope = sign_release_evidence(facts(), signer=SIGNER, sign=private.sign)

    signature = _verifier_decode(envelope["signature"])
    private.public_key().verify(signature, canonical_bytes(envelope["document"]))


def test_the_signature_covers_the_document_and_nothing_else() -> None:
    """SENSITIVITY for the test above: verification must FAIL on a document that
    moved, or the signature would be decorative."""
    private = Ed25519PrivateKey.generate()
    envelope = sign_release_evidence(facts(), signer=SIGNER, sign=private.sign)

    tampered = {**envelope["document"], "conclusion": "failure"}
    with pytest.raises(InvalidSignature):
        private.public_key().verify(
            _verifier_decode(envelope["signature"]), canonical_bytes(tampered)
        )


def test_the_document_is_a_nested_object_never_a_string() -> None:
    """The a4 corruption, inherited as a prohibition.

    A conforming provider once satisfied `Mapping[str, str]` by doing `str()`
    over the document, flattening the very object the signature covers into a
    Python repr. `SignedEvidenceEnvelope.document` now refuses a string at
    construction, so this producer cannot reintroduce it -- but the property is
    asserted here rather than assumed, because the type that forbids it lives in
    a package this repository does not depend on.
    """
    envelope = sign_release_evidence(
        facts(), signer=SIGNER, sign=Ed25519PrivateKey.generate().sign
    )
    assert isinstance(envelope["document"], dict)
    assert not isinstance(envelope["document"], str)
    assert envelope["document"]["schema"] == RELEASE_EVIDENCE_SCHEMA


def test_the_key_id_sits_outside_the_document() -> None:
    """A document carrying its own key id would let a forger nominate the key
    that verifies it."""
    envelope = sign_release_evidence(
        facts(), signer=SIGNER, sign=Ed25519PrivateKey.generate().sign
    )
    assert envelope["key_id"] == KEY_ID
    assert "key_id" not in envelope["document"]


@pytest.mark.parametrize("absent", RUN_FACTS)
def test_each_missing_run_fact_is_named(absent: str) -> None:
    """Parametrized over the declared facts, so one added tomorrow is covered
    the moment it is declared."""
    incomplete = facts()
    del incomplete[absent]

    with pytest.raises(EvidenceRefused) as raised:
        release_evidence_document(incomplete)
    assert raised.value.refusal is EvidenceRefusal.MISSING_FACT
    assert raised.value.facts == (absent,)


def test_a_blank_fact_is_missing_rather_than_present() -> None:
    """A CI variable that expanded to nothing is the common shape, and it
    arrives as `""` rather than as an absent key."""
    assert (
        _refusal(lambda: release_evidence_document(facts(workflow="   ")))
        is EvidenceRefusal.MISSING_FACT
    )


def test_two_blank_repository_ids_are_refused_before_they_compare_equal() -> None:
    """THE sensitivity case for the fork discriminator.

    Blank ids compare EQUAL, so a producer that reached the comparison would
    emit `from_a_fork == False` -- a confident claim that this was our own run,
    assembled from two facts nobody supplied. The missing-fact refusal must
    answer first, and it must name both.
    """
    with pytest.raises(EvidenceRefused) as raised:
        release_evidence_document(facts(repository_id="", head_repository_id=""))
    assert raised.value.refusal is EvidenceRefusal.MISSING_FACT
    assert set(raised.value.facts) == {"repository_id", "head_repository_id"}


def test_a_fork_run_is_not_signed() -> None:
    """`repository_id != head_repository_id` separates "our CI ran this" from
    "someone else's CI ran something and told us about it"."""
    assert (
        _refusal(lambda: release_evidence_document(facts(head_repository_id="99")))
        is EvidenceRefusal.FOREIGN_RUN
    )


def test_a_revision_that_is_not_a_commit_is_refused() -> None:
    assert (
        _refusal(lambda: release_evidence_document(facts(revision="HEAD")))
        is EvidenceRefusal.NOT_A_COMMIT
    )
    assert (
        _refusal(lambda: release_evidence_document(facts(revision="a" * 39)))
        is EvidenceRefusal.NOT_A_COMMIT
    )


def test_an_uppercase_revision_is_normalised_not_refused() -> None:
    """Git prints both cases and neither is wrong. Refusing one would make the
    producer fail on correct input, which teaches an operator to work around
    it."""
    document = release_evidence_document(facts(revision="A" * 40))
    assert document["revision"] == "a" * 40


def test_evidence_with_no_key_id_is_refused() -> None:
    assert (
        _refusal(
            lambda: sign_release_evidence(
                facts(),
                signer=_blank_key_id_signer(),
                sign=Ed25519PrivateKey.generate().sign,
            )
        )
        is EvidenceRefusal.UNUSABLE_KEY_ID
    )


def test_a_signer_that_returns_nothing_is_refused() -> None:
    """An empty signature would produce an envelope that looks signed."""
    assert (
        _refusal(
            lambda: sign_release_evidence(facts(), signer=SIGNER, sign=lambda _: b"")
        )
        is EvidenceRefusal.UNUSABLE_SIGNATURE
    )


def test_the_signature_is_canonical_unpadded_base64url() -> None:
    """The far side refuses padding and non-canonical encodings, so a padded
    signature would look right here and be rejected on the target."""
    envelope = sign_release_evidence(
        facts(), signer=SIGNER, sign=Ed25519PrivateKey.generate().sign
    )
    signature = envelope["signature"]
    assert "=" not in signature
    assert signature == signature.strip()
    assert len(_verifier_decode(signature)) == 64


def test_the_canonical_bytes_are_sorted_and_tight() -> None:
    """The same facts must always produce the same message, whatever order a
    caller happened to build the mapping in."""
    document = release_evidence_document(facts())
    shuffled = dict(reversed(list(document.items())))
    assert canonical_bytes(document) == canonical_bytes(shuffled)
    assert b", " not in canonical_bytes(document)
    assert json.loads(canonical_bytes(document)) == document


def test_no_refusal_code_ships_without_a_test() -> None:
    """A two-directional ratchet on the refusal vocabulary."""
    assert set(EvidenceRefusal) == EXERCISED_REFUSALS


def test_the_evidence_contract_matches_the_installed_foundation() -> None:
    """The restated contract, compared against the authority that enforces it.

    `dotmac-deployment-foundation` is deliberately not a dependency of this
    assembly, so this skips where it is absent -- and the skip NAMES the version
    it saw, so a silent pass is never mistaken for agreement.
    """
    import importlib.metadata as metadata

    try:
        installed = metadata.version("dotmac-deployment-foundation")
    except metadata.PackageNotFoundError:
        installed = "absent"
    evidence = pytest.importorskip(
        "dotmac_deployment_foundation.evidence",
        reason=(
            f"installed dotmac-deployment-foundation {installed} is not "
            "importable here; the restated contract is compared once it is"
        ),
    )
    assert RELEASE_EVIDENCE_SCHEMA == evidence.RELEASE_EVIDENCE_SCHEMA
    assert set(evidence.REQUIRED_FIELDS) == {"schema", *RUN_FACTS}

    document = release_evidence_document(facts())
    parsed = evidence.ReleaseEvidenceV1.from_document(document)
    assert parsed.canonical_bytes() == canonical_bytes(document)
    assert parsed.from_a_fork() is False


def test_an_identity_of_another_purpose_is_refused() -> None:
    """PURPOSE_MISMATCH, exercised here so the two-directional ratchet above is
    satisfied by a real refusal rather than by a name added to a set.

    This is the gap the typed identity closes: the producer took a key id and a
    signing callable as unrelated arguments, so the AUTHORIZATION key could be
    handed a release-evidence key id and nothing would object.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from vendor_cp.deployment.signers import AuthorizationSignerPointer

    authorization = AuthorizationSignerPointer(
        pointer="secret/dotmac/platform-cp/authorization-signing/primary"
    )
    with pytest.raises(EvidenceRefused) as refused:
        sign_release_evidence(
            facts(),
            signer=authorization,  # type: ignore[arg-type]
            sign=Ed25519PrivateKey.generate().sign,
        )
    assert refused.value.refusal is EvidenceRefusal.PURPOSE_MISMATCH
