"""Two purposes, two keys, and the refusals that keep them apart.

An observation signed by the authorization key cannot contradict the
authorization — which is the only reason the observation exists.

Every refusal here is asserted by CODE, never by prose. The first cut of this
suite matched on the message and found the bug it was written to find: three
tests refused the licensing pointer and passed while the by-value branch they
named had never run, because the namespace check answered first. `match=` was
the right instrument for finding that and the wrong one for pinning it — a
reworded sentence stops a prose assertion discriminating, silently.
"""

from __future__ import annotations

import pytest

from vendor_cp.deployment.signers import (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    FORBIDDEN_SIGNING_POINTERS,
    POINTER_PREFIX,
    RELEASE_EVIDENCE_PURPOSE,
    AuthorizationSignerPointer,
    ObservationSignerPointer,
    ReleaseEvidenceSignerPointer,
    SignerPointerRefused,
    SignerRefusal,
    require_distinct_signers,
)

AUTH = "secret/dotmac/platform-cp/authorization-signing/primary"
OBS = "secret/dotmac/platform-cp/target-observation-signing/primary"
RELEASE = "secret/dotmac/platform-cp/release-evidence-signing/primary"

#: The refusal codes this file actually drives, maintained by hand beside the
#: tests that drive them. Ratcheted in both directions against the enum below,
#: so a fifth code cannot ship untested and a retired one cannot linger here.
EXERCISED_REFUSALS = frozenset(
    {
        SignerRefusal.FORBIDDEN_POINTER,
        SignerRefusal.FOREIGN_NAMESPACE,
        SignerRefusal.PURPOSE_MISMATCH,
        SignerRefusal.SHARED_POINTER,
    }
)


def test_no_refusal_code_ships_without_a_test() -> None:
    """A vocabulary ratchet. A new `SignerRefusal` member fails here until it is
    added above, which is the moment to notice it has no test yet."""
    assert set(SignerRefusal) == EXERCISED_REFUSALS


def test_the_two_pointers_are_admitted() -> None:
    """SENSITIVITY. Every other test here is a refusal, and a validator only
    ever observed refusing might refuse everything."""
    assert AuthorizationSignerPointer(AUTH).purpose == AUTHORIZATION_PURPOSE
    assert ObservationSignerPointer(OBS).purpose == EXECUTION_OBSERVATION_PURPOSE
    assert ReleaseEvidenceSignerPointer(RELEASE).purpose == RELEASE_EVIDENCE_PURPOSE


def test_every_forbidden_pointer_is_refused_by_value_whatever_its_namespace() -> None:
    """The property this module exists for, and the one that shipped dead.

    One key covering licence issuance and deployment permission means a party
    able to mint a licence can mint a deployment authorization. Asserting the
    CODE is what makes this test able to fail: a bare
    `pytest.raises(SignerPointerRefused)` passes just as happily when the
    namespace check answers first and the by-value comparison never runs.
    """
    assert FORBIDDEN_SIGNING_POINTERS, "an empty forbidden set refuses nothing"
    for pointer in FORBIDDEN_SIGNING_POINTERS:
        for factory in (
            AuthorizationSignerPointer,
            ObservationSignerPointer,
            ReleaseEvidenceSignerPointer,
        ):
            with pytest.raises(SignerPointerRefused) as refused:
                factory(pointer)
            assert refused.value.refusal is SignerRefusal.FORBIDDEN_POINTER


def test_the_by_value_refusal_is_not_shadowed_by_the_namespace_check() -> None:
    """SENSITIVITY for the test above, and the whole reason it can bite.

    That test only proves the check order while some forbidden pointer is ALSO
    foreign. If every forbidden pointer moved under this product's own prefix,
    the namespace check could return in front of the by-value check again and
    nothing would notice — the guard would pass for the wrong reason a second
    time.
    """
    foreign_and_forbidden = {
        pointer
        for pointer in FORBIDDEN_SIGNING_POINTERS
        if not pointer.startswith(POINTER_PREFIX)
    }
    assert foreign_and_forbidden, (
        "no forbidden pointer is foreign, so nothing here proves the by-value "
        "check runs before the namespace check"
    )


@pytest.mark.parametrize(
    "foreign",
    (
        "secret/dotmac/vendor-control-plane/production/database",
        "secret/dotmac/other-product/authorization-signing/primary",
        "authorization-signing/primary",
    ),
)
def test_a_pointer_outside_this_products_space_is_refused(foreign: str) -> None:
    """A pointer elsewhere is another owner's key being borrowed.

    POSITIVE CONTROL for the ordering fix: the namespace refusal must still be
    reachable. These are deliberately pointers that are foreign and NOT
    forbidden — the licensing key belongs to the by-value test above, and
    asserting `FOREIGN_NAMESPACE` for it here is the exact confusion this suite
    now refuses to make.
    """
    with pytest.raises(SignerPointerRefused) as refused:
        AuthorizationSignerPointer(foreign)
    assert refused.value.refusal is SignerRefusal.FOREIGN_NAMESPACE


def test_a_signer_may_not_declare_the_other_purpose() -> None:
    """The purposes are not interchangeable, and swapping them is the exact
    mistake the separation exists to prevent."""
    with pytest.raises(SignerPointerRefused) as authorization:
        AuthorizationSignerPointer(AUTH, purpose=EXECUTION_OBSERVATION_PURPOSE)
    assert authorization.value.refusal is SignerRefusal.PURPOSE_MISMATCH
    with pytest.raises(SignerPointerRefused) as observation:
        ObservationSignerPointer(OBS, purpose=AUTHORIZATION_PURPOSE)
    assert observation.value.refusal is SignerRefusal.PURPOSE_MISMATCH
    with pytest.raises(SignerPointerRefused) as release:
        ReleaseEvidenceSignerPointer(RELEASE, purpose=AUTHORIZATION_PURPOSE)
    assert release.value.refusal is SignerRefusal.PURPOSE_MISMATCH


def test_one_pointer_cannot_serve_both_purposes() -> None:
    """The rule neither dataclass can see on its own. A pair naming one pointer
    twice satisfies every per-class refusal and still collapses the two
    questions into one key."""
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH),
        ObservationSignerPointer(OBS),
        ReleaseEvidenceSignerPointer(RELEASE),
    )
    same = "secret/dotmac/platform-cp/shared/primary"
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(
            AuthorizationSignerPointer(same),
            ObservationSignerPointer(OBS),
            ReleaseEvidenceSignerPointer(same),
        )
    assert refused.value.refusal is SignerRefusal.SHARED_POINTER


def test_no_key_material_can_be_held_here() -> None:
    """The seam carries pointers. A field able to hold a secret would make this
    module a place where one could come to rest."""
    for pointer in (
        AuthorizationSignerPointer(AUTH),
        ObservationSignerPointer(OBS),
        ReleaseEvidenceSignerPointer(RELEASE),
    ):
        assert set(type(pointer).__dataclass_fields__) == {"pointer", "purpose"}


def test_signer_purposes_match_the_installed_control() -> None:
    """Restated constants must not drift from the authority that enforces them.

    Compared against the installed distribution rather than a changelog. Skipped
    only where Control predates the purpose split — and the skip says which
    version it saw, so a silent pass is not mistaken for agreement.
    """
    import importlib.metadata as metadata

    try:
        installed = metadata.version("dotmac-deployment-control")
    except metadata.PackageNotFoundError:  # pragma: no cover - hard dependency
        installed = "absent"
    reason = (
        f"installed dotmac-deployment-control {installed} predates the purpose "
        "split; these constants are compared once it is pinned"
    )
    control_authorization = pytest.importorskip(
        "dotmac_deployment_control.authorization", reason=reason
    )
    control_observation = pytest.importorskip(
        "dotmac_deployment_control.execution_observation", reason=reason
    )
    assert AUTHORIZATION_PURPOSE == control_authorization.AUTHORIZATION_PURPOSE
    assert (
        EXECUTION_OBSERVATION_PURPOSE
        == control_observation.EXECUTION_OBSERVATION_PURPOSE
    )
