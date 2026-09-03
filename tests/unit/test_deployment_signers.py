"""Two purposes, two keys, and the refusals that keep them apart.

An observation signed by the authorization key cannot contradict the
authorization — which is the only reason the observation exists.
"""

from __future__ import annotations

import pytest

from vendor_cp.deployment.signers import (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    FORBIDDEN_SIGNING_POINTERS,
    AuthorizationSignerPointer,
    ObservationSignerPointer,
    SignerPointerRefused,
    require_distinct_signers,
)

AUTH = "secret/dotmac/platform-cp/authorization-signing/primary"
OBS = "secret/dotmac/platform-cp/target-observation-signing/primary"


def test_the_two_pointers_are_admitted() -> None:
    """SENSITIVITY. Every other test here is a refusal, and a validator only
    ever observed refusing might refuse everything."""
    assert AuthorizationSignerPointer(AUTH).purpose == AUTHORIZATION_PURPOSE
    assert ObservationSignerPointer(OBS).purpose == EXECUTION_OBSERVATION_PURPOSE


def test_neither_signer_may_name_the_licensing_key() -> None:
    """One key covering licence issuance and deployment permission means a party
    able to mint a licence can mint a deployment authorization."""
    licensing = next(iter(FORBIDDEN_SIGNING_POINTERS))
    for factory in (AuthorizationSignerPointer, ObservationSignerPointer):
        with pytest.raises(SignerPointerRefused):
            factory(licensing)


def test_the_licensing_pointer_is_refused_by_value_not_by_name() -> None:
    """Aliasing the constant must not defeat the refusal, so the check compares
    the pointer string itself."""
    aliased = "secret/dotmac/licensing/signing-key"
    assert aliased in FORBIDDEN_SIGNING_POINTERS
    with pytest.raises(SignerPointerRefused, match="licence"):
        AuthorizationSignerPointer(aliased)


@pytest.mark.parametrize(
    "foreign",
    (
        "secret/dotmac/licensing/signing-key",
        "secret/dotmac/vendor-control-plane/production/database",
        "secret/dotmac/other-product/authorization-signing/primary",
        "authorization-signing/primary",
    ),
)
def test_a_pointer_outside_this_products_space_is_refused(foreign: str) -> None:
    """A pointer elsewhere is another owner's key being borrowed."""
    with pytest.raises(SignerPointerRefused):
        AuthorizationSignerPointer(foreign)


def test_a_signer_may_not_declare_the_other_purpose() -> None:
    """The purposes are not interchangeable, and swapping them is the exact
    mistake the separation exists to prevent."""
    with pytest.raises(SignerPointerRefused):
        AuthorizationSignerPointer(AUTH, purpose=EXECUTION_OBSERVATION_PURPOSE)
    with pytest.raises(SignerPointerRefused):
        ObservationSignerPointer(OBS, purpose=AUTHORIZATION_PURPOSE)


def test_one_pointer_cannot_serve_both_purposes() -> None:
    """The rule neither dataclass can see on its own. A pair naming one pointer
    twice satisfies every per-class refusal and still collapses the two
    questions into one key."""
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH), ObservationSignerPointer(OBS)
    )
    same = "secret/dotmac/platform-cp/shared/primary"
    with pytest.raises(SignerPointerRefused, match="echo rather than evidence"):
        require_distinct_signers(
            AuthorizationSignerPointer(same), ObservationSignerPointer(same)
        )


def test_no_key_material_can_be_held_here() -> None:
    """The seam carries pointers. A field able to hold a secret would make this
    module a place where one could come to rest."""
    for pointer in (AuthorizationSignerPointer(AUTH), ObservationSignerPointer(OBS)):
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
