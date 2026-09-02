"""The effect adapter asks Control, and refuses when it cannot.

The bypass this closes: `scripts/deploy_production.sh` took one argument and a
`sha256:` regex, and every check that made a deploy legitimate lived in the
workflow. The deploy SSH key was enough to skip all of them.
"""

from __future__ import annotations

import sys
import types

import pytest

from vendor_cp.deployment.authority import (
    CONTROL_READ_API_SYMBOLS,
    AuthorityUnavailable,
    control_read_api_status,
    require_control_approved_image,
)

DIGEST = "sha256:" + "a" * 64


def test_the_pinned_control_exports_no_read_api() -> None:
    """Measured against the installed wheel, not inferred from a version string.

    A version present in a lockfile is not evidence of what it contains — the
    lesson a5 taught by resolving cleanly, matching every hash, and dying at boot.
    """
    assert control_read_api_status() == ()


def test_the_probe_can_report_presence(monkeypatch: pytest.MonkeyPatch) -> None:
    """SENSITIVITY. An empty result is also what a broken probe returns, so the
    probe must be shown finding the symbols when they exist."""
    stand_in = types.ModuleType("dotmac_deployment_control")
    for name in CONTROL_READ_API_SYMBOLS:
        setattr(stand_in, name, object())
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", stand_in)
    assert control_read_api_status() == CONTROL_READ_API_SYMBOLS


def test_an_unreferenced_deployment_is_refused() -> None:
    """An authorization reference is not defaulted. A deployment with none is
    one nobody approved."""
    with pytest.raises(AuthorityUnavailable, match="no authorization reference"):
        require_control_approved_image(authorization_ref="   ", image_digest=DIGEST)


def test_no_read_api_means_no_image_is_authorized() -> None:
    """Fail closed. Leaving the effector ungated until the lookup exists keeps
    the bypass open for as long as it takes someone to forget."""
    with pytest.raises(AuthorityUnavailable, match="exports none of"):
        require_control_approved_image(
            authorization_ref="rollout-1", image_digest=DIGEST
        )


def test_the_capability_arriving_is_itself_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tripwire, and why it is not a stub.

    If the read API imports before the wiring is written, this still refuses —
    with a DIFFERENT reason. That is a true statement and a refusal, not a
    placeholder that could be mistaken for an implementation, and it stops a
    silently-open path appearing the moment the pin moves.
    """
    stand_in = types.ModuleType("dotmac_deployment_control")
    for name in CONTROL_READ_API_SYMBOLS:
        setattr(stand_in, name, object())
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", stand_in)

    with pytest.raises(AuthorityUnavailable, match="has not been written"):
        require_control_approved_image(
            authorization_ref="rollout-1", image_digest=DIGEST
        )


def test_success_is_the_only_silent_outcome() -> None:
    """`require_control_approved_image` returns None or raises — it never returns a
    falsy value a caller could mistake for permission. That is the failure mode
    `ApprovedPlanLookup.__bool__` exists to remove, applied one level up."""
    import inspect

    source = inspect.getsource(require_control_approved_image)
    assert "return False" not in source
    assert "return None" not in source
