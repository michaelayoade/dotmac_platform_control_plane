"""Synthetic request/window intersection regressions, never live token evidence."""

import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from test_gate0_runtime_providers import (
    jwt_case as _jwt_case,
)
from test_gate0_runtime_providers import (
    synthetic_http_only as _synthetic_http_only,
)
from test_gate0_window import (
    mutation_case as _mutation_case,
)
from test_gate0_window import (
    signed_binding as _signed_binding,
)
from test_gate0_window import (
    window_document as _window_document,
)

from vendor_cp.deployment import gate0_composition as composition
from vendor_cp.deployment import gate0_github_jwt as jwt
from vendor_cp.deployment import gate0_workload_admission as admission
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
)
from vendor_cp.deployment.gate0_window import (
    AuthenticatedApprovalWithdrawal,
    OwnerWindowWithdrawal,
)

jwt_case = _jwt_case
synthetic_http_only = _synthetic_http_only
mutation_case = _mutation_case
signed_binding = _signed_binding
window_document = _window_document


def test_legacy_exp_beyond_window_is_bounded_by_original_intersection(jwt_case):  # noqa: F811
    provider, window, _, token = jwt_case
    now = int(datetime.now(UTC).timestamp())
    result = provider.admit(token({"exp": now + 300}), "issue", UUID(int=1))
    assert replace(result, authentication_freshness=None) == window.expectation
    assert (
        result.authentication_freshness.deadline
        <= provider._window_deadlines[("issue", str(UUID(int=1)))]
    )
    assert provider.window_record_digest(result) == window.authority_record_digest


def test_expiry_during_jwks_cannot_become_authenticated(jwt_case, monkeypatch):  # noqa: F811
    provider, _, transport, token = jwt_case
    base = datetime.now(UTC)
    elapsed = [0]
    original = transport.request

    class ClockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return base + timedelta(seconds=elapsed[0])

    def response(*a, **k):
        result = original(*a, **k)
        elapsed[0] = 6
        return result

    monkeypatch.setattr(transport, "request", response)
    monkeypatch.setattr(jwt, "datetime", ClockDateTime)
    with pytest.raises(ProviderRefused):
        provider.admit(token({"exp": int(base.timestamp()) + 5}), "issue", UUID(int=1))


@pytest.mark.parametrize("withdrawn", [False, True])
@pytest.mark.parametrize("expire_during_read", [False, True])
def test_owner_read_checks_request_intersection_after_cleanup_boundary(
    signed_binding,
    monkeypatch,
    withdrawn,
    expire_during_read,  # noqa: F811
):
    binding, *_ = signed_binding
    base = datetime.now(UTC)
    origin = time.monotonic()
    elapsed = [0]

    class ClockDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return base + timedelta(seconds=elapsed[0])

    monkeypatch.setattr(admission, "datetime", ClockDateTime)
    monkeypatch.setattr(composition, "datetime", ClockDateTime)
    monkeypatch.setattr(admission.time, "monotonic", lambda: origin + elapsed[0])
    monkeypatch.setattr(composition, "monotonic", lambda: origin + elapsed[0])
    provider = object.__new__(admission.OwnerWorkloadAdmission)
    provider._origin, provider._started_at = origin, base
    provider._deadline, provider._expires = origin + 90, base + timedelta(seconds=90)
    provider._attempts, provider._transport = 0, object()
    claims = dict(
        binding.window.document["github"],
        iat=int(base.timestamp()),
        nbf=int(base.timestamp()),
        exp=int(base.timestamp()) + (5 if expire_during_read else 300),
    )
    monkeypatch.setattr(provider, "_claims", lambda token: claims)
    denial = OwnerWindowWithdrawal(
        window=binding.window,
        plan_id=UUID(binding.expectation.operation.plan_id),
        request_id=binding.expectation.approval_request_id,
        content_digest=binding.expectation.operation.plan_digest,
        phase="issue",
        freshness=binding.expectation.window_freshness,
    )

    def read(*a):
        if expire_during_read:
            elapsed[0] = 6
        if withdrawn:
            raise denial
        return binding

    provider._reader = SimpleNamespace(read=read)
    if expire_during_read:
        with pytest.raises(ProviderRefused) as caught:
            provider.admit("synthetic", "issue", denial.plan_id)
        assert not isinstance(caught.value, AuthenticatedApprovalWithdrawal)
    elif withdrawn:
        with pytest.raises(AuthenticatedApprovalWithdrawal) as caught:
            provider.admit("synthetic", "issue", denial.plan_id)
        assert caught.value.denial.freshness is binding.expectation.window_freshness
        assert caught.value.authentication_freshness is not None
    else:
        result = provider.admit("synthetic", "issue", denial.plan_id)
        assert result.window_freshness is binding.expectation.window_freshness
        assert result.authentication_freshness is not result.window_freshness


def test_approved_start_snapshot_retains_original_window_and_request_cap(
    signed_binding, monkeypatch
):  # noqa: F811
    binding, identity, verifier, *_ = signed_binding
    provider = admission.ApprovedAtStartAdmission(
        binding=binding,
        issuer_identity=identity,
        authorization_verifier=verifier,
        transport=BoundedJSONTransport(admission.GITHUB_ISSUER),
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )
    stamp = int(datetime.now(UTC).timestamp())
    claims = dict(
        binding.window.document["github"], iat=stamp, nbf=stamp, exp=stamp + 300
    )
    monkeypatch.setattr(provider, "_claims", lambda token: claims)
    first = provider.admit(
        "synthetic", "issue", UUID(binding.expectation.operation.plan_id)
    )
    second = provider.admit(
        "synthetic", "issue", UUID(binding.expectation.operation.plan_id)
    )
    assert first.window_freshness is second.window_freshness
    assert first.authentication_freshness is not second.authentication_freshness
    assert first.authentication_freshness.deadline <= provider._deadline
    assert provider.window_record_digest(first) == binding.window.digest
    claims["exp"] = stamp - 1
    with pytest.raises(ProviderRefused):
        provider.admit(
            "synthetic", "issue", UUID(binding.expectation.operation.plan_id)
        )


@pytest.mark.parametrize("late_stage", ["transition", "close"])
def test_request_expiry_before_commit_rolls_back_and_after_commit_is_incomplete(
    mutation_case,
    monkeypatch,
    late_stage,  # noqa: F811
):
    driver, _, expected, events, _ = mutation_case
    origin = time.monotonic()
    clock = [origin]
    authentication = composition.RequestAuthenticationFreshness(
        origin, origin + 10, datetime.now(UTC) + timedelta(seconds=10)
    )
    expected = replace(expected, authentication_freshness=authentication)
    monkeypatch.setattr(composition, "monotonic", lambda: clock[0])

    def transition(db):
        events.append("transition")
        if late_stage == "transition":
            clock[0] = origin + 11
        else:

            def close():
                events.append("close")
                clock[0] = origin + 11

            db.close = close
        return composition.PhaseResult("sha256:" + "c" * 64, "authorization", "lease")

    error = (
        composition.CompositionRefused
        if late_stage == "transition"
        else composition.CompositionIncomplete
    )
    with pytest.raises(error):
        driver._mutate(expected, None, transition)
    assert events == (
        ["transition", "rollback", "close"]
        if late_stage == "transition"
        else ["transition", "commit", "close"]
    )
    assert expected.window_freshness is not authentication


def test_proof_completion_after_request_expiry_is_not_registered(
    mutation_case, monkeypatch
):  # noqa: F811
    driver, _, expected, _, _ = mutation_case
    origin = time.monotonic()
    clock = [origin]
    authentication = composition.RequestAuthenticationFreshness(
        origin, origin + 10, datetime.now(UTC) + timedelta(seconds=10)
    )
    expected = replace(expected, authentication_freshness=authentication)
    monkeypatch.setattr(composition, "monotonic", lambda: clock[0])

    def resolver(packet):
        assert packet.window_freshness is expected.window_freshness
        assert packet.authentication_freshness is authentication
        clock[0] = origin + 11
        return object()

    driver._resolver = resolver
    driver._verifier._register = lambda *a: pytest.fail("expired proof became eligible")
    with pytest.raises(composition.CompositionRefused):
        driver._proof(expected)


@pytest.mark.parametrize("bad", ["future_nbf", "signature"])
def test_shared_verifier_keeps_nbf_and_signature_policy(jwt_case, bad):  # noqa: F811
    provider, _, _, token = jwt_case
    if bad == "future_nbf":
        value = token({"nbf": int(datetime.now(UTC).timestamp()) + 10})
    else:
        value = token()
        parts = value.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        value = ".".join(parts)
    with pytest.raises(ProviderRefused):
        provider.admit(value, "issue", UUID(int=1))
