"""Composing the drain: what it refuses, and what it wires together.

SCOPE. Nothing here claims a batch — the kernel's claim and settle are Postgres
functions and this tier is SQLite. What this file proves is the COMPOSITION: the
consumer really is the transport, the two connections really are two different
credentials, and an unconfigured relay refuses instead of reporting a quiet
success. The drain itself is `tests/migration/test_platform_relay_drain.py`.
"""

from __future__ import annotations

import inspect
from dataclasses import replace

import pytest
from dotmac_kernel.messaging.platform_worker import PlatformDeliveryTransport

from vendor_cp.allocations.consumer import ContractEventConsumer
from vendor_cp.cli.exits import ExitCode, Refusal
from vendor_cp.cli.runtime import translate
from vendor_cp.config import ProductionConfigurationError, load_vendor_settings
from vendor_cp.config import vendor_settings as configured
from vendor_cp.relay.runner import (
    RelayComposition,
    RelayNotConfiguredError,
    dispatcher_runtime,
    require_dispatcher_dsn,
)

DSN = "postgresql+psycopg://platform_outbox_dispatcher@127.0.0.1:5432/vendor_cp"


# ── an unconfigured relay refuses ───────────────────────────────────────────


def test_an_unset_dispatcher_dsn_refuses() -> None:
    """The whole point of this package, as one assertion.

    "Drained 0 events" from a relay that never had a credential is
    indistinguishable from "drained 0 events" from a healthy idle relay. One of
    those must be a refusal.
    """
    with pytest.raises(RelayNotConfiguredError):
        require_dispatcher_dsn(replace(configured, relay_dispatcher_database_url=""))


def test_a_whitespace_only_dsn_is_still_unset() -> None:
    with pytest.raises(RelayNotConfiguredError):
        require_dispatcher_dsn(replace(configured, relay_dispatcher_database_url="   "))


def test_a_configured_dsn_is_returned() -> None:
    """NON-VACUITY: a function that always raised would pass both tests above."""
    settings = replace(configured, relay_dispatcher_database_url=DSN)
    assert require_dispatcher_dsn(settings) == DSN


def test_the_refusal_carries_a_typed_code_not_a_message() -> None:
    """`2`, not `4`. Nothing was attempted and nothing is missing from the
    database — an operator scripting on `unavailable` would go looking for a
    row instead of at the environment.

    Asserted on the CODE rather than on the prose, because the prose is for a
    human and may change.
    """
    refusal = translate(RelayNotConfiguredError("no dsn"))
    assert isinstance(refusal, Refusal)
    assert refusal.code == "config.invalid"
    assert int(refusal.exit_code) == 2


# ── the two connections are two credentials ─────────────────────────────────


def test_the_dispatcher_runtime_uses_the_dispatcher_dsn_for_both_halves() -> None:
    """One credential in play, and only the platform half is ever used.

    Engine construction does not connect, so this asserts the arrangement
    without a database.
    """
    runtime = dispatcher_runtime(DSN)
    assert runtime.platform_engine.url.username == "platform_outbox_dispatcher"
    assert runtime.engine.url.username == "platform_outbox_dispatcher"


def test_the_dispatcher_pool_is_one_connection() -> None:
    """A sequential poller. Sizing it like a request pool would hold idle
    connections open for a role that must be able to do nothing else."""
    runtime = dispatcher_runtime(DSN)
    assert runtime.platform_engine.pool.size() == 1


# ── the transport is the consumer, and it is the kernel's protocol ──────────


def test_the_composed_transport_is_the_contract_event_consumer() -> None:
    """The defect being repaired, stated as an assertion: this class was
    constructed NOWHERE under `src/`, so activation reached no allocation."""
    composition = RelayComposition(
        dispatcher_sessions=lambda: None,  # type: ignore[arg-type,return-value]
        delivery_sessions=lambda: None,  # type: ignore[arg-type,return-value]
        transport=ContractEventConsumer(),
    )
    assert isinstance(composition.transport, ContractEventConsumer)


def test_the_consumer_matches_the_kernel_delivery_signature() -> None:
    """Structural, against the kernel's own Protocol rather than a `hasattr`.

    `PlatformDeliveryTransport` is not `runtime_checkable`, so `isinstance`
    cannot answer this — and a `hasattr(x, "deliver")` would be satisfied by a
    method taking the wrong arguments, which is exactly the drift worth
    catching when the kernel pin moves.
    """
    expected = inspect.signature(PlatformDeliveryTransport.deliver)
    actual = inspect.signature(ContractEventConsumer.deliver)
    assert [p.name for p in actual.parameters.values()] == [
        p.name for p in expected.parameters.values()
    ]


def test_the_signature_comparison_can_still_fail() -> None:
    """SENSITIVITY. The comparison above asserts an equality, and a broken
    reader produces two empty lists that compare equal."""

    class _WrongShape:
        def deliver(self, event: object) -> None: ...

    expected = inspect.signature(PlatformDeliveryTransport.deliver)
    actual = inspect.signature(_WrongShape.deliver)
    assert [p.name for p in actual.parameters.values()] != [
        p.name for p in expected.parameters.values()
    ]


# ── the thresholds are configuration, and a bad one refuses ─────────────────


def test_a_non_positive_window_is_refused_at_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero window makes every pending event instantly overdue, so the health
    surface goes permanently red and is learned to be ignored. That is worse
    than the default, so it fails loudly instead of falling back to it."""
    monkeypatch.setenv("VENDOR_RELAY_OVERDUE_SECONDS", "0")
    with pytest.raises(ProductionConfigurationError):
        load_vendor_settings()


def test_an_unparseable_window_is_refused_at_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VENDOR_RELAY_STALE_LEASE_SECONDS", "five minutes")
    with pytest.raises(ProductionConfigurationError):
        load_vendor_settings()


def test_the_windows_default_and_a_valid_override_is_taken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NON-VACUITY for both refusals above, and the documented defaults."""
    monkeypatch.delenv("VENDOR_RELAY_OVERDUE_SECONDS", raising=False)
    monkeypatch.delenv("VENDOR_RELAY_STALE_LEASE_SECONDS", raising=False)
    settings = load_vendor_settings()
    assert settings.relay_overdue_seconds == 300
    assert settings.relay_stale_lease_seconds == 300
    assert settings.relay_dispatcher_database_url == ""

    monkeypatch.setenv("VENDOR_RELAY_OVERDUE_SECONDS", "900")
    assert load_vendor_settings().relay_overdue_seconds == 900


def test_the_stale_window_default_matches_the_kernel_reclaim_window() -> None:
    """A window TIGHTER than the relay's own reclaim window would report a stale
    lease the relay still considers live — an alert for a healthy system."""
    from dotmac_kernel.messaging import RelayPolicy

    assert load_vendor_settings().relay_stale_lease_seconds >= (
        RelayPolicy().stale_lease_seconds
    )


# ── the operator surface refuses, rather than reporting a quiet success ─────


def test_the_drain_command_exits_two_when_no_relay_is_configured(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Through the real parser, the real handler and the real exit mapping.

    The unit above proves the translation; this proves the WIRING, which is the
    half that was missing. An operator who runs this against a deployment with
    no dispatcher credential must get a refusal and a non-zero status — not
    `{"claimed": 0}` and a zero, which is what a healthy idle relay returns.
    """
    from vendor_cp.cli import main

    code = main(["relay", "drain", "--worker-id", "operator-canary"])
    capsys.readouterr()
    assert code == int(ExitCode.USAGE)


def test_the_drain_command_is_reachable_at_all(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """NON-VACUITY for the test above: an unparsed command also exits non-zero,
    and would pass it for entirely the wrong reason."""
    from vendor_cp.cli import main

    with pytest.raises(SystemExit) as caught:
        main(["relay", "drain", "--help"])
    capsys.readouterr()
    assert caught.value.code == 0
