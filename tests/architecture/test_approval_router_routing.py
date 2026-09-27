"""S4-B2's router sits in front of every `approval.` fact, and the old
silent-return consumer it replaced is gone.

Two structural claims, proved independently of any fixture:

1. `PlatformEventConsumers.deliver` routes the `approval.` prefix to the
   router BEFORE it ever reaches the contracts consumer — an `approval.*`
   event must never fall through to `ContractEventConsumer.deliver`.
2. `ApprovalWithdrawalConsumer`, the pre-S4-B2 transport that silently
   returned on an unrecognised subject type (ruling 3), no longer exists
   anywhere `vendor_cp.deployment.protected_rehearsal_issuer` exports.
"""

from __future__ import annotations

import ast
from pathlib import Path
from uuid import UUID

from dotmac_kernel.messaging import ClaimedPlatformEvent

from vendor_cp.deployment import protected_rehearsal_issuer
from vendor_cp.relay.approval_router import ApprovalEventRouter
from vendor_cp.relay.runner import PlatformEventConsumers

ROOT = Path(__file__).resolve().parents[2]
RUNNER_SOURCE = ROOT / "src" / "vendor_cp" / "relay" / "runner.py"


def test_approval_withdrawal_consumer_no_longer_exists() -> None:
    assert not hasattr(protected_rehearsal_issuer, "ApprovalWithdrawalConsumer")


def test_deliver_routes_the_approval_prefix_before_the_contracts_consumer() -> None:
    """AST proof: inside `PlatformEventConsumers.deliver`, the `approval.`
    branch's `return` statement lexically precedes the unconditional
    `self.contracts.deliver(...)` call — an `approval.*` event can never
    reach the contracts consumer on its way through this method."""
    tree = ast.parse(RUNNER_SOURCE.read_text())
    deliver_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PlatformEventConsumers":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "deliver":
                    deliver_fn = item
    assert deliver_fn is not None, "PlatformEventConsumers.deliver not found"

    body = deliver_fn.body
    if_index = next(
        i
        for i, stmt in enumerate(body)
        if isinstance(stmt, ast.If)
        and isinstance(stmt.test, ast.Call)
        and isinstance(stmt.test.func, ast.Attribute)
        and stmt.test.func.attr == "startswith"
    )
    guarded_if = body[if_index]
    assert any(
        isinstance(stmt, ast.Return) for stmt in guarded_if.body
    ), "the approval.-prefix branch must return before falling through"
    assert if_index < len(body) - 1, "no unconditional contracts delivery follows"
    trailing = body[if_index + 1 :]
    assert any(
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr == "deliver"
        and isinstance(stmt.value.func.value, ast.Attribute)
        and stmt.value.func.value.attr == "contracts"
        for stmt in trailing
    ), "the fallthrough path must call self.contracts.deliver"


def test_an_approval_event_never_reaches_the_contracts_consumer() -> None:
    """Behavioural companion to the AST proof above."""
    calls: list[str] = []

    class _Contracts:
        def deliver(self, event: object, db: object) -> None:
            calls.append("contracts")

    class _Approvals:
        def deliver(self, event: object, db: object) -> None:
            calls.append("approvals")

    transport = PlatformEventConsumers(
        contracts=_Contracts(),  # type: ignore[arg-type]
        approvals=_Approvals(),  # type: ignore[arg-type]
    )
    withdrawn = ClaimedPlatformEvent(
        id=UUID("30000000-0000-0000-0000-000000000003"),
        event_type="approval.withdrawn",
        payload={},
        attempts=0,
        correlation_id=None,
    )
    transport.deliver(withdrawn, object())
    assert calls == ["approvals"]

    unrelated = ClaimedPlatformEvent(
        id=UUID("30000000-0000-0000-0000-000000000004"),
        event_type="contract.activated",
        payload={},
        attempts=0,
        correlation_id=None,
    )
    transport.deliver(unrelated, object())
    assert calls == ["approvals", "contracts"]


def test_production_composition_wires_the_router_type() -> None:
    field_type = PlatformEventConsumers.__dataclass_fields__["approvals"].type
    assert field_type in ("ApprovalEventRouter", ApprovalEventRouter)
