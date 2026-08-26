"""Vendor platform-audit actions are manifest-owned vocabulary.

Kernel a68 made the platform writer enforce the same manifest registry as the
tenant writer. Vendor first crossed that boundary in the a61→a77 jump and the
a94 pin remains behind it, so every Vendor-owned action stays declared.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from vendor_cp.assembly import VENDOR_SURFACES

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "vendor_cp"


def _vendor_action_literals(node: ast.AST) -> set[str]:
    return {
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.startswith("vendor.")
    }


def referenced_platform_audit_actions() -> frozenset[str]:
    """Find action literals supplied directly or through a local `action`.

    The services use two shapes: `action="vendor..."` at the audit call (or
    the `_emit` audit/outbox helper), and a small branch that assigns one of two
    literal values to a local named `action` before writing. Both are explicit
    vocabulary references and both must be swept.
    """
    referenced: set[str] = set()
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "action":
                        referenced.update(_vendor_action_literals(keyword.value))
            if isinstance(node, ast.Assign | ast.AnnAssign):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == "action"
                    for target in targets
                ):
                    if node.value is not None:
                        referenced.update(_vendor_action_literals(node.value))
    return frozenset(referenced)


def declared_platform_audit_actions() -> tuple[str, ...]:
    return tuple(
        action
        for manifest in VENDOR_SURFACES
        for action in manifest.audit_actions
        if action.startswith("vendor.")
    )


def vocabulary_violations(
    referenced: frozenset[str], declared: tuple[str, ...]
) -> tuple[str, ...]:
    declaration_counts = Counter(declared)
    problems = [
        f"undeclared platform audit action: {action}"
        for action in sorted(referenced - declaration_counts.keys())
    ]
    problems.extend(
        f"orphan platform audit declaration: {action}"
        for action in sorted(declaration_counts.keys() - referenced)
    )
    problems.extend(
        f"platform audit action has {count} owners: {action}"
        for action, count in sorted(declaration_counts.items())
        if count != 1
    )
    return tuple(problems)


def test_every_vendor_platform_audit_action_is_declared_once_and_consumed() -> None:
    assert (
        vocabulary_violations(
            referenced_platform_audit_actions(), declared_platform_audit_actions()
        )
        == ()
    )


def test_an_undeclared_platform_audit_action_fails_the_decision() -> None:
    """Sensitivity: prove the guard rejects the regression it names."""
    assert vocabulary_violations(frozenset({"vendor.example.changed"}), ()) == (
        "undeclared platform audit action: vendor.example.changed",
    )
