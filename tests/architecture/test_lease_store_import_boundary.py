"""`lease_store.py` is a LEAF module -- held to it here (CP-2, design 3.3).

The lease store is a thin client of the `cp_lane3` functions, used where the
launcher runs. It must not drag the CP application's dependency closure behind
it, and it must never import Starter: the launcher's own `StoreRefused`,
`HeldLease` and `LeaseStanding` are INJECTED, so CP names none of them.

The boundary is an ALLOWLIST, in two parts:

* at module scope: the standard library and SQLAlchemy only;
* inside a function: additionally Foundation (`dotmac_deployment_foundation`), and
  only there, so importing the module needs nothing the launcher may lack and a
  missing Foundation is a runtime answer at the point of use.

A new `vendor_cp.*`, `dotmac_*` or Starter import anywhere is exactly what this
test exists to catch.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAF = ROOT / "src" / "vendor_cp" / "deployment" / "lease_store.py"

STDLIB_AND_SQLALCHEMY = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "sqlalchemy",
    }
)
INSIDE_FUNCTIONS = STDLIB_AND_SQLALCHEMY | {"dotmac_deployment_foundation"}


def _imports(source: str) -> tuple[set[str], set[str]]:
    """`(module-scope top-level names, function-scope top-level names)`."""
    tree = ast.parse(source)
    scoped: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            scoped.update(id(child) for child in ast.walk(node))
    module: set[str] = set()
    nested: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names = ["." * node.level + (node.module or "")]
            else:
                names = [node.module or ""]
        else:
            continue
        for name in names:
            top = name.split(".", 1)[0] or name
            (nested if id(node) in scoped else module).add(top)
    return module, nested


def _offenders(source: str) -> list[str]:
    module, nested = _imports(source)
    return sorted(
        {m for m in module if m not in STDLIB_AND_SQLALCHEMY}
        | {n for n in nested if n not in INSIDE_FUNCTIONS}
    )


def test_the_leaf_exists_and_is_not_vacuous() -> None:
    assert LEAF.exists()
    module, nested = _imports(LEAF.read_text())
    assert "sqlalchemy" in module
    assert "dotmac_deployment_foundation" in nested


def test_the_leaf_reaches_nothing_outside_its_boundary() -> None:
    assert _offenders(LEAF.read_text()) == []


def test_foundation_is_never_imported_at_module_scope() -> None:
    module, _ = _imports(LEAF.read_text())
    assert "dotmac_deployment_foundation" not in module


def test_the_scan_sees_planted_violations() -> None:
    """SENSITIVITY: an allowlist that finds nothing could mean the boundary
    holds or that it cannot see."""
    planted = (
        "import dotmac_deployment_foundation\n"
        "from vendor_cp.deployment import consumption_scope\n"
        "from lane3_lease_store import StoreRefused\n"
        "def f():\n"
        "    import dotmac_kernel\n"
        "    from dotmac_deployment_foundation.lease import HostLease\n"
    )
    assert _offenders(planted) == [
        "dotmac_deployment_foundation",
        "dotmac_kernel",
        "lane3_lease_store",
        "vendor_cp",
    ]
