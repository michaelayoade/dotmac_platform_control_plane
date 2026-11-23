"""The lease store's refusal-code set is CLOSED (CP-2, design 3.3).

Every code the Python store raises with `_refuse("...")`, and every code the
migration's functions raise, must be a member of `REFUSAL_CODES`: a code outside
it is mapped to `store-error` by the mapper, so a typed refusal that is not in the
set silently loses its meaning. No database and no Foundation needed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from vendor_cp.deployment import lease_store

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "src" / "vendor_cp" / "deployment" / "lease_store.py"
MIGRATION = ROOT / "alembic" / "versions" / "v023_lane3_store.py"
_OWN = {
    lease_store.STORE_UNREACHABLE,
    lease_store.STORE_COMMIT_UNKNOWN,
    lease_store.STORE_ERROR,
}


def _python_literals() -> set[str]:
    codes: set[str] = set()
    for node in ast.walk(ast.parse(STORE.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_refuse"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            codes.add(node.args[0].value)
    return codes


def _sql_codes() -> set[str]:
    source = MIGRATION.read_text(encoding="utf-8")
    codes = set(re.findall(r'_refuse\("([a-z0-9-]+)"\)', source))
    suffixes = set(re.findall(r"v_pre \|\| '([a-z-]+)'", source))
    prefixes = set(re.findall(r"'((?:reprovision|e10)-receipt-)'", source))
    assert prefixes == {"reprovision-receipt-", "e10-receipt-"}
    return codes | {p + s for p in prefixes for s in suffixes}


def test_every_python_refusal_literal_is_in_the_closed_set() -> None:
    literals = _python_literals()
    assert "lease-controller-identity-invalid" in literals
    assert literals - lease_store.REFUSAL_CODES - _OWN == set()


def test_every_sql_refusal_code_is_in_the_closed_set() -> None:
    codes = _sql_codes()
    assert len(codes) >= 25
    assert codes - lease_store.REFUSAL_CODES == set()


def test_the_closed_set_holds_no_stray_member() -> None:
    """Every member is raised by the SQL or by Python (nothing is declared and
    never used); the three transport codes are not members."""
    # the deploy lease class (`v024_deploy_lease`) raises two of its own
    deploy = set(
        re.findall(
            r'_refuse\("([a-z0-9-]+)"\)',
            (ROOT / "alembic" / "versions" / "v024_deploy_lease.py").read_text(
                encoding="utf-8"
            ),
        )
    )
    assert {"lease-max-reached", "reconcile-marker-required"} <= deploy
    used = _sql_codes() | _python_literals() | deploy
    assert lease_store.REFUSAL_CODES - used == set()
    assert not (lease_store.REFUSAL_CODES & _OWN)
