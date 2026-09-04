"""The OpenBao pointer is dereferenced at EXECUTION, never during planning.

Michael's clause: *"Resolve the OpenBao pointer at execution time."* The effect
satisfies it today — `_resolve_material` is called from the two execution entry
points and from nowhere else, and the plan-construction path touches no secret
at all. What it did not have was anything that would REFUSE a regression, and
the property is invisible in review: moving one call earlier, to "validate the
pointer while building the plan", reads like diligence and quietly puts material
on the planning host.

So this asserts WHERE the dereference happens, structurally, rather than that it
happens correctly once.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path
from typing import Final

from vendor_cp.deployment.credential_bootstrap import PrincipalCredentialBootstrap

SRC: Final = Path(__file__).resolve().parents[2] / "src" / "vendor_cp"
EFFECT: Final = SRC / "deployment" / "credential_bootstrap.py"

#: The only functions permitted to dereference the pointer. Both are execution
#: entry points, invoked on the target by the executor.
EXECUTION_ENTRY_POINTS: Final = frozenset(
    {"bootstrap_principal_credential", "verify_credential"}
)

#: The plan-construction path. Nothing here may reach a secret: a plan is built
#: where the operator is, and the material lives where the deployment is.
PLANNING_MODULES: Final = ("deployment/candidate.py", "deployment/plan_inputs.py")

#: Names that would mean a secret had been reached.
_DEREFERENCE = ("read_versioned", "read_optional", "_resolve_material")


def _callers_of(tree: ast.Module, name: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and getattr(inner.func, "id", "") == name:
                found.add(node.name)
    return found


def test_only_the_execution_entry_points_dereference_the_pointer() -> None:
    """The whole clause, as one assertion."""
    tree = ast.parse(EFFECT.read_text(encoding="utf-8"))
    callers = _callers_of(tree, "_resolve_material")
    assert callers == EXECUTION_ENTRY_POINTS, sorted(callers ^ EXECUTION_ENTRY_POINTS)


def test_the_caller_check_can_still_see_one() -> None:
    """SENSITIVITY. The assertion above compares two sets, and a reader that
    found nothing would make them both empty — which would compare equal to an
    empty expectation and pass for the wrong reason."""
    planted = ast.parse("def build_the_plan():\n    return _resolve_material(x, y)\n")
    assert _callers_of(planted, "_resolve_material") == {"build_the_plan"}


def test_the_planning_path_reaches_no_secret() -> None:
    """A plan is built where the operator is; the material lives where the
    deployment is. A pointer dereferenced while planning puts it on the wrong
    host, and every downstream property — that the plan carries no material,
    that the receipt cannot — is downstream of this one."""
    offenders = [
        f"{relative}: {name}"
        for relative in PLANNING_MODULES
        for name in _DEREFERENCE
        if name in (SRC / relative).read_text(encoding="utf-8")
    ]
    assert offenders == [], offenders


def test_the_planning_modules_exist_and_are_the_planning_path() -> None:
    """NON-VACUITY for the test above: a path list naming files that no longer
    exist asserts nothing, and would keep passing after the planning code moved."""
    for relative in PLANNING_MODULES:
        assert (SRC / relative).is_file(), relative
    assert "render_execution_plan" in (SRC / "deployment/candidate.py").read_text(
        encoding="utf-8"
    )
    assert "resolve_plan_inputs" in (SRC / "deployment/plan_inputs.py").read_text(
        encoding="utf-8"
    )


def test_the_plan_instruction_carries_a_reference_and_no_material() -> None:
    """Checked on the FIELD NAMES, so a field added later that could hold a
    value fails here rather than at a review that did not happen."""
    names = {f.name for f in dataclasses.fields(PrincipalCredentialBootstrap)}
    assert names == {
        "database",
        "principal",
        "secret_path",
        "secret_field",
        "expected_version",
    }
    assert not names & {"material", "password", "secret", "dsn", "credential"}
