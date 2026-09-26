"""Every approval-dependent Control transition sits behind `held_transition`.

C2 S1's ruling: an Approvals-owned FOR SHARE seam is held through the Control
transition and commit — `held_transition` (`approval_barrier.py`) is the ONE
place that composes the hold with the transition. This is the structural half
of that guarantee: an AST scan over `src/vendor_cp/**.py` that finds every call
to one of Control's approval-dependent transitions (`approve_plan`,
`request_rollout`, `issue_rehearsal_issuer_authorization_for_plan`, `finalize`)
and requires it to be lexically inside a function passed as `held_transition`'s
`transition=` argument, or inside `approval_barrier.py` itself.

`host_admission_adapter.py`'s `finalize` call is allowlisted explicitly,
because it dispatches a `FOUNDATION_EXECUTION` plan that has no Approvals
subject at all. Michael decided C2-D1 on 2026-09-26: dispatch FAILS CLOSED for
an approval-requiring Foundation plan until Gate 3 defines its subject, and
`test_the_allowlisted_finalize_is_preceded_by_the_fail_closed_check` below
enforces that premise structurally. An exemption states an enforceable premise
(AGENTS.md), not a bare pass.

`authorize_deployment`/`propose_deployment_plan` (`deployment/adapter.py`) are
asserted to still raise `PlanInputDerivationUnavailable` before reaching any
transition call — they must stay refusals, not new call sites.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "vendor_cp"
APPROVAL_BARRIER = SRC / "deployment" / "approval_barrier.py"
PROTECTED_REHEARSAL_ISSUER = SRC / "deployment" / "protected_rehearsal_issuer.py"
HOST_ADMISSION_ADAPTER = SRC / "deployment" / "host_admission_adapter.py"
DEPLOYMENT_ADAPTER = SRC / "deployment" / "adapter.py"

#: Control transitions this barrier exists to guard. A call to any of these,
#: by attribute (`control.approve_plan(...)`) or bare name (imported by
#: name), must be inside a `held_transition` callback.
GUARDED_CALL_NAMES = frozenset(
    {
        "approve_plan",
        "request_rollout",
        "issue_rehearsal_issuer_authorization_for_plan",
        "finalize",
    }
)

#: (file, enclosing-function-name) pairs allowed to call a guarded name
#: without being inside a `held_transition` callback, each with a premise.
ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        # FOUNDATION_EXECUTION plans have no Approvals subject to hold. C2-D1
        # (Michael, 2026-09-26): dispatch fails closed instead —
        # `_refuse_an_approval_requiring_plan` runs before this finalize and
        # refuses any plan without an explicit requires_approval=False
        # (proved in tests/unit/test_foundation_v3_provider.py). Until Gate 3
        # gives the plan a subject, there is nothing for a barrier to hold.
        # Keyed by the path relative to src/vendor_cp, exactly as the scan
        # reports it.
        ("deployment/host_admission_adapter.py", "consume_dispatch"),
    }
)


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _held_transition_callback_names(tree: ast.AST) -> set[str]:
    """Names of functions passed as `transition=...` to any `held_transition`
    call, anywhere in the module (nested or top-level)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node) != "held_transition":
            continue
        for keyword in node.keywords:
            if keyword.arg == "transition" and isinstance(keyword.value, ast.Name):
                names.add(keyword.value.id)
        # A `transition=lambda ...` or an inline `def` would not be a Name;
        # such a call has no enclosing-function name to match against, so a
        # guarded call nested inside it is handled by the enclosing-function
        # walk below instead (the lambda/def node itself is the boundary).
    return names


def _enclosing_function_names(tree: ast.AST, target: ast.Call) -> list[str]:
    """Names of every function definition lexically enclosing `target`,
    innermost first, by walking the tree and tracking a def stack."""
    stack: list[str] = []
    found: list[str] = []

    def visit(node: ast.AST, in_scope: list[str]) -> None:
        if node is target:
            found[:] = list(reversed(in_scope))
            return
        new_scope = in_scope
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            new_scope = [*in_scope, node.name]
        elif isinstance(node, ast.Lambda):
            new_scope = [*in_scope, "<lambda>"]
        for child in ast.iter_child_nodes(node):
            visit(child, new_scope)

    visit(tree, stack)
    return found


def find_unguarded_calls(source: str, *, filename: str) -> list[str]:
    """Return a description of every guarded-name call not inside a
    `held_transition` callback and not on the allowlist."""
    tree = ast.parse(source)
    callback_names = _held_transition_callback_names(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name not in GUARDED_CALL_NAMES:
            continue
        enclosing = _enclosing_function_names(tree, node)
        if any(fn in callback_names for fn in enclosing):
            continue
        if enclosing and (filename, enclosing[0]) in ALLOWLIST:
            continue
        location = f"line {node.lineno}"
        violations.append(
            f"{filename}:{location} calls {name!r} outside a held_transition "
            f"callback (enclosing function(s): {enclosing or '<module scope>'})"
        )
    return violations


def _iter_source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_the_owned_source_files_exist() -> None:
    """The premise: if these files moved, every assertion below would be
    vacuously scanning nothing."""
    for path in (
        APPROVAL_BARRIER,
        PROTECTED_REHEARSAL_ISSUER,
        HOST_ADMISSION_ADAPTER,
        DEPLOYMENT_ADAPTER,
    ):
        assert path.exists(), path


def test_every_guarded_control_call_is_barriered_or_allowlisted() -> None:
    violations: list[str] = []
    for path in _iter_source_files():
        if path == APPROVAL_BARRIER:
            # The barrier's own module is the declared exemption: it is the
            # ONE place `held_transition` is defined, not a caller of it.
            continue
        source = path.read_text()
        violations.extend(
            find_unguarded_calls(source, filename=path.relative_to(SRC).as_posix())
        )
    assert violations == [], "\n".join(violations)


def test_the_allowlisted_finalize_call_still_exists_at_its_named_site() -> None:
    """A stale allowlist entry that no longer matches any real call would
    hide a regression rather than document one."""
    source = HOST_ADMISSION_ADAPTER.read_text()
    tree = ast.parse(source)
    matched = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) == "finalize":
            enclosing = _enclosing_function_names(tree, node)
            if enclosing and enclosing[0] == "consume_dispatch":
                matched = True
    assert matched, (
        "host_admission_adapter.py no longer calls finalize() inside "
        "consume_dispatch(); the ALLOWLIST entry naming that premise is stale "
        "and must be reviewed"
    )


def test_the_allowlisted_finalize_is_preceded_by_the_fail_closed_check() -> None:
    """The allowlist premise, enforced: inside `consume_dispatch`, the C2-D1
    refusal is called on an earlier line than `finalize`, in the same block."""
    tree = ast.parse(HOST_ADMISSION_ADAPTER.read_text())
    (consume,) = (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "consume_dispatch"
    )
    lines = {
        _call_name(node): node.lineno
        for node in ast.walk(consume)
        if isinstance(node, ast.Call)
        and _call_name(node) in {"finalize", "_refuse_an_approval_requiring_plan"}
    }
    assert set(lines) == {"finalize", "_refuse_an_approval_requiring_plan"}, lines
    assert lines["_refuse_an_approval_requiring_plan"] < lines["finalize"]


def test_authorize_deployment_and_propose_plan_still_raise_before_any_call() -> None:
    source = DEPLOYMENT_ADAPTER.read_text()
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name in {"authorize_deployment", "propose_deployment_plan"}
    }
    assert set(functions) == {"authorize_deployment", "propose_deployment_plan"}
    for name, function in functions.items():
        body = function.body
        # Skip a leading docstring `Expr` node, if present.
        statements = [
            stmt
            for stmt in body
            if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
        ]
        assert len(statements) == 1, (
            f"{name} has more than a single raise statement in its body; it "
            "was expected to refuse unconditionally before any Control call"
        )
        (only,) = statements
        assert isinstance(only, ast.Raise), (
            f"{name}'s single statement is not a `raise` — it may now perform "
            "a call this guard must account for"
        )
        raised_names = {
            _call_name(node) for node in ast.walk(only) if isinstance(node, ast.Call)
        }
        assert raised_names == {"PlanInputDerivationUnavailable"}, (
            f"{name} raises {raised_names}, not exactly "
            "PlanInputDerivationUnavailable"
        )


def test_the_detector_flags_a_planted_bare_control_call() -> None:
    """SENSITIVITY (positive). A bare `control.approve_plan(...)` outside any
    `held_transition` callback must be flagged."""
    planted = (
        "def approve_without_a_barrier(db, plan_id):\n"
        "    control = None\n"
        "    return control.approve_plan(db, plan_id)\n"
    )
    violations = find_unguarded_calls(planted, filename="planted.py")
    assert len(violations) == 1
    assert "approve_plan" in violations[0]
    assert "approve_without_a_barrier" in violations[0]


def test_the_detector_does_not_flag_a_call_inside_a_held_transition_callback() -> None:
    """SENSITIVITY (negative / near-miss). The identical call, this time
    inside a function passed as `held_transition`'s `transition=` argument,
    must NOT be flagged — otherwise the guard cannot distinguish the two
    shapes it exists to tell apart."""
    clean = (
        "def approve_with_a_barrier(db, plan_id):\n"
        "    control = None\n\n"
        "    def transition(held):\n"
        "        return control.approve_plan(db, plan_id)\n\n"
        "    return held_transition(\n"
        "        db,\n"
        "        request_id=None,\n"
        "        subject_type='x',\n"
        "        subject_id='y',\n"
        "        content_digest='sha256:aa',\n"
        "        transition=transition,\n"
        "    )\n"
    )
    assert find_unguarded_calls(clean, filename="clean.py") == []
