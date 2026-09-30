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
CONTRACTS_ADAPTER = SRC / "contracts" / "adapter.py"

#: Control's approval-dependent entry points. ANY reference to one of these
#: names -- a call, an attribute read (`fn = control.approve_plan`), a
#: `functools.partial`, a by-name import (`from ... import approve_plan as x`)
#: or `getattr(control, "approve_plan")` -- must sit inside a `held_transition`
#: callback. `admit_and_consume_host_admission` is Control's own name for what
#: the Foundation V3 composition binds as `finalize`.
GUARDED_CALL_NAMES = frozenset(
    {
        "approve_plan",
        "request_rollout",
        "dispatch_attempt",
        "issue_rehearsal_issuer_authorization_for_plan",
        "stage_rehearsal_issuer_consumption",
        "finalize",
        "admit_and_consume_host_admission",
        # Commercial Agreements' approve/activate/reinstate, bound under these
        # exact names by contracts/adapter.py's own aliased imports
        # (`from dotmac_commercial_agreements import approve as module_approve`,
        # etc.) — the bound identifier at the real call site is what this
        # detector matches, however the name arrived (S4-A).
        "module_approve",
        "module_activate",
        "module_reinstate",
    }
)

#: Commercial Agreements commands that consume approval evidence (or, for
#: reinstate, restore standing on it). Guarded by their bound aliases above;
#: any other spelling of these names from the module is flagged directly.
_CA_EVIDENCE_COMMANDS = frozenset({"approve", "activate", "reinstate"})

#: (file relative to src/vendor_cp, enclosing function, guarded name) triples
#: allowed outside a `held_transition` callback, each with its premise. Narrow
#: by NAME: an entry exempts only that one reference, never every guarded
#: name in the function.
ALLOWLIST: frozenset[tuple[str, str, str]] = frozenset(
    {
        # FOUNDATION_EXECUTION plans have no Approvals subject to hold. C2-D1
        # (Michael, 2026-09-26): dispatch fails closed instead —
        # `_refuse_an_approval_requiring_plan` runs before this finalize and
        # refuses any plan without an explicit requires_approval=False
        # (proved in tests/unit/test_foundation_v3_provider.py and ordered by
        # `test_the_allowlisted_finalize_is_preceded_by_the_fail_closed_check`).
        ("deployment/host_admission_adapter.py", "consume_dispatch", "finalize"),
        # Startup composition only checks that the bound callable IS callable;
        # it never calls it.
        (
            "deployment/host_admission_adapter.py",
            "compose_foundation_v3_providers",
            "finalize",
        ),
    }
)

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_functions(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> list[ast.AST]:
    """Function/lambda nodes lexically enclosing `node`, innermost first."""
    chain: list[ast.AST] = []
    current = parents.get(node)
    while current is not None:
        if isinstance(current, _FUNCTION_NODES):
            chain.append(current)
        current = parents.get(current)
    return chain


def _scope_of(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    chain = _enclosing_functions(node, parents)
    return chain[0] if chain else None


def _held_transition_callbacks(
    tree: ast.AST, parents: dict[ast.AST, ast.AST]
) -> set[ast.AST]:
    """The exact function DEFINITIONS passed as `transition=` to a
    `held_transition` call: a `def` of that name defined in the SAME scope as
    the call, or an inline lambda. Matching the definition node rather than
    the bare name means an unrelated `def transition()` elsewhere in the module
    is not exempt."""
    callbacks: set[ast.AST] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node) == "held_transition"):
            continue
        call_scope = _scope_of(node, parents)
        for keyword in node.keywords:
            if keyword.arg != "transition":
                continue
            if isinstance(keyword.value, ast.Lambda):
                callbacks.add(keyword.value)
            elif isinstance(keyword.value, ast.Name):
                for candidate in ast.walk(call_scope or tree):
                    if (
                        isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef)
                        and candidate.name == keyword.value.id
                        and _scope_of(candidate, parents) is call_scope
                    ):
                        callbacks.add(candidate)
    return callbacks


def _is_ca_module(module: str | None) -> bool:
    return module == "dotmac_commercial_agreements" or (module or "").startswith(
        "dotmac_commercial_agreements."
    )


def _root_name(node: ast.AST) -> str | None:
    """`a` for `a`, `a.b`, `a.b.c` — the Name an attribute chain hangs off."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _ca_module_names(tree: ast.AST) -> set[str]:
    """Every local name bound to Commercial Agreements or one of its
    submodules: `import dotmac_commercial_agreements[.x] [as n]` and
    `from dotmac_commercial_agreements import service [as n]`."""
    names = {"dotmac_commercial_agreements"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_ca_module(alias.name):
                    names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and _is_ca_module(node.module):
            names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name not in _CA_EVIDENCE_COMMANDS and alias.name != "*"
            )
    return names


def _guarded_references(tree: ast.AST) -> list[tuple[ast.AST, str]]:
    """Every node that names a guarded entry point, however it is spelled."""
    found: list[tuple[ast.AST, str]] = []
    ca_modules = _ca_module_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in GUARDED_CALL_NAMES:
            found.append((node, node.attr))
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in GUARDED_CALL_NAMES
        ):
            found.append((node, node.id))
        elif isinstance(node, ast.ImportFrom):
            found.extend(
                (node, alias.name)
                for alias in node.names
                if alias.name in GUARDED_CALL_NAMES
            )
            # Commercial Agreements' evidence-consuming commands are guarded by
            # their bound aliases (`module_approve` ...). Importing one under
            # any OTHER name — or unaliased — would slip past that bound-name
            # match, so the import itself is the reference.
            if _is_ca_module(node.module):
                found.extend(
                    (node, alias.name)
                    for alias in node.names
                    if alias.name == "*"
                    or (
                        alias.name in _CA_EVIDENCE_COMMANDS
                        and (alias.asname or alias.name) not in GUARDED_CALL_NAMES
                    )
                )
        elif (
            isinstance(node, ast.Attribute)
            and node.attr in _CA_EVIDENCE_COMMANDS
            and _root_name(node.value) in ca_modules
        ):
            found.append((node, node.attr))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and (
                node.args[1].value in GUARDED_CALL_NAMES
                or node.args[1].value in _CA_EVIDENCE_COMMANDS
            )
        ):
            found.append((node, str(node.args[1].value)))
    return found


def _function_name(node: ast.AST) -> str:
    return getattr(node, "name", "<lambda>")


def _own_body_descendants(node: ast.AST) -> list[ast.AST]:
    """Every descendant of `node`, WITHOUT descending into a nested
    function/lambda definition -- so a call inside a helper defined inside
    the callback does not count as the callback's own, direct call."""
    found: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        found.append(current)
        if isinstance(current, _FUNCTION_NODES):
            continue
        stack.extend(ast.iter_child_nodes(current))
    return found


def _calls_directly(function: ast.AST, name: str) -> bool:
    """`True` if `function`'s OWN body calls `name(...)` -- not from inside a
    nested function/lambda defined within it."""
    return any(
        isinstance(node, ast.Call) and _call_name(node) == name
        for node in _own_body_descendants(function)
    )


def find_unguarded_calls(source: str, *, filename: str) -> list[str]:
    """Return a description of every guarded-name reference that is neither
    inside a `held_transition` callback nor an allowlisted (file, function,
    name) triple."""
    tree = ast.parse(source)
    parents = _parents(tree)
    callbacks = _held_transition_callbacks(tree, parents)
    violations: list[str] = []
    for node, name in _guarded_references(tree):
        enclosing = _enclosing_functions(node, parents)
        if any(fn in callbacks for fn in enclosing):
            continue
        innermost = _function_name(enclosing[0]) if enclosing else "<module scope>"
        if (filename, innermost, name) in ALLOWLIST:
            continue
        violations.append(
            f"{filename}:line {getattr(node, 'lineno', '?')} references {name!r} "
            f"outside a held_transition callback (in {innermost})"
        )
    return violations


def _enclosing_function_names(tree: ast.AST, target: ast.AST) -> list[str]:
    """Names of the functions enclosing `target`, innermost first."""
    return [_function_name(fn) for fn in _enclosing_functions(target, _parents(tree))]


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
        CONTRACTS_ADAPTER,
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


def test_the_detector_flags_aliased_imported_and_getattr_references() -> None:
    """SENSITIVITY (bypass shapes). Each spelling reaches Control's approval
    without a call node named `approve_plan`; each must still be flagged."""
    shapes = {
        "alias": "def f(control):\n    fn = control.approve_plan\n    return fn()\n",
        "import": "from dotmac_deployment_control import approve_plan as grant\n",
        "getattr": "def f(control):\n    return getattr(control, 'approve_plan')()\n",
        "partial": (
            "import functools\n"
            "def f(control):\n"
            "    return functools.partial(control.dispatch_attempt, 1)\n"
        ),
    }
    for label, source in shapes.items():
        assert find_unguarded_calls(source, filename="planted.py"), label


def test_a_same_named_function_outside_the_barrier_scope_is_not_exempt() -> None:
    """SENSITIVITY (name collision). Only the definition actually passed to
    held_transition, in the same scope, is exempt; another `transition`
    elsewhere in the module is not."""
    source = (
        "def guarded(db, control):\n"
        "    def transition(held):\n"
        "        return control.approve_plan(db)\n"
        "    return held_transition(db, request_id=None, subject_type='x',\n"
        "        subject_id='y', content_digest='sha256:aa', transition=transition)\n"
        "\n"
        "def transition(db, control):\n"
        "    return control.request_rollout(db)\n"
    )
    violations = find_unguarded_calls(source, filename="planted.py")
    assert len(violations) == 1
    assert "request_rollout" in violations[0]


def test_the_detector_flags_a_planted_bare_agreement_module_approve_call() -> None:
    """SENSITIVITY (positive, S4-A). A bare `module_approve(...)` outside any
    `held_transition` callback must be flagged, the same as Control's own
    `approve_plan` above -- this is the agreement-side call site the barrier
    now also covers."""
    planted = (
        "def approve_without_a_barrier(db, command):\n"
        "    return module_approve(db, command)\n"
    )
    violations = find_unguarded_calls(planted, filename="contracts/adapter.py")
    assert len(violations) == 1
    assert "module_approve" in violations[0]
    assert "approve_without_a_barrier" in violations[0]


def test_the_allowlist_exempts_one_name_not_the_whole_function() -> None:
    """An allowlisted (file, function, finalize) entry must not exempt a new
    guarded call added to the same function."""
    source = (
        "class P:\n"
        "    def consume_dispatch(self):\n"
        "        self._control.finalize()\n"
        "        self._control.approve_plan()\n"
    )
    violations = find_unguarded_calls(
        source, filename="deployment/host_admission_adapter.py"
    )
    assert len(violations) == 1
    assert "approve_plan" in violations[0]


def test_the_detector_flags_an_unaliased_commercial_agreements_command() -> None:
    """SENSITIVITY (spelling). The guard matches CA's evidence commands by their
    bound aliases; an unaliased import, a different alias, or an attribute call
    on the module must each still be flagged."""
    shapes = {
        "unaliased": "from dotmac_commercial_agreements import activate\n",
        "other alias": "from dotmac_commercial_agreements import approve as ok\n",
        "attribute": (
            "import dotmac_commercial_agreements\n"
            "def f(db, c):\n"
            "    return dotmac_commercial_agreements.reinstate(db, c)\n"
        ),
        "module alias": (
            "import dotmac_commercial_agreements as ca\n"
            "def f(db, c):\n"
            "    return ca.approve(db, c)\n"
        ),
        "submodule attribute": (
            "import dotmac_commercial_agreements.service\n"
            "def f(db, c):\n"
            "    return dotmac_commercial_agreements.service.activate(db, c)\n"
        ),
        "from-imported submodule": (
            "from dotmac_commercial_agreements import service as svc\n"
            "def f(db, c):\n"
            "    return svc.reinstate(db, c)\n"
        ),
        "getattr": (
            "import dotmac_commercial_agreements as ca\n"
            "def f(db, c):\n"
            "    return getattr(ca, 'activate')(db, c)\n"
        ),
        "star import": "from dotmac_commercial_agreements import *\n",
    }
    for label, source in shapes.items():
        assert find_unguarded_calls(source, filename="planted.py"), label
    # The sanctioned aliased import itself is not a violation.
    assert not find_unguarded_calls(
        "from dotmac_commercial_agreements import approve as module_approve\n",
        filename="planted.py",
    )


# ── fix 5: the receipt index's completeness is a structural property ────────


def test_every_issuance_callback_also_records_a_receipt() -> None:
    """D18-C's receipt index (`issuer_receipts.issued_authorization_refs`) is
    only complete if every `held_transition` callback that issues an
    authorization also records its receipt -- in the SAME callback. This is
    a structural property (two calls living in one function), not something a
    single unit test replaying one path can prove, so it is an AST check
    here, mirroring the rest of this module."""
    violations: list[str] = []
    for path in _iter_source_files():
        source = path.read_text()
        tree = ast.parse(source)
        parents = _parents(tree)
        for callback in _held_transition_callbacks(tree, parents):
            if not _calls_directly(
                callback, "issue_rehearsal_issuer_authorization_for_plan"
            ):
                continue
            if not _calls_directly(callback, "record_receipt"):
                violations.append(
                    f"{path.relative_to(SRC).as_posix()}:{_function_name(callback)} "
                    "issues a rehearsal-issuer authorization without recording "
                    "a receipt in the same held_transition callback"
                )
    assert violations == [], "\n".join(violations)


def test_the_receipt_completeness_guard_flags_a_planted_violation() -> None:
    """SENSITIVITY (positive). An issuance callback that never calls
    `record_receipt` must be flagged."""
    planted = (
        "def issue_without_a_receipt(db, control):\n"
        "    def transition(held):\n"
        "        return control.issue_rehearsal_issuer_authorization_for_plan(db)\n"
        "    return held_transition(db, request_id=None, subject_type='x',\n"
        "        subject_id='y', content_digest='sha256:aa', transition=transition)\n"
    )
    tree = ast.parse(planted)
    parents = _parents(tree)
    (callback,) = _held_transition_callbacks(tree, parents)
    assert _calls_directly(callback, "issue_rehearsal_issuer_authorization_for_plan")
    assert not _calls_directly(callback, "record_receipt")


def test_the_receipt_completeness_guard_does_not_flag_a_callback_with_both_calls() -> (
    None
):
    """SENSITIVITY (near-miss). The identical shape, this time with
    `record_receipt` also called directly in the callback, must NOT be
    flagged -- otherwise the guard cannot tell the two shapes apart."""
    clean = (
        "def issue_with_a_receipt(db, control):\n"
        "    def transition(held):\n"
        "        result = control.issue_rehearsal_issuer_authorization_for_plan(db)\n"
        "        record_receipt(db)\n"
        "        return result\n"
        "    return held_transition(db, request_id=None, subject_type='x',\n"
        "        subject_id='y', content_digest='sha256:aa', transition=transition)\n"
    )
    tree = ast.parse(clean)
    parents = _parents(tree)
    (callback,) = _held_transition_callbacks(tree, parents)
    assert _calls_directly(callback, "issue_rehearsal_issuer_authorization_for_plan")
    assert _calls_directly(callback, "record_receipt")


def test_the_receipt_completeness_guard_ignores_a_nested_record_receipt() -> None:
    """SENSITIVITY (near-miss, nesting). `record_receipt` called from inside a
    helper function DEFINED INSIDE the callback is not a direct call of the
    callback itself -- the packet requires "directly within the same callback
    function", not merely reachable from it."""
    nested = (
        "def issue_with_a_nested_receipt(db, control):\n"
        "    def transition(held):\n"
        "        def _record():\n"
        "            record_receipt(db)\n"
        "        result = control.issue_rehearsal_issuer_authorization_for_plan(db)\n"
        "        _record()\n"
        "        return result\n"
        "    return held_transition(db, request_id=None, subject_type='x',\n"
        "        subject_id='y', content_digest='sha256:aa', transition=transition)\n"
    )
    tree = ast.parse(nested)
    parents = _parents(tree)
    (callback,) = _held_transition_callbacks(tree, parents)
    assert _calls_directly(callback, "issue_rehearsal_issuer_authorization_for_plan")
    assert not _calls_directly(callback, "record_receipt")
