""" "No automated hard deletion", made into a check rather than a promise.

`PlatformDataGovernanceV1` has two enforcements and this file holds the weaker
one. The grant — `REVOKE DELETE, TRUNCATE` from the online roles, read back from
`has_table_privilege` — is what actually refuses a statement, and it is proved
against a real composed database in
`tests/migration/test_data_governance_catalogue.py`. What is proved here is that
this repository and the distributions it composes contain no code that removes a
row from a table the classification retains.

## Why a scan and not a review

`AGENTS.md` rule 10's shape: coverage is DERIVED and the exceptions are NAMED.
The scan walks every `.py` file in this repository's source, scripts and
migration lineage and in all seven composed distributions; it does not consult a
list of files to look at. What it finds is compared with
`data_governance.DELETION_SITES` in BOTH directions, so a kernel repin that adds
a deletion fails the build, and a site that disappears fails it too rather than
leaving a declaration describing nothing.

## The detector carries its own sensitivity proof

A scan over a clean tree finds nothing, which is also what a broken scan finds.
So a deletion is PLANTED and the scanner must name it, and a near-miss — prose
in a docstring, a comment, and a call to something merely spelled like a
deletion — is planted and must NOT be named. The owner module is deliberately
inside the scanned set rather than exempted from it, because a detector that
excuses the file that defines it proves nothing about that file.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from vendor_cp.data_governance import (
    DELETION_SITES,
    UNSCANNED_FUNCTIONS,
    DeletionSite,
    Reachability,
)

ROOT = Path(__file__).resolve().parents[2]

#: The seven distributions this assembly composes. Their migration lineages are
#: walked too: a lineage is code a deployment runs.
COMPOSED_DISTRIBUTIONS = (
    "dotmac_kernel",
    "dotmac_release_catalog",
    "dotmac_entitlement_allocation",
    "dotmac_approvals",
    "dotmac_commercial_agreements",
    "dotmac_licensing",
    "dotmac_deployment_control",
)

#: A row deletion written as SQL. `TRUNCATE` needs a following identifier so the
#: bare privilege NAME — which appears in every grant-verification helper in the
#: vendor lineage — is not mistaken for a statement.
DELETION_SQL = re.compile(
    r"\bDELETE\s+FROM\b|\bTRUNCATE\s+(?:TABLE\s+)?(?!ON\b)[A-Za-z_\"{]",
    re.IGNORECASE,
)


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Every docstring node, so PROSE about deletion is not a deletion.

    This module's own docstring says "removes a row"; the owner module's
    rationales discuss `DELETE`. A detector that flagged the text explaining it
    would forbid a token its own contract contains — the failure this repository
    already produced once, where a source-text check could never pass.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            found.add(id(first.value))
    return found


def deletion_sites_in(source: str, module: str) -> set[tuple[str, str]]:
    """`(module, top-level symbol)` for every row deletion in `source`.

    The symbol is the enclosing TOP-LEVEL definition, so a ledger entry survives
    a refactor that moves a helper inside a class and a repin that renumbers
    every line. Line numbers are deliberately not part of the identity.
    """
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    found: set[tuple[str, str]] = set()

    def visit(node: ast.AST, symbol: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                if child.name in UNSCANNED_FUNCTIONS:
                    continue
                visit(child, symbol or child.name)
                continue
            name = symbol or "<module>"
            if isinstance(child, ast.Call):
                function = child.func
                if getattr(function, "attr", getattr(function, "id", "")) == "delete":
                    found.add((module, name))
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                if id(child) not in docstrings and DELETION_SQL.search(child.value):
                    found.add((module, name))
            elif isinstance(child, ast.JoinedStr):
                literal = "".join(
                    part.value
                    for part in child.values
                    if isinstance(part, ast.Constant)
                )
                if DELETION_SQL.search(literal):
                    found.add((module, name))
            visit(child, symbol)

    visit(tree, "")
    return found


def _dotted(path: Path, root: Path, prefix: str) -> str:
    parts = [p for p in path.relative_to(root).with_suffix("").parts if p != "__init__"]
    return ".".join(part for part in (prefix, *parts) if part)


def _scanned_files() -> list[tuple[Path, str]]:
    """Every file the scan reads, derived rather than listed."""
    roots = [
        (ROOT / "src", ""),
        (ROOT / "scripts", "scripts"),
        (ROOT / "alembic", "alembic"),
    ]
    for distribution in COMPOSED_DISTRIBUTIONS:
        spec = importlib.util.find_spec(distribution)
        assert spec is not None and spec.submodule_search_locations is not None
        roots.append((Path(next(iter(spec.submodule_search_locations))), distribution))

    files: list[tuple[Path, str]] = []
    for root, prefix in roots:
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            files.append((path, _dotted(path, root, prefix)))
    return files


def scan() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path, module in _scanned_files():
        found |= deletion_sites_in(path.read_text(encoding="utf-8"), module)
    return found


#: The Control deletion seams whose `DELETION_SITES` entries are declared
#: `NOT_COMPOSED`. Each premise rests on this executable check, not on prose:
#: no composed source, script, migration or distribution may reference a seam
#: name outside its defining module and the exact `symbol=` constants of the
#: ledger's own `DeletionSite(...)` declarations. The attestation pair is the
#: shape CP PR #187 designed; the host-admission pair arrived with Control a15.
NOT_COMPOSED_SEAMS: dict[str, frozenset[str]] = {
    "dotmac_deployment_control.attestation_trust_registry": frozenset(
        {"repair_current_root"}
    ),
    "dotmac_deployment_control.host_admission_service": frozenset(
        {"revoke_target_admission_policy", "revoke_target_host"}
    ),
}

#: A module that may NAME a seam without reaching it, and why. The package
#: `__init__` re-exports the host-admission pair (an import plus two `__all__`
#: strings); a re-export is the public surface, not a caller, and every CP-side
#: consumer of that surface is still held by the scan below.
SEAM_REEXPORTERS: dict[str, frozenset[str]] = {
    "dotmac_deployment_control": frozenset(
        {"revoke_target_admission_policy", "revoke_target_host"}
    ),
}


def seam_references_in(
    source: str,
    seams: dict[str, frozenset[str]],
    *,
    allow_ledger_declaration: bool = False,
) -> set[str]:
    """Static references to any seam name, excluding docstring prose.

    Deliberately stricter than "calls": an import, an alias, an attribute read
    in any block, or an exact string literal (the `getattr` route) already
    invalidates a `NOT_COMPOSED` premise, without interpreting Python binding.
    """
    names = frozenset().union(*seams.values())
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    ledger_symbol_constants: set[int] = set()
    if allow_ledger_declaration:
        for statement in tree.body:
            target = (
                statement.targets[0]
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1
                else statement.target
                if isinstance(statement, ast.AnnAssign)
                else None
            )
            value = getattr(statement, "value", None)
            if isinstance(target, ast.Name) and target.id == "DELETION_SITES" and value:
                for node in ast.walk(value):
                    if not (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "DeletionSite"
                    ):
                        continue
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "symbol"
                            and isinstance(keyword.value, ast.Constant)
                            and isinstance(keyword.value.value, str)
                            and keyword.value.value in names
                        ):
                            ledger_symbol_constants.add(id(keyword.value))
    found: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in ledger_symbol_constants:
            continue
        if isinstance(node, ast.ImportFrom) and node.module in seams:
            module_seams = seams[node.module]
            for imported in node.names:
                if imported.name == "*":
                    found |= module_seams
                elif imported.name in module_seams:
                    found.add(imported.name)
        elif isinstance(node, ast.alias) and node.name in names:
            found.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in names:
                found.add(node.id)
        elif isinstance(node, ast.Attribute):
            if node.attr in names:
                found.add(node.attr)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and node.value in names
        ):
            found.add(node.value)
    return found


def not_composed_seam_reference_sites() -> set[tuple[str, str]]:
    """References from every composed entrypoint family, minus the definitions.

    `_scanned_files` derives repository sources, scripts and the migration
    lineage plus every composed distribution. Excluded: each seam's defining
    module, the declared re-exporters for exactly the names they re-export,
    and the ledger's own `symbol=` constants in `vendor_cp.data_governance`.
    """
    found: set[tuple[str, str]] = set()
    for path, module in _scanned_files():
        seams = {
            owner: symbols
            for owner, symbols in NOT_COMPOSED_SEAMS.items()
            if owner != module
        }
        if not seams:
            continue
        references = seam_references_in(
            path.read_text(encoding="utf-8"),
            seams,
            allow_ledger_declaration=module == "vendor_cp.data_governance",
        )
        references -= SEAM_REEXPORTERS.get(module, frozenset())
        # A seam's own sibling in the SAME defining module is excluded with it.
        for owner, symbols in NOT_COMPOSED_SEAMS.items():
            if owner == module:
                references -= symbols
        found |= {(module, symbol) for symbol in references}
    return found


# ── the ledger, held in both directions ─────────────────────────────────────


def test_every_row_deletion_in_composed_code_is_declared() -> None:
    """The direction that catches a kernel repin adding a deletion."""
    undeclared = sorted(scan() - {site.identity for site in DELETION_SITES})
    assert not undeclared, (
        f"{undeclared} remove rows and are not in DELETION_SITES. Classify what "
        "each deletes from in `vendor_cp/data_governance.py`: if it is reachable "
        "on an online request, the table it targets must be LIFECYCLE_DELETE "
        "with a deleting owner and a trigger, and the grant must let the online "
        "role act on it"
    )


def test_every_declared_deletion_site_still_exists() -> None:
    """The direction that catches a declaration describing nothing.

    A site that has gone keeps reading as an examined, accepted risk. That is
    the exemption shape `dotmac_starter_mt` ADR-0018 refuses, and the repair is
    to lower the ledger in the same change that removed the code.
    """
    stale = sorted({site.identity for site in DELETION_SITES} - scan())
    assert not stale, (
        f"{stale} are declared in DELETION_SITES and no longer exist. Remove "
        "each entry in the change that removed the code, rather than leaving a "
        "premise nobody can test"
    )


def test_the_scan_is_not_vacuous() -> None:
    """A scan that read nothing finds nothing, which is what a clean tree also
    yields. These counts are how the two are told apart."""
    files = _scanned_files()
    assert len(files) > 200, len(files)
    assert {module for _, module in files} >= {
        "vendor_cp.data_governance",
        "dotmac_kernel.platform_web",
        "dotmac_kernel.consent",
    }
    assert scan()


# ── the detector's sensitivity, plant and near-miss ─────────────────────────

PLANTED = '''
"""A module docstring that talks about DELETE FROM and truncating things."""

# A comment mentioning DELETE FROM public.platform_audit_events.


def purge_the_audit_log(db, model):
    db.execute("DELETE FROM public.platform_audit_events")
'''

NEAR_MISS = '''
"""A module docstring that talks about DELETE FROM and truncating things."""

# A comment mentioning DELETE FROM public.platform_audit_events.

REVOKED = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")


def describe(db):
    """Explains that v017 withheld DELETE FROM the projection."""
    db.delete_later("public.platform_audit_events")
    return f"REVOKE {', '.join(REVOKED)} ON public.platform_audit_events"
'''


def test_the_detector_names_a_planted_deletion() -> None:
    """A check that has only ever run over a clean tree proves nothing about
    itself."""
    assert deletion_sites_in(PLANTED, "planted") == {("planted", "purge_the_audit_log")}


TRIGGER_NEAR_MISS = '''
def install_refusal_trigger(db):
    db.execute("""
        CREATE TRIGGER refuse_evidence_truncate
        BEFORE TRUNCATE ON mod_deploy.attestation_enrolments
        FOR EACH STATEMENT EXECUTE FUNCTION mod_deploy.refuse_evidence_rewrite();
    """)
'''

TRUNCATE_STATEMENT_PLANT = """
def wipe(db):
    db.execute("TRUNCATE TABLE mod_deploy.attestation_enrolments")
"""


def test_the_detector_does_not_mistake_a_trigger_event_for_truncate() -> None:
    """`BEFORE TRUNCATE ON table` names a guarded event, not a statement.

    Control's lineage installs exactly these guards (dc_0010, dc_0011, dc_0013).
    Reading their event clause as row removal would make the ledger describe
    code that cannot delete a row. Ported from CP PR #187.
    """
    assert deletion_sites_in(TRIGGER_NEAR_MISS, "trigger_nearmiss") == set()


def test_a_real_truncate_statement_is_still_named() -> None:
    """SENSITIVITY for the exclusion above: only `TRUNCATE ON` is exempt."""
    assert deletion_sites_in(TRUNCATE_STATEMENT_PLANT, "truncate_plant") == {
        ("truncate_plant", "wipe")
    }


def test_the_detector_does_not_name_a_near_miss() -> None:
    """Prose, a comment, a privilege NAME in a tuple, a `REVOKE` statement and a
    call merely spelled like a deletion. Every one of these appears in real
    files here — the vendor lineage's grant verifiers are made of the fourth and
    fifth — and a detector that flagged them would be turned off within a week.
    """
    assert deletion_sites_in(NEAR_MISS, "nearmiss") == set()


SEAM_CALL_PLANT = """
from dotmac_deployment_control.attestation_trust_registry import repair_current_root
import dotmac_deployment_control.attestation_trust_registry as registry
import dotmac_deployment_control.host_admission_service as admission


def mounted_adapter(db):
    repair_current_root(db, custody_domain="host_attester", subject="host-1")
    registry.revoke_root(db, fingerprint="f", revocation_authority="operator")
    admission.revoke_target_host(db, target_id=None, authority="operator")
"""

SEAM_ALIAS_PLANT = """
from dotmac_deployment_control import revoke_target_admission_policy as drop
from dotmac_deployment_control.attestation_trust_registry import revoke_root as rv


def mounted_adapter(db):
    drop(db, target_id=None, authority="operator")
    rv(db, fingerprint="f", revocation_authority="operator")
"""

SEAM_DYNAMIC_PLANT = """
import dotmac_deployment_control as control


def mounted_adapter():
    return getattr(control, "revoke_target_host")
"""

SEAM_BENIGN_NEAR_MISS = '''"""Prose may name revoke_target_host, repair_current_root."""

import dotmac_deployment_control.host_admission_service as admission


def read_only(db, target_id):
    return admission.lock_target
'''

SEAM_LEDGER_SCOPE_PLANT = """
import dotmac_deployment_control as control

DELETION_SITES = (
    DeletionSite(symbol="revoke_target_host"),
    control.revoke_target_admission_policy(),
)


def helper():
    return control.revoke_target_host
"""


def test_not_composed_seam_premises_are_executable() -> None:
    """Every `NOT_COMPOSED` Control seam is declared, and none has a caller."""
    declared = {
        (site.module, site.symbol)
        for site in DELETION_SITES
        if site.module in NOT_COMPOSED_SEAMS
    }
    expected = {
        (module, symbol)
        for module, symbols in NOT_COMPOSED_SEAMS.items()
        for symbol in symbols
    }
    assert declared == expected
    assert all(
        site.reachability is Reachability.NOT_COMPOSED
        for site in DELETION_SITES
        if site.module in NOT_COMPOSED_SEAMS
    )
    assert not_composed_seam_reference_sites() == set()


def test_the_seam_detector_is_sensitive_to_calls() -> None:
    assert seam_references_in(SEAM_CALL_PLANT, NOT_COMPOSED_SEAMS) == {
        "repair_current_root",
        "revoke_root",
        "revoke_target_host",
    }


def test_the_seam_detector_is_sensitive_to_aliases_and_package_imports() -> None:
    """A re-exported name imported from the package, under an alias, is seen."""
    assert seam_references_in(SEAM_ALIAS_PLANT, NOT_COMPOSED_SEAMS) == {
        "revoke_target_admission_policy",
        "revoke_root",
    }


def test_the_seam_detector_is_sensitive_to_dynamic_references() -> None:
    assert seam_references_in(SEAM_DYNAMIC_PLANT, NOT_COMPOSED_SEAMS) == {
        "revoke_target_host"
    }


def test_the_seam_detector_ignores_prose_and_unrelated_reads() -> None:
    assert seam_references_in(SEAM_BENIGN_NEAR_MISS, NOT_COMPOSED_SEAMS) == set()


def test_the_ledger_exception_does_not_skip_sibling_helpers() -> None:
    """Only the exact declaration symbols are exempt; executable nodes are not."""
    assert seam_references_in(
        SEAM_LEDGER_SCOPE_PLANT, NOT_COMPOSED_SEAMS, allow_ledger_declaration=True
    ) == {"revoke_target_admission_policy", "revoke_target_host"}


def test_the_owner_module_is_scanned_rather_than_exempted() -> None:
    """It is in the scanned set and it yields nothing.

    A detector that excused the file defining it would say nothing about that
    file — and this owner is precisely where a convenient `DELETE` would be
    written. It issues `REVOKE`, never a deletion, and that is checked rather
    than described.
    """
    modules = {module for _, module in _scanned_files()}
    assert "vendor_cp.data_governance" in modules
    source = (ROOT / "src" / "vendor_cp" / "data_governance.py").read_text()
    assert deletion_sites_in(source, "vendor_cp.data_governance") == set()


# ── the exclusion's premise, and the composition ────────────────────────────


def test_the_downgrade_exclusion_rests_on_a_checkable_premise() -> None:
    """`downgrade` bodies are not scanned, and the reason has to be testable.

    The deploy path applies composed `heads` and refuses every other target, and
    the installed operator surface exposes no downgrade command at all. If
    either stops being true this fails, rather than the exclusion quietly
    widening.
    """
    from vendor_cp.migrations import COMPOSED_TARGET, deploy_target_refusal

    assert UNSCANNED_FUNCTIONS == ("downgrade",)
    assert deploy_target_refusal(COMPOSED_TARGET) is None
    for target in ("base", "-1", "ap_0001_approvals"):
        assert deploy_target_refusal(target) is not None

    cli = (ROOT / "src" / "vendor_cp" / "cli" / "__init__.py").read_text()
    assert '"downgrade"' not in cli


def test_every_declared_site_names_a_composed_distribution() -> None:
    known = {"dotmac-vendor-control-plane"} | {
        name.replace("_", "-") for name in COMPOSED_DISTRIBUTIONS
    }
    assert {site.distribution for site in DELETION_SITES} <= known


def test_the_rehearsal_only_site_targets_a_schema_no_lineage_builds() -> None:
    """Its premise, made enforceable: `bf_rehearsal` is created by a script in a
    disposable database, so it is absent from the composed catalogue — which is
    exactly why it is not in `GOVERNED_TABLES` and why the admission check does
    not refuse the production database for it."""
    from vendor_cp.commercial_backfill.shadow import SHADOW_SCHEMA
    from vendor_cp.data_governance import POLICY_BY_TABLE

    rehearsal = [
        site
        for site in DELETION_SITES
        if site.reachability is Reachability.REHEARSAL_ONLY
    ]
    assert [site.target for site in rehearsal] == [f"{SHADOW_SCHEMA}.shadow_verdicts"]
    assert not [q for q in POLICY_BY_TABLE if q.startswith(f"{SHADOW_SCHEMA}.")]


# ── the binding is executed, not merely present ─────────────────────────────


def test_the_deploy_path_calls_the_owner_in_the_composed_transaction() -> None:
    """The gate this repository's own inventory applies: a binding whose only
    consumer is a test is absent.

    `alembic/env.py` calls `enforce_retention` inside the same transaction the
    composed upgrade runs in, guarded by the DEPLOY path's
    `require_composed_heads` attribute — so `dotmac-platform admin migrate` is
    the consumer, and a refusal rolls the whole composition back instead of
    committing a half-governed database.
    """
    env = (ROOT / "alembic" / "env.py").read_text()
    assert "from vendor_cp.data_governance import enforce_retention" in env
    assert "enforce_retention(connection)" in env

    body = env.split('if config.attributes.get("require_composed_heads"):', 1)[1]
    guarded = body.split("\n\n", 1)[0]
    assert "_enforce_data_governance(connection)" in guarded


def test_the_census_owner_now_has_a_caller_outside_its_own_tests() -> None:
    """`table_inventory` said it was an INPUT to a future owner. This is that
    owner, and until it existed the census had no caller in the source tree at
    all — which by this repository's own rule made it absent."""
    callers = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src").rglob("*.py")
        if "table_inventory" in path.read_text(encoding="utf-8")
        and path.name != "table_inventory.py"
    )
    assert callers == ["src/vendor_cp/data_governance.py"]


# ── the operator-command seam: `revoke_root`, called by `lane3_e10 revoke` ──────
#
# `revoke_root` is no longer `NOT_COMPOSED`: the Lane 3 operator command calls it at
# step 15. Its ledger entry is `OPERATOR_COMMAND`, a reachability that is only as
# strong as the premises below, so they are executable and ratcheted both ways:
# exactly one caller; the command is loaded only by operator commands; and no
# online entrypoint ever has it in `sys.modules`.

OPERATOR_SEAM_OWNER = "dotmac_deployment_control.attestation_trust_registry"
OPERATOR_SEAMS: dict[str, frozenset[str]] = {
    OPERATOR_SEAM_OWNER: frozenset({"revoke_root"})
}
#: (module, top-level symbol) of the ONLY reference to the seam.
OPERATOR_SEAM_CALLERS = {("vendor_cp.deployment.lane3_e10", "ControlRegistry")}
LANE3_E10 = "vendor_cp.deployment.lane3_e10"
#: Every module that may import `lane3_e10`, directly or transitively. All three
#: are operator commands (`materials_producer issue`, `lane3_record export`, and
#: the custody helper only `materials_producer.main` loads).
LANE3_E10_IMPORTERS = frozenset(
    {
        "vendor_cp.deployment.lane3_record",
        "vendor_cp.deployment.materials_producer",
        "vendor_cp.deployment.transit_custody",
    }
)
ROUTE_IDENTIFIERS = frozenset(
    {
        "APIRouter",
        "FastAPI",
        "Router",
        "router",
        "routers",
        "route",
        "routes",
        "include_router",
        "add_api_route",
        "add_route",
    }
)
ROUTE_MODULES = ("fastapi", "starlette")
CONTROL_PIN = "0.1.0a17"


def _ledger_symbol_ids(tree: ast.AST, names: frozenset[str]) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "DeletionSite"
        ):
            for keyword in node.keywords:
                value = keyword.value
                if (
                    keyword.arg == "symbol"
                    and isinstance(value, ast.Constant)
                    and value.value in names
                ):
                    found.add(id(value))
    return found


def operator_seam_sites(
    source: str, module: str, names: frozenset[str], *, ledger: bool = False
) -> set[tuple[str, str]]:
    """`(module, top-level symbol)` of every reference to a seam name.

    Stricter than "calls": an import, an alias, a name or attribute read, or an
    exact string literal (the `getattr` / `importlib` route). Docstring prose and,
    in the ledger module, the `symbol=` constants of `DeletionSite(...)` are not
    references.
    """
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    skip = _ledger_symbol_ids(tree, names) if ledger else set()
    found: set[tuple[str, str]] = set()

    def visit(node: ast.AST, symbol: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                visit(child, symbol or child.name)
                continue
            where = symbol or "<module>"
            if id(child) in skip:
                continue
            if isinstance(child, ast.alias) and child.name.split(".")[-1] in names:
                found.add((module, where))
            elif isinstance(child, ast.Name) and child.id in names:
                found.add((module, where))
            elif isinstance(child, ast.Attribute) and child.attr in names:
                found.add((module, where))
            elif (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and id(child) not in docstrings
                and child.value in names
            ):
                found.add((module, where))
            visit(child, symbol)

    visit(tree, "")
    return found


def _imports(source: str, module: str, target: str) -> bool:
    """Does `source` (the module `module`) import `target`?

    Counts static imports (absolute and relative) AND exact string literals naming
    the module (`importlib.import_module("...lane3_e10")`, `".lane3_e10"`), so a
    dynamic load is caught as well as a statement.
    """
    parent, _, leaf = target.rpartition(".")
    package = module.rpartition(".")[0]
    literals = {target, f".{leaf}"}
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == target for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = package.split(".")
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join([*anchor, *([base] if base else [])])
            if base == target:
                return True
            if base == parent and any(alias.name == leaf for alias in node.names):
                return True
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and node.value in literals
        ):
            return True
    return False


def importer_closure(sources: dict[str, str], target: str) -> set[str]:
    """Every module that imports `target`, or imports one that does, transitively."""
    closure: set[str] = set()
    changed = True
    while changed:
        changed = False
        for module, source in sources.items():
            if module == target or module in closure:
                continue
            if any(_imports(source, module, t) for t in (target, *closure)):
                closure.add(module)
                changed = True
    return closure


def route_references(source: str) -> set[str]:
    """APIRouter / router / route identifiers, and fastapi/starlette imports."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found |= {
                a.name for a in node.names if a.name.split(".")[0] in ROUTE_MODULES
            }
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in ROUTE_MODULES:
                found.add(node.module or "")
            found |= {a.name for a in node.names if a.name in ROUTE_IDENTIFIERS}
        elif isinstance(node, ast.Name) and node.id in ROUTE_IDENTIFIERS:
            found.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in ROUTE_IDENTIFIERS:
            found.add(node.attr)
    return found


def _scanned_sources() -> dict[str, str]:
    return {
        module: path.read_text(encoding="utf-8") for path, module in _scanned_files()
    }


def _seam_callers(sources: dict[str, str]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    names = OPERATOR_SEAMS[OPERATOR_SEAM_OWNER]
    for module, source in sources.items():
        if module == OPERATOR_SEAM_OWNER:
            continue
        found |= operator_seam_sites(
            source, module, names, ledger=module == "vendor_cp.data_governance"
        )
    return found


def _route_modules(sources: dict[str, str], closure: set[str]) -> dict[str, set[str]]:
    return {
        module: refs
        for module in (*sorted(closure), LANE3_E10)
        if (refs := route_references(sources[module]))
    }


def test_the_operator_command_sites_are_exactly_revoke_root() -> None:
    """The ratchet, both directions: a second site, or revoke_root leaving the
    reachability, fails; and the constructor refuses any non-gauge target."""
    operator = {
        (site.module, site.symbol)
        for site in DELETION_SITES
        if site.reachability is Reachability.OPERATOR_COMMAND
    }
    assert operator == {(OPERATOR_SEAM_OWNER, "revoke_root")}
    # a repair that nothing calls stays NOT_COMPOSED
    assert (OPERATOR_SEAM_OWNER, "repair_current_root") not in operator
    assert NOT_COMPOSED_SEAMS[OPERATOR_SEAM_OWNER] == {"repair_current_root"}
    for target in ("public.platform_audit_log", "mod_deploy.rollout_attempts", "x.y"):
        with pytest.raises(ValueError, match="SUPERSEDED_IN_PLACE"):
            DeletionSite(
                distribution="dotmac-deployment-control",
                module="m",
                symbol="s",
                target=target,
                reachability=Reachability.OPERATOR_COMMAND,
                premise="p",
            )


def test_revoke_root_has_exactly_one_reference_and_it_is_the_operator_registry() -> (
    None
):
    sources = _scanned_sources()
    assert _seam_callers(sources) == OPERATOR_SEAM_CALLERS


def test_the_lane3_command_is_imported_only_by_operator_commands_and_no_route() -> None:
    """The transitive importer closure of `lane3_e10` (statements AND string
    literals, so an `importlib` load counts) is exactly the three operator
    modules, and none of those, nor `lane3_e10`, references a router or route."""
    sources = _scanned_sources()
    closure = importer_closure(sources, LANE3_E10)
    assert closure == LANE3_E10_IMPORTERS, sorted(closure)
    assert _route_modules(sources, closure) == {}


def test_the_installed_control_is_exactly_the_reviewed_pin() -> None:
    """`revoke_root` is reviewed against ONE Control build."""
    from importlib import metadata

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'dotmac-deployment-control = {{ version = "{CONTROL_PIN}"' in pyproject
    installed = metadata.version("dotmac-deployment-control")
    assert installed == CONTROL_PIN, (
        f"dotmac-deployment-control is {installed}, not the reviewed {CONTROL_PIN}. "
        "RE-REVIEW before changing this pin: `revoke_root` must still INSERT the "
        "closure row first and delete ONLY the current-root pointer that still "
        "names the revoked fingerprint (`attestation_trust_registry.revoke_root`), "
        "`lane3_e10 revoke` must still be its only caller, and the data-governance "
        "premise for `OPERATOR_COMMAND` must still hold."
    )


_ONLINE_ENTRYPOINTS = """
import importlib, pkgutil, sys
import vendor_cp.main                      # create_app(build_spec()): the ASGI app
import vendor_cp.relay as relay            # the outbox relay and its workers
for info in pkgutil.iter_modules(relay.__path__):
    importlib.import_module("vendor_cp.relay." + info.name)
import vendor_cp.cli as cli                # `dotmac-platform` (relay run, ...)
cli.build_parser()
%s
sys.exit(3 if "vendor_cp.deployment.lane3_e10" in sys.modules else 0)
"""


def _run_entrypoints(extra: str = "") -> subprocess.CompletedProcess[str]:
    dummy = "postgresql+psycopg://x:x@127.0.0.1:5432/vendor_control_plane_test"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": dummy,
        "PLATFORM_DATABASE_URL": dummy,
    }
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell, isolated mode
        [sys.executable, "-I", "-c", _ONLINE_ENTRYPOINTS % extra],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=300,
        check=False,
    )


def test_no_online_entrypoint_loads_the_lane3_command() -> None:
    """RUNTIME premise: build the app, import every relay worker and the CLI in a
    fresh `-I` interpreter; the operator command is not in `sys.modules`."""
    done = _run_entrypoints()
    assert done.returncode == 0, (done.returncode, done.stderr[-400:])


def test_the_runtime_probe_can_still_fail() -> None:
    """SENSITIVITY: the same probe, with the command imported, exits 3."""
    done = _run_entrypoints("import vendor_cp.deployment.lane3_e10")
    assert done.returncode == 3, (done.returncode, done.stderr[-400:])


# ── sensitivity plants ──────────────────────────────────────────────────────


def _planted(**extra: str) -> dict[str, str]:
    sources = {
        LANE3_E10: "def f():\n    pass\n",
        "vendor_cp.deployment.lane3_record": (
            "from vendor_cp.deployment.lane3_e10 import f\n"
        ),
        "vendor_cp.deployment.materials_producer": (
            "def g():\n    from vendor_cp.deployment import lane3_e10\n"
        ),
        "vendor_cp.deployment.transit_custody": (
            "from vendor_cp.deployment.materials_producer import g\n"
        ),
    }
    sources.update({k.replace("__", "."): v for k, v in extra.items()})
    return sources


def test_the_importer_closure_matches_the_expected_set_on_a_clean_plant() -> None:
    assert importer_closure(_planted(), LANE3_E10) == LANE3_E10_IMPORTERS


@pytest.mark.parametrize(
    "plant",
    [
        "from vendor_cp.deployment import lane3_e10\n",
        "import vendor_cp.deployment.lane3_e10\n",
        "from vendor_cp.deployment.lane3_e10 import ControlRegistry\n",
        "from . import lane3_e10\n",
        "from .lane3_e10 import ControlRegistry\n",
        "import importlib\nimportlib.import_module('vendor_cp.deployment.lane3_e10')\n",
        "import importlib\nimportlib.import_module('.lane3_e10', 'vendor_cp.deployment')\n",  # noqa: E501
        "from vendor_cp.deployment.materials_producer import g\n",  # transitive
        "from vendor_cp.deployment.transit_custody import g\n",
    ],
)
def test_a_planted_importer_of_the_command_breaks_the_closure(plant: str) -> None:
    sources = _planted(**{"vendor_cp__deployment__routes": plant})
    assert importer_closure(sources, LANE3_E10) == LANE3_E10_IMPORTERS | {
        "vendor_cp.deployment.routes"
    }


def test_a_planted_route_in_the_closure_is_named() -> None:
    plant = "from fastapi import APIRouter\nrouter = APIRouter()\n"
    sources = _planted(
        vendor_cp__deployment__routes=(
            plant + "from vendor_cp.deployment import lane3_e10\n"
        )
    )
    closure = importer_closure(sources, LANE3_E10)
    assert "vendor_cp.deployment.routes" in closure
    assert _route_modules(sources, closure) == {
        "vendor_cp.deployment.routes": {"fastapi", "APIRouter", "router"}
    }
    # a route planted into an EXISTING member of the closure is named too
    existing = _planted(
        vendor_cp__deployment__lane3_record=(
            plant + "from vendor_cp.deployment.lane3_e10 import f\n"
        )
    )
    assert _route_modules(existing, importer_closure(existing, LANE3_E10)) == {
        "vendor_cp.deployment.lane3_record": {"fastapi", "APIRouter", "router"}
    }


@pytest.mark.parametrize(
    "plant",
    [
        "from dotmac_deployment_control.attestation_trust_registry import revoke_root\n",  # noqa: E501
        "import dotmac_deployment_control.attestation_trust_registry as r\nr.revoke_root\n",  # noqa: E501
        "x = getattr(m, 'revoke_root')\n",
        "def late(db):\n    return revoke_root(db)\n",
    ],
)
def test_a_second_revoke_root_caller_is_a_different_site(plant: str) -> None:
    sources = {
        "vendor_cp.deployment.lane3_e10": (
            "class ControlRegistry:\n    def revoke(self):\n"
            "        from dotmac_deployment_control.attestation_trust_registry "
            "import revoke_root\n        revoke_root()\n"
        ),
        "vendor_cp.other": plant,
    }
    sites = _seam_callers(sources)
    assert sites >= OPERATOR_SEAM_CALLERS
    assert any(module == "vendor_cp.other" for module, _ in sites)
    assert sites != OPERATOR_SEAM_CALLERS


def test_the_seam_scan_ignores_prose_near_misses_and_the_ledger_declaration() -> None:
    names = OPERATOR_SEAMS[OPERATOR_SEAM_OWNER]
    benign = (
        '"""Calls revoke_root."""\n'
        "# revoke_root in a comment\n"
        "def revoke_root_report():\n    return 'revoke_root_x'\n"
    )
    assert operator_seam_sites(benign, "m", names) == set()
    ledger = "DELETION_SITES = (DeletionSite(symbol='revoke_root', premise='p'),)\n"
    assert (
        operator_seam_sites(ledger, "vendor_cp.data_governance", names, ledger=True)
        == set()
    )
    assert operator_seam_sites(ledger, "vendor_cp.other", names) == {
        ("vendor_cp.other", "<module>")
    }
