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
import re
from pathlib import Path

from vendor_cp.data_governance import (
    DELETION_SITES,
    UNSCANNED_FUNCTIONS,
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
    r"\bDELETE\s+FROM\b|\bTRUNCATE\s+(?:TABLE\s+)?[A-Za-z_\"{]", re.IGNORECASE
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


def test_the_detector_does_not_name_a_near_miss() -> None:
    """Prose, a comment, a privilege NAME in a tuple, a `REVOKE` statement and a
    call merely spelled like a deletion. Every one of these appears in real
    files here — the vendor lineage's grant verifiers are made of the fourth and
    fifth — and a detector that flagged them would be turned off within a week.
    """
    assert deletion_sites_in(NEAR_MISS, "nearmiss") == set()


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
