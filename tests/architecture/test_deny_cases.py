"""D1–D5 deny-case architecture tests — the vendor control plane's boundaries.

These fail the build if the control plane drifts across a boundary the design
forbids: a second/product database (D1), product data-plane code (D2), Vendor
external-provider execution (D3), non-kernel auth (D4), or private/copied kernel
code (D5).
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import dotmac_kernel
import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "vendor_cp"
ENTRYPOINTS = ROOT / "scripts"


def _py_files() -> list[Path]:
    return [
        p
        for root in (SRC, ENTRYPOINTS)
        for p in root.rglob("*.py")
        if "__pycache__" not in p.parts
    ]


def _imports(path: Path) -> list[tuple[str, str | None]]:
    """(module, imported_name|None) for every import in a file."""
    out: list[tuple[str, str | None]] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out += [(a.name, None) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out += [(node.module, a.name) for a in node.names]
    return out


# ── D1 — one control-plane database; the kernel owns the engine ──────────────

# Connection constructors, not just SQLAlchemy's. `psycopg.connect` opens a
# database exactly as effectively as `create_engine`, so a guard naming only the
# latter can be satisfied by changing library — which is evading the rule rather
# than following it.
_CONNECTION_CONSTRUCTORS = ("create_engine", "sessionmaker", "psycopg.connect")

#: The ONE entrypoint permitted to construct a connection, with the enforceable
#: premises that make it not a violation of D1's purpose.
#:
#: D1 protects "one control-plane database, and the kernel owns its engine". The
#: read-only inventory is the opposite case by design: an operator names a
#: target for a single run, precisely so nothing infers one from configuration.
#: It is allowed here because — and only while — all three hold, each checked in
#: `tests/architecture/test_inventory_boundaries.py`:
#:
#:   1. the DSN is supplied explicitly and never read from the app's own
#:      environment variables or any deployment config;
#:   2. the transaction is opened READ ONLY, so the database refuses writes;
#:   3. it writes to neither system, and records nothing anywhere.
#:
#: An entry added here without those properties is a second database creeping in
#: under an exemption written for something else.
#: EMPTY again. The read-only inventory was the one entry, and it retired with
#: its purpose: the estate question was answered by a direct check
#: (TARGET_ABSENT) and the tables the tool read no longer exist. An exemption
#: that outlives the thing it was written for is an exemption the next author
#: inherits without the argument that justified it.
_D1_CONNECTION_ALLOWLIST: set[str] = set()


def test_d1_no_engine_or_session_construction() -> None:
    bad = [
        f"{p.name}: {fn}("
        for p in _py_files()
        if p.name not in _D1_CONNECTION_ALLOWLIST
        for fn in _CONNECTION_CONSTRUCTORS
        if re.search(rf"\b{re.escape(fn)}\s*\(", p.read_text())
    ]
    assert (
        not bad
    ), f"vendor code must use the kernel's single engine, not build one: {bad}"


def test_d1_allowlist_names_only_files_that_exist() -> None:
    """An allowlist entry for a deleted file is an exemption nobody is using and
    everybody inherits."""
    present = {p.name for p in _py_files()}
    stale = sorted(_D1_CONNECTION_ALLOWLIST - present)
    assert not stale, f"allowlisted file no longer exists: {stale}"


def test_d1_allowlist_is_the_only_connecting_entrypoint() -> None:
    """NON-VACUITY: the allowlisted file really does construct a connection, so
    the exemption is load-bearing rather than decorative."""
    connecting = {
        p.name
        for p in _py_files()
        for fn in _CONNECTION_CONSTRUCTORS
        if re.search(rf"\b{re.escape(fn)}\s*\(", p.read_text())
    }
    assert connecting == _D1_CONNECTION_ALLOWLIST, (
        "the set of files constructing a database connection changed: "
        f"{sorted(connecting ^ _D1_CONNECTION_ALLOWLIST)}"
    )


@pytest.mark.parametrize(
    ("source", "constructor"),
    [
        pytest.param("sessionmaker()\n", "sessionmaker", id="sessionmaker"),
        pytest.param("create_engine('x')\n", "create_engine", id="create-engine"),
        pytest.param(
            "import psycopg\npsycopg.connect('x')\n",
            "psycopg.connect",
            id="psycopg-connect",
        ),
    ],
)
def test_d1_session_authority_guard_covers_every_entrypoint_family(
    source: str, constructor: str
) -> None:
    """SENSITIVITY: each forbidden constructor, in a scripts/ file, must trip
    the guard — including the one a determined author would reach for after
    finding `create_engine` blocked."""
    probe = ENTRYPOINTS / "_session_authority_sensitivity.py"
    probe.write_text(source, encoding="utf-8")
    try:
        bad = [
            p
            for p in _py_files()
            if re.search(
                rf"\b{re.escape(constructor)}\s*\(", p.read_text(encoding="utf-8")
            )
        ]
        assert probe in bad
    finally:
        probe.unlink()


def test_d1_no_product_database_dsns() -> None:
    bad = [
        f"{p.name}: {m}"
        for p in _py_files()
        for m in re.findall(
            r"[A-Z0-9_]*(?:SUB|CRM|ERP|PRODUCT)[A-Z0-9_]*DATABASE_URL", p.read_text()
        )
    ]
    assert not bad, f"no product database DSNs — one control-plane database only: {bad}"


# ── D2 — no product data-plane imports (cross-database via code) ─────────────
_PRODUCT_ROOTS = {"dotmac_sub", "dotmac_crm", "dotmac_erp", "crm", "erp", "app"}


def test_d2_no_product_domain_imports() -> None:
    bad = [
        f"{p.name}: import {mod}"
        for p in _py_files()
        for mod, _ in _imports(p)
        if mod.split(".")[0] in _PRODUCT_ROOTS
    ]
    assert not bad, f"vendor CP must not import product data-plane code: {bad}"


# ── D3 — Integrator alone owns provider I/O; no provider SDKs in Vendor ─────
_REAL_PROVIDER_SDKS = {
    "boto3",
    "botocore",
    "kubernetes",
    "googleapiclient",
    "azure",
    "hcloud",
    "digitalocean",
    "openstack",
    "libvirt",
    "proxmoxer",
    "docker",
}


def test_d3_no_real_provider_sdk_imports() -> None:
    bad = [
        f"{p.name}: import {mod}"
        for p in _py_files()
        for mod, _ in _imports(p)
        if mod.split(".")[0] in _REAL_PROVIDER_SDKS
    ]
    assert not bad, (
        "Vendor records provider-neutral intent; provider SDKs belong only to "
        f"Integrator connector plugins (ADR-0007): {bad}"
    )


# ── D4 — platform-admin auth THROUGH the kernel ──────────────────────────────
def test_d4_console_web_routes_are_platform_admin_guarded() -> None:
    from dotmac_kernel.platform_auth import require_platform_admin

    from vendor_cp.console.web import router

    unguarded = []
    for route in router.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        deps = [
            p.default.dependency
            for p in inspect.signature(endpoint).parameters.values()
            if hasattr(p.default, "dependency")
        ]
        if require_platform_admin not in deps:
            unguarded.append(getattr(route, "path", "?"))
    assert not unguarded, (
        "every vendor web route must depend on the kernel's require_platform_admin "
        f"(no local auth): {unguarded}"
    )


# ── D5 — only the kernel's PUBLIC surface; no private/internal/copied code ────
def test_d5_only_public_kernel_surface_is_imported() -> None:
    supported = set(dotmac_kernel.SUPPORTED_MODULES)
    internal = set(dotmac_kernel.INTERNAL_MODULES)
    top_level = set(dotmac_kernel.__all__)
    bad: list[str] = []
    for p in _py_files():
        for mod, name in _imports(p):
            if not (mod == "dotmac_kernel" or mod.startswith("dotmac_kernel.")):
                continue
            if mod == "dotmac_kernel":
                if name and name not in top_level:
                    bad.append(f"{p.name}: top-level `{name}` not in public __all__")
            elif mod in internal:
                bad.append(f"{p.name}: imports INTERNAL kernel module {mod}")
            elif mod not in supported:
                bad.append(f"{p.name}: imports non-supported kernel module {mod}")
            if name and name.startswith("_"):
                bad.append(f"{p.name}: imports private name {name} from {mod}")
    assert not bad, f"vendor CP may import ONLY the kernel's public surface: {bad}"


# ── D6 — no deployment-mode / plan-name branching in commercial logic ────────
# ADR-0003 ban (design case 10): a contract/commercial decision reads explainable
# local values (status, capability codes, quorum), never a profile/plan/mode
# string. Scan the contracts domain for `if <mode/plan/tier/profile> == "..."`.
_BANNED_BRANCH = re.compile(
    r"\b(deployment_mode|plan_name|plan|tier|profile_code|mode)\b\s*(==|!=|in)\s*",
)


def test_d6_no_plan_or_mode_string_branching_in_contracts() -> None:
    bad: list[str] = []
    for p in (SRC / "contracts").rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            code = line.split("#", 1)[0]
            if _BANNED_BRANCH.search(code):
                bad.append(f"{p.name}:{i}: {line.strip()}")
    assert not bad, (
        "commercial logic must not branch on a plan/mode/profile string "
        f"(ADR-0003): {bad}"
    )
