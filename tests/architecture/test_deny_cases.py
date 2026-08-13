"""D1–D5 deny-case architecture tests — the vendor control plane's boundaries.

These fail the build if the control plane drifts across a boundary the design
forbids: a second/product database (D1), product data-plane code (D2), a real
provider (D3), non-kernel auth (D4), or private/copied kernel code (D5).
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import dotmac_kernel

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
def test_d1_no_engine_or_session_construction() -> None:
    bad = [
        f"{p.name}: {fn}("
        for p in _py_files()
        for fn in ("create_engine", "sessionmaker")
        if re.search(rf"\b{fn}\s*\(", p.read_text())
    ]
    assert (
        not bad
    ), f"vendor code must use the kernel's single engine, not build one: {bad}"


def test_d1_session_authority_guard_covers_every_entrypoint_family() -> None:
    """SENSITIVITY: a forbidden constructor in scripts must trip the guard."""
    probe = ENTRYPOINTS / "_session_authority_sensitivity.py"
    probe.write_text("sessionmaker()\n", encoding="utf-8")
    try:
        bad = [
            p
            for p in _py_files()
            if re.search(r"\bsessionmaker\s*\(", p.read_text(encoding="utf-8"))
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


# ── D3 — fake providers only; no real-provider SDKs ──────────────────────────
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
    assert not bad, f"no real-provider SDKs — fake providers only this phase: {bad}"


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
