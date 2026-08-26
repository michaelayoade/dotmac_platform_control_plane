"""ADR-0007: fleet/profile code records intent and never performs external I/O.

The boundary is transitive. Checking only ``fleet/service.py`` would permit a
one-line delegated helper to become the real runner while the named directory
stayed clean. The graph below starts at both intent domains and at every
script/job/worker whose local dependency graph reaches them, then walks every
absolute ``vendor_cp`` import. Relative imports are refused in this region: an
unresolved edge is unmonitored code, not evidence that the dependency is safe.

This is an import/call-structure check. Comments and docstrings never participate
and therefore cannot be punished for explaining the rule.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = ROOT / "src" / "vendor_cp"
DOMAIN_PACKAGES = (
    "vendor_cp.fleet",
    "vendor_cp.managed_profiles",
    "vendor_cp.planning",
)
ENTRYPOINT_ROOTS = (
    ROOT / "scripts",
    ROOT / "jobs",
    ROOT / "workers",
    VENDOR_ROOT / "jobs",
    VENDOR_ROOT / "workers",
)

# Fleet intent can use the standard library, the kernel, web/schema/ORM
# primitives and Vendor-local modules. Anything else is not assumed harmless:
# an unrecognised provider SDK must fail on its first import, not after someone
# remembers to add its brand to a denylist.
ALLOWED_IMPORT_ROOTS = frozenset(
    {
        "dotmac_kernel",
        "dotmac_approvals",
        "dotmac_entitlement_allocation",
        "dotmac_release_catalog",
        "fastapi",
        # Pure in-process JSON Schema validation over already-held bytes.  It
        # has no transport role; the guard still walks its Vendor-local callers
        # and continues to refuse every unrecognised provider dependency.
        "jsonschema",
        "pydantic",
        "sqlalchemy",
        "vendor_cp",
    }
)

FORBIDDEN_STDLIB_IMPORTS = frozenset(
    {
        "ftplib",
        "http.client",
        "imaplib",
        "importlib.metadata",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "asyncio.open_connection",
        "asyncio.start_server",
        "os.popen",
        "os.system",
        "poplib",
        "smtplib",
        "socket",
        "subprocess",
        "telnetlib",
        "urllib.request",
        "xmlrpc.client",
    }
)

FORBIDDEN_CALL_PREFIXES = ("os.exec", "os.spawn")

FORBIDDEN_IMPORT_PREFIXES = frozenset(
    {
        "dotmac_kernel.secret_sources",
        "dotmac_kernel.settings_crypto",
        "vendor_cp.production_secrets",
        "vendor_cp.providers",
        "vendor_cp.provisioning",
    }
)

FORBIDDEN_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "importlib.import_module",
        "os.popen",
        "os.system",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "socket.create_connection",
        "socket.socket",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
        "urllib.request.urlopen",
        "__import__",
    }
)


@dataclass(frozen=True, slots=True)
class ImportRef:
    module: str
    names: tuple[str, ...]
    level: int = 0


def _python_files(root: Path) -> set[Path]:
    if not root.exists():
        return set()
    return {path for path in root.rglob("*.py") if "__pycache__" not in path.parts}


def _imports(path: Path) -> tuple[ImportRef, ...]:
    refs: list[ImportRef] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            refs.extend(ImportRef(alias.name, ()) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Preserve the level even when node.module is None. Dropping that
            # case made ``from .. import provider_transport`` invisible.
            refs.append(
                ImportRef(
                    module=node.module or "",
                    names=tuple(alias.name for alias in node.names),
                    level=node.level,
                )
            )
    return tuple(refs)


def _module_name(path: Path, vendor_root: Path) -> str | None:
    try:
        relative = path.relative_to(vendor_root)
    except ValueError:
        return None
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(("vendor_cp", *parts))


def _module_index(vendor_root: Path) -> dict[str, Path]:
    return {
        module: path
        for path in _python_files(vendor_root)
        if (module := _module_name(path, vendor_root)) is not None
    }


def _local_dependencies(path: Path, modules: dict[str, Path]) -> set[Path]:
    dependencies: set[Path] = set()
    for ref in _imports(path):
        if ref.level:
            # Kept unresolved on purpose; the violation scanner reports it.
            continue
        candidates = [ref.module]
        candidates.extend(f"{ref.module}.{name}" for name in ref.names if ref.module)
        for candidate in candidates:
            if resolved := modules.get(candidate):
                dependencies.add(resolved)
    return dependencies


def _closure(start: Iterable[Path], modules: dict[str, Path]) -> set[Path]:
    reachable = set(start)
    pending = list(reachable)
    while pending:
        current = pending.pop()
        for dependency in _local_dependencies(current, modules):
            if dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    return reachable


def _fleet_reachable_files(
    vendor_root: Path = VENDOR_ROOT,
    entrypoint_roots: Iterable[Path] = ENTRYPOINT_ROOTS,
) -> set[Path]:
    modules = _module_index(vendor_root)
    domain_files = {
        path
        for module, path in modules.items()
        if any(
            module == root or module.startswith(f"{root}.") for root in DOMAIN_PACKAGES
        )
    }
    reachable = _closure(domain_files, modules)

    # An entrypoint can delegate through a helper before reaching a fleet
    # domain. Compute its full local closure first; direct-import-only scans miss
    # exactly that escape.
    for root in entrypoint_roots:
        for entrypoint in _python_files(root):
            entrypoint_closure = _closure({entrypoint}, modules)
            if entrypoint_closure & domain_files:
                reachable |= entrypoint_closure
    return reachable


def _attribute_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _external_io_violations(paths: Iterable[Path]) -> list[str]:
    violations: list[str] = []
    for path in sorted(paths):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for ref in _imports(path):
            if ref.level:
                rendered = "." * ref.level + ref.module
                violations.append(
                    f"{path}: unresolved relative import {rendered or '.'} "
                    f"({', '.join(ref.names)})"
                )
                continue
            imported_modules = (ref.module,) + tuple(
                f"{ref.module}.{name}" for name in ref.names if ref.module
            )
            root = ref.module.split(".", 1)[0]
            if any(
                imported == forbidden or imported.startswith(f"{forbidden}.")
                for imported in imported_modules
                for forbidden in FORBIDDEN_IMPORT_PREFIXES
            ):
                violations.append(
                    f"{path}: forbidden executor/secret import "
                    f"{'/'.join(imported_modules)}"
                )
            elif any(
                imported == forbidden or imported.startswith(f"{forbidden}.")
                for imported in imported_modules
                for forbidden in FORBIDDEN_STDLIB_IMPORTS
            ):
                violations.append(
                    f"{path}: forbidden I/O import {'/'.join(imported_modules)}"
                )
            elif (
                root
                and root not in sys.stdlib_module_names
                and root not in ALLOWED_IMPORT_ROOTS
            ):
                violations.append(f"{path}: undeclared external import {ref.module}")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call = _attribute_name(node.func)
            if call in FORBIDDEN_CALLS or (
                call is not None
                and any(call.startswith(prefix) for prefix in FORBIDDEN_CALL_PREFIXES)
            ):
                violations.append(f"{path}:{node.lineno}: external call {call}")
    return violations


def _dependency_calls(route: APIRoute) -> set[object]:
    calls: set[object] = set()
    pending = list(route.dependant.dependencies)
    while pending:
        dependency = pending.pop()
        if dependency.call is not None:
            calls.add(dependency.call)
        pending.extend(dependency.dependencies)
    return calls


def test_fleet_and_profiles_are_external_io_free_transitively() -> None:
    reachable = _fleet_reachable_files()
    assert reachable, "fleet/profile domains are missing from the composed source tree"
    assert not (violations := _external_io_violations(reachable)), (
        "Vendor owns desired state, never provider execution; external I/O belongs "
        f"to Integrator connector plugins (ADR-0007): {violations}"
    )


def test_composed_fleet_routes_are_platform_admin_guarded() -> None:
    from dotmac_kernel.platform_auth import require_platform_admin

    from vendor_cp.assembly import VENDOR_SURFACES

    routed_packages: list[str] = []
    for qualified in DOMAIN_PACKAGES:
        package = qualified.rsplit(".", 1)[-1]
        feature_path = VENDOR_ROOT / package / "feature.py"
        router_path = VENDOR_ROOT / package / "router.py"
        if not feature_path.exists() and not router_path.exists():
            continue
        assert (
            feature_path.exists() and router_path.exists()
        ), f"{package} has only half of a routed feature"
        routed_packages.append(package)
        feature = importlib.import_module(f"vendor_cp.{package}.feature").feature
        router = importlib.import_module(f"vendor_cp.{package}.router").router

        assert (
            feature in VENDOR_SURFACES
        ), f"{package} feature exists but is not composed"
        assert (
            router in feature.routers
        ), f"{package} router is not mounted by its feature"
        unguarded = [
            route.path
            for route in router.routes
            if isinstance(route, APIRoute)
            and require_platform_admin not in _dependency_calls(route)
        ]
        assert (
            not unguarded
        ), f"{package} routes lack require_platform_admin: {unguarded}"
    assert routed_packages, "Stack 1 exposes no platform-admin fleet surface"


@pytest.mark.parametrize(
    "source, expected",
    (
        ("import httpx\nhttpx.get('https://provider.invalid')\n", "httpx"),
        ("import subprocess\nsubprocess.run(['provider'])\n", "subprocess"),
        ("import smtplib\n", "smtplib"),
        ("from urllib import request\n", "urllib"),
        ("from os import system\n", "os.system"),
        ("import importlib\nimportlib.import_module('provider_sdk')\n", "importlib"),
        ("import vendor_cp.providers\n", "vendor_cp.providers"),
        ("import never_seen_cloud_sdk\n", "never_seen_cloud_sdk"),
        ("from .. import provider_transport\n", "provider_transport"),
    ),
)
def test_external_io_guard_sensitivity(
    tmp_path: Path, source: str, expected: str
) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(source, encoding="utf-8")
    violations = _external_io_violations({probe})
    assert violations and expected in " ".join(violations)


def test_transitive_guard_follows_a_delegated_helper(tmp_path: Path) -> None:
    vendor_root = tmp_path / "src" / "vendor_cp"
    fleet = vendor_root / "fleet"
    shared = vendor_root / "shared"
    fleet.mkdir(parents=True)
    shared.mkdir(parents=True)
    (fleet / "service.py").write_text(
        "import vendor_cp.shared.provider_transport\n", encoding="utf-8"
    )
    (shared / "provider_transport.py").write_text(
        "import never_seen_cloud_sdk\n", encoding="utf-8"
    )

    reachable = _fleet_reachable_files(vendor_root, ())
    assert shared / "provider_transport.py" in reachable
    assert "never_seen_cloud_sdk" in " ".join(_external_io_violations(reachable))


def test_entrypoint_guard_follows_helper_before_fleet(tmp_path: Path) -> None:
    vendor_root = tmp_path / "src" / "vendor_cp"
    fleet = vendor_root / "fleet"
    shared = vendor_root / "shared"
    scripts = tmp_path / "scripts"
    fleet.mkdir(parents=True)
    shared.mkdir(parents=True)
    scripts.mkdir()
    (fleet / "service.py").write_text("VALUE = 1\n", encoding="utf-8")
    (shared / "launcher.py").write_text(
        "import vendor_cp.fleet.service\n", encoding="utf-8"
    )
    script = scripts / "apply_fleet.py"
    script.write_text(
        "import vendor_cp.shared.launcher\nimport never_seen_cloud_sdk\n",
        encoding="utf-8",
    )

    reachable = _fleet_reachable_files(vendor_root, (scripts,))
    assert script in reachable
    assert "never_seen_cloud_sdk" in " ".join(_external_io_violations(reachable))


def test_guard_is_structural_not_prose_matching(tmp_path: Path) -> None:
    probe = tmp_path / "explanation.py"
    probe.write_text(
        inspect.cleandoc(
            '''
            """Do not import httpx or call subprocess.run here."""
            EXPLANATION = "from .. import provider_transport"
            '''
        ),
        encoding="utf-8",
    )
    assert _external_io_violations({probe}) == []
