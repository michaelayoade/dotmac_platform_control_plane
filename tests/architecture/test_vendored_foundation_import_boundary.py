"""Only the Lane 3 operator command may import the vendored Foundation verifier (H1).

`vendor_cp.vendored_foundation` is a byte-for-byte copy of Foundation source, pinned
PROVISIONAL-PENDING-E5. Its single consumer is step 8 (`lane3_e10.record_destruction`).
A second importer would make an unreviewed copy of a verifier an authority elsewhere
(a web route, a service), so the consumer set is closed and named. Derived by an AST
scan of `src/`, never a list of files to look at, and it carries a sensitivity proof.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = "vendor_cp.vendored_foundation"
ALLOWED = {"vendor_cp.deployment.lane3_e10"}


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _docstring_ids(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def importers_of_vendored(source: str, module: str, is_package: bool = False) -> bool:
    """Whether `source` (module `module`) imports the vendored package, any form."""
    pkg = module if is_package else module.rpartition(".")[0]
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and "vendored_foundation" in node.value
        ):
            # importlib / __import__ by string, in any spelling, absolute or relative
            return True
        if isinstance(node, ast.Import):
            if any(
                a.name == PACKAGE or a.name.startswith(PACKAGE + ".")
                for a in node.names
            ):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg.split(".")
                base = base[: len(base) - (node.level - 1)]
                target = ".".join([*base, *([node.module] if node.module else [])])
            else:
                target = node.module or ""
            if target == PACKAGE or target.startswith(PACKAGE + "."):
                return True
            if target == "vendor_cp" and any(
                a.name == "vendored_foundation" for a in node.names
            ):
                return True
    return False


def test_only_the_lane3_operator_command_imports_the_vendored_verifier() -> None:
    found = set()
    for path in sorted(SRC.rglob("*.py")):
        module = _module_name(path)
        if module == PACKAGE or module.startswith(PACKAGE + "."):
            continue  # the package's own files
        if importers_of_vendored(
            path.read_text(encoding="utf-8"), module, path.name == "__init__.py"
        ):
            found.add(module)
    assert found == ALLOWED, sorted(found ^ ALLOWED)


def test_the_boundary_detector_can_still_fail() -> None:
    """SENSITIVITY: every import form is named, and near-misses are not."""
    for source in (
        "import vendor_cp.vendored_foundation.trusted_host_source",
        "from vendor_cp.vendored_foundation import errors",
        "from vendor_cp.vendored_foundation.digest import Digest",
        "from vendor_cp import vendored_foundation",
    ):
        assert importers_of_vendored(source, "vendor_cp.web.x")
    assert importers_of_vendored(
        "from ..vendored_foundation import errors", "vendor_cp.web.x"
    )
    assert importers_of_vendored(
        "from .vendored_foundation import errors", "vendor_cp", True
    )
    for source in (
        "import importlib\n"
        'importlib.import_module("vendor_cp.vendored_foundation.errors")',
        '__import__("vendor_cp.vendored_foundation")',
        "import importlib\n"
        'importlib.import_module(".vendored_foundation", "vendor_cp")',
        "import importlib\n"
        'importlib.import_module(f"vendor_cp.vendored_foundation.{x}")',
    ):
        assert importers_of_vendored(source, "vendor_cp.web.x"), source
    for source in (
        "import vendor_cp.vendored_foundation_notes",
        "from dotmac_deployment_foundation import errors",
        '"""vendor_cp.vendored_foundation prose"""',
    ):
        assert not importers_of_vendored(source, "vendor_cp.web.x")
