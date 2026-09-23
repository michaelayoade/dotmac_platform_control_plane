"""The rehearsal issuer source seam imports only its exact stdlib dependencies."""

from __future__ import annotations

import ast
from pathlib import Path

from import_scanner import module_targets, scan_imports

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
LEAF = SRC / "vendor_cp" / "deployment" / "rehearsal_issuer_seam.py"

ALLOWED_MODULES = frozenset(
    {"__future__", "collections.abc", "dataclasses", "types", "uuid"}
)
EXPECTED_METHODS = {
    "RehearsalIssuerCommand": ("__post_init__", "to_control_request"),
    "RehearsalIssuerInvocation": ("__post_init__", "to_control_request"),
}
ALLOWED_CALL_TARGETS = frozenset(
    {
        "dataclass",
        "isinstance",
        "type",
        "TypeError",
        "ValueError",
        "self.command_id.strip",
        "self.actor_ref.strip",
        "MappingProxyType",
        "self.command.to_control_request",
    }
)


def _offenders(path: Path, *, source_root: Path) -> list[str]:
    static = module_targets(scan_imports(path, source_root=source_root))
    dynamic: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            dynamic.add("dynamic:__import__")
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
        ):
            dynamic.add("dynamic:importlib.import_module")
    return sorted((static - ALLOWED_MODULES) | dynamic)


def _call_target(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_target(node.value)}.{node.attr}"
    return "<computed-call>"


def _behavior_offenders(tree: ast.Module) -> list[str]:
    offenders: set[str] = set()
    definitions = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    if [(type(node).__name__, node.name) for node in definitions] != [
        ("ClassDef", name) for name in EXPECTED_METHODS
    ]:
        offenders.add("surface:top-level")
    for node in tree.body:
        if isinstance(node, ast.ImportFrom | ast.ClassDef):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                continue  # module docstring
        offenders.add("surface:top-level-statement")

    for class_node in definitions:
        if not isinstance(class_node, ast.ClassDef):
            continue
        expected = EXPECTED_METHODS.get(class_node.name)
        if expected is None:
            continue
        methods = [
            node
            for node in class_node.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        if [type(node).__name__ for node in methods] != ["FunctionDef"] * len(
            expected
        ) or [node.name for node in methods] != list(expected):
            offenders.add(f"surface:{class_node.name}.methods")
        for method in methods:
            args = method.args
            if (
                [arg.arg for arg in args.args] != ["self"]
                or args.posonlyargs
                or args.vararg
                or args.kwonlyargs
                or args.kwarg
                or args.defaults
                or args.kw_defaults
                or method.decorator_list
            ):
                offenders.add(f"signature:{class_node.name}.{method.name}")

    calls = {
        _call_target(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)
    }
    offenders.update(f"call:{target}" for target in calls - ALLOWED_CALL_TARGETS)
    return sorted(offenders)


def test_leaf_exists_and_uses_only_declared_stdlib_imports() -> None:
    assert LEAF.is_file(), LEAF
    assert _offenders(LEAF, source_root=SRC) == []
    assert _behavior_offenders(ast.parse(LEAF.read_text())) == []


def test_planted_forbidden_imports_are_detected(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    plant = source_root / "plant.py"
    plant.write_text(
        "from vendor_cp.deployment import adapter\n"
        "import dotmac_deployment_control\n"
        "from dotmac_deployment_foundation import plans\n"
        "from dotmac_kernel import db\n"
        "from sqlalchemy.orm import Session\n"
    )
    assert _offenders(plant, source_root=source_root) == [
        "dotmac_deployment_control",
        "dotmac_deployment_foundation",
        "dotmac_kernel",
        "sqlalchemy.orm",
        "vendor_cp.deployment",
    ]


def test_planted_dynamic_import_calls_are_detected(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    plant = source_root / "dynamic_plant.py"
    plant.write_text(
        "import importlib\n"
        "__import__('dotmac_deployment_control')\n"
        "importlib.import_module('vendor_cp.deployment.adapter')\n"
    )
    assert _offenders(plant, source_root=source_root) == [
        "dynamic:__import__",
        "dynamic:importlib.import_module",
        "importlib",
    ]


def test_planted_clean_imports_pass_the_boundary(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    clean = source_root / "clean.py"
    clean.write_text(
        "from __future__ import annotations\n"
        "from collections.abc import Mapping\n"
        "from dataclasses import dataclass\n"
        "from types import MappingProxyType\n"
        "from uuid import UUID\n"
    )
    assert (
        module_targets(scan_imports(clean, source_root=source_root)) == ALLOWED_MODULES
    )
    assert _offenders(clean, source_root=source_root) == []


def test_planted_callback_call_is_refused_inside_existing_method() -> None:
    tree = ast.parse(LEAF.read_text())
    command = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RehearsalIssuerCommand"
    )
    method = next(
        node
        for node in command.body
        if isinstance(node, ast.FunctionDef) and node.name == "to_control_request"
    )
    method.body.extend(ast.parse("callback()\n").body)
    assert _behavior_offenders(tree) == ["call:callback"]


def test_planted_execution_function_and_method_shape_are_refused() -> None:
    tree = ast.parse(LEAF.read_text())
    tree.body.extend(ast.parse("def issue(callback):\n    callback()\n").body)
    assert _behavior_offenders(tree) == [
        "call:callback",
        "surface:top-level",
        "surface:top-level-statement",
    ]

    tree = ast.parse(LEAF.read_text())
    command = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RehearsalIssuerCommand"
    )
    command.body.extend(ast.parse("def issue(self):\n    pass\n").body)
    assert _behavior_offenders(tree) == ["surface:RehearsalIssuerCommand.methods"]

    tree = ast.parse(LEAF.read_text())
    command = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RehearsalIssuerCommand"
    )
    method = next(
        node
        for node in command.body
        if isinstance(node, ast.FunctionDef) and node.name == "to_control_request"
    )
    method.args.args.append(ast.arg(arg="callback"))
    assert _behavior_offenders(tree) == [
        "signature:RehearsalIssuerCommand.to_control_request"
    ]
