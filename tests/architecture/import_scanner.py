"""One import scanner, because three guards were each half-blind on their own.

`test_allocations_authority.py` and `test_deployment_profile.py` both ask "does any
source file reach for X?" and both answered it with a walk that matched only
`from <exact.module> import <name>`. Every other import form was invisible:

    import vendor_cp.allocations.models            # not an ImportFrom at all
    import vendor_cp.allocations.models as legacy  # aliased
    from vendor_cp.allocations import models       # module taken as a NAME
    from . import models                           # relative, no module string
    from .models import Allocation                 # relative with a module
    from dotmac_entitlement_allocation.service import stage_allocation  # submodule

Any of those reintroduces a legacy writer path, or reads a deployment profile in
a second place, while the guard that forbids it stays green. A guard that can be
walked around is worse than no guard, because it reports safety.

So the scanner lives here once, is used by every guard, and is sensitivity-tested
per import FORM in `test_import_scanner.py` — the mutation proof that it can
actually see each one.

## Two target sets, and why they are separate

`module_targets` holds modules the source names UNAMBIGUOUSLY: `import a.b.c`
gives `a.b.c`, and `from a.b import n` gives `a.b`. This is what a "do not reach
into a package's submodules" rule must use — `from pkg import module` names an
ATTRIBUTE called `module`, not a submodule, and treating it as one would flag the
package's own public surface.

`possible_module_targets` additionally includes `a.b.n` for every `from a.b
import n`, because `from vendor_cp.allocations import models` really is a
reference to the models module and a guard on that module must catch it. It is
deliberately over-inclusive, so it is used only where over-inclusion is safe.

## Why this is a uniquely-named module, not `conftest.py`

`tests/migration/` is a package, so pytest puts `tests/` on `sys.path`, where a
`tests/conftest.py` already lives. A guard doing `from conftest import ...` could
then bind to the WRONG file depending on collection order. `import_scanner` is a
name nothing else in the tree uses, so the import is unambiguous — and it fails
loudly at collection if it ever stops resolving, rather than silently importing
something else.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from python_entrypoints import is_python_source

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"


@dataclass(frozen=True, slots=True)
class ImportRef:
    """One name taken from one module, with relative imports already resolved.

    `name is None` marks a whole-module import (`import a.b`), which takes no
    individual name but still reaches the module.
    """

    module: str
    name: str | None
    alias: str | None = None


def _package_of(path: Path, *, source_root: Path) -> str:
    """The dotted package a file lives in — the base a relative import resolves
    against. `src/vendor_cp/allocations/service.py` → `vendor_cp.allocations`."""
    relative = path.resolve().relative_to(source_root.resolve())
    parts = list(relative.parts[:-1])
    if relative.stem != "__init__":
        return ".".join(parts)
    return ".".join(parts)


def _resolve_relative(base_package: str, module: str | None, level: int) -> str:
    """`from . import x` / `from ..pkg import x` → an absolute dotted module.

    Level 1 is the containing package, level 2 its parent, and so on. A level
    that walks past the source root yields what is left, which is enough for a
    guard: it cannot then match a real target and the file is simply not a hit.
    """
    parts = base_package.split(".") if base_package else []
    if level > 1:
        parts = parts[: -(level - 1)] if level - 1 <= len(parts) else []
    return ".".join([*parts, module]) if module else ".".join(parts)


def scan_imports(path: Path, *, source_root: Path = SRC) -> tuple[ImportRef, ...]:
    """Every import in one file, in every form Python offers."""
    tree = ast.parse(path.read_text())
    base_package = _package_of(path, source_root=source_root)
    refs: list[ImportRef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # `import a.b.c` and `import a.b.c as z` both reach `a.b.c`.
            refs.extend(
                ImportRef(module=alias.name, name=None, alias=alias.asname)
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            module = (
                _resolve_relative(base_package, node.module, node.level)
                if node.level
                else (node.module or "")
            )
            refs.extend(
                ImportRef(module=module, name=alias.name, alias=alias.asname)
                for alias in node.names
            )
    return tuple(refs)


def module_targets(refs: Iterable[ImportRef]) -> frozenset[str]:
    """Modules the source names unambiguously. See the module docstring."""
    return frozenset(ref.module for ref in refs if ref.module)


def possible_module_targets(refs: Iterable[ImportRef]) -> frozenset[str]:
    """`module_targets`, plus `module.name` for every `from module import name`.

    Over-inclusive by design: `from pkg import thing` cannot be told statically
    from a submodule import, and a guard protecting a MODULE must assume it is
    one.
    """
    targets = set(module_targets(refs))
    targets.update(
        f"{ref.module}.{ref.name}" for ref in refs if ref.module and ref.name
    )
    return frozenset(targets)


def names_from(refs: Iterable[ImportRef], module: str) -> frozenset[str]:
    """Names taken from exactly `module` (not from its submodules)."""
    return frozenset(
        ref.name for ref in refs if ref.module == module and ref.name is not None
    )


def reaches_module(refs: Iterable[ImportRef], module: str) -> bool:
    """Does the file reach `module` itself, by any import form?"""
    return module in possible_module_targets(refs)


def submodule_reach_ins(refs: Iterable[ImportRef], package: str) -> frozenset[str]:
    """Modules UNDER `package` that the file names unambiguously.

    Uses `module_targets`, so `from package import public_name` — the package's
    own surface — is not mistaken for reaching inside it.
    """
    prefix = f"{package}."
    return frozenset(
        target for target in module_targets(refs) if target.startswith(prefix)
    )


def source_files(package_dir: Path) -> list[Path]:
    """Every file under `package_dir` this product's Python interpreter runs.

    NOT `rglob("*.py")`, which is what this was. Five guards ask "does any
    source file reach for X?" through this function, and all five were answering
    a question about file NAMES. `src/vendor_cp/rotation_runtime_oracle.pyprogram`
    is Python, is executed by the deployed application's interpreter, and was
    invisible to every one of them — see `python_entrypoints.is_python_source`
    for the property that replaces the suffix, and why the classification it
    produces is itself ratcheted.
    """

    return [
        path
        for path in sorted(package_dir.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts and is_python_source(path)
    ]
