"""What this product's Python interpreter executes — by property, not by suffix.

A guard that globs `*.py` answers a question about FILE NAMES. The question it
is asked is about EXECUTION, and the two came apart here:
`src/vendor_cp/rotation_runtime_oracle.pyprogram` imports four names out of
`dotmac_kernel.db` and runs under the deployed application's own interpreter,
while every `.py`-globbing scan in `tests/architecture/` skipped it. Nothing was
hidden — the payload's header says plainly that it lives outside the `.py`
surface on purpose — but a census of kernel-database importers that cannot see
it reports ten where there are eleven, and a cutover measured against that
census finishes while a site is still open.

`dotmac_starter_mt` rule 23 / `AGENTS.md` rule 25 (ADR-0018) is the rule this
module exists to satisfy: guards enumerate ENTRY-POINT FAMILIES, not one
directory — and, here, not one file extension either. The next payload will not
be called `.pyprogram` any more than the console script was called `scripts/`.

## The property

`is_python_source` asks whether the bytes are a Python module. A shell payload
and a SQL catalogue do not parse. One refinement is needed and only one: a data
file can parse by accident, because `key = "value"` is a valid Python
assignment, so a module whose entire top level is literal assignment is refused
as data. Everything else parseable is Python — INCLUDING an empty `__init__.py`,
which declares nothing and is still a module this interpreter imports.

The bias is deliberate. Reading a non-Python file as Python costs a guard
nothing: it finds no imports. FAILING to read a Python payload is the defect
being repaired. When the two directions are not symmetric, the guard leans
toward looking.

This is a property of the CONTENT, so a payload named `.pypayload`, `.tmpl` or
nothing at all is covered on the day it lands.

## Why the property alone is not enough

The property is a heuristic and is honest about it: the five `.sh` scripts here
fail to parse only because `umask 077` and `chmod 0600` are not valid Python
integers. A shell script without a leading-zero literal could parse.

So the classification itself is ratcheted. `NON_PYTHON_TRACKED_SOURCE` records
every file under a Python entry-point family that this guard asserts is NOT
executed by a Python interpreter, each with the interpreter that does run it.
`test_python_entrypoints.py` fails when a file joins that set, when one leaves
it, and when a file is in neither set — so a new payload cannot arrive silently
whatever it is called and however the property happens to answer.

## The enumeration

`git ls-files --cached --others --exclude-standard` — tracked source PLUS files
that are present and not ignored. The second half is deliberate: a sensitivity
proof plants a file that has never been committed, and a guard that could not
see it would prove nothing about the guard that runs in CI.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

#: The families a Python file in this repository can be executed FROM. Ordered
#: general-to-specific; a file is attributed to the LONGEST matching prefix, so
#: a failure names the surface an author has to think about rather than "src".
#:
#: `scripts` was the only family when the first session-authority guard was
#: written. The operator surface became an installed console script, the relay
#: became a worker, and a rotation oracle became a payload handed to another
#: image's interpreter. Each is named here because each is somewhere a kernel
#: import can be introduced.
PYTHON_ENTRYPOINT_FAMILIES: tuple[tuple[str, str], ...] = (
    ("assembly", "src/vendor_cp"),
    ("console-script", "src/vendor_cp/cli"),
    ("worker", "src/vendor_cp/relay"),
    ("operator-scripts", "scripts"),
    ("migrations", "alembic"),
)

#: Files under a Python entry-point family that no Python interpreter executes,
#: each with the interpreter that does. This is an ENFORCEABLE premise, not an
#: exemption: `test_python_entrypoints.py` proves each entry still fails to be
#: Python source, and the set is a two-directional ratchet.
NON_PYTHON_TRACKED_SOURCE: dict[str, str] = {
    "scripts/bootstrap/bootstrap_once.sh": "sh, on the production host",
    "scripts/bootstrap_production_host.sh": "sh, on the production host",
    "scripts/deploy_production.sh": "sh, on the production host",
    "scripts/deploy_production_with_registry_token.sh": "sh, on the production host",
    "scripts/install_deployment_tool.sh": "sh, on the operator's machine",
    "src/vendor_cp/recovery/capture_catalog.sql": "PostgreSQL",
    "src/vendor_cp/rotation_database_auth_oracle.shprogram": (
        "sh, inside the label-selected PostgreSQL container"
    ),
}


def _is_literal_assignment(node: ast.stmt) -> bool:
    """`key = "value"` — the shape a configuration file shares with Python."""

    if not isinstance(node, ast.Assign):
        return False
    try:
        ast.literal_eval(node.value)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False
    return True


def is_python_source(path: Path) -> bool:
    """Do these bytes parse as a Python module rather than as data?

    An empty module is Python — `__init__.py` is the commonest file in the tree
    and declares nothing. A module whose top level is nothing but literal
    assignment is data that happens to be syntactically valid, and treating one
    as source would let every `.toml` under a family be reported as checked.
    """

    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError):
        return False
    if not tree.body:
        return True
    return not all(_is_literal_assignment(node) for node in tree.body)


def _listed(*roots: str) -> list[str]:
    existing = [root for root in roots if (ROOT / root).exists()]
    if not existing:
        return []
    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        (
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *existing,
        ),
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def candidate_source() -> tuple[str, ...]:
    """Every present, non-ignored file under a Python entry-point family."""

    roots = {prefix for _, prefix in PYTHON_ENTRYPOINT_FAMILIES}
    seen = {
        relative
        for relative in _listed(*sorted(roots))
        if "__pycache__" not in Path(relative).parts
    }
    return tuple(sorted(seen))


def family_of(relative: str) -> str:
    """The most specific entry-point family a path belongs to."""

    best = ""
    name = ""
    for family, prefix in PYTHON_ENTRYPOINT_FAMILIES:
        if (relative == prefix or relative.startswith(f"{prefix}/")) and len(
            prefix
        ) > len(best):
            best, name = prefix, family
    return name or "unattributed"


def python_sources() -> tuple[Path, ...]:
    """Everything this product's Python interpreter executes, by property."""

    return tuple(
        ROOT / relative
        for relative in candidate_source()
        if is_python_source(ROOT / relative)
    )


def imports_of(path: Path) -> tuple[tuple[str, str | None, int], ...]:
    """(module, name|None, line) for every absolute import in one file.

    PARSED, never grepped. `src/vendor_cp/cli/commands.py` names
    `dotmac_kernel.db` in prose, explaining why the real import is deferred into
    a function body; a substring census counts that paragraph as an importer and
    then reports a site that does not exist. The prose is kept as a permanent
    negative control in `test_kernel_database_importers.py`.
    """

    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError):
        return ()
    found: list[tuple[str, str | None, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(alias.name, None, node.lineno) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found += [(node.module, alias.name, node.lineno) for alias in node.names]
    return tuple(found)
