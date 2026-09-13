"""The facade Platform imports is proven against the INSTALLED wheel.

## Why a source tree cannot answer this

`dotmac-deployment-control` is a published distribution installed from the
private index. Every other check in this repository reads its own source, and
none of them can tell you whether the wheel that will actually be on
`sys.path` exports the names this assembly imports. That gap is exactly what
cost this repository a boot failure once before: a5's artifact identity and
behaviour both passed, its hashes matched the release evidence, and the
container still died on `ModuleNotFoundError` because the published bytes did
not supply what the importer needed. A hash comparison proves you got the
published bytes; it cannot prove they import.

So this reads `importlib.metadata`, not the repository — the distribution's own
recorded version and its installed files — and then imports the facade from
site-packages and resolves every name against it.

## Why the declaration is closed, and two-directional

`IMPORTED_FACADE_NAMES` is the closed set this assembly imports from
`dotmac_deployment_control`. It is compared with a SCAN of the real source in
both directions: a name imported but undeclared fails, and a declared name no
longer imported fails too. A one-directional list rots into a set of names
nobody uses, which then "passes" while proving nothing about the imports that
actually exist.

Set equality, never a count. A symbol swapped for another leaves the count
identical and the set different.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata as metadata
from pathlib import Path
from typing import Final

import pytest

ROOT: Final = Path(__file__).resolve().parents[2]
#: This repository's own SOURCE tree — the thing an installed view must not
#: resolve to. Narrower than `ROOT`: CI installs into an in-project
#: virtualenv at `<repo>/.venv`, so the installed distribution legitimately
#: resolves under `ROOT` (inside `.venv/.../site-packages`) without that being
#: this repository's own source. `<repo>/src` is where this repository's own
#: code lives; that is the path a checkout-resolved import would run under.
SOURCE_TREE: Final = ROOT / "src"
DISTRIBUTION: Final = "dotmac-deployment-control"
PACKAGE: Final = "dotmac_deployment_control"


#: The exact version this assembly pins. Read from the manifest rather than
#: restated, because a literal here would be a second place to forget.
def _pinned_version() -> str:
    import tomllib

    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = manifest["tool"]["poetry"]["dependencies"][DISTRIBUTION]
    assert isinstance(declared, dict), declared
    return str(declared["version"])


#: Every name imported from the facade, declared closed. Derived once by AST and
#: then frozen, so that ADDING an import is a visible change to this file.
IMPORTED_FACADE_NAMES: Final = frozenset(
    {
        "ApprovalEvidence",
        "ApprovalDecisionStatus",
        "ApprovePlanCommand",
        "AuthorizationSignature",
        "AuthorizationSigner",
        "AuthorizationSignerIdentity",
        "AuthorizedImage",
        "DesiredDeployment",
        "DriftReport",
        "PlanView",
        "ProposePlanCommand",
        "RegisterTargetCommand",
        "RequestRolloutCommand",
        "RolloutView",
        "SetDesiredStateCommand",
        "TargetStatus",
        "TargetView",
        "approve_plan",
        "drift",
        "get_plan",
        "get_rollout",
        "get_target",
        "module",
        "propose_plan",
        "register_target",
        "request_rollout",
        "set_desired_state",
        "versions_dir",
    }
)


def _scanned_facade_names() -> frozenset[str]:
    """Every name this repository's own source imports from the facade."""

    found: set[str] = set()
    for root in (ROOT / "src", ROOT / "tests"):
        for source in root.rglob("*.py"):
            try:
                tree = ast.parse(source.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover - reported, never skipped
                pytest.fail(f"{source} does not parse")
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == PACKAGE:
                    found.update(alias.name for alias in node.names)
    return frozenset(found)


def test_the_declared_facade_matches_the_source_in_both_directions() -> None:
    """The closed declaration is not allowed to drift from the real imports."""

    scanned = _scanned_facade_names()
    assert scanned, "the scan found no facade imports at all; it has stopped looking"
    undeclared = sorted(scanned - IMPORTED_FACADE_NAMES)
    unused = sorted(IMPORTED_FACADE_NAMES - scanned)
    assert not undeclared, (
        f"these names are imported from {PACKAGE} but not declared here: "
        f"{undeclared}. Add them, so the installed-view check below covers them."
    )
    assert not unused, (
        f"these names are declared here but no longer imported: {unused}. "
        "Remove them, or this list becomes names nobody uses while appearing "
        "to prove something about the imports that exist."
    )


def test_the_installed_distribution_is_the_pinned_version() -> None:
    """What is INSTALLED, from its own metadata — not what the manifest says.

    A manifest states an intention. This states what is on `sys.path`, and the
    two disagreeing is the condition every later assertion here would otherwise
    be silently testing against.
    """

    try:
        installed = metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError as exc:  # pragma: no cover
        pytest.fail(
            f"{DISTRIBUTION} is not installed, so the facade cannot be checked "
            "against the published wheel at all. This is an ACQUISITION "
            f"failure, not a facade failure: {exc}"
        )
    assert installed == _pinned_version(), (
        f"{DISTRIBUTION} {installed} is installed while this assembly pins "
        f"{_pinned_version()}"
    )


def test_the_installed_wheel_supplies_every_imported_name() -> None:
    """Import the facade from site-packages and resolve every declared name.

    This is the check a source tree cannot perform. It fails with the missing
    names rather than on the first one, because a partial answer sends a reader
    back for another round.
    """

    facade = importlib.import_module(PACKAGE)
    missing = sorted(
        name for name in IMPORTED_FACADE_NAMES if not hasattr(facade, name)
    )
    assert not missing, (
        f"the installed {DISTRIBUTION} {metadata.version(DISTRIBUTION)} does not "
        f"export {missing}, which this assembly imports. The pin resolves and the "
        "hashes match; the bytes do not supply the surface."
    )


def test_the_facade_is_imported_from_site_packages_not_the_repository() -> None:
    """Non-vacuity for the test above.

    If a path entry made `dotmac_deployment_control` resolve to a checkout
    inside this repository, every assertion above would pass while proving
    nothing about the published wheel — which is the one thing this module
    exists to establish.
    """

    facade = importlib.import_module(PACKAGE)
    origin = Path(facade.__file__ or "").resolve()
    assert SOURCE_TREE not in origin.parents, (
        f"{PACKAGE} resolved to {origin}, inside this repository's own source "
        f"tree ({SOURCE_TREE}). The installed view is then this repository's "
        "own source and proves nothing about the published distribution."
    )
    recorded = metadata.files(DISTRIBUTION) or []
    assert recorded, (
        f"{DISTRIBUTION} records no installed files, so there is nothing to "
        "distinguish the installed wheel from a path entry"
    )
