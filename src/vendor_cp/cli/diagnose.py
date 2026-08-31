"""The commands that answer questions about this process rather than the fleet.

`diagnose self` is the one that matters, and it exists because of a specific
defect class rather than for tidiness.

## What `diagnose self` proves, and why a canary would not

`dotmac-deployment-control 0.1.0a4` shipped correct bytes with a wrong
self-report: `pyproject.toml` said `0.1.0a4`, the module attribute said
`0.1.0a2`, and every controller fingerprint reading the attribute would have
recorded the wrong version into an authorization it exists to make auditable.
Nothing caught it, because nothing asked the artifact who it was.

A check that merely IMPORTS the package and prints a version passes just as
happily from a source checkout, which is the state in which every "am I the
installed thing?" question is answered wrongly. So this command resolves each
module's `__file__` and compares it against the interpreter's own `purelib` and
`platlib`, which come from `sysconfig` rather than from anything the package
says about itself. A run against a checkout FAILS, and that failing is the
entire value: a canary that passed in both places would prove nothing while
looking like proof.

`--strict` turns the report into a verdict, exiting `6` — an identity mismatch,
not a policy refusal — when anything resolves outside the installed tree.

## Owners are resolved without being executed

`importlib.util.find_spec` locates a module and returns its origin without
running it. That matters here: the owner modules build database engines at
import time, and a proof of INSTALLED LOCATION should not require a configured
database. The clean-install acceptance runs this command in an environment that
has none.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import sysconfig
from pathlib import Path
from typing import Final

import vendor_cp
from vendor_cp.cli.exits import refuse
from vendor_cp.cli.io import Result
from vendor_cp.cli.owners import DELEGATED_COMMANDS, OWNERS, mutating_owners
from vendor_cp.identity import (
    COMPOSED_DISTRIBUTIONS,
    DISTRIBUTION,
    installed_version,
)

#: The package prefix everything this assembly owns lives under.
PACKAGE: Final[str] = "vendor_cp"


def _install_roots() -> tuple[Path, ...]:
    """Where the interpreter puts installed packages.

    `sysconfig`, deliberately. Asking the package where it thinks it lives is
    the question a defective self-report already answers wrongly.
    """
    roots: list[Path] = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value:
            roots.append(Path(value).resolve())
    for entry in sys.path:
        if not entry:
            continue
        candidate = Path(entry).resolve()
        if candidate.name == "site-packages":
            roots.append(candidate)
    return tuple(dict.fromkeys(roots))


def _is_installed(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path.is_relative_to(root) for root in roots)


def _module_origin(module_name: str) -> str | None:
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, ValueError):
        return None
    if spec is None or spec.origin is None:
        return None
    return spec.origin


def self_report(args: argparse.Namespace) -> Result:
    """Prove this runs from an installed distribution, or report that it does not."""
    roots = _install_roots()
    version = installed_version(DISTRIBUTION)

    package_paths = [Path(entry).resolve() for entry in vendor_cp.__path__]
    imported: dict[str, Path] = {}
    for name, module in sorted(sys.modules.items()):
        if name != PACKAGE and not name.startswith(f"{PACKAGE}."):
            continue
        origin = getattr(module, "__file__", None)
        if origin:
            imported[name] = Path(origin).resolve()

    owner_origins: dict[str, str | None] = {}
    for owner in OWNERS:
        owner_origins.setdefault(owner.module, _module_origin(owner.module))

    outside = sorted(
        name for name, path in imported.items() if not _is_installed(path, roots)
    )
    unresolved = sorted(
        name for name, origin in owner_origins.items() if origin is None
    )
    owner_outside = sorted(
        name
        for name, origin in owner_origins.items()
        if origin is not None and not _is_installed(Path(origin).resolve(), roots)
    )

    duplicate_owners = _duplicate_mutation_owners()
    cli_owned_mutations = sorted(
        owner.command
        for owner in mutating_owners()
        if owner.module.startswith(f"{PACKAGE}.cli")
    )

    findings: list[str] = []
    if version is None:
        findings.append(
            f"{DISTRIBUTION} has no installed distribution metadata — this is a "
            "checkout, not an installation"
        )
    if len(package_paths) != 1:
        findings.append(
            f"{PACKAGE} resolves to {len(package_paths)} paths {package_paths}; "
            "two copies on the path means two versions can answer"
        )
    findings.extend(
        f"imported module {name} resolves outside the installed tree"
        for name in outside
    )
    findings.extend(f"owner module {name} could not be located" for name in unresolved)
    findings.extend(
        f"owner module {name} resolves outside the installed tree"
        for name in owner_outside
    )
    findings.extend(
        f"mutating owner {symbol} is claimed by more than one command: {commands}"
        for symbol, commands in duplicate_owners
    )
    findings.extend(
        f"mutating command {command!r} names an owner inside {PACKAGE}.cli, so a "
        "decision would exist only in the CLI"
        for command in cli_owned_mutations
    )

    result = Result(
        command="diagnose self",
        data={
            "distribution": DISTRIBUTION,
            "version": version,
            "install_roots": [str(root) for root in roots],
            "package_paths": [str(path) for path in package_paths],
            "imported_modules": len(imported),
            "owner_modules": len(owner_origins),
            "delegated_commands": sorted(DELEGATED_COMMANDS),
            "findings": findings,
            "installed": not findings,
        },
        message=(
            "running from the installed distribution"
            if not findings
            else f"{len(findings)} finding(s)"
        ),
    )
    if findings and args.strict:
        # Two codes, because the two failures send different people. A module
        # resolving outside the installed tree is a packaging or deployment
        # fault; a mutating symbol claimed twice is a design fault in the
        # command surface. Collapsing them would hand an operator one number
        # for two problems only one of which they can act on.
        code = (
            "integrity.duplicate_owner"
            if duplicate_owners
            else "integrity.source_not_installed"
        )
        raise refuse(code, "; ".join(findings))
    return result


def _duplicate_mutation_owners() -> list[tuple[str, list[str]]]:
    """Mutating symbols claimed by more than one command.

    Two entry points onto one transition is fine and is not what this looks
    for; the failure it names is one symbol appearing under two command names,
    which is how a second spelling of the same mutation starts.
    """
    seen: dict[str, list[str]] = {}
    for owner in mutating_owners():
        seen.setdefault(f"{owner.module}:{owner.symbol}", []).append(owner.command)
    return [
        (symbol, commands) for symbol, commands in seen.items() if len(commands) > 1
    ]


def version_report(args: argparse.Namespace) -> Result:
    """Installed versions, read from metadata rather than from module attributes."""
    composed = {name: installed_version(name) for name in COMPOSED_DISTRIBUTIONS}
    missing = sorted(name for name, value in composed.items() if value is None)
    return Result(
        command="diagnose version",
        data={
            "distribution": DISTRIBUTION,
            "version": installed_version(DISTRIBUTION),
            "composed": composed,
            "not_installed": missing,
        },
    )


def owners_report(args: argparse.Namespace) -> Result:
    """The command-to-owner table, as data rather than as prose."""
    return Result(
        command="diagnose owners",
        data={
            "count": len(OWNERS),
            "owners": [
                {
                    "command": owner.command,
                    "owner": f"{owner.module}:{owner.symbol}",
                    "mutates": owner.mutates,
                    "summary": owner.summary,
                }
                for owner in OWNERS
            ],
        },
    )


def composition_report(args: argparse.Namespace) -> Result:
    """The composed migration lineages and the planes this assembly selects."""
    from vendor_cp.migration_bindings import (
        ASSEMBLY_MODULE_PLANES,
        ASSEMBLY_PREREQUISITE_BINDINGS,
    )
    from vendor_cp.migrations import composed_version_locations, migration_root

    return Result(
        command="diagnose composition",
        data={
            "migration_root": str(migration_root()),
            "lineages": composed_version_locations().split(),
            "prerequisite_bindings": len(ASSEMBLY_PREREQUISITE_BINDINGS),
            "module_planes": len(ASSEMBLY_MODULE_PLANES),
        },
    )


__all__ = [
    "PACKAGE",
    "composition_report",
    "owners_report",
    "self_report",
    "version_report",
]
