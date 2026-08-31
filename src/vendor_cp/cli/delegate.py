"""Hand an argument vector to the published Foundation CLI, unchanged.

`render`, `apply`, `observe` and `rollback` belong to
`dotmac-deployment-foundation`. They are not reimplemented here and must not be:
this assembly owns the operator WORKFLOW, the Foundation owns target-side
rendering and EXECUTION, and a second renderer on this side would be a second
answer to what a deployment looks like.

## Why a passthrough rather than nothing at all

Documenting "run `dotmac-deploy` yourself" would satisfy the letter of the rule
and prove nothing. A passthrough makes the delegation a fact the tests can see:
the vector is forwarded verbatim, no flag is interpreted, no default is
supplied, and there is no branch on which subcommand was asked for.

## The delegate's status is returned, not remapped

Every other command in this CLI reports one of the stable codes in
`vendor_cp.cli.exits`. This one deliberately does not: it returns the Foundation
CLI's own exit status. Remapping it would invent a verdict this process did not
compute and would flatten whatever distinctions that tool makes into ours.

Two statuses are ours, and both are about the delegate rather than about the
deployment: `4` when the console script is not installed, which is an absence of
the tool and not a refusal by it, and `5` when it could not be executed at all.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404 - the delegate is a named console script, argv is a list
from collections.abc import Sequence
from typing import Final

from vendor_cp.cli.exits import ExitCode, refuse

#: The Foundation's console script, as its own `pyproject.toml` declares it.
FOUNDATION_COMMAND: Final[str] = "dotmac-deploy"

#: The distribution that installs it, for the message when it is absent.
FOUNDATION_DISTRIBUTION: Final[str] = "dotmac-deployment-foundation"

#: The verbs this CLI refuses to grow. Named so the guard in
#: `tests/architecture/test_installed_cli.py` has something concrete to check
#: for: none of these may appear as a command of ours.
FOUNDATION_OWNED_VERBS: Final[tuple[str, ...]] = (
    "render",
    "apply",
    "apply-exposure",
    "observe",
    "rollback",
    "deploy",
    "rehearse",
    "verify",
)


def foundation_path() -> str | None:
    """Where the Foundation CLI is, or `None`.

    `PATH` lookup rather than an import: the Foundation is a separately released
    package that this assembly does not declare as a dependency, and importing
    it to find out whether it exists would create the coupling the delegation
    exists to avoid.
    """
    override = os.environ.get("VENDOR_FOUNDATION_CLI")
    if override:
        return override if shutil.which(override) else None
    return shutil.which(FOUNDATION_COMMAND)


def run_foundation(argv: Sequence[str]) -> int:
    """Execute the Foundation CLI with `argv` and return its exit status."""
    executable = foundation_path()
    if executable is None:
        raise refuse(
            "evidence.tool_absent",
            f"{FOUNDATION_COMMAND} is not on PATH. Rendering, applying, "
            f"observing and rolling back belong to {FOUNDATION_DISTRIBUTION}; "
            "this command forwards to it and never reimplements it. Install "
            "the published Foundation, or set VENDOR_FOUNDATION_CLI to its "
            "console script.",
        )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable, list argv, no shell
            [executable, *argv],
            check=False,
        )
    except OSError as error:
        raise refuse(
            "execution.delegate_failed",
            f"{executable} could not be executed ({error.strerror})",
        ) from error
    return completed.returncode


def delegate_exit(status: int) -> ExitCode | int:
    """The passthrough's status, unchanged when it is the delegate's own."""
    return ExitCode.OK if status == 0 else status


__all__ = [
    "FOUNDATION_COMMAND",
    "FOUNDATION_DISTRIBUTION",
    "FOUNDATION_OWNED_VERBS",
    "delegate_exit",
    "foundation_path",
    "run_foundation",
]
