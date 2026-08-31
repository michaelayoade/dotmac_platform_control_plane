"""The CLI's stable exit codes and its closed refusal vocabulary.

## Why 3 and 4 are different numbers

An owner REFUSED, and there is NO EVIDENCE, look identical from outside the
process — both are "it did not happen" — and they mean opposite things about
what to do next. A refusal is a decision: the owner looked, and said no, and
retrying without changing anything will be refused again. An absence is not a
decision: nothing looked, or what would have answered was not reachable, and the
same command may well succeed once the missing thing exists.

An operator scripting against a single "failed" code cannot tell those apart,
so it retries the refusal and gives up on the absence — exactly backwards. So
they are separate codes, and they stay separate everywhere, including through
`docker compose run`, which propagates the container's status unchanged.

## Why 6 exists next to 3

`dotmac-deployment-control 0.1.0a4` shipped a digest comparison that returned
"the plan changed after approval" — a tampering refusal — when the caller had
merely supplied the same digest in the other encoding. A formatting bug wearing
a security refusal's message is the worst available failure mode, because it
looks like the system working. `a6` split those into distinct exceptions, and
this enum keeps them distinct on the way out: an integrity or identity mismatch
is `6`, never `3`.

## Nothing here is a policy

These are the CLI's own transport-level verdicts. What counts as a refusal is
decided by the owning service; this module only carries the answer out.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Final


class ExitCode(IntEnum):
    """The CLI's contract with whatever invoked it."""

    #: The command did what it said.
    OK = 0
    #: The invocation or the configuration is wrong. Nothing was attempted.
    USAGE = 2
    #: An owner refused. A decision was made, and it was no.
    REFUSED = 3
    #: The evidence needed is incomplete, absent, or unreachable. No decision.
    UNAVAILABLE = 4
    #: Execution began and failed.
    FAILED = 5
    #: Something did not match what it claimed to be.
    MISMATCH = 6


#: The status word each code reports in the JSON envelope. One word per code,
#: because a status that could mean two codes would undo the split above.
STATUS: Final[dict[ExitCode, str]] = {
    ExitCode.OK: "ok",
    ExitCode.USAGE: "usage",
    ExitCode.REFUSED: "refused",
    ExitCode.UNAVAILABLE: "unavailable",
    ExitCode.FAILED: "failed",
    ExitCode.MISMATCH: "mismatch",
}


class Refusal(Exception):
    """A verdict this process is carrying out, with a stable machine code.

    The `code` is the part a caller may branch on and is drawn from
    `REFUSAL_CODES` below. The message is for a human and may change; the code
    may not, which is why the two are separate fields rather than one string
    somebody eventually parses.
    """

    def __init__(self, code: str, message: str, *, exit_code: ExitCode) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


#: The closed vocabulary. Every refusal this CLI can emit is named here with the
#: code it exits on, so the mapping is reviewable in one place rather than
#: scattered across the command modules that raise them.
#:
#: A code is a permanent identifier: it may be retired, but it may never be
#: reassigned to a different meaning, because an operator's runbook branches on
#: it. Adding one is a one-line change here plus its raiser.
REFUSAL_CODES: Final[dict[str, ExitCode]] = {
    # ── usage / configuration (2) ──────────────────────────────────────────
    "usage.invalid_argument": ExitCode.USAGE,
    "usage.secret_unreadable": ExitCode.USAGE,
    "usage.bad_request": ExitCode.USAGE,
    "config.missing": ExitCode.USAGE,
    "config.invalid": ExitCode.USAGE,
    "config.migration_root_unset": ExitCode.USAGE,
    # ── owner refusals (3) ─────────────────────────────────────────────────
    "owner.transition_refused": ExitCode.REFUSED,
    "owner.expected_state": ExitCode.REFUSED,
    "owner.plan_refused": ExitCode.REFUSED,
    "owner.approval_refused": ExitCode.REFUSED,
    "owner.conflict": ExitCode.REFUSED,
    "owner.forbidden": ExitCode.REFUSED,
    "owner.migration_target_refused": ExitCode.REFUSED,
    "owner.provider_not_permitted": ExitCode.REFUSED,
    # ── absent or unreachable evidence (4) ─────────────────────────────────
    "evidence.not_found": ExitCode.UNAVAILABLE,
    "evidence.tool_absent": ExitCode.UNAVAILABLE,
    "evidence.capability_absent": ExitCode.UNAVAILABLE,
    # ── execution failure (5) ──────────────────────────────────────────────
    "execution.failed": ExitCode.FAILED,
    "execution.delegate_failed": ExitCode.FAILED,
    # ── integrity / identity (6) ───────────────────────────────────────────
    "integrity.digest_unreadable": ExitCode.MISMATCH,
    "integrity.digest_mismatch": ExitCode.MISMATCH,
    "integrity.source_not_installed": ExitCode.MISMATCH,
    "integrity.duplicate_owner": ExitCode.MISMATCH,
}


def refuse(code: str, message: str) -> Refusal:
    """Build a `Refusal` whose exit code comes from the declared vocabulary.

    A raiser names the code and nothing else. It cannot choose an exit status
    that disagrees with the vocabulary, which is how 3 and 4 stay apart in a
    module whose author was thinking about something else at the time.
    """
    try:
        exit_code = REFUSAL_CODES[code]
    except KeyError:  # pragma: no cover - guarded by test_installed_cli
        raise AssertionError(f"undeclared refusal code {code!r}") from None
    return Refusal(code, message, exit_code=exit_code)


__all__ = ["REFUSAL_CODES", "STATUS", "ExitCode", "Refusal", "refuse"]
