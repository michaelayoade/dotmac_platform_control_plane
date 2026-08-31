"""What the CLI prints, and how a secret gets in without being printed.

Two responsibilities, kept in one module because they are the same boundary
seen from opposite sides: everything a command emits goes out through `emit`,
and everything secret a command needs comes in through `read_secret`.

## Redaction is structural, not a habit

`emit` walks the payload and replaces the VALUE of any field whose NAME reads
like credential material. It is deliberately name-based and deliberately
over-broad: a command that accidentally puts a password in a field called
`password` is the realistic mistake, and a redactor that only covered the fields
somebody remembered would cover exactly the fields that were never going to
leak. A digest, a key IDENTIFIER and a public key are not redacted — they are
the evidence an operator needs, and redacting them would push people toward
reading the raw values out of the database instead.

## Secrets never arrive on argv

`ps -ef` shows another user's command line for as long as the process lives, and
`/proc/<pid>/cmdline` is world-readable on this fleet — a registration token
leaked into a transcript exactly that way. So a secret arrives as a FILE the
caller already holds, or on stdin, and never as the value of a flag. There is no
`--password` and there will not be one: `read_secret` takes the two paths that
exist, and the argument parser is checked by
`tests/architecture/test_installed_cli.py` for the one that must not.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TextIO

from vendor_cp.cli.exits import STATUS, ExitCode, refuse

#: Output shapes this CLI supports. `table` is for a human at a terminal; `json`
#: is the contract anything else should use.
FORMATS: Final[tuple[str, ...]] = ("json", "table")

#: A field whose name contains one of these has its VALUE replaced. Substring
#: matching on a lowercased field name, so `db_password` and `jwtSecret` are
#: both covered without anyone maintaining a list of exact names.
SECRET_NAME_MARKERS: Final[tuple[str, ...]] = (
    "password",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "passphrase",
    "authorization",
)

#: Names that CONTAIN a marker but are safe, and are the evidence an operator
#: came for. Exact names, not substrings: an allowlist matched loosely would
#: quietly re-expose the thing it was carved out of.
SECRET_NAME_EXEMPTIONS: Final[frozenset[str]] = frozenset(
    {
        "token_kind",
        "credential_id",
        "credential_status",
        "credential_count",
        "has_token",
        "secret_source",
        "secret_paths",
    }
)

#: What a redacted value prints as. A fixed marker rather than the empty string,
#: because "the field was present and withheld" and "the field was absent" are
#: different facts and an operator reading output needs to tell them apart.
REDACTED: Final[str] = "<redacted>"


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in SECRET_NAME_EXEMPTIONS:
        return False
    return any(marker in lowered for marker in SECRET_NAME_MARKERS)


def redact(value: object) -> object:
    """Return `value` with every credential-named field replaced.

    Recursive over mappings and sequences, because a secret two levels down in a
    nested result is exactly as printed as one at the top.
    """
    if isinstance(value, Mapping):
        return {
            str(key): (REDACTED if _is_secret_name(str(key)) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class Result:
    """One command's answer, before it is rendered.

    `references` is separate from `data` on purpose: the command id, the
    receipt, the plan digest and the rollout reference are what a later step
    binds to, and burying them among the payload makes an operator hunt for the
    one field the next command needs.
    """

    command: str
    data: Mapping[str, object] = ()  # type: ignore[assignment]
    references: Mapping[str, object] = ()  # type: ignore[assignment]
    exit_code: ExitCode = ExitCode.OK
    refusal_code: str | None = None
    message: str = ""


def _envelope(result: Result) -> dict[str, object]:
    return {
        "command": result.command,
        "status": STATUS[result.exit_code],
        "exit_code": int(result.exit_code),
        "refusal_code": result.refusal_code,
        "message": result.message,
        "references": redact(dict(result.references or {})),
        "data": redact(dict(result.data or {})),
    }


def _rows(prefix: str, value: object) -> list[tuple[str, str]]:
    if isinstance(value, Mapping):
        rows: list[tuple[str, str]] = []
        for key, item in value.items():
            rows.extend(_rows(f"{prefix}.{key}" if prefix else str(key), item))
        return rows
    if isinstance(value, list | tuple):
        if not value:
            return [(prefix, "")]
        rows = []
        for index, item in enumerate(value):
            rows.extend(_rows(f"{prefix}[{index}]", item))
        return rows
    return [(prefix, "" if value is None else str(value))]


def render(result: Result, output_format: str) -> str:
    """The envelope as text, in the caller's chosen shape."""
    envelope = _envelope(result)
    if output_format == "json":
        return json.dumps(envelope, indent=2, sort_keys=True, default=str)
    rows = _rows("", envelope)
    width = max((len(key) for key, _ in rows), default=0)
    return "\n".join(f"{key.ljust(width)}  {value}" for key, value in rows)


def emit(
    result: Result,
    output_format: str,
    *,
    stdout: TextIO | None = None,
) -> ExitCode:
    """Print the envelope and hand back the status to exit with.

    Everything goes to stdout, including refusals, because the envelope IS the
    answer in both cases and a caller parsing JSON should not have to merge two
    streams to find out what happened. The exit code carries the verdict.
    """
    stream = sys.stdout if stdout is None else stdout
    print(render(result, output_format), file=stream)
    return result.exit_code


def read_secret(
    *,
    from_file: str | None,
    from_stdin: bool,
    prompt: str,
    stdin: TextIO | None = None,
) -> str:
    """One secret, from a held file or from stdin. Never from argv.

    Exactly one source must be named. Defaulting to stdin when neither was given
    would make a forgotten flag hang a deploy script forever; defaulting to a
    file would guess at a path. Both are refused with `usage.*`, which is a
    configuration fault and not an owner's decision.
    """
    if from_file and from_stdin:
        raise refuse(
            "usage.invalid_argument",
            f"{prompt}: give either a held file or stdin, not both",
        )
    if from_file:
        path = Path(from_file)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise refuse(
                "usage.secret_unreadable",
                f"{prompt}: cannot read the held file {from_file} ({error.strerror})",
            ) from error
    elif from_stdin:
        raw = (sys.stdin if stdin is None else stdin).read()
    else:
        raise refuse(
            "usage.invalid_argument",
            f"{prompt}: supply it through a held file or stdin — this command "
            "has no flag that takes a secret value, because argv is readable by "
            "every process on the host for as long as this one lives",
        )
    value = raw.strip("\r\n")
    if not value:
        raise refuse(
            "usage.secret_unreadable", f"{prompt}: the supplied source is empty"
        )
    return value


def read_bytes(source: str, *, what: str, limit: int = 1_048_576) -> bytes:
    """Read a held document a command was pointed at, or refuse.

    Absence is `evidence.*` rather than `usage.*`: the caller named a path
    correctly and the thing it names is not there, which is the difference
    between a typo and a missing artifact.
    """
    path = Path(source)
    try:
        payload = path.read_bytes()
    except FileNotFoundError as error:
        raise refuse(
            "evidence.not_found", f"{what}: {source} does not exist"
        ) from error
    except OSError as error:
        raise refuse(
            "evidence.not_found", f"{what}: cannot read {source} ({error.strerror})"
        ) from error
    if len(payload) > limit:
        raise refuse(
            "usage.invalid_argument",
            f"{what}: {source} is {len(payload)} bytes, over the {limit}-byte limit",
        )
    return payload


def as_sequence(values: Sequence[str] | None) -> tuple[str, ...]:
    return tuple(values or ())


__all__ = [
    "FORMATS",
    "REDACTED",
    "SECRET_NAME_EXEMPTIONS",
    "SECRET_NAME_MARKERS",
    "Result",
    "as_sequence",
    "emit",
    "read_bytes",
    "read_secret",
    "redact",
    "render",
]
