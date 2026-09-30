"""Independently measured evidence on each side of a migration transition.

D16's ruling (`docs/design/d16-transition-receipt-decisions.md`) is that a
transition receipt must be built from evidence that cannot be supplied by
the thing it is meant to verify. This module is that evidence, on both
sides, with **no** dependency on `dotmac-deployment-foundation` at all —
the receipt itself (`TransitionReceiptV1`, `TransitionSide`, `TargetSide`)
is a later slice's job, which will late-import Foundation the same way
`recovery/dump_evidence.py`'s `to_backup_record()` does and map these plain
dataclasses into Foundation's shape.

## The asymmetry this module exists to prove

`scripts/deploy_production.sh` (read-only reference, DO NOT TOUCH) reads
`deploy/product.toml` off the live working-tree checkout at the moment it
runs (`DESCRIPTOR_SHA256="sha256:$(sha256sum "$DESCRIPTOR_FILE" ...)"`,
around line 332) — there is no `git pull`/checkout anywhere in that script,
so the working tree may already hold the NEW descriptor by the time an
operator runs it (a descriptor promotion is a normal, independent git
commit — see `deploy/descriptor-promotions.json`). That answers "what
descriptor does this checkout hold right now", never "what descriptor was
the currently-running application actually deployed with".

So: the SOURCE side of a transition (what was actually running, before a
migration) can never be read from the live checkout — it has to come from
something that is independent of the checkout's current state. The one
thing that fixes a running instance's identity is the OCI revision label
baked into the image that instance is actually running, at build time
(Dockerfile `ARG SOURCE_REVISION` -> `LABEL
org.opencontainers.image.revision`; `deploy_production.sh` already reads
this back off the image for the TARGET side, around line 323). From that
revision, the descriptor as it actually was is `git show
<revision>:deploy/product.toml` — never the file currently on disk.

The TARGET side has no such hazard: at the point a real deploy calls
`capture_target_state`, the working tree genuinely IS the target, so
reading `deploy/product.toml` directly off disk is correct, not a
shortcut. `TargetState` therefore carries no `target_revision` field —
see its own docstring for why that absence is deliberate, not an
oversight to "fix" into false symmetry with `GenesisBaseline`.

## Non-circularity is structural

Neither `capture_genesis_baseline` nor `capture_target_state` accepts any
`expected_*`/override parameter for any field. A caller cannot supply what
this evidence "should" say — only measure what it actually is. See
`tests/unit/test_transition_evidence_refusals.py` for the structural proof
(`inspect.signature`), and `tests/migration/test_transition_evidence.py`
for the proof that the source side genuinely reads git history rather than
the working tree.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess  # noqa: S404 - argv list, shell=False throughout
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sqlalchemy import text
from sqlalchemy.engine import Connection

from vendor_cp.deployment.image_heads import SOURCE_REVISION_PATTERN

__all__ = [
    "GenesisBaseline",
    "InvalidSourceRevision",
    "SourceRevisionUnavailable",
    "TargetState",
    "capture_genesis_baseline",
    "capture_target_state",
    "raw_bytes_digest",
    "read_current_migration_heads",
    "read_descriptor_at_revision",
    "read_descriptor_from_working_tree",
]

#: Bounded, never open-ended — matching this repo's own subprocess
#: convention (`recovery/dump_evidence.py`'s `_PG_RESTORE_TIMEOUT_SECONDS`,
#: `transition_fence.py`'s `session_wait_seconds`). `git show` against a
#: single blob at a known revision is fast; 15s stays generous.
_GIT_SHOW_TIMEOUT_SECONDS: Final = 15


class InvalidSourceRevision(ValueError):
    """`source_revision` does not match `SOURCE_REVISION_PATTERN` fully.

    Raised before any subprocess call — this is also the injection defence:
    a value that does not fullmatch 40 lowercase hex characters can never
    reach a `git show` argv, regardless of what it contains.
    """


class SourceRevisionUnavailable(RuntimeError):
    """`source_revision` was well-formed but `git show
    <source_revision>:deploy/product.toml` failed against the given repo.

    Distinct from `InvalidSourceRevision`: the revision LOOKS like a real
    peeled commit, but this repo does not have it (wrong repo root, a
    revision from a different history, a shallow clone) — the same "absent
    capability vs failed check" discipline `recovery/dump_evidence.py`
    already established for `pg_restore` (a malformed request is a
    different fact than a request this host cannot fulfil).
    """


@dataclass(frozen=True, slots=True)
class GenesisBaseline:
    """The SOURCE side of a transition: what was actually running, measured
    independently of the live checkout.

    CP-local evidence, not a Foundation `TransitionSide` — that mapping is a
    later slice's job. Carries no `expected_*`/override field anywhere, by
    design: a caller cannot supply what this evidence "should" say, only
    measure it. `source_revision` is the 40-hex commit the RUNNING image
    was built from (read off the image's OCI revision label by the caller,
    outside this module); `raw_bytes_descriptor_digest` and
    `migration_heads` are measured from that revision's git history and the
    live database respectively, never from the working tree.
    """

    source_revision: str
    raw_bytes_descriptor_digest: str
    migration_heads: tuple[str, ...]
    captured_at_epoch: int


@dataclass(frozen=True, slots=True)
class TargetState:
    """The TARGET side of a transition: the state a migration is moving to.

    Unlike `GenesisBaseline`, this carries no `target_revision` field. At
    the point a real deploy calls `capture_target_state`, the working tree
    genuinely IS the target — there is no "wrong file" risk on this side,
    which is exactly the asymmetry the source side's git-history read
    exists to correct for. Do not "fix" this into false symmetry with
    `GenesisBaseline` by adding a revision field here: the two sides answer
    genuinely different questions, and that difference is the whole point.
    """

    raw_bytes_descriptor_digest: str
    migration_heads: tuple[str, ...]
    captured_at_epoch: int


def raw_bytes_digest(text_: str) -> str:
    """`"sha256:" + hex` over the UTF-8 bytes of `text_`, exactly as given —
    no stripping, no normalization. Kept separate from
    `read_descriptor_at_revision` so "what got hashed" always has one,
    inspectable answer in tests.
    """
    return "sha256:" + hashlib.sha256(text_.encode("utf-8")).hexdigest()


def read_descriptor_at_revision(repo_root: Path, source_revision: str) -> str:
    """`deploy/product.toml`'s text AT `source_revision` — from git history,
    never the working tree.

    Validates `source_revision` against `SOURCE_REVISION_PATTERN.fullmatch`
    first (a 40-hex string embedded in a longer string does not pass) and
    raises `InvalidSourceRevision` before any subprocess call. Runs `git -C
    <repo_root> show <source_revision>:deploy/product.toml`
    (`shell=False`, a bounded timeout); a non-zero exit raises
    `SourceRevisionUnavailable` with the command's stderr included. Returns
    `stdout` exactly as returned — the raw bytes a caller then hashes with
    `raw_bytes_digest`.
    """
    if not SOURCE_REVISION_PATTERN.fullmatch(source_revision):
        raise InvalidSourceRevision(
            f"{source_revision!r} is not 40 lowercase hex characters; "
            "refusing to construct a git command from a value that does "
            "not fully match the expected shape"
        )

    git_executable = shutil.which("git")
    if git_executable is None:
        raise SourceRevisionUnavailable(
            "git is not on PATH, so the descriptor at "
            f"{source_revision}:deploy/product.toml cannot be read from "
            f"{repo_root}; this is an absent capability, not a failed check"
        )

    try:
        result = subprocess.run(  # noqa: S603 - argv list, resolved executable
            [
                git_executable,
                "-C",
                str(repo_root),
                "show",
                f"{source_revision}:deploy/product.toml",
            ],
            capture_output=True,
            text=True,
            timeout=_GIT_SHOW_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise SourceRevisionUnavailable(
            f"git show {source_revision}:deploy/product.toml could not be "
            f"run to completion against {repo_root}: {error}"
        ) from error

    if result.returncode != 0:
        raise SourceRevisionUnavailable(
            f"git show {source_revision}:deploy/product.toml failed against "
            f"{repo_root} (exit {result.returncode}): {result.stderr.strip()}"
        )

    return result.stdout


def read_descriptor_from_working_tree(descriptor_path: Path) -> str:
    """`descriptor_path`'s text, read directly from the working tree.

    Mirrors `deploy_production.sh`'s own `[[ -f "$DESCRIPTOR_FILE" ]] || die
    ...` framing: an absent file is a real, existing Python fact
    (`FileNotFoundError`) and is left to surface as such rather than being
    wrapped in a new exception type.
    """
    return descriptor_path.read_text(encoding="utf-8")


def read_current_migration_heads(conn: Connection) -> tuple[str, ...]:
    """`alembic_version`'s current rows, sorted — the exact query
    `deploy_production.sh` already uses (`SELECT version_num FROM
    alembic_version ORDER BY version_num`, around line 337).
    """
    rows = conn.execute(
        text("SELECT version_num FROM alembic_version ORDER BY version_num")
    )
    return tuple(sorted(row[0] for row in rows))


def capture_genesis_baseline(
    conn: Connection,
    *,
    repo_root: Path,
    source_revision: str,
    now_epoch: int | None = None,
) -> GenesisBaseline:
    """Compose the source-side evidence: the descriptor as it actually was
    at `source_revision` (never the working tree) plus the live database's
    current migration heads.

    Refuses before any database read if `source_revision` is invalid —
    delegated entirely to `read_descriptor_at_revision`'s own validation,
    not duplicated here. No parameter lets a caller supply an
    expected/override value for any field: the signature itself is the
    proof of non-circularity.
    """
    descriptor_text = read_descriptor_at_revision(
        repo_root=repo_root, source_revision=source_revision
    )
    digest = raw_bytes_digest(descriptor_text)
    heads = read_current_migration_heads(conn)
    return GenesisBaseline(
        source_revision=source_revision,
        raw_bytes_descriptor_digest=digest,
        migration_heads=heads,
        captured_at_epoch=now_epoch if now_epoch is not None else int(time.time()),
    )


def capture_target_state(
    conn: Connection,
    *,
    descriptor_path: Path,
    now_epoch: int | None = None,
) -> TargetState:
    """Compose the target-side evidence: the descriptor as it currently
    sits in the working tree plus the live database's current migration
    heads.

    No parameter lets a caller supply an expected/override value for any
    field: the signature itself is the proof of non-circularity.
    """
    descriptor_text = read_descriptor_from_working_tree(descriptor_path)
    digest = raw_bytes_digest(descriptor_text)
    heads = read_current_migration_heads(conn)
    return TargetState(
        raw_bytes_descriptor_digest=digest,
        migration_heads=heads,
        captured_at_epoch=now_epoch if now_epoch is not None else int(time.time()),
    )
