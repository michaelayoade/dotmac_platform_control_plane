"""Local descriptor and migration-head observations for a transition.

D16's ruling (`docs/design/d16-transition-receipt-decisions.md`) is that a
transition receipt must be built from evidence that cannot be supplied by
the thing it is meant to verify. This module measures bytes and database
heads, but does not verify a running image's identity or a host fence. It
has **no** dependency on `dotmac-deployment-foundation` at all —
the receipt itself (`TransitionReceiptV1`, `TransitionSide`, `TargetSide`)
is a later slice's job. These observations retain descriptor bytes so that
Foundation's canonical descriptor digest can be computed later; their raw
byte digests are CP provenance and must never be copied into receipt fields.

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

So: the SOURCE descriptor candidate cannot be read from the live checkout
— it has to come from the revision independently established for the running
image. That identity must be verified from the OCI revision label baked into
the image that instance is actually running, at build time
(Dockerfile `ARG SOURCE_REVISION` -> `LABEL
org.opencontainers.image.revision`; `deploy_production.sh` already reads
this back off the image for the TARGET side, around line 323). Given that
verified revision, Git history can supply its descriptor via `git show
<revision>:deploy/product.toml`. This module only accepts a caller-supplied
revision and reads that blob; it does not perform the image verification.

The TARGET capture reads the caller-selected working-tree descriptor. A
deploy must establish that this checkout is the intended target; this
module does not do so. `TargetState` carries no `target_revision` field
because this capture observes bytes and heads, not image identity.

## Non-circularity is structural

Neither capture accepts an override for the descriptor bytes, raw digest or
migration heads it reads. The caller still selects the source revision or
target path and supplies the connection; their authority must be established
elsewhere. See `tests/unit/test_transition_evidence_refusals.py` for the
structural proof
(`inspect.signature`), and `tests/migration/test_transition_evidence.py`
for the proof that the source side genuinely reads git history rather than
the working tree.
"""

from __future__ import annotations

import hashlib
import os
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
    """A proposed SOURCE observation measured independently of the checkout.

    CP-local evidence, not a Foundation `TransitionSide` — that mapping is a
    later slice's job. `source_revision` is a caller-supplied 40-hex commit;
    this module does not verify that the running image was built from it.
    `descriptor_bytes` preserves the exact blob read from that revision's Git
    history; `raw_bytes_descriptor_digest` identifies
    those bytes for CP provenance, not for a Foundation receipt. Migration
    heads are measured from the live database, never the working tree.
    """

    source_revision: str
    descriptor_bytes: bytes
    raw_bytes_descriptor_digest: str
    migration_heads: tuple[str, ...]
    captured_at_epoch: int

    def __post_init__(self) -> None:
        _require_matching_raw_descriptor(
            self.descriptor_bytes, self.raw_bytes_descriptor_digest
        )


@dataclass(frozen=True, slots=True)
class TargetState:
    """The TARGET side of a transition: the state a migration is moving to.

    Unlike `GenesisBaseline`, this carries no `target_revision` field. The
    caller selects the working-tree path and must establish separately that
    it is the intended target. This observation does not attest image identity.
    `descriptor_bytes` preserves the exact working-tree read at capture time;
    its raw digest is CP provenance, not a Foundation receipt input.
    """

    descriptor_bytes: bytes
    raw_bytes_descriptor_digest: str
    migration_heads: tuple[str, ...]
    captured_at_epoch: int

    def __post_init__(self) -> None:
        _require_matching_raw_descriptor(
            self.descriptor_bytes, self.raw_bytes_descriptor_digest
        )


def raw_bytes_digest(data: bytes) -> str:
    """`"sha256:" + hex` over `data`, exactly as given — no decoding, no
    newline normalization, no re-encoding. Kept separate from
    `read_descriptor_at_revision` so "what got hashed" always has one,
    inspectable answer in tests.

    Takes `bytes`, not `str`, deliberately: `subprocess.run(text=True)` and
    `Path.read_text()` both perform universal-newline translation
    (`\\r\\n`/`\\r` -> `\\n`) and locale/encoding-dependent decoding before a
    caller ever sees a `str` — hashing a decoded-then-re-encoded string would
    silently diverge from `sha256sum`'s (and `scripts/promote_descriptor.py`'s
    `raw_digest`'s) raw-bytes convention for any descriptor containing a
    `\\r` or content decoded under an unexpected locale.
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_matching_raw_descriptor(descriptor_bytes: bytes, digest: str) -> None:
    """Keep a frozen observation's bytes immutable and its raw digest honest."""
    if type(descriptor_bytes) is not bytes:
        raise TypeError("descriptor_bytes must be immutable bytes")
    if raw_bytes_digest(descriptor_bytes) != digest:
        raise ValueError("raw_bytes_descriptor_digest does not match descriptor_bytes")


def _git_isolated_env() -> dict[str, str]:
    """An environment for a git subprocess call that cannot be redirected by
    ambient `GIT_*` variables, matching `d16_source_verifier.py`'s own `_git`
    helper (the established pattern in this codebase for exactly this
    class of risk): every existing `GIT_*` variable is stripped (so
    `GIT_DIR`/`GIT_WORK_TREE` cannot repoint `-C <repo_root>` at a different
    repository), and a fixed set is then applied on top.
    """
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_TERMINAL_PROMPT="0",
    )
    return environment


def read_descriptor_at_revision(repo_root: Path, source_revision: str) -> bytes:
    """`deploy/product.toml`'s RAW BYTES AT `source_revision` — from git
    history, never the working tree.

    Validates `source_revision` is a `str` matching
    `SOURCE_REVISION_PATTERN.fullmatch` first (a 40-hex string embedded in a
    longer string does not pass; a non-`str` value is refused the same way,
    never left to raise a bare `TypeError`) and raises
    `InvalidSourceRevision` before any subprocess call. Runs `git
    --no-replace-objects -C <repo_root> show
    <source_revision>:deploy/product.toml` (`shell=False`, binary mode, a
    bounded timeout, replacement objects and ambient `GIT_*` overrides
    disabled — see `_git_isolated_env`); a non-zero exit raises
    `SourceRevisionUnavailable` with the command's stderr included. Returns
    `stdout` exactly as returned, in bytes — no decode, no newline
    translation — the raw bytes a caller then hashes with `raw_bytes_digest`.
    """
    if not isinstance(source_revision, str) or not SOURCE_REVISION_PATTERN.fullmatch(
        source_revision
    ):
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
                "--no-replace-objects",
                "-C",
                str(repo_root),
                "show",
                f"{source_revision}:deploy/product.toml",
            ],
            capture_output=True,
            text=False,
            timeout=_GIT_SHOW_TIMEOUT_SECONDS,
            check=False,
            env=_git_isolated_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise SourceRevisionUnavailable(
            f"git show {source_revision}:deploy/product.toml could not be "
            f"run to completion against {repo_root}: {error}"
        ) from error

    if result.returncode != 0:
        # `stderr` is bytes here (binary mode) — decoded ONLY for this human
        # error message, with `errors="replace"`; never for hashed content.
        stderr_text = result.stderr.decode("utf-8", errors="replace").strip()
        raise SourceRevisionUnavailable(
            f"git show {source_revision}:deploy/product.toml failed against "
            f"{repo_root} (exit {result.returncode}): {stderr_text}"
        )

    return result.stdout


def read_descriptor_from_working_tree(descriptor_path: Path) -> bytes:
    """`descriptor_path`'s RAW BYTES, read directly from the working tree —
    no decode, no newline translation.

    Mirrors `deploy_production.sh`'s own `[[ -f "$DESCRIPTOR_FILE" ]] || die
    ...` framing: an absent file is a real, existing Python fact
    (`FileNotFoundError`) and is left to surface as such rather than being
    wrapped in a new exception type.
    """
    return descriptor_path.read_bytes()


def read_current_migration_heads(conn: Connection) -> tuple[str, ...]:
    """`alembic_version`'s current rows, sorted — the exact query
    `deploy_production.sh` already uses (`SELECT version_num FROM
    alembic_version ORDER BY version_num`, around line 337), schema-qualified
    (`public.alembic_version`) since an unqualified read depends on
    `search_path`.

    A genuinely never-migrated database (a fresh `scratch_db`, before its
    first `dotmac-platform admin migrate` run) has no `alembic_version`
    table at all — `to_regclass` is checked FIRST, and `()` is returned when
    it is `NULL`, the same `to_regclass('public.alembic_version') IS NOT
    NULL` guard `tests/migration/test_vendor_migration_rehearsals.py`
    already uses. This is a real, meaningful fact about a brand-new
    database, not an error to raise.
    """
    table_exists = conn.execute(
        text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
    ).scalar_one()
    if not table_exists:
        return ()
    rows = conn.execute(
        text("SELECT version_num FROM public.alembic_version ORDER BY version_num")
    )
    return tuple(sorted(row[0] for row in rows))


def capture_genesis_baseline(
    conn: Connection,
    *,
    repo_root: Path,
    source_revision: str,
    now_epoch: int | None = None,
) -> GenesisBaseline:
    """Capture the descriptor at the caller-supplied `source_revision`
    (never the working tree) plus the connection's current migration heads.

    Refuses before any database read if `source_revision` is invalid —
    delegated entirely to `read_descriptor_at_revision`'s own validation,
    not duplicated here. The caller must establish the revision's running-image
    provenance and the connection's host and fence elsewhere.
    """
    descriptor_bytes = read_descriptor_at_revision(
        repo_root=repo_root, source_revision=source_revision
    )
    digest = raw_bytes_digest(descriptor_bytes)
    heads = read_current_migration_heads(conn)
    return GenesisBaseline(
        source_revision=source_revision,
        descriptor_bytes=descriptor_bytes,
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

    The caller must establish that the selected path and connection refer to
    the intended target elsewhere.
    """
    descriptor_bytes = read_descriptor_from_working_tree(descriptor_path)
    digest = raw_bytes_digest(descriptor_bytes)
    heads = read_current_migration_heads(conn)
    return TargetState(
        descriptor_bytes=descriptor_bytes,
        raw_bytes_descriptor_digest=digest,
        migration_heads=heads,
        captured_at_epoch=now_epoch if now_epoch is not None else int(time.time()),
    )
