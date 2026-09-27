"""What migration heads does THIS image carry, and do two sources agree?

`composed_effective_heads` used to be defined once, inline, inside
`tests/architecture/test_descriptor_promotion.py` — a test computing a fact
about the composed migration graph that nothing outside the test suite could
read. D16 needs the identical computation at BUILD time, to freeze
`migration_heads.json` into the image, so PR 2's deploy-time check can compare
the pulled image's declared heads against the live database's
`alembic_version` rows before a single writer is unfenced. Moving the function
here and having the architecture test import it is what keeps there being ONE
implementation rather than two that happen to agree today.

## Why this is a document, not a database read

The image does not carry a live database connection at compare time — PR 2
extracts this file from a PULLED image before anything is running. So the
"effective heads" claim has to travel as data, computed once at build time
from the same installed migration lineages the running container would use,
and compared later without re-deriving it from a checkout that may not be the
one that built the image.

## Fails closed, always by naming why

`compare_heads` never merely returns "mismatch" — every `HeadsVerdict` names
the exact defect: a missing document, one that fails to parse, the wrong
schema, an empty head set, a duplicate within one source, or a real
disagreement between two sources. A malformed document and a document that
disagrees are different repairs (a broken build versus an image that is not
the one authorized), so they get different verdicts rather than one.

## Absent and unreadable are different facts

`read_image_document` returns `None` only when the file itself does not
exist, and the distinct `UNREADABLE_DOCUMENT` sentinel when it exists but is
not usable JSON (or not a mapping). "Nobody built this" and "the build wrote
something broken" call for different repairs, so `compare_heads` gives them
`DOCUMENT_ABSENT` and `DOCUMENT_UNREADABLE` respectively rather than folding
both to one generic falsy value.

## `source_revision` is validated, not merely carried

A document's `source_revision` must be exactly 40 lowercase hex characters —
a peeled git commit, never `unknown`, a branch name, or a short SHA — or
`compare_heads` returns `SOURCE_REVISION_INVALID` before it looks at heads at
all. When a caller supplies `expected_source_revision`, a well-formed but
different revision returns `SOURCE_REVISION_MISMATCH`: the pulled image
claims to have been built from a commit that is not the one authorized. The
`--emit` entry point enforces the same 40-hex-character shape at build time
and exits non-zero rather than freezing a document that could never satisfy
either check downstream.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final

from alembic.config import Config
from alembic.script import ScriptDirectory

__all__ = [
    "IMAGE_HEADS_SCHEMA",
    "SOURCE_REVISION_PATTERN",
    "UNREADABLE_DOCUMENT",
    "HeadsVerdict",
    "composed_effective_heads",
    "compare_heads",
    "read_image_document",
    "render_image_document",
]

IMAGE_HEADS_SCHEMA: Final = "ImageMigrationHeads.v1"

#: A peeled git commit: exactly 40 lowercase hex characters. Anything else —
#: `unknown`, a branch name, a short SHA, uppercase hex — is refused.
SOURCE_REVISION_PATTERN: Final = re.compile(r"[0-9a-f]{40}")

#: Where the document travels inside the image, beside
#: `application_foundation_profile.json` and `distributions.json`.
DEFAULT_IMAGE_HEADS_PATH: Final = Path("/app/migration_heads.json")


class _UnreadableDocument:
    """Sentinel: a document file exists but is not usable JSON.

    Distinct from `None` (`read_image_document` returns that only when the
    file is absent) so `compare_heads` can tell "nothing was ever written
    here" from "something was written and it is broken" — a missing document
    and a malformed one call for different repairs."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "UNREADABLE_DOCUMENT"


UNREADABLE_DOCUMENT: Final = _UnreadableDocument()

#: What `read_image_document` can hand back: a parsed mapping, `None` for an
#: absent file, or `UNREADABLE_DOCUMENT` for a present-but-broken one.
ImageDocument = Mapping[str, object] | None | _UnreadableDocument


class HeadsVerdict(StrEnum):
    """Why the image's declared heads were or were not admitted."""

    MATCHED = "matched"
    #: No document at the given path at all.
    DOCUMENT_ABSENT = "document_absent"
    #: Present, but not parseable JSON, not a mapping, or the wrong shape once
    #: parsed (e.g. `heads` is not a list of strings).
    DOCUMENT_UNREADABLE = "document_unreadable"
    #: Parsed, but not this schema.
    CONTRACT_UNKNOWN = "contract_unknown"
    #: `source_revision` is not exactly 40 lowercase hex characters.
    SOURCE_REVISION_INVALID = "source_revision_invalid"
    #: `source_revision` is well-formed but does not equal the revision the
    #: caller expected.
    SOURCE_REVISION_MISMATCH = "source_revision_mismatch"
    #: A source (image, descriptor, or database) declared zero heads.
    EMPTY_HEAD_SET = "empty_head_set"
    #: The same head named twice within one source.
    DUPLICATE_HEADS = "duplicate_heads"
    #: The image's heads and the descriptor's heads are not the same set.
    IMAGE_DESCRIPTOR_MISMATCHED = "image_descriptor_mismatched"
    #: The database's heads (when supplied) are not the same set as the image's.
    IMAGE_DATABASE_MISMATCHED = "image_database_mismatched"


def composed_effective_heads(config: Config) -> tuple[str, ...]:
    """The revisions `alembic_version` holds after the composed lineage runs.

    NOT `ScriptDirectory.get_heads()`, which answers a different question: the
    graph can have a head that is also named in another revision's
    `depends_on`, and Alembic prunes a subsumed dependency from the version
    table rather than leaving it there as a second row. Comparing against the
    graph's heads would demand a row the database will never hold.
    """
    script = ScriptDirectory.from_config(config)
    heads = set(script.get_heads())
    dependencies: set[str] = set()
    for revision in script.walk_revisions("base", "heads"):
        declared = revision.dependencies or ()
        names: Iterable[str] = (declared,) if isinstance(declared, str) else declared
        dependencies.update(names)
    return tuple(sorted(heads - dependencies))


def render_image_document(*, source_revision: str, heads: Sequence[str]) -> str:
    """The bytes written into the image at build time."""
    document = {
        "schema": IMAGE_HEADS_SCHEMA,
        "source_revision": source_revision,
        "heads": sorted(heads),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def read_image_document(path: Path) -> ImageDocument:
    """Parse `path`. `None` when it is absent; `UNREADABLE_DOCUMENT` when it
    exists but is not usable JSON.

    An absent file and a broken one are different facts calling for different
    repairs — a missing build step versus a corrupted build artifact —  so
    `compare_heads` turns each into its own NAMED verdict rather than folding
    both to one generic falsy value.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        # Present but unreadable (permission denied, a directory at the
        # path, ...): a broken artifact, not a missing build step.
        return UNREADABLE_DOCUMENT
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return UNREADABLE_DOCUMENT
    if not isinstance(parsed, dict):
        return UNREADABLE_DOCUMENT
    return parsed


def _duplicates(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for value in values:
        if value in seen:
            dupes.add(value)
        seen.add(value)
    return tuple(sorted(dupes))


def compare_heads(
    *,
    image_document: ImageDocument,
    descriptor_heads: Sequence[str],
    database_heads: Sequence[str] | None = None,
    expected_source_revision: str | None = None,
) -> HeadsVerdict:
    """Fail closed on a missing document, a malformed one, or a disagreement."""
    if image_document is None:
        return HeadsVerdict.DOCUMENT_ABSENT

    if not isinstance(image_document, Mapping):
        # `UNREADABLE_DOCUMENT`, the only non-Mapping value left here.
        return HeadsVerdict.DOCUMENT_UNREADABLE

    if image_document.get("schema") != IMAGE_HEADS_SCHEMA:
        return HeadsVerdict.CONTRACT_UNKNOWN

    source_revision = image_document.get("source_revision")
    if not isinstance(source_revision, str) or not SOURCE_REVISION_PATTERN.fullmatch(
        source_revision
    ):
        return HeadsVerdict.SOURCE_REVISION_INVALID
    if (
        expected_source_revision is not None
        and source_revision != expected_source_revision
    ):
        return HeadsVerdict.SOURCE_REVISION_MISMATCH

    raw_heads = image_document.get("heads")
    if not isinstance(raw_heads, list) or not all(
        isinstance(item, str) for item in raw_heads
    ):
        return HeadsVerdict.DOCUMENT_UNREADABLE
    image_heads: list[str] = list(raw_heads)

    for label, values in (
        ("image", image_heads),
        ("descriptor", list(descriptor_heads)),
        ("database", list(database_heads) if database_heads is not None else []),
    ):
        if label == "database" and database_heads is None:
            continue
        if not values:
            return HeadsVerdict.EMPTY_HEAD_SET
        if _duplicates(values):
            return HeadsVerdict.DUPLICATE_HEADS

    if set(image_heads) != set(descriptor_heads):
        return HeadsVerdict.IMAGE_DESCRIPTOR_MISMATCHED

    if database_heads is not None and set(image_heads) != set(database_heads):
        return HeadsVerdict.IMAGE_DATABASE_MISMATCHED

    return HeadsVerdict.MATCHED


def main(argv: Sequence[str] | None = None) -> int:
    from vendor_cp.migrations import make_alembic_config

    parser = argparse.ArgumentParser(
        prog="python -m vendor_cp.deployment.image_heads",
        description="Emit this build's composed effective migration heads.",
    )
    parser.add_argument("--emit", action="store_true", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    # No database is dialled: `make_alembic_config` builds an offline `Config`
    # and constructs no engine, matching `test_descriptor_promotion.py`'s own
    # `OFFLINE_DSN` use of the same function.
    parser.add_argument(
        "--offline-dsn",
        default="postgresql+psycopg://image-heads@127.0.0.1:5432/none",
    )
    args = parser.parse_args(argv)

    if not SOURCE_REVISION_PATTERN.fullmatch(args.source_revision):
        print(
            f"--source-revision {args.source_revision!r} is not 40 lowercase "
            "hex characters; refusing to emit a document that claims an "
            "artifact this module cannot identify",
            file=sys.stderr,
        )
        return 1

    config = make_alembic_config(args.offline_dsn)
    heads = composed_effective_heads(config)
    if not heads:
        print(
            "composed_effective_heads returned no heads; refusing to emit an "
            "empty head set",
            file=sys.stderr,
        )
        return 1

    args.output.write_text(
        render_image_document(source_revision=args.source_revision, heads=heads),
        encoding="utf-8",
    )
    print(f"{args.output}: {len(heads)} effective head(s): {', '.join(heads)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    sys.exit(main())
