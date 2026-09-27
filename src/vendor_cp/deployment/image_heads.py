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
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Final

from alembic.config import Config
from alembic.script import ScriptDirectory

__all__ = [
    "IMAGE_HEADS_SCHEMA",
    "HeadsVerdict",
    "composed_effective_heads",
    "compare_heads",
    "read_image_document",
    "render_image_document",
]

IMAGE_HEADS_SCHEMA: Final = "ImageMigrationHeads.v1"

#: Where the document travels inside the image, beside
#: `application_foundation_profile.json` and `distributions.json`.
DEFAULT_IMAGE_HEADS_PATH: Final = Path("/app/migration_heads.json")


class HeadsVerdict(StrEnum):
    """Why the image's declared heads were or were not admitted."""

    MATCHED = "matched"
    #: No document at the given path at all.
    DOCUMENT_ABSENT = "document_absent"
    #: Present, but not parseable JSON, or not a mapping.
    DOCUMENT_UNREADABLE = "document_unreadable"
    #: Parsed, but not this schema.
    CONTRACT_UNKNOWN = "contract_unknown"
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


def read_image_document(path: Path) -> Mapping[str, object] | None:
    """Parse `path`, or None when it is absent or unusable.

    Follows `profile_readback._load`'s style: absence and unreadability are
    both folded to None here, because `compare_heads` is the place that turns
    "missing" into a NAMED verdict rather than a generic falsy value.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
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
    image_document: Mapping[str, object] | None,
    descriptor_heads: Sequence[str],
    database_heads: Sequence[str] | None = None,
) -> HeadsVerdict:
    """Fail closed on a missing document, a malformed one, or a disagreement."""
    if image_document is None:
        return HeadsVerdict.DOCUMENT_ABSENT

    if image_document.get("schema") != IMAGE_HEADS_SCHEMA:
        return HeadsVerdict.CONTRACT_UNKNOWN

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

    config = make_alembic_config(args.offline_dsn)
    heads = composed_effective_heads(config)
    args.output.write_text(
        render_image_document(source_revision=args.source_revision, heads=heads),
        encoding="utf-8",
    )
    print(f"{args.output}: {len(heads)} effective head(s): {', '.join(heads)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    sys.exit(main())
