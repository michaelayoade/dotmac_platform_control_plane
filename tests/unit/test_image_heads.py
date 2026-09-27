"""`compare_heads` names the exact defect, and the document round-trips.

Every `HeadsVerdict` branch gets a positive case (the verdict fires) and a
negative case (the identical input, minimally repaired, does not fire) — a
verdict that never fires on a repaired input is a verdict nothing tests.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from vendor_cp.deployment.image_heads import (
    IMAGE_HEADS_SCHEMA,
    UNREADABLE_DOCUMENT,
    HeadsVerdict,
    compare_heads,
    composed_effective_heads,
    read_image_document,
    render_image_document,
)
from vendor_cp.migrations import make_alembic_config

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_TOML = ROOT / "deploy" / "product.toml"

#: A dummy DSN. `make_alembic_config` builds a `Config` and constructs no
#: engine, matching `test_descriptor_promotion.py`'s own `OFFLINE_DSN` use.
OFFLINE_DSN = "postgresql+psycopg://image-heads@127.0.0.1:5432/none"

#: A well-formed 40-lowercase-hex source revision, so tests that are not
#: about `source_revision` itself do not trip `SOURCE_REVISION_INVALID`.
_VALID_REVISION = "a" * 40

_VALID_DOCUMENT = {
    "schema": IMAGE_HEADS_SCHEMA,
    "source_revision": _VALID_REVISION,
    "heads": ["h1", "h2"],
}


def _doc(**overrides: object) -> dict[str, object]:
    document = dict(_VALID_DOCUMENT)
    document.update(overrides)
    return document


# ── MATCHED ──────────────────────────────────────────────────────────────────


def test_matched_when_image_and_descriptor_heads_agree() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h2", "h1"],
    )
    assert verdict == HeadsVerdict.MATCHED


def test_matched_extends_to_a_supplied_database_head_set_too() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h2"],
        database_heads=["h2", "h1"],
    )
    assert verdict == HeadsVerdict.MATCHED


# ── DOCUMENT_ABSENT ──────────────────────────────────────────────────────────


def test_document_absent_when_image_document_is_none() -> None:
    verdict = compare_heads(image_document=None, descriptor_heads=["h1"])
    assert verdict == HeadsVerdict.DOCUMENT_ABSENT


def test_document_absent_does_not_fire_when_a_document_is_supplied() -> None:
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict != HeadsVerdict.DOCUMENT_ABSENT


def test_document_absent_does_not_fire_for_the_unreadable_sentinel() -> None:
    """`UNREADABLE_DOCUMENT` is a PRESENT, broken document — the negative
    control proving it never collapses into the absent-document verdict."""
    verdict = compare_heads(image_document=UNREADABLE_DOCUMENT, descriptor_heads=["h1"])
    assert verdict != HeadsVerdict.DOCUMENT_ABSENT
    assert verdict == HeadsVerdict.DOCUMENT_UNREADABLE


# ── CONTRACT_UNKNOWN ─────────────────────────────────────────────────────────


def test_contract_unknown_when_schema_does_not_match() -> None:
    verdict = compare_heads(
        image_document=_doc(schema="SomeOtherSchema.v1"),
        descriptor_heads=["h1", "h2"],
    )
    assert verdict == HeadsVerdict.CONTRACT_UNKNOWN


def test_contract_unknown_does_not_fire_when_schema_matches() -> None:
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict != HeadsVerdict.CONTRACT_UNKNOWN


# ── SOURCE_REVISION_INVALID ──────────────────────────────────────────────────


def test_source_revision_invalid_when_it_is_the_literal_unknown() -> None:
    verdict = compare_heads(
        image_document=_doc(source_revision="unknown"), descriptor_heads=["h1", "h2"]
    )
    assert verdict == HeadsVerdict.SOURCE_REVISION_INVALID


def test_source_revision_invalid_when_it_is_short() -> None:
    verdict = compare_heads(
        image_document=_doc(source_revision="abc123"),
        descriptor_heads=["h1", "h2"],
    )
    assert verdict == HeadsVerdict.SOURCE_REVISION_INVALID


def test_source_revision_invalid_when_it_has_uppercase_hex() -> None:
    verdict = compare_heads(
        image_document=_doc(source_revision="A" * 40),
        descriptor_heads=["h1", "h2"],
    )
    assert verdict == HeadsVerdict.SOURCE_REVISION_INVALID


def test_source_revision_invalid_when_it_is_not_a_string() -> None:
    verdict = compare_heads(
        image_document=_doc(source_revision=123456),
        descriptor_heads=["h1", "h2"],
    )
    assert verdict == HeadsVerdict.SOURCE_REVISION_INVALID


def test_source_revision_invalid_does_not_fire_on_40_lowercase_hex_chars() -> None:
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict != HeadsVerdict.SOURCE_REVISION_INVALID


# ── SOURCE_REVISION_MISMATCH ─────────────────────────────────────────────────


def test_source_revision_mismatch_when_it_disagrees_with_the_expected_one() -> None:
    verdict = compare_heads(
        image_document=_doc(),
        descriptor_heads=["h1", "h2"],
        expected_source_revision="b" * 40,
    )
    assert verdict == HeadsVerdict.SOURCE_REVISION_MISMATCH


def test_source_revision_mismatch_does_not_fire_when_it_agrees() -> None:
    verdict = compare_heads(
        image_document=_doc(),
        descriptor_heads=["h1", "h2"],
        expected_source_revision=_VALID_REVISION,
    )
    assert verdict != HeadsVerdict.SOURCE_REVISION_MISMATCH
    assert verdict == HeadsVerdict.MATCHED


def test_source_revision_mismatch_does_not_fire_when_no_expectation_is_given() -> None:
    """The negative control for `expected_source_revision=None`: no expected
    revision means no opinion at all, even on a well-formed but arbitrary
    source_revision."""
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict == HeadsVerdict.MATCHED


# ── DOCUMENT_UNREADABLE ──────────────────────────────────────────────────────


def test_document_unreadable_when_heads_is_not_a_list() -> None:
    verdict = compare_heads(image_document=_doc(heads="h1"), descriptor_heads=["h1"])
    assert verdict == HeadsVerdict.DOCUMENT_UNREADABLE


def test_document_unreadable_when_heads_contains_a_non_string() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", 2]), descriptor_heads=["h1"]
    )
    assert verdict == HeadsVerdict.DOCUMENT_UNREADABLE


def test_document_unreadable_does_not_fire_on_a_well_formed_heads_list() -> None:
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict != HeadsVerdict.DOCUMENT_UNREADABLE


# ── EMPTY_HEAD_SET ───────────────────────────────────────────────────────────


def test_empty_head_set_when_image_heads_is_empty() -> None:
    verdict = compare_heads(image_document=_doc(heads=[]), descriptor_heads=["h1"])
    assert verdict == HeadsVerdict.EMPTY_HEAD_SET


def test_empty_head_set_when_descriptor_heads_is_empty() -> None:
    verdict = compare_heads(image_document=_doc(), descriptor_heads=[])
    assert verdict == HeadsVerdict.EMPTY_HEAD_SET


def test_empty_head_set_when_database_heads_is_empty() -> None:
    verdict = compare_heads(
        image_document=_doc(),
        descriptor_heads=["h1", "h2"],
        database_heads=[],
    )
    assert verdict == HeadsVerdict.EMPTY_HEAD_SET


def test_empty_head_set_does_not_fire_when_every_source_is_non_empty() -> None:
    verdict = compare_heads(
        image_document=_doc(),
        descriptor_heads=["h1", "h2"],
        database_heads=["h1", "h2"],
    )
    assert verdict != HeadsVerdict.EMPTY_HEAD_SET


def test_a_database_argument_of_none_is_not_the_empty_head_set() -> None:
    """`database_heads=None` means "not supplied", not "supplied and empty" —
    the negative control for the empty-set branch above."""
    verdict = compare_heads(image_document=_doc(), descriptor_heads=["h1", "h2"])
    assert verdict == HeadsVerdict.MATCHED


# ── DUPLICATE_HEADS ──────────────────────────────────────────────────────────


def test_duplicate_heads_when_image_repeats_a_head() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h1"]), descriptor_heads=["h1"]
    )
    assert verdict == HeadsVerdict.DUPLICATE_HEADS


def test_duplicate_heads_when_descriptor_repeats_a_head() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h1", "h2"],
    )
    assert verdict == HeadsVerdict.DUPLICATE_HEADS


def test_duplicate_heads_when_database_repeats_a_head() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h2"],
        database_heads=["h1", "h1", "h2"],
    )
    assert verdict == HeadsVerdict.DUPLICATE_HEADS


def test_duplicate_heads_does_not_fire_when_every_source_is_deduplicated() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h2"],
        database_heads=["h1", "h2"],
    )
    assert verdict != HeadsVerdict.DUPLICATE_HEADS


# ── IMAGE_DESCRIPTOR_MISMATCHED ──────────────────────────────────────────────


def test_image_descriptor_mismatched_when_the_sets_differ() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]), descriptor_heads=["h1", "h3"]
    )
    assert verdict == HeadsVerdict.IMAGE_DESCRIPTOR_MISMATCHED


def test_image_descriptor_mismatched_does_not_fire_when_the_sets_agree() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]), descriptor_heads=["h2", "h1"]
    )
    assert verdict != HeadsVerdict.IMAGE_DESCRIPTOR_MISMATCHED


# ── IMAGE_DATABASE_MISMATCHED ────────────────────────────────────────────────


def test_image_database_mismatched_when_the_sets_differ() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h2"],
        database_heads=["h1", "h3"],
    )
    assert verdict == HeadsVerdict.IMAGE_DATABASE_MISMATCHED


def test_image_database_mismatched_does_not_fire_when_the_sets_agree() -> None:
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]),
        descriptor_heads=["h1", "h2"],
        database_heads=["h2", "h1"],
    )
    assert verdict != HeadsVerdict.IMAGE_DATABASE_MISMATCHED


def test_image_database_mismatched_does_not_fire_when_database_heads_is_absent() -> (
    None
):
    """The negative control for `database_heads=None`: no database source means
    no `IMAGE_DATABASE_MISMATCHED` opinion at all, even if the image and a
    hypothetical database might disagree."""
    verdict = compare_heads(
        image_document=_doc(heads=["h1", "h2"]), descriptor_heads=["h1", "h2"]
    )
    assert verdict == HeadsVerdict.MATCHED


# ── render/read round-trip ───────────────────────────────────────────────────


def test_render_and_read_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "migration_heads.json"
    rendered = render_image_document(source_revision="deadbeef", heads=["h2", "h1"])
    path.write_text(rendered, encoding="utf-8")

    document = read_image_document(path)

    assert document is not None
    assert document["schema"] == IMAGE_HEADS_SCHEMA
    assert document["source_revision"] == "deadbeef"
    # Rendered sorted, regardless of input order.
    assert document["heads"] == ["h1", "h2"]


def test_read_image_document_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    assert read_image_document(missing) is None


def test_a_present_but_unreadable_path_is_unreadable_not_absent(tmp_path: Path) -> None:
    """A directory at the path exists but cannot be read as a file: a broken
    artifact, never a missing build step."""
    directory = tmp_path / "migration_heads.json"
    directory.mkdir()
    assert read_image_document(directory) is UNREADABLE_DOCUMENT


def test_read_image_document_gives_the_unreadable_sentinel_for_bad_json(
    tmp_path: Path,
) -> None:
    """A PRESENT but broken file is a different fact from an ABSENT one — it
    means a build wrote something, and that something is corrupt — so it must
    not be conflated with `None` (see `test_read_image_document_returns_none_
    for_a_missing_file` for the true-absence case)."""
    path = tmp_path / "migration_heads.json"
    path.write_text("not valid json {{{", encoding="utf-8")

    document = read_image_document(path)

    assert document is UNREADABLE_DOCUMENT
    assert document is not None
    # And `compare_heads` turns the sentinel into its OWN named verdict,
    # never the absent-document one.
    verdict = compare_heads(image_document=document, descriptor_heads=["h1"])
    assert verdict == HeadsVerdict.DOCUMENT_UNREADABLE


def test_read_image_document_returns_the_unreadable_sentinel_for_a_json_array() -> None:
    """Parsed JSON that is not a mapping (a list, a bare string, a number) is
    a PRESENT, broken document — `UNREADABLE_DOCUMENT`, not `None` —
    `compare_heads` cannot ask `.get("schema")` of a list."""
    import json
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(["h1", "h2"], handle)
        temp_path = Path(handle.name)
    try:
        assert read_image_document(temp_path) is UNREADABLE_DOCUMENT
    finally:
        temp_path.unlink()


# ── composed_effective_heads vs deploy/product.toml ─────────────────────────


def test_composed_effective_heads_equals_the_descriptors_expected_heads() -> None:
    """The same equality `test_descriptor_promotion.py` checks, read here
    directly via `tomllib` per the packet's instruction, so this file does not
    depend on that architecture test module."""
    migration = tomllib.loads(PRODUCT_TOML.read_text(encoding="utf-8"))["migration"]
    config = make_alembic_config(OFFLINE_DSN)
    assert tuple(migration["expected_heads"]) == composed_effective_heads(config)


# ── `--emit` fails closed ────────────────────────────────────────────────────


def test_emit_exits_non_zero_on_a_source_revision_that_is_not_40_hex_chars(
    tmp_path: Path,
) -> None:
    from vendor_cp.deployment.image_heads import main

    output = tmp_path / "migration_heads.json"
    exit_code = main(
        [
            "--emit",
            "--source-revision",
            "unknown",
            "--output",
            str(output),
            "--offline-dsn",
            OFFLINE_DSN,
        ]
    )
    assert exit_code != 0
    assert not output.exists()


def test_emit_exits_non_zero_on_an_empty_head_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vendor_cp.deployment.image_heads as image_heads_module

    monkeypatch.setattr(
        image_heads_module, "composed_effective_heads", lambda config: ()
    )
    output = tmp_path / "migration_heads.json"
    exit_code = image_heads_module.main(
        [
            "--emit",
            "--source-revision",
            _VALID_REVISION,
            "--output",
            str(output),
            "--offline-dsn",
            OFFLINE_DSN,
        ]
    )
    assert exit_code != 0
    assert not output.exists()


def test_emit_succeeds_and_writes_the_document_on_a_valid_revision(
    tmp_path: Path,
) -> None:
    from vendor_cp.deployment.image_heads import main

    output = tmp_path / "migration_heads.json"
    exit_code = main(
        [
            "--emit",
            "--source-revision",
            _VALID_REVISION,
            "--output",
            str(output),
            "--offline-dsn",
            OFFLINE_DSN,
        ]
    )
    assert exit_code == 0
    document = read_image_document(output)
    assert document is not None and document is not UNREADABLE_DOCUMENT
    assert document["source_revision"] == _VALID_REVISION
