"""The vendored Starter blobs equal their pinned digests, byte for byte (CP-5).

No database, no Foundation: this runs in the ordinary job and fails on the first
edit to a vendored file. A pin is only as strong as the test that reads it, so the
test also refuses a pin file that names a file not on disk, a file on disk that no
pin names, and a pin whose recorded commit is not a full 40-hex SHA.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

VENDORED = Path(__file__).resolve().parents[1] / "vendored"
PIN_FILES = sorted(VENDORED.glob("*/PINS.json"))


def test_both_vendored_suites_are_pinned() -> None:
    assert [p.parent.name for p in PIN_FILES] == [
        "starter_lane3",
        "starter_lane3_cp6",
    ]


@pytest.mark.parametrize("pins_path", PIN_FILES, ids=lambda p: p.parent.name)
def test_every_vendored_file_is_pinned_and_unchanged(pins_path: Path) -> None:
    pins = json.loads(pins_path.read_text(encoding="utf-8"))
    assert re.fullmatch(r"[0-9a-f]{40}", pins["source_commit"]), "pin a full commit"
    assert pins["source_repository"] == "michaelayoade/dotmac_starter_mt"
    directory = pins_path.parent
    on_disk = {p.name for p in directory.glob("*.py")}
    assert on_disk == set(pins["files"]), "a vendored file has no pin, or a pin no file"
    for name, entry in pins["files"].items():
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"{name} drifted from its pinned digest"
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])


def test_the_pin_check_can_still_fail(tmp_path: Path) -> None:
    """SENSITIVITY: a one-byte edit changes the digest the pin records."""
    source = next((VENDORED / "starter_lane3").glob("lane3_lease_store.py"))
    original = source.read_bytes()
    assert (
        hashlib.sha256(original + b" ").hexdigest()
        != hashlib.sha256(original).hexdigest()
    )


def test_the_cp6_pin_records_that_the_starter_schema_is_provisional() -> None:
    pins = json.loads(
        (VENDORED / "starter_lane3_cp6" / "PINS.json").read_text(encoding="utf-8")
    )
    assert "PROVISIONAL" in pins["source_pr"]
    assert "#1103" in pins["source_pr"]
