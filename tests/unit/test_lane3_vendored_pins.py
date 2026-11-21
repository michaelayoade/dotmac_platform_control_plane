"""The vendored Starter blobs equal their pinned digests, byte for byte (CP-5).

No database, no Foundation: this runs in the ordinary job and fails on the first
edit to a vendored file. A pin is only as strong as the test that reads it, so the
test also refuses a pin file that names a file not on disk, a file on disk that no
pin names, and a pin whose recorded commit is not a full 40-hex SHA.
"""

from __future__ import annotations

import hashlib
import json
import os
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


SOURCE_DIR_ENV = "LANE3_STARTER_SOURCE_DIR"


def _differences(directory: Path, pins: dict[str, object], checkout: Path) -> list[str]:
    """Vendored files that are not, byte for byte, the checkout's `source_path`."""
    wrong: list[str] = []
    files = pins["files"]
    assert isinstance(files, dict)
    for name, entry in files.items():
        source = checkout / entry["source_path"]
        if (
            not source.is_file()
            or source.read_bytes() != (directory / name).read_bytes()
        ):
            wrong.append(name)
    return sorted(wrong)


def test_the_vendored_s1_files_equal_the_pinned_starter_checkout_byte_for_byte() -> (
    None
):
    """The digest pin proves the vendored file is the one that was pinned; this
    proves the pin was TAKEN from the pinned commit. CI points
    `LANE3_STARTER_SOURCE_DIR` at its f50d497e checkout (the same one the suite's
    Foundation comes from); under `LANE3_REQUIRE_FOUNDATION=1` a missing checkout
    FAILS rather than skips."""
    checkout = os.environ.get(SOURCE_DIR_ENV, "").strip()
    if not checkout:
        if os.environ.get("LANE3_REQUIRE_FOUNDATION") == "1":
            pytest.fail(f"{SOURCE_DIR_ENV} is required in the Lane 3 CI step")
        pytest.skip(f"{SOURCE_DIR_ENV} is not set; the Lane 3 CI step runs this")
    directory = VENDORED / "starter_lane3"
    pins = json.loads((directory / "PINS.json").read_text(encoding="utf-8"))
    assert _differences(directory, pins, Path(checkout)) == []


def test_the_checkout_comparison_can_still_fail(tmp_path: Path) -> None:
    """SENSITIVITY: a one-byte difference, and an absent file, are both reported."""
    directory = VENDORED / "starter_lane3"
    pins = json.loads((directory / "PINS.json").read_text(encoding="utf-8"))
    for name, entry in pins["files"].items():
        target = tmp_path / entry["source_path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((directory / name).read_bytes())
    assert _differences(directory, pins, tmp_path) == []
    victim = "lane3_lease_store.py"
    (tmp_path / pins["files"][victim]["source_path"]).write_bytes(
        (directory / victim).read_bytes() + b" "
    )
    (tmp_path / pins["files"]["lane3_e10_receipt.py"]["source_path"]).unlink()
    assert _differences(directory, pins, tmp_path) == [
        "lane3_e10_receipt.py",
        victim,
    ]
