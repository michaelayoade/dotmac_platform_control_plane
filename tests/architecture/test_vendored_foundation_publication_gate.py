"""Publication refuses a provisional vendored pin; PR-head builds do not (M1)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / ".github" / "candidate" / "require_certified_vendored_pins.py"
PINS = ROOT / "src" / "vendor_cp" / "vendored_foundation" / "PINS.json"
DIGEST = "sha256:" + "a" * 64


def _run(tmp_path: Path, document: object) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "PINS.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(  # noqa: S603
        [sys.executable, str(GATE), str(path)], capture_output=True, text=True
    )


def test_the_committed_pin_is_provisional_so_publication_refuses_today() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GATE), str(PINS)], capture_output=True, text=True
    )
    assert json.loads(PINS.read_text("utf-8"))["status"] == "PROVISIONAL-PENDING-E5"
    assert result.returncode == 1
    assert "not 'CERTIFIED'" in result.stderr


def test_a_certified_pin_with_an_e5_record_digest_is_admitted(tmp_path: Path) -> None:
    result = _run(tmp_path, {"status": "CERTIFIED", "e5_record_digest": DIGEST})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "document",
    [
        {"status": "PROVISIONAL-PENDING-E5", "e5_record_digest": DIGEST},
        {"status": "CERTIFIED"},
        {"status": "CERTIFIED", "e5_record_digest": "sha256:" + "A" * 64},
        {"status": "CERTIFIED", "e5_record_digest": "sha256:abc"},
        {"status": "CERTIFIED", "e5_record_digest": 7},
        {"status": "certified", "e5_record_digest": DIGEST},
        {},
        [],
    ],
)
def test_anything_short_of_certified_with_a_digest_is_refused(
    tmp_path: Path, document: object
) -> None:
    assert _run(tmp_path, document).returncode == 1


def test_an_unreadable_pin_file_is_refused(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GATE), str(tmp_path / "absent.json")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2


def test_the_gate_runs_on_the_publication_path_and_not_in_ordinary_ci() -> None:
    publication = (ROOT / ".github/workflows/production-image.yml").read_text("utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    assert "require_certified_vendored_pins.py" in publication
    # before the image is built, so a refused pin publishes nothing
    assert publication.index("require_certified_vendored_pins.py") < publication.index(
        "docker buildx build"
    )
    # the PR-head image build (dry run 2) and the ordinary CI image job stay open
    assert "require_certified_vendored_pins.py" not in ci
