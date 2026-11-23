"""The vendored Foundation verifier equals its pinned digests, byte for byte (H1).

PROVISIONAL-PENDING-E5: the pin names Starter's Foundation src tree
940cdf344b49d1b2bce16383978a7ee9ebc21460 at commit e4f9a072, which E5 has not yet
certified. No database and no Foundation: this runs in the ordinary job.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "vendor_cp" / "vendored_foundation"
PINS = json.loads((PACKAGE / "PINS.json").read_text(encoding="utf-8"))
TREE = "940cdf344b49d1b2bce16383978a7ee9ebc21460"
COMMIT = "e4f9a072684291ef15dab04cd99ebd6d4ce60762"
# The files the step-8 closure needs: `AttestationEnvelopeV2` / `SpecError` /
# `attestation_envelope_digest` live in these three, and these import only
# each other (relative imports) and the standard library.
CLOSURE = {"errors.py", "digest.py", "trusted_host_source.py"}


def test_the_pin_records_the_provisional_e5_source() -> None:
    assert PINS["status"] == "PROVISIONAL-PENDING-E5"
    assert PINS["source_repository"] == "michaelayoade/dotmac_starter_mt"
    assert PINS["source_commit"] == COMMIT
    assert PINS["foundation_src_tree"] == TREE
    assert re.fullmatch(r"[0-9a-f]{40}", PINS["source_commit"])
    assert re.fullmatch(r"[0-9a-f]{40}", PINS["foundation_src_tree"])


def test_exactly_the_closure_is_vendored_and_every_file_is_pinned() -> None:
    assert set(PINS["files"]) == CLOSURE
    on_disk = {p.name for p in PACKAGE.glob("*.py")} - {"__init__.py"}
    assert on_disk == CLOSURE, "a vendored file has no pin, or a pin has no file"
    # nothing nested, and no stray module a pin does not name
    assert not [p for p in PACKAGE.rglob("*") if p.is_dir() and p.name != "__pycache__"]


@pytest.mark.parametrize("name", sorted(CLOSURE))
def test_every_vendored_file_equals_its_pinned_digests(name: str) -> None:
    entry = PINS["files"][name]
    data = (PACKAGE / name).read_bytes()
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert hashlib.sha256(data).hexdigest() == entry["sha256"], f"{name} drifted"
    blob = hashlib.sha1(  # noqa: S324 - a git object id, not a security digest
        b"blob %d\0" % len(data) + data
    ).hexdigest()
    assert blob == entry["git_blob"], f"{name} is not the pinned git blob"
    assert entry["source_path"] == f"{PINS['source_root']}/{name}"


def test_the_pin_check_can_still_fail() -> None:
    """SENSITIVITY: a one-byte edit changes both digests the pin records."""
    data = (PACKAGE / "errors.py").read_bytes()
    assert (
        hashlib.sha256(data + b" ").hexdigest() != PINS["files"]["errors.py"]["sha256"]
    )


def test_the_closure_imports_only_itself_and_the_standard_library() -> None:
    """Foundation's other modules are NOT reachable from the vendored closure."""
    for name in CLOSURE:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                assert node.module in {"digest", "errors"}, (name, node.module)
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {
                    "dotmac_deployment_foundation",
                    "dotmac_kernel",
                }, (name, node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("dotmac"), (name, alias.name)


def test_step_eight_does_not_import_the_foundation_distribution() -> None:
    """The image carries no `dotmac_deployment_foundation` (acceptance step 17)."""
    source = (ROOT / "src/vendor_cp/deployment/lane3_e10.py").read_text("utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("dotmac_deployment_foundation")
        elif isinstance(node, ast.Import):
            assert not any(
                a.name.startswith("dotmac_deployment_foundation") for a in node.names
            )
    assert "vendor_cp.vendored_foundation.trusted_host_source" in source


def test_the_vendored_files_equal_the_pinned_starter_checkout() -> None:
    """In the hosted differential job: bytes equal the pinned Starter checkout and
    the checkout's Foundation src tree is the pinned one. Absent elsewhere."""
    value = os.environ.get("VENDORED_FOUNDATION_SOURCE_DIR")
    if not value:
        if os.environ.get("VENDORED_FOUNDATION_REQUIRED") == "1":
            pytest.fail("VENDORED_FOUNDATION_SOURCE_DIR is required in this job")
        pytest.skip("the hosted differential job runs this against the checkout")
    checkout = Path(value)
    head = subprocess.run(  # noqa: S603
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert head == COMMIT
    tree = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(checkout),
            "rev-parse",
            "HEAD:packages/dotmac-deployment-foundation/src",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert tree == TREE
    for name, entry in PINS["files"].items():
        assert (checkout / entry["source_path"]).read_bytes() == (
            PACKAGE / name
        ).read_bytes(), name
