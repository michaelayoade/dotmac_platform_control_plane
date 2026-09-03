from __future__ import annotations

import datetime as dt
import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from stage_foundation_candidate import (  # noqa: E402
    CandidateResolutionError,
    FoundationCandidate,
    extract_and_verify_wheel,
    validate_artifact_metadata,
    validate_run_metadata,
)


def _candidate() -> FoundationCandidate:
    return FoundationCandidate(
        repository="michaelayoade/dotmac_starter_mt",
        source_sha="a" * 40,
        run_id=123,
        artifact_id=456,
        artifact_zip_size=789,
        wheel_filename="foundation.whl",
        wheel_sha256=hashlib.sha256(b"wheel-bytes").hexdigest(),
        wheel_size=len(b"wheel-bytes"),
        expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.UTC),
    )


def _artifact() -> dict[str, object]:
    return {
        "id": 456,
        "expired": False,
        "expires_at": "2030-01-01T00:00:00Z",
        "size_in_bytes": 789,
        "workflow_run": {
            "id": 123,
            "head_sha": "a" * 40,
            "repository_id": 99,
            "head_repository_id": 99,
        },
    }


def _run() -> dict[str, object]:
    return {
        "id": 123,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "a" * 40,
        "head_branch": "main",
        "path": ".github/workflows/foundation-candidate.yml",
        "repository": {
            "id": 99,
            "full_name": "michaelayoade/dotmac_starter_mt",
        },
        "head_repository": {"id": 99},
    }


def test_real_coordinate_parses_and_remains_leased() -> None:
    candidate = FoundationCandidate.load()
    assert candidate.artifact_id == 9903418260
    assert candidate.wheel_sha256 == (
        "17b3464ede04a182958753b493d08c5f06e2b5643960c113ecf6584d4ed56e1b"
    )
    assert candidate.expires_at > dt.datetime.now(dt.UTC)


def test_metadata_admits_only_the_bound_successful_main_run() -> None:
    candidate = _candidate()
    validate_artifact_metadata(
        candidate,
        _artifact(),
        now=dt.datetime(2029, 1, 1, tzinfo=dt.UTC),
    )
    validate_run_metadata(candidate, _run())

    forked = _run()
    forked["head_repository"] = {"id": 100}
    with pytest.raises(CandidateResolutionError, match="fork"):
        validate_run_metadata(candidate, forked)

    wrong_workflow = _run()
    wrong_workflow["path"] = ".github/workflows/release-facility.yml"
    with pytest.raises(CandidateResolutionError, match="workflow"):
        validate_run_metadata(candidate, wrong_workflow)


def test_expired_or_rebound_artifact_is_refused() -> None:
    candidate = _candidate()
    with pytest.raises(CandidateResolutionError, match="lease has expired"):
        validate_artifact_metadata(
            candidate,
            _artifact(),
            now=dt.datetime(2031, 1, 1, tzinfo=dt.UTC),
        )

    rebound = _artifact()
    rebound["workflow_run"] = {
        **rebound["workflow_run"],  # type: ignore[arg-type]
        "head_sha": "b" * 40,
    }
    with pytest.raises(CandidateResolutionError, match="source revision"):
        validate_artifact_metadata(
            candidate,
            rebound,
            now=dt.datetime(2029, 1, 1, tzinfo=dt.UTC),
        )


def test_wheel_bytes_are_selected_by_exact_name_and_digest(tmp_path: Path) -> None:
    candidate = _candidate()
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("package/foundation.whl", b"wheel-bytes")
        bundle.writestr("receipt/candidate-receipt.json", b"{}")
    output = tmp_path / "foundation.whl"
    extract_and_verify_wheel(candidate, archive, output)
    assert output.read_bytes() == b"wheel-bytes"

    duplicate = tmp_path / "duplicate.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("one/foundation.whl", b"wheel-bytes")
        bundle.writestr("two/foundation.whl", b"wheel-bytes")
    duplicate.write_bytes(buffer.getvalue())
    with pytest.raises(CandidateResolutionError, match="2 candidates"):
        extract_and_verify_wheel(candidate, duplicate, tmp_path / "duplicate.whl")


def test_a_one_byte_wheel_change_is_refused(tmp_path: Path) -> None:
    candidate = _candidate()
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("foundation.whl", b"wheel-byteS")
    output = tmp_path / "foundation.whl"
    with pytest.raises(CandidateResolutionError, match="digest differs"):
        extract_and_verify_wheel(candidate, archive, output)
    assert not output.exists()
