#!/usr/bin/env python3
"""Resolve the exact accepted Foundation candidate into ``.candidate-build``.

The candidate is an Actions artifact in another repository, not a package-index
release.  Every consumer uses this one resolver so CI, the production image
build and a local review cannot silently apply different admission rules.

``GH_TOKEN`` must be a read-only credential able to read Actions artifacts from
the repository named by ``deploy/foundation-candidate.json``.  It is inherited
by ``gh`` and is never placed in argv, output or a generated file.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parents[1]
COORDINATE_FILE: Final = ROOT / "deploy" / "foundation-candidate.json"
DESTINATION: Final = ROOT / ".candidate-build"
EXPECTED_SCHEMA: Final = "FoundationToolCandidate.v1"
EXPECTED_WORKFLOW: Final = ".github/workflows/foundation-candidate.yml"


class CandidateResolutionError(RuntimeError):
    """The candidate coordinate could not be authenticated or resolved."""


def _mapping(value: object, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidateResolutionError(f"{name} is not a JSON object")
    return value


def _exact_text(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value or value != value.strip():
        raise CandidateResolutionError(f"candidate {key} is not exact non-empty text")
    return value


def _positive_int(document: Mapping[str, Any], key: str) -> int:
    value = document.get(key)
    if isinstance(value, bool):
        raise CandidateResolutionError(f"candidate {key} is not a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise CandidateResolutionError(
            f"candidate {key} is not a positive integer"
        ) from error
    if parsed < 1 or str(parsed) != str(value):
        raise CandidateResolutionError(f"candidate {key} is not a positive integer")
    return parsed


@dataclass(frozen=True, slots=True)
class FoundationCandidate:
    repository: str
    source_sha: str
    run_id: int
    artifact_id: int
    artifact_zip_size: int
    wheel_filename: str
    wheel_sha256: str
    wheel_size: int
    expires_at: dt.datetime

    @classmethod
    def load(cls, path: Path = COORDINATE_FILE) -> FoundationCandidate:
        try:
            document = _mapping(
                json.loads(path.read_text(encoding="utf-8")), name=str(path)
            )
        except (OSError, json.JSONDecodeError) as error:
            raise CandidateResolutionError(
                f"candidate coordinate {path} is unreadable"
            ) from error
        if document.get("schema") != EXPECTED_SCHEMA:
            raise CandidateResolutionError("Foundation candidate schema is unknown")
        if (
            document.get("published") is not False
            or document.get("tagged") is not False
        ):
            raise CandidateResolutionError(
                "candidate coordinate is not the unpublished, untagged "
                "bootstrap artifact"
            )
        source_sha = _exact_text(document, "source_sha")
        if len(source_sha) != 40 or any(
            ch not in "0123456789abcdef" for ch in source_sha
        ):
            raise CandidateResolutionError(
                "candidate source_sha is not 40 lowercase hex"
            )
        wheel_sha256 = _exact_text(document, "wheel_sha256")
        if len(wheel_sha256) != 64 or any(
            ch not in "0123456789abcdef" for ch in wheel_sha256
        ):
            raise CandidateResolutionError(
                "candidate wheel_sha256 is not 64 lowercase hex"
            )
        expires_text = _exact_text(document, "expires_at")
        try:
            expires_at = dt.datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
        except ValueError as error:
            raise CandidateResolutionError(
                "candidate expires_at is not ISO-8601"
            ) from error
        if expires_at.tzinfo is None:
            raise CandidateResolutionError("candidate expires_at has no timezone")
        return cls(
            repository=_exact_text(document, "source_repository"),
            source_sha=source_sha,
            run_id=_positive_int(document, "run_id"),
            artifact_id=_positive_int(document, "artifact_id"),
            artifact_zip_size=_positive_int(document, "artifact_zip_size_bytes"),
            wheel_filename=_exact_text(document, "wheel_filename"),
            wheel_sha256=wheel_sha256,
            wheel_size=_positive_int(document, "wheel_size_bytes"),
            expires_at=expires_at,
        )


def validate_artifact_metadata(
    candidate: FoundationCandidate,
    value: object,
    *,
    now: dt.datetime | None = None,
) -> None:
    document = _mapping(value, name="artifact metadata")
    workflow = _mapping(document.get("workflow_run"), name="artifact workflow_run")
    observed_now = dt.datetime.now(dt.UTC) if now is None else now
    if observed_now.tzinfo is None:
        raise CandidateResolutionError("validation clock has no timezone")
    expected = {
        "artifact id": (document.get("id"), candidate.artifact_id),
        "artifact size": (document.get("size_in_bytes"), candidate.artifact_zip_size),
        "run id": (workflow.get("id"), candidate.run_id),
        "source revision": (workflow.get("head_sha"), candidate.source_sha),
    }
    mismatches = [
        name for name, (actual, wanted) in expected.items() if actual != wanted
    ]
    if mismatches:
        raise CandidateResolutionError(
            "artifact metadata differs on " + ", ".join(mismatches)
        )
    if document.get("expired") is not False:
        raise CandidateResolutionError("Foundation candidate artifact is expired")
    if document.get("expires_at") != candidate.expires_at.isoformat().replace(
        "+00:00", "Z"
    ):
        raise CandidateResolutionError("artifact expiry differs from the coordinate")
    if observed_now >= candidate.expires_at:
        raise CandidateResolutionError("Foundation candidate lease has expired")
    if workflow.get("repository_id") != workflow.get("head_repository_id"):
        raise CandidateResolutionError("artifact run was built from a fork")


def validate_run_metadata(candidate: FoundationCandidate, value: object) -> None:
    document = _mapping(value, name="run metadata")
    repository = _mapping(document.get("repository"), name="run repository")
    head_repository = _mapping(
        document.get("head_repository"), name="run head_repository"
    )
    expected = {
        "run id": (document.get("id"), candidate.run_id),
        "source revision": (document.get("head_sha"), candidate.source_sha),
        "source branch": (document.get("head_branch"), "main"),
        "workflow": (document.get("path"), EXPECTED_WORKFLOW),
        "repository": (repository.get("full_name"), candidate.repository),
    }
    mismatches = [
        name for name, (actual, wanted) in expected.items() if actual != wanted
    ]
    if mismatches:
        raise CandidateResolutionError(
            "run metadata differs on " + ", ".join(mismatches)
        )
    if document.get("status") != "completed" or document.get("conclusion") != "success":
        raise CandidateResolutionError("candidate run did not complete successfully")
    if repository.get("id") != head_repository.get("id"):
        raise CandidateResolutionError("candidate run was built from a fork")


def extract_and_verify_wheel(
    candidate: FoundationCandidate, archive: Path, destination: Path
) -> None:
    try:
        with zipfile.ZipFile(archive) as bundle:
            matching = [
                member
                for member in bundle.infolist()
                if Path(member.filename).name == candidate.wheel_filename
                and not member.is_dir()
            ]
            if len(matching) != 1:
                raise CandidateResolutionError(
                    f"artifact contains {len(matching)} candidates named "
                    f"{candidate.wheel_filename!r}"
                )
            member = matching[0]
            if member.file_size != candidate.wheel_size:
                raise CandidateResolutionError(
                    "Foundation wheel size differs from the coordinate"
                )
            digest = hashlib.sha256()
            with bundle.open(member) as source, destination.open("xb") as target:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    target.write(chunk)
    except (OSError, zipfile.BadZipFile) as error:
        raise CandidateResolutionError(
            "candidate artifact is not a readable zip"
        ) from error
    if digest.hexdigest() != candidate.wheel_sha256:
        destination.unlink(missing_ok=True)
        raise CandidateResolutionError(
            "Foundation wheel digest differs from the accepted coordinate"
        )


def _gh_json(endpoint: str) -> object:
    executable = shutil.which("gh")
    if executable is None:
        raise CandidateResolutionError("the gh CLI is unavailable")
    result = subprocess.run(  # noqa: S603 - absolute gh path; typed endpoint
        [executable, "api", endpoint],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise CandidateResolutionError(
            f"GitHub refused candidate metadata at {endpoint!r} "
            f"(exit {result.returncode})"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CandidateResolutionError("GitHub returned non-JSON metadata") from error


def _gh_download(endpoint: str, destination: Path) -> None:
    executable = shutil.which("gh")
    if executable is None:
        raise CandidateResolutionError("the gh CLI is unavailable")
    with destination.open("xb") as output:
        result = subprocess.run(  # noqa: S603 - absolute gh path; typed endpoint
            [executable, "api", endpoint],
            check=False,
            stdout=output,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        destination.unlink(missing_ok=True)
        raise CandidateResolutionError(
            f"GitHub refused the candidate artifact (exit {result.returncode})"
        )


def stage() -> Path:
    if not os.environ.get("GH_TOKEN"):
        raise CandidateResolutionError(
            "GH_TOKEN must be a read-only Actions credential for the Starter repository"
        )
    if DESTINATION.exists() or DESTINATION.is_symlink():
        raise CandidateResolutionError(
            f"{DESTINATION.relative_to(ROOT)} already exists; refusing to replace it"
        )
    candidate = FoundationCandidate.load()
    artifact = _gh_json(
        f"/repos/{candidate.repository}/actions/artifacts/{candidate.artifact_id}"
    )
    validate_artifact_metadata(candidate, artifact)
    run = _gh_json(f"/repos/{candidate.repository}/actions/runs/{candidate.run_id}")
    validate_run_metadata(candidate, run)

    temporary = Path(tempfile.mkdtemp(prefix=".candidate-build.", dir=ROOT))
    try:
        archive = temporary / "artifact.zip"
        _gh_download(
            f"/repos/{candidate.repository}/actions/artifacts/"
            f"{candidate.artifact_id}/zip",
            archive,
        )
        wheel = temporary / candidate.wheel_filename
        extract_and_verify_wheel(candidate, archive, wheel)
        archive.unlink()
        temporary.replace(DESTINATION)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return DESTINATION / candidate.wheel_filename


def main() -> int:
    try:
        wheel = stage()
    except CandidateResolutionError as error:
        print(f"Foundation candidate refused: {error}", file=os.sys.stderr)
        return 1
    print(f"staged {wheel.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
