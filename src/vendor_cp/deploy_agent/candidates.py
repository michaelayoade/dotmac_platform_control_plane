"""Trusted Sub workflow artifact reader; gh owns authentication and transport."""

import hashlib
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol, cast

from dotmac_kernel import ProductManifestSnapshot

from . import contracts as c

REPO = "michaelayoade/dotmac_sub"
WORKFLOW = ".github/workflows/release-candidate.yml"
FIELDS = (
    "source_revision source_tree image_digest product_manifest_digest "
    "build_run_id evidence_run_id"
).split()


class CandidateEvidenceReader(Protocol):
    def verify(self, desired: c.DesiredState) -> None: ...


class GitHubCandidateEvidenceReader:
    def __init__(self, executable: str, executable_digest: str) -> None:
        path = Path(executable)
        c.sha(executable_digest)
        c.require(path.is_absolute() and path.is_file(), "candidate_reader_unavailable")
        c.require(
            "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            == executable_digest,
            "candidate_reader_unavailable",
        )
        self.executable = str(path)

    def _run(self, *args: str) -> bytes:
        try:
            result = subprocess.run(  # noqa: S603 - pinned executable, typed fixed argv
                [self.executable, *args], capture_output=True, timeout=120
            )
        except (OSError, subprocess.TimeoutExpired):
            raise c.ContractError("candidate_reader_unavailable") from None
        c.require(result.returncode == 0, "candidate_reader_unavailable")
        return result.stdout

    def verify(self, desired: c.DesiredState) -> None:
        try:
            for run_id in {desired["evidence_run_id"], desired["build_run_id"]}:
                run = c.read_json(
                    self._run(
                        "api",
                        "--hostname",
                        "github.com",
                        f"repos/{REPO}/actions/runs/{run_id}",
                    )
                )
                repository, head_repository = (
                    run.get("repository"),
                    run.get("head_repository"),
                )
                c.require(
                    isinstance(repository, dict)
                    and repository.get("full_name") == REPO
                    and isinstance(head_repository, dict)
                    and head_repository.get("full_name") == REPO,
                    "candidate_run_mismatch",
                )
                expected = {
                    "id": run_id,
                    "path": WORKFLOW,
                    "event": "workflow_dispatch",
                    "head_branch": "main",
                    "head_sha": desired["source_revision"],
                    "status": "completed",
                    "conclusion": "success",
                }
                c.require(
                    all(run.get(key) == value for key, value in expected.items()),
                    "candidate_run_mismatch",
                )
            with TemporaryDirectory(prefix="deploy-candidate-") as directory:
                self._run(
                    "run",
                    "download",
                    str(desired["evidence_run_id"]),
                    "--repo",
                    "github.com/" + REPO,
                    "--name",
                    "release-candidate-evidence",
                    "--dir",
                    directory,
                )
                root = Path(directory)
                c.require(
                    {p.name for p in root.iterdir()}
                    == {"candidate.json", "product-manifest.json"},
                    "candidate_artifact_mismatch",
                )
                c.require(
                    all(p.is_file() and not p.is_symlink() for p in root.iterdir()),
                    "candidate_artifact_mismatch",
                )
                evidence = c.read_json((root / "candidate.json").read_bytes())
                c.exact(
                    evidence,
                    {"schema_version", "kind", "source_ci_conclusion", *FIELDS},
                )
                c.require(
                    type(evidence["schema_version"]) is int
                    and evidence["schema_version"] == 3
                    and evidence["kind"] == "dotmac.release_candidate"
                    and evidence["source_ci_conclusion"] == "success",
                    "candidate_artifact_mismatch",
                )
                c.require(
                    all(
                        evidence[field] == cast(c.Json, c.plan_document(desired))[field]
                        for field in FIELDS
                    ),
                    "candidate_artifact_mismatch",
                )
                ProductManifestSnapshot.from_json_bytes(
                    (root / "product-manifest.json").read_bytes(),
                    expected_digest=desired["product_manifest_digest"],
                )
        except c.ContractError:
            raise
        except (OSError, ValueError):
            raise c.ContractError("candidate_artifact_mismatch") from None
