"""No network: a pinned executable fixture supplies upstream artifacts."""

import hashlib
import json
import sys
from pathlib import Path

import pytest
from conformance_data import desired
from dotmac_kernel import ProductManifestSnapshot

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent.candidates import (
    REPO,
    WORKFLOW,
    GitHubCandidateEvidenceReader,
)


@pytest.fixture
def candidate(tmp_path):
    doc = desired()
    manifest = ProductManifestSnapshot(
        product_code="dotmac_sub", product_version="fixture", capability_codes=()
    )
    doc["product_manifest_digest"] = manifest.digest
    doc["plan_digest"] = c.plan_digest(doc)
    (tmp_path / "product-manifest.json").write_bytes(manifest.to_json_bytes())
    evidence = {
        key: doc[key]
        for key in (
            "source_revision",
            "source_tree",
            "image_digest",
            "product_manifest_digest",
            "build_run_id",
            "evidence_run_id",
        )
    }
    evidence.update(
        schema_version=3,
        kind="dotmac.release_candidate",
        source_ci_conclusion="success",
    )
    (tmp_path / "candidate.json").write_text(json.dumps(evidence))
    run = {
        "path": WORKFLOW,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": doc["source_revision"],
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
    }
    (tmp_path / "run.json").write_text(json.dumps(run))
    executable = tmp_path / "fixture-gh"
    executable.write_text(f"""#!{sys.executable}
import json, pathlib, shutil, sys
root = pathlib.Path(__file__).parent
if sys.argv[1] == "api":
    assert sys.argv[2:4] == ["--hostname", "github.com"]
    value = json.loads((root / "run.json").read_text())
    value["id"] = int(sys.argv[-1].rsplit("/", 1)[1])
    print(json.dumps(value))
else:
    repo_argument = sys.argv.index("--repo") + 1
    assert sys.argv[repo_argument] == "github.com/michaelayoade/dotmac_sub"
    destination = pathlib.Path(sys.argv[sys.argv.index("--dir") + 1])
    for name in ("candidate.json", "product-manifest.json"):
        shutil.copyfile(root / name, destination / name)
""")
    executable.chmod(0o700)
    digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
    return GitHubCandidateEvidenceReader(str(executable), digest), doc, tmp_path


def test_trusted_fixture(candidate):
    reader, doc, _ = candidate
    reader.verify(doc)


@pytest.mark.parametrize(
    "field",
    [
        "source_tree",
        "product_manifest_digest",
        "build_run_id",
        "evidence_run_id",
        "image_digest",
        "source_revision",
    ],
)
def test_caller_cannot_swap_candidate_facts(candidate, field):
    reader, doc, _ = candidate
    original = doc[field]
    doc[field] = (
        original + 10
        if type(original) is int
        else ("sha256:" + "9" * 64 if field.endswith("digest") else "9" * 40)
    )
    doc["plan_digest"] = c.plan_digest(doc)
    with pytest.raises(c.ContractError):
        reader.verify(doc)


@pytest.mark.parametrize(
    "field,value",
    [
        ("conclusion", "failure"),
        ("head_branch", "feature"),
        ("path", ".github/workflows/other.yml"),
        ("event", "pull_request"),
        ("head_repository", {"full_name": "foreign/fork"}),
    ],
)
def test_run_identity_refusals(candidate, field, value):
    reader, doc, root = candidate
    run_path = root / "run.json"
    run = json.loads(run_path.read_bytes())
    run[field] = value
    run_path.write_text(json.dumps(run))
    with pytest.raises(c.ContractError, match="candidate_run_mismatch"):
        reader.verify(doc)


def test_manifest_exact_bytes_and_reader_unavailable(candidate):
    reader, doc, root = candidate
    path = root / "product-manifest.json"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(c.ContractError, match="candidate_artifact_mismatch"):
        reader.verify(doc)
    Path(reader.executable).unlink()
    with pytest.raises(c.ContractError, match="candidate_reader_unavailable"):
        reader.verify(doc)
