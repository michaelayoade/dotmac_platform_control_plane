"""The sibling composition cannot grow a rollout or eager successor import."""

from __future__ import annotations

import ast
import json
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The conformance lane lives outside the installed application package, and
# hosted CI does not put the repository root on sys.path. Load it explicitly and
# restore sys.path, as the rehearsal-issuer harness boundary test does.
sys.path.insert(0, str(ROOT))
try:
    from protected_issuer_conformance import check  # noqa: E402
finally:
    sys.path.remove(str(ROOT))
SOURCE = ROOT / "src/vendor_cp/deployment/protected_rehearsal_issuer.py"


def test_successor_imports_are_lazy_and_no_rollout_path_exists() -> None:
    tree = ast.parse(SOURCE.read_text())
    imported_names = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom | ast.Import):
            names = (
                [node.module]
                if isinstance(node, ast.ImportFrom)
                else [alias.name for alias in node.names]
            )
            assert not any(
                name
                and name.startswith(("dotmac_deployment_control", "dotmac_approvals"))
                for name in names
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Attribute):
            imported_names.add(node.attr)
    assert "request_rollout" not in imported_names
    assert "dispatch_attempt" not in imported_names


def test_successor_lane_uses_private_index_and_checked_in_evidence() -> None:
    workflow = (ROOT / ".github/workflows/protected-issuer-successors.yml").read_text()
    assert "--evidence-only" in workflow
    assert "--verify-publications" in workflow
    assert "--requirements" in workflow
    assert "--wheel-dir" in workflow
    assert "--isolated download" in workflow
    assert (
        "--index-url https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
        in workflow
    )
    assert "--extra-index-url" not in workflow
    assert "inputs.control_sha256" not in workflow
    assert "inputs.approvals_sha256" not in workflow
    for source in (workflow, check.EVIDENCE.with_name("check.py").read_text()):
        assert "0.1.0a15" not in source
        assert "0.1.0a7" not in source
    # Both producers have published (Control 0.1.0a15, record #68; Approvals
    # 0.1.0a7, record #756), so the manifest carries complete immutable
    # coordinates and the lane's evidence step accepts it. Since CP #204 the
    # application pins the SAME versions, so the lane verifies the exact bytes
    # the assembly composes; the two may not drift apart.
    manifest = json.loads(check.EVIDENCE.read_text())
    for item in manifest["artifacts"].values():
        for field in ("record_commit", "tag_object", "source_commit"):
            assert isinstance(item[field], str) and len(item[field]) == 40, field
        assert isinstance(item["sha256"], str) and len(item["sha256"]) == 64
        assert item["tag"].endswith(f"-v{item['version']}")
    assert set(check._release_evidence()) == set(manifest["artifacts"])
    pins = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["poetry"][
        "dependencies"
    ]
    for distribution, item in manifest["artifacts"].items():
        assert pins[distribution]["version"] == item["version"], distribution


def _complete_manifest() -> dict[str, object]:
    manifest = json.loads(check.EVIDENCE.read_text())
    for distribution, item in manifest["artifacts"].items():
        item["record_commit"] = "1" * 40
        item["tag"] = f"{distribution}-v{item['version']}"
        item["tag_object"] = "2" * 40
        item["source_commit"] = "3" * 40
        item["sha256"] = "4" * 64
    return manifest


def test_release_evidence_schema_accepts_only_complete_producer_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "release-evidence.json"
    path.write_text(json.dumps(_complete_manifest()))
    monkeypatch.setattr(check, "EVIDENCE", path)
    assert set(check._release_evidence()) == set(check.PRODUCERS)
    manifest = _complete_manifest()
    manifest["artifacts"]["dotmac-approvals"]["repository"] = "other/repo"
    path.write_text(json.dumps(manifest))
    with pytest.raises(SystemExit, match="unexpected producing repository"):
        check._release_evidence()


@pytest.mark.parametrize(
    "field",
    ["version", "tag", "tag_object", "peeled_commit", "status", "pinnable"],
)
def test_producer_record_must_bind_all_release_coordinates(field: str) -> None:
    item = _complete_manifest()["artifacts"]["dotmac-deployment-control"]
    filename = check._wheel_name("dotmac-deployment-control", item["version"])
    row = {
        "version": item["version"],
        "tag": item["tag"],
        "tag_object": item["tag_object"],
        "peeled_commit": item["source_commit"],
        "status": "released",
        "pinnable": True,
        "sha256": {filename: item["sha256"]},
    }
    check._publication_row(
        "dotmac-deployment-control", item, {"releases": [row]}, filename
    )
    row[field] = "wrong"
    with pytest.raises(SystemExit):
        check._publication_row(
            "dotmac-deployment-control", item, {"releases": [row]}, filename
        )


def test_approvals_record_requires_distribution_schema_and_wheel_hash() -> None:
    item = _complete_manifest()["artifacts"]["dotmac-approvals"]
    filename = check._wheel_name("dotmac-approvals", item["version"])
    row = {
        "distribution": "dotmac-approvals",
        "version": item["version"],
        "tag": item["tag"],
        "tag_object": item["tag_object"],
        "peeled_commit": item["source_commit"],
        "status": "released",
        "pinnable": True,
        "sha256": {filename: item["sha256"]},
    }
    document = {"schema": "ModuleReleaseVerifications.v1", "releases": [row]}
    check._publication_row("dotmac-approvals", item, document, filename)
    row["sha256"][filename] = "0" * 64
    with pytest.raises(SystemExit, match="wheel SHA-256"):
        check._publication_row("dotmac-approvals", item, document, filename)
