"""Fail-closed checks for the future isolated successor-wheel lane."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import inspect
import json
import re
import subprocess
import sysconfig
import tempfile
import zipfile
from pathlib import Path

PRODUCERS = {
    "dotmac-deployment-control": (
        "michaelayoade/dotmac_deployment_control",
        "docs/published-versions.json",
    ),
    "dotmac-approvals": (
        "michaelayoade/dotmac_starter_mt",
        "docs/inventories/module-release-verifications.json",
    ),
}
EVIDENCE = Path(__file__).with_name("release-evidence.json")
KERNEL_LOCK = (
    Path(__file__).resolve().parents[1] / "rehearsal_issuer_harness/artifacts.json"
)


def _die(message: str) -> None:
    raise SystemExit(f"protected issuer conformance: {message}")


def _release_evidence() -> dict[str, dict[str, str]]:
    try:
        document = json.loads(EVIDENCE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _die(f"cannot read checked-in release evidence: {exc}")
    if not isinstance(document, dict) or set(document) != {"artifacts"}:
        _die("release evidence must contain only the artifacts map")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != set(PRODUCERS):
        _die("release evidence must name exactly the two successor distributions")
    for distribution, (repository, record_path) in PRODUCERS.items():
        item = artifacts[distribution]
        if not isinstance(item, dict) or set(item) != {
            "repository",
            "record_path",
            "version",
            "record_commit",
            "tag",
            "tag_object",
            "source_commit",
            "sha256",
        }:
            _die(f"{distribution} release evidence has unexpected fields")
        if item["repository"] != repository or item["record_path"] != record_path:
            _die(f"{distribution} names an unexpected producing repository or record")
        version = item["version"]
        if not isinstance(version, str) or not re.fullmatch(
            r"0\.1\.0a[1-9][0-9]*", version
        ):
            _die(f"{distribution} requires a valid immutable release version")
        if item["tag"] != f"{distribution}-v{version}":
            _die(f"{distribution} tag does not bind its release version")
        for field in ("record_commit", "tag_object", "source_commit"):
            if not isinstance(item[field], str) or not re.fullmatch(
                r"[0-9a-f]{40}", item[field]
            ):
                _die(f"{distribution} requires its immutable {field}")
        if not isinstance(item["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", item["sha256"]
        ):
            _die(f"{distribution} requires its real wheel SHA-256")
    return artifacts


def _wheel(path: Path, distribution: str, version: str, expected_hash: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        _die(f"{distribution} requires its real 64-character wheel SHA-256")
    if not path.is_file() or path.suffix != ".whl":
        _die(f"{distribution} wheel path is absent or not a wheel: {path}")
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        _die(f"{distribution} wheel SHA-256 does not match release evidence")
    expected_name = distribution.replace("-", "_") + "-" + version
    if not path.name.startswith(expected_name + "-"):
        _die(f"{distribution} wheel filename does not name {version}")
    with zipfile.ZipFile(path) as archive:
        names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(names) != 1:
            _die(f"{distribution} wheel has no unique METADATA")
        content = archive.read(names[0]).decode("utf-8")
    if f"Name: {distribution}\n" not in content or (
        f"Version: {version}\n" not in content
    ):
        _die(f"{distribution} wheel METADATA differs from expected name/version")


def _wheel_path(directory: Path, distribution: str, version: str) -> Path:
    prefix = f"{distribution.replace('-', '_')}-{version}-"
    matches = sorted(directory.glob(f"{prefix}*.whl"))
    if len(matches) != 1:
        _die(f"{distribution} requires exactly one downloaded wheel for {version}")
    return matches[0]


def _kernel_artifact() -> dict[str, str]:
    try:
        item = json.loads(KERNEL_LOCK.read_text())["artifacts"]["dotmac-kernel"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        _die(f"cannot read existing kernel artifact lock: {exc}")
    if not isinstance(item, dict) or not all(
        isinstance(item.get(field), str) for field in ("version", "sha256", "filename")
    ):
        _die("existing kernel artifact lock is incomplete")
    return item


def _publication_row(
    distribution: str, item: dict[str, str], document: object, filename: str
) -> None:
    if not isinstance(document, dict) or not isinstance(document.get("releases"), list):
        _die(f"{distribution} producing publication record has no releases")
    if distribution == "dotmac-approvals" and document.get("schema") != (
        "ModuleReleaseVerifications.v1"
    ):
        _die("Approvals needs a checked-in ModuleReleaseVerifications.v1 record")
    matches = [
        row
        for row in document["releases"]
        if isinstance(row, dict)
        and row.get("version") == item["version"]
        and (
            distribution == "dotmac-deployment-control"
            or row.get("distribution") == distribution
        )
    ]
    if len(matches) != 1:
        _die(f"{distribution} has no unique producing publication row")
    row = matches[0]
    required = {
        "version": item["version"],
        "tag": item["tag"],
        "tag_object": item["tag_object"],
        "peeled_commit": item["source_commit"],
        "status": "released",
        "pinnable": True,
    }
    for field, expected in required.items():
        if row.get(field) != expected:
            _die(f"{distribution} publication row differs on {field}")
    wheel_hashes = row.get("sha256")
    if (
        not isinstance(wheel_hashes, dict)
        or wheel_hashes.get(filename) != item["sha256"]
    ):
        _die(f"{distribution} publication row differs on wheel SHA-256")


def _git(directory: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed git executable; validated refs
        ["/usr/bin/git", "-C", str(directory), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        _die(f"producing git evidence failed: git {' '.join(args)}")
    return result.stdout.strip()


def _verify_publications(evidence: dict[str, dict[str, str]]) -> None:
    """Fetch exact producer records and tag objects; never trust copied SHAs alone."""
    for distribution, item in evidence.items():
        with tempfile.TemporaryDirectory(prefix="issuer-publication-") as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(
                repo,
                "remote",
                "add",
                "origin",
                f"https://github.com/{item['repository']}.git",
            )
            _git(
                repo,
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "origin",
                "refs/heads/main:refs/remotes/origin/main",
            )
            _git(
                repo,
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "origin",
                f"refs/tags/{item['tag']}:refs/tags/{item['tag']}",
            )
            _git(repo, "cat-file", "-e", f"{item['record_commit']}^{{commit}}")
            _git(
                repo,
                "merge-base",
                "--is-ancestor",
                item["record_commit"],
                "refs/remotes/origin/main",
            )
            if _git(repo, "cat-file", "-t", f"refs/tags/{item['tag']}") != "tag":
                _die(f"{distribution} release tag is not annotated")
            if (
                _git(repo, "rev-parse", f"refs/tags/{item['tag']}")
                != item["tag_object"]
            ):
                _die(f"{distribution} tag object differs from release evidence")
            if (
                _git(repo, "rev-parse", f"refs/tags/{item['tag']}^{{commit}}")
                != item["source_commit"]
            ):
                _die(f"{distribution} peeled tag differs from release evidence")
            _git(
                repo,
                "merge-base",
                "--is-ancestor",
                item["source_commit"],
                item["record_commit"],
            )
            try:
                document = json.loads(
                    _git(repo, "show", f"{item['record_commit']}:{item['record_path']}")
                )
            except json.JSONDecodeError as exc:
                _die(f"{distribution} producing publication record is not JSON: {exc}")
            filename = _wheel_name(distribution, item["version"])
            _publication_row(distribution, item, document, filename)


def _wheel_name(distribution: str, version: str) -> str:
    return f"{distribution.replace('-', '_')}-{version}-py3-none-any.whl"


def _installed() -> None:
    from dotmac_approvals import withdraw_platform_approval
    from dotmac_deployment_control import (
        ApprovalEvidence,
        ProposePlanCommand,
        RevokePlanApprovalCommand,
        approve_plan,
        issue_rehearsal_issuer_authorization_for_plan,
        propose_plan,
        revoke_plan_approval,
    )

    for distribution, item in _release_evidence().items():
        if metadata.version(distribution) != item["version"]:
            _die(f"installed {distribution} is not {item['version']}")
    site_roots = tuple(
        Path(sysconfig.get_paths()[key]).resolve() for key in ("purelib", "platlib")
    )
    for function in (propose_plan, withdraw_platform_approval):
        origin = Path(inspect.getfile(function)).resolve()
        if not any(origin.is_relative_to(root) for root in site_roots):
            _die(f"{function.__name__} imported from outside the isolated install")
    proposal_fields = set(ProposePlanCommand.__dataclass_fields__)
    required_proposal = {
        "command_id",
        "target_id",
        "operation",
        "descriptor_digest",
        "execution_plan_digest",
        "purpose",
        "requires_approval",
        "approval_policy_code",
        "approval_policy_version",
        "expected_desired_revision",
        "actor_ref",
    }
    if not required_proposal <= proposal_fields:
        _die("Control proposal lacks the protected composition terms")
    evidence_fields = set(ApprovalEvidence.__dataclass_fields__)
    if (
        not {
            "decision_status",
            "operation",
            "execution_plan_digest",
            "content_digest",
            "decision_ref",
            "decided_at",
        }
        <= evidence_fields
    ):
        _die("Control approval evidence lacks the required terms")
    if not {"command_id", "plan_id", "revocation_ref"} <= set(
        RevokePlanApprovalCommand.__dataclass_fields__
    ):
        _die("Control revocation command lacks stable provenance fields")
    for function in (propose_plan, approve_plan, revoke_plan_approval):
        if tuple(inspect.signature(function).parameters) != ("db", "command"):
            _die(f"Control {function.__name__} signature changed")
    if tuple(
        inspect.signature(issue_rehearsal_issuer_authorization_for_plan).parameters
    ) != ("db", "request", "harness_evidence_document"):
        _die("Control issuer signature changed")
    if tuple(inspect.signature(withdraw_platform_approval).parameters) != (
        "db",
        "request_id",
        "actor",
        "authority_ref",
        "reason",
        "external_ref",
    ):
        _die("Approvals withdrawal signature changed")
    print("protected issuer successor signatures and installed versions verified")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-only", action="store_true")
    parser.add_argument("--requirements", action="store_true")
    parser.add_argument("--verify-publications", action="store_true")
    parser.add_argument("--wheel-dir", type=Path)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    if args.installed:
        _installed()
        return
    evidence = _release_evidence()
    if args.evidence_only:
        print("protected issuer checked-in release evidence verified")
        return
    if args.requirements:
        for distribution, item in evidence.items():
            print(f"{distribution}=={item['version']}")
        print(f"dotmac-kernel=={_kernel_artifact()['version']}")
        return
    if args.verify_publications:
        _verify_publications(evidence)
        print("protected issuer producing publication records and tags verified")
        return
    if args.wheel_dir is None:
        _die("a requested verification mode or wheel directory is required")
    for distribution, item in evidence.items():
        path = _wheel_path(args.wheel_dir, distribution, item["version"])
        _wheel(path, distribution, item["version"], item["sha256"])
        print(path)
    kernel = _kernel_artifact()
    kernel_path = args.wheel_dir / kernel["filename"]
    _wheel(kernel_path, "dotmac-kernel", kernel["version"], kernel["sha256"])
    print(kernel_path)


if __name__ == "__main__":
    main()
