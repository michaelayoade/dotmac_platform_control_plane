#!/usr/bin/env python3
"""Source-only CP adapter for a reviewed, unchanged private dependency baseline.

The public Workspace binder is imported only after checking its immutable source
hash. Candidate manifest and lock bytes are data; neither candidate code nor
acquired wheel/sdist code is imported, installed, built, or resolved.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

import kernel_lock as owner

REPOSITORY = "michaelayoade/dotmac_platform_control_plane"
PRODUCER_PATH = ".github/workflows/private-artifact-produce.yml"
TOOLING_REVISION = "baa69b8291d77897553694c359bd8bb9906915ea"
BINDER_SHA256 = "7109c375cc6a4b2595d32319470744326f4ec9015c285548168811e4d2ae9bba"
MANIFEST_SHA256S = frozenset(
    {
        "57eb78949f1b652614ba0670a09a9d6814d4149d2f61c4e403d1a6b50d3d9e78",
        "22311a7d1927cac7c4ebdef1490a977063c1fed616dedc6672a500c2b61c280c",
    }
)
LOCK_SHA256 = "92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301"
PRIVATE = {
    "dotmac-approvals": "0.1.0a8",
    "dotmac-commercial-agreements": "0.1.0a4",
    "dotmac-deployment-control": "0.1.0a17",
    "dotmac-entitlement-allocation": "0.1.0a6",
    "dotmac-kernel": "0.1.0a100",
    "dotmac-licensing": "0.1.0a1",
    "dotmac-release-catalog": "0.1.0a4",
}


def load_binder(tooling: Path) -> Any:
    """Hash before import: never load a sibling or a candidate's helper."""
    path = tooling / "scripts" / "warm_reviewed_wheelhouse.py"
    payload = path.read_bytes()
    if path.is_symlink() or owner.sha256_hex(payload) != BINDER_SHA256:
        raise owner.Refusal("pinned Workspace binder source mismatch")
    spec = importlib.util.spec_from_file_location("pinned_workspace_binder", path)
    if spec is None or spec.loader is None:
        raise owner.Refusal("pinned Workspace binder unavailable")
    module = importlib.util.module_from_spec(spec)
    # Compile the verified bytes themselves; import loaders may reuse cached pyc.
    exec(compile(payload, str(path), "exec"), module.__dict__)  # noqa: S102
    return module


def closed_plan(manifest: bytes, lock: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """Validate RAW identities before the owner's dictionary-based comparison.

    This source draft accepts only two explicitly reviewed manifest byte strings
    paired with one lock. No dependency movement or unpublished version is admitted.
    """
    if (
        owner.sha256_hex(manifest) not in MANIFEST_SHA256S
        or owner.sha256_hex(lock) != LOCK_SHA256
    ):
        raise owner.Refusal("pair is outside the reviewed baseline")
    try:
        manifest_doc = tomllib.loads(manifest.decode("utf-8"))
        lock_doc = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise owner.Refusal("unreadable dependency pair") from None
    poetry = manifest_doc.get("tool", {}).get("poetry", {})
    sources = poetry.get("source")
    if sources != [
        {
            "name": owner.INDEX_SOURCE_NAME,
            "url": owner.INDEX_URL,
            "priority": "explicit",
        }
    ]:
        raise owner.Refusal("manifest source is not the exact private index")
    declared: dict[str, str] = {}
    for _, dependencies in owner._poetry_constraint_tables(manifest_doc):
        for name, value in dependencies.items():
            if isinstance(value, dict) and "source" in value:
                if (
                    name not in PRIVATE
                    or name in declared
                    or value.get("source") != owner.INDEX_SOURCE_NAME
                    or value.get("version") != PRIVATE[name]
                ):
                    raise owner.Refusal("private manifest identity mismatch")
                declared[name] = value["version"]
    if declared != PRIVATE:
        raise owner.Refusal("manifest private package set mismatch")

    locked: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    seen_names: set[str] = set()
    seen_hashes: set[str] = set()
    for entry in lock_doc.get("package", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise owner.Refusal("unreadable raw lock identity")
        name = entry["name"]
        normal = re.sub(r"[-_.]+", "-", name).lower()
        if name != normal or normal in seen_names:
            raise owner.Refusal("duplicate or aliased raw lock identity")
        seen_names.add(normal)
        source = entry.get("source")
        if name not in PRIVATE:
            if source is not None:
                raise owner.Refusal("unexpected sourced lock package")
            continue
        if entry.get("version") != PRIVATE[name] or source != {
            "type": "legacy",
            "url": owner.INDEX_URL,
            "reference": owner.INDEX_SOURCE_NAME,
        }:
            raise owner.Refusal("private lock identity or source mismatch")
        locked[name] = entry["version"]
        files = entry.get("files")
        expected_names = {
            f"{name.replace('-', '_')}-{PRIVATE[name]}-py3-none-any.whl",
            f"{name.replace('-', '_')}-{PRIVATE[name]}.tar.gz",
        }
        if not isinstance(files, list) or len(files) != 2:
            raise owner.Refusal("private lock must retain wheel and sdist")
        raw_names: set[str] = set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {"file", "hash"}:
                raise owner.Refusal("malformed private file record")
            filename, digest = item["file"], item["hash"]
            if (
                not isinstance(filename, str)
                or filename not in expected_names
                or filename in raw_names
                or filename in artifacts
                or not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or digest in seen_hashes
            ):
                raise owner.Refusal("duplicate or malformed private artifact identity")
            raw_names.add(filename)
            seen_hashes.add(digest)
            artifacts[filename] = digest.removeprefix("sha256:")
        if raw_names != expected_names:
            raise owner.Refusal("private wheel/sdist pair mismatch")
    if locked != PRIVATE or len(artifacts) != 14:
        raise owner.Refusal("private lock package set mismatch")
    plan = owner.acquisition_plan(manifest_doc, lock_doc, PRIVATE[owner.KERNEL])
    if plan != PRIVATE:
        raise owner.Refusal("owner acquisition plan disagrees with baseline")
    for name, version in plan.items():
        if owner.acquired_matches_lock(artifacts, lock_doc, name, version):
            raise owner.Refusal("raw artifact set disagrees with lock")
    return plan, artifacts


def run_binding(pr: str, head: str) -> dict[str, str]:
    """Only nonsecret, bounded coordinates can enter the receipt."""
    result = {
        "repository": REPOSITORY,
        "reviewed-pr": pr,
        "reviewed-head": head,
        "tooling-revision": TOOLING_REVISION,
        "tooling-sha256": BINDER_SHA256,
    }
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise owner.Refusal("workflow repository mismatch")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise owner.Refusal("workflow ref is not main")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = os.environ.get(key, "")
        if re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise owner.Refusal("workflow run coordinate unavailable")
        result[key.lower()] = value
    sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise owner.Refusal("trusted main revision unavailable")
    result["trusted-main-sha"] = sha
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    workflow_sha = os.environ.get("GITHUB_WORKFLOW_SHA", "")
    if workflow_ref != f"{REPOSITORY}/{PRODUCER_PATH}@refs/heads/main":
        raise owner.Refusal("producer workflow path or ref mismatch")
    if workflow_sha != sha:
        raise owner.Refusal("producer workflow revision differs from trusted main")
    workflow = Path(__file__).resolve().parents[1] / PRODUCER_PATH
    if workflow.is_symlink() or not workflow.is_file():
        raise owner.Refusal("trusted producer workflow file unavailable")
    result.update(
        {
            "workflow-ref": workflow_ref,
            "workflow-sha": workflow_sha,
            "workflow-file-sha256": owner.sha256_hex(workflow.read_bytes()),
        }
    )
    return result


def bind(tooling: Path, snapshot: Path, pr: str, head: str) -> None:
    helper = load_binder(tooling)
    number, exact_head = helper.admit_dispatch(
        os.environ.get("GITHUB_REF", ""), pr, head
    )
    receipt = run_binding(str(number), exact_head)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise owner.Refusal("read API token unavailable")
    manifest, lock = helper.bind_snapshot(
        helper._live_fetch(token), REPOSITORY, number, exact_head
    )
    closed_plan(manifest, lock)
    receipt.update(
        {
            "manifest-sha256": owner.sha256_hex(manifest),
            "lock-sha256": owner.sha256_hex(lock),
        }
    )
    snapshot.mkdir(parents=True, exist_ok=False)
    (snapshot / "pyproject.toml").write_bytes(manifest)
    (snapshot / "poetry.lock").write_bytes(lock)
    (snapshot / "binding.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


def acquire(snapshot: Path, out: Path, pr: str, head: str) -> None:
    if (
        re.fullmatch(r"[1-9][0-9]{0,6}", pr) is None
        or re.fullmatch(r"[0-9a-f]{40}", head) is None
    ):
        raise owner.Refusal("reviewed coordinates unavailable")
    if {path.name for path in snapshot.iterdir()} != {
        "pyproject.toml",
        "poetry.lock",
        "binding.json",
    } or any(path.is_symlink() or not path.is_file() for path in snapshot.iterdir()):
        raise owner.Refusal("snapshot is not the bound data-only directory")
    manifest = (snapshot / "pyproject.toml").read_bytes()
    lock = (snapshot / "poetry.lock").read_bytes()
    plan, artifacts = closed_plan(manifest, lock)
    expected = run_binding(pr, head)
    expected.update(
        {
            "manifest-sha256": owner.sha256_hex(manifest),
            "lock-sha256": owner.sha256_hex(lock),
        }
    )
    receipt = json.loads((snapshot / "binding.json").read_text())
    if receipt != expected:
        raise owner.Refusal("snapshot binding changed")
    credential = os.environ.pop("FORGEJO_BUNDLE_READ_TOKEN", "")
    if not credential or any(
        char.isspace() or char in '\\"' or ord(char) < 32 for char in credential
    ):
        raise owner.Refusal("credential cannot be represented safely in netrc")
    original_home = os.environ.get("HOME")
    try:
        with tempfile.TemporaryDirectory(prefix="cp-private-home-") as private_home:
            os.chmod(private_home, 0o700)
            netrc = Path(private_home) / ".netrc"
            with netrc.open("x", encoding="utf-8") as stream:
                os.chmod(netrc, 0o600)
                stream.write(
                    f"machine registry.dotmac.io login {owner.INDEX_USERNAME} "
                    f"password {credential}\n"
                )
            os.environ["HOME"] = private_home
            owner.acquire(plan, out, expected_artifacts=artifacts)
            (out / "binding.json").write_text(
                json.dumps(receipt, sort_keys=True) + "\n"
            )
            paths = [path for path in out.rglob("*") if path.is_file()]
            if any(path.is_symlink() for path in out.rglob("*")):
                raise owner.Refusal("bundle contains a symlink")
            if owner.credential_sightings(paths, credential):
                raise owner.Refusal(
                    "credential encoding found in bundle; upload refused"
                )
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("operation", choices=("bind", "acquire"))
    parser.add_argument("--tooling", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        pr, head = (
            os.environ.get("REVIEWED_PR", ""),
            os.environ.get("REVIEWED_HEAD", ""),
        )
        if args.operation == "bind" and args.tooling is not None:
            bind(args.tooling, args.snapshot, pr, head)
        elif args.operation == "acquire" and args.out is not None:
            acquire(args.snapshot, args.out, pr, head)
        else:
            raise owner.Refusal("operation arguments unavailable")
    except Exception:
        # Neither candidate data nor downloader/credential exception text is a log.
        print("private artifact producer refused", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
