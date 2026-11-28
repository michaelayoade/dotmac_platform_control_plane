#!/usr/bin/env python3
"""Bounded, secret-free, unpublished Control a18 qualification. No installation."""
from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import html
import http.server
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import tomllib

HEAD = "79735d0d573231723ad4cad2d2348f8dc42ce6c4"
CONTROL = "dotmac-deployment-control"
WHEEL = "dotmac_deployment_control-0.1.0a18-py3-none-any.whl"
WHEEL_SHA = "17fdb59adc23b8eda5108c32caf6f3850e627e83a4ec7a94e7942f462c39f421"
CANDIDATE_NAME = "a2-control-candidate"
CANDIDATE_URL = "http://127.0.0.1:8899/a2-control-candidate/simple"
MIRROR = "http://127.0.0.1:8899/baseline/simple"
BINDINGS = {
    "README.md": "4e1715a20142eaf69deac87c25be71a0bbff4b042cdf55db4f9661e22c56f271",
    "scripts/kernel_lock.py": "ef80e927e1aefba218ec528ac165d2b2c590645dfa9ab1f24b080e2b186ed27d",
    "scripts/warm_reviewed_private_artifacts.py": "568870bc0e1fbd9be262490ac9022a97240569feb0dcf6c58be45676f505ba12",
    ".github/bootstrap/poetry-requirements.txt": "8416ab4e2a619884937ed3be34ea1928829fee0df76773e25108e73acd97ab1f",
    "pyproject.toml": "22311a7d1927cac7c4ebdef1490a977063c1fed616dedc6672a500c2b61c280c",
    "poetry.lock": "92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301",
}


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "nonregular input")


def verify_flat_inputs(directory, expected):
    require(not directory.is_symlink() and directory.is_dir(), "invalid bundle directory")
    require({p.name for p in directory.iterdir()} == set(expected), "bundle file closure mismatch")
    for name, value in expected.items():
        require(Path(name).name == name, "unsafe artifact name")
        regular(directory / name)
        require(digest(directory / name) == value, "artifact hash mismatch")


def entries(document):
    found = {}
    for entry in document.get("package", []):
        name = entry.get("name")
        require(isinstance(name, str), "missing lock identity")
        require(name == re.sub(r"[-_.]+", "-", name).lower() and name not in found,
                "duplicate or aliased lock identity")
        files = entry.get("files", [])
        require(len({f.get("file") for f in files}) == len(files), "duplicate lock file")
        found[name] = entry
    require(bool(found), "empty lock")
    return found


def verify_candidate_pair(before, actual, manifest, planned, owner, bundle, digests, private):
    """Inspect ACTUAL source first; owner's comparison projection exists only in memory."""
    require(manifest == planned, "actual manifest differs from explicit plan")
    old, new = entries(before), entries(actual)
    require(set(old) == set(new), "package set changed")
    control = new[CONTROL]
    require(control.get("version") == "0.1.0a18", "wrong Control version")
    require(control.get("source") == {"type": "legacy", "url": CANDIDATE_URL,
                                     "reference": CANDIDATE_NAME}, "wrong actual candidate source")
    require(control.get("files") == [{"file": WHEEL, "hash": "sha256:" + WHEEL_SHA}],
            "candidate must retain only the exact a18 wheel")
    require(control.get("dependencies") == old[CONTROL].get("dependencies"), "Control dependencies changed")
    require(all(new[name] == entry for name, entry in old.items() if name != CONTROL),
            "Kernel or unrelated entry changed")
    allowed = copy.deepcopy(old[CONTROL])
    allowed.update(version="0.1.0a18", files=control["files"], source=control["source"])
    require(control == allowed, "unexpected Control field changed")
    for key in set(before) | set(actual):
        if key not in {"package", "metadata"}:
            require(before.get(key) == actual.get(key), "top-level lock table changed")
    old_meta, new_meta = copy.deepcopy(before.get("metadata", {})), copy.deepcopy(actual.get("metadata", {}))
    old_hash, new_hash = old_meta.pop("content-hash", None), new_meta.pop("content-hash", None)
    require(old_meta == new_meta and bool(new_hash) and new_hash != old_hash, "lock metadata drift")
    comparison = copy.deepcopy(actual)
    next(e for e in comparison["package"] if e["name"] == CONTROL)["source"] = copy.deepcopy(old[CONTROL]["source"])
    delta = owner.parse_dependency_delta(CONTROL, "0.1.0a17", "0.1.0a18")
    require(not owner.drift_problems(before, comparison, delta, bundle), "owner drift gate refused")
    verify_flat_inputs(bundle / "files", digests)
    require(json.loads((bundle / "digests.json").read_text()) == digests, "bundle digest record drift")
    for name, version in private.items():
        version = "0.1.0a18" if name == CONTROL else version
        require(not owner.acquired_matches_lock(digests, actual, name, version), "actual acquired/lock mismatch")
        wheels = [bundle / "files" / f for f in digests if f.endswith(".whl") and owner.artifact_belongs_to(f, name, version)]
        require(len(wheels) == 1, "missing or ambiguous private wheel")
        require(not owner.wheel_identity_problems(wheels[0], name, version), "actual wheel identity mismatch")
        owner.wheel_metadata(wheels[0], name, version)
        if name == CONTROL:
            require(not owner.metadata_binding_problems(new[name], wheels[0], digests), "actual Control metadata mismatch")
    require(not owner.lock_wheel_problems(actual), "closing wheel-only gate refused")
    return True


def build_index(index, files, digests, private, owner):
    """Copy opaque sdists and wheels; no extraction or package code imports."""
    for lane, packages in (("baseline", {n: v for n, v in private.items() if n != CONTROL}),
                           (CANDIDATE_NAME, {CONTROL: "0.1.0a18"})):
        root = index / lane
        (root / "files").mkdir(parents=True)
        for name, version in packages.items():
            offered = sorted(f for f in digests if owner.artifact_belongs_to(f, name, version))
            require(not owner.wheel_only_problems([(name, version, offered)]), "index wheel gate refused")
            page = root / "simple" / name
            page.mkdir(parents=True)
            links = []
            for filename in offered:
                shutil.copyfile(files / filename, root / "files" / filename)
                links.append(f'<a href="../../files/{html.escape(filename)}#sha256={digests[filename]}">{html.escape(filename)}</a>')
            (page / "index.html").write_text("\n".join(links) + "\n")
    for path in sorted(index.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    index.chmod(0o555)


def load_verified(source):
    for relative, value in BINDINGS.items():
        regular(source / relative)
        require(digest(source / relative) == value, "source binding mismatch")
    owner_path = source / "scripts/kernel_lock.py"
    def load(name, path):
        module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
        sys.modules[name] = module
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        return module
    require("kernel_lock" not in sys.modules, "ambient owner module")
    owner = load("kernel_lock", owner_path)
    producer = load("verified_private_producer", source / "scripts/warm_reviewed_private_artifacts.py")
    return owner, producer


def planned_manifest(text, owner):
    delta = owner.parse_dependency_delta(CONTROL, "0.1.0a17", "0.1.0a18")
    edited = owner.replace_dependency_version(text, delta)
    doc = tomllib.loads(edited)
    require(not owner.manifest_problems(doc, "0.1.0a100", delta), "unchanged normal manifest guard refused")
    expected = copy.deepcopy(doc)
    expected["tool"]["poetry"]["dependencies"][CONTROL]["source"] = CANDIDATE_NAME
    expected["tool"]["poetry"]["source"].append({"name": CANDIDATE_NAME, "url": CANDIDATE_URL, "priority": "explicit"})
    needle = 'dotmac-deployment-control = { version = "0.1.0a18", source = "forgejo" }'
    require(edited.count(needle) == 1, "unexpected Control declaration shape")
    edited = edited.replace(needle, needle.replace('"forgejo"', '"' + CANDIDATE_NAME + '"'))
    edited += f'\n[[tool.poetry.source]]\nname = "{CANDIDATE_NAME}"\nurl = "{CANDIDATE_URL}"\npriority = "explicit"\n'
    require(tomllib.loads(edited) == expected, "candidate manifest edit escaped plan")
    return edited, expected


def clean_environment(out):
    for key, value in os.environ.items():
        require(not value or not re.search(r"FORGEJO|POETRY_HTTP_BASIC|NETRC|TWINE|GITHUB|^GH_|DOTMAC_KNOWLEDGE", key.upper()),
                "credential-shaped environment refused")
    home = Path(os.environ.get("HOME", "/nonexistent"))
    require(not (home / ".netrc").exists() and not (home / ".netrc").is_symlink(), "ambient netrc refused")
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "POETRY_KEYRING_ENABLED": "false", "POETRY_INSTALLER_ONLY_BINARY": ":all:",
           "POETRY_NO_INTERACTION": "1", "POETRY_VIRTUALENVS_CREATE": "false"}
    for key, name in (("HOME", "home"), ("POETRY_CONFIG_DIR", "config"), ("POETRY_DATA_DIR", "data"),
                      ("POETRY_CACHE_DIR", "cache"), ("XDG_CONFIG_HOME", "xdg-config"), ("XDG_CACHE_HOME", "xdg-cache")):
        path = out / name
        path.mkdir(mode=0o700)
        env[key] = str(path)
    return env


def poetry_argv(*arguments):
    """Disable installed Poetry plugins for every resolver/check invocation."""
    return [sys.executable, "-I", "-B", "-m", "poetry", "--no-plugins", *arguments]


def verify_control_dependencies(headers, baseline_entry, owner):
    """Use the unchanged owner's dependency map AND its canonical key spelling."""
    deps = owner.metadata_dependencies(owner.requires_dist(headers))
    require(deps == owner.locked_dependencies(baseline_entry)
            and deps.get(owner._normalised("dotmac-kernel")) == ">=0.1.0a100",
            "a18 dependencies mismatch")
    return deps


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("source-root", "baseline-bundle", "control-wheel", "out", "acceptance", "transfer-receipt"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    source, out = args.source_root.resolve(), args.out.absolute()
    require(sys.version_info[:2] == (3, 12), "Python 3.12 required")
    require(importlib.metadata.version("poetry") == "2.4.1", "Poetry 2.4.1 required in driver interpreter")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    env = clean_environment(out)
    def run(argv, cwd=out):
        with (out / "resolver.log").open("ab") as log:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=900, check=False, shell=False)
        require(result.returncode == 0, "subprocess refused; retained private resolver.log")
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], env=env,
                              capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    require(revision == HEAD, "source HEAD mismatch")
    owner, producer = load_verified(source)
    manifest_bytes, lock_bytes = (source / "pyproject.toml").read_bytes(), (source / "poetry.lock").read_bytes()
    private, expected = producer.closed_plan(manifest_bytes, lock_bytes)
    require(len(private) == 7 and len(expected) == 14, "baseline closure mismatch")
    for path in (args.acceptance, args.transfer_receipt):
        regular(path)
    acceptance = json.loads(args.acceptance.read_text())
    transfer = json.loads(args.transfer_receipt.read_text())
    require(acceptance.get("status") == "ACCEPTED_OPERATOR_BOOTSTRAP_BASELINE_ONLY" and acceptance.get("artifacts") == expected
            and acceptance.get("fresh_cp_tokens") == 0 and acceptance.get("root_authorized_secret_free_next_steps") is True
            and acceptance.get("operator_only_provenance") is True and acceptance.get("normal_producer_admission") is False,
            "independent acceptance mismatch")
    require(transfer.get("status") == "SECRET_FREE_ACCEPTED_ARTIFACT_TRANSFER_VERIFIED" and transfer.get("files") == expected
            and transfer.get("source_receipt_sha256") == acceptance.get("remote_receipt_sha256")
            and transfer.get("no_package_code_executed") is True, "transfer receipt mismatch")
    verify_flat_inputs(args.baseline_bundle, expected)
    require(sum(p.stat().st_size for p in args.baseline_bundle.iterdir()) == 2427617
            and acceptance.get("total_bytes") == 2427617 and transfer.get("bytes") == 2427617
            and acceptance.get("artifact_count") == 14 and transfer.get("count") == 14, "accepted byte/count mismatch")
    regular(args.control_wheel)
    require(args.control_wheel.name == WHEEL and digest(args.control_wheel) == WHEEL_SHA, "wrong a18 wheel")
    before = tomllib.loads(lock_bytes.decode())
    old_entries = entries(before)
    for name, version in private.items():
        wheel = args.baseline_bundle / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        require(not owner.acquired_matches_lock(expected, before, name, version), "baseline acquired/lock mismatch")
        require(not owner.wheel_identity_problems(wheel, name, version), "baseline wheel identity refused")
        owner.wheel_metadata(wheel, name, version)
        if name == CONTROL:
            require(not owner.metadata_binding_problems(old_entries[name], wheel, expected), "baseline Control metadata binding refused")
    require(not owner.wheel_identity_problems(args.control_wheel, CONTROL, "0.1.0a18"), "a18 identity refused")
    verify_control_dependencies(owner.wheel_metadata(args.control_wheel, CONTROL, "0.1.0a18"), old_entries[CONTROL], owner)
    selected = {f: d for f, d in expected.items() if not owner.artifact_belongs_to(f, CONTROL, "0.1.0a17")}
    selected[WHEEL] = WHEEL_SHA
    bundle = out / "candidate_bundle"
    (bundle / "files").mkdir(parents=True)
    for filename in selected:
        shutil.copyfile(args.control_wheel if filename == WHEEL else args.baseline_bundle / filename, bundle / "files" / filename)
    (bundle / "digests.json").write_text(json.dumps(selected, sort_keys=True) + "\n")
    verify_flat_inputs(bundle / "files", selected)
    build_index(out / "index", bundle / "files", selected, private, owner)
    work = out / "pair"
    work.mkdir()
    manifest, lock = work / "pyproject.toml", work / "poetry.lock"
    shutil.copyfile(source / "README.md", work / "README.md")
    text, planned = planned_manifest(manifest_bytes.decode(), owner)
    manifest.write_text(owner.point_at_mirror(text, MIRROR))
    lock.write_bytes(lock_bytes)
    require(not owner.lock_wheel_problems(before), "opening wheel-only gate refused")
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *unused):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8899), functools.partial(QuietHandler, directory=str(out / "index")))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        run(poetry_argv("lock"), work)
        manifest.write_text(owner.restore_index_url(manifest.read_text(), MIRROR))
        lock.write_text(owner.restore_index_url(lock.read_text(), MIRROR, required=False))
        lock.write_text(owner.set_content_hash(lock.read_text(), owner.poetry_content_hash(manifest, lock)))
        run(poetry_argv("check", "--lock"), work)
        actual = tomllib.loads(lock.read_text())
        require(actual["metadata"]["content-hash"] == owner.poetry_content_hash(manifest, lock), "actual content hash mismatch")
        verify_candidate_pair(before, actual, tomllib.loads(manifest.read_text()), planned, owner, bundle, selected, private)
        verify_flat_inputs(args.baseline_bundle, expected)
        require(digest(args.control_wheel) == WHEEL_SHA, "a18 changed during resolve")
        require(all(digest(source / p) == d for p, d in BINDINGS.items()), "source changed during resolve")
        closing_revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], env=env,
                                          capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        require(closing_revision == HEAD, "source HEAD changed during resolve")
        evidence = {"status": "UNPUBLISHED_CANDIDATE_LOCK_QUALIFIED", "source_revision": HEAD,
                    "source_bindings_before_after": BINDINGS, "driver_sha256": digest(Path(__file__)),
                    "acceptance_sha256": digest(args.acceptance), "transfer_receipt_sha256": digest(args.transfer_receipt),
                    "manifest_sha256": digest(manifest), "lock_sha256": digest(lock), "control_wheel_sha256": WHEEL_SHA,
                    "runtime": {"python": sys.version.split()[0], "poetry": "2.4.1"},
                    "actual_control_source": actual["package"][[e["name"] for e in actual["package"]].index(CONTROL)]["source"],
                    "checks": {"normal_manifest_guard_before_candidate_edit": True, "opening_closing_wheel_only": True,
                               "actual_pair_and_owner_drift": True, "actual_wheel_identity_all_seven_and_control_metadata": True,
                               "input_rehash_before_after": True, "poetry_check_lock": True},
                    "source_ephemeral": True, "published": False, "image_qualified": False,
                    "normal_producer_admission": False, "publication_or_deployment": False}
        (out / "qualification.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"candidate resolver refused ({type(error).__name__}); outputs retained", file=sys.stderr)
        sys.exit(1)
