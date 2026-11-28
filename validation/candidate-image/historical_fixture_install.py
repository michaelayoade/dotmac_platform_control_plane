#!/usr/bin/env python3
"""Install one rebuilt historical validation fixture through a temporary mirror."""
from __future__ import annotations

import copy
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
import types
from contextlib import contextmanager

MANIFEST_SHA = "06f21ab12967c387af5f9792530cfc66c7b590cfeedd75ff6e1450dcfd7f75db"
LOCK_SHA = "92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301"
OWNER_SHA = "ef80e927e1aefba218ec528ac165d2b2c590645dfa9ab1f24b080e2b186ed27d"
CANONICAL = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
MIRROR = "http://127.0.0.1:8899/baseline/simple"
CONTROL = "dotmac-deployment-control"
WHEEL = "dotmac_deployment_control-0.1.0a17-py3-none-any.whl"
WHEEL_SHA = "ecd3478a5398ce7c93d1c7195edf76ca4b4630f9c8474527e914d1561a3f39f9"
SDIST = "dotmac_deployment_control-0.1.0a17.tar.gz"
SDIST_SHA = "52f2d1f07f6a8aea59fd59eb0c03c6f11973921b9dd5055d9aa84a8c1dd2196a"
PYTHON = "/opt/poetry/bin/python"


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "nonregular input")


def validate_config(config):
    require(set(config) == {"manifest_sha256", "lock_sha256", "owner_sha256", "index_files"},
            "config fields mismatch")
    require((config["manifest_sha256"], config["lock_sha256"], config["owner_sha256"])
            == (MANIFEST_SHA, LOCK_SHA, OWNER_SHA), "config qualified bindings mismatch")
    files = config["index_files"]
    require(isinstance(files, dict) and len(files) == 21, "index closure count mismatch")
    for name, digest in files.items():
        path = Path(name)
        require(not path.is_absolute() and path.as_posix() == name
                and all(part not in {".", ".."} for part in path.parts)
                and re.fullmatch(r"[a-zA-Z0-9_./-]+", name), "unsafe index path")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid digest")
        require((len(path.parts) == 3 and path.parts[1] == "files")
                or (len(path.parts) == 4 and path.parts[1] == "simple"
                    and path.name == "index.html"), "unexpected index path")
        require(path.parts[0] == "baseline", "unexpected index lane")
    require(sum(name.startswith("baseline/files/") for name in files) == 14
            and sum(name.startswith("baseline/simple/") for name in files) == 7
            and files.get("baseline/files/" + WHEEL) == WHEEL_SHA
            and files.get("baseline/files/" + SDIST) == SDIST_SHA,
            "index lane closure mismatch")
    return files


def verify_index(root, expected):
    require(root.is_dir() and not root.is_symlink(), "invalid index root")
    require(not root.stat().st_mode & 0o222, "index root must be readonly")
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "index symlink refused")
        require(not path.stat().st_mode & 0o222, "index must be readonly")
        if path.is_dir():
            require(any(name.startswith(path.relative_to(root).as_posix() + "/")
                        for name in expected), "extra index directory")
            continue
        regular(path)
        name = path.relative_to(root).as_posix()
        actual.add(name)
        require(name in expected and sha(path.read_bytes()) == expected[name], "index hash mismatch")
    require(actual == set(expected), "index file closure mismatch")


def clean_environment(base, ambient):
    for key, value in ambient.items():
        require(not value or not re.search(
            r"TOKEN|PASSWORD|SECRET|CREDENTIAL|FORGEJO|POETRY_HTTP_BASIC|NETRC|TWINE|GITHUB|^GH_|OPENBAO|VAULT|DOTMAC_KNOWLEDGE",
            key.upper()), "credential-shaped environment refused")
    home = Path(ambient.get("HOME", "/nonexistent"))
    require(not (home / ".netrc").exists() and not (home / ".netrc").is_symlink(), "ambient netrc refused")
    env = {"PATH": "/opt/venv/bin:/opt/poetry/bin:/usr/local/bin:/usr/bin:/bin",
           "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "VIRTUAL_ENV": "/opt/venv",
           "POETRY_KEYRING_ENABLED": "false", "POETRY_INSTALLER_ONLY_BINARY": ":all:",
           "POETRY_INSTALLER_RE_RESOLVE": "false",
           "POETRY_NO_INTERACTION": "1", "POETRY_VIRTUALENVS_CREATE": "false"}
    for key in ("HOME", "POETRY_CONFIG_DIR", "POETRY_DATA_DIR", "POETRY_CACHE_DIR",
                "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        path = base / key.lower()
        path.mkdir(mode=0o700)
        env[key] = str(path)
    return env


def load_owner(path):
    regular(path)
    data = path.read_bytes()
    require(sha(data) == OWNER_SHA, "owner hash mismatch")
    require("kernel_lock" not in sys.modules, "ambient owner module")
    module = types.ModuleType("kernel_lock")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def validate_pair(manifest_bytes, lock_bytes):
    require(sha(manifest_bytes) == MANIFEST_SHA and sha(lock_bytes) == LOCK_SHA,
            "qualified pair hash mismatch")
    manifest, lock = tomllib.loads(manifest_bytes.decode()), tomllib.loads(lock_bytes.decode())
    sources = manifest["tool"]["poetry"]["source"]
    require(sources == [
        {"name": "forgejo", "url": CANONICAL, "priority": "explicit"}],
        "manifest source closure mismatch")
    require(manifest["tool"]["poetry"]["dependencies"][CONTROL]
            == {"version": "0.1.0a17", "source": "forgejo"}, "Control declaration mismatch")
    packages = lock["package"]
    require(len(packages) == 54 and len({p["name"] for p in packages}) == 54, "package closure mismatch")
    private = [p for p in packages if "source" in p]
    require(len(private) == 7, "private source closure mismatch")
    for package in private:
        expected = {"type": "legacy", "url": CANONICAL, "reference": "forgejo"}
        require(package["source"] == expected, "lock source mismatch")
    control = next(p for p in packages if p["name"] == CONTROL)
    require(control["version"] == "0.1.0a17" and control["files"] == [
        {"file": WHEEL, "hash": "sha256:" + WHEEL_SHA},
        {"file": SDIST, "hash": "sha256:" + SDIST_SHA}], "Control artifact mismatch")
    require(next(p for p in packages if p["name"] == "dotmac-kernel")["version"] == "0.1.0a100",
            "Kernel version mismatch")
    return manifest, lock


def validate_lock_index(lock, files):
    """Every old private lock artifact and package page, with no extra offer."""
    private = [p for p in lock["package"] if "source" in p]
    artifacts = {}
    for package in private:
        for artifact in package["files"]:
            name, digest = artifact["file"], artifact["hash"]
            require(Path(name).name == name and digest.startswith("sha256:"),
                    "invalid locked artifact")
            key = "baseline/files/" + name
            require(key not in artifacts, "duplicate locked artifact")
            artifacts[key] = digest.removeprefix("sha256:")
    offered = {name: digest for name, digest in files.items() if "/files/" in name}
    require(len(artifacts) == 14 and offered == artifacts, "index/old lock artifact mismatch")
    pages = {"baseline/simple/" + p["name"] + "/index.html" for p in private}
    require(set(files) == set(artifacts) | pages, "index/old lock page closure mismatch")


def mirror_pair(manifest_bytes, lock_bytes, owner):
    before_manifest, before_lock = validate_pair(manifest_bytes, lock_bytes)
    manifest = owner.point_at_mirror(manifest_bytes.decode(), MIRROR)
    expected_manifest = copy.deepcopy(before_manifest)
    expected_manifest["tool"]["poetry"]["source"][0]["url"] = MIRROR
    require(tomllib.loads(manifest) == expected_manifest, "manifest transform escaped plan")
    text = lock_bytes.decode()
    needle = 'url = "' + CANONICAL + '"'
    require(text.count(needle) == 7 and text.count(CANONICAL) == 7, "baseline URL count mismatch")
    text = text.replace(needle, 'url = "' + MIRROR + '"')
    expected_lock = copy.deepcopy(before_lock)
    for package in expected_lock["package"]:
        if package.get("source", {}).get("url") == CANONICAL:
            package["source"]["url"] = MIRROR
    require(tomllib.loads(text) == expected_lock, "lock transform escaped plan")
    return manifest, text, expected_lock


def install_argv():
    return [PYTHON, "-I", "-B", "-m", "poetry", "--no-plugins", "install",
            "--only", "main", "--no-root", "--no-interaction", "--no-ansi"]


@contextmanager
def restored_pair(manifest, lock):
    original = manifest.read_bytes(), lock.read_bytes()
    validate_pair(*original)
    try:
        yield original
    finally:
        manifest.write_bytes(original[0])
        lock.write_bytes(original[1])
        require((manifest.read_bytes(), lock.read_bytes()) == original, "exact pair restore failed")
        validate_pair(manifest.read_bytes(), lock.read_bytes())


class QuietReadonlyHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *unused):
        pass


def main():
    require(sys.executable == PYTHON and sys.version_info[:2] == (3, 12), "Poetry Python 3.12 required")
    app, tools, index = Path("/app"), Path("/opt/a2-tools"), Path("/opt/a2-index")
    regular(tools / "config.json")
    files = validate_config(json.loads((tools / "config.json").read_text()))
    verify_index(index, files)
    manifest, lock = app / "pyproject.toml", app / "poetry.lock"
    regular(manifest)
    regular(lock)
    _, original_lock = validate_pair(manifest.read_bytes(), lock.read_bytes())
    validate_lock_index(original_lock, files)
    require(not (app / "poetry.toml").exists() and not (app / "poetry.toml").is_symlink(), "project Poetry config refused")
    with tempfile.TemporaryDirectory(prefix="a2-install-") as temporary:
        env = clean_environment(Path(temporary), os.environ)
        # Clean ambient configuration before the pinned owner imports Poetry's Locker.
        os.environ.clear()
        os.environ.update(env)
        owner = load_owner(tools / "kernel_lock.py")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 8899),
            functools.partial(QuietReadonlyHandler, directory=str(index)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with restored_pair(manifest, lock) as original:
                temporary_manifest, temporary_lock, expected_lock = mirror_pair(*original, owner)
                manifest.write_text(temporary_manifest)
                lock.write_text(temporary_lock)
                content_hash = owner.poetry_content_hash(manifest, lock)
                lock.write_text(owner.set_content_hash(temporary_lock, content_hash))
                expected_lock["metadata"]["content-hash"] = content_hash
                require(tomllib.loads(lock.read_text()) == expected_lock, "content hash edit escaped plan")
                result = subprocess.run(install_argv(), cwd=app, env=env, check=False,
                                        shell=False, timeout=900)
                require(result.returncode == 0, "Poetry install failed")
                require(manifest.read_text() == temporary_manifest
                        and tomllib.loads(lock.read_text()) == expected_lock, "install changed temporary pair")
                verify_index(index, files)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print(json.dumps({"status": "HISTORICAL_FIXTURE_DEPENDENCIES_INSTALLED", "pair_restored": True,
                      "temporary_mirror_only": True, "published": False,
                      "normal_producer_provenance": False,
                      "rebuilt_validation_input": True,
                      "prior_accepted_image_continuity": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("historical fixture install refused (" + type(error).__name__ + ")", file=sys.stderr)
        sys.exit(1)
