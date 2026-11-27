"""Source-only operator acquisition boundary; no live authority or acceptance.

The launcher supplies verified, already loaded owner/producer modules before mint.
This module imports no candidate or acquired code. Sdists remain opaque bytes.
One process, one thread, one attempt; any output remains quarantined.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
import tomllib
from types import SimpleNamespace
from urllib.parse import urlsplit

CP_USERNAME = "cp-bundle-reader"
MANIFEST_SHA256 = "22311a7d1927cac7c4ebdef1490a977063c1fed616dedc6672a500c2b61c280c"
LOCK_SHA256 = "92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301"
ORIGIN = "https://registry.dotmac.io"
PREFIX = "/api/packages/dotmac/pypi/"
INDEX = ORIGIN + PREFIX + "simple"
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
_RUN = subprocess.run
_GATE = threading.Lock()
_ATTEMPTED = []


class Refused(Exception):
    """Fixed public refusal; never include underlying exception text."""


def _require(condition):
    if not condition:
        raise Refused("operator_acquisition_refused")


def _safe_parent(out):
    _require(isinstance(out, Path) and out.is_absolute())
    _require(not out.exists() and not out.is_symlink())
    _require(out.parent.is_dir())
    _require(all(not p.is_symlink() for p in (out, *out.parents)))
    _require(out.parent.resolve() == out.parent)
    # The owner creates the fresh output itself. Its ordinary directory modes
    # are safe only beneath an already private, launcher-owned quarantine root.
    _require(stat.S_IMODE(out.parent.stat().st_mode) == 0o700)


def _transport(owner, out, plan, expected, home, netrc):
    """Replace only the trusted owner's sole subprocess.run call surface."""
    def run(argv, **kwargs):
        _require(kwargs == {"check": False, "capture_output": True, "text": True})
        _require(type(argv) is list and len(argv) == 17)
        _require(all(type(arg) is str for arg in argv))
        url, target = argv[-1], Path(argv[-2])
        _require(argv == owner.curl_argv(url, target))
        _require(argv == [
            "curl", "--netrc", "--proto", "=https", "--max-redirs", "0",
            "--max-filesize", str(owner.ARTIFACT_MAX_BYTES), "--max-time",
            str(owner.ARTIFACT_MAX_SECONDS), "--silent", "--show-error", "-w",
            "%{http_code}", "-o", str(target), url])
        parts = urlsplit(url)
        _require(parts.scheme == "https" and parts.netloc == "registry.dotmac.io")
        _require(not parts.query and not parts.fragment)
        _require(parts.path.startswith(PREFIX) and "%" not in parts.path
                 and "\\" not in parts.path and ".." not in parts.path.split("/"))
        index_urls = {f"{INDEX}/{name}/": f"{name}.html" for name in plan}
        if url in index_urls:
            _require(target.name == index_urls[url])
            directory = out / "pages"
        else:
            _require(target.name in expected and parts.path.rsplit("/", 1)[-1] == target.name)
            _require(owner.approved_artifact_url(url, INDEX + "/") == url)
            directory = out / "files"
        _require(target.parent.parent == directory)
        _require(target.parent.name.startswith(".staging-"))
        _require(target.parent.is_dir() and not target.exists() and not target.is_symlink())
        _require(all(not p.is_symlink() for p in (target.parent, *target.parent.parents)))
        _require(stat.S_IMODE(target.parent.stat().st_mode) == 0o700)
        fixed = ["/usr/bin/curl", "--disable", "--netrc-file", str(netrc),
                 "--proxy", "", "--noproxy", "*", "--cacert", CA_FILE, *argv[2:]]
        result = _RUN(fixed, check=False, capture_output=True, text=True,
                      env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
                      timeout=owner.ARTIFACT_MAX_SECONDS + 5)
        # Neither stderr nor an arbitrary stdout can reach the owner or caller.
        _require(result.returncode == 0 and re.fullmatch(r"[0-9]{3}", result.stdout) is not None)
        return SimpleNamespace(returncode=0, stdout=result.stdout, stderr="")
    return SimpleNamespace(run=run)


def _verify_bundle(owner, out, plan, expected, lock, token):
    expected_paths = {"digests.json"}
    expected_dirs = {"files", "pages", "simple"}
    expected_paths.update("files/" + name for name in expected)
    for name in plan:
        expected_paths.update({f"pages/{name}.html", f"simple/{name}/index.html"})
        expected_dirs.add(f"simple/{name}")
    files, dirs = set(), set()
    forms = list(owner.credential_encodings(token).values())
    forms.append(base64.b64encode(f"{CP_USERNAME}:{token}".encode()).decode("ascii"))
    needles = [form.encode("utf-8") for form in forms]
    for path in out.rglob("*"):
        _require(not path.is_symlink())
        relative = path.relative_to(out).as_posix()
        mode = path.stat().st_mode
        if stat.S_ISDIR(mode):
            dirs.add(relative)
        else:
            _require(stat.S_ISREG(mode) and path.stat().st_nlink == 1)
            files.add(relative)
            payload = path.read_bytes()
            _require(not any(needle in payload for needle in needles))
    _require(files == expected_paths and dirs == expected_dirs)
    for filename, digest in expected.items():
        path = out / "files" / filename
        _require(hashlib.sha256(path.read_bytes()).hexdigest() == digest)
    for name, version in plan.items():
        _require(not owner.acquired_matches_lock(expected, lock, name, version))
        wheel = out / "files" / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        _require(not owner.wheel_identity_problems(wheel, name, version))


def acquire_baseline(owner, producer, manifest_bytes, lock_bytes, out: Path, token: str) -> dict:
    """Acquire one exact baseline and return nonsecret quarantine evidence.

    No acceptance marker is written. Revocation, native proof and independent
    acceptance remain the lifecycle coordinator's responsibility.
    """
    entered = _GATE.acquire(blocking=False)
    if not entered:
        raise Refused("operator_acquisition_refused")
    original = None
    try:
        _require(not any(item is owner for item in _ATTEMPTED))
        _ATTEMPTED.append(owner)
        _require(owner.subprocess is subprocess)
        _require(type(token) is str and bool(token)
                 and all(33 <= ord(char) <= 126 and char not in '\\"' for char in token))
        _require(type(manifest_bytes) is bytes and type(lock_bytes) is bytes)
        _require(hashlib.sha256(manifest_bytes).hexdigest() == MANIFEST_SHA256)
        _require(hashlib.sha256(lock_bytes).hexdigest() == LOCK_SHA256)
        plan, expected = producer.closed_plan(manifest_bytes, lock_bytes)
        _require(len(plan) == 7 and len(expected) == 14)
        _require(plan == producer.PRIVATE and plan.get("dotmac-kernel") == "0.1.0a100"
                 and plan.get("dotmac-deployment-control") == "0.1.0a17")
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
        _safe_parent(out)
        with tempfile.TemporaryDirectory(prefix="cp-acquisition-home-") as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            netrc = home / ".netrc"
            descriptor = os.open(netrc, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(f"machine registry.dotmac.io login {CP_USERNAME} password {token}\n")
            original = owner.subprocess
            owner.subprocess = _transport(owner, out, plan, expected, home, netrc)
            try:
                digests = owner.acquire(plan, out, expected_artifacts=expected)
            finally:
                owner.subprocess = original
                original = None
            _require(digests == expected)
            _require(out.is_dir() and not out.is_symlink())
            out.chmod(0o700)
            _verify_bundle(owner, out, plan, expected, lock, token)
        return {"artifacts": dict(sorted(expected.items())), "artifact_count": 14,
                "package_count": 7, "wheel_count": 7, "sdist_count": 7,
                "status": "quarantined", "manifest_sha256": MANIFEST_SHA256,
                "lock_sha256": LOCK_SHA256}
    except BaseException:
        raise Refused("operator_acquisition_refused") from None
    finally:
        if original is not None:
            owner.subprocess = original
        _GATE.release()
