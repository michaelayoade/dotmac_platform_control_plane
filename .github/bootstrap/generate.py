"""Emit a --require-hashes requirements file pinning Poetry and every
transitive dependency, resolved for THIS interpreter/platform.

Run inside a linux/amd64 container for the TARGET interpreter, so the
resolution matches the CI runner that will use it. Markers are evaluated
against the RUNNING interpreter, so resolving on macOS silently produces a
different dependency set (xattr in; SecretStorage, jeepney and cryptography
out), and resolving on one Python minor produces a different set from another.

For each resolved (name, version) it records the sha256 of EVERY distribution
PyPI publishes for that version, not just the one wheel this resolution picked.
A runner image with a different glibc or a newer manylinux tag may legitimately
select a different wheel of the same version; pinning only one would fail the
hash check for no security reason.
"""

import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

POETRY = sys.argv[1] if len(sys.argv) > 1 else "poetry==2.4.1"

with tempfile.TemporaryDirectory() as tmp:
    report = Path(tmp) / "report.json"
    argv = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        # --ignore-installed is LOAD-BEARING, not tidiness. Without it the
        # report describes what pip would install INTO THIS IMAGE, so anything
        # already present is silently omitted from the closure. python:3.11-slim
        # ships `packaging`; python:3.12-slim does not — which produced a lock
        # missing `packaging` that installed fine in the container and then
        # failed on the CI runner, where nothing is pre-installed:
        #   ERROR: In --require-hashes mode, all requirements must have their
        #   versions pinned with ==. These do not: packaging>=24.0
        # The lock must be the COMPLETE closure, independent of whatever
        # happens to be in the environment that generated it.
        "--ignore-installed",
        "--quiet",
        "--report",
        str(report),
        POETRY,
    ]
    # fixed argv, no shell, sys.executable — the only variable is the version
    # pin this script exists to accept.
    subprocess.run(  # noqa: S603
        argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    resolved = json.loads(report.read_text())["install"]
pins = sorted(
    ((i["metadata"]["name"], i["metadata"]["version"]) for i in resolved),
    key=lambda nv: nv[0].lower(),
)

print("# Hash-locked Poetry bootstrap — GENERATED, do not hand-edit.")
print("# Regenerate with .github/bootstrap/regenerate.sh (see that script for why")
print("# it must run in a linux/amd64 container for THIS interpreter).")
print(f"# Pinned installer: {POETRY}")
print("#")
print("# Install with:")
print("#   pip install --require-hashes --only-binary=:all: -r <this file>")
print()

for name, version in pins:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url) as fh:  # noqa: S310 - fixed https host
        data = json.load(fh)
    hashes = sorted(
        {
            f["digests"]["sha256"]
            for f in data["urls"]
            if f["packagetype"] in ("bdist_wheel", "sdist")
        }
    )
    if not hashes:
        raise SystemExit(f"no distributions found for {name}=={version}")
    lines = [f"{name}=={version}"] + [f"--hash=sha256:{h}" for h in hashes]
    print(" \\\n    ".join(lines))
