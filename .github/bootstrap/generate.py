"""Emit a --require-hashes requirements file pinning Poetry and every
transitive dependency, resolved for THIS interpreter/platform.

Run inside a linux/amd64 cp312 container so the resolution matches the CI
runners; markers are evaluated against the running interpreter, so resolving
on macOS silently produces a different dependency set (xattr in, SecretStorage
and jeepney out).

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
print("# it must run in a linux/amd64 cp312 container).")
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
