"""Build-only installation of hash-pinned SSH artifacts on Ubuntu 24.04.

No application imports or credentials. Native dependencies are resolved by the
official Ubuntu package manager and recorded in the resulting image inventory.
The accepted image/config/layers, rather than a future rebuild, are deployed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import urllib.request

ROOT = pathlib.Path("/opt/gate0-native-build")
DESTINATIONS = {
    "openssh-server": pathlib.Path("/usr/sbin/sshd"),
    "openssh-client": pathlib.Path("/usr/bin/ssh"),
}


def main() -> None:
    pins = json.loads(pathlib.Path("/opt/openssh-ubuntu-artifacts.json").read_bytes())
    if pins["schema"] != "Gate0HostedSshArtifacts.v1":
        raise RuntimeError("invalid native artifact manifest")
    ROOT.mkdir(mode=0o700)
    dependencies: set[str] = set()
    binaries: dict[str, dict[str, str]] = {}
    packages = set()
    for item in pins["artifacts"]:
        package = item["package"]
        if (
            package not in DESTINATIONS
            or package in packages
            or item["version"] != "1:9.6p1-3ubuntu13.19"
            or item["architecture"] != "amd64"
            or not item["url"].startswith(
                "https://security.ubuntu.com/ubuntu/pool/main/o/openssh/"
            )
        ):
            raise RuntimeError("invalid native artifact coordinate")
        packages.add(package)
        with urllib.request.urlopen(item["url"], timeout=30) as response:  # noqa: S310 -- exact HTTPS prefix above
            if response.geturl() != item["url"]:
                raise RuntimeError("native artifact redirect")
            data = response.read(item["size"] + 1)
        if (
            len(data) != item["size"]
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            raise RuntimeError("native artifact mismatch")
        archive = ROOT / (package + ".deb")
        archive.write_bytes(data)
        depends = subprocess.check_output(  # noqa: S603 -- fixed build metadata tool
            ["/usr/bin/dpkg-deb", "--field", str(archive), "Depends"], timeout=10
        ).decode("ascii")
        if len(depends) > 16384:
            raise RuntimeError("native dependency metadata too large")
        for term in depends.strip().split(","):
            first = term.strip().split("|", 1)[0].strip()
            match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \([^()]+\))?", first)
            if match is None:
                raise RuntimeError("unsupported native dependency grammar")
            name = match[1]
            # Only the two pinned binaries are installed. No SFTP subsystem,
            # package service startup or generated host keys enter this image.
            if name not in {"openssh-client", "openssh-sftp-server"}:
                dependencies.add(name)
        extracted = ROOT / package
        subprocess.run(  # noqa: S603 -- verified fixed archive
            ["/usr/bin/dpkg-deb", "--extract", str(archive), str(extracted)],
            check=True,
            timeout=20,
        )
        source = extracted / item["binary_path"]
        destination = DESTINATIONS[package]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.unlink(missing_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        binaries[str(destination)] = {
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "archive_sha256": item["sha256"],
            "package_version": item["version"],
        }
    if packages != set(DESTINATIONS) or not 0 < len(dependencies) <= 64:
        raise RuntimeError("incomplete native artifact closure")
    subprocess.run(  # noqa: S603 -- closed official package names, no shell
        [
            "/usr/bin/apt-get",
            "install",
            "-y",
            "--no-install-recommends",
            *sorted(dependencies),
        ],
        check=True,
        timeout=300,
    )
    for name in ("/usr/bin/wg", "/usr/sbin/ip", "/usr/sbin/nft"):
        path = pathlib.Path(name)
        if not path.is_file():
            raise RuntimeError("missing native launch tool")
        # The runtime opens fixed binaries with O_NOFOLLOW. Ubuntu may ship
        # /usr/sbin/ip as a compatibility symlink; materialize its measured
        # package bytes at the fixed path in this role image only.
        if path.is_symlink():
            target = path.resolve(strict=True)
            path.unlink()
            shutil.copyfile(target, path)
            path.chmod(0o755)
        binaries[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    installed = subprocess.check_output(  # noqa: S603 -- fixed public inventory
        ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"], timeout=20
    ).decode("utf-8")
    pathlib.Path("/app/gate0_native_tools.json").write_text(
        json.dumps(
            {
                "schema": "Gate0NativeTools.v1",
                "binaries": binaries,
                "packages": installed,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
