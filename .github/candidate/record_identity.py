"""Record the loaded candidate's original config bytes, never a Docker store ID."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def platform(value):
    result = "/".join(value.get(key, "") for key in ("os", "architecture", "variant"))
    result = result.rstrip("/")
    if not re.fullmatch(r"[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?", result):
        raise ValueError("invalid image platform")
    return result


def archive_config(path, expected_platform, expected_revision):
    with tarfile.open(path) as archive:

        def read(name):
            members = [member for member in archive.getmembers() if member.name == name]
            if len(members) != 1 or not members[0].isreg():
                raise ValueError("archive member absent, duplicated or not regular")
            if not 0 < members[0].size <= 4 * 1024 * 1024:
                raise ValueError("archive member exceeds JSON bound")
            return archive.extractfile(members[0]).read()

        manifest = json.loads(read("manifest.json"))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("archive must contain exactly one image")
        name = manifest[0]["Config"]
        if not isinstance(name, str) or not re.fullmatch(
            r"(?:[0-9a-f]{64}\.json|blobs/sha256/[0-9a-f]{64})", name
        ):
            raise ValueError("invalid config path")
        raw = read(name)
        if hashlib.sha256(raw).hexdigest() != name.removesuffix(".json").split("/")[-1]:
            raise ValueError("config bytes differ from their archive digest")
        config = json.loads(raw)
        if platform(config) != expected_platform:
            raise ValueError("archive platform differs from inspected platform")
        if (
            config["config"]["Labels"].get("org.opencontainers.image.revision")
            != expected_revision
        ):
            raise ValueError("archive revision differs from selected revision")
        rootfs = config["rootfs"]
        layers = rootfs["diff_ids"]
        if rootfs["type"] != "layers" or not isinstance(layers, list) or not layers:
            raise ValueError("invalid saved config rootfs")
        if not all(
            isinstance(layer, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", layer)
            for layer in layers
        ):
            raise ValueError("invalid saved config layer digest")
        return digest(raw), layers


def docker(*args):
    return subprocess.check_output(["docker", *args])  # noqa: S603,S607 -- fixed CLI, argv only


def main(image, revision):
    (inspected,) = json.loads(docker("image", "inspect", image))
    selected = platform({key.lower(): value for key, value in inspected.items()})
    if (
        not re.fullmatch(r"[0-9a-f]{40}", revision)
        or inspected["Config"]["Labels"].get("org.opencontainers.image.revision")
        != revision
    ):
        raise ValueError("candidate source revision differs from selected revision")
    with tempfile.TemporaryDirectory(prefix="candidate-identity-") as directory:
        path = Path(directory) / "image.tar"
        docker("image", "save", "--platform", selected, "-o", str(path), image)
        config_digest, layers = archive_config(path, selected, revision)
    if layers != inspected["RootFS"]["Layers"] or not isinstance(layers, list):
        raise ValueError("saved config layers differ from inspected layers")
    distributions_raw = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "cat",
        image,
        "/app/distributions.json",
    )
    distributions = json.loads(distributions_raw)
    files = distributions["files"]
    if not (
        len(files) >= 2
        and any(f["filename"].endswith(".whl") for f in files)
        and any(f["filename"].endswith(".tar.gz") for f in files)
        and all(re.fullmatch(r"sha256:[0-9a-f]{64}", f["sha256"]) for f in files)
    ):
        raise ValueError("invalid installed distribution digests")
    identity = dict(
        source_revision=revision,
        config_digest=config_digest,
        platform=selected,
        layers=layers,
        rootfs_chain=digest(compact(layers).encode()),
        lock_digest=digest(Path("poetry.lock").read_bytes()),
        dockerfile_digest=digest(Path("Dockerfile").read_bytes()),
        distributions=distributions,
    )
    encoded = compact(identity)
    Path("candidate-distributions.json").write_bytes(distributions_raw)
    Path("candidate-identity.json").write_text(encoded + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(
            "".join(
                f"{key}={value}\n"
                for key, value in identity.items()
                if key not in {"layers", "distributions"}
            )
        )
        output.write(f"identity_json={encoded}\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
