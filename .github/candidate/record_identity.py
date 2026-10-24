"""Record the loaded candidate's original config bytes, never a Docker store ID."""

import gzip
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


def archive_oci_coordinate(path, expected_platform, expected_revision):
    """Read a genuine saved OCI manifest; never invent one from a config ID.

    This coordinate belongs to the local acceptance export. Publication may
    construct a different index; the release recorder independently joins its
    config and uncompressed layer identities.
    """
    config_digest, diff_ids = archive_config(path, expected_platform, expected_revision)
    with tarfile.open(path) as archive:
        members = {}
        for member in archive.getmembers():
            if member.name in members:
                raise ValueError("duplicate OCI archive member")
            members[member.name] = member

        def raw(name, *, bound=4 * 1024 * 1024):
            member = members.get(name)
            if member is None or not member.isreg() or not 0 < member.size <= bound:
                raise ValueError("invalid or absent OCI archive member")
            return archive.extractfile(member).read()

        if json.loads(raw("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("unsupported OCI layout")

        def blob(descriptor, *, json_blob=True):
            checksum, size = descriptor["digest"], descriptor["size"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
                raise ValueError("invalid OCI descriptor digest")
            member = members.get("blobs/sha256/" + checksum[7:])
            if (
                member is None
                or not member.isreg()
                or type(size) is not int
                or member.size != size
                or size <= 0
            ):
                raise ValueError("OCI descriptor size/member mismatch")
            measured = hashlib.sha256()
            with archive.extractfile(member) as stream:
                while piece := stream.read(1024 * 1024):
                    measured.update(piece)
            if "sha256:" + measured.hexdigest() != checksum:
                raise ValueError("OCI descriptor digest mismatch")
            return json.loads(raw(member.name)) if json_blob else None

        index = json.loads(raw("index.json"))
        if index.get("schemaVersion") != 2:
            raise ValueError("invalid OCI index")
        candidates = []

        def visit(descriptor, depth=0):
            if depth > 2:
                raise ValueError("OCI index nesting exceeds bound")
            document = blob(descriptor)
            media_type = descriptor.get("mediaType")
            if media_type in {
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            }:
                for child in document["manifests"]:
                    visit(child, depth + 1)
            elif media_type in {
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            }:
                if document.get("schemaVersion") != 2:
                    raise ValueError("invalid OCI manifest")
                config = blob(document["config"])
                if platform(config) != expected_platform:
                    return
                if document["config"]["digest"] != config_digest:
                    raise ValueError("OCI manifest/config identity mismatch")
                if (
                    "platform" in descriptor
                    and platform(descriptor["platform"]) != expected_platform
                ):
                    raise ValueError("OCI descriptor/config platform mismatch")
                layers = document["layers"]
                if len(layers) != len(diff_ids):
                    raise ValueError("OCI layer count mismatch")
                for layer, diff_id in zip(layers, diff_ids, strict=True):
                    blob(layer, json_blob=False)
                    kind = layer.get("mediaType")
                    if kind not in {
                        "application/vnd.oci.image.layer.v1.tar",
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                        "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    }:
                        raise ValueError("unsupported OCI layer encoding")
                    member = members["blobs/sha256/" + layer["digest"][7:]]
                    measured = hashlib.sha256()
                    with archive.extractfile(member) as compressed:
                        stream = (
                            gzip.GzipFile(fileobj=compressed)
                            if kind.endswith(("+gzip", ".gzip"))
                            else compressed
                        )
                        with stream:
                            while piece := stream.read(1024 * 1024):
                                measured.update(piece)
                    if "sha256:" + measured.hexdigest() != diff_id:
                        raise ValueError("OCI layer/config diff_id mismatch")
                candidates.append(descriptor["digest"])

        for descriptor in index["manifests"]:
            visit(descriptor)
        if len(candidates) != 1:
            raise ValueError("OCI export must select exactly one candidate manifest")
        return candidates[0], config_digest, diff_ids


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
