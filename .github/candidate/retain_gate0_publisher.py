"""Private runtime packaging primitives; production entrypoint is fail-closed.

These functions do not establish origin, operational approval, retained-artifact
acceptance, or native qualification. No production certificate is embedded here.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from types import MappingProxyType
from typing import BinaryIO

DESIGN_SHA256 = "f32f50a82f05ee17ccd5980c72417c3f2ac45351489686c4e9652ef5c4cdaa58"
CERTIFICATE_SHA256 = "c90ee5dfe344d7b992d35e191946efa85ef1781827ccc0a5cb43d068079948e9"
PRIMARY_FINGERPRINT = "DD262E657C7E5E976E2CDE701D594D41EEF11AB7"
ENCRYPTION_FINGERPRINT = PRIMARY_FINGERPRINT
MAX_COMPRESSED_BYTES = 2 * 1024**3
MAX_TAR_BYTES = 8 * 1024**3
MAX_FILES_BYTES = 128 * 1024**2
MAX_METADATA_BYTES = 1024**2
MAX_CIPHERTEXT_BYTES = MAX_COMPRESSED_BYTES + 160 * 1024**2
INNER_NAMES = ("publisher-rootfs.tar.gz", "files.json", "build.json", "shape.json")


class RetentionRefused(ValueError):
    """Generic structural refusal; never expose private inputs or tool output."""


def check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline or time.time() >= getattr(
        deadline, "wall_expiry", float("inf")
    ):
        raise RetentionRefused("runtime retention refused")


def canonical_json(value: object, maximum: int) -> bytes:
    raw = (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        + b"\n"
    )
    if len(raw) > maximum:
        raise RetentionRefused("runtime retention refused")
    return raw


class DeadlineReader:
    def __init__(self, source: BinaryIO, deadline: float) -> None:
        self.source = source
        self.deadline = deadline

    def read(self, size: int) -> bytes:
        check_deadline(self.deadline)
        return self.source.read(size)


def compress_inspected_rootfs(
    source: BinaryIO, output: BinaryIO, expected_sha256: str, deadline: float
) -> dict[str, int | str]:
    """Compress the held inspected export once, never re-export or rebuild it."""
    source.seek(0)
    source_hash = hashlib.sha256()
    source_bytes = 0
    with gzip.GzipFile(
        fileobj=output, mode="wb", filename="", mtime=0, compresslevel=6
    ) as compressor:
        while block := source.read(1024 * 1024):
            check_deadline(deadline)
            source_bytes += len(block)
            if source_bytes > MAX_TAR_BYTES:
                raise RetentionRefused("runtime retention refused")
            source_hash.update(block)
            compressor.write(block)
            if output.tell() > MAX_COMPRESSED_BYTES:
                raise RetentionRefused("runtime retention refused")
    check_deadline(deadline)
    compressed_bytes = output.tell()
    if (
        source_hash.hexdigest() != expected_sha256
        or compressed_bytes > MAX_COMPRESSED_BYTES
    ):
        raise RetentionRefused("runtime retention refused")
    output.flush()
    output.seek(0)
    compressed_hash = hashlib.sha256()
    while block := output.read(1024 * 1024):
        check_deadline(deadline)
        compressed_hash.update(block)
    output.seek(0)
    return {
        "uncompressed_sha256": source_hash.hexdigest(),
        "uncompressed_bytes": source_bytes,
        "compressed_sha256": compressed_hash.hexdigest(),
        "compressed_bytes": compressed_bytes,
    }


def _write_inner_archive(
    output: BinaryIO,
    rootfs: BinaryIO,
    compressed_bytes: int,
    files: bytes,
    build: bytes,
    shape: bytes,
    deadline: float,
    *,
    role: bool,
) -> None:
    """Exactly four deterministic members; build manifest has no future hashes."""
    if not 0 < compressed_bytes <= MAX_COMPRESSED_BYTES or any(
        len(raw) > maximum
        for raw, maximum in (
            (files, MAX_FILES_BYTES),
            (build, MAX_METADATA_BYTES),
            (shape, MAX_METADATA_BYTES),
        )
    ):
        raise RetentionRefused("runtime retention refused")
    names = ROLE_INNER_NAMES if role else INNER_NAMES
    rootfs.seek(0)
    with tarfile.open(
        fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT
    ) as archive:
        for name, source, size in (
            (names[0], rootfs, compressed_bytes),
            (names[1], io.BytesIO(files), len(files)),
            (names[2], io.BytesIO(build), len(build)),
            (names[3], io.BytesIO(shape), len(shape)),
        ):
            check_deadline(deadline)
            item = tarfile.TarInfo(name)
            item.mode, item.uid, item.gid, item.mtime = 0o600, 0, 0, 0
            item.size = size
            archive.addfile(item, DeadlineReader(source, deadline))
    check_deadline(deadline)


def write_inner_archive(
    output, rootfs, compressed_bytes, files, build, shape, deadline
):
    return _write_inner_archive(
        output, rootfs, compressed_bytes, files, build, shape, deadline, role=False
    )


def write_role_inner_archive(
    output, rootfs, compressed_bytes, files, build, qualification, deadline
):
    return _write_inner_archive(
        output,
        rootfs,
        compressed_bytes,
        files,
        build,
        qualification,
        deadline,
        role=True,
    )


# Fixed production selection. No command, recipient or destination is caller chosen.
REPOSITORY = "michaelayoade/dotmac_platform_control_plane"
WORKFLOW = ".github/workflows/ci.yml"
BASE_IMAGE = (
    "python:3.12-slim@sha256:"
    "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
SOURCE_FILES = {
    "dockerfile_sha256": "Dockerfile",
    "pyproject_sha256": "pyproject.toml",
    "poetry_lock_sha256": "poetry.lock",
    "prepare_helper_sha256": ".github/candidate/prepare_gate0_publisher.py",
    "inspect_helper_sha256": ".github/candidate/inspect_gate0_publisher.py",
    "retention_helper_sha256": ".github/candidate/retain_gate0_publisher.py",
}
LIMITS = {
    "rootfs_compressed_bytes": MAX_COMPRESSED_BYTES,
    "rootfs_uncompressed_bytes": MAX_TAR_BYTES,
    "rootfs_members": 250_000,
    "regular_member_bytes": 512 * 1024**2,
    "files_manifest_bytes": MAX_FILES_BYTES,
}


ROLE_SCHEMA = "DotmacRoleRuntimeQualificationRetentionExecution.v1"
ROLE_PURPOSE = "private-native-qualification-input-only"
ROLE_WORKFLOW = ".github/workflows/gate0-sshd-conformance.yml"
ROLE_BASE_IMAGE = (
    "ubuntu:24.04@sha256:"
    "f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b"
)
ROLE_SOURCE_FILES = MappingProxyType(
    {
        "dockerfile_sha256": "Dockerfile",
        "pyproject_sha256": "pyproject.toml",
        "poetry_lock_sha256": "poetry.lock",
        "prepare_helper_sha256": ".github/candidate/prepare_gate0_native.py",
        "native_artifacts_sha256": "conformance/openssh-ubuntu-artifacts.json",
        "inspect_helper_sha256": ".github/candidate/inspect_gate0_publisher.py",
        "retention_helper_sha256": ".github/candidate/retain_gate0_publisher.py",
        "smoke_helper_sha256": "conformance/gate0_role_image_smoke.py",
        "network_wrapper_sha256": ".github/candidate/accept_gate0_network.sh",
        "network_proof_sha256": "conformance/test_gate0_network_privileges.py",
    }
)
ROLE_INNER_NAMES = (
    "role-rootfs.tar.gz",
    "files.json",
    "build.json",
    "qualification.json",
)


def closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise RetentionRefused("runtime retention refused")
    return value


def positive(value):
    if type(value) is not int or value <= 0:
        raise RetentionRefused("runtime retention refused")
    return value


def sha256(value):
    import re

    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RetentionRefused("runtime retention refused")
    return value


def utc(value):
    import datetime
    import re

    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None
    ):
        raise RetentionRefused("runtime retention refused")
    return (
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=datetime.UTC)
        .timestamp()
    )


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RetentionRefused("runtime retention refused")
        result[key] = value
    return result


def parse_json(raw, maximum):
    if len(raw) > maximum:
        raise RetentionRefused("runtime retention refused")
    return json.loads(
        raw,
        object_pairs_hook=no_duplicate_keys,
        parse_constant=lambda _: (_ for _ in ()).throw(
            RetentionRefused("runtime retention refused")
        ),
    )


def _load_packet(raw, selected_sha256, now, *, role):
    import re

    if hashlib.sha256(raw).hexdigest() != sha256(selected_sha256):
        raise RetentionRefused("runtime retention refused")
    packet = closed(
        parse_json(raw, 16 * 1024),
        (
            "schema",
            "operation",
            *(("purpose",) if role else ()),
            "source",
            "github",
            "validity",
            "recipient",
            "tool_qualification_sha256",
            "build",
            "limits",
            "artifact",
        ),
    )
    if raw != canonical_json(packet, 16 * 1024):
        raise RetentionRefused("runtime retention refused")
    if (
        packet["schema"]
        != (ROLE_SCHEMA if role else "DotmacPublisherRuntimeRetentionExecution.v1")
        or (role and packet["purpose"] != ROLE_PURPOSE)
        or packet["operation"] != "build-inspect-encrypt-retain"
    ):
        raise RetentionRefused("runtime retention refused")
    source = closed(
        packet["source"],
        ("revision", "ref", "workflow_path", "workflow_blob_sha256", "files"),
    )
    if (
        not isinstance(source["revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", source["revision"]) is None
    ):
        raise RetentionRefused("runtime retention refused")
    if (
        not isinstance(source["ref"], str)
        or re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", source["ref"])
        is None
        or ".." in source["ref"]
    ):
        raise RetentionRefused("runtime retention refused")
    if source["workflow_path"] != (ROLE_WORKFLOW if role else WORKFLOW):
        raise RetentionRefused("runtime retention refused")
    sha256(source["workflow_blob_sha256"])
    for value in closed(
        source["files"], ROLE_SOURCE_FILES if role else SOURCE_FILES
    ).values():
        sha256(value)
    github = closed(
        packet["github"],
        (
            "repository",
            "repository_id",
            "owner_id",
            "workflow_id",
            "actor_id",
            "job_key",
        ),
    )
    if github["repository"] != REPOSITORY or github["job_key"] != (
        "role-image" if role else "image"
    ):
        raise RetentionRefused("runtime retention refused")
    for key in ("repository_id", "owner_id", "workflow_id", "actor_id"):
        positive(github[key])
    validity = closed(packet["validity"], ("not_before", "expires_at"))
    if not utc(validity["not_before"]) <= now < utc(validity["expires_at"]):
        raise RetentionRefused("runtime retention refused")
    recipient = closed(
        packet["recipient"],
        ("certificate_sha256", "primary_fingerprint", "encryption_fingerprint"),
    )
    if recipient != {
        "certificate_sha256": CERTIFICATE_SHA256,
        "primary_fingerprint": PRIMARY_FINGERPRINT,
        "encryption_fingerprint": ENCRYPTION_FINGERPRINT,
    }:
        raise RetentionRefused("runtime retention refused")
    sha256(packet["tool_qualification_sha256"])
    expected_build = {
        "mode": "build-once-in-selected-job",
        "platform": "linux/amd64",
        "base_image": ROLE_BASE_IMAGE if role else BASE_IMAGE,
        **(
            {"target": "gate0-role"}
            if role
            else {"production_target": "runtime", "publisher_target": "gate0-publisher"}
        ),
    }
    if closed(packet["build"], expected_build) != expected_build:
        raise RetentionRefused("runtime retention refused")
    for key, value in closed(packet["limits"], LIMITS).items():
        if positive(value) > LIMITS[key]:
            raise RetentionRefused("runtime retention refused")
    if closed(packet["artifact"], ("name", "retention_days", "files")) != {
        "name": "gate0-role-qualification-runtime"
        if role
        else "gate0-publisher-runtime",
        "retention_days": 30,
        "files": ["encrypted-runtime-bundle.pgp", "producer-receipt.json"],
    }:
        raise RetentionRefused("runtime retention refused")
    return packet


def load_packet(raw, selected_sha256, now):
    return _load_packet(raw, selected_sha256, now, role=False)


def load_role_packet(raw, selected_sha256, now):
    return _load_packet(raw, selected_sha256, now, role=True)


def run_bounded(
    arguments,
    deadline,
    *,
    environment=None,
    stdin=None,
    cipher_output=None,
    maximum=1024**2,
):
    import os
    import selectors
    import subprocess

    check_deadline(deadline)
    environment = environment or {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    reader = writer = None
    if cipher_output is not None:
        reader, writer = os.pipe()
        arguments = [*arguments, "--status-fd", str(writer)]
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 -- all production callers use fixed executables and arguments
            arguments,
            stdin=stdin or subprocess.DEVNULL,
            stdout=cipher_output if cipher_output is not None else subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            pass_fds=(writer,) if writer is not None else (),
        )
        if writer is not None:
            os.close(writer)
            writer = None
        channel = (
            os.fdopen(reader, "rb", buffering=0)
            if reader is not None
            else process.stdout
        )
        reader = None
        result = bytearray()
        with channel, selectors.DefaultSelector() as selector:
            selector.register(channel, selectors.EVENT_READ)
            while selector.get_map():
                check_deadline(deadline)
                for key, _ in selector.select(
                    min(0.25, max(0, deadline - time.monotonic()))
                ):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        result.extend(block)
                        if len(result) > maximum:
                            raise RetentionRefused("runtime retention refused")
                if (
                    cipher_output is not None
                    and os.fstat(cipher_output.fileno()).st_size > MAX_CIPHERTEXT_BYTES
                ):
                    raise RetentionRefused("runtime retention refused")
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise RetentionRefused("runtime retention refused")
        return bytes(result)
    finally:
        for descriptor in (reader, writer):
            if descriptor is not None:
                os.close(descriptor)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def api_json(path, token, deadline):
    import urllib.request

    check_deadline(deadline)
    if not path.startswith("/repos/" + REPOSITORY + "/") or ".." in path:
        raise RetentionRefused("runtime retention refused")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dotmac-publisher-retention",
        },
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise RetentionRefused("runtime retention refused")

    with urllib.request.build_opener(NoRedirect()).open(
        request, timeout=min(20, max(0.001, deadline - time.monotonic()))
    ) as response:
        raw = response.read(2 * 1024**2 + 1)
    return parse_json(raw, 2 * 1024**2)


def read_owned_regular(path, maximum, *, private):
    import os
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and not info.st_mode & (0o077 if private else 0o022)
            and 0 < info.st_size <= maximum
        ):
            raise RetentionRefused("runtime retention refused")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise RetentionRefused("runtime retention refused")
        return raw


def _authenticate_context(packet, environment, repository_root, deadline, *, role):
    import base64
    import re
    import urllib.parse

    workflow_path = ROLE_WORKFLOW if role else WORKFLOW
    source_files = ROLE_SOURCE_FILES if role else SOURCE_FILES
    job_key = "role-image" if role else "image"
    if (
        environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_RUN_ATTEMPT") != "1"
        or environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or environment.get("GITHUB_JOB") != job_key
    ):
        raise RetentionRefused("runtime retention refused")
    source = packet["source"]
    if (
        environment.get("GITHUB_SHA") != source["revision"]
        or environment.get("GITHUB_REF") != source["ref"]
    ):
        raise RetentionRefused("runtime retention refused")
    if (
        environment.get("GITHUB_WORKFLOW_SHA") != source["revision"]
        or environment.get("GITHUB_WORKFLOW_REF")
        != REPOSITORY + "/" + workflow_path + "@" + source["ref"]
    ):
        raise RetentionRefused("runtime retention refused")
    run_id_text = environment.get("GITHUB_RUN_ID", "")
    if re.fullmatch(r"[1-9][0-9]{0,19}", run_id_text) is None:
        raise RetentionRefused("runtime retention refused")
    token = environment.get("GITHUB_TOKEN", "")
    if not token:
        raise RetentionRefused("runtime retention refused")
    head = (
        run_bounded(
            ["/usr/bin/git", "-C", str(repository_root), "rev-parse", "HEAD"], deadline
        )
        .decode("ascii")
        .strip()
    )
    if head != source["revision"]:
        raise RetentionRefused("runtime retention refused")
    for key, relative in {
        "workflow_blob_sha256": workflow_path,
        **source_files,
    }.items():
        path = repository_root / relative
        for parent in path.parents:
            if parent == repository_root:
                break
            if parent.is_symlink() or not parent.is_dir():
                raise RetentionRefused("runtime retention refused")
        raw = read_owned_regular(path, 16 * 1024**2, private=False)
        expected = (
            source[key] if key == "workflow_blob_sha256" else source["files"][key]
        )
        if hashlib.sha256(raw).hexdigest() != expected:
            raise RetentionRefused("runtime retention refused")
    prefix = "/repos/" + REPOSITORY
    run = api_json(prefix + "/actions/runs/" + run_id_text, token, deadline)
    github = packet["github"]
    if (
        run["id"] != int(run_id_text)
        or run["run_attempt"] != 1
        or run["event"] != "workflow_dispatch"
        or run["head_sha"] != source["revision"]
        or run["head_branch"] != source["ref"].removeprefix("refs/heads/")
        or run["repository"]["full_name"] != REPOSITORY
        or run["head_repository"]["full_name"] != REPOSITORY
        or run["repository"]["id"] != github["repository_id"]
        or run["repository"]["owner"]["id"] != github["owner_id"]
        or run["workflow_id"] != github["workflow_id"]
        or run["actor"]["id"] != github["actor_id"]
        or run["triggering_actor"]["id"] != github["actor_id"]
    ):
        raise RetentionRefused("runtime retention refused")
    workflow = api_json(
        prefix + "/actions/workflows/" + str(github["workflow_id"]), token, deadline
    )
    if workflow["id"] != github["workflow_id"] or workflow["path"] != workflow_path:
        raise RetentionRefused("runtime retention refused")
    remote = api_json(
        prefix
        + "/contents/"
        + workflow_path
        + "?ref="
        + urllib.parse.quote(source["revision"], safe=""),
        token,
        deadline,
    )
    if (
        remote["type"] != "file"
        or remote["encoding"] != "base64"
        or hashlib.sha256(
            base64.b64decode(remote["content"], validate=False)
        ).hexdigest()
        != source["workflow_blob_sha256"]
    ):
        raise RetentionRefused("runtime retention refused")
    jobs = api_json(
        prefix + "/actions/runs/" + run_id_text + "/attempts/1/jobs?per_page=100",
        token,
        deadline,
    )
    if jobs["total_count"] != len(jobs["jobs"]) or len(jobs["jobs"]) > 100:
        raise RetentionRefused("runtime retention refused")
    selected = [job for job in jobs["jobs"] if job["name"] == job_key]
    if (
        len(selected) != 1
        or selected[0]["run_id"] != int(run_id_text)
        or (
            "run_attempt" in selected[0]
            and (
                type(selected[0]["run_attempt"]) is not int
                or selected[0]["run_attempt"] != 1
            )
        )
        or selected[0]["head_sha"] != source["revision"]
        or selected[0]["status"] != "in_progress"
    ):
        raise RetentionRefused("runtime retention refused")
    return {
        "repository_id": github["repository_id"],
        "owner_id": github["owner_id"],
        "workflow_id": github["workflow_id"],
        "actor_id": github["actor_id"],
        "run_id": int(run_id_text),
        "attempt": 1,
        "job_id": positive(selected[0]["id"]),
    }


def authenticate_context(packet, environment, repository_root, deadline):
    return _authenticate_context(
        packet, environment, repository_root, deadline, role=False
    )


def authenticate_role_context(packet, environment, repository_root, deadline):
    return _authenticate_context(
        packet, environment, repository_root, deadline, role=True
    )


def ascii_field(value, maximum=200):
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= maximum
        or any(not 32 <= ord(c) < 127 for c in value)
    ):
        raise RetentionRefused("runtime retention refused")
    return value


def _qualify_tools(raw, expected_digest, now, deadline, *, role):
    import os
    import platform
    import re
    import stat
    from pathlib import Path

    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise RetentionRefused("runtime retention refused")
    record = closed(
        parse_json(raw, 64 * 1024),
        (
            "schema",
            "method_scope",
            "qualified_at",
            "valid_until",
            "operating_system",
            "tools",
            "packages",
            "measurements_sha256",
            "reviewer_record_sha256",
        ),
    )
    if (
        record["schema"]
        != (
            "DotmacRoleRuntimeGpgQualification.v1"
            if role
            else "DotmacPublisherRuntimeGpgQualification.v1"
        )
        or record["method_scope"]
        != (
            "role-runtime-public-key-encryption.v1"
            if role
            else "publisher-runtime-public-key-encryption.v1"
        )
        or not utc(record["qualified_at"]) <= now < utc(record["valid_until"])
    ):
        raise RetentionRefused("runtime retention refused")
    sha256(record["measurements_sha256"])
    sha256(record["reviewer_record_sha256"])
    operating = closed(record["operating_system"], ("id", "version_id", "architecture"))
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or operating["architecture"] != "amd64"
    ):
        raise RetentionRefused("runtime retention refused")
    values = {}
    with Path("/etc/os-release").open(encoding="ascii") as stream:
        for line in stream.read(16385).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
    if any(
        ascii_field(operating[key], 64) != values[key.upper()]
        for key in ("id", "version_id")
    ):
        raise RetentionRefused("runtime retention refused")
    for name, pin in closed(record["tools"], ("gpg", "gpgconf")).items():
        pin = closed(pin, ("path", "sha256", "version_line"))
        path = Path("/usr/bin") / name
        if pin["path"] != str(path):
            raise RetentionRefused("runtime retention refused")
        for parent in (path, *path.parents):
            info = parent.lstat()
            if (
                info.st_uid != 0
                or info.st_mode & 0o022
                or (parent == path and not stat.S_ISREG(info.st_mode))
                or (parent != path and not stat.S_ISDIR(info.st_mode))
            ):
                raise RetentionRefused("runtime retention refused")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            if not 0 < os.fstat(
                stream.fileno()
            ).st_size <= 32 * 1024**2 or hashlib.sha256(
                stream.read(32 * 1024**2 + 1)
            ).hexdigest() != sha256(pin["sha256"]):
                raise RetentionRefused("runtime retention refused")
        version = (
            run_bounded(
                [str(path), "--no-options", "--version"]
                if name == "gpg"
                else [str(path), "--version"],
                min(deadline, time.monotonic() + 10),
                maximum=16384,
            )
            .decode("ascii")
            .splitlines()[0]
        )
        if version != ascii_field(pin["version_line"], 128):
            raise RetentionRefused("runtime retention refused")
    packages = record["packages"]
    if not isinstance(packages, list) or not 2 <= len(packages) <= 32:
        raise RetentionRefused("runtime retention refused")
    names = []
    for package in packages:
        package = closed(package, ("name", "version", "architecture"))
        name = ascii_field(package["name"], 100)
        if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) is None or package[
            "architecture"
        ] not in {"amd64", "all"}:
            raise RetentionRefused("runtime retention refused")
        names.append(name)
        expected = (
            name
            + "\t"
            + ascii_field(package["version"], 128)
            + "\t"
            + package["architecture"]
        )
        actual = run_bounded(
            [
                "/usr/bin/dpkg-query",
                "--show",
                "--showformat=${Package}\t${Version}\t${Architecture}",
                name,
            ],
            min(deadline, time.monotonic() + 10),
            maximum=4096,
        ).decode("ascii")
        if actual != expected or run_bounded(
            ["/usr/bin/dpkg", "--verify", name],
            min(deadline, time.monotonic() + 10),
            maximum=16384,
        ):
            raise RetentionRefused("runtime retention refused")
    if names != sorted(set(names)) or not {"gpg", "gpgconf"} <= set(names):
        raise RetentionRefused("runtime retention refused")
    return record


def qualify_tools(raw, expected_digest, now, deadline):
    return _qualify_tools(raw, expected_digest, now, deadline, role=False)


def qualify_role_tools(raw, expected_digest, now, deadline):
    return _qualify_tools(raw, expected_digest, now, deadline, role=True)


def packet_header(stream):
    first = stream.read(1)
    if len(first) != 1 or not first[0] & 0x80:
        raise RetentionRefused("runtime retention refused")
    if first[0] & 0x40:
        size, partial = packet_length(stream)
        return first[0] & 63, size, partial
    length_type = first[0] & 3
    if length_type == 3:
        raise RetentionRefused("runtime retention refused")
    raw = read_exact(stream, 1 << length_type)
    return (first[0] >> 2) & 15, int.from_bytes(raw, "big"), False


def packet_length(stream):
    raw = stream.read(1)
    if not raw:
        raise RetentionRefused("runtime retention refused")
    first = raw[0]
    if first < 192:
        return first, False
    if first < 224:
        second = stream.read(1)
        if not second:
            raise RetentionRefused("runtime retention refused")
        return ((first - 192) << 8) + second[0] + 192, False
    if first == 255:
        raw = stream.read(4)
        if len(raw) != 4:
            raise RetentionRefused("runtime retention refused")
        return int.from_bytes(raw, "big"), False
    return 1 << (first & 31), True


def read_exact(stream, size):
    raw = stream.read(size)
    if len(raw) != size:
        raise RetentionRefused("runtime retention refused")
    return raw


def verify_ciphertext_framing(stream, recipient_fingerprint, deadline):
    """Runtime-size streaming framing, independent of the proof's 16-MiB API."""
    stream.seek(0)
    tag, size, partial = packet_header(stream)
    if tag != 1 or partial or not 12 <= size <= 16384:
        raise RetentionRefused("runtime retention refused")
    body = io.BytesIO(read_exact(stream, size))
    if (
        read_exact(body, 1) != b"\x03"
        or read_exact(body, 8).hex().upper() != recipient_fingerprint[-16:]
    ):
        raise RetentionRefused("runtime retention refused")
    algorithm = read_exact(body, 1)[0]

    def mpi():
        bits = int.from_bytes(read_exact(body, 2), "big")
        value = read_exact(body, (bits + 7) // 8)
        if not bits or not value or value[0].bit_length() != (bits - 1) % 8 + 1:
            raise RetentionRefused("runtime retention refused")

    if algorithm in {1, 2, 3}:
        mpi()
    elif algorithm == 16:
        mpi()
        mpi()
    elif algorithm == 18:
        mpi()
        read_exact(body, read_exact(body, 1)[0])
    else:
        raise RetentionRefused("runtime retention refused")
    if body.read(1):
        raise RetentionRefused("runtime retention refused")
    tag, size, partial = packet_header(stream)
    if tag != 18 or size < 1 or read_exact(stream, 1) != b"\x01":
        raise RetentionRefused("runtime retention refused")
    consumed = 1
    remaining = size - 1
    while True:
        while remaining:
            check_deadline(deadline)
            block = read_exact(stream, min(remaining, 1024**2))
            consumed += len(block)
            remaining -= len(block)
            if consumed > MAX_CIPHERTEXT_BYTES:
                raise RetentionRefused("runtime retention refused")
        if not partial:
            break
        remaining, partial = packet_length(stream)
    if consumed < 40 or stream.read(1):
        raise RetentionRefused("runtime retention refused")
    stream.seek(0)


def certificate_packet_shape(raw):
    stream = io.BytesIO(raw)
    primary = 0
    while stream.tell() < len(raw):
        tag, size, partial = packet_header(stream)
        if partial or tag not in {2, 6, 13} or not 0 < size <= 64 * 1024:
            raise RetentionRefused("runtime retention refused")
        read_exact(stream, size)
        primary += tag == 6
    if primary != 1:
        raise RetentionRefused("runtime retention refused")


def checked_encrypt(
    public_certificate,
    primary_fingerprint,
    encryption_fingerprint,
    home,
    payload,
    cipher,
    deadline,
):
    """Internal synthetic profile seam; production supplies fixed constants only."""
    certificate_packet_shape(public_certificate)
    certificate_path = home / "public-certificate.pgp"
    import os

    descriptor = os.open(
        certificate_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(public_certificate)
    common = [
        "/usr/bin/gpg",
        "--no-options",
        "--homedir",
        str(home),
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-auto-key-retrieve",
        "--auto-key-locate",
        "clear",
        "--no-auto-check-trustdb",
    ]
    status = run_bounded(
        [*common, "--status-fd", "1", "--import", str(certificate_path)],
        deadline,
        maximum=65536,
    )
    if (
        b"[GNUPG:] IMPORT_OK " not in status
        or primary_fingerprint.encode() not in status
        or any(marker in status for marker in (b"IMPORT_PROBLEM", b"FAILURE", b"ERROR"))
    ):
        raise RetentionRefused("runtime retention refused")
    records = (
        run_bounded(
            [
                *common,
                "--with-colons",
                "--fixed-list-mode",
                "--with-fingerprint",
                "--check-sigs",
                primary_fingerprint,
            ],
            deadline,
            maximum=65536,
        )
        .decode("ascii")
        .splitlines()
    )
    pubs = [line.split(":") for line in records if line.startswith("pub:")]
    fingerprints = [line.split(":")[9] for line in records if line.startswith("fpr:")]
    signatures = [line.split(":") for line in records if line.startswith("sig:")]
    if (
        len(pubs) != 1
        or fingerprints != [primary_fingerprint]
        or any(line.startswith(("sub:", "sec:", "ssb:")) for line in records)
    ):
        raise RetentionRefused("runtime retention refused")
    pub = pubs[0]
    if (
        pub[1] in {"r", "e", "d", "i"}
        or "e" not in pub[11].lower()
        or (pub[6] and int(pub[6]) <= time.time())
    ):
        raise RetentionRefused("runtime retention refused")
    if not any(
        sig[1] == "!"
        and sig[4].upper() == primary_fingerprint[-16:]
        and sig[10][:2] in {"10", "11", "12", "13", "1f"}
        for sig in signatures
    ) or any(sig[10][:2] in {"20", "28"} for sig in signatures):
        raise RetentionRefused("runtime retention refused")
    payload.seek(0)
    status = run_bounded(
        [
            *common,
            "--trust-model",
            "always",
            "--no-encrypt-to",
            "--cipher-algo",
            "AES256",
            "--compress-algo",
            "none",
            "--force-mdc",
            "--recipient",
            encryption_fingerprint + "!",
            "--output",
            "-",
            "--encrypt",
        ],
        deadline,
        stdin=payload,
        cipher_output=cipher,
        maximum=65536,
    )
    if (
        b"[GNUPG:] BEGIN_ENCRYPTION 2 9" not in status
        or b"[GNUPG:] END_ENCRYPTION" not in status
        or any(marker in status for marker in (b"FAILURE", b"ERROR", b"INV_RECP"))
    ):
        raise RetentionRefused("runtime retention refused")
    cipher.flush()
    verify_ciphertext_framing(cipher, encryption_fingerprint, deadline)


def image_identity(raw, reference, target, revision, base_diff_ids=None):
    document = parse_json(raw, 1024**2)
    if not isinstance(document, list) or len(document) != 1:
        raise RetentionRefused("runtime retention refused")
    image = document[0]
    identity = image["Id"]
    if not isinstance(identity, str) or not identity.startswith("sha256:"):
        raise RetentionRefused("runtime retention refused")
    sha256(identity.removeprefix("sha256:"))
    diff_ids = image["RootFS"]["Layers"]
    if (
        image["Architecture"] != "amd64"
        or image["Os"] != "linux"
        or image["RootFS"]["Type"] != "layers"
        or not isinstance(diff_ids, list)
        or not 0 < len(diff_ids) <= 256
    ):
        raise RetentionRefused("runtime retention refused")
    for item in diff_ids:
        if not isinstance(item, str) or not item.startswith("sha256:"):
            raise RetentionRefused("runtime retention refused")
        sha256(item[7:])
    if target is None:
        if reference not in image["RepoDigests"]:
            raise RetentionRefused("runtime retention refused")
        return {
            "reference": reference,
            "image_id": identity,
            "rootfs_diff_ids": diff_ids,
        }
    label = image["Config"]["Labels"]["org.opencontainers.image.revision"]
    if (
        label != revision
        or diff_ids[: len(base_diff_ids)] != base_diff_ids
        or len(diff_ids) <= len(base_diff_ids)
    ):
        raise RetentionRefused("runtime retention refused")
    return {
        "target": target,
        "image_id": identity,
        "source_revision_label": label,
        "rootfs_diff_ids": diff_ids,
        "inspect_sha256": hashlib.sha256(raw).hexdigest(),
    }


class ProductionDeadline(float):
    def __new__(cls, monotonic_deadline, wall_expiry):
        instance = super().__new__(cls, monotonic_deadline)
        instance.wall_expiry = wall_expiry
        return instance


def production_main(private_argument, preflight=False):
    import base64
    import importlib.util
    import os
    import re
    import stat
    from pathlib import Path

    private = Path(private_argument)
    runner_temp = Path(os.environ["RUNNER_TEMP"])
    if (
        private.parent != runner_temp
        or re.fullmatch(r"gate0-publisher\.[A-Za-z0-9]{8}", private.name) is None
    ):
        raise RetentionRefused("runtime retention refused")
    info = private.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise RetentionRefused("runtime retention refused")
    root = Path(__file__).resolve().parents[2]
    clock = closed(
        parse_json(
            read_owned_regular(private / "packaging-clock.json", 1024, private=True),
            1024,
        ),
        ("monotonic", "wall"),
    )
    now = time.time()
    mono_now = time.monotonic()
    if (
        any(type(clock[key]) not in {int, float} for key in clock)
        or not 0 <= mono_now - clock["monotonic"] < 1200
        or not 0 <= now - clock["wall"] < 1200
    ):
        raise RetentionRefused("runtime retention refused")
    selected = os.environ.get("RETENTION_PACKET_SHA256", "")
    raw_packet = os.environ.get("RETENTION_PACKET_CONFIGURATION", "").encode()
    packet = load_packet(raw_packet, selected, now)
    deadline = ProductionDeadline(
        min(
            clock["monotonic"] + 1180,
            mono_now + utc(packet["validity"]["expires_at"]) - now,
        ),
        utc(packet["validity"]["expires_at"]),
    )
    check_deadline(deadline)
    producer = authenticate_context(packet, os.environ, root, deadline)
    # Import a sibling source owner only after its exact pinned bytes and origin
    # have been checked; absent/invalid selection never imports candidate code.
    spec = importlib.util.spec_from_file_location(
        "retention_inspector", root / SOURCE_FILES["inspect_helper_sha256"]
    )
    if spec is None or spec.loader is None:
        raise RetentionRefused("runtime retention refused")
    inspector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspector)
    qualification_raw = os.environ.get(
        "RETENTION_GPG_QUALIFICATION_CONFIGURATION", ""
    ).encode()
    qualification = qualify_tools(
        qualification_raw, packet["tool_qualification_sha256"], now, deadline
    )
    qualification_expiry = utc(qualification["valid_until"])
    deadline = ProductionDeadline(
        min(deadline, time.monotonic() + qualification_expiry - time.time()),
        min(deadline.wall_expiry, qualification_expiry),
    )
    check_deadline(deadline)
    certificate_base64 = os.environ.get("RETENTION_CERTIFICATE_CONFIGURATION", "")
    if len(certificate_base64) > 90_000:
        raise RetentionRefused("runtime retention refused")
    certificate = base64.b64decode(certificate_base64, validate=True)
    if (
        not 0 < len(certificate) <= 64 * 1024
        or hashlib.sha256(certificate).hexdigest() != CERTIFICATE_SHA256
    ):
        raise RetentionRefused("runtime retention refused")
    certificate_packet_shape(certificate)
    if preflight:
        return
    with (
        inspector.private_input(private / "publisher.tar", MAX_TAR_BYTES) as rootfs,
        inspector.private_input(
            private / "manifest.json", MAX_METADATA_BYTES
        ) as measurement_stream,
        inspector.private_input(
            private / "files.json", MAX_FILES_BYTES
        ) as files_stream,
        inspector.private_input(
            private / "shape.json", MAX_METADATA_BYTES
        ) as shape_stream,
    ):
        measurement = parse_json(
            measurement_stream.read(MAX_METADATA_BYTES + 1), MAX_METADATA_BYTES
        )
        files = files_stream.read(MAX_FILES_BYTES + 1)
        shape = shape_stream.read(MAX_METADATA_BYTES + 1)
        if (
            measurement["schema"] != "Gate0PublisherBuild.v1"
            or measurement["status"] != "runtime_NOT_RETAINED"
            or measurement["production_wheel_retained"] is not False
            or measurement["files_manifest_sha256"] != hashlib.sha256(files).hexdigest()
        ):
            raise RetentionRefused("runtime retention refused")
        # Re-inventory the same held descriptor and bind the complete bytes again.
        inspector.bounded_tar_headers(rootfs)
        with tarfile.open(fileobj=rootfs, mode="r:") as archive:
            inventory = inspector.inventory(archive, publisher=True)
            if inspector.complete_files(archive, inventory) != files:
                raise RetentionRefused("runtime retention refused")
        footprint = measurement["footprint"]
        limits = packet["limits"]
        if (
            footprint["entries"] > limits["rootfs_members"]
            or footprint["largest_member_bytes"] > limits["regular_member_bytes"]
            or footprint["publisher_tar_bytes"] > limits["rootfs_uncompressed_bytes"]
            or len(files) > limits["files_manifest_bytes"]
        ):
            raise RetentionRefused("runtime retention refused")
        selected_images = {"base": BASE_IMAGE}
        for key in ("production", "publisher"):
            with inspector.private_input(private / (key + "-image-id"), 128) as stream:
                identity = stream.read(129).decode("ascii").strip()
            if not identity.startswith("sha256:"):
                raise RetentionRefused("runtime retention refused")
            sha256(identity[7:])
            selected_images[key] = identity
        image_raw = {
            key: run_bounded(["/usr/bin/docker", "image", "inspect", name], deadline)
            for key, name in selected_images.items()
        }
        base = image_identity(image_raw["base"], BASE_IMAGE, None, None)
        images = {"base": base}
        for name, target in (
            ("production", "runtime"),
            ("publisher", "gate0-publisher"),
        ):
            images[name] = image_identity(
                image_raw[name],
                None,
                target,
                packet["source"]["revision"],
                base["rootfs_diff_ids"],
            )
        compressed_path = private / "publisher-rootfs.tar.gz"
        compressed_descriptor = os.open(
            compressed_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(compressed_descriptor, "w+b") as compressed:
            compression = compress_inspected_rootfs(
                rootfs, compressed, measurement["publisher_rootfs_sha256"], deadline
            )
            if compression["compressed_bytes"] > limits["rootfs_compressed_bytes"]:
                raise RetentionRefused("runtime retention refused")
            runtime = {
                "uncompressed_tar_sha256": compression["uncompressed_sha256"],
                "uncompressed_tar_bytes": compression["uncompressed_bytes"],
                "compressed_archive_sha256": compression["compressed_sha256"],
                "compressed_archive_bytes": compression["compressed_bytes"],
                "files_manifest_sha256": hashlib.sha256(files).hexdigest(),
                "files_manifest_bytes": len(files),
                "shape_manifest_sha256": hashlib.sha256(shape).hexdigest(),
                "shape_manifest_bytes": len(shape),
                "distribution_manifest_sha256": measurement[
                    "distribution_manifest_sha256"
                ],
                "publisher_wheel_sha256": measurement["publisher_wheel_sha256"],
                "production_wheel_retained": False,
                "comparison": (
                    "actual_manifest_installed_source_owners_and_dependency_closure"
                ),
            }
            build_source = {
                "revision": packet["source"]["revision"],
                "workflow_blob_sha256": packet["source"]["workflow_blob_sha256"],
                **packet["source"]["files"],
            }
            build = canonical_json(
                {
                    "schema": "Gate0PublisherPrivateBuild.v1",
                    "source": build_source,
                    "producer": producer,
                    "images": images,
                    "runtime": runtime,
                    "limits": limits,
                    "footprint": footprint,
                    "tool_qualification_sha256": packet["tool_qualification_sha256"],
                },
                MAX_METADATA_BYTES,
            )
            with inspector.private_output(private / "build.json") as build_stream:
                build_stream.write(build)
            payload_descriptor = os.open(
                private / "runtime-payload.tar",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(payload_descriptor, "w+b") as payload:
                write_inner_archive(
                    payload,
                    compressed,
                    compression["compressed_bytes"],
                    files,
                    build,
                    shape,
                    deadline,
                )
                payload.flush()
                if payload.tell() > MAX_CIPHERTEXT_BYTES - 1024**2:
                    raise RetentionRefused("runtime retention refused")
                home = private / "gpg-home"
                home.mkdir(mode=0o700)
                cipher_descriptor = os.open(
                    private / "encrypted-runtime-bundle.pgp.pending",
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(cipher_descriptor, "w+b") as cipher:
                    checked_encrypt(
                        certificate,
                        PRIMARY_FINGERPRINT,
                        ENCRYPTION_FINGERPRINT,
                        home,
                        payload,
                        cipher,
                        deadline,
                    )
                    cipher_bytes = os.fstat(cipher.fileno()).st_size
                    if not 0 < cipher_bytes <= MAX_CIPHERTEXT_BYTES:
                        raise RetentionRefused("runtime retention refused")
                    cipher_sha256 = inspector.stream_digest(
                        cipher, MAX_CIPHERTEXT_BYTES
                    )
                receipt = canonical_json(
                    {
                        "schema": "Gate0PublisherProducerReceipt.v1",
                        "source_revision": packet["source"]["revision"],
                        "workflow_blob_sha256": packet["source"][
                            "workflow_blob_sha256"
                        ],
                        "run_id": producer["run_id"],
                        "attempt": 1,
                        "job_id": producer["job_id"],
                        "recipient_certificate_sha256": CERTIFICATE_SHA256,
                        "recipient_encryption_fingerprint": ENCRYPTION_FINGERPRINT,
                        "encrypted_bundle_sha256": cipher_sha256,
                        "encrypted_bundle_bytes": cipher_bytes,
                        "private_manifest_sha256": hashlib.sha256(build).hexdigest(),
                    },
                    16384,
                )
                with inspector.private_output(
                    private / "producer-receipt.json.pending"
                ) as stream:
                    stream.write(receipt)
                check_deadline(deadline)
                # Completion names become eligible only after every check succeeds.
                os.link(
                    private / "encrypted-runtime-bundle.pgp.pending",
                    private / "encrypted-runtime-bundle.pgp",
                )
                os.unlink(private / "encrypted-runtime-bundle.pgp.pending")
                os.link(
                    private / "producer-receipt.json.pending",
                    private / "producer-receipt.json",
                )
                os.unlink(private / "producer-receipt.json.pending")


def role_private_directory(argument):
    import os
    import re
    import stat
    from pathlib import Path

    private = Path(argument)
    if (
        private.parent != Path(os.environ["RUNNER_TEMP"])
        or re.fullmatch(r"gate0-role\.[A-Za-z0-9]{8}", private.name) is None
    ):
        raise RetentionRefused("runtime retention refused")
    info = private.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RetentionRefused("runtime retention refused")
    return private


def role_context(private):
    """Authenticate before candidate import; original packaging clocks only."""
    import base64
    import importlib.util
    import os
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    clock = closed(
        parse_json(
            read_owned_regular(private / "packaging-clock.json", 1024, private=True),
            1024,
        ),
        ("monotonic", "wall"),
    )
    now, monotonic = time.time(), time.monotonic()
    if (
        any(type(value) not in {int, float} for value in clock.values())
        or not 0 <= monotonic - clock["monotonic"] < 1200
        or not 0 <= now - clock["wall"] < 1200
    ):
        raise RetentionRefused("runtime retention refused")
    packet = load_role_packet(
        os.environ.get("RETENTION_PACKET_CONFIGURATION", "").encode(),
        os.environ.get("RETENTION_PACKET_SHA256", ""),
        now,
    )
    expiry = utc(packet["validity"]["expires_at"])
    deadline = ProductionDeadline(
        min(clock["monotonic"] + 1180, monotonic + expiry - now),
        min(clock["wall"] + 1180, expiry),
    )
    check_deadline(deadline)
    producer = authenticate_role_context(packet, os.environ, root, deadline)
    tool = qualify_role_tools(
        os.environ.get("RETENTION_GPG_QUALIFICATION_CONFIGURATION", "").encode(),
        packet["tool_qualification_sha256"],
        now,
        deadline,
    )
    expiry = utc(tool["valid_until"])
    deadline = ProductionDeadline(
        min(deadline, time.monotonic() + expiry - time.time()),
        min(deadline.wall_expiry, expiry),
    )
    encoded = os.environ.get("RETENTION_CERTIFICATE_CONFIGURATION", "")
    if len(encoded) > 90_000:
        raise RetentionRefused("runtime retention refused")
    certificate = base64.b64decode(encoded, validate=True)
    if (
        not 0 < len(certificate) <= 64 * 1024
        or hashlib.sha256(certificate).hexdigest() != CERTIFICATE_SHA256
    ):
        raise RetentionRefused("runtime retention refused")
    certificate_packet_shape(certificate)
    spec = importlib.util.spec_from_file_location(
        "role_retention_inspector", root / ROLE_SOURCE_FILES["inspect_helper_sha256"]
    )
    if spec is None or spec.loader is None:
        raise RetentionRefused("runtime retention refused")
    inspector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inspector)
    check_deadline(deadline)
    return packet, producer, deadline, certificate, inspector


def _role_owner_record(private, name, value):
    import os

    descriptor = os.open(
        private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical_json(value, 4096))


def _read_role_owner_record(private, name):
    import os
    import stat

    descriptor = os.open(private / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= 4096
        ):
            raise RetentionRefused("runtime retention refused")
        raw = source.read(4097)
        current = (private / name).lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise RetentionRefused("runtime retention refused")
    return parse_json(raw, 4096), raw, (info.st_dev, info.st_ino)


def _role_container_subject(container_id, name, image_id, deadline):
    sha256(container_id)
    document = parse_json(
        run_bounded(
            ["/usr/bin/docker", "container", "inspect", container_id], deadline
        ),
        MAX_METADATA_BYTES,
    )
    if (
        not isinstance(document, list)
        or len(document) != 1
        or document[0]["Id"] != container_id
        or document[0]["Name"] != "/" + name
        or document[0]["Image"] != image_id
    ):
        raise RetentionRefused("runtime retention refused")
    return document[0]


def role_export_create(private, image_id, deadline):
    """Fixed never-started export creation with durable owned-attempt identity."""
    private = role_private_directory(str(private))
    if not image_id.startswith("sha256:"):
        raise RetentionRefused("runtime retention refused")
    sha256(image_id[7:])
    observed = (
        read_owned_regular(private / "role-image-id", 128, private=True)
        .decode("ascii")
        .strip()
    )
    if observed != image_id:
        raise RetentionRefused("runtime retention refused")
    original = read_owned_regular(
        private / "role-image.json", MAX_METADATA_BYTES, private=True
    )
    inspected = run_bounded(["/usr/bin/docker", "image", "inspect", image_id], deadline)
    document = parse_json(original, MAX_METADATA_BYTES)
    if (
        document != parse_json(inspected, MAX_METADATA_BYTES)
        or not isinstance(document, list)
        or len(document) != 1
        or document[0]["Id"] != image_id
        or document[0]["Config"]["Labels"].get("io.dotmac.runtime")
        != "gate0-finite-role"
    ):
        raise RetentionRefused("runtime retention refused")
    name = "gate0-role-export-" + private.name.removeprefix("gate0-role.")
    if run_bounded(
        [
            "/usr/bin/docker",
            "container",
            "ls",
            "-aq",
            "--filter",
            "name=^" + name + "$",
        ],
        deadline,
    ).strip():
        raise RetentionRefused("runtime retention refused")
    info = private.lstat()
    intent = {
        "schema": "Gate0RoleExportOwnershipIntent.v1",
        "name": name,
        "image_id": image_id,
        "private_device": info.st_dev,
        "private_inode": info.st_ino,
        "work_deadline": float(deadline),
        "wall_deadline": deadline.wall_expiry,
    }
    _role_owner_record(private, "export-ownership-intent.json", intent)
    run_bounded(
        [
            "/usr/bin/docker",
            "create",
            "--name",
            name,
            "--cidfile",
            str(private / "export-container-id"),
            "--entrypoint",
            "/bin/true",
            image_id,
        ],
        deadline,
    )
    cid_record, cid_raw, cid_identity = _read_role_cid(private)
    subject = _role_container_subject(cid_record, name, image_id, deadline)
    if (
        subject["State"]["Status"] != "created"
        or subject["State"]["Running"] is not False
        or subject["Mounts"]
    ):
        raise RetentionRefused("runtime retention refused")
    _role_owner_record(
        private,
        "export-created-owner.json",
        {
            "schema": "Gate0RoleExportCreatedOwner.v1",
            "container_id": cid_record,
            "cid_device": cid_identity[0],
            "cid_inode": cid_identity[1],
            "intent_sha256": hashlib.sha256(canonical_json(intent, 4096)).hexdigest(),
        },
    )
    return cid_record


def _read_role_cid(private):
    import os
    import stat

    descriptor = os.open(
        private / "export-container-id", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= 65
        ):
            raise RetentionRefused("runtime retention refused")
        raw = source.read(66)
        current = (private / "export-container-id").lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise RetentionRefused("runtime retention refused")
    cid = raw.decode("ascii").strip()
    sha256(cid)
    return cid, raw, (info.st_dev, info.st_ino)


def role_export_cleanup(private):
    """Remove only a reverified recorded CID/name/image; preserve unknown custody."""
    private = role_private_directory(str(private))
    intent, intent_raw, _ = _read_role_owner_record(
        private, "export-ownership-intent.json"
    )
    closed(
        intent,
        (
            "schema",
            "name",
            "image_id",
            "private_device",
            "private_inode",
            "work_deadline",
            "wall_deadline",
        ),
    )
    info = private.lstat()
    expected_name = "gate0-role-export-" + private.name.removeprefix("gate0-role.")
    image_id = (
        read_owned_regular(private / "role-image-id", 128, private=True)
        .decode("ascii")
        .strip()
    )
    if (
        intent["schema"] != "Gate0RoleExportOwnershipIntent.v1"
        or intent["name"] != expected_name
        or intent["image_id"] != image_id
        or (intent["private_device"], intent["private_inode"])
        != (info.st_dev, info.st_ino)
        or any(
            type(intent[key]) not in {int, float}
            for key in ("work_deadline", "wall_deadline")
        )
    ):
        raise RetentionRefused("runtime retention refused")
    if not image_id.startswith("sha256:"):
        raise RetentionRefused("runtime retention refused")
    sha256(image_id[7:])
    cleanup = ProductionDeadline(
        intent["work_deadline"] + 20, intent["wall_deadline"] + 20
    )
    owner, _, _ = _read_role_owner_record(private, "export-created-owner.json")
    closed(
        owner, ("schema", "container_id", "cid_device", "cid_inode", "intent_sha256")
    )
    cid, _, identity = _read_role_cid(private)
    if (
        owner["schema"] != "Gate0RoleExportCreatedOwner.v1"
        or owner["container_id"] != cid
        or (owner["cid_device"], owner["cid_inode"]) != identity
        or owner["intent_sha256"] != hashlib.sha256(intent_raw).hexdigest()
    ):
        raise RetentionRefused("runtime retention refused")
    _role_container_subject(cid, expected_name, image_id, cleanup)
    run_bounded(["/usr/bin/docker", "container", "rm", "-f", cid], cleanup)
    if run_bounded(
        ["/usr/bin/docker", "container", "ls", "-aq", "--filter", "id=" + cid], cleanup
    ).strip():
        raise RetentionRefused("runtime retention refused")
    _role_owner_record(
        private,
        "export-cleanup-confirmed.json",
        {
            "schema": "Gate0RoleExportCleanupConfirmed.v1",
            "container_id": cid,
            "intent_sha256": hashlib.sha256(intent_raw).hexdigest(),
        },
    )


def role_base_identity(raw):
    """Docker canonicalizes RepoDigests by removing the source reference tag.

    Admit only the exact source-pinned ubuntu repository and manifest digest;
    publisher image_identity keeps its original exact-reference behavior.
    """
    document = parse_json(raw, MAX_METADATA_BYTES)
    if not isinstance(document, list) or len(document) != 1:
        raise RetentionRefused("runtime retention refused")
    references = document[0].get("RepoDigests")
    canonical = "ubuntu@" + ROLE_BASE_IMAGE.split("@", 1)[1]
    if not isinstance(references, list) or not all(
        isinstance(value, str) for value in references
    ):
        raise RetentionRefused("runtime retention refused")
    selected = next(
        (value for value in references if value in {ROLE_BASE_IMAGE, canonical}), None
    )
    if selected is None:
        raise RetentionRefused("runtime retention refused")
    result = image_identity(raw, selected, None, None)
    # The source coordinate remains fixed; the observed ID and ordered diffIDs
    # come from the actual Docker inspection, never from the execution packet.
    result["reference"] = ROLE_BASE_IMAGE
    return result


# Fixed Docker/OCI config field vocabulary for diagnostics only. Unknown keys
# are counted and never emitted. This is not an acceptance/normalization policy.
ROLE_CONFIG_DIAGNOSTIC_FIELDS = frozenset(
    {
        "Hostname",
        "Domainname",
        "User",
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "ExposedPorts",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "Env",
        "Cmd",
        "Healthcheck",
        "ArgsEscaped",
        "Image",
        "Volumes",
        "WorkingDir",
        "Entrypoint",
        "NetworkDisabled",
        "MacAddress",
        "OnBuild",
        "Labels",
        "StopSignal",
        "StopTimeout",
        "Shell",
    }
)


# Only the twelve observed saved-omitted/inspect-added defaults are equivalent.
# Moby v28.5.1 api/server/router/image/inspect_response.go, legacyConfigFields
# v1.49 (lines16-34), injects these exact typed values. No reverse omission,
# other field, empty collection, or nondefault value is admitted by this rule.
ROLE_INSPECT_ADDED_DEFAULTS = MappingProxyType(
    {
        "AttachStderr": False,
        "AttachStdin": False,
        "AttachStdout": False,
        "Cmd": None,
        "Domainname": "",
        "Hostname": "",
        "Image": "",
        "OnBuild": None,
        "OpenStdin": False,
        "StdinOnce": False,
        "Tty": False,
        "Volumes": None,
    }
)


def _role_config_value_equal(saved, inspected):
    """Deep exact JSON types: Python's False==0 is not config equivalence."""
    if type(saved) is not type(inspected):
        return False
    if isinstance(saved, dict):
        return saved.keys() == inspected.keys() and all(
            _role_config_value_equal(saved[key], inspected[key]) for key in saved
        )
    if isinstance(saved, list):
        return len(saved) == len(inspected) and all(
            _role_config_value_equal(left, right)
            for left, right in zip(saved, inspected, strict=True)
        )
    return saved == inspected


def role_config_matches(saved, inspected):
    """Directional representation join; raw config bytes remain SHA256-pinned."""
    if (
        type(saved) is not dict
        or type(inspected) is not dict
        or saved.keys() - inspected.keys()
    ):
        return False
    added = inspected.keys() - saved.keys()
    if added - ROLE_INSPECT_ADDED_DEFAULTS.keys():
        return False
    if any(
        not _role_config_value_equal(inspected[key], ROLE_INSPECT_ADDED_DEFAULTS[key])
        for key in added
    ):
        return False
    return all(
        _role_config_value_equal(value, inspected[key]) for key, value in saved.items()
    )


def role_config_difference(saved, inspected):
    """Finite field-name/count metadata only, never values or unknown key names."""
    if not isinstance(saved, dict) or not isinstance(inspected, dict):
        return {
            "type_mismatch": True,
            "only_in_saved": [],
            "only_in_inspected": [],
            "different": [],
            "unknown_saved_count": 0,
            "unknown_inspected_count": 0,
        }
    allowed = ROLE_CONFIG_DIAGNOSTIC_FIELDS
    return {
        "type_mismatch": False,
        "only_in_saved": sorted((saved.keys() - inspected.keys()) & allowed),
        "only_in_inspected": sorted((inspected.keys() - saved.keys()) & allowed),
        "different": sorted(
            key
            for key in saved.keys() & inspected.keys() & allowed
            if not _role_config_value_equal(saved[key], inspected[key])
        ),
        "unknown_saved_count": len(saved.keys() - allowed),
        "unknown_inspected_count": len(inspected.keys() - allowed),
    }


def role_export_image_subject(private, revision, inspector, deadline):
    identity = (
        read_owned_regular(private / "role-image-id", 128, private=True)
        .decode("ascii")
        .strip()
    )
    if not identity.startswith("sha256:"):
        raise RetentionRefused("runtime retention refused")
    sha256(identity[7:])
    container_id = (
        read_owned_regular(private / "export-container-id", 128, private=True)
        .decode("ascii")
        .strip()
    )
    if len(container_id) != 64:
        raise RetentionRefused("runtime retention refused")
    sha256(container_id)
    container = parse_json(
        run_bounded(
            ["/usr/bin/docker", "container", "inspect", container_id], deadline
        ),
        MAX_METADATA_BYTES,
    )
    if (
        not isinstance(container, list)
        or len(container) != 1
        or container[0]["Id"] != container_id
        or container[0]["Image"] != identity
        or container[0]["State"]["Status"] != "created"
        or container[0]["State"]["Running"] is not False
        or container[0]["Mounts"]
    ):
        raise RetentionRefused("runtime retention refused")
    original = read_owned_regular(
        private / "role-image.json", MAX_METADATA_BYTES, private=True
    )
    current = run_bounded(["/usr/bin/docker", "image", "inspect", identity], deadline)
    # Inspection JSON is compared semantically; actual original bytes are bound.
    if parse_json(current, MAX_METADATA_BYTES) != parse_json(
        original, MAX_METADATA_BYTES
    ):
        raise RetentionRefused("runtime retention refused")
    base_raw = run_bounded(
        ["/usr/bin/docker", "image", "inspect", ROLE_BASE_IMAGE], deadline
    )
    base = role_base_identity(base_raw)
    role = image_identity(
        original,
        None,
        "gate0-role",
        revision,
        base["rootfs_diff_ids"],
    )
    if role["image_id"] != identity:
        raise RetentionRefused("runtime retention refused")
    image = parse_json(original, MAX_METADATA_BYTES)[0]
    if (
        image["Config"]["Labels"].get("io.dotmac.runtime") != "gate0-finite-role"
        or image["Config"]["User"] != "0:0"
        or image["Config"]["Entrypoint"]
        != ["/opt/venv/bin/dotmac-platform", "gate0", "supervise"]
    ):
        raise RetentionRefused("runtime retention refused")
    with inspector.private_input(
        private / "role-image-save.tar", MAX_TAR_BYTES
    ) as saved:
        inspector.bounded_tar_headers(saved)
        with tarfile.open(fileobj=saved, mode="r:") as archive:
            entries = inspector.inventory(archive, publisher=False)
            manifest_raw = inspector.read(
                archive, entries, "manifest.json", MAX_METADATA_BYTES
            )
            manifest = parse_json(manifest_raw, MAX_METADATA_BYTES)
            if not isinstance(manifest, list) or len(manifest) != 1:
                raise RetentionRefused("runtime retention refused")
            config_name = inspector.member_name(manifest[0]["Config"])
            if config_name not in {
                identity[7:] + ".json",
                "blobs/sha256/" + identity[7:],
            }:
                raise RetentionRefused("runtime retention refused")
            config = inspector.read(archive, entries, config_name, MAX_METADATA_BYTES)
            if hashlib.sha256(config).hexdigest() != identity[7:]:
                raise RetentionRefused("runtime retention refused")
            document = parse_json(config, MAX_METADATA_BYTES)
            if document["rootfs"]["diff_ids"] != role["rootfs_diff_ids"]:
                raise RetentionRefused("role saved-config rootfs mismatch")
            if not role_config_matches(document["config"], image["Config"]):
                error = RetentionRefused("role saved-config fields differ")
                error.role_config_difference = role_config_difference(
                    document["config"], image["Config"]
                )
                raise error
            role["config_sha256"] = hashlib.sha256(config).hexdigest()
            role["config_bytes"] = len(config)
    return {"base": base, "role": role}


def role_image_subject(private, packet, inspector, deadline):
    return role_export_image_subject(
        private, packet["source"]["revision"], inspector, deadline
    )


def role_export_measurement(private, source, limits, inspector, rootfs, image_id):
    inspector.bounded_tar_headers(rootfs)
    with tarfile.open(fileobj=rootfs, mode="r:") as archive:
        inventory = inspector.role_inventory(archive)
        subjects = inspector.role_subjects(archive, inventory, source)
        files = inspector.complete_role_files(archive, inventory)
        footprint = {
            "entries": len(inventory),
            "regular_files": sum(item.isfile() for item in inventory.values()),
            "regular_bytes": sum(
                item.size for item in inventory.values() if item.isfile()
            ),
            "largest_member_bytes": max(
                (item.size for item in inventory.values()), default=0
            ),
            "role_tar_bytes": __import__("os").fstat(rootfs.fileno()).st_size,
        }
    smoke = read_owned_regular(private / "smoke.json", MAX_METADATA_BYTES, private=True)
    network = read_owned_regular(
        private / "network.json", MAX_METADATA_BYTES, private=True
    )
    qualification = inspector.role_synthetic_qualification(
        smoke, network, source["revision"], image_id
    )
    if (
        footprint["entries"] > limits["rootfs_members"]
        or footprint["largest_member_bytes"] > limits["regular_member_bytes"]
        or footprint["role_tar_bytes"] > limits["rootfs_uncompressed_bytes"]
        or len(files) > limits["files_manifest_bytes"]
    ):
        raise RetentionRefused("runtime retention refused")
    measurement = {
        "schema": "Gate0RoleQualificationInspection.v1",
        "role_rootfs_sha256": inspector.stream_digest(rootfs),
        "files_manifest_sha256": hashlib.sha256(files).hexdigest(),
        "qualification_manifest_sha256": hashlib.sha256(qualification).hexdigest(),
        "subjects": subjects,
        "footprint": footprint,
    }
    return canonical_json(measurement, MAX_METADATA_BYTES), files, qualification


def role_measurement(private, packet, inspector, rootfs, image_id):
    return role_export_measurement(
        private, packet["source"], packet["limits"], inspector, rootfs, image_id
    )


def role_inspection(private):
    packet, _, deadline, _, inspector = role_context(private)
    images = role_image_subject(private, packet, inspector, deadline)
    with inspector.private_input(private / "role.tar", MAX_TAR_BYTES) as rootfs:
        outputs = role_measurement(
            private, packet, inspector, rootfs, images["role"]["image_id"]
        )
    for name, raw in zip(
        ("manifest.json", "files.json", "qualification.json"), outputs, strict=True
    ):
        check_deadline(deadline)
        with inspector.private_output(private / name) as output:
            output.write(raw)


def role_main(private_argument, preflight=False):
    import os

    private = role_private_directory(private_argument)
    complete = (
        private / "encrypted-runtime-bundle.pgp",
        private / "producer-receipt.json",
    )
    success = False
    owned_completions = {}
    pending_identities = {}
    try:
        if any(path.exists() or path.is_symlink() for path in complete):
            raise RetentionRefused("runtime retention refused")
        packet, producer, deadline, certificate, inspector = role_context(private)
        if preflight:
            with inspector.private_output(
                private / "packaging-deadline.json"
            ) as output:
                output.write(
                    canonical_json(
                        {"monotonic": float(deadline), "wall": deadline.wall_expiry},
                        1024,
                    )
                )
            return
        images = role_image_subject(private, packet, inspector, deadline)
        with inspector.private_input(private / "role.tar", MAX_TAR_BYTES) as rootfs:
            measured, files, qualification = role_measurement(
                private, packet, inspector, rootfs, images["role"]["image_id"]
            )
            for name, expected, maximum in (
                ("manifest.json", measured, MAX_METADATA_BYTES),
                ("files.json", files, MAX_FILES_BYTES),
                ("qualification.json", qualification, MAX_METADATA_BYTES),
            ):
                if (
                    read_owned_regular(private / name, maximum, private=True)
                    != expected
                ):
                    raise RetentionRefused("runtime retention refused")
            measurement = parse_json(measured, MAX_METADATA_BYTES)
            descriptor = os.open(
                private / "role-rootfs.tar.gz",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "w+b") as compressed:
                compression = compress_inspected_rootfs(
                    rootfs, compressed, measurement["role_rootfs_sha256"], deadline
                )
                if (
                    compression["compressed_bytes"]
                    > packet["limits"]["rootfs_compressed_bytes"]
                ):
                    raise RetentionRefused("runtime retention refused")
                runtime = {
                    "uncompressed_tar_sha256": compression["uncompressed_sha256"],
                    "uncompressed_tar_bytes": compression["uncompressed_bytes"],
                    "compressed_archive_sha256": compression["compressed_sha256"],
                    "compressed_archive_bytes": compression["compressed_bytes"],
                    "files_manifest_sha256": hashlib.sha256(files).hexdigest(),
                    "files_manifest_bytes": len(files),
                    "qualification_manifest_sha256": hashlib.sha256(
                        qualification
                    ).hexdigest(),
                    "qualification_manifest_bytes": len(qualification),
                    **measurement["subjects"],
                }
                build = canonical_json(
                    {
                        "schema": "Gate0RoleQualificationPrivateBuild.v1",
                        "source": {
                            "revision": packet["source"]["revision"],
                            "workflow_blob_sha256": packet["source"][
                                "workflow_blob_sha256"
                            ],
                            **packet["source"]["files"],
                        },
                        "producer": producer,
                        "images": images,
                        "runtime": runtime,
                        "limits": packet["limits"],
                        "footprint": measurement["footprint"],
                        "tool_qualification_sha256": packet[
                            "tool_qualification_sha256"
                        ],
                    },
                    MAX_METADATA_BYTES,
                )
                with inspector.private_output(private / "build.json") as output:
                    output.write(build)
                descriptor = os.open(
                    private / "runtime-payload.tar",
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(descriptor, "w+b") as payload:
                    write_role_inner_archive(
                        payload,
                        compressed,
                        compression["compressed_bytes"],
                        files,
                        build,
                        qualification,
                        deadline,
                    )
                    payload.flush()
                    if payload.tell() > MAX_CIPHERTEXT_BYTES - 1024**2:
                        raise RetentionRefused("runtime retention refused")
                    home = private / "gpg-home"
                    home.mkdir(mode=0o700)
                    descriptor = os.open(
                        private / "encrypted-runtime-bundle.pgp.pending",
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(descriptor, "w+b") as cipher:
                        checked_encrypt(
                            certificate,
                            PRIMARY_FINGERPRINT,
                            ENCRYPTION_FINGERPRINT,
                            home,
                            payload,
                            cipher,
                            deadline,
                        )
                        size = os.fstat(cipher.fileno()).st_size
                        if not 0 < size <= MAX_CIPHERTEXT_BYTES:
                            raise RetentionRefused("runtime retention refused")
                        cipher_hash = inspector.stream_digest(
                            cipher, MAX_CIPHERTEXT_BYTES
                        )
                        info = os.fstat(cipher.fileno())
                        pending_identities["encrypted-runtime-bundle.pgp"] = (
                            info.st_dev,
                            info.st_ino,
                        )
                    receipt = canonical_json(
                        {
                            "schema": "Gate0RoleQualificationProducerReceipt.v1",
                            "purpose": ROLE_PURPOSE,
                            "image_target": "gate0-role",
                            "source_revision": packet["source"]["revision"],
                            "workflow_blob_sha256": packet["source"][
                                "workflow_blob_sha256"
                            ],
                            "run_id": producer["run_id"],
                            "attempt": 1,
                            "job_id": producer["job_id"],
                            "recipient_certificate_sha256": CERTIFICATE_SHA256,
                            "recipient_encryption_fingerprint": ENCRYPTION_FINGERPRINT,
                            "encrypted_bundle_sha256": cipher_hash,
                            "encrypted_bundle_bytes": size,
                            "private_manifest_sha256": hashlib.sha256(
                                build
                            ).hexdigest(),
                        },
                        16384,
                    )
                    with inspector.private_output(
                        private / "producer-receipt.json.pending"
                    ) as output:
                        output.write(receipt)
                        info = os.fstat(output.fileno())
                        pending_identities["producer-receipt.json"] = (
                            info.st_dev,
                            info.st_ino,
                        )
                    check_deadline(deadline)
                    for path in complete:
                        # Reuse publisher's no-overwrite completion primitive.
                        # Record our FD-derived inode before the link, including
                        # a syscall failure after its effect. Never erase a
                        # preexisting or replacement destination on refusal.
                        owned_completions[path] = pending_identities[path.name]
                        os.link(str(path) + ".pending", path)
                        os.unlink(str(path) + ".pending")
                    check_deadline(deadline)
                    success = True
    finally:
        if not success:
            # Never erase an initial/preexisting output or a replacement inode.
            # Only completion files created by this exact attempt are ours.
            for path, identity in owned_completions.items():
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) == identity:
                    path.unlink()


if __name__ == "__main__":
    import sys

    try:
        if len(sys.argv) == 3 and sys.argv[1] == "role-export-create":
            private = role_private_directory(sys.argv[2])
            _, _, deadline, _, _ = role_context(private)
            image_id = (
                read_owned_regular(private / "role-image-id", 128, private=True)
                .decode("ascii")
                .strip()
            )
            role_export_create(private, image_id, deadline)
        elif len(sys.argv) == 3 and sys.argv[1] == "role-export-cleanup":
            role_export_cleanup(role_private_directory(sys.argv[2]))
        elif len(sys.argv) == 3 and sys.argv[1] == "role-preflight":
            role_main(sys.argv[2], preflight=True)
        elif len(sys.argv) == 3 and sys.argv[1] == "role":
            role_main(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "preflight":
            production_main(sys.argv[2], preflight=True)
        elif len(sys.argv) == 2:
            production_main(sys.argv[1])
        else:
            raise RetentionRefused("runtime retention refused")
    except Exception:
        raise SystemExit("runtime retention refused") from None
