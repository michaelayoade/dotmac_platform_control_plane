#!/usr/bin/python3.12 -I
"""Source-only bounded installer for two pre-payload R4 component observations.

No operational selection ships here. Protected nonsecret selection and execution
approval are separate, external prerequisites. No native PASS is emitted.
"""

import base64
import binascii
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import resource
import stat
import subprocess
import sys
import tarfile
import time
import types
import urllib.request
from pathlib import PurePosixPath

PREFIX = "/usr/local/libexec/dotmac-gate0-native-envelope"
INSTALLER = PREFIX + "/installer"
SELECTION = "/etc/dotmac-gate0-native-envelope/selection.json"
CONTEXT = "/etc/dotmac-gate0-native-envelope/invocation.json"
STATE = "/var/lib/dotmac-gate0-native-envelope"
PUBLIC = STATE + "/public"
CASES = ("pre-guard-stop", "runc-exec-stop")
WORKFLOW = ".github/workflows/gate0-native-envelope-qualification.yml"
CHECKOUT = "3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
IMAGE = "57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
R4 = {
    "outer": "2f8035879ac0ce198ad66a42cc7d7a8176dc7227aa2451a31dacad7a856a142a",
    "adapter": "8639c8231532bca304c4e7f96633320d3cd89c0f15b15bd4ec9fa55a2ae0b4e9",
    "scratch-helper": (
        "fe0f0de0f2155620172e1000aec5b1438ee3cd5cd0ca78f5896ac7600b986701"
    ),
}
TOOLS = {
    "python": "/usr/bin/python3.12",
    "runc": "/usr/sbin/runc",
    "libc": "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "systemd_run": "/usr/bin/systemd-run",
    "systemctl": "/usr/bin/systemctl",
    "manager": "/usr/lib/systemd/systemd",
    "docker": "/usr/bin/docker",
    "ip": "/usr/sbin/ip",
    "mount": "/usr/bin/mount",
    "dpkg_query": "/usr/bin/dpkg-query",
    "gpgv": "/usr/bin/gpgv",
}
CAPS = dict(
    export=1 << 30,
    content=1 << 30,
    entries=100000,
    file=256 << 20,
    path=4096,
    tree=32 << 20,
    fixture=65536,
    installation=256 << 10,
    diagnostic=1 << 20,
    evidence=256 << 10,
    public=1 << 20,
)


class Refusal(Exception):
    """Deliberately carries no untrusted diagnostic text."""


def require(condition):
    if not condition:
        raise Refusal()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value))
    require(value != "0" * 64)
    return value


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw, limit):
    require(0 < len(raw) <= limit)
    result = json.loads(raw, object_pairs_hook=unique)
    require(canonical(result) == raw)
    return result


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def protected(path, directory=False):
    require(path.startswith("/") and ".." not in path.split("/"))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.strip("/").split("/")
        for index, part in enumerate(parts):
            is_dir = directory or index < len(parts) - 1
            nxt = os.open(
                part,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | (os.O_DIRECTORY if is_dir else 0),
                dir_fd=fd,
            )
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            require(
                stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode)
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_fixed(path, limit, mode=None):
    fd = protected(path)
    try:
        before = os.fstat(fd)
        require(before.st_nlink == 1 and 0 < before.st_size <= limit)
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode)
        raw = os.pread(fd, limit + 1, 0)
        require(
            len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
        )
        return raw
    finally:
        os.close(fd)


def exclusive(path, raw, mode=0o600):
    parent, name = path.rsplit("/", 1)
    directory = protected(parent, True)
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=directory,
        )
        try:
            os.fchmod(fd, mode)
            require(os.fstat(fd).st_uid == os.fstat(fd).st_gid == 0)
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def mkdir(path):
    parent, name = path.rsplit("/", 1)
    directory = protected(parent, True)
    try:
        os.mkdir(name, 0o700, dir_fd=directory)
    finally:
        os.close(directory)


def ensure_parent(path):
    """Only fixed bootstrap ancestry; existing parents must be root protected."""
    try:
        fd = protected(path, True)
    except FileNotFoundError:
        mkdir(path)
    else:
        os.close(fd)


def pin(path):
    fd = protected(path)
    try:
        before = os.fstat(fd)
        require(0 < before.st_size <= CAPS["file"] and before.st_nlink == 1)
        hasher = hashlib.sha256()
        while chunk := os.read(fd, 1 << 20):
            hasher.update(chunk)
        require(identity(before) == identity(os.fstat(fd)))
        return dict(
            sha256=hasher.hexdigest(),
            size=before.st_size,
            mode=stat.S_IMODE(before.st_mode),
        )
    finally:
        os.close(fd)


def run(argv, limit=1 << 20, timeout=30, env=None):
    """Fixed internal vectors only, output goes to capped regular files."""
    require(type(argv) is list and argv[0] in set(TOOLS.values()))
    # Never PIPE unbounded command output or kill a qualification target.
    import tempfile

    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:

        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        result = subprocess.run(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=error,
            timeout=timeout,
            check=False,
            env={} if env is None else env,
            close_fds=True,
            preexec_fn=limits,
        )
        require(
            result.returncode == 0 and output.tell() <= limit and error.tell() <= limit
        )
        output.seek(0)
        return output.read(limit + 1)


def validate_selection(selection):
    closed(
        selection,
        (
            "schema",
            "repository",
            "source_commit",
            "workflow_sha256",
            "installer_sha256",
            "actions",
            "tools",
            "runc_artifact",
        ),
    )
    require(selection["schema"] == "DotmacNativeComponentSelection.v1")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", selection["repository"]))
    require(re.fullmatch("[0-9a-f]{40}", selection["source_commit"]))
    for key in ("workflow_sha256", "installer_sha256"):
        digest(selection[key])
    require(selection["actions"] == {"checkout": CHECKOUT, "upload": UPLOAD})
    closed(selection["tools"], TOOLS)
    for key, item in selection["tools"].items():
        closed(
            item,
            (
                "sha256",
                "size",
                "mode",
                "package",
                "version",
                "origin",
                "package_artifact_sha256",
                "provenance_sha256",
            ),
        )
        digest(item["sha256"])
        require(type(item["size"]) is int and 0 < item["size"] <= CAPS["file"])
        require(
            item["mode"] in (0o644, 0o755) and (key == "libc" or item["mode"] == 0o755)
        )
        require(re.fullmatch("[a-z0-9][a-z0-9+.-]{0,127}", item["package"]))
        require(re.fullmatch("[A-Za-z0-9:~+._-]{1,128}", item["version"]))
        require(item["origin"] in ("Ubuntu-signed-archive", "upstream-signed-release"))
        digest(item["package_artifact_sha256"])
        digest(item["provenance_sha256"])
    artifact = selection["runc_artifact"]
    closed(
        artifact,
        (
            "kind",
            "url",
            "sha256",
            "size",
            "version",
            "signature_sha256",
            "signature_size",
            "keyring_url",
            "keyring_sha256",
            "keyring_size",
            "signer_fingerprint",
            "provenance_sha256",
        ),
    )
    require(artifact["kind"] == "upstream-detached-openpgp-elf")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", artifact["version"]))
    require(
        artifact["url"]
        == "https://github.com/opencontainers/runc/releases/download/"
        + artifact["version"]
        + "/runc.amd64"
    )
    require(
        re.fullmatch(
            r"https://raw.githubusercontent.com/opencontainers/runc/[0-9a-f]{40}/runc.keyring",
            artifact["keyring_url"],
        )
    )
    require(re.fullmatch("[A-F0-9]{40}", artifact["signer_fingerprint"]))
    for key in ("sha256", "signature_sha256", "keyring_sha256", "provenance_sha256"):
        digest(artifact[key])
    for key, cap in (
        ("size", CAPS["file"]),
        ("signature_size", 65536),
        ("keyring_size", 65536),
    ):
        require(type(artifact[key]) is int and 0 < artifact[key] <= cap)
    require(
        artifact["sha256"] == selection["tools"]["runc"]["sha256"]
        and artifact["size"] == selection["tools"]["runc"]["size"]
    )


def load_selection(case):
    require(case in CASES and os.geteuid() == 0)
    selection = decode(read_fixed(SELECTION, CAPS["fixture"], 0o600), CAPS["fixture"])
    validate_selection(selection)
    context = decode(read_fixed(CONTEXT, CAPS["fixture"], 0o600), CAPS["fixture"])
    closed(
        context,
        (
            "repository",
            "source_commit",
            "run_id",
            "run_attempt",
            "job_id",
            "job_name",
            "event",
            "selection_sha256",
            "image_version",
        ),
    )
    require(
        context["repository"] == selection["repository"]
        and context["source_commit"] == selection["source_commit"]
        and context["run_attempt"] == 1
        and context["event"] == "workflow_dispatch"
    )
    require(context["job_name"] == "native-" + case)
    for key in ("run_id", "job_id"):
        require(type(context[key]) is int and context[key] > 0)
    require(context["selection_sha256"] == sha(canonical(selection)))
    require(re.fullmatch("[0-9]{8}\\.[0-9]+\\.[0-9]+", context["image_version"]))
    return selection, context


def source_module(name):
    raw = read_fixed(PREFIX + "/" + name, CAPS["installation"], 0o555)
    require(sha(raw) == R4[name])
    module = types.ModuleType("fixed_" + name)
    module.__file__ = PREFIX + "/" + name
    exec(compile(raw, module.__file__, "exec"), module.__dict__)  # noqa: S102
    return module


def verify_source_and_tools(selection):
    require(pin(INSTALLER)["sha256"] == selection["installer_sha256"])
    require(pin(INSTALLER)["mode"] == 0o555)
    for name in R4:
        require(pin(PREFIX + "/" + name)["sha256"] == R4[name])
        require(pin(PREFIX + "/" + name)["mode"] == 0o555)
    measured = {}
    for key, path in TOOLS.items():
        selected = selection["tools"][key]
        actual = pin(path)
        require(actual == {k: selected[k] for k in ("sha256", "size", "mode")})
        if key == "runc":
            measured[key] = dict(pin=actual, signed_artifact=selection["runc_artifact"])
            continue
        package = run(
            [
                TOOLS["dpkg_query"],
                "--show",
                "--showformat=${Package}\\t${Version}\\t${Architecture}\\n",
                selected["package"],
            ]
        )
        require(
            package
            == (selected["package"] + "\t" + selected["version"] + "\tamd64\n").encode()
        )
        owned = run([TOOLS["dpkg_query"], "--search", path])
        require(
            owned
            in (
                (selected["package"] + ": " + path + "\n").encode(),
                (selected["package"] + ":amd64: " + path + "\n").encode(),
            )
        )
        measured[key] = dict(
            pin=actual,
            package=selected["package"],
            version=selected["version"],
            origin=selected["origin"],
            package_artifact_sha256=selected["package_artifact_sha256"],
            provenance_sha256=selected["provenance_sha256"],
        )
    elf = read_fixed(TOOLS["runc"], CAPS["file"])[:20]
    require(
        elf[:6] == b"\x7fELF\x02\x01" and int.from_bytes(elf[18:20], "little") == 62
    )
    require(not os.stat(TOOLS["runc"]).st_mode & (stat.S_ISUID | stat.S_ISGID))
    try:
        os.getxattr(TOOLS["runc"], "security.capability")
    except OSError as error:
        require(error.errno == errno.ENODATA)
    else:
        raise Refusal()
    return measured, source_module("adapter"), source_module("outer")


def safe_name(name):
    require(type(name) is str and 0 < len(name.encode()) <= CAPS["path"])
    require(not name.startswith("/") and "\x00" not in name)
    parts = name.rstrip("/").split("/")
    require(all(part not in ("", ".", "..") for part in parts))
    require(str(PurePosixPath(name.rstrip("/"))) == name.rstrip("/"))
    return name.rstrip("/")


def bounded_pax_records(raw):
    """Publisher-reviewed framing algorithm, no sparse-map interpretation."""
    require(len(raw) <= 16 * 1024)
    offset, records = 0, 0
    while offset < len(raw):
        records += 1
        require(records <= 1024)
        space = raw.find(b" ", offset, min(offset + 7, len(raw)))
        require(space != -1)
        encoded_length = raw[offset:space]
        require(encoded_length.isdigit() and not encoded_length.startswith(b"0"))
        length = int(encoded_length)
        end = offset + length
        require(end <= len(raw) and end > space + 3 and raw[end - 1 : end] == b"\n")
        key, separator, _ = raw[space + 1 : end - 1].partition(b"=")
        require(key and separator and b"\x00" not in key and b"\n" not in key)
        require(not key.startswith(b"GNU.sparse."))
        offset = end
    return records


def bounded_tar_headers(stream):
    """Physical framing checks precede every tarfile parser invocation.

    Reuses inspect_gate0_publisher.bounded_tar_headers with native caps and
    tighter L/K payload bounds: at most 4096 path bytes plus one NUL terminator.
    """
    stream.seek(0, os.SEEK_END)
    total = stream.tell()
    require(0 < total <= CAPS["export"] and total % 512 == 0)
    stream.seek(0)
    headers, extension_bytes, extension_records = 0, 0, 0
    while stream.tell() < total:
        header = stream.read(512)
        require(len(header) == 512)
        if header == bytes(512):
            require(stream.read(512) == bytes(512))
            while block := stream.read(1 << 20):
                require(not any(block))
            stream.seek(0)
            return
        headers += 1
        require(headers <= CAPS["entries"] * 2)
        kind = header[156:157]
        require(kind != b"S")
        encoded = header[124:136]
        if encoded[0] & 0x80:
            size = int.from_bytes(encoded, "big", signed=True)
            if encoded[0] == 0x80:
                size += 1 << 95
        else:
            try:
                size = int(encoded.strip(b"\x00 ") or b"0", 8)
            except ValueError:
                raise Refusal() from None
        maximum = (
            16 * 1024
            if kind in {b"x", b"g", b"X"}
            else CAPS["path"] + 1
            if kind in {b"L", b"K"}
            else CAPS["file"]
        )
        padded = ((size + 511) // 512) * 512
        require(0 <= size <= maximum and stream.tell() + padded <= total)
        if kind in {b"x", b"g", b"X", b"L", b"K"}:
            extension_bytes += size
            require(extension_bytes <= 16 * 1024 * 1024)
            raw = stream.read(size)
            require(len(raw) == size)
            if kind in {b"x", b"g", b"X"}:
                extension_records += bounded_pax_records(raw)
                require(extension_records <= CAPS["entries"])
            else:
                require(raw.endswith(b"\x00") and b"\x00" not in raw[:-1])
                require(0 < len(raw) - 1 <= CAPS["path"])
            stream.seek(padded - size, os.SEEK_CUR)
        else:
            stream.seek(padded, os.SEEK_CUR)
    raise Refusal()


def extract_export_stream(stream, root):
    bounded_tar_headers(stream)
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        entries = archive_plan(archive)
        extract_validated(archive, entries, root)


def archive_plan(archive):
    """Validate the ENTIRE archive before creating any rootfs entry."""
    require(os.fstat(archive.fileobj.fileno()).st_size <= CAPS["export"])
    before = identity(os.fstat(archive.fileobj.fileno()))
    entries, content = {}, 0
    for item in archive:
        require(len(entries) < CAPS["entries"])
        name = safe_name(item.name)
        require(name not in entries and not item.sparse)
        require(not any("sparse" in key.lower() for key in item.pax_headers))
        require(item.isfile() or item.isdir() or item.issym() or item.islnk())
        require(not item.mode & (stat.S_ISUID | stat.S_ISGID))
        require(0 <= item.size <= CAPS["file"])
        content += item.size
        require(content <= CAPS["content"])
        if item.issym() or item.islnk():
            require(0 < len(item.linkname.encode()) <= CAPS["path"])
            require(not item.linkname.startswith("/") and "\x00" not in item.linkname)
        entries[name] = item
    require(entries)
    for name, item in entries.items():
        parents = PurePosixPath(name).parents
        for parent in parents:
            if str(parent) == ".":
                continue
            require(str(parent) not in entries or entries[str(parent)].isdir())
        if item.islnk():
            target = safe_name(item.linkname)
            require(target in entries and entries[target].isfile())
        if item.issym():
            parts = list(PurePosixPath(name).parts[:-1])
            for part in item.linkname.split("/"):
                if part == "..":
                    require(parts)
                    parts.pop()
                elif part not in ("", "."):
                    parts.append(part)
            require(parts)
            target = "/".join(parts)
            # Refuse symlink chains; every link must resolve directly internally.
            require(
                target in entries
                and not entries[target].issym()
                and not entries[target].islnk()
            )
    require(before == identity(os.fstat(archive.fileobj.fileno())))
    return entries


def extract_validated(archive, entries, root):
    require(not os.listdir(root))
    for name, item in sorted(
        entries.items(), key=lambda pair: (pair[0].count("/"), pair[0])
    ):
        path = root + "/" + name
        parent = path.rsplit("/", 1)[0]
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if item.isdir():
            os.mkdir(path, 0o700) if not os.path.exists(path) else None
        elif item.isfile():
            stream = archive.extractfile(item)
            require(stream is not None)
            fd = os.open(
                path, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600
            )
            try:
                remaining = item.size
                while remaining:
                    chunk = stream.read(min(1 << 20, remaining))
                    require(chunk and os.write(fd, chunk) == len(chunk))
                    remaining -= len(chunk)
                require(not stream.read(1))
                os.fchmod(fd, item.mode & 0o777)
            finally:
                stream.close()
                os.close(fd)
    for name, item in sorted(entries.items()):
        if item.islnk():
            os.link(
                root + "/" + item.linkname, root + "/" + name, follow_symlinks=False
            )
    for name, item in sorted(entries.items()):
        if item.issym():
            os.symlink(item.linkname, root + "/" + name)
    # Set directory modes last; no link can become an extraction parent.
    for name, item in sorted(entries.items(), reverse=True):
        if item.isdir():
            os.chmod(root + "/" + name, item.mode & 0o777, follow_symlinks=False)


def tree_manifest(root):
    result, total = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = directory + "/" + name
            relative = path[len(root) + 1 :]
            safe_name(relative)
            info = os.lstat(path)
            item = dict(
                path=relative,
                mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid,
                gid=info.st_gid,
            )
            require(not info.st_mode & (stat.S_ISUID | stat.S_ISGID))
            if stat.S_ISDIR(info.st_mode):
                item["kind"] = "directory"
            elif stat.S_ISLNK(info.st_mode):
                item.update(kind="symlink", target=os.readlink(path))
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_size <= CAPS["file"])
                total += info.st_size
                require(total <= CAPS["content"])
                with open(path, "rb") as source:
                    hasher = hashlib.file_digest(source, "sha256")
                item.update(kind="file", size=info.st_size, sha256=hasher.hexdigest())
            result.append(item)
            require(len(result) <= CAPS["entries"])
    raw = canonical(sorted(result, key=lambda item: item["path"]))
    require(len(raw) <= CAPS["tree"])
    return raw


def registry_json(url, token=None):
    require(
        url.startswith("https://registry-1.docker.io/v2/library/python/")
        or url
        == "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull"
    )
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={  # noqa: S310
            "Accept": (
                "application/vnd.oci.image.index.v1+json,"
                "application/vnd.docker.distribution.manifest.list.v2+json,"
                "application/vnd.oci.image.manifest.v1+json,"
                "application/vnd.docker.distribution.manifest.v2+json"
            ),
            **({"Authorization": "Bearer " + token} if token else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        require(response.geturl() == url)
        raw = response.read(CAPS["diagnostic"] + 1)
    require(0 < len(raw) <= CAPS["diagnostic"])
    return raw, json.loads(raw, object_pairs_hook=unique)


def verify_registry_layer(layer, token):
    url = "https://registry-1.docker.io/v2/library/python/blobs/" + layer["digest"]
    request = urllib.request.Request(  # noqa: S310
        url, headers={"Authorization": "Bearer " + token}
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        final = response.geturl()
        require(
            final == url
            or final.startswith("https://production.cloudflare.docker.com/")
        )
        hasher, size = hashlib.sha256(), 0
        while chunk := response.read(1 << 20):
            size += len(chunk)
            require(size <= layer["size"] and size <= CAPS["export"])
            hasher.update(chunk)
    require(size == layer["size"] and hasher.hexdigest() == layer["digest"][7:])


def authenticated_diff_ids(config, layers):
    require(type(layers) is list and 0 < len(layers) <= CAPS["entries"])
    rootfs = config.get("rootfs")
    closed(rootfs, ("type", "diff_ids"))
    require(rootfs["type"] == "layers")
    chain = rootfs["diff_ids"]
    require(type(chain) is list and len(chain) == len(layers))
    for value in chain:
        require(type(value) is str and value.startswith("sha256:"))
        digest(value[7:])
    return chain


def validate_docker_image(inspected, config_digest, diff_ids):
    require(type(inspected) is list and len(inspected) == 1)
    image = inspected[0]
    require(
        type(image) is dict
        and image.get("Id") == config_digest
        and image.get("Os") == "linux"
        and image.get("Architecture") == "amd64"
    )
    rootfs = image.get("RootFS")
    require(
        type(rootfs) is dict
        and rootfs.get("Type") == "layers"
        and type(rootfs.get("Layers")) is list
        and rootfs["Layers"] == diff_ids
    )


def prepare_public_rootfs(p):
    _, auth = registry_json(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull"
    )
    token = auth["token"]
    base = "https://registry-1.docker.io/v2/library/python/"
    index_raw, index = registry_json(base + "manifests/sha256:" + IMAGE, token)
    require(sha(index_raw) == IMAGE)
    matches = [
        item
        for item in index["manifests"]
        if item.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    require(len(matches) == 1)
    manifest_digest = matches[0]["digest"]
    require(manifest_digest.startswith("sha256:"))
    digest(manifest_digest[7:])
    manifest_raw, manifest = registry_json(base + "manifests/" + manifest_digest, token)
    require(sha(manifest_raw) == manifest_digest[7:])
    config_digest = manifest["config"]["digest"]
    require(config_digest.startswith("sha256:"))
    digest(config_digest[7:])
    config_raw, config = registry_json(base + "blobs/" + config_digest, token)
    require(
        sha(config_raw) == config_digest[7:]
        and config["architecture"] == "amd64"
        and config["os"] == "linux"
    )
    require(type(manifest["layers"]) is list)
    diff_ids = authenticated_diff_ids(config, manifest["layers"])
    layers = []
    for layer in manifest["layers"]:
        require(layer["digest"].startswith("sha256:"))
        digest(layer["digest"][7:])
        require(type(layer["size"]) is int and 0 < layer["size"] <= CAPS["export"])
        layers.append(dict(digest=layer["digest"], size=layer["size"]))
    require(sum(item["size"] for item in layers) <= CAPS["export"])
    for layer in layers:
        verify_registry_layer(layer, token)
    del token
    docker_env = {"DOCKER_CONFIG": p["base"] + "/docker-config"}
    mkdir(docker_env["DOCKER_CONFIG"])
    reference = "docker.io/library/python@" + manifest_digest
    run(
        [TOOLS["docker"], "pull", "--platform=linux/amd64", reference],
        timeout=180,
        env=docker_env,
    )
    inspected = json.loads(
        run([TOOLS["docker"], "image", "inspect", reference], env=docker_env)
    )
    validate_docker_image(inspected, config_digest, diff_ids)
    name = "dotmac-g0n-" + p["instance"]
    container = (
        run(
            [TOOLS["docker"], "create", "--name", name, "--network=none", reference],
            env=docker_env,
        )
        .decode()
        .strip()
    )
    require(re.fullmatch("[0-9a-f]{64}", container))
    status = json.loads(
        run([TOOLS["docker"], "container", "inspect", container], env=docker_env)
    )
    require(
        len(status) == 1
        and status[0]["State"]["Status"] == "created"
        and status[0]["State"]["Running"] is False
        and status[0]["Image"] == config_digest
    )
    export = p["base"] + "/rootfs-export.tar"
    fd = os.open(export, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:

        def export_limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (CAPS["export"], CAPS["export"]))

        result = subprocess.run(  # noqa: S603
            [TOOLS["docker"], "export", container],
            stdin=subprocess.DEVNULL,
            stdout=fd,
            stderr=subprocess.DEVNULL,
            check=False,
            close_fds=True,
            env=docker_env,
            timeout=180,
            preexec_fn=export_limit,
        )
        require(result.returncode == 0 and 0 < os.fstat(fd).st_size <= CAPS["export"])
    finally:
        os.close(fd)
    with os.fdopen(protected(export), "rb") as stream:
        before = identity(os.fstat(stream.fileno()))
        extract_export_stream(stream, p["base"] + "/rootfs")
        require(before == identity(os.fstat(stream.fileno())))
    root = p["base"] + "/rootfs"
    require(not os.path.lexists(root + "/opt/venv/bin/dotmac-platform"))
    if not os.path.lexists(root + "/app"):
        os.mkdir(root + "/app", 0o755)
    require(stat.S_ISDIR(os.lstat(root + "/app").st_mode))
    # Fixed self bind becomes readonly; no host bind appears in OCI config.
    run([TOOLS["mount"], "--bind", root, root])
    run([TOOLS["mount"], "-o", "remount,bind,ro,nosuid,nodev", root])
    require(os.statvfs(root).f_flag & os.ST_RDONLY)
    raw = tree_manifest(root)
    exclusive(p["base"] + "/rootfs-manifest.json", raw)
    return dict(
        registry_index_digest="sha256:" + IMAGE,
        platform_manifest_digest=manifest_digest,
        image_config_digest=config_digest,
        layers=layers,
        rootfs_tree_digest=sha(raw),
        container_id=container,
    )


def prepare_owned_footprint(a, context, case):
    boot = proc_text("/proc/sys/kernel/random/boot_id", 64).strip()
    coordinates = {
        key: context[key]
        for key in ("repository", "source_commit", "run_id", "run_attempt", "job_id")
    }
    coordinates.update(case=case, boot_id=boot)
    record = dict(case=case, instance=sha(canonical(coordinates)))
    p = a.paths(record)
    ensure_parent(STATE)
    mkdir(p["base"])
    mkdir(p["bundle"])
    mkdir(p["base"] + "/rootfs")
    ensure_parent("/run/dm-g0n")
    mkdir("/run/dm-g0n/" + record["instance"])
    mkdir(p["runc_root"])
    # Does not create cgroups, once claims, fragments, sockets or latches.
    run([TOOLS["ip"], "netns", "add", p["instance"]])
    return record, p, boot


def proc_text(path, limit=65536):
    with open(path, "rb") as source:
        raw = source.read(limit + 1)
    require(0 < len(raw) <= limit)
    return raw.decode("ascii")


def measure_host(context, boot):
    require(
        os.geteuid() == 0
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
        and sys.version_info[:2] == (3, 12)
    )
    require(platform.libc_ver()[0] == "glibc")
    require(os.readlink("/proc/1/exe") == TOOLS["manager"])
    manager, pid1 = os.stat(TOOLS["manager"]), os.stat("/proc/1/exe")
    require((manager.st_dev, manager.st_ino) == (pid1.st_dev, pid1.st_ino))
    for namespace in ("pid", "cgroup"):
        own, parent = (
            os.stat("/proc/self/ns/" + namespace),
            os.stat("/proc/1/ns/" + namespace),
        )
        require((own.st_dev, own.st_ino) == (parent.st_dev, parent.st_ino))
    require(
        [ctypes.sizeof(item) for item in (ctypes.c_long, ctypes.c_void_p, ctypes.c_int)]
        == [8, 8, 4]
    )
    mounts = [line.split() for line in proc_text("/proc/self/mountinfo").splitlines()]
    mounted = [line for line in mounts if line[4] == "/sys/fs/cgroup"]
    require(len(mounted) == 1 and mounted[0][mounted[0].index("-") + 1] == "cgroup2")
    yama = int(proc_text("/proc/sys/kernel/yama/ptrace_scope"))
    require(yama in (0, 1, 2))
    lsm = proc_text("/sys/kernel/security/lsm", 4096).strip()
    apparmor = proc_text("/proc/self/attr/current", 4096).strip()
    require(apparmor == "unconfined")
    status = proc_text("/proc/self/status")
    require("\nSeccomp:\t0\n" in status and "\nTracerPid:\t0\n" in status)
    version = (
        run(
            [
                TOOLS["systemctl"],
                "--system",
                "--no-pager",
                "show",
                "--property=Version",
                "--value",
            ]
        )
        .decode()
        .strip()
    )
    require(re.fullmatch("255([. -][A-Za-z0-9_.+() -]+)?", version))
    require(proc_text("/proc/sys/kernel/random/boot_id").strip() == boot)
    return dict(
        manager_version=version,
        kernel_release=platform.release(),
        yama_scope=yama,
        libc_abi="linux-x86_64-glibc-ptrace-long",
        boot_id=boot,
        lsm=lsm,
        apparmor=apparmor,
        image_version=context["image_version"],
    )


def config_for(record, p):
    caps = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_ADMIN",
        "CAP_SYS_CHROOT",
    ]
    return dict(
        ociVersion="1.0.2",
        root=dict(path=p["base"] + "/rootfs", readonly=True),
        process=dict(
            terminal=False,
            user=dict(uid=0, gid=0, additionalGids=[]),
            args=["/opt/venv/bin/dotmac-platform", "gate0", "supervise"],
            cwd="/app",
            env=[
                "PATH=/opt/venv/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "VIRTUAL_ENV=/opt/venv",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONUNBUFFERED=1",
            ],
            capabilities=dict(
                bounding=caps,
                effective=caps,
                permitted=caps,
                ambient=[],
                inheritable=[],
            ),
            noNewPrivileges=True,
            rlimits=[
                dict(type="RLIMIT_CORE", hard=0, soft=0),
                dict(
                    type="RLIMIT_FSIZE",
                    hard=CAPS["diagnostic"],
                    soft=CAPS["diagnostic"],
                ),
            ],
        ),
        mounts=[],
        linux=dict(
            cgroupsPath=p["group"] + "/payload",
            devices=[],
            resources=dict(devices=[dict(allow=False, access="rwm")]),
            namespaces=[
                dict(type=kind) for kind in ("pid", "mount", "ipc", "uts", "cgroup")
            ]
            + [dict(type="network", path=p["netns"])],
        ),
    )


def intent_rosters(a, p):
    u = p["units"]
    rosters = {kind: {dep: [] for dep in a.DEPS} for kind in u}
    for service, ready, expired, timer in (
        ("service", "ready", "expired", "timer"),
        ("observer", "observer_ready", "observer_expired", "observer_timer"),
    ):
        rosters[service].update(
            Requisite=[u[ready]],
            After=[u[ready], "system.slice"],
            Requires=["system.slice"],
            Conflicts=[u[expired]],
        )
        rosters[ready].update(Before=[u[service]], Conflicts=[u[expired]])
        rosters[timer]["Before"] = [u[expired]]
        rosters[expired]["Conflicts"] = [u[ready], u[service]]
    return rosters


def render_config_and_intent(a, outer, record, p, host, image, installation, tools):
    exclusive(p["bundle"] + "/config.json", canonical(config_for(record, p)))
    install_raw = canonical(installation)
    require(len(install_raw) <= CAPS["installation"])
    exclusive(p["base"] + "/installation-evidence.json", install_raw)
    record.update(
        {
            key: host[key]
            for key in (
                "manager_version",
                "kernel_release",
                "yama_scope",
                "libc_abi",
                "boot_id",
            )
        }
    )
    # Slow preparation is complete. Exactly one wall/monotonic anchor and no retry.
    wall, mono = time.time_ns() // 1000, time.monotonic_ns() // 1000
    record.update(
        not_before_wall_us=wall,
        not_before_mono_us=mono,
        e_wall_us=wall + 60000000,
        e_mono_us=mono + 60000000,
        r_us=60000000,
        t_us=30000000,
        s_us=mono + 90000000,
        c_us=mono + 120000000,
        accuracy_us=1000,
        observer_accuracy_us=1000,
        cpu_quota_percent=100,
        memory_max_bytes=512 << 20,
        tasks_max=128,
        diagnostic_max_bytes=CAPS["diagnostic"],
        evidence_max_bytes=CAPS["evidence"],
        schema="DotmacNativeEnvelopeFixture.v2",
        isolation_scope="disposable-task-vm-only",
        image_digest=image["image_config_digest"][7:],
        rootfs_tree_digest=image["rootfs_tree_digest"],
        installation_evidence_digest=sha(install_raw),
    )
    pins = {
        key: tools[key]["pin"]
        for key in ("python", "runc", "libc", "systemd_run", "systemctl", "manager")
    }
    pins.update(
        adapter=pin(PREFIX + "/adapter"),
        helper=pin(PREFIX + "/scratch-helper"),
        bundle_config=pin(p["bundle"] + "/config.json"),
        rootfs_manifest=pin(p["base"] + "/rootfs-manifest.json"),
        installation_evidence=pin(p["base"] + "/installation-evidence.json"),
    )
    # Read unchanged renderer's literal templates, never copy an observed graph.
    replacements = dict(
        S_US=record["s_us"],
        C_US=record["c_us"],
        T_US=record["t_us"],
        ACCURACY_US=1000,
        OBSERVER_ACCURACY_US=1000,
        DIAGNOSTIC_MAX=CAPS["diagnostic"],
        CPU_QUOTA=100,
        MEMORY_MAX=512 << 20,
        TASKS_MAX=128,
        OUTPUT=p["observer_output"],
        DIAGNOSTIC=p["observer_diagnostic"],
    )
    replacements.update({key.upper(): value for key, value in p["units"].items()})
    for kind, template in outer.TEMPLATES.items():
        for key, value in replacements.items():
            template = template.replace("@@" + key + "@@", str(value))
        require("@@" not in template)
        raw = template.encode("ascii")
        pins[kind] = dict(sha256=sha(raw), size=len(raw), mode=0o644)
    record.update(pins=pins, rosters=intent_rosters(a, p))
    require(record["rootfs_tree_digest"] == pins["rootfs_manifest"]["sha256"])
    a.validate_record(record)
    outer.fragments(record, p)
    return record


def freeze_fixture(a, record):
    a.validate_record(record)
    a.clock(record, True)
    raw = canonical(record)
    require(len(raw) <= CAPS["fixture"])
    exclusive(STATE + "/fixture.json", raw)
    require(read_fixed(STATE + "/fixture.json", CAPS["fixture"], 0o600) == raw)
    a.clock(record, True)
    return sha(raw)


def invoke_outer_once(a, record, p):
    a.clock(record, True)
    output, error = p["base"] + "/outer-output", p["base"] + "/outer-diagnostic"
    exclusive(output, b"")
    exclusive(error, b"")
    with open(output, "r+b") as stdout, open(error, "r+b") as stderr:

        def limit():
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (CAPS["diagnostic"], CAPS["diagnostic"])
            )

        child = subprocess.Popen(  # noqa: S603
            [PREFIX + "/outer"],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env={},
            close_fds=True,
            preexec_fn=limit,
        )
        # No timeout API that kills the owner, no deadline extension/cleanup tail.
        while child.poll() is None and time.monotonic_ns() // 1000 < record["c_us"]:
            time.sleep(0.001)
        exitcode = child.poll()
    if exitcode != 0:
        return exitcode, None
    raw = read_fixed(output, CAPS["evidence"], 0o600)
    document = decode(raw, CAPS["evidence"])
    validate_observation(document, record)
    return exitcode, document


def validate_observation(document, record):
    closed(
        document,
        (
            "schema",
            "status",
            "case",
            "instance",
            "boot_id",
            "original_s_us",
            "original_c_us",
            "observer",
            "observer_terminal",
            "retained_observer_cgroup",
            "original_observer_disappeared",
            "observer_pidfd_ready",
            "observer_recursive_populated_zero",
            "target_observation",
            "overall_native_pass",
        ),
    )
    require(
        document["schema"] == "DotmacNativeEnvelopeOwnerComponentObservation.v1"
        and document["status"] == "observer-normal-retirement-observed-unqualified"
        and document["overall_native_pass"] is False
    )
    for key in ("case", "instance", "boot_id"):
        require(document[key] == record[key])
    require(
        document["original_s_us"] == record["s_us"]
        and document["original_c_us"] == record["c_us"]
    )
    for key in (
        "original_observer_disappeared",
        "observer_pidfd_ready",
        "observer_recursive_populated_zero",
    ):
        require(document[key] is True)
    target = document["target_observation"]
    require(
        target["schema"] == "DotmacNativeEnvelopeTargetObservation.v1"
        and target["overall_native_pass"] is False
        and target["actual_stdout_empty_eof"] is True
    )

    # Every retained scalar must be bounded public vocabulary, never raw logs.
    def bounded(value, depth=0):
        require(depth < 20)
        if type(value) is str:
            require(
                len(value) <= 4096 and re.fullmatch(r"[A-Za-z0-9_./:+()= -]*", value)
            )
        elif type(value) is dict:
            require(len(value) <= 64)
            for key, item in value.items():
                bounded(key, depth + 1)
                bounded(item, depth + 1)
        elif type(value) is list:
            require(len(value) <= 64)
            for item in value:
                bounded(item, depth + 1)
        else:
            require(
                type(value) in (int, bool)
                and (type(value) is bool or 0 <= value < 2**64)
            )

    bounded(document)
    require(len(canonical(document)) <= CAPS["evidence"])


def retain_public_receipt(
    selection, context, record, fixture_hash, exitcode, document, image=None
):
    if document is not None:
        validate_observation(document, record)
    receipt = dict(
        schema="DotmacNativeComponentProducerReceipt.v1",
        status="component-observed-unqualified" if document else "incomplete",
        failure_class="none" if document else "owner-retirement-unproven",
        source_commit=context["source_commit"],
        repository=context["repository"],
        run_id=context["run_id"],
        run_attempt=1,
        job_id=context["job_id"],
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        original_clocks={
            key: record[key]
            for key in (
                "not_before_wall_us",
                "not_before_mono_us",
                "e_wall_us",
                "e_mono_us",
                "r_us",
                "t_us",
                "accuracy_us",
                "observer_accuracy_us",
            )
        },
        fixture_sha256=fixture_hash,
        selection_sha256=sha(canonical(selection)),
        installer_sha256=selection["installer_sha256"],
        workflow_sha256=selection["workflow_sha256"],
        actions=selection["actions"],
        r4_source_sha256=R4,
        runc_artifact=selection["runc_artifact"],
        image_provenance=image,
        host={
            key: record[key]
            for key in ("manager_version", "kernel_release", "yama_scope", "libc_abi")
        },
        image_version=context.get("image_version"),
        tool_pins=record["pins"],
        image_config_digest=record["image_digest"],
        rootfs_tree_digest=record["rootfs_tree_digest"],
        installation_evidence_digest=record["installation_evidence_digest"],
        outer_exit=exitcode,
        normal_observer_retirement=document is not None,
        overall_native_pass=False,
    )
    observation = (
        document
        if document is not None
        else dict(
            schema="DotmacNativeComponentIncomplete.v1",
            failure_class="owner-retirement-unproven",
            overall_native_pass=False,
        )
    )
    raws = canonical(receipt), canonical(observation)
    require(
        sum(map(len, raws)) <= CAPS["public"]
        and all(len(raw) <= CAPS["evidence"] for raw in raws)
    )
    mkdir(PUBLIC)
    for name, raw in zip(
        ("producer-receipt.json", "component-observation.json"), raws, strict=True
    ):
        exclusive(PUBLIC + "/" + name, raw)
    return document is not None


PRODUCER_KEYS = (
    "schema",
    "status",
    "failure_class",
    "source_commit",
    "repository",
    "run_id",
    "run_attempt",
    "job_id",
    "case",
    "instance",
    "boot_id",
    "original_s_us",
    "original_c_us",
    "original_clocks",
    "fixture_sha256",
    "selection_sha256",
    "installer_sha256",
    "workflow_sha256",
    "actions",
    "r4_source_sha256",
    "runc_artifact",
    "image_provenance",
    "host",
    "image_version",
    "tool_pins",
    "image_config_digest",
    "rootfs_tree_digest",
    "installation_evidence_digest",
    "outer_exit",
    "normal_observer_retirement",
    "overall_native_pass",
)


def validate_public_pair(producer_raw, observation_raw, expected):
    """Pure continuation gate; source/job coordinates join through the instance."""
    producer = decode(producer_raw, CAPS["evidence"])
    observation = decode(observation_raw, CAPS["evidence"])
    require(len(producer_raw) + len(observation_raw) <= CAPS["public"])
    closed(producer, PRODUCER_KEYS)
    require(
        producer["schema"] == "DotmacNativeComponentProducerReceipt.v1"
        and producer["status"] == "component-observed-unqualified"
        and producer["failure_class"] == "none"
        and producer["normal_observer_retirement"] is True
        and producer["overall_native_pass"] is False
        and type(producer["outer_exit"]) is int
        and producer["outer_exit"] == 0
    )
    for key in (
        "repository",
        "source_commit",
        "run_id",
        "run_attempt",
        "case",
        "installer_sha256",
        "workflow_sha256",
    ):
        require(producer[key] == expected[key])
    for key in ("run_id", "run_attempt", "job_id"):
        require(type(producer[key]) is int and producer[key] > 0)
    require(producer["run_attempt"] == 1 and producer["case"] in CASES)
    require(re.fullmatch("[0-9a-f]{40}", producer["source_commit"]))
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", producer["repository"]))
    require(
        re.fullmatch("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", producer["boot_id"])
    )
    coordinates = {
        key: producer[key]
        for key in (
            "repository",
            "source_commit",
            "run_id",
            "run_attempt",
            "job_id",
            "case",
            "boot_id",
        )
    }
    require(producer["instance"] == sha(canonical(coordinates)))
    for key in (
        "fixture_sha256",
        "selection_sha256",
        "installer_sha256",
        "workflow_sha256",
        "image_config_digest",
        "rootfs_tree_digest",
        "installation_evidence_digest",
    ):
        digest(producer[key])
    require(
        producer["actions"] == dict(checkout=CHECKOUT, upload=UPLOAD)
        and producer["r4_source_sha256"] == R4
    )
    clocks = producer["original_clocks"]
    closed(
        clocks,
        (
            "not_before_wall_us",
            "not_before_mono_us",
            "e_wall_us",
            "e_mono_us",
            "r_us",
            "t_us",
            "accuracy_us",
            "observer_accuracy_us",
        ),
    )
    for value in (
        *clocks.values(),
        producer["original_s_us"],
        producer["original_c_us"],
    ):
        require(type(value) is int and 0 < value < 2**64)
    require(
        clocks["e_wall_us"] - clocks["not_before_wall_us"] == 60000000
        and clocks["e_mono_us"] - clocks["not_before_mono_us"] == 60000000
        and clocks["r_us"] == 60000000
        and clocks["t_us"] == 30000000
        and clocks["accuracy_us"] == clocks["observer_accuracy_us"] == 1000
        and producer["original_c_us"] == clocks["e_mono_us"] + clocks["r_us"]
        and producer["original_s_us"] == producer["original_c_us"] - clocks["t_us"]
    )
    record = {key: producer[key] for key in ("case", "instance", "boot_id")}
    record.update(s_us=producer["original_s_us"], c_us=producer["original_c_us"])
    validate_observation(observation, record)
    target = observation["target_observation"]
    closed(
        target,
        (
            "schema",
            "status",
            "case",
            "instance",
            "boot_id",
            "original_s_us",
            "original_c_us",
            "held_boundary",
            "target",
            "retirement",
            "observer",
            "observer_cgroup",
            "systemd_run_exit",
            "actual_stdout_empty_eof",
            "overall_native_pass",
        ),
    )
    require(target["status"] == "target-cutoff-observed-observer-retirement-pending")
    for key in ("case", "instance", "boot_id", "original_s_us", "original_c_us"):
        require(target[key] == observation[key])
    require(
        target["observer"] == observation["observer"]
        and target["observer_cgroup"] == observation["retained_observer_cgroup"]
    )
    require(type(target["systemd_run_exit"]) is int and target["systemd_run_exit"] != 0)
    return True


def stage_public_receipts(case):
    """Unprivileged, read-only fixed-file staging; never install or invoke main."""
    require(case in CASES and os.geteuid() != 0)
    expected = dict(
        repository=os.environ["GITHUB_REPOSITORY"],
        source_commit=os.environ["GITHUB_SHA"],
        run_id=int(os.environ["GITHUB_RUN_ID"]),
        run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        case=case,
    )
    workspace = os.environ["GITHUB_WORKSPACE"]
    for key, path in (
        (
            "installer_sha256",
            workspace + "/conformance/gate0_envelope_source/native/installer.py",
        ),
        ("workflow_sha256", workspace + "/" + WORKFLOW),
    ):
        with open(path, "rb") as source:
            raw = source.read(CAPS["installation"] + 1)
        require(0 < len(raw) <= CAPS["installation"])
        expected[key] = sha(raw)
    destination = os.environ["RUNNER_TEMP"] + "/gate0-native-public"
    os.mkdir(destination, 0o700)
    staged = []
    for name in ("producer-receipt.json", "component-observation.json"):
        result = subprocess.run(  # noqa: S603
            [
                "/usr/bin/sudo",
                "--non-interactive",
                "/usr/bin/head",
                "-c",
                "262145",
                PUBLIC + "/" + name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            env={},
            close_fds=True,
        )
        try:
            require(result.returncode == 0)
            raw = result.stdout
            document = decode(raw, CAPS["evidence"])
            require(
                type(document) is dict and document.get("overall_native_pass") is False
            )
            if name == "producer-receipt.json":
                closed(document, PRODUCER_KEYS)
                require(document["schema"] == "DotmacNativeComponentProducerReceipt.v1")
            elif document.get("schema") == "DotmacNativeComponentIncomplete.v1":
                closed(document, ("schema", "failure_class", "overall_native_pass"))
                require(document["failure_class"] == "owner-retirement-unproven")
            else:
                own_record = {
                    key: document[key] for key in ("case", "instance", "boot_id")
                }
                own_record.update(
                    s_us=document["original_s_us"], c_us=document["original_c_us"]
                )
                validate_observation(document, own_record)
        except Exception:
            raw = canonical(
                dict(
                    schema="DotmacNativeComponentPreparationRefusal.v1",
                    failure_class="preparation-refused",
                    case=case,
                    run_id=expected["run_id"],
                    source_commit=expected["source_commit"],
                    normal_observer_retirement=False,
                    overall_native_pass=False,
                )
            )
        staged.append(raw)
        fd = os.open(
            destination + "/" + name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as output:
            require(output.write(raw) == len(raw))
    # Failure files are present for always-upload, but never unlock next case.
    return validate_public_pair(*staged, expected)


def download_public(url, expected, size):
    require(
        url.startswith(
            (
                "https://github.com/opencontainers/runc/releases/download/",
                "https://raw.githubusercontent.com/opencontainers/runc/",
            )
        )
    )
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        # GitHub release assets redirect to the official HTTPS asset endpoint.
        final = response.geturl()
        require(
            final == url
            or final.startswith("https://release-assets.githubusercontent.com/")
        )
        raw = response.read(size + 1)
    require(len(raw) == size and sha(raw) == expected)
    return raw


# The selected official listing has one reviewed encoding; no format fallback.
RUNC_KEYRING_SIZE = 8507
RUNC_KEYRING_SHA = "9bd9742cb79b215cf5f7f71ea71a51a2a95ab573412d54c2905be072d8fcab7c"
RUNC_BINARY_KEYRING_SHA = (
    "cdec7014cf714a452a6da3f7db8dbf24495db8d466e0b6b7d4f9ab7888c65e68"
)


def normalize_selected_keyring(raw, artifact):
    """Decode only the pinned official listing before any installation writes."""
    require(
        type(raw) is bytes
        and artifact["keyring_size"] == RUNC_KEYRING_SIZE
        and artifact["keyring_sha256"] == RUNC_KEYRING_SHA
        and len(raw) == RUNC_KEYRING_SIZE
        and sha(raw) == RUNC_KEYRING_SHA
    )
    begin = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = b"-----END PGP PUBLIC KEY BLOCK-----"
    require(raw.count(begin) == 3 and raw.count(end) == 3)
    pattern = (
        rb"(?m)^"
        + begin
        + rb"\nComment: github=[A-Za-z0-9]+\n\n([A-Za-z0-9+/=\n]+)\n"
        + end
        + rb"$"
    )
    blocks = re.findall(pattern, raw)
    require(len(blocks) == 3)
    decoded = []
    for block in blocks:
        lines = block.splitlines()
        require(len(lines) > 1 and re.fullmatch(rb"=[A-Za-z0-9+/]{4}", lines[-1]))
        require(
            all(
                re.fullmatch(rb"[A-Za-z0-9+/]{1,64}={0,2}", line) for line in lines[:-1]
            )
        )
        try:
            decoded.append(base64.b64decode(b"".join(lines[:-1]), validate=True))
        except binascii.Error:
            raise Refusal() from None
    binary = b"".join(decoded)
    require(
        list(map(len, decoded)) == [1915, 1243, 2272]
        and len(binary) == 5430
        and sha(binary) == RUNC_BINARY_KEYRING_SHA
    )
    return binary


def install_selected_runc(selection):
    artifact = selection["runc_artifact"]
    actual_verifier = pin(TOOLS["gpgv"])
    require(
        actual_verifier
        == {key: selection["tools"]["gpgv"][key] for key in ("sha256", "size", "mode")}
    )
    binary = download_public(artifact["url"], artifact["sha256"], artifact["size"])
    signature = download_public(
        artifact["url"] + ".asc",
        artifact["signature_sha256"],
        artifact["signature_size"],
    )
    keyring = download_public(
        artifact["keyring_url"], artifact["keyring_sha256"], artifact["keyring_size"]
    )
    require(
        binary[:6] == b"\x7fELF\x02\x01"
        and int.from_bytes(binary[18:20], "little") == 62
    )
    binary_keyring = normalize_selected_keyring(keyring, artifact)
    work = STATE + "/public-tool-preparation"
    mkdir(work)
    for name, raw in (
        ("runc.amd64", binary),
        ("runc.amd64.asc", signature),
        ("runc-keyring.gpg", binary_keyring),
    ):
        exclusive(work + "/" + name, raw)
    mkdir(work + "/gnupg")
    status = run(
        [
            TOOLS["gpgv"],
            "--homedir",
            work + "/gnupg",
            "--keyring",
            work + "/runc-keyring.gpg",
            "--status-fd=1",
            work + "/runc.amd64.asc",
            work + "/runc.amd64",
        ],
        limit=65536,
    ).decode("ascii")
    valid = [
        line.split()
        for line in status.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    require(len(valid) == 1 and valid[0][2] == artifact["signer_fingerprint"])
    require(
        not any(
            word in status
            for word in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")
        )
    )
    exclusive(TOOLS["runc"], binary, 0o755)


def staged_install(selection, context, sources, case):
    """Future fixed privileged materialization; no supplied paths or commands."""
    require(os.geteuid() == 0 and case in CASES)
    validate_selection(selection)
    require(set(sources) == {*R4, "installer"})
    for name, raw in sources.items():
        require(
            sha(raw)
            == (selection["installer_sha256"] if name == "installer" else R4[name])
        )
    # Root installation follows complete selector/hash validation. Missing tools
    # or unknown signed provenance refuses rather than upgrading host packages.
    for key, path in TOOLS.items():
        if key != "runc":
            require(
                pin(path)
                == {
                    field: selection["tools"][key][field]
                    for field in ("sha256", "size", "mode")
                }
            )
    boot = proc_text("/proc/sys/kernel/random/boot_id").strip()
    measure_host(context, boot)
    ensure_parent("/etc/dotmac-gate0-native-envelope")
    exclusive(SELECTION, canonical(selection))
    exclusive(CONTEXT, canonical(context))
    ensure_parent(STATE)
    install_selected_runc(selection)
    ensure_parent("/usr/local/libexec")
    mkdir(PREFIX)
    for name, raw in sources.items():
        exclusive(PREFIX + "/" + name, raw, 0o555)
    # No token/configuration environment crosses into the installed entry point.
    os.execve(INSTALLER, [INSTALLER, case], {})  # noqa: S606


def bootstrap(case):
    """Only workflow checkout entry, authenticated before privileged mutation."""
    require(
        case in CASES and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
    )
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
    raw = os.environ.get("GATE0_NATIVE_EXECUTION_SELECTION_JSON", "").encode()
    require(0 < len(raw) <= CAPS["fixture"])
    expected = digest(os.environ.get("GATE0_NATIVE_SELECTION_SHA256", ""))
    require(sha(raw) == expected)
    selection = decode(raw, CAPS["fixture"])
    validate_selection(selection)
    require(
        selection["repository"] == os.environ.get("GITHUB_REPOSITORY")
        and selection["source_commit"] == os.environ.get("GITHUB_SHA")
        and selection["source_commit"] == os.environ.get("GITHUB_WORKFLOW_SHA")
    )
    require(
        os.environ.get("GITHUB_WORKFLOW_REF", "").startswith(
            selection["repository"] + "/" + WORKFLOW + "@"
        )
    )
    workspace = os.environ["GITHUB_WORKSPACE"]
    require(
        os.path.abspath(__file__)
        == workspace + "/conformance/gate0_envelope_source/native/installer.py"
    )
    sources = {}
    for name in (*R4, "installer"):
        filename = "scratch_helper.py" if name == "scratch-helper" else name + ".py"
        path = workspace + "/conformance/gate0_envelope_source/native/" + filename
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            data = os.read(fd, CAPS["installation"] + 1)
            require(
                len(data) == before.st_size
                and len(data) <= CAPS["installation"]
                and identity(before) == identity(os.fstat(fd))
            )
        finally:
            os.close(fd)
        require(
            sha(data)
            == (selection["installer_sha256"] if name == "installer" else R4[name])
        )
        sources[name] = data
    with open(workspace + "/" + WORKFLOW, "rb") as workflow:
        require(
            sha(workflow.read(CAPS["installation"] + 1)) == selection["workflow_sha256"]
        )
    run_id = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch("[1-9][0-9]{0,19}", run_id))
    # Built-in token is used only for this bounded read-only request. It is not
    # written, passed to a subprocess, logged or included in retained evidence.
    token = os.environ.pop("GH_TOKEN", "")
    require(token)
    url = (
        "https://api.github.com/repos/"
        + selection["repository"]
        + "/actions/runs/"
        + run_id
        + "/attempts/1/jobs?per_page=100"
    )
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        require(response.geturl() == url)
        data = response.read(CAPS["diagnostic"] + 1)
    del token
    require(len(data) <= CAPS["diagnostic"])
    jobs = json.loads(data, object_pairs_hook=unique)
    require(jobs["total_count"] <= 100)
    matches = [job for job in jobs["jobs"] if job["name"] == "native-" + case]
    require(len(matches) == 1)
    job = matches[0]
    require(
        type(job["id"]) is int
        and job["id"] > 0
        and job["run_id"] == int(run_id)
        and job["head_sha"] == selection["source_commit"]
        and job["status"] == "in_progress"
    )
    context = dict(
        repository=selection["repository"],
        source_commit=selection["source_commit"],
        run_id=int(run_id),
        run_attempt=1,
        job_id=job["id"],
        job_name=job["name"],
        event="workflow_dispatch",
        selection_sha256=expected,
        image_version=os.environ.get("ImageVersion", ""),
    )
    require(re.fullmatch(r"[0-9]{8}\.[0-9]+\.[0-9]+", context["image_version"]))
    payload = dict(
        selection=selection,
        context=context,
        case=case,
        sources={
            name: base64.b64encode(data).decode() for name, data in sources.items()
        },
    )
    # Exact reviewed bootstrap code/data via stdin; no shell expansion and no
    # arbitrary module path, destination, command or environment reaches root.
    program = (
        "import base64,json,types\np="
        + repr(payload)
        + "\nm=types.ModuleType('installer');m.__file__="
        + repr(INSTALLER)
        + "\ns=base64.b64decode(p['sources']['installer'])\n"
        + "exec(compile(s,m.__file__,'exec'),m.__dict__)\n"
        + "sources={k:base64.b64decode(v) for k,v in p['sources'].items()}\n"
        + "m.staged_install(p['selection'],p['context'],sources,p['case'])\n"
    )
    result = subprocess.run(  # noqa: S603
        ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3.12", "-I", "-"],
        input=program.encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        close_fds=True,
        env={},
    )
    require(result.returncode == 0)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in CASES)
    if os.path.abspath(__file__) != INSTALLER:
        bootstrap(sys.argv[1])
        return
    selection, context = load_selection(sys.argv[1])
    tools, a, outer = verify_source_and_tools(selection)
    # Eligibility is checked before namespace/rootfs mutations and again after prep.
    boot = proc_text("/proc/sys/kernel/random/boot_id").strip()
    measure_host(context, boot)
    record, p, original_boot = prepare_owned_footprint(a, context, sys.argv[1])
    require(original_boot == boot)
    image = prepare_public_rootfs(p)
    host = measure_host(context, boot)
    installation = dict(
        schema="DotmacNativeComponentInstallation.v1",
        source=context,
        selection_sha256=sha(canonical(selection)),
        tools=tools,
        source_pins={name: pin(PREFIX + "/" + name) for name in R4},
        image=image,
        host=host,
        overall_native_pass=False,
    )
    record = render_config_and_intent(
        a, outer, record, p, host, image, installation, tools
    )
    fixture_hash = freeze_fixture(a, record)
    try:
        exitcode, document = invoke_outer_once(a, record, p)
    except Exception:
        exitcode, document = None, None
    require(
        retain_public_receipt(
            selection, context, record, fixture_hash, exitcode, document, image
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(125) from None
