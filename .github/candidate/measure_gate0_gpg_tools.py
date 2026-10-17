"""Public hosted-CI OS/GnuPG measurements, never native qualification.

No producer entrypoint, credential, certificate, network or reviewer is used.
The existing retention owner's standard-library bounded subprocess primitive is
reused solely for six code-fixed public metadata commands.
"""

import hashlib
import os
import platform
import re
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

SOURCE = Path(__file__).resolve()
ROOT = SOURCE.parents[2]
PRIMITIVES = ROOT / ".github/candidate/retain_gate0_publisher.py"
P = {}
RUN = None
TEMP = None
LIMIT = 65536
CONTEXT_KEYS = (
    "GITHUB_ACTIONS",
    "GITHUB_SHA",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_JOB",
    "GITHUB_REF",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
)
COMMANDS = {
    "architecture": ("/usr/bin/dpkg", "--print-architecture"),
    "packages": (
        "/usr/bin/dpkg-query",
        "--show",
        "--showformat=${Package}\t${Version}\t${Architecture}\n",
        "gpg",
        "gpgconf",
    ),
    "verify_gpg": ("/usr/bin/dpkg", "--verify", "gpg"),
    "verify_gpgconf": ("/usr/bin/dpkg", "--verify", "gpgconf"),
    "gpg_version": ("/usr/bin/gpg", "--no-options", "--version"),
    "gpgconf_version": ("/usr/bin/gpgconf", "--version"),
}
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
STABLE = (
    "st_dev st_ino st_mode st_uid st_gid st_nlink st_size st_mtime_ns st_ctime_ns"
).split()


class Incomplete(ValueError):
    pass


def require(value):
    if not value:
        raise Incomplete("public-tool-measurement-incomplete")


def before(deadline):
    require(time.monotonic() < deadline)


def command(name, deadline):
    require(name in COMMANDS)
    # Existing primitive reserves up to five seconds for kill/reap on failure;
    # that reserve belongs inside the original sixty-second measurement budget.
    end = min(deadline - 5, time.monotonic() + 10)
    before(end)
    raw = RUN(list(COMMANDS[name]), end, environment=ENVIRONMENT, maximum=16384)
    before(deadline)
    return raw


def read_regular(path, maximum, deadline, *, root_owned=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts)
    if root_owned:
        for parent in path.parents:
            info = parent.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022
            )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == (0 if root_owned else os.getuid())
            and not info.st_mode & 0o022
            and 0 < info.st_size <= maximum
        )
        chunks = []
        count = 0
        while count <= maximum:
            before(deadline)
            chunk = os.read(descriptor, min(65536, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        require(count == info.st_size and count <= maximum)
        actual = os.fstat(descriptor)
        current = path.lstat()
        expected = tuple(getattr(info, key) for key in STABLE)
        require(
            tuple(getattr(actual, key) for key in STABLE) == expected
            and tuple(getattr(current, key) for key in STABLE) == expected
        )
        before(deadline)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


SOURCE_PATHS = {
    "workflow_sha256": ROOT / ".github/workflows/ci.yml",
    "helper_sha256": SOURCE,
    "primitives_sha256": PRIMITIVES,
}


def source_snapshots(deadline):
    return {
        name: read_regular(path, 1024**2, deadline)
        for name, path in SOURCE_PATHS.items()
    }


def load_primitives(raw):
    global P, RUN
    require(type(raw) is bytes and 0 < len(raw) <= 1024**2)
    module = ModuleType("public_gpg_measurement_primitives")
    module.__file__ = str(PRIMITIVES)
    module.__package__ = ""
    # Execute precisely the bounded initial snapshot, never reopen a mutable
    # pathname for runpy/import. The fixed non-main module context prevents the
    # producer CLI from running. Source bytes are hashed into the observation.
    code = compile(raw, str(PRIMITIVES), "exec", dont_inherit=True)
    exec(code, module.__dict__)  # noqa: S102 -- fixed measured repository primitive bytes, no caller code selector
    require(module.__dict__["WORKFLOW"] == ".github/workflows/ci.yml")
    P = module.__dict__
    RUN = P["run_bounded"]


def verify_sources(record, deadline):
    actual = source_snapshots(deadline)
    require(
        all(
            hashlib.sha256(raw).hexdigest() == record["source"][name]
            for name, raw in actual.items()
        )
    )


def operating_system(deadline):
    # Ubuntu can expose /etc/os-release through the standard merged-/usr alias.
    # Only those two root-controlled coordinates are admitted, never a learned
    # source path or an arbitrary symlink destination.
    path = Path("/etc/os-release").resolve(strict=True)
    require(str(path) in ("/etc/os-release", "/usr/lib/os-release"))
    raw = read_regular(path, 16384, deadline, root_owned=True)
    result = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID"):
            require(key.lower() not in result)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            require(re.fullmatch(r"[a-z0-9_.-]{1,64}", value) is not None)
            result[key.lower()] = value
    require(set(result) == {"id", "version_id"})
    return result


def context():
    values = {key: os.environ[key] for key in CONTEXT_KEYS}
    require(values["GITHUB_ACTIONS"] == "true" and values["GITHUB_JOB"] == "check")
    require(values["GITHUB_REPOSITORY"] == P["REPOSITORY"])
    for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        require(re.fullmatch(r"[0-9a-f]{40}", values[key]) is not None)
    for key in ("GITHUB_REPOSITORY_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", values[key]) is not None)
    reference = values["GITHUB_REF"]
    require(
        re.fullmatch(r"refs/(heads|pull)/[A-Za-z0-9._/-]{1,200}", reference) is not None
        and ".." not in reference
    )
    workflow = values["GITHUB_WORKFLOW_REF"]
    prefix = P["REPOSITORY"] + "/" + P["WORKFLOW"] + "@"
    require(
        workflow.startswith(prefix)
        and re.fullmatch(
            r"refs/(heads|pull)/[A-Za-z0-9._/-]{1,200}", workflow[len(prefix) :]
        )
        is not None
        and ".." not in workflow
    )
    return values


def packages(raw):
    require(type(raw) is bytes and len(raw) <= 16384)
    rows = raw.decode("ascii").splitlines()
    require(len(rows) == 2 and raw.endswith(b"\n"))
    result = []
    for row in rows:
        fields = row.split("\t")
        require(len(fields) == 3)
        name, version, architecture = fields
        require(
            name in ("gpg", "gpgconf")
            and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", version) is not None
            and architecture in ("amd64", "all")
        )
        result.append(dict(name=name, version=version, architecture=architecture))
    result.sort(key=lambda item: item["name"])
    require([item["name"] for item in result] == ["gpg", "gpgconf"])
    return result


def measure(deadline):
    before(deadline)
    require(
        TEMP is not None
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
    )
    initial_sources = source_snapshots(deadline)
    load_primitives(initial_sources["primitives_sha256"])
    github = context()
    legacy_raw = read_regular(TEMP / "cp-gpg-tool-identities.json", 4096, deadline)
    legacy = P["parse_json"](legacy_raw, 4096)
    os_facts = operating_system(deadline)
    architecture = command("architecture", deadline).decode("ascii")
    require(architecture == "amd64\n")
    os_facts["architecture"] = architecture.rstrip("\n")
    tools, expected_legacy = {}, {}
    for name in ("gpg", "gpgconf"):
        path = Path("/usr/bin") / name
        raw = read_regular(path, 32 * 1024**2, deadline, root_owned=True)
        version = command(name + "_version", deadline).decode("ascii").splitlines()[0]
        require(
            re.fullmatch(re.escape(name) + r" \(GnuPG\) 2\.[0-9]+\.[0-9]+", version)
            is not None
        )
        require(read_regular(path, 32 * 1024**2, deadline, root_owned=True) == raw)
        tools[name] = dict(
            path=str(path), sha256=hashlib.sha256(raw).hexdigest(), version_line=version
        )
        prefix = "GATE0_TEST_QUALIFIED_" + name.upper()
        expected_legacy.update(
            {
                prefix: str(path),
                prefix + "_SHA256": tools[name]["sha256"],
                prefix + "_VERSION": version,
            }
        )
    require(legacy == expected_legacy)
    package_facts = packages(command("packages", deadline))
    verification = {}
    for name in ("gpg", "gpgconf"):
        raw = command("verify_" + name, deadline)
        require(raw == b"")
        verification[name] = dict(
            command=list(COMMANDS["verify_" + name]),
            exit_code=0,
            stdout_bytes=len(raw),
            stdout_sha256=hashlib.sha256(raw).hexdigest(),
        )
    require(source_snapshots(deadline) == initial_sources)
    sources = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in initial_sources.items()
    }
    before(deadline)
    return dict(
        schema="DotmacPublisherGpgToolMeasurements.v1",
        measurement_scope="hosted-ci-public-os-and-tool-metadata.v1",
        measured_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        source=dict(
            revision=github["GITHUB_SHA"],
            workflow_path=P["WORKFLOW"],
            helper_path=".github/candidate/measure_gate0_gpg_tools.py",
            primitives_path=".github/candidate/retain_gate0_publisher.py",
            **sources,
        ),
        github=dict(
            repository=github["GITHUB_REPOSITORY"],
            repository_id=int(github["GITHUB_REPOSITORY_ID"]),
            run_id=int(github["GITHUB_RUN_ID"]),
            attempt=int(github["GITHUB_RUN_ATTEMPT"]),
            job_key=github["GITHUB_JOB"],
            ref=github["GITHUB_REF"],
            workflow_ref=github["GITHUB_WORKFLOW_REF"],
            workflow_revision=github["GITHUB_WORKFLOW_SHA"],
        ),
        operating_system=os_facts,
        tools=tools,
        packages=package_facts,
        package_verification=verification,
        legacy_tool_identities_sha256=hashlib.sha256(legacy_raw).hexdigest(),
    )


OUTPUT_NAMES = ("cp-gpg-native-measurements.json", "cp-gpg-native-measurements.sha256")


def publish(record, deadline):
    raw = P["canonical_json"](record, LIMIT)
    digest = hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n"
    verify_sources(record, deadline)
    before(deadline)
    parent = os.open(TEMP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned = {}
    descriptors = set()
    names = (*OUTPUT_NAMES, *(name + ".pending" for name in OUTPUT_NAMES))
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022)
        for name in names:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(name)
        for name, data in zip(OUTPUT_NAMES, (raw, digest), strict=True):
            before(deadline)
            fd = os.open(
                name + ".pending",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            descriptors.add(fd)
            metadata = os.fstat(fd)
            owned[name] = (metadata.st_dev, metadata.st_ino)
            offset = 0
            while offset < len(data):
                before(deadline)
                count = os.write(fd, data[offset:])
                require(count > 0)
                offset += count
            os.fsync(fd)
            before(deadline)
            os.close(fd)
            descriptors.remove(fd)
        os.fsync(parent)
        verify_sources(record, deadline)
        for name in OUTPUT_NAMES:
            before(deadline)
            os.link(
                name + ".pending",
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((metadata.st_dev, metadata.st_ino) == owned[name])
        os.fsync(parent)
        for name in OUTPUT_NAMES:
            before(deadline)
            metadata = os.stat(name + ".pending", dir_fd=parent, follow_symlinks=False)
            require((metadata.st_dev, metadata.st_ino) == owned[name])
            os.unlink(name + ".pending", dir_fd=parent)
        os.fsync(parent)
        for name, expected in zip(OUTPUT_NAMES, (raw, digest), strict=True):
            require(read_regular(TEMP / name, LIMIT, deadline) == expected)
        verify_sources(record, deadline)
        before(deadline)
    except BaseException:
        cleanup_failed = False
        for fd in descriptors:
            try:
                os.close(fd)
            except BaseException:
                cleanup_failed = True
        # Fixed finite cleanup still attempts each owned inode after expiry.
        # Foreign/preexisting names are never removed. Workflow upload requires
        # helper success, so uncertainty cannot publish a partial new pair.
        for name in names:
            try:
                metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except BaseException:
                cleanup_failed = True
                continue
            if (metadata.st_dev, metadata.st_ino) not in owned.values():
                continue
            try:
                os.unlink(name, dir_fd=parent)
            except BaseException:
                cleanup_failed = True
        try:
            os.fsync(parent)
        except BaseException:
            cleanup_failed = True
        if cleanup_failed:
            raise Incomplete("public-tool-measurement-cleanup-incomplete") from None
        raise
    finally:
        os.close(parent)


def main():
    global TEMP
    require(len(sys.argv) == 1 and os.geteuid() != 0)
    TEMP = Path(os.environ["RUNNER_TEMP"])
    require(TEMP.is_absolute() and ".." not in TEMP.parts)
    deadline = time.monotonic() + 60
    publish(measure(deadline), deadline)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("GATE0_PUBLIC_GPG_MEASUREMENT_INCOMPLETE") from None
