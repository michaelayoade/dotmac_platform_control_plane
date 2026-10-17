"""Hosted public ELF loader resolution; never live encryption or qualification."""

import hashlib
import json
import os
import platform
import posixpath
import re
import stat
import struct
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

SOURCE = Path(__file__).resolve()
ROOT = SOURCE.parents[2]
SOURCES = {
    "observer_sha256": SOURCE,
    "workflow_sha256": ROOT / ".github/workflows/ci.yml",
    "measurement_sha256": ROOT / ".github/candidate/measure_gate0_gpg_tools.py",
    "primitives_sha256": ROOT / ".github/candidate/retain_gate0_publisher.py",
    "crypto_test_sha256": ROOT / "conformance/test_gate0_publisher_retention_gpg.py",
}
TARGETS = {"gpg": "/usr/bin/gpg", "gpgconf": "/usr/bin/gpgconf"}
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
LOADERS = {
    "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
}
OUTPUT_NAMES = ("cp-gpg-loader-observation.json", "cp-gpg-loader-observation.sha256")
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
LIMITS = dict(
    shared_seconds=60,
    per_command_seconds=10,
    cleanup_reserve_seconds=5,
    targets=2,
    max_program_headers_per_target=128,
    max_loader_output_bytes_per_target=16384,
    max_dependencies_per_target=64,
    max_unique_files=128,
    max_file_bytes=33554432,
    max_total_hashed_bytes=134217728,
    max_package_owners=32,
    max_symlink_hops=8,
    max_manifest_bytes=262144,
)
STABLE = (
    "st_dev st_ino st_mode st_uid st_gid st_nlink st_size st_mtime_ns st_ctime_ns"
).split()
M = None
MEASUREMENT_BYTES = None
TEMP = None
PHASES = frozenset(
    {
        "bootstrap",
        "source",
        "prior",
        "os",
        "target",
        "interpreter",
        "loader-state",
        "dependency",
        "package",
        "final-check",
        "publication",
        "publication-cleanup",
        "descriptor-cleanup",
        "unknown",
    }
)
EXCEPTION_KINDS = frozenset(
    {
        "Incomplete",
        "RetentionRefused",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "UnicodeDecodeError",
        "FileNotFoundError",
        "PermissionError",
        "FileExistsError",
        "TimeoutError",
        "OSError",
        "error",
    }
)
LOADER_ROW_SHAPES = frozenset(
    {
        "blank",
        "not-found",
        "absolute-mapping",
        "soname-mapping",
        "direct-absolute",
        "vdso",
        "other",
    }
)
PACKAGE_ROW_SHAPES = frozenset(
    {"package-owner", "diversion-from", "diversion-to", "other"}
)
FILE_CATEGORIES = frozenset({"target", "loader", "library"})
DIAGNOSTIC = {
    "phase": "bootstrap",
    "work_failure": None,
    "loader_row": None,
    "package_row": None,
}


class Incomplete(ValueError):
    pass


def failure_metadata(error):
    """Allowlisted labels and line integers only; no error/frame body values."""
    kind = type(error).__name__
    owners = {
        str(SOURCE): "observer",
        str(SOURCES["measurement_sha256"]): "measurement-owner",
        str(SOURCES["primitives_sha256"]): "retention-owner",
    }
    frames = []
    trace = error.__traceback__
    scanned = 0
    while trace is not None and scanned < 64:
        owner = owners.get(trace.tb_frame.f_code.co_filename)
        if owner is not None and len(frames) < 8:
            frames.append({"owner": owner, "line": trace.tb_lineno})
        trace = trace.tb_next
        scanned += 1
    return {
        "kind": kind if kind in EXCEPTION_KINDS else "other",
        "frames": frames,
        "trace_truncated": trace is not None,
    }


def remember_failure(error):
    if DIAGNOSTIC["work_failure"] is None:
        DIAGNOSTIC["work_failure"] = (DIAGNOSTIC["phase"], error)


def failure_diagnostic(error):
    # Bounded cause AND context traversal keeps a work refusal visible when a
    # finally/rollback error replaces it, including suppressed exception context.
    # This function performs no file, command, source or clock reads.
    pending = [(error, "raised", None)]
    seen, chain = set(), []
    while pending and len(chain) < 4:
        current, relation, parent = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        index = len(chain)
        chain.append(
            dict(parent=parent, relation=relation, **failure_metadata(current))
        )
        for relation, next_error in (
            ("cause", current.__cause__),
            ("context", current.__context__),
        ):
            if next_error is not None and id(next_error) not in seen:
                pending.append((next_error, relation, index))
    phase = DIAGNOSTIC["phase"]
    remembered = DIAGNOSTIC["work_failure"]
    row = DIAGNOSTIC.get("loader_row")
    loader_row = None
    if type(row) is dict:
        shape = row.get("shape")
        loader_row = dict(
            shape=shape
            if type(shape) is str and shape in LOADER_ROW_SHAPES
            else "other",
            validated_interpreter_alias_mapping=(
                row.get("validated_interpreter_alias_mapping") is True
            ),
            known_row_spacing_variant=row.get("known_row_spacing_variant") is True,
        )
    row = DIAGNOSTIC.get("package_row")
    package_row = None
    if type(row) is dict:
        shape, category = row.get("shape"), row.get("file_category")
        package_row = dict(
            shape=shape
            if type(shape) is str and shape in PACKAGE_ROW_SHAPES
            else "other",
            file_category=(
                category
                if type(category) is str and category in FILE_CATEGORIES
                else None
            ),
            grammar_matched=row.get("grammar_matched") is True,
            exact_alias_matched=row.get("exact_alias_matched") is True,
        )
    work = None
    if remembered is not None:
        work_phase, work_error = remembered
        work = dict(
            phase=work_phase if work_phase in PHASES else "unknown",
            **failure_metadata(work_error),
        )
    return "GATE0_PUBLIC_GPG_LOADER_OBSERVATION_INCOMPLETE " + json.dumps(
        dict(
            phase=phase if phase in PHASES else "unknown",
            work_failure=work,
            exception_chain=chain,
            chain_truncated=bool(pending),
            loader_row=loader_row,
            package_row=package_row,
        ),
        sort_keys=True,
        separators=(",", ":"),
    )


def require(value):
    if not value:
        raise Incomplete("public-loader-observation-incomplete")


def before(deadline):
    require(time.monotonic() < deadline)


def stamp(info):
    return tuple(getattr(info, key) for key in STABLE)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_measurement(raw):
    global M, MEASUREMENT_BYTES
    require(type(raw) is bytes and 0 < len(raw) <= 1024**2)
    MEASUREMENT_BYTES = raw
    M = ModuleType("public_loader_measured_owner")
    M.__file__ = str(SOURCES["measurement_sha256"])
    M.__package__ = ""
    exec(compile(raw, M.__file__, "exec", dont_inherit=True), M.__dict__)  # noqa: S102 -- fixed measured owner, non-main context


def snapshots(deadline):
    return {
        key: M.read_regular(path, 1024**2, deadline) for key, path in SOURCES.items()
    }


def command(arguments, deadline):
    end = min(deadline - 5, time.monotonic() + 10)
    before(end)
    raw = M.RUN(arguments, end, environment=ENVIRONMENT, maximum=16384)
    before(deadline)
    return raw


def elf_interpreter(raw):
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, version, _, offset, _, _, size, entry_size, count, *_ = header
    require(kind in (2, 3) and machine == 62 and version == 1 and size == 64)
    require(entry_size == 56 and 0 < count <= 128 and offset >= 64)
    require(offset + count * entry_size <= len(raw))
    found = []
    for index in range(count):
        row = struct.unpack_from("<IIQQQQQQ", raw, offset + index * entry_size)
        if row[0] == 3:
            start, length = row[2], row[5]
            require(1 < length <= 256 and start + length <= len(raw))
            value = raw[start : start + length]
            require(value[-1:] == b"\0" and b"\0" not in value[:-1])
            found.append(value[:-1].decode("ascii"))
    require(found == [INTERPRETER])
    return found[0]


def library_coordinate(path, *, loader=False):
    require(type(path) is str and re.fullmatch(r"/[A-Za-z0-9_+./:-]{1,512}", path))
    require(posixpath.normpath(path) == path and ".." not in Path(path).parts)
    roots = ("/lib/", "/lib64/", "/usr/lib/")
    require(path.startswith(roots) or (loader and path.startswith("/usr/lib64/")))


def resolve_library(path, *, loader=False):
    library_coordinate(path, loader=loader)
    edges = []
    current = path
    while True:
        parts = Path(current).parts
        changed = False
        for index in range(1, len(parts) + 1):
            prefix = Path(*parts[:index])
            info = prefix.lstat()
            require(info.st_uid == 0)
            if stat.S_ISLNK(info.st_mode):
                require(len(edges) < 8)
                target = os.readlink(prefix)
                require(stamp(prefix.lstat()) == stamp(info))
                require(type(target) is str and len(target) <= 512)
                destination = posixpath.normpath(
                    target if target.startswith("/") else str(prefix.parent / target)
                )
                remainder = parts[index:]
                resolved = posixpath.join(destination, *remainder)
                library_coordinate(resolved, loader=loader)
                edge = dict(path=str(prefix), target=target)
                require(edge not in edges)
                edges.append(edge)
                current = resolved
                changed = True
                break
            require(not info.st_mode & 0o022)
            if index < len(parts):
                require(stat.S_ISDIR(info.st_mode))
            else:
                require(stat.S_ISREG(info.st_mode))
        if not changed:
            if loader:
                require(current in LOADERS)
            return current, edges


def rejected_loader_row(line, loader):
    """Classify in-memory syntax only; never retain the rejected row or values."""
    normalized = re.sub(r"[ \t]+", " ", line)
    alias_pattern = (
        re.escape(INTERPRETER) + r" => " + re.escape(loader) + r" \(0x[0-9a-f]+\)"
    )
    alias = re.fullmatch(alias_pattern, normalized) is not None
    soname_pattern = r"([A-Za-z0-9_.+-]{1,128}) => (/[^ ]+) \(0x[0-9a-f]+\)"
    direct_pattern = r"(/[^ ]+) \(0x[0-9a-f]+\)"
    vdso_pattern = r"linux-vdso\.so\.1 \(0x[0-9a-f]+\)"
    if not normalized:
        shape = "blank"
    elif re.fullmatch(r"[^ ]+ => not found", normalized):
        shape = "not-found"
    elif re.fullmatch(r"/[^ ]+ => /[^ ]+ \(0x[0-9a-f]+\)", normalized):
        shape = "absolute-mapping"
    elif re.fullmatch(soname_pattern, normalized):
        shape = "soname-mapping"
    elif re.fullmatch(direct_pattern, normalized):
        shape = "direct-absolute"
    elif normalized.startswith("linux-vdso.so.1"):
        shape = "vdso"
    else:
        shape = "other"
    known = alias or any(
        re.fullmatch(pattern, normalized) is not None
        for pattern in (soname_pattern, direct_pattern, vdso_pattern)
    )
    return dict(
        shape=shape,
        validated_interpreter_alias_mapping=alias,
        known_row_spacing_variant=line != normalized and known,
    )


def parse_loader(raw, loader):
    DIAGNOSTIC["loader_row"] = None
    require(type(raw) is bytes and 0 < len(raw) <= 16384 and raw.endswith(b"\n"))
    result, names, paths = [], set(), set()
    for line in raw.decode("ascii").splitlines():
        line = line.strip()
        vdso = re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line)
        mapped = re.fullmatch(
            r"([A-Za-z0-9_.+-]{1,128}) => (/[^ ]+) \(0x[0-9a-f]+\)", line
        )
        interpreter_alias = re.fullmatch(
            re.escape(INTERPRETER) + r" => " + re.escape(loader) + r" \(0x[0-9a-f]+\)",
            line,
        )
        direct = re.fullmatch(r"(/[^ ]+) \(0x[0-9a-f]+\)", line)
        if vdso:
            name, path, kind = "linux-vdso.so.1", None, "kernel-vdso"
        elif mapped:
            name, path = mapped.groups()
            library_coordinate(path)
            require(name == Path(path).name and name != "linux-vdso.so.1")
            kind = "library"
        elif interpreter_alias:
            # Hosted output maps the fixed PT_INTERP alias to this already
            # validated canonical loader. Keep the listed alias so capture
            # rejoins its protected symlink chain to the held loader inode.
            require(loader in LOADERS)
            name, path, kind = "interpreter", INTERPRETER, "interpreter"
        elif direct:
            path = direct.group(1)
            require(path in (INTERPRETER, loader))
            name, kind = "interpreter", "interpreter"
        else:
            DIAGNOSTIC["loader_row"] = rejected_loader_row(line, loader)
            raise Incomplete("public-loader-observation-incomplete")
        require(name not in names and (path is None or path not in paths))
        names.add(name)
        paths.add(path)
        result.append(dict(soname=name, listed_path=path, kind=kind))
        require(len(result) <= 64)
    require("interpreter" in names and "linux-vdso.so.1" in names)
    return result


class Files:
    """Hold discovered regular descriptors until final byte/identity checks."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.held = {}
        self.aliases = {}
        self.total = 0

    def read(self, fd, maximum):
        os.lseek(fd, 0, os.SEEK_SET)
        chunks, count = [], 0
        while count <= maximum:
            before(self.deadline)
            raw = os.read(fd, min(65536, maximum + 1 - count))
            if not raw:
                break
            chunks.append(raw)
            count += len(raw)
        self.total += count
        require(count <= maximum and self.total <= 134217728)
        return b"".join(chunks)

    def capture(self, path, *, library=False, loader=False):
        before(self.deadline)
        canonical, edges = (
            resolve_library(path, loader=loader) if library else (path, [])
        )
        # Reuse the existing strict regular-file and root-ancestry predicates
        # only after finite system aliases have been separately validated.
        raw = M.read_regular(Path(canonical), 33554432, self.deadline, root_owned=True)
        self.total += len(raw)
        require(self.total <= 134217728)
        fd = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and info.st_nlink == 1
                and not info.st_mode & 0o022
                and 0 < info.st_size <= 33554432
            )
            require(stamp(info) == stamp(Path(canonical).lstat()))
            require(
                self.read(fd, 33554432) == raw and stamp(os.fstat(fd)) == stamp(info)
            )
            identity = (info.st_dev, info.st_ino)
            if identity in self.held:
                row = self.held[identity][2]
                require(
                    row["sha256"] == digest(raw) and row["canonical_path"] == canonical
                )
            else:
                require(len(self.held) < 128)
                row = dict(
                    id=f"file-{len(self.held) + 1}",
                    listed_paths=[],
                    canonical_path=canonical,
                    symlink_edges=[],
                    dev=info.st_dev,
                    inode=info.st_ino,
                    mode=stat.S_IMODE(info.st_mode),
                    uid=info.st_uid,
                    gid=info.st_gid,
                    size=info.st_size,
                    sha256=digest(raw),
                    stable_before_after=False,
                    package_names=[],
                )
                self.held[identity] = (fd, stamp(info), row)
                fd = None
            if path not in row["listed_paths"]:
                row["listed_paths"].append(path)
                row["symlink_edges"].extend(
                    e for e in edges if e not in row["symlink_edges"]
                )
            self.aliases[path] = (canonical, edges, library, loader)
            return row, raw
        finally:
            if fd is not None:
                os.close(fd)

    def verify(self):
        for path, (canonical, edges, library, loader) in self.aliases.items():
            if library:
                require(resolve_library(path, loader=loader) == (canonical, edges))
        for fd, initial, row in self.held.values():
            require(stamp(os.fstat(fd)) == initial)
            require(stamp(Path(row["canonical_path"]).lstat()) == initial)
            require(digest(self.read(fd, 33554432)) == row["sha256"])
            raw = M.read_regular(
                Path(row["canonical_path"]), 33554432, self.deadline, root_owned=True
            )
            self.total += len(raw)
            require(self.total <= 134217728 and digest(raw) == row["sha256"])
            require(stamp(os.fstat(fd)) == initial)
            row["stable_before_after"] = True
        before(self.deadline)

    def close(self):
        for fd, _, _ in self.held.values():
            os.close(fd)


def no_preload():
    try:
        Path("/etc/ld.so.preload").lstat()
    except FileNotFoundError:
        return
    raise Incomplete("public-loader-observation-incomplete")


def rejected_package_row(line, match, aliases, row):
    """Closed syntax facts only; no queried owner or pathname is retained."""
    owner = r"(?:local diversion|diversion by [a-z0-9][a-z0-9+.-]{0,127}(?::amd64)?)"
    if match is not None:
        shape = "package-owner"
    elif re.fullmatch(owner + r" from: /[^\n]+", line):
        shape = "diversion-from"
    elif re.fullmatch(owner + r" to: /[^\n]+", line):
        shape = "diversion-to"
    else:
        shape = "other"
    canonical = row["canonical_path"]
    category = (
        "target"
        if canonical in TARGETS.values()
        else ("loader" if canonical in LOADERS else "library")
    )
    return dict(
        shape=shape,
        file_category=category,
        grammar_matched=match is not None,
        exact_alias_matched=match is not None and match.group(2) in aliases,
    )


def package_owners(rows, deadline):
    DIAGNOSTIC["package_row"] = None
    packages = {}
    for row in rows:
        candidates = sorted(set(row["listed_paths"] + [row["canonical_path"]]))
        # dpkg's file lists may use either side of merged-/usr aliases. Search
        # the finite coordinate set in one command, accepting only exact rows.
        aliases = set(candidates)
        for path in candidates:
            if path.startswith("/usr/lib/"):
                aliases.add(path.removeprefix("/usr"))
            elif path.startswith("/lib/"):
                aliases.add("/usr" + path)
        owners = set()
        # A single suffix pattern avoids dpkg-query's nonzero status for one
        # missing alias even when its equivalent owns the file. Every returned
        # coordinate must still be in the finite exact alias set.
        pattern = row["canonical_path"]
        if pattern.startswith("/usr/lib/"):
            pattern = "*" + pattern.removeprefix("/usr")
        for line in (
            command(["/usr/bin/dpkg-query", "--search", pattern], deadline)
            .decode("ascii")
            .splitlines()
        ):
            match = re.fullmatch(
                r"([a-z0-9][a-z0-9+.-]{0,127}(?::amd64)?)\: (/[^\n]+)", line
            )
            if match is None or match.group(2) not in aliases:
                DIAGNOSTIC["package_row"] = rejected_package_row(
                    line, match, aliases, row
                )
            require(match is not None and match.group(2) in aliases)
            owners.add(match.group(1))
        require(len(owners) == 1)
        owner = owners.pop()
        require(len(packages) < 32 or owner in packages)
        if owner not in packages:
            raw = command(
                [
                    "/usr/bin/dpkg-query",
                    "--show",
                    "--showformat=${Package}\t${Version}\t${Architecture}\n",
                    owner,
                ],
                deadline,
            )
            fields = raw.decode("ascii").rstrip("\n").split("\t")
            require(len(fields) == 3 and raw.count(b"\n") == 1 and raw.endswith(b"\n"))
            name, version, architecture = fields
            require(name == owner.split(":")[0] and architecture in ("amd64", "all"))
            require(re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", version))
            checked = command(["/usr/bin/dpkg", "--verify", owner], deadline)
            require(checked == b"")
            packages[owner] = dict(
                name=name,
                version=version,
                architecture=architecture,
                owner=owner,
                file_ids=[],
                verification=dict(
                    exit_code=0, stdout_bytes=0, stdout_sha256=digest(checked)
                ),
            )
        packages[owner]["file_ids"].append(row["id"])
        row["package_names"] = [owner]
    return [packages[key] for key in sorted(packages)]


def github_record(context):
    return dict(
        repository=context["GITHUB_REPOSITORY"],
        repository_id=int(context["GITHUB_REPOSITORY_ID"]),
        run_id=int(context["GITHUB_RUN_ID"]),
        attempt=int(context["GITHUB_RUN_ATTEMPT"]),
        job_key=context["GITHUB_JOB"],
        ref=context["GITHUB_REF"],
        workflow_ref=context["GITHUB_WORKFLOW_REF"],
        workflow_revision=context["GITHUB_WORKFLOW_SHA"],
    )


def observe(deadline, files):
    DIAGNOSTIC["phase"] = "source"
    require(platform.system() == "Linux" and platform.machine() == "x86_64")
    initial = snapshots(deadline)
    # The source roster must name the exact owner bytes executed during
    # bootstrap, before loading primitives or invoking any reused command.
    require(initial["measurement_sha256"] == MEASUREMENT_BYTES)
    M.load_primitives(initial["primitives_sha256"])
    context = M.context()
    github = github_record(context)
    DIAGNOSTIC["phase"] = "prior"
    prior_raw = M.read_regular(
        TEMP / "cp-gpg-native-measurements.json", 65536, deadline
    )
    sidecar = M.read_regular(TEMP / "cp-gpg-native-measurements.sha256", 65, deadline)
    require(sidecar == (digest(prior_raw) + "\n").encode("ascii"))
    prior = M.P["parse_json"](prior_raw, 65536)
    require(prior["schema"] == "DotmacPublisherGpgToolMeasurements.v1")
    require(prior["measurement_scope"] == "hosted-ci-public-os-and-tool-metadata.v1")
    require(
        prior["github"] == github
        and prior["source"]["revision"] == context["GITHUB_SHA"]
    )
    for old, new in (
        ("workflow_sha256", "workflow_sha256"),
        ("helper_sha256", "measurement_sha256"),
        ("primitives_sha256", "primitives_sha256"),
    ):
        require(prior["source"][old] == digest(initial[new]))
    DIAGNOSTIC["phase"] = "os"
    os_facts = M.operating_system(deadline)
    require(os_facts == {"id": "ubuntu", "version_id": "24.04"})
    require(command(["/usr/bin/dpkg", "--print-architecture"], deadline) == b"amd64\n")
    os_facts["architecture"] = "amd64"
    require(
        prior["operating_system"] == os_facts and set(prior["tools"]) == set(TARGETS)
    )
    DIAGNOSTIC["phase"] = "loader-state"
    no_preload()
    target_rows = {}
    for name, path in TARGETS.items():
        DIAGNOSTIC["phase"] = "target"
        row, raw = files.capture(path)
        require(
            prior["tools"][name]["path"] == path
            and prior["tools"][name]["sha256"] == row["sha256"]
        )
        require(
            M.command(name + "_version", deadline).decode("ascii").splitlines()[0]
            == prior["tools"][name]["version_line"]
        )
        DIAGNOSTIC["phase"] = "interpreter"
        require(elf_interpreter(raw) == INTERPRETER)
        target_rows[name] = row
    DIAGNOSTIC["phase"] = "interpreter"
    loader, loader_raw = files.capture(INTERPRETER, library=True, loader=True)
    require(
        loader_raw[:7] == b"\x7fELF\x02\x01\x01"
        and struct.unpack_from("<H", loader_raw, 18)[0] == 62
    )
    DIAGNOSTIC["phase"] = "loader-state"
    cache_path = Path("/etc/ld.so.cache")
    try:
        cache_path.lstat()
    except FileNotFoundError:
        cache = dict(path=str(cache_path), present=False, file=None)
    else:
        cache_row, _ = files.capture(str(cache_path))
        cache = dict(path=str(cache_path), present=True, file=cache_row)
    targets = {}
    for name, path in TARGETS.items():
        DIAGNOSTIC["phase"] = "dependency"
        argv = [loader["canonical_path"], "--list", path]
        wall_start, start = datetime.now(UTC).isoformat(), time.monotonic()
        raw = command(argv, deadline)
        end, wall_end = time.monotonic(), datetime.now(UTC).isoformat()
        bindings = parse_loader(raw, loader["canonical_path"])
        for binding in bindings:
            if binding["kind"] == "kernel-vdso":
                binding["file_id"] = None
                continue
            row, _ = files.capture(
                binding["listed_path"],
                library=True,
                loader=binding["kind"] == "interpreter",
            )
            if binding["kind"] == "interpreter":
                require(row["id"] == loader["id"])
            binding["file_id"] = row["id"]
        targets[name] = dict(
            path=path,
            file_id=target_rows[name]["id"],
            pt_interp=INTERPRETER,
            command=argv,
            exit_code=0,
            dependencies=bindings,
            stdout_sha256=digest(raw),
            stdout_bytes=len(raw),
            wall_start=wall_start,
            wall_end=wall_end,
            monotonic_start=start,
            monotonic_end=end,
        )
    package_rows = [
        row for _, _, row in files.held.values() if row is not cache.get("file")
    ]
    DIAGNOSTIC["phase"] = "package"
    packages = package_owners(package_rows, deadline)
    for name in TARGETS:
        matches = [p for p in packages if target_rows[name]["id"] in p["file_ids"]]
        require(len(matches) == 1)
        require(
            {key: matches[0][key] for key in ("name", "version", "architecture")}
            in prior["packages"]
        )

    def verify():
        DIAGNOSTIC["phase"] = "final-check"
        before(deadline)
        no_preload()
        if not cache["present"]:
            try:
                cache_path.lstat()
            except FileNotFoundError:
                pass
            else:
                raise Incomplete("public-loader-observation-incomplete")
        files.verify()
        for package in packages:
            expected = (
                "\t".join(package[key] for key in ("name", "version", "architecture"))
                + "\n"
            )
            require(
                command(
                    [
                        "/usr/bin/dpkg-query",
                        "--show",
                        "--showformat=${Package}\t${Version}\t${Architecture}\n",
                        package["owner"],
                    ],
                    deadline,
                )
                == expected.encode("ascii")
            )
            require(
                command(["/usr/bin/dpkg", "--verify", package["owner"]], deadline)
                == b""
            )
        require(snapshots(deadline) == initial)
        require(
            M.read_regular(TEMP / "cp-gpg-native-measurements.json", 65536, deadline)
            == prior_raw
        )
        require(
            M.read_regular(TEMP / "cp-gpg-native-measurements.sha256", 65, deadline)
            == sidecar
        )

    verify()
    rows = sorted(
        (row for _, _, row in files.held.values()), key=lambda r: r["canonical_path"]
    )
    for row in rows:
        row["listed_paths"].sort()
        row["symlink_edges"].sort(key=lambda edge: (edge["path"], edge["target"]))
    record = dict(
        schema="DotmacGpgLoaderDependencyObservation.v1",
        measurement_scope="hosted-public-gpg-elf-loader-resolution.v1",
        observed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        source=dict(
            revision=context["GITHUB_SHA"],
            **{key: digest(raw) for key, raw in initial.items()},
        ),
        github=github,
        operating_system=os_facts,
        prior_measurement_sha256=digest(prior_raw),
        environment=ENVIRONMENT,
        limits=LIMITS,
        loader=dict(
            requested_path=INTERPRETER,
            canonical_path=loader["canonical_path"],
            file_id=loader["id"],
            elf_class=64,
            elf_endianness="little",
            elf_machine="x86_64",
            trust_basis="existing-hosted-Ubuntu-bootstrap",
        ),
        loader_cache=dict(**cache, preload_absent=True),
        targets=targets,
        files=rows,
        packages=packages,
        scope_limits=[
            "no-live-encryption-process-observation",
            "no-dlopen-plugins-NSS-or-runtime-conditional-module-coverage",
            "no-spawned-helper-gpg-agent-or-child-history",
            "no-complete-runtime-closure",
            "no-qualification-acceptance-or-reviewer-record",
            "no-package-authentication-claim",
        ],
    )
    return record, verify


def publish(record, verify, deadline):
    DIAGNOSTIC["phase"] = "publication"
    raw = M.P["canonical_json"](record, 262144)
    sidecar = (digest(raw) + "\n").encode("ascii")
    verify()
    DIAGNOSTIC["phase"] = "publication"
    parent = os.open(TEMP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    owned, descriptors = {}, set()
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
                raise Incomplete("public-loader-observation-incomplete")
        for name, data in zip(OUTPUT_NAMES, (raw, sidecar), strict=True):
            before(deadline)
            fd = os.open(
                name + ".pending",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            descriptors.add(fd)
            info = os.fstat(fd)
            owned[name] = (info.st_dev, info.st_ino)
            offset = 0
            while offset < len(data):
                before(deadline)
                count = os.write(fd, data[offset:])
                require(count > 0)
                offset += count
            os.fsync(fd)
            os.close(fd)
            descriptors.remove(fd)
        os.fsync(parent)
        verify()
        DIAGNOSTIC["phase"] = "publication"
        for name in OUTPUT_NAMES:
            before(deadline)
            os.link(
                name + ".pending",
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == owned[name])
        os.fsync(parent)
        for name in OUTPUT_NAMES:
            info = os.stat(name + ".pending", dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == owned[name])
            os.unlink(name + ".pending", dir_fd=parent)
        os.fsync(parent)
        for name, expected in zip(OUTPUT_NAMES, (raw, sidecar), strict=True):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == owned[name])
            require(M.read_regular(TEMP / name, 262144, deadline) == expected)
        actual_parent = TEMP.lstat()
        held_parent = os.fstat(parent)
        require(
            (actual_parent.st_dev, actual_parent.st_ino)
            == (held_parent.st_dev, held_parent.st_ino)
            and stat.S_ISDIR(actual_parent.st_mode)
        )
        verify()
        before(deadline)
    except BaseException as error:
        remember_failure(error)
        DIAGNOSTIC["phase"] = "publication-cleanup"
        failed = False
        for fd in descriptors:
            try:
                os.close(fd)
            except BaseException:
                failed = True
        for name in names:
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (info.st_dev, info.st_ino) in owned.values():
                    os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            except BaseException:
                failed = True
        try:
            os.fsync(parent)
        except BaseException:
            failed = True
        if failed:
            raise Incomplete("public-loader-observation-incomplete") from None
        raise
    finally:
        os.close(parent)


def main():
    global TEMP
    DIAGNOSTIC.update(
        phase="bootstrap", work_failure=None, loader_row=None, package_row=None
    )
    require(len(sys.argv) == 1 and os.geteuid() != 0)
    TEMP = Path(os.environ["RUNNER_TEMP"])
    require(TEMP.is_absolute() and ".." not in TEMP.parts)
    deadline = time.monotonic() + 60
    # Initial owner read is fixed; the same bytes must match the source snapshot
    # before its reusable primitives are invoked.
    fd = os.open(SOURCES["measurement_sha256"], os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1024**2)
        raw = os.read(fd, 1024**2 + 1)
        require(len(raw) == info.st_size and stamp(os.fstat(fd)) == stamp(info))
    finally:
        os.close(fd)
    load_measurement(raw)
    require(M.read_regular(SOURCES["measurement_sha256"], 1024**2, deadline) == raw)
    files = Files(deadline)
    try:
        record, verify = observe(deadline, files)
        publish(record, verify, deadline)
    except BaseException as error:
        remember_failure(error)
        raise
    finally:
        DIAGNOSTIC["phase"] = "descriptor-cleanup"
        files.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(failure_diagnostic(error)) from None
