"""Non-root candidate input observation, not native or production proof.

Self-hashes and dpkg metadata only help locate independently signed packages.
The public runc ELF is signature-checked as data and is never executed.
GITHUB_SHA may be a synthetic merge; GITHUB_JOB is a key, not a numeric job ID.
ImageRelease is optional and remains null when the provider does not supply it.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

FILES = (
    "/usr/bin/python3.12",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/bin/systemd-run",
    "/usr/bin/systemctl",
    "/usr/lib/systemd/systemd",
    "/usr/bin/docker",
    "/usr/sbin/ip",
    "/usr/bin/mount",
    "/usr/bin/dpkg-query",
    "/usr/bin/gpgv",
)
BASE = "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.amd64"
BINARY_SHA = "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488"
SIGNATURE_SHA = "2b36d2bfd696ce0fb90e0b7d218f74a258eb1294586abc1130d561b9eb58c04f"
KEYRING_SHA = "9bd9742cb79b215cf5f7f71ea71a51a2a95ab573412d54c2905be072d8fcab7c"
KEYRING_BINARY_SHA = "cdec7014cf714a452a6da3f7db8dbf24495db8d466e0b6b7d4f9ab7888c65e68"
KEYRING_URL = (
    "https://raw.githubusercontent.com/opencontainers/runc/"
    "29dd3dc2b13b4123162e5fe132504bb4b15569f1/runc.keyring"
)
ARTIFACTS = (
    ("runc.amd64", BASE, 10866512, BINARY_SHA),
    ("runc.amd64.asc", BASE + ".asc", 488, SIGNATURE_SHA),
    ("runc.keyring", KEYRING_URL, 8507, KEYRING_SHA),
)
SIGNER = "C2428CD75720FACDCF76B6EA17DE5ECB75A1100E"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}
CHILD = dict(
    stdin=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    check=False,
    env=ENV,
    close_fds=True,
)
LIMIT = 65536
STABLE_FIELDS = (
    "st_dev st_ino st_mode st_uid st_gid st_nlink st_size st_mtime_ns st_ctime_ns"
).split()
QUERY = "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\n"


class Incomplete(Exception):
    pass


EXPECTED_ERRORS = (Incomplete, OSError, UnicodeError, subprocess.SubprocessError)


def require(value, failure="input-incomplete"):
    if not value:
        raise Incomplete(failure)


def text(value, pattern=r"[A-Za-z0-9_.:+~/-]{1,160}"):
    require(type(value) is str and re.fullmatch(pattern, value))
    return value


def stable(info):
    return tuple(getattr(info, key) for key in STABLE_FIELDS)


def command(argv, timeout=2):
    require(argv[0] in ("/usr/bin/dpkg-query", "/usr/bin/gpgv"))
    with tempfile.TemporaryFile() as output:

        def bounded():
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))

        result = subprocess.run(  # noqa: S603
            argv, stdout=output, timeout=timeout, preexec_fn=bounded, **CHILD
        )
        require(result.returncode == 0 and output.tell() <= LIMIT, "command-incomplete")
        output.seek(0)
        return output.read(LIMIT + 1).decode("ascii")


def fixed_aliases(path):
    require(path in FILES, "unexpected-alias")
    if path.startswith(("/lib/", "/usr/lib/")):
        suffix = path.split("/lib/", 1)[1]
        return {"/lib/" + suffix, "/usr/lib/" + suffix}
    return {
        prefix + path.rsplit("/", 1)[1]
        for prefix in ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")
    }


def file_type(mode):
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "special"


def stat_facts(info):
    return dict(
        uid=info.st_uid,
        gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        nlink=info.st_nlink,
        type=file_type(info.st_mode),
        symlink=stat.S_ISLNK(info.st_mode),
    )


def ancestry(path, resolved):
    paths = {"/"}
    for value in (path, resolved):
        paths.update(str(parent) for parent in Path(value).parents)
    require(len(paths) <= 12)
    return [dict(path=value, **stat_facts(os.lstat(value))) for value in sorted(paths)]


def capabilities(fd):
    try:
        return "present" if "security.capability" in os.listxattr(fd) else "absent"
    except OSError:
        return "unknown"


def query_fact(argv, deadline):
    require(argv[0] == "/usr/bin/dpkg-query" and argv[1] in ("--search", "--show"))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return "budget-exhausted", None
    with tempfile.TemporaryFile() as output:

        def bounded():
            resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))

        try:
            result = subprocess.run(  # noqa: S603
                argv,
                stdout=output,
                timeout=min(2, remaining),
                preexec_fn=bounded,
                **CHILD,
            )
        except subprocess.TimeoutExpired:
            return "timeout", None
        except OSError:
            return "unavailable", None
        if time.monotonic() >= deadline:
            return "budget-exhausted", None
        if output.tell() > LIMIT:
            return "bounds", None
        output.seek(0)
        try:
            raw = output.read(LIMIT + 1).decode("ascii")
        except UnicodeError:
            return "encoding", None
        if len(raw) > LIMIT:
            return "bounds", None
        return "zero" if result.returncode == 0 else "nonzero", raw


PACKAGE = r"[a-z0-9][a-z0-9+.-]{0,100}(?::[a-z0-9]{1,16})?"


def search_facts(raw, alias):
    rows = raw.splitlines()
    result = dict(shape="valid", rows=[], unknown_rows=0, row_count=len(rows))
    if not 0 < len(rows) <= 12 or any(len(row) > 1024 for row in rows):
        result.update(shape="bounds-or-empty", row_count=min(len(rows), 13))
        return result, set()
    names = set()
    for row in rows:
        diversion = re.fullmatch(
            r"(?:diversion by (" + PACKAGE + r")|local diversion) "
            r"(from|to): (/[A-Za-z0-9_./+-]{1,512})",
            row,
        )
        if diversion:
            base, _, qualifier = (diversion[1] or "").partition(":")
            result["rows"].append(
                dict(
                    type="diversion",
                    package=base or None,
                    qualifier=qualifier or None,
                    direction=diversion[2],
                    matched_fixed_path=diversion[3] == alias,
                )
            )
            continue
        group, separator, owned = row.partition(": ")
        owners = group.split(", ")
        if (
            not separator
            or not 0 < len(owners) <= 4
            or not all(re.fullmatch(PACKAGE, name) for name in owners)
        ):
            result["unknown_rows"] += 1
            continue
        for owner in owners:
            base, _, qualifier = owner.partition(":")
            result["rows"].append(
                dict(
                    type="owner",
                    package=base,
                    qualifier=qualifier or None,
                    matched_fixed_path=owned == alias,
                )
            )
            if owned == alias:
                names.add(owner)
    if result["unknown_rows"] or not names or len(names) > 4:
        result["shape"] = "unrecognized-or-unassociated"
    return result, names if len(names) <= 4 else set()


def show_fact(package, kind, deadline):
    exit_class, raw = query_fact(
        ["/usr/bin/dpkg-query", "--show", QUERY, package], deadline
    )
    record = dict(
        query_kind=kind,
        requested_package=package,
        show_exit=exit_class,
        show_shape="unavailable",
        failure_stage="show-exit",
    )
    if raw is None or exit_class != "zero":
        return record
    fields = raw.removesuffix("\n").split("\t")
    if (
        len(fields) != 3
        or "\n" in raw.removesuffix("\n")
        or not re.fullmatch(PACKAGE, fields[0])
        or not re.fullmatch(r"[A-Za-z0-9:~+._-]{1,128}", fields[1])
        or not re.fullmatch(r"[a-z0-9]{1,16}", fields[2])
    ):
        record.update(show_shape="unrecognized", failure_stage="show-shape")
        return record
    base, _, qualifier = fields[0].partition(":")
    record.update(
        show_shape="valid",
        failure_stage="none",
        package=base,
        qualifier=qualifier or None,
        version=fields[1],
        architecture=fields[2],
        architecture_matches_amd64=fields[2] == "amd64",
        requested_package_matches=(
            fields[0] == package or (":" not in package and base == package)
        ),
    )
    if not record["requested_package_matches"]:
        record.update(
            show_shape="requested-package-mismatch", failure_stage="show-shape"
        )
    return record


def package_facts(aliases, deadline):
    records, associated = [], []
    for alias in sorted(set(aliases)):
        exit_class, raw = query_fact(
            ["/usr/bin/dpkg-query", "--search", alias], deadline
        )
        record = dict(
            alias=alias,
            search_exit=exit_class,
            search_shape="unavailable",
            failure_stage="search-exit",
            shows=[],
        )
        if raw is not None:
            parsed, names = search_facts(raw, alias)
            record.update(search_shape=parsed.pop("shape"), **parsed)
            record["failure_stage"] = (
                "search-exit"
                if exit_class != "zero"
                else "search-shape"
                if record["search_shape"] != "valid"
                else "none"
            )
            if exit_class == "zero":
                record["shows"] = [
                    show_fact(name, "owner-association", deadline)
                    for name in sorted(names)
                ]
                for show in record["shows"]:
                    if show["failure_stage"] != "none":
                        record["failure_stage"] = show["failure_stage"]
                    elif (
                        record["failure_stage"] == "none"
                        and show["requested_package_matches"]
                    ):
                        associated.append(
                            dict(
                                alias=alias,
                                package=show["package"],
                                version=show["version"],
                                architecture=show["architecture"],
                                diversion_observed=any(
                                    row["type"] == "diversion" for row in record["rows"]
                                ),
                            )
                        )
        records.append(record)
    if "/usr/bin/python3.12" in aliases:
        records.append(
            dict(
                candidate_query=show_fact(
                    "python3.12-minimal", "candidate-only-not-association", deadline
                )
            )
        )
    return associated, records


def observe_file(path, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + 30
    result = dict(
        lexical_path=path, status="incomplete", failure_class="file-incomplete"
    )
    try:
        require(time.monotonic() < deadline, "metadata-budget")
        resolved = os.path.realpath(path)
        require(resolved in fixed_aliases(path), "unexpected-alias")
        lexical = os.lstat(path)
        result.update(lexical=stat_facts(lexical), ancestors=ancestry(path, resolved))
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 << 20)
            hasher, received = hashlib.sha256(), 0
            while block := os.read(fd, 65536):
                require(time.monotonic() < deadline, "metadata-budget")
                received += len(block)
                require(received <= before.st_size)
                hasher.update(block)
            require(received == before.st_size)
            require(stable(before) == stable(os.fstat(fd)))
            capability = capabilities(fd)
        finally:
            os.close(fd)
        result.update(
            status="observed-not-authenticated",
            failure_class="none",
            resolved_path=resolved,
            lexical_symlink=stat.S_ISLNK(lexical.st_mode),
            resolved_differs=resolved != path,
            size=before.st_size,
            **stat_facts(before),
            sha256=hasher.hexdigest(),
            capability_presence=capability,
            packages=[],
            package_queries=[],
        )
        associated, facts = package_facts((path, resolved), deadline)
        result.update(packages=associated, package_queries=facts)
    except FileNotFoundError:
        result["failure_class"] = "file-missing"
    except EXPECTED_ERRORS as error:
        result["failure_class"] = (
            error.args[0]
            if isinstance(error, Incomplete)
            and error.args[0] in ("metadata-budget", "unexpected-alias")
            else "file-incomplete"
        )
    return result


def runc_target():
    # Presence/type only; never follow, read, hash, install or replace the target.
    try:
        info = os.lstat("/usr/sbin/runc")
        return dict(presence="present", type=file_type(info.st_mode))
    except FileNotFoundError:
        return dict(presence="absent", type=None)
    except OSError:
        return dict(presence="unknown", type=None)


def observe_metadata():
    def expired(signum, frame):
        raise Incomplete("metadata-budget")

    original = signal.signal(signal.SIGALRM, expired)
    deadline = time.monotonic() + 30
    signal.setitimer(signal.ITIMER_REAL, 30)
    files = []
    try:
        for path in FILES:
            if time.monotonic() >= deadline:
                files.append(
                    dict(
                        lexical_path=path,
                        status="incomplete",
                        failure_class="metadata-budget",
                    )
                )
            else:
                files.append(observe_file(path, deadline))
        target = (
            runc_target()
            if time.monotonic() < deadline
            else dict(presence="unknown", type=None)
        )
    except Incomplete:
        files.extend(
            dict(
                lexical_path=path, status="incomplete", failure_class="metadata-budget"
            )
            for path in FILES[len(files) :]
        )
        target = dict(presence="unknown", type=None)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)
    return files, target


def checked_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        raise Incomplete("redirect-refused") from None
    hosts = (
        "github.com",
        "release-assets.githubusercontent.com",
        "raw.githubusercontent.com",
    )
    # Exact netloc admits only these hosts on HTTPS443, excluding all userinfo.
    netlocs = {*hosts, *(host + ":443" for host in hosts)}
    require(
        parsed.scheme == "https" and parsed.netloc in netlocs and not parsed.fragment,
        "redirect-refused",
    )
    return url


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(
            request, response, code, message, headers, newurl
        )


def download(opener, directory, artifact, deadline):
    name, url, size, expected = artifact
    require(time.monotonic() < deadline, "public-input-deadline")
    request = urllib.request.Request(checked_url(url))  # noqa: S310
    with opener.open(request, timeout=min(10, deadline - time.monotonic())) as response:
        checked_url(response.geturl())
        fd = os.open(
            directory + "/" + name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as output:
            hasher, received = hashlib.sha256(), 0
            while True:
                require(time.monotonic() < deadline, "public-input-deadline")
                block = response.read1(65536)
                if not block:
                    break
                received += len(block)
                require(received <= size, "public-input-bounds")
                hasher.update(block)
                require(output.write(block) == len(block), "public-input-write")
    require(
        time.monotonic() < deadline
        and received == size
        and hasher.hexdigest() == expected,
        "public-input-digest",
    )


def signature_status(raw):
    lines = raw.splitlines()
    require(
        len(lines) <= 64 and all(len(line) <= 4096 for line in lines),
        "signature-status",
    )
    allowed = {"NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG"}
    valid = []
    for line in lines:
        words = line.split()
        require(
            len(words) >= 2 and words[0] == "[GNUPG:]" and words[1] in allowed,
            "signature-status",
        )
        if words[1] == "VALIDSIG":
            require(len(words) in (11, 12) and words[2] == SIGNER, "signature-signer")
            valid.append(words)
    require(len(valid) == 1, "signature-status")
    primary = text(valid[0][11], r"[A-F0-9]{40}") if len(valid[0]) == 12 else None
    return dict(
        status="public-signature-observed",
        direct_signer_fingerprint=SIGNER,
        reported_primary_fingerprint=primary,
        cryptographic_signature_verified=True,
    )


def derive_keyring(work):
    """Decode only the exact pinned official listing's three public armor blocks."""
    fd = os.open(work + "/runc.keyring", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        raw = source.read(8508)
    require(
        len(raw) == 8507 and hashlib.sha256(raw).hexdigest() == KEYRING_SHA,
        "keyring-source-digest",
    )
    begin, end = (
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----",
        b"-----END PGP PUBLIC KEY BLOCK-----",
    )
    require(raw.count(begin) == raw.count(end) == 3, "keyring-armor")
    pattern = (
        rb"(?m)^" + begin + rb"\nComment: github=[A-Za-z0-9]+\n\n"
        rb"([A-Za-z0-9+/=\n]+)\n" + end + rb"$"
    )
    blocks = re.findall(pattern, raw)
    require(
        len(blocks) == 3 and re.search(rb"(?m)^      " + SIGNER.encode() + rb"$", raw),
        "keyring-armor",
    )
    decoded = []
    for block in blocks:
        lines = block.splitlines()
        require(
            lines and re.fullmatch(rb"=[A-Za-z0-9+/]{4}", lines[-1]), "keyring-armor"
        )
        require(
            all(
                re.fullmatch(rb"[A-Za-z0-9+/]{1,64}={0,2}", line) for line in lines[:-1]
            ),
            "keyring-armor",
        )
        try:
            decoded.append(base64.b64decode(b"".join(lines[:-1]), validate=True))
        except binascii.Error:
            raise Incomplete("keyring-armor") from None
    binary = b"".join(decoded)
    require(
        [len(block) for block in decoded] == [1915, 1243, 2272]
        and len(binary) == 5430
        and hashlib.sha256(binary).hexdigest() == KEYRING_BINARY_SHA,
        "keyring-binary-digest",
    )
    path = work + "/runc-keyring.gpg"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        require(output.write(binary) == len(binary), "keyring-write")
    return path


def observe_signature():
    result = dict(
        status="incomplete",
        failure_class="public-signature-incomplete",
        cryptographic_signature_verified=False,
    )

    def expired(signum, frame):
        raise Incomplete("public-input-deadline")

    keyring_observed = False
    original = signal.signal(signal.SIGALRM, expired)
    # One original 60-second deadline covers all three downloads and gpgv.
    deadline = time.monotonic() + 60
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        with tempfile.TemporaryDirectory(prefix="gate0-public-inputs-") as work:
            os.chmod(work, 0o700)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), PublicRedirect()
            )
            for artifact in ARTIFACTS:
                download(opener, work, artifact, deadline)
            os.mkdir(work + "/gnupg", 0o700)
            home, keyring = work + "/gnupg", derive_keyring(work)
            keyring_observed = True
            signature, binary = work + "/runc.amd64.asc", work + "/runc.amd64"
            argv = ["/usr/bin/gpgv", "--homedir", home, "--keyring", keyring]
            argv += ["--status-fd=1", signature, binary]
            status = command(
                argv, timeout=min(10, max(0.001, deadline - time.monotonic()))
            )
            require(time.monotonic() < deadline, "public-input-deadline")
            result = signature_status(status)
            result["failure_class"] = "none"
    except EXPECTED_ERRORS as error:
        failure = (
            error.args[0]
            if isinstance(error, Incomplete)
            else "public-signature-incomplete"
        )
        result = dict(
            status="incomplete",
            failure_class=failure,
            cryptographic_signature_verified=False,
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)
    result["keyring_encoding"] = dict(
        original_listing_sha256=KEYRING_SHA,
        listed_fingerprint=SIGNER,
        expected_binary_sha256=KEYRING_BINARY_SHA,
        expected_binary_size=5430,
        binary_derivation_observed=keyring_observed,
    )
    return result


def metadata():
    result = {}
    keys = (
        "ImageVersion ImageOS ImageRelease GITHUB_SHA GITHUB_REPOSITORY "
        "GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_JOB"
    ).split()
    for key in keys:
        value = os.environ.get(key, "")
        pattern = r"[A-Za-z0-9_./+-]{1,128}"
        if key == "GITHUB_SHA":
            pattern = r"[0-9a-f]{40}"
        elif key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            pattern = r"[1-9][0-9]{0,19}"
        result[key] = value if re.fullmatch(pattern, value) else None
    return result


def main():
    require(len(sys.argv) == 1 and os.geteuid() != 0, "nonroot-required")
    record = dict(
        schema="DotmacNativeInputObservation.v1",
        context=metadata(),
        overall_native_pass=False,
        production_qualified=False,
        operational_selector_configured=False,
    )
    record["files"], record["runc_target"] = observe_metadata()
    record["os_release"] = {}
    try:
        with open("/etc/os-release", "rb") as source:
            raw = source.read(4097)
        require(len(raw) <= 4096, "os-release-bounds")
        for line in raw.decode("ascii").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("ID", "VERSION_ID", "UBUNTU_CODENAME"):
                record["os_release"][key] = text(value.strip('"'), r"[a-z0-9_.-]{1,64}")
    except EXPECTED_ERRORS:
        record["os_release"] = dict(failure_class="os-release-incomplete")
    signature = observe_signature()
    verifier = record["files"][-1].get("sha256")
    record["public_candidate"] = dict(
        release="v1.5.2",
        direct_signer=SIGNER,
        artifacts=[
            dict(name=name, url=url, size=size, sha256=digest)
            for name, url, size, digest in ARTIFACTS
        ],
        observation=signature,
        verifier_file_sha256=verifier,
    )
    complete = all(
        item["status"] == "observed-not-authenticated"
        and any("package" in package for package in item["packages"])
        and all(
            query.get("candidate_query", query)["failure_stage"] == "none"
            for query in item.get("package_queries", [])
        )
        for item in record["files"]
    )
    complete = (
        complete
        and all(
            record["context"].get(key)
            for key in (
                "ImageVersion",
                "ImageOS",
                "GITHUB_SHA",
                "GITHUB_REPOSITORY",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
                "GITHUB_JOB",
            )
        )
        and set(record["os_release"]) == {"ID", "VERSION_ID", "UBUNTU_CODENAME"}
    )
    record["status"] = (
        "candidate-observation-only"
        if complete and signature["cryptographic_signature_verified"]
        else "incomplete"
    )
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= LIMIT, "output-bounds")
    destination = Path(os.environ["RUNNER_TEMP"]) / "native-input-observation.json"
    with destination.open("xb") as output:
        os.chmod(destination, 0o600)
        require(output.write(raw) == len(raw), "output-write")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(125) from None
