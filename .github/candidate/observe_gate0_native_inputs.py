"""Non-root candidate input observation, not native or production proof.

Self-hashes and dpkg metadata only help locate independently signed packages.
The public runc ELF is signature-checked as data and is never executed.
GITHUB_SHA may be a synthetic merge; GITHUB_JOB is a key, not a numeric job ID.
"""

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
    "/usr/bin/gpgv",
)
BASE = "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.amd64"
BINARY_SHA = "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488"
SIGNATURE_SHA = "2b36d2bfd696ce0fb90e0b7d218f74a258eb1294586abc1130d561b9eb58c04f"
KEYRING_SHA = "9bd9742cb79b215cf5f7f71ea71a51a2a95ab573412d54c2905be072d8fcab7c"
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
STABLE_FIELDS = "st_dev st_ino st_mode st_size st_mtime_ns st_ctime_ns".split()
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


def packages(aliases):
    records = []
    for alias in sorted(set(aliases)):
        try:
            owners = command(["/usr/bin/dpkg-query", "--search", alias]).splitlines()
            require(0 < len(owners) <= 4)
            for owner in owners:
                package, separator, owned = owner.partition(": ")
                require(separator and owned == alias)
                text(package, r"[a-z0-9][a-z0-9+.-]{0,100}(:[a-z0-9]+)?")
                row = command(["/usr/bin/dpkg-query", "--show", QUERY, package])
                fields = row.rstrip("\n").split("\t")
                require(len(fields) == 3 and "\n" not in row.rstrip("\n"))
                names = ("package", "version", "architecture")
                entry = dict(zip(names, map(text, fields), strict=True))
                records.append(dict(alias=alias, **entry))
        except EXPECTED_ERRORS:
            records.append(dict(alias=alias, failure_class="package-incomplete"))
    return records


def observe_file(path):
    result = dict(
        lexical_path=path, status="incomplete", failure_class="file-incomplete"
    )
    try:
        resolved = os.path.realpath(path)
        require(
            resolved in (path, "/usr/lib/x86_64-linux-gnu/libc.so.6")
            and (path.endswith("/libc.so.6") or resolved == path),
            "unexpected-alias",
        )
        lexical = os.lstat(path)
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 << 20)
            hasher, received = hashlib.sha256(), 0
            while block := os.read(fd, 65536):
                received += len(block)
                require(received <= before.st_size)
                hasher.update(block)
            require(received == before.st_size)
            require(stable(before) == stable(os.fstat(fd)))
        finally:
            os.close(fd)
        result.update(
            status="observed-not-authenticated",
            failure_class="none",
            resolved_path=resolved,
            lexical_symlink=stat.S_ISLNK(lexical.st_mode),
            resolved_differs=resolved != path,
            size=before.st_size,
            mode=stat.S_IMODE(before.st_mode),
            sha256=hasher.hexdigest(),
            packages=packages((path, resolved)),
        )
    except FileNotFoundError:
        result["failure_class"] = "file-missing"
    except EXPECTED_ERRORS:
        result["failure_class"] = "file-incomplete"
    return result


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


def observe_signature():
    result = dict(
        status="incomplete",
        failure_class="public-signature-incomplete",
        cryptographic_signature_verified=False,
    )

    def expired(signum, frame):
        raise Incomplete("public-input-deadline")

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
            home, keyring = work + "/gnupg", work + "/runc.keyring"
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
    record["files"] = [observe_file(path) for path in FILES]
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
        for item in record["files"]
    )
    complete = (
        complete
        and all(record["context"].values())
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
