"""Read-only public Ubuntu package-chain observation; never install package data.

Bootstrap assumes the existing GitHub Ubuntu image's gpgv, archive keyring and
archive reader. Their self-hashes are observations, not native qualification.
"""

import hashlib
import json
import lzma
import os
import resource
import runpy
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

SIBLING = Path(__file__).parent
U = runpy.run_path(
    str(SIBLING / "observe_gate0_native_inputs.py"), run_name="public_utilities"
)
P = runpy.run_path(
    str(SIBLING / "inspect_gate0_publisher.py"), run_name="tar_framing_only"
)
require, Incomplete = U["require"], U["Incomplete"]
BASE = "https://snapshot.ubuntu.com/ubuntu/20261012T000000Z/"
DIST = "dists/noble-updates/"
INDEX = "main/binary-amd64/Packages.xz"
RELEASE = (126125, "73c1f36093b3247c866091dc6a486e887aa73665c013672cf240276f32348dd4")
INDEX_PIN = (
    1374820,
    "6ce2842640a6906a0ca97bb6575a3a3348241160f9bb1eaac46e477fcf99e053",
)
SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
FINGERPRINT_SOURCE = (
    "https://lists.ubuntu.com/archives/foundations-bugs/2020-May/422926.html"
)
# Exact reviewed coordinates; no caller selector or latest-package resolution.
PACKAGES = json.loads("""[
{"Package":"gpgv","Version":"2.4.4-2ubuntu17.6","Architecture":"amd64","Filename":"pool/main/g/gnupg2/gpgv_2.4.4-2ubuntu17.6_amd64.deb","Size":"158120","SHA256":"c8810069e98cd343c4c5c64b3ef5a0bb1f526419cff3266cd99ed4c87ad99868"},
{"Package":"libc6","Version":"2.39-0ubuntu8.9","Architecture":"amd64","Filename":"pool/main/g/glibc/libc6_2.39-0ubuntu8.9_amd64.deb","Size":"3264314","SHA256":"ff5557d99b51f761c4b7c92368b9cc45565eda17df9bf9eb4b134d09825008be"},
{"Package":"python3.12-minimal","Version":"3.12.3-1ubuntu0.17","Architecture":"amd64","Filename":"pool/main/p/python3.12/python3.12-minimal_3.12.3-1ubuntu0.17_amd64.deb","Size":"2334634","SHA256":"d452689b9660845345a4c3e05e4ad82c082d5474e04031b7aa47f1a6d5610a6e"},
{"Package":"systemd","Version":"255.4-1ubuntu8.17","Architecture":"amd64","Filename":"pool/main/s/systemd/systemd_255.4-1ubuntu8.17_amd64.deb","Size":"3475000","SHA256":"250345b73e42a97ee71cae7c1e470897dfad3c639eb0a7aafe4f9a3a29871cb2"}
]""")
MEMBERS = {
    "gpgv": ["usr/bin/gpgv"],
    "libc6": ["usr/lib/x86_64-linux-gnu/libc.so.6"],
    "python3.12-minimal": ["usr/bin/python3.12"],
    "systemd": ["usr/bin/systemd-run", "usr/bin/systemctl", "usr/lib/systemd/systemd"],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def local_hash(path):
    with open(path, "rb") as source:
        raw = source.read((32 << 20) + 1)
    require(0 < len(raw) <= 32 << 20, "bootstrap-file-bounds")
    return sha(raw)


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        require(
            parsed.scheme == "https"
            and parsed.netloc == "snapshot.ubuntu.com"
            and parsed.path.startswith("/ubuntu/20261012T000000Z/")
            and not parsed.query
            and not parsed.fragment,
            "snapshot-redirect",
        )
        return super().redirect_request(request, response, code, message, headers, url)


def fetch(work, name, relative, pin, deadline):
    require(time.monotonic() < deadline, "package-deadline")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    request = urllib.request.Request(BASE + relative)  # noqa: S310
    with opener.open(request, timeout=min(10, deadline - time.monotonic())) as response:
        require(response.geturl() == BASE + relative, "snapshot-redirect")
        fd = os.open(
            work + "/" + name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as output:
            hasher, count = hashlib.sha256(), 0
            while block := response.read1(65536):
                count += len(block)
                require(
                    time.monotonic() < deadline and count <= pin[0],
                    "package-download-bounds",
                )
                hasher.update(block)
                require(output.write(block) == len(block), "package-write")
    require(
        time.monotonic() < deadline
        and count == pin[0]
        and hasher.hexdigest() == pin[1],
        "package-download-digest",
    )
    return Path(work) / name


def signed_status(raw):
    rows = [line.split() for line in raw.splitlines()]
    require(
        len(rows) <= 64 and all(len(line) <= 4096 for line in raw.splitlines()),
        "release-signature-status",
    )
    allowed = {"NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG"}
    require(
        all(
            len(row) >= 2 and row[0] == "[GNUPG:]" and row[1] in allowed for row in rows
        ),
        "release-signature-status",
    )
    valid = [row for row in rows if row[1] == "VALIDSIG"]
    require(
        len(valid) == 1 and len(valid[0]) in (11, 12) and valid[0][2] == SIGNER,
        "release-signature-signer",
    )
    return dict(cryptographic_signature_verified=True, direct_fingerprint=SIGNER)


def release_chain(raw):
    require(raw.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n"), "release-framing")
    body = raw.split(b"\n\n", 1)[1].split(b"-----BEGIN PGP SIGNATURE-----", 1)[0]
    matches, selected = [], False
    for line in body.decode("ascii").splitlines():
        if line == "SHA256:":
            selected = True
        elif line and not line.startswith(" "):
            selected = False
        elif selected:
            fields = line.split()
            require(len(fields) == 3, "release-sha256-shape")
            if fields[2] == INDEX:
                matches.append((int(fields[1]), fields[0]))
    require(matches == [INDEX_PIN], "release-index-mismatch")


def package_index(raw):
    decoder = lzma.LZMADecompressor(memlimit=64 << 20)
    clear = decoder.decompress(raw, max_length=(32 << 20) + 1)
    require(
        len(clear) <= 32 << 20 and decoder.eof and not decoder.unused_data,
        "index-decompression-bounds",
    )
    expected = {item["Package"]: item for item in PACKAGES}
    found = set()
    blocks = clear.decode("utf-8").split("\n\n")
    require(len(blocks) <= 100000, "index-stanza-bounds")
    for block in blocks:
        require(len(block) <= 65536, "index-stanza-bounds")
        fields = {}
        for line in block.splitlines():
            require(len(line) <= 8192, "index-line-bounds")
            if line.startswith((" ", "\t")):
                continue
            key, separator, value = line.partition(": ")
            require(separator and key not in fields, "index-field-shape")
            fields[key] = value
        name = fields.get("Package")
        if name in expected:
            require(
                name not in found
                and all(
                    fields.get(key) == value for key, value in expected[name].items()
                ),
                "index-package-mismatch",
            )
            found.add(name)
    require(found == set(expected), "index-package-missing")


def package_members(package, archive, work, deadline):
    target = work + "/package-data.tar"
    fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w+b") as stream:

        def bounded():
            resource.setrlimit(resource.RLIMIT_FSIZE, (128 << 20, 128 << 20))

        result = subprocess.run(  # noqa: S603
            ["/usr/bin/dpkg-deb", "--fsys-tarfile", str(archive)],
            stdout=stream,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=U["ENV"],
            close_fds=True,
            check=False,
            timeout=min(10, max(0.001, deadline - time.monotonic())),
            preexec_fn=bounded,
        )
        require(
            result.returncode == 0 and 0 < stream.tell() <= 128 << 20,
            "package-data-reader",
        )
        P["bounded_tar_headers"](stream)  # Reject sparse/PAX abuse before tarfile.
        wanted, found = set(MEMBERS[package]), {}
        with tarfile.open(fileobj=stream, mode="r:") as tar:
            for member in tar:
                name = member.name.removeprefix("./")
                if name in wanted:
                    require(
                        name not in found
                        and member.isfile()
                        and not member.sparse
                        and 0 < member.size <= 64 << 20,
                        "package-member-shape",
                    )
                    source = tar.extractfile(member)
                    require(source is not None, "package-member-shape")
                    with source:
                        hasher, count = hashlib.sha256(), 0
                        while block := source.read(65536):
                            count += len(block)
                            require(count <= member.size, "package-member-bounds")
                            hasher.update(block)
                    require(count == member.size, "package-member-bounds")
                    found[name] = dict(
                        path="/" + name,
                        size=count,
                        mode=member.mode & 0o7777,
                        sha256=hasher.hexdigest(),
                    )
        require(set(found) == wanted, "package-member-missing")
    os.unlink(target)  # Only this owned temporary data-reader output.
    return list(found.values())


def observed_files(context):
    path = Path(os.environ["RUNNER_TEMP"]) / "native-input-observation.json"
    try:
        with path.open("rb") as source:
            raw = source.read(65537)
        require(len(raw) <= 65536, "prior-observation-bounds")
        record = json.loads(raw)
        require(
            all(
                context.get(key)
                for key in (
                    "GITHUB_SHA",
                    "GITHUB_REPOSITORY",
                    "GITHUB_RUN_ID",
                    "GITHUB_RUN_ATTEMPT",
                    "GITHUB_JOB",
                )
            ),
            "prior-observation-context",
        )
        require(
            record["schema"] == "DotmacNativeInputObservation.v1"
            and all(
                record["context"].get(key) == context.get(key)
                for key in (
                    "GITHUB_SHA",
                    "GITHUB_REPOSITORY",
                    "GITHUB_RUN_ID",
                    "GITHUB_RUN_ATTEMPT",
                    "GITHUB_JOB",
                )
            ),
            "prior-observation-context",
        )
        return {
            item["resolved_path"]: item
            for item in record["files"]
            if "resolved_path" in item
        }
    except (OSError, ValueError, KeyError, Incomplete):
        return {}


def main():
    require(len(sys.argv) == 1 and os.geteuid() != 0, "nonroot-required")
    context = U["metadata"]()
    record = dict(
        schema="DotmacUbuntuPackageObservation.v1",
        context=context,
        status="incomplete",
        failure_class="package-chain-incomplete",
        packages=[],
        overall_native_pass=False,
        production_qualified=False,
        operational_selector_configured=False,
        bootstrap_assumption=(
            "Existing GitHub Ubuntu image gpgv, Ubuntu archive "
            "keyring and dpkg-deb; self-hashes do not qualify tools"
        ),
        fingerprint_source=FINGERPRINT_SOURCE,
    )

    def expired(signum, frame):
        raise Incomplete("package-deadline")

    record["release_signature"] = dict(cryptographic_signature_verified=False)
    record["metadata_inputs"] = [
        dict(url=BASE + DIST + "InRelease", size=RELEASE[0], sha256=RELEASE[1]),
        dict(url=BASE + DIST + INDEX, size=INDEX_PIN[0], sha256=INDEX_PIN[1]),
    ]
    previous = signal.signal(signal.SIGALRM, expired)
    deadline = time.monotonic() + 120
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        record["bootstrap_hashes"] = {
            path: local_hash(path)
            for path in ("/usr/bin/gpgv", KEYRING, "/usr/bin/dpkg-deb")
        }
        with tempfile.TemporaryDirectory(prefix="gate0-ubuntu-packages-") as work:
            release = fetch(work, "InRelease", DIST + "InRelease", RELEASE, deadline)
            os.mkdir(work + "/gnupg", 0o700)
            status = U["command"](
                [
                    "/usr/bin/gpgv",
                    "--homedir",
                    work + "/gnupg",
                    "--keyring",
                    KEYRING,
                    "--status-fd=1",
                    str(release),
                ],
                timeout=min(10, max(0.001, deadline - time.monotonic())),
            )
            record["release_signature"] = signed_status(status)
            release_chain(release.read_bytes())
            index = fetch(work, "Packages.xz", DIST + INDEX, INDEX_PIN, deadline)
            package_index(index.read_bytes())
            observed = observed_files(context)
            for candidate in PACKAGES:
                archive = fetch(
                    work,
                    candidate["Package"] + ".deb",
                    candidate["Filename"],
                    (int(candidate["Size"]), candidate["SHA256"]),
                    deadline,
                )
                members = package_members(candidate["Package"], archive, work, deadline)
                for member in members:
                    actual = observed.get(member["path"])
                    member["observed_match"] = (
                        "unobserved"
                        if actual is None
                        else "match"
                        if all(
                            actual.get(key) == member[key]
                            for key in ("size", "mode", "sha256")
                        )
                        else "mismatch"
                    )
                record["packages"].append(dict(candidate=candidate, members=members))
            require(time.monotonic() < deadline, "package-deadline")
            matched = all(
                member["observed_match"] == "match"
                for package in record["packages"]
                for member in package["members"]
            )
            record["failure_class"] = "none" if matched else "tool-bytes-unmatched"
            record["status"] = (
                "package-candidate-observation-only" if matched else "incomplete"
            )
    except (
        *U["EXPECTED_ERRORS"],
        ValueError,
        KeyError,
        IndexError,
        tarfile.TarError,
        lzma.LZMAError,
    ):
        record["failure_class"] = "package-chain-incomplete"
        record["status"] = "incomplete"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= 65536, "output-bounds")
    with (Path(os.environ["RUNNER_TEMP"]) / "ubuntu-package-observation.json").open(
        "xb"
    ) as output:
        os.fchmod(output.fileno(), 0o600)
        require(output.write(raw) == len(raw), "output-write")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(125) from None
