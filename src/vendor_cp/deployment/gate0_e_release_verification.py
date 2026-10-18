"""Installed official-gh release assertion verification; no E acceptance authority."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import resource
from dataclasses import dataclass, field

from vendor_cp.deployment.gate0_e_github import (
    AttestationTransportUnqualified,
    DownloadedReleaseFacts,
    InstalledGate0GitHubReads,
)

_GH_SOURCE = "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"
_JSON_CAP = 1024 * 1024
_SEAL = object()


def _require(condition: bool) -> None:
    if not condition:
        raise AttestationTransportUnqualified()


def _object(value: object, fields: str | None = None) -> dict[str, object]:
    _require(isinstance(value, dict))
    if not isinstance(value, dict):
        raise AttestationTransportUnqualified()
    result: dict[str, object] = {}
    for key, child in value.items():
        _require(isinstance(key, str))
        if not isinstance(key, str):
            raise AttestationTransportUnqualified()
        result[key] = child
    if fields is not None:
        _require(set(result) == set(fields.split()))
    return result


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise AttestationTransportUnqualified()
    return value


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AttestationTransportUnqualified()
    return list(value)


def _json(raw: bytes) -> object:
    _require(0 < len(raw) <= _JSON_CAP)

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    def invalid(value: str) -> object:
        raise AttestationTransportUnqualified()

    def bound(value: object, depth: int) -> None:
        _require(depth <= 32)
        if isinstance(value, dict):
            _require(len(value) <= 2048)
            for key, child in value.items():
                bound(key, depth + 1)
                bound(child, depth + 1)
        elif isinstance(value, list):
            _require(len(value) <= 2048)
            for child in value:
                bound(child, depth + 1)
        elif isinstance(value, str):
            _require(len(value) <= 750000)

    try:
        parsed: object = json.loads(
            raw, object_pairs_hook=pairs, parse_constant=invalid
        )
        bound(parsed, 0)
        return parsed
    except Exception:
        raise AttestationTransportUnqualified() from None


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ReleaseCommandEvidence:
    """Output preserved after owned process success, not a verification capability."""

    command: str
    asset_id: int | None
    sha256: str
    raw: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedReleaseAssertion:
    repository_id: int
    owner_id: int
    release_id: int
    tag: str
    raw_tag_sha: str
    peeled_commit: str
    assets: tuple[tuple[int, str, int, str], ...]
    gh_sha256: str
    qualification_sha256: str
    commands: tuple[ReleaseCommandEvidence, ...]


def _decode_statement(raw: bytes) -> dict[str, object]:
    """Decode only: caller bytes never establish cryptographic success."""
    outer = _object(_json(raw), "attestation verificationResult")
    attestation = _object(outer["attestation"], "bundle bundle_url initiator")
    _text(attestation["bundle_url"])
    _text(attestation["initiator"])
    bundle = _object(attestation["bundle"])
    _require(set(bundle) <= {"mediaType", "verificationMaterial", "dsseEnvelope"})
    _require({"mediaType", "verificationMaterial", "dsseEnvelope"} <= set(bundle))
    _require(bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json")
    _object(bundle["verificationMaterial"])
    dsse = _object(bundle["dsseEnvelope"], "payloadType payload signatures")
    _require(dsse["payloadType"] == "application/vnd.in-toto+json")
    signatures = _array(dsse["signatures"])
    _require(bool(signatures))
    for entry in signatures:
        signature = _object(entry)
        _require(set(signature) in ({"sig"}, {"sig", "keyid"}))
        if "keyid" in signature:
            _text(signature["keyid"])
        _require(bool(base64.b64decode(_text(signature["sig"]), validate=True)))
    payload = base64.b64decode(_text(dsse["payload"]), validate=True)
    decoded = _object(_json(payload), "_type subject predicateType predicate")
    result = _object(outer["verificationResult"])
    _require({"mediaType", "statement", "signature"} <= set(result))
    _require(
        set(result)
        <= {
            "mediaType",
            "statement",
            "signature",
            "verifiedTimestamps",
            "verifiedIdentity",
        }
    )
    _require(
        result["mediaType"]
        == "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
    )
    signature_result = _object(result["signature"])
    _require(set(signature_result) == {"certificate"})
    _object(signature_result["certificate"])
    timestamps = _array(result.get("verifiedTimestamps"))
    _require(bool(timestamps))
    for timestamp in timestamps:
        item = _object(timestamp, "type uri timestamp")
        _require(item["type"] == "TimestampAuthority")
        _require(bool(_text(item["uri"])) and bool(_text(item["timestamp"])))
    if "verifiedIdentity" in result:
        _object(result["verifiedIdentity"])
    _require(_object(result["statement"]) == decoded)
    _require(decoded["_type"] == "https://in-toto.io/Statement/v1")
    _require(decoded["predicateType"] == "https://in-toto.io/attestation/release/v0.1")
    return decoded


def _statement(raw: bytes) -> dict[str, object]:
    try:
        return _decode_statement(raw)
    except Exception:
        raise AttestationTransportUnqualified() from None


def _join(
    statement: dict[str, object],
    facts: DownloadedReleaseFacts,
    repository: str,
    release_subject: str,
    purl: str,
) -> None:
    predicate = _object(
        statement["predicate"], "ownerId purl releaseId repository repositoryId tag"
    )
    _require(
        predicate
        == {
            "ownerId": str(facts.owner_id),
            "purl": purl,
            "releaseId": str(facts.release_id),
            "repository": repository,
            "repositoryId": str(facts.repository_id),
            "tag": facts.tag,
        }
    )
    expected: dict[str, dict[str, str]] = {
        release_subject: {"sha1": facts.raw_tag_sha},
    }
    for asset in facts.assets:
        _require(asset.name not in expected)
        expected[asset.name] = {"sha256": asset.sha256}
    actual: dict[str, dict[str, str]] = {}
    for subject in _array(statement["subject"]):
        item = _object(subject)
        _require(set(item) in ({"name", "digest"}, {"uri", "digest"}))
        name = _text(item["name"] if "name" in item else item["uri"])
        _require((name == release_subject) == ("uri" in item))
        _require(name not in actual)
        digest = _object(item["digest"])
        actual[name] = {key: _text(value) for key, value in digest.items()}
    _require(actual == expected)


_INSTALLATION = "/run/dotmac-gate0-e/release-verifier.json"
_BINDING = "/etc/dotmac-gate0-e/release-verifier-binding.json"
_QUALIFICATION = "/etc/dotmac-gate0-e/release-verifier-qualification.json"
_NATIVE = "/etc/dotmac-gate0-e/release-verifier-native.json"
_CREDENTIAL = "/run/dotmac-gate0-e/github-read-token"
_WORK = "/run/dotmac-gate0-e/gh-work"
_CA = "/etc/ssl/certs/ca-certificates.crt"
_POLICY = {
    "aggregate_seconds": 120,
    "cleanup_seconds": 2,
    "stdout_bytes": _JSON_CAP,
    "address_space_bytes": 8 * 1024**3,
    "cpu_seconds": 120,
    "file_bytes": 32 * 1024**2,
    "open_files": 64,
    "uid_tasks": 64,
    "filesystem_bytes": 64 * 1024**2,
    "filesystem_inodes": 4096,
}


def _protected(path: str, maximum: int, *, uid: int = 0, private: bool = True) -> bytes:
    # Intentional same-assembly reuse: this owner defines no-follow/root ancestry.
    from vendor_cp.deployment.gate0_e_github import _protected as read

    return read(path, maximum, leaf_uid=uid, private=private)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _pin(value: object, maximum: int = _JSON_CAP) -> tuple[str, bytes]:
    pin = _object(value, "path sha256")
    path, digest = _text(pin["path"]), _text(pin["sha256"])
    _require(path.startswith("/") and re.fullmatch(r"[a-f0-9]{64}", digest) is not None)
    raw = _protected(path, maximum, private=False)
    _require(_sha(raw) == digest)
    return path, raw


def _integer(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise AttestationTransportUnqualified()
    return value


def _before(deadline: float) -> None:
    import time

    _require(time.monotonic() < deadline)


def _limits() -> None:
    """Fixed child-only kernel limits; native qualification must prove suitability."""
    for kind, amount in (
        (resource.RLIMIT_AS, _POLICY["address_space_bytes"]),
        (resource.RLIMIT_CPU, _POLICY["cpu_seconds"]),
        (resource.RLIMIT_FSIZE, _POLICY["file_bytes"]),
        (resource.RLIMIT_NOFILE, _POLICY["open_files"]),
        (resource.RLIMIT_NPROC, _POLICY["uid_tasks"]),
        (resource.RLIMIT_CORE, 0),
    ):
        resource.setrlimit(kind, (amount, amount))
    os.umask(0o077)


def _command(argv: list[str], env: dict[str, str], cwd: str, deadline: float) -> bytes:
    """Fixed adapter's child; one absolute work/cleanup boundary for all commands."""
    import selectors
    import signal
    import subprocess
    import time

    work_end = deadline - _POLICY["cleanup_seconds"]
    _before(work_end)
    _require(len(os.listdir("/proc/self/task")) == 1)
    process = subprocess.Popen(  # noqa: S603 -- pinned official binary, fixed command
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=cwd,
        close_fds=True,
        start_new_session=True,
        preexec_fn=_limits,
    )
    output = bytearray()
    completed = False
    cleanup_failed = False
    try:
        _require(process.stdout is not None)
        if process.stdout is None:
            raise AttestationTransportUnqualified()
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                _before(work_end)
                for key, _ in selector.select(
                    min(0.05, max(0, work_end - time.monotonic()))
                ):
                    chunk = os.read(key.fd, min(65536, _JSON_CAP + 1 - len(output)))
                    if not chunk:
                        selector.unregister(process.stdout)
                    else:
                        output.extend(chunk)
                        _require(len(output) <= _JSON_CAP)
            _before(work_end)
            _require(process.wait(timeout=work_end - time.monotonic()) == 0)
            _before(work_end)
            completed = True
    finally:
        # Never resignal a reaped PID. A native-qualified fixed binary/profile
        # must establish group cancellation contains every possible descendant.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                cleanup_failed = True
                try:
                    process.kill()
                except BaseException:
                    cleanup_failed = True
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException:
                    cleanup_failed = True
        if process.returncode is None:
            try:
                remaining = deadline - time.monotonic()
                _require(remaining > 0)
                process.wait(timeout=remaining)
            except BaseException:
                cleanup_failed = True
        if not completed or cleanup_failed or time.monotonic() >= deadline:
            output.clear()
            raise AttestationTransportUnqualified() from None
    return bytes(output)


class InstalledGhReleaseVerifier:
    """Single use, fixed installed selection; qualification is externally installed."""

    __slots__ = (
        "_installation",
        "_qualification",
        "_binary",
        "_used",
        "_qual_digest",
        "_binary_digest",
        "_binding_digest",
    )

    def __init__(
        self,
        seal: object,
        installation: dict[str, object],
        qualification: dict[str, object],
        binary: str,
        qualification_digest: str,
        binary_digest: str,
        binding_digest: str = "",
    ) -> None:
        _require(seal is _SEAL)
        self._installation = installation
        self._qualification = qualification
        self._binary = binary
        self._used = False
        self._qual_digest = qualification_digest
        self._binary_digest = binary_digest
        self._binding_digest = binding_digest

    @classmethod
    def from_installed(cls) -> InstalledGhReleaseVerifier:
        import platform
        import sys

        try:
            _require(sys.platform == "linux")
            raw = _protected(_INSTALLATION, _JSON_CAP, private=False)
            installation = _object(
                _json(raw), "schema repository release gh interpreter qualification"
            )
            _require(
                raw == _canonical(installation)
                and installation["schema"] == "Gate0EGhReleaseInstallation.v1"
            )
            _selection(installation)
            binding_raw = _protected(_BINDING, _JSON_CAP, private=False)
            binding = _object(
                _json(binding_raw),
                "schema installation_sha256 qualification_sha256 native_receipt "
                "source_sha256 runtime_uid credential_uid reader_binding_sha256 "
                "runtime_image_digest",
            )
            _require(
                binding_raw == _canonical(binding)
                and binding["schema"] == "Gate0EGhReleaseRootBinding.v1"
            )
            _require(binding["installation_sha256"] == _sha(raw))
            uid = _integer(binding["runtime_uid"])
            _require(os.getuid() == os.geteuid() == uid)
            _require(
                type(binding["credential_uid"]) is int
                and binding["credential_uid"] in (0, uid)
            )
            _require(
                re.fullmatch(r"[a-f0-9]{64}", _text(binding["runtime_image_digest"]))
                is not None
            )
            _require(
                _sha(_protected(os.path.abspath(__file__), _JSON_CAP, private=False))
                == binding["source_sha256"]
            )
            _require(
                _object(installation["qualification"], "path sha256")["path"]
                == _QUALIFICATION
            )
            _, qualification_raw = _pin(installation["qualification"])
            qualification = _object(
                _json(qualification_raw),
                "schema gh_source gh_version installation_policy_sha256 "
                "resource_policy "
                "runtime_uid credential_uid kernel boot_id work_mountinfo_sha256 "
                "ca_sha256 source_sha256 reader_binding_sha256 runtime_image_digest "
                "output_profile process_profile network_profile native_receipt",
            )
            _require(qualification_raw == _canonical(qualification))
            _require(qualification["schema"] == "Gate0EGhReleaseNativeQualification.v1")
            _require(_sha(qualification_raw) == binding["qualification_sha256"])
            _require(
                qualification["gh_source"] == _GH_SOURCE
                and qualification["gh_version"] == "2.102.0"
            )
            for name in (
                "runtime_uid",
                "credential_uid",
                "source_sha256",
                "reader_binding_sha256",
                "runtime_image_digest",
                "native_receipt",
            ):
                _require(qualification[name] == binding[name])
            _require(
                qualification["installation_policy_sha256"]
                == _sha(
                    _canonical(
                        {
                            key: value
                            for key, value in installation.items()
                            if key != "qualification"
                        }
                    )
                )
            )
            _require(qualification["resource_policy"] == _POLICY)
            _require(
                qualification["output_profile"] == "gh-2.102-release-single-result-v1"
            )
            _require(
                qualification["process_profile"]
                == "dedicated-uid-contained-gh-group-v1"
            )
            _require(
                qualification["network_profile"]
                == "github-release-tuf-ca-isolated-cache-v1"
            )
            _require(qualification["kernel"] == platform.release())
            _require(qualification["boot_id"] == _boot_id())
            _require(
                _object(binding["native_receipt"], "path sha256")["path"] == _NATIVE
            )
            _, receipt_raw = _pin(binding["native_receipt"])
            receipt = _object(
                _json(receipt_raw),
                "schema qualification_measurements_digest runtime_identity_digest "
                "reviewer_record_digest",
            )
            _require(receipt["schema"] == "Gate0ENativeReviewReceipt.v1")
            for name in (
                "qualification_measurements_digest",
                "runtime_identity_digest",
                "reviewer_record_digest",
            ):
                _require(
                    re.fullmatch(r"[a-f0-9]{64}", _text(receipt[name])) is not None
                )
            reader_binding = _protected(
                "/etc/dotmac-gate0-e/github-read-published-release-binding.json",
                _JSON_CAP,
                private=False,
            )
            _require(_sha(reader_binding) == binding["reader_binding_sha256"])
            _require(
                _sha(_protected(_CA, 2 * _JSON_CAP, private=False))
                == qualification["ca_sha256"]
            )
            interpreter, _ = _pin(installation["interpreter"], 128 * _JSON_CAP)
            _require(os.path.realpath(sys.executable) == interpreter)
            binary, binary_raw = _pin(installation["gh"], 128 * _JSON_CAP)
            _require(os.access(binary, os.X_OK))
            cls._work_profile(qualification)
            return cls(
                _SEAL,
                installation,
                qualification,
                binary,
                _sha(qualification_raw),
                _sha(binary_raw),
                _sha(binding_raw),
            )
        except Exception:
            raise AttestationTransportUnqualified() from None

    @staticmethod
    def _work_profile(qualification: dict[str, object]) -> None:
        import stat

        info = os.stat(_WORK, follow_symlinks=False)
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )
        # Full dedicated mount record is bound by native installation. Its total
        # capacity is a real aggregate storage cap, unlike per-file RLIMIT_FSIZE.
        with open("/proc/self/mountinfo", "rb") as source:
            records = source.read(_JSON_CAP + 1)
        _require(len(records) <= _JSON_CAP)
        selected = [
            line
            for line in records.splitlines()
            if len(line.split()) > 5 and line.split()[4] == _WORK.encode()
        ]
        _require(
            len(selected) == 1
            and _sha(selected[0]) == qualification["work_mountinfo_sha256"]
        )
        _require(b" - tmpfs " in selected[0])
        storage = os.statvfs(_WORK)
        _require(0 < storage.f_blocks * storage.f_frsize <= _POLICY["filesystem_bytes"])
        _require(0 < storage.f_files <= _POLICY["filesystem_inodes"])

    def _runtime_profile(self) -> None:
        _require(
            _protected(_INSTALLATION, _JSON_CAP, private=False)
            == _canonical(self._installation)
        )
        _require(
            _sha(_protected(_BINDING, _JSON_CAP, private=False)) == self._binding_digest
        )
        binary, raw = _pin(self._installation["gh"], 128 * _JSON_CAP)
        _require(binary == self._binary and _sha(raw) == self._binary_digest)
        _require(
            _sha(_protected(_CA, 2 * _JSON_CAP, private=False))
            == self._qualification["ca_sha256"]
        )

    def _reader_profile(self, reads: InstalledGate0GitHubReads) -> None:
        raw = _protected(
            "/etc/dotmac-gate0-e/github-read-published-release-binding.json",
            _JSON_CAP,
            private=False,
        )
        _require(_sha(raw) == self._qualification["reader_binding_sha256"])
        binding = _object(_json(raw))
        _require(
            binding.get("installation_sha256") == _sha(_canonical(reads._installation))
        )
        _require(
            binding.get("qualification_sha256")
            == _sha(_canonical(reads._qualification))
        )

    def verify_published(
        self, reads: InstalledGate0GitHubReads, facts: DownloadedReleaseFacts
    ) -> VerifiedReleaseAssertion:
        import shutil
        import tempfile
        import time
        from urllib.parse import quote

        _require(not self._used)
        self._used = True
        directory: str | None = None
        directory_identity: tuple[int, int] | None = None
        env: dict[str, str] = {}
        staged: dict[str, tuple[tuple[int, int], bytes]] = {}
        result: VerifiedReleaseAssertion | None = None
        failed = False
        deadline = time.monotonic() + _POLICY["aggregate_seconds"]
        try:
            _require(
                type(reads) is InstalledGate0GitHubReads
                and type(facts) is DownloadedReleaseFacts
                and reads.owns_facts(facts)
            )
            self._runtime_profile()
            self._reader_profile(reads)
            repository = _object(
                self._installation["repository"], "owner name repository_id owner_id"
            )
            owner, name = _text(repository["owner"]), _text(repository["name"])
            _require(
                all(
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item) is not None
                    and item not in (".", "..")
                    for item in (owner, name)
                )
            )
            full_name = owner + "/" + name
            release = _object(
                self._installation["release"],
                "release_id tag raw_tag_sha peeled_commit assets",
            )
            for field_name in ("repository_id", "owner_id"):
                _integer(repository[field_name])
            _integer(release["release_id"])
            expected_assets = [
                _object(item, "id name size sha256")
                for item in _array(release["assets"])
            ]
            _require(
                not facts.draft
                and facts.immutable
                and len(facts.assets) == len(expected_assets) == 3
            )
            _require(
                repository["repository_id"] == facts.repository_id
                and repository["owner_id"] == facts.owner_id
            )
            _require(
                release["release_id"] == facts.release_id
                and release["tag"] == facts.tag
                and release["raw_tag_sha"] == facts.raw_tag_sha
                and release["peeled_commit"] == facts.peeled_commit
            )
            _require(
                re.fullmatch(r"[a-f0-9]{40}", facts.raw_tag_sha) is not None
                and re.fullmatch(r"[a-f0-9]{40}", facts.peeled_commit) is not None
            )
            _require(
                bool(facts.tag)
                and not facts.tag.startswith("-")
                and len(facts.tag) <= 200
            )
            for asset, expected in zip(facts.assets, expected_assets, strict=True):
                _integer(expected["id"])
                _integer(expected["size"])
                _require(
                    expected
                    == {
                        "id": asset.id,
                        "name": asset.name,
                        "size": asset.size,
                        "sha256": asset.sha256,
                    }
                )
                _require(
                    asset.size == len(asset.raw_bytes)
                    and _sha(asset.raw_bytes) == asset.sha256
                )
            _require(
                [asset.name for asset in facts.assets]
                == [
                    "gate0-evidence.pgp",
                    "gate0-evidence-public.json",
                    "gate0-readiness-receipt.json",
                ]
            )
            self._work_profile(self._qualification)
            _before(deadline - _POLICY["cleanup_seconds"])
            directory = tempfile.mkdtemp(prefix="release-", dir=_WORK)
            os.chmod(directory, 0o700)
            directory_stat = os.stat(directory, follow_symlinks=False)
            directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
            for subdir in ("config", "cache", "scratch"):
                os.mkdir(directory + "/" + subdir, 0o700)
            token = _protected(
                _CREDENTIAL,
                16384,
                uid=_integer(self._qualification["credential_uid"])
                if self._qualification["credential_uid"] != 0
                else 0,
            )
            _require(bool(token) and all(32 < byte < 127 for byte in token))
            env = {
                "GH_TOKEN": token.decode("ascii"),
                "GH_HOST": "github.com",
                "GH_CONFIG_DIR": directory + "/config",
                "XDG_CACHE_HOME": directory + "/cache",
                "HOME": directory,
                "TMPDIR": directory + "/scratch",
                "GH_PROMPT_DISABLED": "1",
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
                "NO_COLOR": "1",
                "TERM": "dumb",
                "GOMAXPROCS": "2",
            }
            token = b""
            commands: list[ReleaseCommandEvidence] = []
            base = [
                self._binary,
                "release",
                "verify",
                facts.tag,
                "--repo",
                full_name,
                "--format",
                "json",
            ]
            raw = _command(base, env, directory, deadline)
            statement = _statement(raw)
            _before(deadline - _POLICY["cleanup_seconds"])
            purl = "pkg:github/" + full_name + "@" + quote(facts.tag, safe="")
            _join(statement, facts, full_name, purl, purl)
            commands.append(ReleaseCommandEvidence("verify", None, _sha(raw), raw))
            for asset in facts.assets:
                _before(deadline - _POLICY["cleanup_seconds"])
                _require(
                    asset.size
                    <= {
                        "gate0-evidence.pgp": 17 * _JSON_CAP,
                        "gate0-evidence-public.json": 65536,
                        "gate0-readiness-receipt.json": 131072,
                    }[asset.name]
                )
                path = directory + "/" + asset.name
                fd = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(asset.raw_bytes)
                        stream.flush()
                        os.fsync(fd)
                    identity = os.fstat(fd)
                    staged[path] = ((identity.st_dev, identity.st_ino), asset.raw_bytes)
                finally:
                    os.close(fd)
                _require(
                    _staged(
                        path,
                        (identity.st_dev, identity.st_ino),
                        asset.raw_bytes,
                        deadline - _POLICY["cleanup_seconds"],
                    )
                )
                raw = _command(
                    [
                        self._binary,
                        "release",
                        "verify-asset",
                        facts.tag,
                        path,
                        "--repo",
                        full_name,
                        "--format",
                        "json",
                    ],
                    env,
                    directory,
                    deadline,
                )
                _require(_statement(raw) == statement)
                _before(deadline - _POLICY["cleanup_seconds"])
                _require(
                    _staged(
                        path,
                        (identity.st_dev, identity.st_ino),
                        asset.raw_bytes,
                        deadline - _POLICY["cleanup_seconds"],
                    )
                )
                current = os.stat(path, follow_symlinks=False)
                _require(
                    (current.st_dev, current.st_ino)
                    == (identity.st_dev, identity.st_ino)
                )
                os.unlink(path)
                del staged[path]
                commands.append(
                    ReleaseCommandEvidence("verify-asset", asset.id, _sha(raw), raw)
                )
            env.clear()
            self._runtime_profile()
            _before(deadline - _POLICY["cleanup_seconds"])
            _require(reads.owns_facts(facts))
            result = VerifiedReleaseAssertion(
                facts.repository_id,
                facts.owner_id,
                facts.release_id,
                facts.tag,
                facts.raw_tag_sha,
                facts.peeled_commit,
                tuple(
                    (asset.id, asset.name, asset.size, asset.sha256)
                    for asset in facts.assets
                ),
                self._binary_digest,
                self._qual_digest,
                tuple(commands),
            )
        except Exception:
            failed = True
        finally:
            env.clear()
            if directory is not None:
                try:
                    for staged_path, (staged_identity, staged_bytes) in staged.items():
                        _require(
                            _staged(
                                staged_path, staged_identity, staged_bytes, deadline
                            )
                        )
                    _before(deadline)
                    cleanup_stat = os.stat(directory, follow_symlinks=False)
                    _before(deadline)
                    _require(
                        (cleanup_stat.st_dev, cleanup_stat.st_ino) == directory_identity
                    )
                    shutil.rmtree(directory)
                    _before(deadline)
                except BaseException:
                    failed = True
            if time.monotonic() >= deadline:
                failed = True
        if failed or result is None:
            raise AttestationTransportUnqualified() from None
        return result


def _boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
        return source.read(128).strip()


def _staged(
    path: str, identity: tuple[int, int], expected: bytes, deadline: float
) -> bool:
    import stat

    _before(deadline)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _before(deadline)
        info = os.fstat(descriptor)
        _before(deadline)
        _require((info.st_dev, info.st_ino) == identity)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid())
        _require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
        _require(info.st_size == len(expected))
        data = bytearray()
        while len(data) <= len(expected):
            _before(deadline)
            part = os.read(descriptor, min(65536, len(expected) + 1 - len(data)))
            _before(deadline)
            if not part:
                break
            data.extend(part)
        return bytes(data) == expected
    finally:
        os.close(descriptor)
        _before(deadline)


def _selection(installation: dict[str, object]) -> None:
    repository = _object(
        installation["repository"], "owner name repository_id owner_id"
    )
    for name in ("repository_id", "owner_id"):
        _integer(repository[name])
    for name in ("owner", "name"):
        text = _text(repository[name])
        _require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", text) is not None)
        _require(text not in (".", ".."))
    release = _object(
        installation["release"], "release_id tag raw_tag_sha peeled_commit assets"
    )
    _integer(release["release_id"])
    tag = _text(release["tag"])
    _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", tag) is not None)
    _require(".." not in tag and "//" not in tag)
    for name in ("raw_tag_sha", "peeled_commit"):
        _require(re.fullmatch(r"[a-f0-9]{40}", _text(release[name])) is not None)
    assets = [
        _object(item, "id name size sha256") for item in _array(release["assets"])
    ]
    caps = {
        "gate0-evidence.pgp": 17 * _JSON_CAP,
        "gate0-evidence-public.json": 65536,
        "gate0-readiness-receipt.json": 131072,
    }
    _require([item["name"] for item in assets] == list(caps))
    _require(len({_integer(item["id"]) for item in assets}) == 3)
    for item in assets:
        _require(_integer(item["size"]) <= caps[_text(item["name"])])
        _require(re.fullmatch(r"[a-f0-9]{64}", _text(item["sha256"])) is not None)
