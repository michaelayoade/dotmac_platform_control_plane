"""Root-installed, inert A9 campaign inputs. No CP database or private role keys."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    load_ssh_public_identity,
)

from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import _local_packet, parse_run_document
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_handoff import RootHostBinding
from vendor_cp.deployment.gate0_runner_projection import RunnerProjectionCase, _instant
from vendor_cp.deployment.gate0_runner_ssh import (
    RunnerFilePin,
    RunnerSshEndpoint,
    RunnerSshInstallation,
)
from vendor_cp.deployment.gate0_runner_tokens import JobBrokerBinding
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState

_ROOT = "/run/dotmac-gate0-collector"
_INSTALLATION = _ROOT + "/installation.json"


def _fields(value: object, fields: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ProviderRefused()
    return value


def _text(value: object, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ProviderRefused()
    return value


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ProviderRefused()
    return value


def _protected_read(
    path: str, *, uid: int = 0, private: bool = False, maximum: int = 65536
) -> bytes:
    """Walk held directory descriptors, rejecting symlinks before each open.

    O_NONBLOCK precedes type/size checking, so FIFOs cannot stall loading.
    Root owns ancestry, including private material's immediate directory.
    """
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or str(parsed) != path or ".." in parsed.parts:
        raise ProviderRefused()
    directory = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        for part in parsed.parts[1:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
            metadata = os.fstat(directory)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise ProviderRefused()
        fd = os.open(
            parsed.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid
                or before.st_mode & (0o077 if private else 0o022)
                or not 0 < before.st_size <= maximum
            ):
                raise ProviderRefused()
            chunks = bytearray()
            while len(chunks) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(fd)
            if len(chunks) != before.st_size or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ProviderRefused()
            return bytes(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _pin(value: object) -> RunnerFilePin:
    document = _fields(value, "path digest")
    return RunnerFilePin(_text(document["path"]), _digest(document["digest"])[7:])


def _read_pin(
    value: object, *, uid: int = 0, private: bool = False, maximum: int = 65536
) -> tuple[RunnerFilePin, bytes]:
    pin = _pin(value)
    raw = _protected_read(pin.path, uid=uid, private=private, maximum=maximum)
    if hashlib.sha256(raw).hexdigest() != pin.sha256:
        raise ProviderRefused()
    return pin, raw


def _document(raw: bytes, fields: str) -> dict[str, Any]:
    result = _fields(strict_object(raw, 65536), fields)
    if canonical(result) != raw:
        raise ProviderRefused()
    return result


@dataclass(frozen=True, slots=True)
class InstalledPublicTrust:
    key_id: str
    public_key: bytes
    minimum_version: int
    record: bytes = field(repr=False)
    source_ref: str
    qualification_digest: str

    def read_record(self) -> object:
        return strict_object(self.record, 65536)

    def start(self) -> RehearsalIssuerTrustState:
        """Only the active-case controller calls this; construction remains inert."""
        return RehearsalIssuerTrustState.start(
            minimum_version=self.minimum_version, read_record=self.read_record
        )


def _trust(value: object, role: dict[str, str]) -> InstalledPublicTrust:
    doc = _fields(value, "record floor source_ref qualification")
    _, raw = _read_pin(doc["record"])
    _, floor_raw = _read_pin(doc["floor"])
    qualification_pin, _ = _read_pin(doc["qualification"])
    floor = _document(floor_raw, "key_id minimum_version source_ref")
    record = _document(raw, "version trusted_key_ids revoked_key_ids")
    key = base64.b64decode(role["public_key_b64"], validate=True)
    fingerprint = "sha256:" + hashlib.sha256(key).hexdigest()
    trusted, revoked = record["trusted_key_ids"], record["revoked_key_ids"]
    if (
        type(floor["minimum_version"]) is not int
        or floor["minimum_version"] < 1
        or floor["key_id"] != role["key_id"]
        or floor["source_ref"] != doc["source_ref"]
        or type(record["version"]) is not int
        or record["version"] < floor["minimum_version"]
        or type(trusted) is not dict
        or any(type(k) is not str or type(v) is not str for k, v in trusted.items())
        or type(revoked) is not list
        or any(type(k) is not str for k in revoked)
        or len(set(revoked)) != len(revoked)
        or trusted.get(role["key_id"]) != fingerprint
        or role["key_id"] in revoked
    ):
        raise ProviderRefused()
    return InstalledPublicTrust(
        role["key_id"],
        key,
        floor["minimum_version"],
        raw,
        _text(doc["source_ref"]),
        "sha256:" + qualification_pin.sha256,
    )


@dataclass(frozen=True, slots=True)
class InstalledRunnerCase:
    projection: RunnerProjectionCase
    command_id: str
    roots: tuple[RootHostBinding, RootHostBinding]
    issuer: RunnerSshEndpoint
    attester: RunnerSshEndpoint
    ssh_binary: RunnerFilePin
    keygen: RunnerFilePin
    private_key: RunnerFilePin = field(repr=False)
    certificate: RunnerFilePin
    known_hosts: RunnerFilePin
    collector_uid: int
    issuer_trust: InstalledPublicTrust
    attester_trust: InstalledPublicTrust

    @property
    def ssh(self) -> RunnerSshInstallation:
        self.projection.require_open()
        return RunnerSshInstallation(
            self.issuer,
            self.attester,
            self.ssh_binary,
            self.keygen,
            self.private_key,
            self.certificate,
            self.known_hosts,
            self.collector_uid,
            _instant(self.projection.window.document["expires_at"]),
            self.projection.deadline,
        )


def _case(
    value: object, uid: int, wall: datetime, elapsed: float
) -> InstalledRunnerCase:
    doc = _fields(
        value,
        "shared_packet frozen_window command_id hosts ssh_binary keygen "
        "private_key certificate known_hosts issuer_trust attester_trust",
    )
    _, shared = _read_pin(doc["shared_packet"])
    _, frozen = _read_pin(doc["frozen_window"])
    selected = RunnerProjectionCase(shared, frozen, wall, elapsed)
    packet, window = parse_run_document(shared), selected.window.document
    hosts = _fields(doc["hosts"], "IDP3 NS3")
    roots, endpoints = [], []
    for name, role in (("IDP3", "issuer"), ("NS3", "attester")):
        host = _fields(hosts[name], "binding local_packet endpoint")
        root = RootHostBinding(canonical(host["binding"]))
        _, local_raw = _read_pin(host["local_packet"])
        local = _local_packet(local_raw)
        binding = root.terms
        if (
            local["host_role"] != role
            or local["shared_run_digest"] != _hash(shared)
            or local["capture"] != packet["capture"]
            or local["run_end"] != packet["expires_at"]
            or binding
            != dict(
                host_role=role,
                case_kind=packet["case_kind"],
                launch_packet_digest=_hash(shared),
                local_packet_digest=_hash(local_raw),
                window_digest=selected.window.digest,
                machine_id_digest=local["machine_id_digest"],
                network_measurement_digest=_digest(
                    binding["network_measurement_digest"]
                ),
                not_before=packet["not_before"],
                expires_at=packet["expires_at"],
            )
        ):
            raise ProviderRefused()
        endpoint_doc = _fields(host["endpoint"], "host port source user host_key_alias")
        endpoint = RunnerSshEndpoint(**endpoint_doc)
        expected = local["ssh_endpoints"][role]
        if (endpoint.host, endpoint.port, endpoint.source) != (
            expected["local_address"],
            expected["local_port"],
            expected["remote_address"],
        ):
            raise ProviderRefused()
        roots.append(root)
        endpoints.append(endpoint)
    ssh, _ = _read_pin(doc["ssh_binary"], maximum=32 * 1024 * 1024)
    keygen, _ = _read_pin(doc["keygen"], maximum=32 * 1024 * 1024)
    if ssh.path != "/usr/bin/ssh" or keygen.path != "/usr/bin/ssh-keygen":
        raise ProviderRefused()
    private, private_raw = _read_pin(doc["private_key"], uid=uid, private=True)
    del private_raw
    certificate, certificate_raw = _read_pin(doc["certificate"])
    known, _ = _read_pin(doc["known_hosts"])
    cert = load_ssh_public_identity(certificate_raw.rstrip(b"\n"))
    controller = window["controller"]
    if (
        not isinstance(cert, SSHCertificate)
        or certificate_raw.rstrip(b"\n") != cert.public_bytes()
        or _hash(cert.public_bytes()) != controller["certificate_digest"]
        or ssh_public_fingerprint(cert.public_key()) != controller["fingerprint"]
        or ssh_public_fingerprint(cert.signature_key()) != controller["ca_fingerprint"]
        or cert.valid_principals != [controller["principal"].encode()]
        or cert.valid_after > _instant(window["not_before"]).timestamp()
        or cert.valid_before < _instant(window["expires_at"]).timestamp()
        or not 0
        < cert.valid_before - cert.valid_after
        <= controller["certificate_ttl_ceiling_seconds"]
    ):
        raise ProviderRefused()
    return InstalledRunnerCase(
        selected,
        _text(doc["command_id"]),
        tuple(roots),
        *endpoints,
        ssh,
        keygen,
        private,
        certificate,
        known,
        uid,
        _trust(doc["issuer_trust"], packet["roles"]["issuer"]),
        _trust(doc["attester_trust"], packet["roles"]["attester"]),
    )


@dataclass(frozen=True, slots=True)
class InstalledRunnerCollection:
    campaign_digest: str
    collector_uid: int
    receiver_uid: int
    origin: str
    broker: JobBrokerBinding
    job: bytes = field(repr=False)
    cases: tuple[InstalledRunnerCase, InstalledRunnerCase]
    withdrawal_reference: str
    output_directory: str
    marker: str
    qualification: bytes = field(repr=False)

    def require_actual_job(self) -> None:
        if os.getuid() != self.collector_uid or os.geteuid() != self.collector_uid:
            raise ProviderRefused()
        job = strict_object(self.job)
        expected = {
            "GITHUB_REPOSITORY": "repository",
            "GITHUB_REPOSITORY_ID": "repository_id",
            "GITHUB_REPOSITORY_OWNER_ID": "repository_owner_id",
            "GITHUB_RUN_ID": "run_id",
            "GITHUB_RUN_ATTEMPT": "run_attempt",
            "GITHUB_REF": "ref",
            "GITHUB_WORKFLOW_REF": "workflow_ref",
            "GITHUB_WORKFLOW_SHA": "workflow_sha",
            "GITHUB_EVENT_NAME": "event_name",
            "RUNNER_GROUP_ID": "runner_group_id",
            "RUNNER_NAME": "runner_name",
        }
        if (
            any(os.environ.get(env) != job[key] for env, key in expected.items())
            or os.environ.get("GITHUB_ACTIONS") != "true"
        ):
            raise ProviderRefused()

    @classmethod
    def from_installed(cls) -> InstalledRunnerCollection:
        failed = False
        result = None
        try:
            result = cls._load()
        except Exception:
            failed = True
        if failed or result is None:
            raise ProviderRefused()
        return result

    @classmethod
    def _load(cls) -> InstalledRunnerCollection:
        raw = _protected_read(_INSTALLATION)
        doc = _document(
            raw,
            "schema campaign_digest collector_uid receiver_uid origin broker job "
            "source_revision image_digest executable source_files qualification "
            "holder_qualification receiver_qualification cases "
            "withdrawal_reference output_directory marker",
        )
        if (
            doc["schema"] != "Gate0RunnerCollectionInstallation.v1"
            or any(
                type(doc[k]) is not int or doc[k] <= 0
                for k in ("collector_uid", "receiver_uid")
            )
            or doc["collector_uid"] == doc["receiver_uid"]
            or re.fullmatch(r"[0-9a-f]{40}", _text(doc["source_revision"])) is None
        ):
            raise ProviderRefused()
        _digest(doc["image_digest"])
        executable, _ = _read_pin(doc["executable"], maximum=32 * 1024 * 1024)
        if os.readlink("/proc/self/exe") != executable.path:
            raise ProviderRefused()
        source_names = (
            "gate0_runner_installation",
            "gate0_runner_tokens",
            "gate0_runner_ssh",
            "gate0_runner_handoff",
            "gate0_runner_collector_handoff",
            "gate0_collection",
        )
        source_files = _fields(doc["source_files"], " ".join(source_names))
        for name in source_names:
            source_pin, _ = _read_pin(source_files[name], maximum=1024 * 1024)
            if source_pin.path != str(Path(__file__).parent / (name + ".py")):
                raise ProviderRefused()
        _, holder = _read_pin(doc["holder_qualification"])
        _, receiver = _read_pin(doc["receiver_qualification"])
        _, qualification = _read_pin(doc["qualification"])
        broker_doc = _fields(doc["broker"], "origin path query qualification")
        broker_pin, _ = _read_pin(broker_doc["qualification"])
        broker = JobBrokerBinding(
            *(_text(broker_doc[k], 8192) for k in ("origin", "path", "query")),
            "sha256:" + broker_pin.sha256,
        )
        job = _fields(
            doc["job"],
            "iss aud repository repository_id repository_owner_id environment ref "
            "workflow_ref workflow_sha event_name run_id run_attempt sub "
            "environment_node_id runner_group_id runner_name",
        )
        for value in job.values():
            _text(value)
        accepted = _document(
            qualification,
            "schema campaign_digest collector_uid receiver_uid job "
            "source_revision image_digest executable_digest installation_digest "
            "holder_qualification_digest receiver_qualification_digest broker "
            "native_receipt_digest",
        )
        expected = dict(
            schema="Gate0RunnerCollectionQualification.v1",
            campaign_digest=_digest(doc["campaign_digest"]),
            collector_uid=doc["collector_uid"],
            receiver_uid=doc["receiver_uid"],
            job=job,
            source_revision=doc["source_revision"],
            image_digest=doc["image_digest"],
            executable_digest="sha256:" + executable.sha256,
            installation_digest=_hash(
                canonical(
                    {key: value for key, value in doc.items() if key != "qualification"}
                )
            ),
            holder_qualification_digest=_hash(holder),
            receiver_qualification_digest=_hash(receiver),
            broker=dict(
                origin=broker.origin,
                path=broker.path,
                query=broker.query,
                qualification_digest=broker.qualification_digest,
            ),
            native_receipt_digest=_digest(accepted["native_receipt_digest"]),
        )
        if (
            accepted != expected
            or doc["output_directory"] != _ROOT + "/session/evidence"
            or doc["marker"] != _ROOT + "/session/claimed"
        ):
            raise ProviderRefused()
        # One sample anchors BOTH original independent intervals. No future use.
        wall, elapsed = datetime.now(UTC), time.monotonic()
        if type(doc["cases"]) is not list or len(doc["cases"]) != 2:
            raise ProviderRefused()
        cases = tuple(
            _case(value, doc["collector_uid"], wall, elapsed) for value in doc["cases"]
        )
        for case, kind in zip(
            cases, ("consume_replay", "withdrawal_later_use"), strict=True
        ):
            github = case.projection.window.document["github"]
            if (
                case.projection.binding["case_kind"] != kind
                or any(job.get(k) != v for k, v in github.items())
                or case.projection.deadline <= elapsed
            ):
                raise ProviderRefused()
        a, b = cases
        if (
            a.projection.deadline > b.projection.start
            or any(
                getattr(a, name) == getattr(b, name)
                for name in ("command_id", "private_key", "certificate")
            )
            or any(
                a.projection.binding[k] == b.projection.binding[k]
                for k in (
                    "window_digest",
                    "window_id",
                    "plan_id",
                    "plan_digest",
                    "approval_request_id",
                    "launch_packet_digest",
                )
            )
            or any(
                a.projection.window.document["controller"][k]
                == b.projection.window.document["controller"][k]
                for k in ("lease_id", "fingerprint", "certificate_digest")
            )
            or len({r.terms["local_packet_digest"] for c in cases for r in c.roots})
            != 4
        ):
            raise ProviderRefused()
        from vendor_cp.deployment.gate0_runner_projection import RunnerProjectionClient

        # Validates exact HTTPS origin only; no socket/approval/freshness created.
        RunnerProjectionClient(_text(doc["origin"]), tuple(c.projection for c in cases))
        result = cls(
            doc["campaign_digest"],
            doc["collector_uid"],
            doc["receiver_uid"],
            doc["origin"],
            broker,
            canonical(job),
            cases,
            _text(doc["withdrawal_reference"], 200),
            doc["output_directory"],
            doc["marker"],
            qualification,
        )
        result.require_actual_job()
        broker.request_path(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
        return result
