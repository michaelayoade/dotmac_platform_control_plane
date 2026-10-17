"""Root-installed, inert A9 campaign inputs. No CP database or private role keys."""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    load_ssh_public_identity,
)

from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import (
    RoleTerms,
    _local_packet,
    parse_run_document,
)
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


_A9_ROOT = "/run/dotmac-gate0-collector"
_A9_PRELAUNCH_FIELDS = (
    "schema lifecycle_binding_digest campaign_digest collection_template "
    "bootstrap_template broker_policy collection_native_qualification "
    "bootstrap_native_qualification"
)
_A9_BINDING_FIELDS = (
    "schema lifecycle_binding_digest campaign_digest prelaunch_digest "
    "broker_policy_digest "
    "static_native_qualification_digests boot_id jit_invocation_id "
    "selected_job_coordinates "
    "github_observation_digest courier_pid courier_start origin path "
    "query original_provisioning_end"
)
_A9_STATIC_FIELDS = (
    "schema role lifecycle_binding_digest campaign_digest prelaunch_selection_digest "
    "template_digest broker_policy_digest runtime_identity native_receipt"
)


def _a9_static_selection_digest(prelaunch: dict[str, Any]) -> str:
    return _hash(
        canonical(
            dict(
                schema="Gate0A9PrelaunchStaticSelection.v1",
                selection={
                    k: v
                    for k, v in prelaunch.items()
                    if k
                    not in (
                        "collection_native_qualification",
                        "bootstrap_native_qualification",
                    )
                },
            )
        )
    )


def _a9_inputs(prelaunch_raw: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    prelaunch = _document(prelaunch_raw, _A9_PRELAUNCH_FIELDS)
    if prelaunch["schema"] != "Gate0A9PrelaunchSelection.v1":
        raise ProviderRefused()
    for name in ("lifecycle_binding_digest", "campaign_digest"):
        _digest(prelaunch[name])
    inputs = {}
    for name in (
        "collection_template",
        "bootstrap_template",
        "broker_policy",
        "collection_native_qualification",
        "bootstrap_native_qualification",
    ):
        pin, raw = _read_pin(prelaunch[name])
        if pin.path != _A9_ROOT + "/" + name.replace("_", "-") + ".json":
            raise ProviderRefused()
        if canonical(strict_object(raw)) != raw:
            raise ProviderRefused()
        inputs[name] = raw
    from vendor_cp.deployment.gate0_runner_tokens import (
        _SUPPLIER_AMENDMENT,
        _SUPPLIER_METHOD,
        _SUPPLIER_SOURCE,
    )

    policy = _document(
        inputs["broker_policy"],
        "schema method amendment_digest supplier_commit origins profile",
    )
    if (
        policy["schema"] != "Gate0A9BrokerPolicy.v1"
        or policy["method"] != _SUPPLIER_METHOD
        or policy["amendment_digest"] != _SUPPLIER_AMENDMENT
        or policy["supplier_commit"] != _SUPPLIER_SOURCE
    ):
        raise ProviderRefused()
    for role in ("collection", "bootstrap"):
        qualification = _document(
            inputs[role + "_native_qualification"], _A9_STATIC_FIELDS
        )
        if (
            qualification["schema"] != "Gate0A9StaticNativeQualification.v1"
            or qualification["role"] != role
            or qualification["prelaunch_selection_digest"]
            != _a9_static_selection_digest(prelaunch)
            or qualification["template_digest"] != _hash(inputs[role + "_template"])
            or qualification["broker_policy_digest"] != _hash(inputs["broker_policy"])
            or any(
                qualification[k] != prelaunch[k]
                for k in ("campaign_digest", "lifecycle_binding_digest")
            )
        ):
            raise ProviderRefused()
        _fields(qualification["native_receipt"], "path digest")
        _digest(qualification["native_receipt"]["digest"])
    return prelaunch, inputs


def _a9_join(raw: bytes, role: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Join prelaunch, static qualification, dynamic binding and last marker.

    Derived qualifications describe publication joins, never native acceptance.
    No old schema is accepted by this loader.
    """
    document = strict_object(raw)
    expected_schema = {
        "collection": "Gate0RunnerCollectionInstallation.v2",
        "bootstrap": "Gate0CollectorBootstrapInstallation.v3",
    }[role]
    if canonical(document) != raw or document.get("schema") != expected_schema:
        raise ProviderRefused()
    prelaunch_pin, prelaunch_raw = _read_pin(document["prelaunch"])
    if prelaunch_pin.path != _A9_ROOT + "/a9-prelaunch.json":
        raise ProviderRefused()
    prelaunch, inputs = _a9_inputs(prelaunch_raw)
    binding_pin, binding_raw = _read_pin(document["job_broker_binding"])
    if binding_pin.path != _A9_ROOT + "/job-broker-binding.json":
        raise ProviderRefused()
    binding = _document(binding_raw, _A9_BINDING_FIELDS)
    static_digests = {
        r: _hash(inputs[r + "_native_qualification"])
        for r in ("collection", "bootstrap")
    }
    if (
        binding["schema"] != "Gate0A9JobBrokerBinding.v1"
        or binding["prelaunch_digest"] != _hash(prelaunch_raw)
        or binding["broker_policy_digest"] != _hash(inputs["broker_policy"])
        or binding["static_native_qualification_digests"] != static_digests
        or any(
            binding[k] != prelaunch[k] or document[k] != prelaunch[k]
            for k in ("campaign_digest",)
        )
        or binding["lifecycle_binding_digest"] != prelaunch["lifecycle_binding_digest"]
        or document["binding_marker"] != _A9_ROOT + "/job-broker-binding-complete.json"
    ):
        raise ProviderRefused()
    policy = strict_object(inputs["broker_policy"])
    from vendor_cp.deployment.gate0_runner_tokens import _supplier_coordinates

    if _supplier_coordinates(
        binding["origin"] + binding["path"] + "?" + binding["query"], policy["origins"]
    ) != (binding["origin"], binding["path"], binding["query"]):
        raise ProviderRefused()
    _digest(binding["github_observation_digest"])
    if (
        type(binding["courier_pid"]) is not int
        or binding["courier_pid"] <= 0
        or type(binding["courier_start"]) is not str
        or not binding["courier_start"].isdigit()
        or type(binding["boot_id"]) is not str
        or re.fullmatch(r"[0-9a-f-]{36}", binding["boot_id"]) is None
        or re.fullmatch(r"[0-9a-f]{32}", binding["jit_invocation_id"]) is None
        or type(binding["original_provisioning_end"]) not in (int, float)
        or not math.isfinite(binding["original_provisioning_end"])
        or binding["original_provisioning_end"] <= 0
    ):
        raise ProviderRefused()
    selected = _fields(
        binding["selected_job_coordinates"],
        "repository_id owner_id run_id attempt workflow_id "
        "source_revision environment_id "
        "job_id job_name runner_id runner_name runner_group_id",
    )
    for key in (
        "repository_id",
        "owner_id",
        "run_id",
        "attempt",
        "workflow_id",
        "environment_id",
        "job_id",
        "runner_id",
        "runner_group_id",
    ):
        if type(selected[key]) is not int or selected[key] <= 0:
            raise ProviderRefused()
    if (
        selected["attempt"] != 1
        or re.fullmatch(r"[0-9a-f]{40}", selected["source_revision"]) is None
    ):
        raise ProviderRefused()
    _text(selected["job_name"])
    _text(selected["runner_name"])
    marker = _document(
        _protected_read(document["binding_marker"]),
        "schema prelaunch_digest collection_digest bootstrap_digest binding_digest",
    )
    if (
        marker["schema"] != "Gate0A9JobBrokerBindingComplete.v1"
        or marker["prelaunch_digest"] != _hash(prelaunch_raw)
        or marker["binding_digest"] != _hash(binding_raw)
        or marker[role + "_digest"] != _hash(raw)
    ):
        raise ProviderRefused()
    # Check BOTH installed descriptors against the committed fixed marker.
    for other, filename in (
        ("collection", "installation.json"),
        ("bootstrap", "bootstrap.json"),
    ):
        if marker[other + "_digest"] != _hash(
            _protected_read(_A9_ROOT + "/" + filename)
        ):
            raise ProviderRefused()
    qualification_pin, qualification_raw = _read_pin(document["qualification"])
    if qualification_pin.path != _A9_ROOT + "/" + role + "-qualification.json":
        raise ProviderRefused()
    expected = dict(
        schema="Gate0A9DerivedInstallationQualification.v1",
        role=role,
        template_digest=_hash(inputs[role + "_template"]),
        static_native_qualification_digest=static_digests[role],
        job_broker_binding_digest=_hash(binding_raw),
        installation_digest=_hash(
            canonical({k: v for k, v in document.items() if k != "qualification"})
        ),
    )
    if _document(qualification_raw, " ".join(expected)) != expected:
        raise ProviderRefused()
    template = strict_object(inputs[role + "_template"])
    reconstructed = {
        k: v
        for k, v in document.items()
        if k
        not in (
            "qualification",
            "prelaunch",
            "job_broker_binding",
            "binding_marker",
            "broker" if role == "collection" else "collection_installation",
        )
    }
    reconstructed["schema"] = {
        "collection": "Gate0RunnerCollectionTemplate.v1",
        "bootstrap": "Gate0CollectorBootstrapTemplate.v1",
    }[role]
    if reconstructed != template:
        raise ProviderRefused()
    if role == "collection":
        broker = _fields(document["broker"], "origin path query qualification")
        if (
            any(broker[k] != binding[k] for k in ("origin", "path", "query"))
            or broker["qualification"] != document["job_broker_binding"]
        ):
            raise ProviderRefused()
    else:
        if document["collection_installation"] != {
            "path": _A9_ROOT + "/installation.json",
            "digest": marker["collection_digest"],
        }:
            raise ProviderRefused()
    return binding, strict_object(inputs[role + "_native_qualification"])


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


def _trust(value: object, role: RoleTerms) -> InstalledPublicTrust:
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
    if not isinstance(cert, SSHCertificate):
        raise ProviderRefused()
    public_key, signature_key = cert.public_key(), cert.signature_key()
    if (
        not isinstance(public_key, Ed25519PublicKey)
        or not isinstance(signature_key, Ed25519PublicKey)
        or certificate_raw.rstrip(b"\n") != cert.public_bytes()
        or _hash(cert.public_bytes()) != controller["certificate_digest"]
        or ssh_public_fingerprint(public_key) != controller["fingerprint"]
        or ssh_public_fingerprint(signature_key) != controller["ca_fingerprint"]
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
        (roots[0], roots[1]),
        endpoints[0],
        endpoints[1],
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
            "withdrawal_reference output_directory marker prelaunch "
            "job_broker_binding binding_marker",
        )
        if (
            doc["schema"] != "Gate0RunnerCollectionInstallation.v2"
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
            "gate0_runner_controller",
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
            _text(broker_doc["origin"], 8192),
            _text(broker_doc["path"], 8192),
            _text(broker_doc["query"], 8192),
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
        binding, _ = _a9_join(raw, "collection")
        selected = binding["selected_job_coordinates"]
        if (
            selected["repository_id"] != int(job["repository_id"])
            or selected["owner_id"] != int(job["repository_owner_id"])
            or selected["source_revision"] != job["workflow_sha"]
            or selected["run_id"] != int(job["run_id"])
            or selected["attempt"] != int(job["run_attempt"])
            or selected["runner_name"] != job["runner_name"]
            or selected["runner_group_id"] != int(job["runner_group_id"])
            or doc["output_directory"] != _ROOT + "/session/evidence"
            or doc["marker"] != _ROOT + "/session/claimed"
        ):
            raise ProviderRefused()
        # One sample anchors BOTH original independent intervals. No future use.
        wall, elapsed = datetime.now(UTC), time.monotonic()
        if type(doc["cases"]) is not list or len(doc["cases"]) != 2:
            raise ProviderRefused()
        cases = (
            _case(doc["cases"][0], doc["collector_uid"], wall, elapsed),
            _case(doc["cases"][1], doc["collector_uid"], wall, elapsed),
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
            or a.projection.window.document["controller"]["lease_id"]
            == b.projection.window.document["controller"]["lease_id"]
            or a.projection.window.document["controller"]["fingerprint"]
            == b.projection.window.document["controller"]["fingerprint"]
            or a.projection.window.document["controller"]["certificate_digest"]
            == b.projection.window.document["controller"]["certificate_digest"]
            or len({r.terms["local_packet_digest"] for c in cases for r in c.roots})
            != 4
        ):
            raise ProviderRefused()
        from vendor_cp.deployment.gate0_runner_projection import RunnerProjectionClient

        # Validates exact HTTPS origin only; no socket/approval/freshness created.
        RunnerProjectionClient(_text(doc["origin"]), (a.projection, b.projection))
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
