"""Finite installed role preparation over existing custody and authority owners.

Only protected launch contexts may open fixed installation/secret/capture files.
Typed inputs remain equality data until compared with that protected installation.
There is no request-selected factory or deployable default installation here.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from dotmac_deployment_control import RehearsalIssuerAuthorizationSignerIdentity

from vendor_cp.deployment.gate0_capture import (
    PublicCapture,
    decode_capture,
    export_approved_start,
)
from vendor_cp.deployment.gate0_database import (
    DatabaseExpectation,
    qualify_authority_database,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import InstalledLaunchContext
from vendor_cp.deployment.gate0_management_delivery import (
    CaptureSelection,
    ManagementDeliveryInstallation,
    selection_document,
)
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    CustodyProfile,
    ProviderRefused,
    PublicIssuerVerifier,
    RoleCustody,
    RoleMaterial,
    WireGuardBaoEndpoint,
    WireGuardBaoTransport,
)
from vendor_cp.deployment.gate0_services import (
    IssuerStartup,
    assemble_attester_session,
    assemble_issuer_startup,
)
from vendor_cp.deployment.gate0_session import AttesterSession, SshdSessionReader
from vendor_cp.deployment.gate0_window import OwnerWindowReader, WindowClockOrigin
from vendor_cp.deployment.gate0_workload_admission import (
    ApprovedAtStartAdmission,
    OwnerWorkloadAdmission,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class PublicKeyPin:
    key_id: str
    public_key: bytes

    def validate(self) -> None:
        if (
            type(self.key_id) is not str
            or not 0 < len(self.key_id) <= 512
            or type(self.public_key) is not bytes
            or len(self.public_key) != 32
        ):
            raise ProviderRefused()

    def document(self) -> dict[str, object]:
        self.validate()
        return {
            "key_id": self.key_id,
            "public_key_b64": base64.b64encode(self.public_key).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class InstallationIdentity:
    packet_digest: str
    source_revision: str
    image_digest: str
    config_digest: str
    not_before: datetime
    expires_at: datetime

    def validate(self) -> None:
        if (
            any(
                type(value) is not str or _DIGEST.fullmatch(value) is None
                for value in (self.packet_digest, self.image_digest, self.config_digest)
            )
            or type(self.source_revision) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is None
        ):
            raise ProviderRefused()
        if (
            any(
                type(value) is not datetime
                or value.tzinfo is None
                or value.utcoffset() != timedelta(0)
                for value in (self.not_before, self.expires_at)
            )
            or not self.not_before <= datetime.now(UTC) < self.expires_at
            or not 0 < (self.expires_at - self.not_before).total_seconds() <= 300
        ):
            raise ProviderRefused()

    def document(self) -> dict[str, object]:
        self.validate()
        return {
            **{
                key: value
                for key, value in asdict(self).items()
                if key not in ("not_before", "expires_at")
            },
            "not_before": self.not_before.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


@dataclass(frozen=True, slots=True)
class CustodyInstallation:
    role_id: str
    key: PublicKeyPin
    issuer_minimum_version: int
    attester_minimum_version: int
    endpoint: WireGuardBaoEndpoint

    def validate(self, role: Literal["issuer", "attester"], packet_digest: str) -> None:
        if (
            type(self.key) is not PublicKeyPin
            or type(self.endpoint) is not WireGuardBaoEndpoint
            or type(self.role_id) is not str
            or not 0 < len(self.role_id) <= 512
            or self.endpoint.role != role
            or self.endpoint.launch_packet_digest != packet_digest
            or any(
                type(value) is not int or value < 1
                for value in (
                    self.issuer_minimum_version,
                    self.attester_minimum_version,
                )
            )
        ):
            raise ProviderRefused()
        self.key.validate()
        self.endpoint.__post_init__()

    def document(self) -> dict[str, object]:
        return {
            "role_id": self.role_id,
            "key": self.key.document(),
            "issuer_minimum_version": self.issuer_minimum_version,
            "attester_minimum_version": self.attester_minimum_version,
            "endpoint": asdict(self.endpoint),
        }


@dataclass(frozen=True, slots=True)
class ActualIssuerInstallation:
    identity: InstallationIdentity
    custody: CustodyInstallation
    database: DatabaseExpectation
    rehearsal_target_id: UUID
    plans: tuple[UUID, UUID]
    attester_key: PublicKeyPin
    authorization_ttl_seconds: int
    actor_ref: str
    management_delivery: ManagementDeliveryInstallation

    def validate(self) -> None:
        if (
            type(self.identity) is not InstallationIdentity
            or type(self.custody) is not CustodyInstallation
            or type(self.database) is not DatabaseExpectation
            or type(self.attester_key) is not PublicKeyPin
            or type(self.rehearsal_target_id) is not UUID
            or type(self.plans) is not tuple
            or len(self.plans) != 2
            or any(type(plan) is not UUID for plan in self.plans)
            or len(set(self.plans)) != 2
            or type(self.authorization_ttl_seconds) is not int
            or not 0 < self.authorization_ttl_seconds <= 300
            or type(self.actor_ref) is not str
            or not 0 < len(self.actor_ref) <= 512
        ):
            raise ProviderRefused()
        if type(self.management_delivery) is not ManagementDeliveryInstallation:
            raise ProviderRefused()
        self.management_delivery.validate()
        if (
            self.management_delivery.launch_packet_digest != self.identity.packet_digest
            or self.management_delivery.expires_at != self.identity.expires_at
            or tuple(
                selection.plan_id for selection in self.management_delivery.captures
            )
            != self.plans
            or any(
                selection.target_id != self.rehearsal_target_id
                for selection in self.management_delivery.captures
            )
        ):
            raise ProviderRefused()
        self.identity.validate()
        self.custody.validate("issuer", self.identity.packet_digest)
        self.database.validate()
        self.attester_key.validate()
        if (
            self.database.source_revision != self.identity.source_revision
            or self.database.expected_source_revision != self.identity.source_revision
        ):
            raise ProviderRefused()

    def document(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": "Gate0IssuerInstallation.v1",
            "identity": self.identity.document(),
            "custody": self.custody.document(),
            "database": asdict(self.database),
            "rehearsal_target_id": str(self.rehearsal_target_id),
            "plans": [str(plan) for plan in self.plans],
            "attester_key": self.attester_key.document(),
            "authorization_ttl_seconds": self.authorization_ttl_seconds,
            "actor_ref": self.actor_ref,
            "management_delivery": self.management_delivery.document(),
        }


@dataclass(frozen=True, slots=True)
class ActualAttesterInstallation:
    identity: InstallationIdentity
    custody: CustodyInstallation
    issuer_key: PublicKeyPin
    ca_public_key: bytes
    capture: CaptureSelection
    phase: Literal["issue", "consume"]
    slot_id: str
    worker_uid: int

    def validate(self) -> None:
        if (
            type(self.identity) is not InstallationIdentity
            or type(self.custody) is not CustodyInstallation
            or type(self.issuer_key) is not PublicKeyPin
            or type(self.capture) is not CaptureSelection
            or type(self.ca_public_key) is not bytes
            or len(self.ca_public_key) != 32
            or type(self.phase) is not str
            or self.phase not in ("issue", "consume")
            or type(self.slot_id) is not str
            or self.slot_id not in ("a_issue", "a_consume", "b_issue", "b_consume")
            or self.slot_id.rsplit("_", 1)[1] != self.phase
            or type(self.worker_uid) is not int
            or self.worker_uid <= 0
        ):
            raise ProviderRefused()
        self.identity.validate()
        self.custody.validate("attester", self.identity.packet_digest)
        self.issuer_key.validate()
        self.capture.__post_init__()

    def document(self) -> dict[str, object]:
        self.validate()
        return {
            "schema": "Gate0AttesterInstallation.v1",
            "identity": self.identity.document(),
            "custody": self.custody.document(),
            "issuer_key": self.issuer_key.document(),
            "ca_public_key_b64": base64.b64encode(self.ca_public_key).decode("ascii"),
            "capture": selection_document(self.capture),
            "phase": self.phase,
            "slot_id": self.slot_id,
            "worker_uid": self.worker_uid,
        }


def _read_owned(fd: int, maximum: int) -> bytes:
    result = bytearray()
    while len(result) <= maximum:
        part = os.read(fd, min(65536, maximum + 1 - len(result)))
        if not part:
            break
        result.extend(part)
    if not 0 < len(result) <= maximum:
        raise ProviderRefused()
    return bytes(result)


def _installation(
    context: InstalledLaunchContext,
    role: Literal["issuer", "attester"],
    identity: InstallationIdentity,
    document: dict[str, object],
) -> None:
    if type(context) is not InstalledLaunchContext:
        raise ProviderRefused()
    context.require_installation(role, identity.packet_digest, identity.expires_at)
    fd = context.open_installation()
    try:
        raw = _read_owned(fd, 65536)
        # Exact canonical bytes bind every typed field, including nested tuples.
        if canonical(strict_object(raw, 65536)) != raw or canonical(document) != raw:
            raise ProviderRefused()
    finally:
        os.close(fd)
    context.require_open()


def _custody(
    context: InstalledLaunchContext,
    role: Literal["issuer", "attester"],
    installation: CustodyInstallation,
    end: datetime,
) -> tuple[RoleCustody, RoleMaterial]:
    custody = RoleCustody(
        role=role,
        role_id=installation.role_id,
        key_id=installation.key.key_id,
        public_key=installation.key.public_key,
        minimum_versions={
            "issuer": installation.issuer_minimum_version,
            "attester": installation.attester_minimum_version,
        },
        transport=WireGuardBaoTransport(installation.endpoint),
        seed_format="a4-provisional-private-key-b64url",
        expires_at=end,
        profile=CustodyProfile.ISSUER_FINITE_V1
        if role == "issuer"
        else CustodyProfile.ATTESTER_FINITE_V1,
        launch_deadline=context.deadline,
    )
    try:
        fd = context.open_wrapping_token()
        try:
            raw = _read_owned(fd, 8192)
            if re.fullmatch(rb"[A-Za-z0-9._-]{1,8192}", raw) is None:
                raise ProviderRefused()
            token = raw.decode("ascii")
        finally:
            os.close(fd)
        try:
            return custody, custody.bootstrap(token)
        finally:
            token = ""
            raw = b""
    except BaseException:
        custody.close()
        raise


@dataclass(frozen=True, slots=True)
class PreparedIssuer:
    startup: IssuerStartup
    custody: RoleCustody
    reader: OwnerWindowReader
    captures: tuple[PublicCapture, PublicCapture]
    deadline: float


@dataclass(frozen=True, slots=True)
class PreparedAttester:
    session: AttesterSession
    reader: SshdSessionReader
    custody: RoleCustody
    deadline: float
    phase: Literal["issue", "consume"]
    plan_id: UUID


@contextmanager
def prepare_installed_issuer(
    context: InstalledLaunchContext, installation: ActualIssuerInstallation
) -> Iterator[PreparedIssuer]:
    if type(installation) is not ActualIssuerInstallation:
        raise ProviderRefused()
    installation.validate()
    _installation(context, "issuer", installation.identity, installation.document())
    context.require_run_role_terms(
        role="issuer",
        source_revision=installation.identity.source_revision,
        image_digest=installation.identity.image_digest,
        own_key_id=installation.custody.key.key_id,
        own_public_key=installation.custody.key.public_key,
        peer_key_id=installation.attester_key.key_id,
        peer_public_key=installation.attester_key.public_key,
    )
    qualification = qualify_authority_database(installation.database)
    qualification.require_runtime(qualification.runtime)
    context.require_open()
    custody, material = _custody(
        context, "issuer", installation.custody, installation.identity.expires_at
    )
    try:
        reader = OwnerWindowReader(
            runtime=qualification.runtime,
            issuer_identity=material.issuer_signer.rehearsal_issuer_identity,
            authorization_verifier=material.issuer_verifier,
            expires_at=installation.identity.expires_at,
            database_io_qualified=True,
            rehearsal_target_id=installation.rehearsal_target_id,
            clock_origin=WindowClockOrigin(
                context.started_at, context.monotonic_origin, context.deadline
            ),
        )
        admission = OwnerWorkloadAdmission(
            reader=reader,
            transport=BoundedJSONTransport(
                "https://token.actions.githubusercontent.com"
            ),
        )
        startup = assemble_issuer_startup(
            material=material,
            admission=admission,
            attester_key_id=installation.attester_key.key_id,
            attester_public_key=installation.attester_key.public_key,
            expires_at=installation.identity.expires_at,
            authorization_ttl=timedelta(seconds=installation.authorization_ttl_seconds),
            actor_ref=installation.actor_ref,
            database_qualified=True,
            custody=custody,
        )
        captures = export_approved_start(reader, installation.plans)
        if len(captures) != 2:
            raise ProviderRefused()
        context.require_open()
        yield PreparedIssuer(
            startup, custody, reader, (captures[0], captures[1]), custody.deadline
        )
    finally:
        custody.close()


@contextmanager
def prepare_installed_attester(
    context: InstalledLaunchContext, installation: ActualAttesterInstallation
) -> Iterator[PreparedAttester]:
    if type(installation) is not ActualAttesterInstallation:
        raise ProviderRefused()
    installation.validate()
    _installation(context, "attester", installation.identity, installation.document())
    context.require_run_role_terms(
        role="attester",
        source_revision=installation.identity.source_revision,
        image_digest=installation.identity.image_digest,
        own_key_id=installation.custody.key.key_id,
        own_public_key=installation.custody.key.public_key,
        peer_key_id=installation.issuer_key.key_id,
        peer_public_key=installation.issuer_key.public_key,
    )
    if (
        context.slot_id != installation.slot_id
        or context.worker_uid != installation.worker_uid
        or context.required_phase != installation.phase
    ):
        raise ProviderRefused()
    coordinates = context.capture_coordinates()
    installation.capture.require_coordinates(coordinates)
    context.require_capture_slot(coordinates, installation.phase)
    capture_fd = context.open_authenticated_capture(coordinates)
    try:
        capture = decode_capture(_read_owned(capture_fd, 65536), expected=coordinates)
        custody, material = _custody(
            context, "attester", installation.custody, installation.identity.expires_at
        )
        try:
            pin = installation.issuer_key
            fingerprint = "sha256:" + hashlib.sha256(pin.public_key).hexdigest()
            identity = RehearsalIssuerAuthorizationSignerIdentity(
                pin.key_id, "ed25519", fingerprint
            )
            verifier = PublicIssuerVerifier(
                pin.key_id,
                pin.public_key,
                material.issuer_trust,
                custody.deadline,
                installation.identity.expires_at,
                context.started_at,
                context.monotonic_origin,
            )
            # The original clock is required here; a new startup mapping after
            # custody would extend a shorter captured window on wall rollback.
            origin = WindowClockOrigin(
                context.started_at, context.monotonic_origin, context.deadline
            )
            admission = ApprovedAtStartAdmission(
                binding=capture.binding,
                issuer_identity=identity,
                authorization_verifier=verifier,
                transport=BoundedJSONTransport(
                    "https://token.actions.githubusercontent.com"
                ),
                expires_at=installation.identity.expires_at,
                clock_origin=origin,
            )
            session = assemble_attester_session(
                material=material,
                admission=admission,
                ca_public_key=installation.ca_public_key,
                expires_at=installation.identity.expires_at,
                custody=custody,
                required_phase=installation.phase,
                required_plan_id=coordinates.plan_id,
            )
            directory_fd = context.open_auth_info_directory()
            try:
                context.require_open()
                yield PreparedAttester(
                    session,
                    SshdSessionReader(directory_fd, context.worker_uid),
                    custody,
                    custody.deadline,
                    installation.phase,
                    coordinates.plan_id,
                )
            finally:
                os.close(directory_fd)
        finally:
            custody.close()
    finally:
        os.close(capture_fd)


def _record(value: object, fields: tuple[str, ...]) -> dict[str, object]:
    from vendor_cp.deployment.gate0_role_custody import json_record

    result = json_record(value)
    if set(result) != set(fields):
        raise ProviderRefused()
    return {key: item for key, item in result.items()}


def _string(value: object) -> str:
    from vendor_cp.deployment.gate0_role_custody import json_string

    return json_string(value)


def _integer(value: object) -> int:
    from vendor_cp.deployment.gate0_role_custody import json_integer

    return json_integer(value)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 256:
        raise ProviderRefused()
    return tuple(_string(item) for item in value)


def _instant(value: object) -> datetime:
    text = _string(value)
    result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if result.tzinfo is None or result.isoformat().replace("+00:00", "Z") != text:
        raise ProviderRefused()
    return result


def _public_key(value: object) -> bytes:
    text = _string(value)
    raw = base64.b64decode(text, validate=True)
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        raise ProviderRefused()
    return raw


def _pin(value: object) -> PublicKeyPin:
    record = _record(value, ("key_id", "public_key_b64"))
    result = PublicKeyPin(
        _string(record["key_id"]), _public_key(record["public_key_b64"])
    )
    result.validate()
    return result


def _identity(value: object) -> InstallationIdentity:
    record = _record(value, tuple(InstallationIdentity.__dataclass_fields__))
    result = InstallationIdentity(
        _string(record["packet_digest"]),
        _string(record["source_revision"]),
        _string(record["image_digest"]),
        _string(record["config_digest"]),
        _instant(record["not_before"]),
        _instant(record["expires_at"]),
    )
    result.validate()
    return result


def _custody_installation(
    value: object, role: Literal["issuer", "attester"]
) -> CustodyInstallation:
    record = _record(value, tuple(CustodyInstallation.__dataclass_fields__))
    endpoint = _record(
        record["endpoint"], tuple(WireGuardBaoEndpoint.__dataclass_fields__)
    )
    timeout = endpoint["timeout"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or endpoint["role"] != role
    ):
        raise ProviderRefused()
    result = CustodyInstallation(
        _string(record["role_id"]),
        _pin(record["key"]),
        _integer(record["issuer_minimum_version"]),
        _integer(record["attester_minimum_version"]),
        WireGuardBaoEndpoint(
            role,
            _string(endpoint["address"]),
            _integer(endpoint["port"]),
            _string(endpoint["local_address"]),
            _string(endpoint["interface"]),
            _integer(endpoint["interface_index"]),
            _integer(endpoint["namespace_device"]),
            _integer(endpoint["namespace_inode"]),
            _string(endpoint["peer_fingerprint"]),
            _string(endpoint["peer_allowed_ip"]),
            _string(endpoint["wg_binary_digest"]),
            _string(endpoint["network_config_digest"]),
            _string(endpoint["launch_packet_digest"]),
            float(timeout),
        ),
    )
    return result


def _management(value: object) -> ManagementDeliveryInstallation:
    from vendor_cp.deployment.gate0_management_delivery import parse_selection

    record = _record(
        value, ("schema", *ManagementDeliveryInstallation.__dataclass_fields__)
    )
    captures = record["captures"]
    if (
        record["schema"] != "Gate0ManagementCaptureDelivery.v1"
        or not isinstance(captures, list)
        or len(captures) != 2
    ):
        raise ProviderRefused()
    result = ManagementDeliveryInstallation(
        _string(record["launch_packet_digest"]),
        _instant(record["not_before"]),
        _instant(record["expires_at"]),
        _string(record["source_address"]),
        _string(record["destination_address"]),
        _integer(record["destination_port"]),
        _integer(record["recipient_uid"]),
        _string(record["recipient_name"]),
        _string(record["management_key_fingerprint"]),
        _string(record["host_key_algorithm"]),
        _string(record["host_key_fingerprint"]),
        _string(record["ssh_client_digest"]),
        _string(record["ssh_server_digest"]),
        _string(record["ssh_config_digest"]),
        (parse_selection(captures[0]), parse_selection(captures[1])),
    )
    result.validate()
    return result


def _database(value: object) -> DatabaseExpectation:
    record = _record(value, tuple(DatabaseExpectation.__dataclass_fields__))
    tls = record["tls"]
    if type(tls) is not bool:
        raise ProviderRefused()
    result = DatabaseExpectation(
        _string(record["database"]),
        _string(record["role"]),
        _string(record["server_address"]),
        _integer(record["server_port"]),
        tls,
        _strings(record["schemas"]),
        _strings(record["image_heads"]),
        _strings(record["descriptor_heads"]),
        _string(record["source_revision"]),
        _string(record["expected_source_revision"]),
        _integer(record["statement_timeout_ms"]),
        _integer(record["lock_timeout_ms"]),
    )
    result.validate()
    return result


def _installed_document(context: InstalledLaunchContext) -> dict[str, object]:
    if type(context) is not InstalledLaunchContext:
        raise ProviderRefused()
    context.require_open()
    fd = context.open_installation()
    try:
        raw = _read_owned(fd, 65536)
        document = strict_object(raw, 65536)
        if canonical(document) != raw:
            raise ProviderRefused()
        return document
    finally:
        os.close(fd)


def load_issuer_installation(
    context: InstalledLaunchContext,
) -> ActualIssuerInstallation:
    document = _record(
        _installed_document(context),
        ("schema", *ActualIssuerInstallation.__dataclass_fields__),
    )
    plans = document["plans"]
    if (
        document["schema"] != "Gate0IssuerInstallation.v1"
        or not isinstance(plans, list)
        or len(plans) != 2
    ):
        raise ProviderRefused()
    result = ActualIssuerInstallation(
        _identity(document["identity"]),
        _custody_installation(document["custody"], "issuer"),
        _database(document["database"]),
        UUID(_string(document["rehearsal_target_id"])),
        (UUID(_string(plans[0])), UUID(_string(plans[1]))),
        _pin(document["attester_key"]),
        _integer(document["authorization_ttl_seconds"]),
        _string(document["actor_ref"]),
        _management(document["management_delivery"]),
    )
    result.validate()
    if result.document() != document:
        # JSON arrays normalize tuples only via canonical serialization.
        if canonical(result.document()) != canonical(document):
            raise ProviderRefused()
    return result


def load_attester_installation(
    context: InstalledLaunchContext,
) -> ActualAttesterInstallation:
    from vendor_cp.deployment.gate0_management_delivery import parse_selection

    document = _record(
        _installed_document(context),
        ("schema", *ActualAttesterInstallation.__dataclass_fields__),
    )
    phase: Literal["issue", "consume"]
    if document["phase"] == "issue":
        phase = "issue"
    elif document["phase"] == "consume":
        phase = "consume"
    else:
        raise ProviderRefused()
    if document["schema"] != "Gate0AttesterInstallation.v1":
        raise ProviderRefused()
    result = ActualAttesterInstallation(
        _identity(document["identity"]),
        _custody_installation(document["custody"], "attester"),
        _pin(document["issuer_key"]),
        _public_key(document["ca_public_key_b64"]),
        parse_selection(document["capture"]),
        phase,
        _string(document["slot_id"]),
        _integer(document["worker_uid"]),
    )
    result.validate()
    if canonical(result.document()) != canonical(document):
        raise ProviderRefused()
    return result


def load_management_delivery_installation(
    context: InstalledLaunchContext,
) -> ManagementDeliveryInstallation:
    if type(context) is not InstalledLaunchContext or context.role not in (
        "management",
        "capture_sender",
    ):
        raise ProviderRefused()
    document = _installed_document(context)
    result = _management(document)
    if (
        result.launch_packet_digest != context.packet_digest
        or result.expires_at != context.expires_at
        or canonical(result.document()) != canonical(document)
    ):
        raise ProviderRefused()
    context.require_installation(
        context.role, result.launch_packet_digest, result.expires_at
    )
    if context.role == "management":
        import pwd

        from vendor_cp.deployment.gate0_management_delivery import (
            require_management_server_pin,
        )

        require_management_server_pin(result.ssh_server_digest)
        if (
            context.worker_uid != result.recipient_uid
            or pwd.getpwuid(context.worker_uid).pw_name != result.recipient_name
        ):
            raise ProviderRefused()
    return result
