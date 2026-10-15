"""Fixed NS3 proof exchange under an explicitly trusted sshd execution boundary.

ExposeAuthInfo is login-UID-owned. File checks constrain lookup; they do not
authenticate arbitrary code already executing as that UID. The dedicated sshd,
worker UID, executable, startup files and environment must be protected by the
qualified installation. No environment-only standalone invocation is trusted.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from vendor_cp.deployment.gate0_role_custody import RoleCustody

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    load_ssh_public_identity,
)

from vendor_cp.deployment.gate0_attester import (
    AttesterProofProducer,
    ssh_public_fingerprint,
)
from vendor_cp.deployment.gate0_composition import AdmissionExpectation
from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused
from vendor_cp.deployment.gate0_observation import (
    SignedSessionObservation,
    bundle_document,
    decode,
    digest,
    encode,
    observation_message,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.rehearsal_issuer_trust_state import RehearsalIssuerTrustState


def parse_auth_info(encoded: bytes) -> bytes:
    """V_9_6_P1 auth2_update_session_info: publickey + sshkey_format_text.

    Accept one Ed25519 certificate method, no alternate auth, method suffix,
    comment, extra credential or metadata. Pin/build qualification remains owed.
    """
    if (
        type(encoded) is not bytes
        or not 0 < len(encoded) <= 16384
        or not encoded.endswith(b"\n")
        or encoded.count(b"\n") != 1
    ):
        raise ServiceRefused()
    parts = encoded[:-1].split(b" ")
    if len(parts) != 3 or parts[:2] != [
        b"publickey",
        b"ssh-ed25519-cert-v01@openssh.com",
    ]:
        raise ServiceRefused()
    certificate = b" ".join(parts[1:])
    try:
        parsed = load_ssh_public_identity(certificate)
        if (
            not isinstance(parsed, SSHCertificate)
            or parsed.public_bytes() != certificate
        ):
            raise ServiceRefused()
        return certificate
    except Exception:
        raise ServiceRefused() from None


@dataclass(frozen=True, slots=True)
class SshdSessionReader:
    """Trusted-startup adapter, never constructed from request/environment flags.

    directory_fd anchors the qualified daemon's private /tmp mount. It must not
    be a client-selected directory. Caller owns/closes the descriptor.
    """

    directory_fd: int
    worker_uid: int

    def read(self, environment: Mapping[str, str]) -> bytes:
        if (
            os.geteuid() != self.worker_uid
            or self.worker_uid <= 0
            or environment.get("SSH_ORIGINAL_COMMAND")
            or environment.get("SSH_TTY")
        ):
            raise ServiceRefused()
        path = environment.get("SSH_USER_AUTH", "")
        if re.fullmatch(r"/tmp/sshauth\.[A-Za-z0-9]{15}", path) is None:  # noqa: S108 -- exact sshd source path, opened relative to trusted private mount FD
            raise ServiceRefused()
        descriptor = os.open(
            path.rsplit("/", 1)[1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self.directory_fd,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != self.worker_uid
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not 0 < before.st_size <= 16384
            ):
                raise ServiceRefused()
            encoded = os.read(descriptor, 16385)
            after = os.fstat(descriptor)
            # Reading may change atime; inode/ownership/content changes refuse.
            fields = (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if (
                any(getattr(before, field) != getattr(after, field) for field in fields)
                or len(encoded) != before.st_size
            ):
                raise ServiceRefused()
            return parse_auth_info(encoded)
        finally:
            os.close(descriptor)


class SessionAdmission(Protocol):
    def admit(
        self,
        token: str,
        phase: Literal["issue", "consume"],
        plan_id: UUID,
        authorization_document: bytes | None = None,
    ) -> AdmissionExpectation: ...
    def window_record_digest(self, expected: AdmissionExpectation) -> str: ...


@dataclass(frozen=True, slots=True)
class AttesterSession:
    admission: SessionAdmission
    ca_public_key: bytes
    key_id: str
    public_key: bytes
    trust_state: RehearsalIssuerTrustState
    sign: Callable[[bytes], bytes]
    expires_at: datetime
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    custody: RoleCustody | None = None
    required_phase: Literal["issue", "consume"] | None = None
    required_plan_id: UUID | None = None

    def run(self, channel: FramedChannel, authenticated_certificate: bytes) -> None:
        """Exactly two input frames, one active challenge, then terminal output."""
        started = self.now()
        invocation_id = secrets.token_hex(32)
        request = channel.receive()
        if (
            request is None
            or set(request)
            != {"schema", "phase", "plan_id", "workload_token", "authorization"}
            or request["schema"] != "Gate0SessionBegin.v1"
        ):
            raise ServiceRefused()
        phase: Literal["issue", "consume"]
        if request["phase"] == "issue":
            phase = "issue"
        elif request["phase"] == "consume":
            phase = "consume"
        else:
            raise ServiceRefused()
        plan_id = UUID(str(request["plan_id"]))
        if (self.required_phase is not None and phase != self.required_phase) or (
            self.required_plan_id is not None and plan_id != self.required_plan_id
        ):
            raise ServiceRefused()
        token = request["workload_token"]
        if not isinstance(token, str) or not 0 < len(token) <= 16384:
            raise ServiceRefused()
        authorization = (
            None
            if request["authorization"] is None
            else decode(request["authorization"], 128 * 1024)
        )
        if (phase == "issue") != (authorization is None):
            raise ServiceRefused()
        try:
            expected = self.admission.admit(token, phase, plan_id, authorization)
        finally:
            request.pop("workload_token", None)
            del token
        authentication = expected.authentication_freshness
        if authentication is not None:
            authentication.require_open()
            channel.deadline = min(channel.deadline, authentication.deadline)
        operation = expected.operation
        certificate = load_ssh_public_identity(authenticated_certificate)
        if not isinstance(certificate, SSHCertificate):
            raise ServiceRefused()
        controller, ca = certificate.public_key(), certificate.signature_key()
        if not isinstance(controller, Ed25519PublicKey) or not isinstance(
            ca, Ed25519PublicKey
        ):
            raise ServiceRefused()
        if (
            not isinstance(certificate, SSHCertificate)
            or digest(certificate.public_bytes()) != operation.certificate_digest
            or ssh_public_fingerprint(controller) != operation.controller_fingerprint
            or ssh_public_fingerprint(ca) != operation.ca_fingerprint
        ):
            raise ServiceRefused()
        channel.require_open()
        if self.custody is not None:
            self.custody.refresh(phase="challenge")
        producer = AttesterProofProducer(
            admitted=AdmittedOperation(**asdict(operation)),
            ca_public_key=self.ca_public_key,
            key_id=self.key_id,
            signer_purpose="deployment_rehearsal_harness_evidence",
            attester_public_key=self.public_key,
            trust_state=self.trust_state,
            sign=self.sign,
            expires_at=min(
                self.expires_at,
                started + timedelta(seconds=30),
                self.expires_at
                if authentication is None
                else authentication.expires_at,
            ),
            now=self.now,
        )
        challenge = producer.begin_challenge(authenticated_certificate)
        channel.send(
            {
                "schema": "Gate0SessionChallenge.v1",
                "challenge_id": challenge.challenge_id,
                "challenge": encode(challenge.canonical_bytes),
            }
        )
        response = channel.receive()
        if (
            response is None
            or set(response) != {"schema", "challenge_id", "sshsig"}
            or response["schema"] != "Gate0SessionResponse.v1"
            or response["challenge_id"] != challenge.challenge_id
        ):
            raise ServiceRefused()
        # Input must be half-closed after its one response. This rejects extra
        # frames and bounds a peer that never closes under the same deadline.
        if channel.receive(allow_eof=True) is not None:
            raise ServiceRefused()
        if self.custody is not None:
            self.custody.refresh(phase="complete")
        if authentication is not None:
            authentication.require_open()
        proof = producer.complete_challenge(
            challenge.challenge_id, decode(response["sshsig"], 16384)
        )
        channel.require_open()
        message = observation_message(
            proof=proof,
            operation=operation,
            window_record_digest=self.admission.window_record_digest(expected),
            invocation_id=invocation_id,
            observed_from=started,
            observed_until=self.now(),
        )
        producer._clock()
        signature = self.sign(message)
        Ed25519PublicKey.from_public_bytes(self.public_key).verify(signature, message)
        producer._clock()
        if authentication is not None:
            authentication.require_open()
        channel.send(
            bundle_document(proof, SignedSessionObservation(message, signature))
        )
        if authentication is not None:
            authentication.require_open()
