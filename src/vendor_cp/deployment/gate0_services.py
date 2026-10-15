"""Installed finite service owners; all operational startup bindings are absent.

Trusted assembly calls serve_issuer/serve_attester with fixed typed inputs.
CLI startup never loads request-selected modules, authorities, databases or test
providers. No live activation follows from installing this source.
"""

from __future__ import annotations

import os
import signal
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from vendor_cp.deployment.gate0_attester import ProducedAttestation
from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    CompositionIncomplete,
    CompositionRefused,
    Gate0Composition,
    assemble_gate0_composition,
)
from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused
from vendor_cp.deployment.gate0_observation import (
    decode,
    encode,
    parse_bundle,
    verify_observation,
)
from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier
from vendor_cp.deployment.gate0_session import (
    AttesterSession,
    SessionAdmission,
    SshdSessionReader,
)
from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerCommand

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSigner,
        RehearsalIssuerAuthorizationVerifier,
    )

    from vendor_cp.deployment.gate0_role_custody import RoleMaterial
    from vendor_cp.deployment.gate0_workload_admission import WorkloadAdmission


class ServiceCancelled(BaseException):
    """Terminal process cancellation, never caught as a retryable phase error."""


class ServiceIncomplete(RuntimeError):
    """A mutation committed but its management response was not confirmed."""


@contextmanager
def process_deadline(deadline: float) -> Iterator[None]:
    """One main-process watchdog covers callbacks, I/O and owner transactions.

    Providers still enforce their own I/O deadlines. This is an additional
    terminal bound, not a claim that Python can interrupt arbitrary native code.
    A supervisor must kill a stuck worker by the same original deadline.
    """
    remaining = deadline - monotonic()
    if not 0 < remaining <= 600 or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise ServiceRefused()
    watched = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)
    old = {number: signal.getsignal(number) for number in watched}

    def cancel(_number: int, _frame: object) -> None:
        raise ServiceCancelled()

    try:
        for number in watched:
            signal.signal(number, cancel)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, handler in old.items():
            signal.signal(number, handler)


@dataclass(frozen=True, slots=True)
class IssuerStartup:
    """Installation-owned inputs, never fields in the management grammar.

    database_qualified is the deployment owner's inventory/adoption decision;
    there is deliberately no automatic socket-health or migration fallback.
    """

    admission: SessionAdmission
    verifier: BoundedHarnessVerifier
    signer: RehearsalIssuerAuthorizationSigner
    authorization_verifier: RehearsalIssuerAuthorizationVerifier
    authorization_ttl: timedelta
    actor_ref: str
    database_qualified: bool
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    require_frozen_window: bool = True


class IssuerWorker:
    """One Control install and verifier for the entire finite process lifetime."""

    def __init__(self, startup: IssuerStartup) -> None:
        if (
            startup.database_qualified is not True
            or not startup.actor_ref
            or len(startup.actor_ref) > 512
        ):
            raise ServiceRefused()
        from dotmac_kernel.db import runtime

        self._startup = startup
        self._request: dict[str, object] | None = None
        self.composition: Gate0Composition = assemble_gate0_composition(
            sessions=runtime.platform_session_factory,
            admission=self._admit,
            proof_resolver=self._proof,
            verifier=startup.verifier,
            signer=startup.signer,
            authorization_verifier=startup.authorization_verifier,
            authorization_ttl=startup.authorization_ttl,
            require_frozen_window=getattr(startup, "require_frozen_window", True),
        )

    def _admit(
        self, phase: Literal["issue", "consume"], plan_id: UUID
    ) -> AdmissionExpectation:
        request = self._request
        if request is None:
            raise ServiceRefused()
        token = request.get("workload_token")
        if not isinstance(token, str) or not 0 < len(token) <= 16384:
            raise ServiceRefused()
        authorization = request.get("authorization")
        try:
            return self._startup.admission.admit(
                token,
                phase,
                plan_id,
                # Standing retains its real envelope for owner checks, while
                # admission follows the retained proof phase. Issue admission
                # never receives an existing authorization.
                None
                if phase == "issue" or authorization is None
                else decode(authorization, 128 * 1024),
            )
        finally:
            request.pop("workload_token", None)

    def _proof(self, expected: AdmissionExpectation) -> ProducedAttestation:
        if self._request is None:
            raise ServiceRefused()
        proof, observation = parse_bundle(self._request.get("proof"))
        verifier = self._startup.verifier
        verify_observation(
            proof=proof,
            observation=observation,
            operation=expected.operation,
            window_record_digest=self._startup.admission.window_record_digest(expected),
            key_id=verifier._key_id,
            public_key=verifier._public_key,
            trust_state=verifier._trust,
            now=self._startup.now(),
        )
        verifier._require_open()
        return proof

    def run(self, channel: FramedChannel) -> None:
        for _ in range(8):
            self._startup.verifier._require_open()
            request = channel.receive(allow_eof=True)
            if request is None:
                return
            phase = request.get("operation")
            common = {"schema", "operation", "workload_token"}
            fields = {
                "issue": common | {"plan_id", "command_id", "proof"},
                "consume": common | {"plan_id", "authorization", "proof"},
                "standing": common | {"authorization", "evidence_digest"},
            }
            if (
                request.get("schema") != "Gate0IssuerSubmission.v1"
                or not isinstance(phase, str)
                or phase not in fields
                or set(request) != fields[phase]
            ):
                raise ServiceRefused()
            self._request = request
            committed = False
            try:
                if phase == "issue":
                    command_id = request["command_id"]
                    if (
                        not isinstance(command_id, str)
                        or not 0 < len(command_id) <= 512
                        or command_id != command_id.strip()
                    ):
                        raise ServiceRefused()
                    result = self.composition.issue(
                        RehearsalIssuerCommand(
                            command_id,
                            UUID(str(request["plan_id"])),
                            self._startup.actor_ref,
                        )
                    )
                    committed = True
                    data: dict[str, object] = asdict(result)
                    if result.authorization_document is not None:
                        data["authorization_document"] = encode(
                            result.authorization_document
                        )
                elif phase == "consume":
                    result = self.composition.consume(
                        UUID(str(request["plan_id"])),
                        decode(request["authorization"], 128 * 1024),
                    )
                    committed = True
                    data = asdict(result)
                else:
                    evidence_digest = request["evidence_digest"]
                    if (
                        not isinstance(evidence_digest, str)
                        or len(evidence_digest) != 71
                    ):
                        raise ServiceRefused()
                    standing = self.composition.standing(
                        decode(request["authorization"], 128 * 1024), evidence_digest
                    )
                    # Public owner result type, no reflection or arbitrary data.
                    data = {
                        "standing": standing.standing.value,
                        "refusal": None
                        if standing.refusal is None
                        else standing.refusal.value,
                    }
                channel.send(
                    {
                        "schema": "Gate0IssuerResult.v1",
                        "operation": phase,
                        "result": data,
                        "readiness_accepted": False,
                    }
                )
            except BaseException:
                if committed:
                    raise ServiceIncomplete() from None
                raise
            finally:
                self._request = None
        # The finite command budget never silently starts a new window.
        if channel.receive(allow_eof=True) is not None:
            raise ServiceRefused()


def serve_issuer(startup: IssuerStartup, channel: FramedChannel) -> None:
    with process_deadline(channel.deadline):
        IssuerWorker(startup).run(channel)


def serve_attester(
    session: AttesterSession,
    reader: SshdSessionReader,
    channel: FramedChannel,
    environment: Mapping[str, str],
) -> None:
    with process_deadline(channel.deadline):
        certificate = reader.read(environment)
        session.run(channel, certificate)


def assemble_issuer_startup(
    *,
    material: RoleMaterial,
    admission: WorkloadAdmission,
    attester_key_id: str,
    attester_public_key: bytes,
    expires_at: datetime,
    authorization_ttl: timedelta,
    actor_ref: str,
    database_qualified: bool,
) -> IssuerStartup:
    """Fixed trusted assembly over concrete role custody and admission adapters.

    Custody bootstrap is a preceding bounded startup operation. Its original
    deadline remains inside the material; this function cannot extend it.
    """
    from vendor_cp.deployment.gate0_workload_admission import OwnerWorkloadAdmission

    if (
        type(admission) is not OwnerWorkloadAdmission
        or admission._expires is None
        or expires_at > admission._expires
        or expires_at > material.key._expires
    ):
        raise ServiceRefused()
    from vendor_cp.deployment.gate0_role_custody import PublicIssuerVerifier

    configured = admission._reader._verifier
    if (
        type(configured) is not PublicIssuerVerifier
        or admission._reader._identity
        != material.issuer_signer.rehearsal_issuer_identity
        or configured.key_id != material.key.key_id
        or configured.public_key != material.public_key
        or configured.trust is not material.issuer_trust
    ):
        raise ServiceRefused()
    verifier = BoundedHarnessVerifier(
        key_id=attester_key_id,
        public_key=attester_public_key,
        trust_state=material.attester_trust,
        expires_at=expires_at,
    )
    verifier._deadline = min(
        verifier._deadline, admission._deadline, material.key._deadline
    )
    verifier._require_open()
    return IssuerStartup(
        admission,
        verifier,
        material.issuer_signer,
        material.issuer_verifier,
        authorization_ttl,
        actor_ref,
        database_qualified,
        require_frozen_window=True,
    )


def assemble_attester_session(
    *,
    material: RoleMaterial,
    admission: WorkloadAdmission,
    ca_public_key: bytes,
    expires_at: datetime,
) -> AttesterSession:
    from vendor_cp.deployment.gate0_workload_admission import ApprovedAtStartAdmission

    if (
        type(admission) is not ApprovedAtStartAdmission
        or admission._expires is None
        or expires_at > admission._expires
        or expires_at > material.key._expires
    ):
        raise ServiceRefused()
    from vendor_cp.deployment.gate0_role_custody import PublicIssuerVerifier

    configured = admission._verifier
    if (
        type(configured) is not PublicIssuerVerifier
        or configured.trust is not material.issuer_trust
        or configured.key_id != admission._identity.key_id
    ):
        raise ServiceRefused()
    return AttesterSession(
        admission,
        ca_public_key,
        material.key.key_id,
        material.public_key,
        material.attester_trust,
        material.attester_sign,
        expires_at,
    )


def issuer_run(startup: IssuerStartup | None = None) -> int:
    """No accepted authority DB/admission/custody binding is installed yet."""
    from vendor_cp.deployment.gate0_workload_admission import OwnerWorkloadAdmission

    if (
        startup is None
        or type(startup.admission) is not OwnerWorkloadAdmission
        or startup.require_frozen_window is not True
    ):
        print("DATABASE_BINDING_UNQUALIFIED", file=sys.stderr)
        return 3
    try:
        # Derive once from the already running verifier; never reset on frames.
        channel = FramedChannel(
            sys.stdin.fileno(), sys.stdout.fileno(), deadline=startup.verifier._deadline
        )
        serve_issuer(startup, channel)
        return 0
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except (ServiceRefused, CompositionRefused):
        print("GATE0_SERVICE_REFUSED", file=sys.stderr)
        return 3
    except (ServiceIncomplete, CompositionIncomplete):
        print("GATE0_SERVICE_INCOMPLETE", file=sys.stderr)
        return 5
    except Exception:
        print("GATE0_SERVICE_FAILED", file=sys.stderr)
        return 5


def attester_session(
    session: AttesterSession | None = None, reader: SshdSessionReader | None = None
) -> int:
    """Standalone environment variables cannot enable an authenticated worker."""
    if session is None or reader is None:
        print("TRUSTED_SSHD_BINDING_UNCONFIGURED", file=sys.stderr)
        return 3
    try:
        duration = min(30.0, (session.expires_at - session.now()).total_seconds())
        if duration <= 0:
            raise ServiceRefused()
        channel = FramedChannel(
            sys.stdin.fileno(),
            sys.stdout.fileno(),
            deadline=monotonic() + duration,
            maximum_frames=3,
        )
        serve_attester(session, reader, channel, os.environ)
        return 0
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except Exception:
        print("GATE0_SERVICE_REFUSED", file=sys.stderr)
        return 3
