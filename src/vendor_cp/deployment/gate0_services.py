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
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID

from vendor_cp.deployment.gate0_attester import ProducedAttestation
from vendor_cp.deployment.gate0_collection import (
    IssuerOutcome,
    OutcomeKind,
    digest,
    request_identity,
)
from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    CompositionIncomplete,
    CompositionRefused,
    Gate0Composition,
    assemble_gate0_composition,
)
from vendor_cp.deployment.gate0_framing import FramedChannel, ServiceRefused, canonical
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
    from types import TracebackType

    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSigner,
        RehearsalIssuerAuthorizationVerifier,
    )
    from sqlalchemy.orm import Session

    from vendor_cp.deployment.gate0_role_custody import RoleCustody, RoleMaterial
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
    sessions: Callable[[], Session] | None = None
    custody: RoleCustody | None = None


class ServiceOwnerRefused(ServiceRefused):
    """One confirmed owner refusal ends the finite worker."""

    def __init__(self, outcome: IssuerOutcome) -> None:
        super().__init__()
        self.outcome = outcome


class IssuerWorker:
    """One Control install and verifier for the entire finite process lifetime."""

    def __init__(self, startup: IssuerStartup) -> None:
        if (
            startup.database_qualified is not True
            or not startup.actor_ref
            or len(startup.actor_ref) > 512
            or startup.sessions is None
        ):
            raise ServiceRefused()
        if startup.require_frozen_window:
            from vendor_cp.deployment.gate0_workload_admission import (
                OwnerWorkloadAdmission,
            )

            if (
                type(startup.admission) is not OwnerWorkloadAdmission
                or startup.sessions
                is not startup.admission._reader._runtime.platform_session_factory
            ):
                raise ServiceRefused()

        self._startup = startup
        self._request: dict[str, object] | None = None
        self._expected: AdmissionExpectation | None = None
        self._current_proof_identity: tuple[str, str] | None = None
        self._bundles: dict[str, bytes] = {}
        self._bundle_bytes = 0
        self.terminal_outcome: IssuerOutcome | None = None
        self.outcomes: list[IssuerOutcome] = []
        self._run_started = False
        self.composition: Gate0Composition = assemble_gate0_composition(
            sessions=startup.sessions,
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
            expected = self._startup.admission.admit(
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
            self._expected = expected
            return expected
        finally:
            request.pop("workload_token", None)

    def _proof(self, expected: AdmissionExpectation) -> ProducedAttestation:
        self._current_proof_identity = None
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
        raw_bundle = canonical(self._request["proof"])
        from vendor_cp.deployment.gate0_framing import strict_object

        owner = decode(strict_object(proof.control_document)["canonical_bytes"], 8192)
        evidence_digest = digest(owner)
        registered = verifier._register(proof, expected.operation)
        if registered != evidence_digest:
            raise ServiceRefused()
        previous = self._bundles.get(evidence_digest)
        if previous is not None and previous != raw_bundle:
            raise ServiceRefused()
        if previous is None:
            if (
                len(self._bundles) >= 4
                or verifier._retained_bytes + self._bundle_bytes + len(raw_bundle)
                > 512 * 1024
            ):
                raise ServiceRefused()
            self._bundles[evidence_digest] = raw_bundle
            self._bundle_bytes += len(raw_bundle)
        # Attribute only the successfully verified, registered and retained
        # proof from this submission. Historical plan/phase matches are not
        # evidence of which proof this operation actually evaluated.
        if expected.authentication_freshness is not None:
            expected.authentication_freshness.require_open()
        self._current_proof_identity = (evidence_digest, digest(raw_bundle))
        return proof

    def run(self, channel: FramedChannel) -> None:
        if self._run_started:
            raise ServiceRefused()
        self._run_started = True
        from dotmac_deployment_control import RehearsalIssuerIssuanceRefusedError

        from vendor_cp.approvals.adapter import ApprovalHoldRefusal, ApprovalNotHeld
        from vendor_cp.deployment.gate0_window import AuthenticatedApprovalWithdrawal

        for ordinal in range(1, 9):
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
            phase = cast(Literal["issue", "consume", "standing"], phase)
            identity = request_identity(request)
            self._request = request
            self._expected = None
            self._current_proof_identity = None
            committed = False
            proof_digest: str | None = None
            bundle_digest: str | None = None
            window_digest: str | None = None
            try:
                if self._startup.custody is not None:
                    self._startup.custody.refresh(phase="submission")
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
                    kind = OutcomeKind.ISSUE_COMMITTED
                    data: dict[str, object] = asdict(result)
                    if result.issuer_receipt is not None:
                        data["issuer_receipt"] = encode(result.issuer_receipt)
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
                    kind = OutcomeKind.CONSUME_COMMITTED
                    data = asdict(result)
                else:
                    evidence_digest = request["evidence_digest"]
                    if (
                        not isinstance(evidence_digest, str)
                        or len(evidence_digest) != 71
                    ):
                        raise ServiceRefused()
                    # Standing selects an existing exact registered proof;
                    # no later same-plan/phase proof may replace that identity.
                    self._startup.verifier.export_registered(evidence_digest)
                    selected_bundle = self._bundles.get(evidence_digest)
                    if selected_bundle is None:
                        raise ServiceRefused()
                    self._current_proof_identity = (
                        evidence_digest,
                        digest(selected_bundle),
                    )
                    standing = self.composition.standing(
                        decode(request["authorization"], 128 * 1024), evidence_digest
                    )
                    # Public owner result type, no reflection or arbitrary data.
                    kind = OutcomeKind.STANDING
                    data = {
                        "standing": standing.standing.value,
                        "refusal": None
                        if standing.refusal is None
                        else standing.refusal.value,
                    }
                expected = self._expected
                if expected is not None:
                    window_digest = expected.window_digest
                if self._current_proof_identity is not None:
                    proof_digest, bundle_digest = self._current_proof_identity
                outcome = IssuerOutcome(
                    ordinal,
                    phase,
                    identity,
                    window_digest,
                    proof_digest,
                    bundle_digest,
                    kind,
                    None,
                    None,
                    canonical(data),
                )
                authentication = (
                    None if expected is None else expected.authentication_freshness
                )
                original_deadline = channel.deadline
                try:
                    if authentication is not None:
                        authentication.require_open()
                        channel.deadline = min(
                            original_deadline, authentication.deadline
                        )
                    channel.send(outcome.document())
                    if authentication is not None:
                        authentication.require_open()
                finally:
                    channel.deadline = original_deadline
                self.outcomes.append(outcome)
            except (
                AuthenticatedApprovalWithdrawal,
                ApprovalNotHeld,
                RehearsalIssuerIssuanceRefusedError,
            ) as caught:
                if committed:
                    raise ServiceIncomplete() from None
                expected = self._expected
                authentication = (
                    None if expected is None else expected.authentication_freshness
                )
                if isinstance(caught, AuthenticatedApprovalWithdrawal):
                    authentication = caught.authentication_freshness
                    window_digest = caught.denial.window.digest
                    namespace, code = "approvals", ApprovalHoldRefusal.WITHDRAWN.value
                elif isinstance(caught, ApprovalNotHeld):
                    if (
                        expected is None
                        or caught.code is not ApprovalHoldRefusal.WITHDRAWN
                    ):
                        raise
                    window_digest = expected.window_digest
                    namespace, code = "approvals", caught.code.value
                else:
                    if expected is None:
                        raise
                    window_digest = expected.window_digest
                    namespace, code = "control.issuance", caught.code.value
                if self._current_proof_identity is not None:
                    proof_digest, bundle_digest = self._current_proof_identity
                outcome = IssuerOutcome(
                    ordinal,
                    phase,
                    identity,
                    window_digest,
                    proof_digest,
                    bundle_digest,
                    OutcomeKind.OWNER_REFUSED,
                    namespace,
                    code,
                    canonical({}),
                )
                if authentication is not None:
                    authentication.require_open()
                self.terminal_outcome = outcome
                original_deadline = channel.deadline
                try:
                    if authentication is not None:
                        channel.deadline = min(
                            original_deadline, authentication.deadline
                        )
                    channel.send(outcome.document())
                    if authentication is not None:
                        authentication.require_open()
                except BaseException:
                    self.terminal_outcome = None
                    raise ServiceIncomplete() from None
                finally:
                    channel.deadline = original_deadline
                self.outcomes.append(outcome)
                raise ServiceOwnerRefused(outcome) from None
            except BaseException:
                if committed:
                    raise ServiceIncomplete() from None
                raise
            finally:
                self._request = None
                self._expected = None
                self._current_proof_identity = None
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
    custody: RoleCustody | None = None,
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
        sessions=admission._reader._runtime.platform_session_factory,
        custody=custody,
    )


def assemble_attester_session(
    *,
    material: RoleMaterial,
    admission: WorkloadAdmission,
    ca_public_key: bytes,
    expires_at: datetime,
    custody: RoleCustody | None = None,
    required_phase: Literal["issue", "consume"] | None = None,
    required_plan_id: UUID | None = None,
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
        custody=custody,
        required_phase=required_phase,
        required_plan_id=required_plan_id,
    )


@dataclass(frozen=True, slots=True)
class IssuerProcessResult:
    exit_code: int
    outcomes: tuple[IssuerOutcome, ...] = ()

    @property
    def transcript_digest(self) -> str:
        return digest(
            canonical(
                {
                    "schema": "Gate0IssuerOutcomeTranscript.v1",
                    "outcomes": [outcome.document() for outcome in self.outcomes],
                }
            )
        )


def issuer_run_result(startup: IssuerStartup | None = None) -> IssuerProcessResult:
    """No accepted authority DB/admission/custody binding is installed yet."""
    from vendor_cp.deployment.gate0_role_custody import CustodyProfile, RoleCustody
    from vendor_cp.deployment.gate0_workload_admission import OwnerWorkloadAdmission

    if (
        startup is None
        or type(startup.admission) is not OwnerWorkloadAdmission
        or startup.require_frozen_window is not True
        or type(startup.custody) is not RoleCustody
        or startup.custody.profile is not CustodyProfile.ISSUER_FINITE_V1
        or startup.custody._material is None
        or startup.custody._material.key is not startup.signer
    ):
        print("DATABASE_BINDING_UNQUALIFIED", file=sys.stderr)
        return IssuerProcessResult(3)
    worker: IssuerWorker | None = None
    try:
        # Derive once from the already running verifier; never reset on frames.
        channel = FramedChannel(
            sys.stdin.fileno(), sys.stdout.fileno(), deadline=startup.verifier._deadline
        )
        with process_deadline(channel.deadline):
            worker = IssuerWorker(startup)
            worker.run(channel)
        return IssuerProcessResult(0, tuple(worker.outcomes))
    except ServiceOwnerRefused:
        return IssuerProcessResult(3, () if worker is None else tuple(worker.outcomes))
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return IssuerProcessResult(5, () if worker is None else tuple(worker.outcomes))
    except (ServiceRefused, CompositionRefused):
        print("GATE0_SERVICE_REFUSED", file=sys.stderr)
        return IssuerProcessResult(3, () if worker is None else tuple(worker.outcomes))
    except (ServiceIncomplete, CompositionIncomplete):
        print("GATE0_SERVICE_INCOMPLETE", file=sys.stderr)
        return IssuerProcessResult(5, () if worker is None else tuple(worker.outcomes))
    except Exception:
        print("GATE0_SERVICE_FAILED", file=sys.stderr)
        return IssuerProcessResult(5, () if worker is None else tuple(worker.outcomes))


def issuer_run(startup: IssuerStartup | None = None) -> int:
    """Compatibility exit-code adapter; root integration uses typed result."""
    return issuer_run_result(startup).exit_code


def attester_session(
    session: AttesterSession | None = None,
    reader: SshdSessionReader | None = None,
    *,
    deadline: float | None = None,
) -> int:
    """Standalone environment variables cannot enable an authenticated worker."""
    from vendor_cp.deployment.gate0_role_custody import CustodyProfile, RoleCustody

    if session is None or reader is None:
        print("TRUSTED_SSHD_BINDING_UNCONFIGURED", file=sys.stderr)
        return 3
    try:
        if (
            type(session.custody) is not RoleCustody
            or session.custody.profile is not CustodyProfile.ATTESTER_FINITE_V1
            or session.custody._material is None
            or session.trust_state is not session.custody._material.attester_trust
            or session.sign != session.custody._material.attester_sign
            or session.required_phase is None
            or session.required_plan_id is None
        ):
            raise ServiceRefused()
        duration = min(30.0, (session.expires_at - session.now()).total_seconds())
        if duration <= 0:
            raise ServiceRefused()
        if deadline is None:
            raise ServiceRefused()
        channel = FramedChannel(
            sys.stdin.fileno(),
            sys.stdout.fileno(),
            deadline=min(deadline, monotonic() + duration),
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


def run_installed_issuer() -> int:
    """Prepare the fixed installed owner, publish capture, then serve commands."""
    execution_started = False
    cleanup_failed = False
    preparation_entry_pending = False
    try:
        from vendor_cp.deployment.gate0_bootstrap import (
            load_issuer_installation,
            prepare_installed_issuer,
        )
        from vendor_cp.deployment.gate0_launch import (
            CaptureInstallReadback,
            InstalledLaunchContext,
        )
        from vendor_cp.deployment.gate0_management_delivery import (
            install_document,
            verify_readback,
        )

        context = InstalledLaunchContext.from_installed()
        installation = load_issuer_installation(context)
        with ExitStack() as custody_scope:
            preparation = prepare_installed_issuer(context, installation)
            # Entry includes generator-owned database/custody setup and may
            # fail while cleaning up before it yields any observable state.
            preparation_entry_pending = True
            prepared = preparation.__enter__()
            preparation_entry_pending = False

            def close_custody(
                error_type: type[BaseException] | None,
                error: BaseException | None,
                traceback: TracebackType | None,
            ) -> Literal[False]:
                nonlocal cleanup_failed
                try:
                    if preparation.__exit__(error_type, error, traceback):
                        raise ServiceIncomplete()
                except BaseException:
                    cleanup_failed = True
                    raise
                return False

            custody_scope.push(close_custody)
            if prepared.capture.coordinates.plan_id != installation.plan_id:
                raise ServiceRefused()
            with ExitStack() as descriptor_scope:
                export = context.open_issuer_capture_export()
                connection = export.__enter__()

                def close_export(
                    error_type: type[BaseException] | None,
                    error: BaseException | None,
                    traceback: TracebackType | None,
                ) -> Literal[False]:
                    nonlocal cleanup_failed
                    try:
                        export.__exit__(error_type, error, traceback)
                    except BaseException:
                        cleanup_failed = True
                        raise
                    return False

                descriptor_scope.push(close_export)
                channel = FramedChannel(
                    connection.fileno(),
                    connection.fileno(),
                    deadline=min(context.deadline, monotonic() + 10),
                    maximum_frames=2,
                )
                channel.send(
                    install_document(
                        context.packet_digest,
                        prepared.capture,
                        installation.management_delivery.capture,
                    )
                )
                import socket

                connection.shutdown(socket.SHUT_WR)
                readback = channel.receive()
                if readback is None:
                    raise ServiceRefused()
                verify_readback(
                    readback,
                    CaptureInstallReadback(
                        context.packet_digest,
                        prepared.capture.coordinates,
                        context.expires_at,
                    ),
                )
                if channel.receive(allow_eof=True) is not None:
                    raise ServiceRefused()
            context.require_open()
            execution_started = True
            result = issuer_run_result(prepared.startup)
        # Only a real typed owner terminal can publish this worker declaration.
        # Custody and every management descriptor have already closed. sshd's
        # daemon status and the authenticated SSH client's status remain distinct.
        if type(result) is not IssuerProcessResult:
            raise ServiceIncomplete()
        if (
            result.exit_code == 3
            and result.outcomes
            and result.outcomes[-1].kind is OutcomeKind.OWNER_REFUSED
        ):
            context.finish_issuer(result)
        return result.exit_code
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except Exception:
        if preparation_entry_pending or execution_started or cleanup_failed:
            print("GATE0_SERVICE_INCOMPLETE", file=sys.stderr)
            return 5
        print("DATABASE_BINDING_UNQUALIFIED", file=sys.stderr)
        return 3
    except BaseException:
        print("GATE0_SERVICE_INCOMPLETE", file=sys.stderr)
        return 5


def run_installed_attester() -> int:
    """One claimed installed slot; parent accepts only its terminal success."""
    execution_started = False
    try:
        from vendor_cp.deployment.gate0_bootstrap import (
            load_attester_installation,
            prepare_installed_attester,
        )
        from vendor_cp.deployment.gate0_launch import InstalledLaunchContext

        context = InstalledLaunchContext.from_installed()
        installation = load_attester_installation(context)
        with prepare_installed_attester(context, installation) as prepared:
            execution_started = True
            result = attester_session(
                prepared.session, prepared.reader, deadline=prepared.deadline
            )
        # Custody teardown must finish before a terminal success is visible.
        completion = prepared.session.completion
        if result == 0:
            if completion is None:
                raise ServiceIncomplete()
            completion.require_open()
            context.finish_slot(
                "success",
                bundle_digest=completion.bundle_digest,
                invocation_id=completion.invocation_id,
            )
            completion.require_open()
        else:
            context.finish_slot("refused")
        return result
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except Exception:
        if execution_started:
            print("GATE0_SERVICE_INCOMPLETE", file=sys.stderr)
            return 5
        print("TRUSTED_SSHD_BINDING_UNCONFIGURED", file=sys.stderr)
        return 3


def run_installed_capture_receiver() -> int:
    """Fixed management SSH endpoint, with publication owned by its parent."""
    try:
        from vendor_cp.deployment.gate0_bootstrap import (
            load_management_delivery_installation,
        )
        from vendor_cp.deployment.gate0_launch import InstalledLaunchContext
        from vendor_cp.deployment.gate0_management_delivery import (
            receive_capture_install,
        )

        context = InstalledLaunchContext.from_installed()
        installation = load_management_delivery_installation(context)
        channel = FramedChannel(
            sys.stdin.fileno(),
            sys.stdout.fileno(),
            deadline=min(context.deadline, monotonic() + 10),
            maximum_frames=2,
        )
        receive_capture_install(
            context=context,
            channel=channel,
            selection=installation.capture,
            absolute_end=context.expires_at,
        )
        return 0
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except Exception:
        print("GATE0_CAPTURE_REFUSED", file=sys.stderr)
        return 3


def run_installed_capture_sender() -> int:
    """Separate management identity; ACK uses only the parent's private stream."""
    try:
        from vendor_cp.deployment.gate0_bootstrap import (
            load_management_delivery_installation,
        )
        from vendor_cp.deployment.gate0_launch import InstalledLaunchContext
        from vendor_cp.deployment.gate0_management_delivery import push_capture_install

        context = InstalledLaunchContext.from_installed()
        installation = load_management_delivery_installation(context)
        push_capture_install(context=context, installation=installation)
        return 0
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        return 5
    except Exception:
        print("GATE0_CAPTURE_REFUSED", file=sys.stderr)
        return 3


def run_installed_supervisor() -> int:
    """Export root mechanics once after outer close; no worker-exit claim."""
    supervisor = None
    result = 5
    incomplete_error: type[Exception] = ServiceIncomplete
    try:
        from vendor_cp.deployment.gate0_launch import (
            FiniteGate0Supervisor,
            LaunchIncomplete,
        )

        incomplete_error = LaunchIncomplete
        supervisor = FiniteGate0Supervisor.from_installed()
        supervisor.run()
        result = 0
    except ServiceCancelled:
        print("GATE0_SERVICE_CANCELLED", file=sys.stderr)
        result = 5
    except incomplete_error:
        print("GATE0_LAUNCH_INCOMPLETE", file=sys.stderr)
        result = 5
    except Exception:
        print("GATE0_LAUNCH_REFUSED", file=sys.stderr)
        result = 3 if supervisor is None else 5
    except BaseException:
        print("GATE0_LAUNCH_INCOMPLETE", file=sys.stderr)
        result = 5
    finally:
        if supervisor is not None:
            try:
                supervisor.close()
            except BaseException:
                print("GATE0_LAUNCH_INCOMPLETE", file=sys.stderr)
                result = 5
    if supervisor is not None:
        # The owner derives complete/incomplete diagnostics from actual run and
        # close state. Export never receives a caller-provided success verdict.
        # A private incomplete export is useful evidence but cannot qualify E.
        try:
            supervisor.export_cleanup()
            if supervisor.mechanics_outcome != "complete":
                result = 5
        except BaseException:
            print("GATE0_LAUNCH_INCOMPLETE", file=sys.stderr)
            result = 5
    return result
