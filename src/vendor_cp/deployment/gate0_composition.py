"""Thin, non-authorizing phase composition over published Control/Approvals.

No admission oracle, custody loader, transport, controller-session observer or
E receipt finalizer is implemented here. All production ports are explicit;
unconfigured ports refuse. Fixture admission never becomes protected evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, timedelta
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.deployment.gate0_attester import ProducedAttestation
from vendor_cp.deployment.gate0_runtime import (
    AdmittedOperation,
    BoundedHarnessVerifier,
    _strict_json,
)
from vendor_cp.deployment.protected_rehearsal_issuer import (
    consume_authorization,
    issue_authorization,
)
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSigner,
        RehearsalIssuerAuthorizationStandingResult,
        RehearsalIssuerAuthorizationV1,
        RehearsalIssuerAuthorizationVerifier,
    )


class CompositionRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_composition_refused")


class CompositionIncomplete(RuntimeError):
    """Commit/cleanup outcome cannot be returned as a successful phase."""

    def __init__(self) -> None:
        super().__init__("gate0_composition_incomplete")


@dataclass(frozen=True, slots=True)
class AdmissionExpectation:
    """Facts supplied by an independent authenticated admission boundary.

    The dataclass validates shape only. It is not a GitHub/approval oracle.
    Policy/request/target expectations are not derived from the checked plan.
    """

    operation: AdmittedOperation
    target_id: UUID
    environment: str
    approval_request_id: UUID
    approval_policy_code: str
    approval_policy_version: int

    def __post_init__(self) -> None:
        if (
            type(self.operation) is not AdmittedOperation
            or type(self.target_id) is not UUID
            or type(self.approval_request_id) is not UUID
            or self.environment != "rehearsal"
            or not isinstance(self.approval_policy_code, str)
            or not self.approval_policy_code
            or self.approval_policy_code != self.approval_policy_code.strip()
            or len(self.approval_policy_code) > 512
            or type(self.approval_policy_version) is not int
            or self.approval_policy_version < 1
        ):
            raise CompositionRefused()


class AdmissionPort(Protocol):
    def __call__(
        self, phase: Literal["issue", "consume"], plan_id: UUID
    ) -> AdmissionExpectation | None: ...


class ProofResolver(Protocol):
    def __call__(self, expected: AdmissionExpectation) -> ProducedAttestation: ...


@dataclass(frozen=True, slots=True)
class AuthorizationBinding:
    encoded: bytes
    digest: str
    issued_at: str
    parsed: RehearsalIssuerAuthorizationV1


def _canonical(document: object) -> bytes:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > 128 * 1024:
        raise CompositionRefused()
    return encoded


def authorization_binding(document: bytes) -> AuthorizationBinding:
    """CP companion convention: hash the full public parsed envelope.

    Strict bounded transport JSON -> owner parse -> full as_mapping, including
    signature/key metadata. This binds bytes but does not establish standing.
    """
    from dotmac_deployment_control import RehearsalIssuerAuthorizationV1

    failed = False
    try:
        parsed = RehearsalIssuerAuthorizationV1.parse(
            _strict_json(document, 128 * 1024)
        )
        encoded = _canonical(parsed.as_mapping())
        return AuthorizationBinding(
            encoded,
            "sha256:" + hashlib.sha256(encoded).hexdigest(),
            parsed.statement.issued_at.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            parsed,
        )
    except Exception:
        failed = True
    if failed:
        raise CompositionRefused()
    raise CompositionRefused()


@dataclass(frozen=True, slots=True)
class PhaseResult:
    evidence_digest: str
    authorization_id: str
    lease_id: str
    authorization_document: bytes | None = None
    single_use_reference: str | None = None

    @property
    def readiness_accepted(self) -> Literal[False]:
        return False


class Gate0Composition:
    """Only phase entrypoints; no generic registration/approval/receipt route."""

    def __init__(
        self,
        *,
        sessions: Callable[[], Session],
        admission: AdmissionPort | None,
        proof_resolver: ProofResolver | None,
        verifier: BoundedHarnessVerifier,
    ) -> None:
        self._sessions = sessions
        self._admission, self._resolver, self._verifier = (
            admission,
            proof_resolver,
            verifier,
        )

    def _admit(
        self, phase: Literal["issue", "consume"], plan_id: UUID
    ) -> AdmissionExpectation:
        if self._admission is None or self._resolver is None:
            raise CompositionRefused()
        failed = False
        try:
            self._verifier._require_open()
            result = self._admission(phase, plan_id)
            if type(result) is not AdmissionExpectation:
                raise CompositionRefused()
            # Detach callback-owned values before any later callback/transaction.
            result = AdmissionExpectation(
                AdmittedOperation(**asdict(result.operation)),
                result.target_id,
                result.environment,
                result.approval_request_id,
                result.approval_policy_code,
                result.approval_policy_version,
            )
            if result.operation.phase != phase or result.operation.plan_id != str(
                plan_id
            ):
                raise CompositionRefused()
            self._verifier._require_open()
            return result
        except Exception:
            failed = True
        if failed:
            raise CompositionRefused()
        raise CompositionRefused()

    def _check_plan(
        self,
        db: Session,
        expected: AdmissionExpectation,
        binding: AuthorizationBinding | None = None,
    ) -> None:
        from dotmac_deployment_control import get_plan, get_target

        operation = expected.operation
        plan = get_plan(db, UUID(operation.plan_id))
        target = get_target(db, expected.target_id)
        if (
            plan is None
            or target is None
            or plan.id != UUID(operation.plan_id)
            or plan.target_id != expected.target_id
            or target.id != expected.target_id
            or target.target_ref != operation.target_ref
            or target.environment != expected.environment
            or plan.purpose != operation.plan_purpose
            or plan.operation != operation.operation
            or plan.plan_digest != operation.plan_digest
            or plan.execution_plan_digest != operation.execution_plan_digest
            or not plan.requires_approval
            or plan.approval_decision_ref != str(expected.approval_request_id)
            or plan.approval_policy_code != expected.approval_policy_code
            or plan.approval_policy_version != expected.approval_policy_version
        ):
            raise CompositionRefused()
        # PlanView.purpose is display-only: the actual CP/Control mutation still
        # re-derives authority under its own locks. No view becomes a grant.
        if binding is not None:
            statement = binding.parsed.statement
            if (
                statement.immutable_reference != operation.plan_id
                or statement.target_id != str(expected.target_id)
                or statement.target_ref != operation.target_ref
                or statement.environment != expected.environment
                or statement.lease_id != operation.lease_id
                or statement.controller_fingerprint != operation.controller_fingerprint
                or statement.desired_state_digest != operation.plan_digest
                or statement.profile_digest != plan.descriptor_digest
                or statement.execution_plan_digest != operation.execution_plan_digest
            ):
                raise CompositionRefused()
            if operation.phase == "consume" and (
                operation.authorization_digest != binding.digest
                or operation.authorization_issued_at != binding.issued_at
            ):
                raise CompositionRefused()

    def _preflight(
        self, expected: AdmissionExpectation, binding: AuthorizationBinding | None
    ) -> None:
        db = self._sessions()
        try:
            self._check_plan(db, expected, binding)
        finally:
            db.close()

    def _proof(self, expected: AdmissionExpectation) -> str:
        if self._resolver is None:
            raise CompositionRefused()
        failed = False
        try:
            self._verifier._require_open()
            resolver_input = AdmissionExpectation(
                AdmittedOperation(**asdict(expected.operation)),
                expected.target_id,
                expected.environment,
                expected.approval_request_id,
                expected.approval_policy_code,
                expected.approval_policy_version,
            )
            proof = self._resolver(resolver_input)
            # Resolver must bound its wire response before constructing a value;
            # registration also checks all retained/decoded source format bounds.
            return self._verifier._register(proof, expected.operation)
        except Exception:
            failed = True
        if failed:
            raise CompositionRefused()
        raise CompositionRefused()

    def _mutate(
        self,
        expected: AdmissionExpectation,
        binding: AuthorizationBinding | None,
        transition: Callable[[Session], PhaseResult],
    ) -> PhaseResult:
        db = self._sessions()
        error: BaseException | None = None
        result: PhaseResult | None = None
        commit_started = False
        try:
            self._check_plan(db, expected, binding)  # ordinary reads, never FOR UPDATE
            self._verifier._require_open()
            result = transition(db)
            self._verifier._require_open()
            commit_started = True
            db.commit()
        except BaseException as caught:
            error = caught
            try:
                db.rollback()
            except BaseException:
                # Cleanup cancellation/failure leaves the outcome unconfirmed.
                commit_started = True
        finally:
            try:
                db.close()
            except BaseException as caught:
                # Even an earlier ordinary refusal cannot confirm failed cleanup.
                if error is None:
                    error = caught
                commit_started = True
        if error is not None:
            if commit_started:
                raise CompositionIncomplete()
            raise error
        if result is None:
            raise CompositionIncomplete()
        # Never call clocks after confirmed commit and claim it did not happen.
        return result

    def issue(self, command: RehearsalIssuerCommand) -> PhaseResult:
        from dotmac_deployment_control import RehearsalIssuerAuthorizationV1

        if type(command) is not RehearsalIssuerCommand:
            raise CompositionRefused()
        command = RehearsalIssuerCommand(
            command.command_id, command.plan_id, command.actor_ref
        )
        expected = self._admit("issue", command.plan_id)
        self._preflight(expected, None)
        evidence_digest = self._proof(expected)
        retained = self._verifier._evidence(evidence_digest)
        evidence = _strict_json(retained.owner_envelope, 128 * 1024)
        invocation = RehearsalIssuerInvocation(command, evidence)

        def transition(db: Session) -> PhaseResult:
            result = issue_authorization(db, invocation)
            if not isinstance(result, RehearsalIssuerAuthorizationV1):
                raise CompositionRefused()
            detached = authorization_binding(_canonical(result.as_mapping()))
            self._check_plan(db, expected, detached)
            return PhaseResult(
                evidence_digest,
                detached.parsed.statement.authorization_id,
                detached.parsed.statement.lease_id,
                detached.encoded,
            )

        return self._mutate(expected, None, transition)

    def consume(self, plan_id: UUID, authorization_document: bytes) -> PhaseResult:
        from dotmac_deployment_control import RehearsalIssuerConsumptionStaged

        binding = authorization_binding(authorization_document)
        expected = self._admit("consume", plan_id)
        self._preflight(expected, binding)
        evidence_digest = self._proof(expected)
        retained = self._verifier._evidence(evidence_digest)
        parsed_evidence = _strict_json(retained.owner_bytes, 8192)
        if not isinstance(parsed_evidence, dict) or not isinstance(
            parsed_evidence.get("issued_at"), str
        ):
            raise CompositionRefused()
        from datetime import datetime

        if (
            datetime.fromisoformat(parsed_evidence["issued_at"])
            <= binding.parsed.statement.issued_at
        ):
            raise CompositionRefused()
        evidence = _strict_json(retained.owner_envelope, 128 * 1024)

        def transition(db: Session) -> PhaseResult:
            result = consume_authorization(
                db,
                plan_id=plan_id,
                authorization_document=binding.parsed.as_mapping(),
                harness_evidence_document=evidence,
            )
            if not isinstance(result, RehearsalIssuerConsumptionStaged):
                raise CompositionRefused()
            return PhaseResult(
                evidence_digest,
                result.authorization_id,
                result.lease_id,
                single_use_reference=result.single_use_reference,
            )

        return self._mutate(expected, binding, transition)

    def standing(
        self, authorization_document: bytes, evidence_digest: str
    ) -> RehearsalIssuerAuthorizationStandingResult:
        from dotmac_deployment_control import rehearsal_issuer_standing_for

        binding = authorization_binding(authorization_document)
        retained = self._verifier._evidence(evidence_digest)
        phase = retained.context.phase
        if phase not in ("issue", "consume"):
            raise CompositionRefused()
        expected = self._admit(
            "issue" if phase == "issue" else "consume", UUID(retained.context.plan_id)
        )
        actual = {
            key: value
            for key, value in asdict(retained.context).items()
            if key not in {"challenge_digest", "proof_transcript_digest"}
        }
        if actual != asdict(expected.operation):
            raise CompositionRefused()
        self._preflight(expected, binding)  # closed BEFORE fresh standing session
        db = self._sessions()
        try:
            self._verifier._require_open()
            return rehearsal_issuer_standing_for(
                db,
                authorization_document=binding.parsed.as_mapping(),
                harness_evidence_document=_strict_json(
                    retained.owner_envelope, 128 * 1024
                ),
            )
        finally:
            db.close()


def assemble_gate0_composition(
    *,
    sessions: Callable[[], Session],
    admission: AdmissionPort | None,
    proof_resolver: ProofResolver | None,
    verifier: BoundedHarnessVerifier,
    signer: RehearsalIssuerAuthorizationSigner | None,
    authorization_verifier: RehearsalIssuerAuthorizationVerifier | None,
    authorization_ttl: timedelta,
) -> Gate0Composition:
    """Trusted startup only; no default custody/admission/transport or reinstall."""
    from dotmac_deployment_control import install_rehearsal_issuer_security

    if (
        admission is None
        or proof_resolver is None
        or signer is None
        or authorization_verifier is None
    ):
        raise CompositionRefused()
    verifier._require_open()
    if (
        not isinstance(authorization_ttl, timedelta)
        or not 0 < authorization_ttl.total_seconds() <= 600
        or authorization_ttl.total_seconds()
        > (verifier._expires - verifier._now()).total_seconds()
    ):
        raise CompositionRefused()
    install_rehearsal_issuer_security(
        signer=signer,
        authorization_verifier=authorization_verifier,
        harness_verifier=verifier,
        authorization_ttl=authorization_ttl,
    )
    return Gate0Composition(
        sessions=sessions,
        admission=admission,
        proof_resolver=proof_resolver,
        verifier=verifier,
    )
