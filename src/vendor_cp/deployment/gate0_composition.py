"""Thin, non-authorizing phase composition over published Control/Approvals.

No admission oracle, custody loader, transport, controller-session observer or
E receipt finalizer is implemented here. All production ports are explicit;
unconfigured ports refuse. Fixture admission never becomes protected evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import TYPE_CHECKING, Literal, Protocol, cast
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
class WindowFreshness:
    """Original process-local clock mapping; never a wire/JSON authority term."""

    origin: float
    deadline: float

    def __post_init__(self) -> None:
        if not (
            math.isfinite(self.origin)
            and math.isfinite(self.deadline)
            and 0 < self.deadline - self.origin <= 300
        ):
            raise CompositionRefused()

    def require_open(self) -> None:
        if not self.origin <= monotonic() < self.deadline:
            raise CompositionRefused()


@dataclass(frozen=True, slots=True)
class RequestAuthenticationFreshness:
    """Per-request JWT/window intersection; never replaces retained window freshness."""

    origin: float
    deadline: float
    expires_at: datetime

    def __post_init__(self) -> None:
        WindowFreshness(self.origin, self.deadline)
        if type(self.expires_at) is not datetime or self.expires_at.tzinfo is None:
            raise CompositionRefused()

    def require_open(self) -> None:
        if (
            not self.origin <= monotonic() < self.deadline
            or datetime.now(UTC) >= self.expires_at
        ):
            raise CompositionRefused()


@dataclass(frozen=True, slots=True)
class AdmissionExpectation:
    """Facts supplied by an independent authenticated admission boundary.

    The dataclass validates shape only. It is not a GitHub/approval oracle.
    Production terms come from the frozen owner window and exact approval hold.
    Optional unbound values serve only explicitly synthetic mechanism tests.
    """

    operation: AdmittedOperation
    target_id: UUID
    environment: str
    approval_request_id: UUID
    approval_policy_code: str
    approval_policy_version: int
    frozen_window_bytes: bytes | None = None
    window_digest: str | None = None
    window_freshness: WindowFreshness | None = None
    authentication_freshness: RequestAuthenticationFreshness | None = None

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
        if (
            self.window_freshness is not None
            and type(self.window_freshness) is not WindowFreshness
        ):
            raise CompositionRefused()
        if (
            self.authentication_freshness is not None
            and type(self.authentication_freshness)
            is not RequestAuthenticationFreshness
        ):
            raise CompositionRefused()
        if (self.frozen_window_bytes is None) != (self.window_digest is None):
            raise CompositionRefused()
        if self.frozen_window_bytes is not None:
            if (
                type(self.frozen_window_bytes) is not bytes
                or not 0 < len(self.frozen_window_bytes) <= 32768
                or self.window_digest
                != "sha256:" + hashlib.sha256(self.frozen_window_bytes).hexdigest()
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
    issuer_receipt: bytes | None = None

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
        require_frozen_window: bool = False,
    ) -> None:
        self._require_frozen_window = require_frozen_window
        self._sessions = sessions
        self._admission, self._resolver, self._verifier = (
            admission,
            proof_resolver,
            verifier,
        )

    def _admit(
        self, phase: Literal["issue", "consume"], plan_id: UUID
    ) -> AdmissionExpectation:
        from vendor_cp.deployment.gate0_window import AuthenticatedApprovalWithdrawal

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
                result.frozen_window_bytes,
                result.window_digest,
                result.window_freshness,
                result.authentication_freshness,
            )
            if result.operation.phase != phase or result.operation.plan_id != str(
                plan_id
            ):
                raise CompositionRefused()
            self._verifier._require_open()
            return result
        except AuthenticatedApprovalWithdrawal as caught:
            if caught.denial.plan_id != plan_id or caught.denial.phase != phase:
                raise CompositionRefused() from None
            self._verifier._require_open()
            caught.denial.freshness.require_open()
            if caught.authentication_freshness is not None:
                caught.authentication_freshness.require_open()
            raise
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
        if self._require_frozen_window or expected.frozen_window_bytes is not None:
            from vendor_cp.deployment.gate0_window import FrozenIssuerWindow

            if (
                expected.frozen_window_bytes is None
                or expected.window_digest is None
                or expected.window_freshness is None
            ):
                raise CompositionRefused()
            expected.window_freshness.require_open()
            window = FrozenIssuerWindow.from_plan(plan)
            if (
                window.canonical_bytes != expected.frozen_window_bytes
                or window.digest != expected.window_digest
            ):
                raise CompositionRefused()
            rederived = window.expectation(
                plan,
                target,
                cast(Literal["issue", "consume"], operation.phase),
                binding if operation.phase == "consume" else None,
                freshness=expected.window_freshness,
            )
            rederived = replace(
                rederived, authentication_freshness=expected.authentication_freshness
            )
            if rederived != expected:
                raise CompositionRefused()
            if binding is not None:
                window.check_authorization_times(binding.parsed.statement)
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
                expected.frozen_window_bytes,
                expected.window_digest,
                expected.window_freshness,
                expected.authentication_freshness,
            )
            self._require_window_open(expected)
            proof = self._resolver(resolver_input)
            self._require_window_open(expected)
            # Resolver must bound its wire response before constructing a value;
            # registration also checks all retained/decoded source format bounds.
            registered = self._verifier._register(proof, expected.operation)
            self._require_window_open(expected)
            return registered
        except Exception:
            failed = True
        if failed:
            raise CompositionRefused()
        raise CompositionRefused()

    def _require_window_open(self, expected: AdmissionExpectation) -> None:
        if expected.authentication_freshness is not None:
            expected.authentication_freshness.require_open()
        if self._require_frozen_window or expected.frozen_window_bytes is not None:
            if expected.window_freshness is None:
                raise CompositionRefused()
            expected.window_freshness.require_open()

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
            self._require_window_open(expected)
            result = transition(db)
            if self._require_frozen_window or expected.frozen_window_bytes is not None:
                self._check_plan(db, expected, binding)
            self._verifier._require_open()
            self._require_window_open(expected)
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
        # Expiry after confirmed commit cannot become a claimed rollback/refusal.
        try:
            self._require_window_open(expected)
        except Exception:
            raise CompositionIncomplete() from None
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

        committed = self._mutate(expected, None, transition)
        return self._issue_receipt(invocation, expected, committed)

    def _issue_receipt(
        self,
        invocation: RehearsalIssuerInvocation,
        expected: AdmissionExpectation,
        committed: PhaseResult,
    ) -> PhaseResult:
        command = invocation.command
        evidence = invocation.harness_evidence_document
        # A new read transaction observes the committed owner receipt. A failed
        # read/cleanup cannot undo issuance and must remain incomplete.
        from vendor_cp.deployment.issuer_receipts import (
            ISSUE_AUTHORIZATION,
            find_receipt,
            request_fingerprint,
        )

        fingerprint = request_fingerprint(
            ISSUE_AUTHORIZATION,
            {
                **dict(invocation.to_control_request()),
                "harness_evidence_digest": "sha256:"
                + hashlib.sha256(_canonical(evidence)).hexdigest(),
            },
        )
        db: Session | None = None
        receipt_bytes: bytes | None = None
        failed = False
        try:
            db = self._sessions()
            receipt = find_receipt(db, command.command_id)
            if (
                receipt is None
                or receipt.verb != ISSUE_AUTHORIZATION
                or receipt.request_fingerprint != fingerprint
                or receipt.plan_id != command.plan_id
                or receipt.approval_request_id != expected.approval_request_id
                or receipt.control_ref != committed.authorization_id
            ):
                raise CompositionIncomplete()
            receipt_bytes = _canonical(
                {
                    "id": str(receipt.id),
                    "command_id": receipt.command_id,
                    "verb": receipt.verb,
                    "request_fingerprint": receipt.request_fingerprint,
                    "plan_id": str(receipt.plan_id),
                    "approval_request_id": str(receipt.approval_request_id),
                    "control_ref": receipt.control_ref,
                    "recorded_at": receipt.recorded_at.isoformat(),
                }
            )
        except BaseException:
            failed = True
        finally:
            if db is not None:
                try:
                    db.rollback()
                except BaseException:
                    failed = True
                try:
                    db.close()
                except BaseException:
                    failed = True
        if failed or receipt_bytes is None:
            raise CompositionIncomplete()
        try:
            self._require_window_open(expected)
        except Exception:
            raise CompositionIncomplete() from None
        return replace(committed, issuer_receipt=receipt_bytes)

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
        result = None
        failed = False
        try:
            self._verifier._require_open()
            self._require_window_open(expected)
            result = rehearsal_issuer_standing_for(
                db,
                authorization_document=binding.parsed.as_mapping(),
                harness_evidence_document=_strict_json(
                    retained.owner_envelope, 128 * 1024
                ),
            )
        except BaseException:
            failed = True
        finally:
            try:
                db.rollback()
            except BaseException:
                failed = True
            try:
                db.close()
            except BaseException:
                failed = True
        if failed or result is None:
            raise CompositionRefused()
        self._require_window_open(expected)
        return result


def assemble_gate0_composition(
    *,
    sessions: Callable[[], Session],
    admission: AdmissionPort | None,
    proof_resolver: ProofResolver | None,
    verifier: BoundedHarnessVerifier,
    signer: RehearsalIssuerAuthorizationSigner | None,
    authorization_verifier: RehearsalIssuerAuthorizationVerifier | None,
    authorization_ttl: timedelta,
    require_frozen_window: bool = False,
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
        require_frozen_window=require_frozen_window,
    )
