"""CP's adopted frozen-spec window, held through existing owner boundaries.

No database/bootstrap, target, policy or plan-input producer is selected here.
NS3 receives approved-at-start public data; only IDP3 rechecks current approval.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal, TypedDict, cast
from uuid import UUID

from sqlalchemy import text

from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    AuthorizationBinding,
    WindowFreshness,
    authorization_binding,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused, json_record
from vendor_cp.deployment.gate0_runtime import AdmittedOperation, _ssh_fingerprint

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        PlanView,
        RehearsalIssuerAuthorizationSignerIdentity,
        RehearsalIssuerAuthorizationStatementV1,
        RehearsalIssuerAuthorizationVerifier,
        TargetView,
    )
    from dotmac_kernel.session_runtime import DatabaseRuntime
    from sqlalchemy.orm import Session

    from vendor_cp.approvals.adapter import HeldPlatformApproval
    from vendor_cp.deployment.gate0_composition import RequestAuthenticationFreshness

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class WindowPolicy(TypedDict):
    code: str
    version: int


class WindowController(TypedDict):
    lease_id: str
    fingerprint: str
    certificate_digest: str
    ca_fingerprint: str
    principal: str
    certificate_ttl_ceiling_seconds: int


class WindowDocument(TypedDict):
    schema: str
    window_id: str
    case_kind: Literal["consume_replay", "withdrawal_later_use"]
    not_before: str
    expires_at: str
    purpose: str
    allowed_phases: list[str]
    github: dict[str, str]
    target: dict[str, str]
    approval_policy: WindowPolicy
    plan_inputs: dict[str, str]
    controller: WindowController
    prerequisite_evidence_refs: list[str]
    authorization_binding: str


def _fields(value: object, names: str) -> None:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ProviderRefused()


def _text(value: object) -> str:
    if type(value) is not str or not 0 < len(value) <= 512 or value != value.strip():
        raise ProviderRefused()
    return value


def _instant(value: object) -> datetime:
    value = _text(value)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if (
        parsed.tzinfo is None
        or parsed.astimezone(UTC).isoformat().replace("+00:00", "Z") != value
    ):
        raise ProviderRefused()
    return parsed


@dataclass(frozen=True, slots=True)
class FrozenIssuerWindow:
    """Only validated canonical bytes persist; document reads detach all values."""

    canonical_bytes: bytes

    @classmethod
    def parse(cls, raw: bytes) -> FrozenIssuerWindow:
        failed = False
        try:
            from vendor_cp.deployment.gate0_workload_admission import _FIXED_CLAIMS

            value = cast(WindowDocument, strict_object(raw, 32768))
            if canonical(value) != raw:
                raise ProviderRefused()
            _fields(
                value,
                "schema window_id case_kind not_before expires_at purpose "
                "allowed_phases github "
                "target approval_policy plan_inputs controller "
                "prerequisite_evidence_refs authorization_binding",
            )
            if (
                value["schema"] != "Gate0IssuerWindow.v1"
                or type(value["case_kind"]) is not str
                or value["case_kind"] not in ("consume_replay", "withdrawal_later_use")
                or value["purpose"] != "rehearsal_issuer_operation"
                or value["allowed_phases"] != ["issue", "consume"]
                or value["authorization_binding"] != "control_parsed_full_envelope_v1"
            ):
                raise ProviderRefused()
            _text(value["window_id"])
            if (
                not 0
                < (
                    _instant(value["expires_at"]) - _instant(value["not_before"])
                ).total_seconds()
                <= 300
            ):
                raise ProviderRefused()
            github = value["github"]
            _fields(
                github,
                " ".join(_FIXED_CLAIMS)
                + " run_id run_attempt sub workflow_sha environment_node_id",
            )
            if any(github[key] != expected for key, expected in _FIXED_CLAIMS.items()):
                raise ProviderRefused()
            for key in ("run_id", "run_attempt"):
                if (
                    type(github[key]) is not str
                    or re.fullmatch(r"[1-9][0-9]{0,19}", github[key]) is None
                ):
                    raise ProviderRefused()
            _text(github["sub"])
            _text(github["environment_node_id"])
            if (
                type(github["workflow_sha"]) is not str
                or re.fullmatch(r"[0-9a-f]{40}", github["workflow_sha"]) is None
            ):
                raise ProviderRefused()
            target = value["target"]
            _fields(target, "id ref environment operation")
            if (
                str(UUID(target["id"])) != target["id"]
                or target["environment"] != "rehearsal"
                or target["operation"] != "deploy"
            ):
                raise ProviderRefused()
            _text(target["ref"])
            policy = value["approval_policy"]
            _fields(policy, "code version")
            _text(policy["code"])
            if type(policy["version"]) is not int or policy["version"] < 1:
                raise ProviderRefused()
            inputs = value["plan_inputs"]
            _fields(
                inputs, "source_ref config_ref descriptor_digest execution_plan_digest"
            )
            for key in ("source_ref", "config_ref"):
                _text(inputs[key])
                if "://" in inputs[key]:
                    raise ProviderRefused()
            for key in ("descriptor_digest", "execution_plan_digest"):
                if (
                    type(inputs[key]) is not str
                    or _DIGEST.fullmatch(inputs[key]) is None
                ):
                    raise ProviderRefused()
            controller = value["controller"]
            _fields(
                controller,
                "lease_id fingerprint certificate_digest ca_fingerprint principal "
                "certificate_ttl_ceiling_seconds",
            )
            _text(controller["lease_id"])
            if (
                not _ssh_fingerprint(controller["fingerprint"])
                or not _ssh_fingerprint(controller["ca_fingerprint"])
                or type(controller["certificate_digest"]) is not str
                or _DIGEST.fullmatch(controller["certificate_digest"]) is None
                or controller["principal"] != "dotmac-gate0-controller"
                or type(controller["certificate_ttl_ceiling_seconds"]) is not int
                or controller["certificate_ttl_ceiling_seconds"] != 600
            ):
                raise ProviderRefused()
            evidence = value["prerequisite_evidence_refs"]
            if (
                type(evidence) is not list
                or not 1 <= len(evidence) <= 16
                or any(
                    type(item) is not str or _DIGEST.fullmatch(item) is None
                    for item in evidence
                )
                or len(set(evidence)) != len(evidence)
            ):
                raise ProviderRefused()
        except Exception:
            failed = True
        if failed:
            raise ProviderRefused()
        return cls(raw)

    @property
    def document(self) -> WindowDocument:
        # parse() established the closed schema before retaining canonical bytes.
        return cast(WindowDocument, strict_object(self.canonical_bytes, 32768))

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def from_plan(cls, plan: PlanView) -> FrozenIssuerWindow:
        # Public frozen owner snapshot, never the target's mutable desired_spec.
        spec = json_record(plan.snapshot["spec"])
        return cls.parse(canonical(spec["gate0_window_v1"]))

    def check_plan(self, plan: PlanView, target: TargetView) -> None:
        document = self.document
        declared = document["target"]
        policy = document["approval_policy"]
        inputs = document["plan_inputs"]
        if (
            plan.target_id != target.id
            or str(target.id) != declared["id"]
            or target.target_ref != declared["ref"]
            or target.environment != declared["environment"]
            or plan.purpose != document["purpose"]
            or plan.operation != declared["operation"]
            or plan.descriptor_digest != inputs["descriptor_digest"]
            or plan.execution_plan_digest != inputs["execution_plan_digest"]
            or plan.approval_policy_code != policy["code"]
            or plan.approval_policy_version != policy["version"]
            or plan.requires_approval is not True
            or not plan.approval_decision_ref
            or plan.snapshot["plan_purpose"] != document["purpose"]
            or plan.snapshot["target_ref"] != declared["ref"]
            or plan.snapshot["environment"] != declared["environment"]
        ):
            raise ProviderRefused()
        if (
            not _instant(document["not_before"])
            <= datetime.now(UTC)
            < _instant(document["expires_at"])
        ):
            raise ProviderRefused()

    def check_authorization_times(
        self, statement: RehearsalIssuerAuthorizationStatementV1
    ) -> None:
        document = self.document
        if not _instant(
            document["not_before"]
        ) <= statement.not_before <= statement.issued_at <= datetime.now(
            UTC
        ) or statement.expires_at > _instant(document["expires_at"]):
            raise ProviderRefused()

    def expectation(
        self,
        plan: PlanView,
        target: TargetView,
        phase: Literal["issue", "consume"],
        binding: AuthorizationBinding | None = None,
        *,
        freshness: WindowFreshness | None = None,
    ) -> AdmissionExpectation:
        self.check_plan(plan, target)
        if phase not in ("issue", "consume") or (phase == "consume") != (
            binding is not None
        ):
            raise ProviderRefused()
        if (
            plan.plan_digest is None
            or plan.execution_plan_digest is None
            or plan.operation is None
            or plan.approval_decision_ref is None
            or plan.approval_policy_code is None
            or plan.approval_policy_version is None
        ):
            raise ProviderRefused()
        document = self.document
        github, controller = document["github"], document["controller"]
        operation = AdmittedOperation(
            github["repository_id"],
            github["run_id"],
            github["run_attempt"],
            document["window_id"],
            phase,
            None if binding is None else binding.digest,
            None if binding is None else binding.issued_at,
            controller["lease_id"],
            controller["fingerprint"],
            target.target_ref,
            str(plan.id),
            plan.plan_digest,
            plan.purpose,
            plan.operation,
            plan.execution_plan_digest,
            controller["certificate_digest"],
            controller["ca_fingerprint"],
        )
        return AdmissionExpectation(
            operation,
            target.id,
            target.environment,
            UUID(plan.approval_decision_ref),
            plan.approval_policy_code,
            plan.approval_policy_version,
            self.canonical_bytes,
            self.digest,
            freshness,
        )


@dataclass(frozen=True, slots=True)
class ApprovedWindowBinding:
    """Public immutable terms produced while CP holds the actual approval.

    NS3 delivery must authenticate this binding independently of the runner.
    It says approved at capture, never that approval still stands at NS3.
    """

    expectation: AdmissionExpectation
    window: FrozenIssuerWindow
    descriptor_digest: str
    authorized_image_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.expectation) is not AdmissionExpectation
            or type(self.window) is not FrozenIssuerWindow
        ):
            raise ProviderRefused()
        if self.expectation.frozen_window_bytes is None:
            raise ProviderRefused()
        window = FrozenIssuerWindow.parse(self.expectation.frozen_window_bytes)
        document = window.document
        op = self.expectation.operation
        github, controller, target = (
            document["github"],
            document["controller"],
            document["target"],
        )
        if (
            window != self.window
            or window.digest != self.expectation.window_digest
            or self.descriptor_digest != document["plan_inputs"]["descriptor_digest"]
            or type(self.authorized_image_digests) is not tuple
            or any(
                type(item) is not str or _DIGEST.fullmatch(item) is None
                for item in self.authorized_image_digests
            )
            or str(self.expectation.target_id) != target["id"]
            or op.target_ref != target["ref"]
            or (op.repository_id, op.run_id, op.run_attempt)
            != (github["repository_id"], github["run_id"], github["run_attempt"])
            or op.window_id != document["window_id"]
            or op.lease_id != controller["lease_id"]
            or op.controller_fingerprint != controller["fingerprint"]
            or op.certificate_digest != controller["certificate_digest"]
            or op.ca_fingerprint != controller["ca_fingerprint"]
            or op.execution_plan_digest
            != document["plan_inputs"]["execution_plan_digest"]
            or self.expectation.approval_policy_code
            != document["approval_policy"]["code"]
            or self.expectation.approval_policy_version
            != document["approval_policy"]["version"]
        ):
            raise ProviderRefused()


def derive_consume_expectation(
    binding: ApprovedWindowBinding,
    actual_document: bytes,
    issuer_identity: RehearsalIssuerAuthorizationSignerIdentity,
    authorization_verifier: RehearsalIssuerAuthorizationVerifier,
) -> AdmissionExpectation:
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSubject,
        verify_rehearsal_issuer_authorization,
    )

    if (
        type(binding) is not ApprovedWindowBinding
        or binding.expectation.operation.phase != "issue"
    ):
        raise ProviderRefused()
    expected = binding.expectation
    op = expected.operation
    actual = authorization_binding(actual_document)
    subject = RehearsalIssuerAuthorizationSubject(
        immutable_reference=op.plan_id,
        target_id=str(expected.target_id),
        target_ref=op.target_ref,
        desired_state_digest=op.plan_digest,
        profile_digest=binding.descriptor_digest,
        authorized_image_digests=binding.authorized_image_digests,
        execution_plan_digest=op.execution_plan_digest,
        controller_fingerprint=op.controller_fingerprint,
        environment=expected.environment,
        signer_public_key_fingerprint=issuer_identity.public_key_fingerprint,
        lease_id=op.lease_id,
    )
    verified = verify_rehearsal_issuer_authorization(
        actual.parsed.as_mapping(),
        verifier=authorization_verifier,
        subject=subject,
        at=datetime.now(UTC),
    )
    binding.window.check_authorization_times(verified.statement)
    return replace(
        expected,
        operation=replace(
            op,
            phase="consume",
            authorization_digest=actual.digest,
            authorization_issued_at=actual.issued_at,
        ),
    )


@dataclass(frozen=True, slots=True)
class WindowClockOrigin:
    """Trusted local launch clocks; never portable window/capture authority."""

    started_at: datetime
    monotonic_origin: float
    deadline: float

    def __post_init__(self) -> None:
        if (
            type(self.started_at) is not datetime
            or self.started_at.tzinfo is None
            or self.started_at.utcoffset() != timedelta(0)
            or self.started_at > datetime.now(UTC)
            or any(
                type(value) not in (int, float) or not math.isfinite(value)
                for value in (self.monotonic_origin, self.deadline)
            )
            or not 0 <= self.monotonic_origin <= time.monotonic() < self.deadline
            or not 0 < self.deadline - self.monotonic_origin <= 300
        ):
            raise ProviderRefused()


class OwnerWindowWithdrawal(ProviderRefused):
    """Detached exact owner denial after confirmed read-transaction cleanup.

    This carries no approved binding. Only the fixed JWT admission provider
    may classify it as an authenticated attempted use.
    """

    def __init__(
        self,
        *,
        window: FrozenIssuerWindow,
        plan_id: UUID,
        request_id: UUID,
        content_digest: str,
        phase: Literal["issue", "consume"],
        freshness: WindowFreshness,
    ) -> None:
        ValueError.__init__(self, "gate0_owner_window_withdrawn")
        self.window, self.plan_id, self.request_id = window, plan_id, request_id
        self.content_digest, self.phase, self.freshness = (
            content_digest,
            phase,
            freshness,
        )


class AuthenticatedApprovalWithdrawal(ProviderRefused):
    """Fixed provider verified JWT and exact original denial coordinates.

    Trusted source contract, not an unforgeable Python capability or grant.
    """

    def __init__(
        self,
        denial: OwnerWindowWithdrawal,
        *,
        authentication_freshness: RequestAuthenticationFreshness | None = None,
    ) -> None:
        ValueError.__init__(self, "gate0_authenticated_approval_withdrawn")
        self.denial = denial
        self.authentication_freshness = authentication_freshness


class OwnerWindowReader:
    """Current public Control snapshot plus the existing exact-content hold.

    Actual kernel runtime connect/pool bounds are an installation obligation.
    Native PostgreSQL query/lock timeouts and the service watchdog cover reads;
    no arbitrary callback is advertised as a bounded database transport.
    No session, approval lock, cached grant or mutable authorization survives read.
    """

    def __init__(
        self,
        *,
        runtime: DatabaseRuntime | None = None,
        issuer_identity: RehearsalIssuerAuthorizationSignerIdentity | None = None,
        authorization_verifier: RehearsalIssuerAuthorizationVerifier | None = None,
        expires_at: datetime | None = None,
        database_io_qualified: bool = False,
        rehearsal_target_id: UUID | None = None,
        clock_origin: WindowClockOrigin | None = None,
    ) -> None:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        if (
            type(runtime) is not DatabaseRuntime
            or type(rehearsal_target_id) is not UUID
            or database_io_qualified is not True
            or issuer_identity is None
            or authorization_verifier is None
            or expires_at is None
            or expires_at.tzinfo is None
            or not 0 < (expires_at - datetime.now(UTC)).total_seconds() <= 300
        ):
            raise ProviderRefused()
        self._runtime, self._identity, self._verifier = (
            runtime,
            issuer_identity,
            authorization_verifier,
        )
        self._target_id = rehearsal_target_id
        if clock_origin is not None:
            if type(clock_origin) is not WindowClockOrigin:
                raise ProviderRefused()
            clock_origin.__post_init__()
            if not 0 < (expires_at - clock_origin.started_at).total_seconds() <= 300:
                raise ProviderRefused()
            self._started, self._origin = (
                clock_origin.started_at,
                clock_origin.monotonic_origin,
            )
        else:
            self._started, self._origin = datetime.now(UTC), time.monotonic()
        self._expires = expires_at
        self._deadline = self._origin + (expires_at - self._started).total_seconds()
        if clock_origin is not None:
            self._deadline = min(self._deadline, clock_origin.deadline)
        self._freshness: dict[tuple[UUID, str], WindowFreshness] = {}

    def _open(self) -> None:
        if not (
            self._origin <= time.monotonic() < self._deadline
            and self._started <= datetime.now(UTC) < self._expires
        ):
            raise ProviderRefused()

    def read(
        self,
        phase: Literal["issue", "consume"],
        plan_id: UUID,
        authorization_document: bytes | None = None,
    ) -> ApprovedWindowBinding:
        from dotmac_deployment_control import get_plan, get_target

        from vendor_cp.approvals.adapter import (
            ApprovalHoldRefusal,
            ApprovalNotHeld,
            request_identity_evidence,
        )
        from vendor_cp.deployment.approval_barrier import held_transition
        from vendor_cp.deployment.protected_rehearsal_issuer import (
            SUBJECT_TYPE,
            issuer_approval_subject,
        )

        self._open()
        if (
            type(plan_id) is not UUID
            or phase not in ("issue", "consume")
            or (phase == "consume") != (authorization_document is not None)
        ):
            raise ProviderRefused()
        failed = False
        db: Session | None = None
        result: ApprovedWindowBinding | None = None
        window_deadline = 0.0
        denial: OwnerWindowWithdrawal | None = None
        try:
            db = self._runtime.platform_session_factory()
            if db.get_bind().dialect.name != "postgresql":
                raise ProviderRefused()
            milliseconds = max(
                1, min(2000, int((self._deadline - time.monotonic()) * 1000))
            )
            for setting in ("statement_timeout", "lock_timeout"):
                db.execute(
                    text("SELECT set_config(:setting, :duration, true)"),
                    {"setting": setting, "duration": str(milliseconds)},
                )
            plan = get_plan(db, plan_id)
            if plan is None or plan.target_id != self._target_id:
                raise ProviderRefused()
            target = get_target(db, plan.target_id)
            if target is None:
                raise ProviderRefused()
            window = FrozenIssuerWindow.from_plan(plan)
            window.check_plan(plan, target)
            coordinate = (plan_id, window.digest)
            freshness = self._freshness.get(coordinate)
            if freshness is None:
                if len(self._freshness) >= 4:
                    raise ProviderRefused()
                mapped_deadline = (
                    self._origin
                    + (
                        _instant(window.document["expires_at"]) - self._started
                    ).total_seconds()
                )
                freshness = WindowFreshness(
                    self._origin, min(self._deadline, mapped_deadline)
                )
                self._freshness[coordinate] = freshness
            freshness.require_open()
            window_deadline = freshness.deadline
            if time.monotonic() >= window_deadline:
                raise ProviderRefused()

            session = db

            def checked(_held: HeldPlatformApproval) -> ApprovedWindowBinding:
                current = get_plan(session, plan_id)
                if (
                    current is None
                    or current.plan_digest != plan.plan_digest
                    or current.approval_decision_ref != plan.approval_decision_ref
                ):
                    raise ProviderRefused()
                reread = FrozenIssuerWindow.from_plan(current)
                if reread.canonical_bytes != window.canonical_bytes:
                    raise ProviderRefused()
                reread.check_plan(current, target)
                if (
                    current.authorized_images is None
                    or current.descriptor_digest is None
                ):
                    raise ProviderRefused()
                captured = ApprovedWindowBinding(
                    window.expectation(current, target, "issue", freshness=freshness),
                    window,
                    current.descriptor_digest,
                    tuple(
                        image.digest.canonical for image in current.authorized_images
                    ),
                )
                if phase == "consume":
                    if authorization_document is None:
                        raise ProviderRefused()
                    captured = replace(
                        captured,
                        expectation=derive_consume_expectation(
                            captured,
                            authorization_document,
                            self._identity,
                            self._verifier,
                        ),
                    )
                return captured

            if plan.approval_decision_ref is None or plan.plan_digest is None:
                raise ProviderRefused()
            try:
                result = held_transition(
                    db,
                    request_id=UUID(plan.approval_decision_ref),
                    subject_type=SUBJECT_TYPE,
                    subject_id=issuer_approval_subject(plan),
                    content_digest=plan.plan_digest,
                    transition=checked,
                )
            except ApprovalNotHeld as caught:
                if caught.code is not ApprovalHoldRefusal.WITHDRAWN:
                    raise
                identity = request_identity_evidence(
                    db, UUID(plan.approval_decision_ref)
                )
                if (
                    identity.subject_type != SUBJECT_TYPE
                    or identity.subject_id != issuer_approval_subject(plan)
                    or identity.content_digest != plan.plan_digest
                    or identity.policy_code != plan.approval_policy_code
                    or identity.policy_version != plan.approval_policy_version
                ):
                    raise ProviderRefused() from None
                denial = OwnerWindowWithdrawal(
                    window=window,
                    plan_id=plan_id,
                    request_id=UUID(plan.approval_decision_ref),
                    content_digest=plan.plan_digest,
                    phase=phase,
                    freshness=freshness,
                )
            self._open()
            if time.monotonic() >= window_deadline:
                raise ProviderRefused()
        except Exception:
            failed = True
        finally:
            if db is not None:
                try:
                    # No mutation is made here; explicitly confirm rollback and
                    # close before any owner denial can become evidence.
                    db.rollback()
                except BaseException:
                    failed = True
                try:
                    db.close()
                except BaseException:
                    failed = True
        if failed:
            raise ProviderRefused()
        self._open()
        if denial is not None:
            denial.freshness.require_open()
            raise denial
        if result is None or time.monotonic() >= window_deadline:
            raise ProviderRefused()
        return result
