"""Private retention-independent E collection; never an acceptance authority.

Only fixed installed service outcomes enter this codec. Source tests and raw
reports cannot supply protected admission, root cleanup or publication policy.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID

from vendor_cp.deployment.gate0_framing import (
    FramedChannel,
    ServiceRefused,
    canonical,
    strict_object,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSignerIdentity,
        RehearsalIssuerAuthorizationStanding,
        RehearsalIssuerAuthorizationVerifier,
    )
    from sqlalchemy.orm import Session

    from vendor_cp.deployment.gate0_composition import AdmissionExpectation
    from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier
    from vendor_cp.deployment.gate0_window import ApprovedWindowBinding


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class OutcomeKind(StrEnum):
    ISSUE_COMMITTED = "issue_committed"
    CONSUME_COMMITTED = "consume_committed"
    STANDING = "standing"
    OWNER_REFUSED = "owner_refused"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class IssuerOutcome:
    """Detached fixed-service result, never assertions supplied by a caller."""

    ordinal: int
    operation: Literal["issue", "consume", "standing"]
    request_digest: str
    window_digest: str | None
    proof_digest: str | None
    bundle_digest: str | None
    kind: OutcomeKind
    owner_namespace: str | None
    owner_code: str | None
    result_bytes: bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": "Gate0IssuerOutcome.v1",
            "ordinal": self.ordinal,
            "operation": self.operation,
            "request_digest": self.request_digest,
            "window_digest": self.window_digest,
            "proof_digest": self.proof_digest,
            "bundle_digest": self.bundle_digest,
            "kind": self.kind.value,
            "owner_namespace": self.owner_namespace,
            "owner_code": self.owner_code,
            "result": strict_object(self.result_bytes, 192 * 1024),
            "readiness_accepted": False,
        }

    @classmethod
    def parse(cls, document: object) -> IssuerOutcome:
        try:
            return cls._parse(document)
        except Exception:
            raise ServiceRefused() from None

    @classmethod
    def _parse(cls, document: object) -> IssuerOutcome:
        if type(document) is not dict or set(document) != {
            "schema",
            "ordinal",
            "operation",
            "request_digest",
            "window_digest",
            "proof_digest",
            "bundle_digest",
            "kind",
            "owner_namespace",
            "owner_code",
            "result",
            "readiness_accepted",
        }:
            raise ServiceRefused()
        value = strict_object(canonical(document))
        if (
            value["schema"] != "Gate0IssuerOutcome.v1"
            or value["readiness_accepted"] is not False
            or type(value["ordinal"]) is not int
            or not 1 <= value["ordinal"] <= 8
            or value["operation"] not in ("issue", "consume", "standing")
        ):
            raise ServiceRefused()
        for field in (
            "request_digest",
            "window_digest",
            "proof_digest",
            "bundle_digest",
        ):
            actual = value[field]
            if actual is None and field != "request_digest":
                continue
            if type(actual) is not str or _DIGEST.fullmatch(actual) is None:
                raise ServiceRefused()
        try:
            if type(value["kind"]) is not str:
                raise ServiceRefused()
            kind = OutcomeKind(value["kind"])
        except (TypeError, ValueError):
            raise ServiceRefused() from None
        namespace, code = value["owner_namespace"], value["owner_code"]
        if (namespace is not None and type(namespace) is not str) or (
            code is not None and type(code) is not str
        ):
            raise ServiceRefused()
        if kind is OutcomeKind.OWNER_REFUSED:
            # Membership comes from actual pinned public owner vocabulary.
            if namespace == "approvals":
                from vendor_cp.approvals.adapter import ApprovalHoldRefusal

                valid = code == ApprovalHoldRefusal.WITHDRAWN.value
            elif namespace == "control.issuance":
                from dotmac_deployment_control import RehearsalIssuerIssuanceRefusalCode

                valid = code in {
                    member.value for member in RehearsalIssuerIssuanceRefusalCode
                }
            else:
                valid = False
            if not valid or value["result"] != {}:
                raise ServiceRefused()
        elif namespace is not None or code is not None:
            raise ServiceRefused()
        result = strict_object(canonical(value["result"]), 192 * 1024)
        if kind in (OutcomeKind.ISSUE_COMMITTED, OutcomeKind.CONSUME_COMMITTED):
            if value["proof_digest"] is None or value["bundle_digest"] is None:
                raise ServiceRefused()
            if any(
                type(result.get(field)) is not str
                or not 0 < len(cast(str, result[field])) <= 512
                for field in ("authorization_id", "lease_id")
            ):
                raise ServiceRefused()
            if (
                set(result)
                != {
                    "evidence_digest",
                    "authorization_id",
                    "lease_id",
                    "authorization_document",
                    "single_use_reference",
                    "issuer_receipt",
                }
                or result["evidence_digest"] != value["proof_digest"]
            ):
                raise ServiceRefused()
            if kind is OutcomeKind.ISSUE_COMMITTED and (
                value["operation"] != "issue"
                or type(result["authorization_document"]) is not str
                or type(result["issuer_receipt"]) is not str
                or result["single_use_reference"] is not None
            ):
                raise ServiceRefused()
            if kind is OutcomeKind.CONSUME_COMMITTED and (
                value["operation"] != "consume"
                or type(result["single_use_reference"]) is not str
                or not result["single_use_reference"]
                or result["authorization_document"] is not None
                or result["issuer_receipt"] is not None
            ):
                raise ServiceRefused()
        elif kind is OutcomeKind.STANDING:
            from dotmac_deployment_control import (
                RehearsalIssuerAuthorizationRefusalCode,
                RehearsalIssuerAuthorizationStanding,
            )

            if (
                value["operation"] != "standing"
                or set(result) != {"standing", "refusal"}
                or result["standing"]
                not in {member.value for member in RehearsalIssuerAuthorizationStanding}
                or result["refusal"] is not None
                and result["refusal"]
                not in {
                    member.value for member in RehearsalIssuerAuthorizationRefusalCode
                }
            ):
                raise ServiceRefused()
        elif kind is OutcomeKind.INCOMPLETE and result:
            raise ServiceRefused()
        return cls(
            value["ordinal"],
            value["operation"],
            cast(str, value["request_digest"]),
            cast(str | None, value["window_digest"]),
            cast(str | None, value["proof_digest"]),
            cast(str | None, value["bundle_digest"]),
            kind,
            namespace,
            code,
            canonical(result),
        )


def request_identity(request: dict[str, object]) -> str:
    """Credentials never enter retained request identity or transcript."""
    return digest(
        canonical(
            {key: value for key, value in request.items() if key != "workload_token"}
        )
    )


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    """Private prepublication source evidence. Missing acceptance stays explicit."""

    case_a: tuple[IssuerOutcome, ...]
    case_b: tuple[IssuerOutcome, ...]
    exact_bundles: tuple[bytes, ...]
    withdrawal_evidence: bytes
    approval_evidence: tuple[bytes, bytes]

    @property
    def readiness_accepted(self) -> Literal[False]:
        return False

    def document(self) -> dict[str, object]:
        from vendor_cp.deployment.gate0_observation import encode

        return {
            "schema": "Gate0CollectedEvidence.v1",
            "case_a": [item.document() for item in self.case_a],
            "case_b": [item.document() for item in self.case_b],
            "exact_bundles": [encode(raw) for raw in self.exact_bundles],
            "withdrawal_evidence": strict_object(self.withdrawal_evidence),
            "approval_evidence": [strict_object(raw) for raw in self.approval_evidence],
            "producer_acceptance": "pending",
            "prerequisite_acceptance": "pending",
            "cleanup_acceptance": "pending_root_integration",
            "publication_acceptance": "pending_owner_policy",
            "readiness_accepted": False,
        }


class FramedCaseCollector:
    """One predeclared case channel; never retry or continue after refusal.

    Construction with pipes is for hosted qualification. Installed execution
    remains unavailable until the root-owned two-start/cleanup integration.
    """

    def __init__(self, channel: FramedChannel) -> None:
        if type(channel) is not FramedChannel:
            raise ServiceRefused()
        self._channel = channel
        self._ordinal = 0
        self._terminal = False
        self._outcomes: list[IssuerOutcome] = []

    def _exchange(self, request: dict[str, object]) -> IssuerOutcome:
        if self._terminal or self._ordinal >= 8:
            raise ServiceRefused()
        self._ordinal += 1
        identity = request_identity(request)
        try:
            self._channel.send(request)
            response = self._channel.receive()
            outcome = IssuerOutcome.parse(response)
            if (
                outcome.ordinal != self._ordinal
                or outcome.operation != request["operation"]
                or outcome.request_digest != identity
            ):
                raise ServiceRefused()
        except BaseException:
            self._terminal = True
            raise
        self._outcomes.append(outcome)
        if outcome.kind in (OutcomeKind.OWNER_REFUSED, OutcomeKind.INCOMPLETE):
            self._terminal = True
        return outcome

    @property
    def outcomes(self) -> tuple[IssuerOutcome, ...]:
        return tuple(self._outcomes)


def run_installed_collection() -> int:
    """No caller flag/file may substitute for protected launcher integration."""
    import sys

    print("GATE0_COLLECTION_UNAVAILABLE", file=sys.stderr)
    return 3


@dataclass(frozen=True, slots=True)
class FixedCasePlan:
    """Exactly two normative independent starts and four existing proof bundles.

    Owner bindings are authenticated outside this mechanism, then matched to
    actual service outcomes. This object never says a human decision is genuine.
    """

    case_a: ApprovedWindowBinding
    case_b: ApprovedWindowBinding
    command_a: str
    command_b: str

    def __post_init__(self) -> None:
        case_a, case_b = self.case_a, self.case_b
        command_a, command_b = self.command_a, self.command_b
        from vendor_cp.deployment.gate0_window import ApprovedWindowBinding

        if (
            type(case_a) is not ApprovedWindowBinding
            or type(case_b) is not ApprovedWindowBinding
        ):
            raise ServiceRefused()
        first, second = case_a.expectation, case_b.expectation
        a, b = first.operation, second.operation
        if (
            a.phase != "issue"
            or b.phase != "issue"
            or a.lease_id == b.lease_id
            or a.controller_fingerprint == b.controller_fingerprint
            or a.certificate_digest == b.certificate_digest
            or a.plan_id == b.plan_id
            or a.window_id == b.window_id
            or first.approval_request_id == second.approval_request_id
            or (a.repository_id, a.run_id, a.run_attempt)
            != (b.repository_id, b.run_id, b.run_attempt)
            or command_a == command_b
            or any(
                type(command) is not str
                or not 0 < len(command) <= 200
                or command != command.strip()
                for command in (command_a, command_b)
            )
        ):
            raise ServiceRefused()


class FixedEvidenceCollector:
    """Concrete fixed framed A/B choreography; no automatic human decisions.

    Both FramedChannels belong to separately predeclared finite issuer starts.
    Attester bundles arrive from their fixed paired proof invocations. Production
    pipe/SSH construction and authenticated root cleanup are integration gates,
    so the installed entrypoint cannot yet construct this mechanism.
    """

    def __init__(
        self,
        *,
        plan: FixedCasePlan,
        case_a: FramedChannel,
        case_b: FramedChannel,
        verifier: BoundedHarnessVerifier,
        issuer_identity: RehearsalIssuerAuthorizationSignerIdentity,
        authorization_verifier: RehearsalIssuerAuthorizationVerifier,
    ) -> None:
        from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier

        if (
            type(plan) is not FixedCasePlan
            or type(verifier) is not BoundedHarnessVerifier
            or case_a is case_b
        ):
            raise ServiceRefused()
        self._plan = plan
        self._a, self._b = FramedCaseCollector(case_a), FramedCaseCollector(case_b)
        self._verifier = verifier
        self._issuer_identity, self._authorization_verifier = (
            issuer_identity,
            authorization_verifier,
        )
        self._bundles: list[bytes] = []
        self._a_done = False
        self._a_authorization: bytes | None = None
        self._a_expected: AdmissionExpectation | None = None
        self._a_issue: IssuerOutcome | None = None
        self._a_use_started = False
        self._b_authorization: bytes | None = None
        self._b_issue_bundle: bytes | None = None
        self._b_consume: bytes | None = None
        self._b_expected: AdmissionExpectation | None = None
        self._b_issue: IssuerOutcome | None = None
        self._b_revocation: bytes | None = None
        self._withdrawal_reads = 0
        self._b_use_started = False
        self._approvals: dict[str, bytes] = {}

    def read_approval(
        self, *, case: Literal["a", "b"], sessions: Callable[[], Session]
    ) -> None:
        from dotmac_deployment_control import get_plan, get_target

        from vendor_cp.approvals.adapter import (
            approved_request_evidence,
            request_identity_evidence,
        )
        from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
        from vendor_cp.deployment.protected_rehearsal_issuer import (
            SUBJECT_TYPE,
            issuer_approval_subject,
        )

        if case not in ("a", "b") or case in self._approvals:
            raise ServiceRefused()
        binding = self._plan.case_a if case == "a" else self._plan.case_b
        expected = binding.expectation
        db: Session | None = None
        evidence: bytes | None = None
        failed = False
        try:
            db = sessions()
            plan = get_plan(db, UUID(expected.operation.plan_id))
            target = get_target(db, expected.target_id)
            if (
                plan is None
                or target is None
                or plan.approval_decision_ref != str(expected.approval_request_id)
            ):
                raise ServiceRefused()
            window = FrozenIssuerWindow.from_plan(plan)
            window.check_plan(plan, target)
            if window != binding.window:
                raise ServiceRefused()
            identity = request_identity_evidence(db, expected.approval_request_id)
            if (
                identity.subject_id != issuer_approval_subject(plan)
                or identity.subject_type != SUBJECT_TYPE
                or identity.content_digest != expected.operation.plan_digest
                or identity.policy_code != expected.approval_policy_code
                or identity.policy_version != expected.approval_policy_version
            ):
                raise ServiceRefused()
            approved = approved_request_evidence(
                db,
                request_id=expected.approval_request_id,
                subject_type=identity.subject_type,
                subject_id=identity.subject_id,
                content_hash=expected.operation.plan_digest.removeprefix("sha256:"),
            )
            evidence = canonical(
                {
                    "request_id": str(approved.request_id),
                    "subject_type": identity.subject_type,
                    "subject_id": identity.subject_id,
                    "content_digest": identity.content_digest,
                    "policy_code": approved.policy_code,
                    "policy_version": approved.policy_version,
                    "state": identity.state,
                    "decided_at": approved.decided_at.isoformat(),
                    "decisions": [
                        {
                            "id": str(item.decision_id),
                            "actor_id": str(item.actor_id),
                            "action": item.action,
                            "decided_at": item.decided_at.isoformat(),
                        }
                        for item in identity.decisions
                    ],
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
        if failed or evidence is None:
            raise ServiceRefused()
        self._approvals[case] = evidence

    def _proof(
        self, raw: bytes, expected: AdmissionExpectation
    ) -> tuple[dict[str, object], str]:
        from dataclasses import asdict
        from datetime import UTC, datetime

        from vendor_cp.deployment.gate0_observation import (
            parse_bundle,
            verify_observation,
        )

        if expected.window_digest is None:
            raise ServiceRefused()
        document = strict_object(raw)
        if canonical(document) != raw:
            raise ServiceRefused()
        proof, observation = parse_bundle(document)
        if {
            key: value
            for key, value in asdict(proof.context).items()
            if key not in {"challenge_digest", "proof_transcript_digest"}
        } != asdict(expected.operation):
            raise ServiceRefused()
        verifier = self._verifier
        verify_observation(
            proof=proof,
            observation=observation,
            operation=expected.operation,
            window_record_digest=expected.window_digest,
            key_id=verifier._key_id,
            public_key=verifier._public_key,
            trust_state=verifier._trust,
            now=datetime.now(UTC),
        )
        proof_digest = verifier._register(proof, expected.operation)
        exported = verifier.export_registered(proof_digest)
        if exported.owner_envelope != proof.control_document:
            raise ServiceRefused()
        if (
            len(self._bundles) >= 4
            or sum(map(len, self._bundles)) + len(raw) > 512 * 1024
        ):
            raise ServiceRefused()
        self._bundles.append(raw)
        return document, proof_digest

    def _issue(
        self,
        channel: FramedCaseCollector,
        binding: ApprovedWindowBinding,
        command: str,
        raw: bytes,
        token: str,
    ) -> tuple[bytes, IssuerOutcome]:
        from vendor_cp.deployment.gate0_observation import decode

        proof, proof_digest = self._proof(raw, binding.expectation)
        outcome = channel._exchange(
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "issue",
                "workload_token": token,
                "plan_id": binding.expectation.operation.plan_id,
                "command_id": command,
                "proof": proof,
            }
        )
        self._matching(outcome, binding.expectation, proof_digest, raw)
        if outcome.kind is not OutcomeKind.ISSUE_COMMITTED:
            raise ServiceRefused()
        result = strict_object(outcome.result_bytes)
        authorization = decode(result["authorization_document"], 128 * 1024)
        receipt = strict_object(decode(result["issuer_receipt"], 8192), 8192)
        if (
            receipt.get("verb") != "issue_authorization"
            or receipt.get("command_id") != command
            or receipt.get("plan_id") != binding.expectation.operation.plan_id
            or receipt.get("approval_request_id")
            != str(binding.expectation.approval_request_id)
            or receipt.get("control_ref") != result["authorization_id"]
            or result["lease_id"] != binding.expectation.operation.lease_id
        ):
            raise ServiceRefused()
        return authorization, outcome

    @staticmethod
    def _matching(
        outcome: IssuerOutcome,
        expected: AdmissionExpectation,
        proof_digest: str,
        raw: bytes,
    ) -> None:
        if (
            outcome.window_digest != expected.window_digest
            or outcome.proof_digest != proof_digest
            or outcome.bundle_digest != digest(raw)
        ):
            raise ServiceRefused()

    @staticmethod
    def _standing(
        channel: FramedCaseCollector,
        authorization: bytes,
        proof_digest: str | None,
        token: str,
        required: RehearsalIssuerAuthorizationStanding,
        expected: AdmissionExpectation,
        raw: bytes,
    ) -> None:
        from vendor_cp.deployment.gate0_observation import encode

        if proof_digest is None:
            raise ServiceRefused()
        outcome = channel._exchange(
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "standing",
                "workload_token": token,
                "authorization": encode(authorization),
                "evidence_digest": proof_digest,
            }
        )
        FixedEvidenceCollector._matching(outcome, expected, proof_digest, raw)
        if (
            outcome.kind is not OutcomeKind.STANDING
            or strict_object(outcome.result_bytes)["standing"] != required.value
        ):
            raise ServiceRefused()

    def issue_a(
        self,
        *,
        issue_bundle: bytes,
        tokens: tuple[str, str],
    ) -> tuple[bytes, AdmissionExpectation]:
        from dotmac_deployment_control import (
            RehearsalIssuerAuthorizationStanding,
        )

        from vendor_cp.deployment.gate0_window import derive_consume_expectation

        if "a" not in self._approvals or self._a.outcomes or len(tokens) != 2:
            raise ServiceRefused()
        binding = self._plan.case_a
        authorization, issued = self._issue(
            self._a, binding, self._plan.command_a, issue_bundle, tokens[0]
        )
        self._standing(
            self._a,
            authorization,
            issued.proof_digest,
            tokens[1],
            RehearsalIssuerAuthorizationStanding.VALID,
            binding.expectation,
            issue_bundle,
        )
        expected = derive_consume_expectation(
            binding, authorization, self._issuer_identity, self._authorization_verifier
        )
        self._a_authorization, self._a_expected, self._a_issue = (
            authorization,
            expected,
            issued,
        )
        return authorization, expected

    def collect_a(self, *, consume_bundle: bytes, tokens: tuple[str, str, str]) -> None:
        from dotmac_deployment_control import (
            RehearsalIssuerAuthorizationStanding,
            RehearsalIssuerIssuanceRefusalCode,
        )

        from vendor_cp.deployment.gate0_composition import authorization_binding
        from vendor_cp.deployment.gate0_observation import encode

        if (
            self._a_use_started
            or self._a_authorization is None
            or self._a_expected is None
            or self._a_issue is None
            or len(tokens) != 3
        ):
            raise ServiceRefused()
        self._a_use_started = True
        authorization, expected, issued = (
            self._a_authorization,
            self._a_expected,
            self._a_issue,
        )
        proof, proof_digest = self._proof(consume_bundle, expected)
        request: dict[str, object] = {
            "schema": "Gate0IssuerSubmission.v1",
            "operation": "consume",
            "plan_id": expected.operation.plan_id,
            "authorization": encode(authorization),
            "proof": proof,
            "workload_token": tokens[0],
        }
        consumed = self._a._exchange(request)
        self._matching(consumed, expected, proof_digest, consume_bundle)
        if consumed.kind is not OutcomeKind.CONSUME_COMMITTED:
            raise ServiceRefused()
        result = strict_object(consumed.result_bytes)
        if (
            result["authorization_id"]
            != strict_object(issued.result_bytes)["authorization_id"]
            or result["lease_id"] != expected.operation.lease_id
            or result["single_use_reference"]
            != authorization_binding(
                authorization
            ).parsed.statement.single_use_reference
        ):
            raise ServiceRefused()
        self._standing(
            self._a,
            authorization,
            proof_digest,
            tokens[1],
            RehearsalIssuerAuthorizationStanding.CONSUMED,
            expected,
            consume_bundle,
        )
        # Exactly the same envelope/proof; only the verified workload token may
        # change. Never produce a fifth proof or continue this channel afterward.
        request["workload_token"] = tokens[2]
        refused = self._a._exchange(request)
        self._matching(refused, expected, proof_digest, consume_bundle)
        if (
            refused.kind is not OutcomeKind.OWNER_REFUSED
            or refused.owner_namespace != "control.issuance"
            or refused.owner_code
            != RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value
        ):
            raise ServiceRefused()
        self._a_done = True

    def issue_b(
        self, *, issue_bundle: bytes, tokens: tuple[str, str]
    ) -> tuple[bytes, AdmissionExpectation]:
        from dotmac_deployment_control import RehearsalIssuerAuthorizationStanding

        from vendor_cp.deployment.gate0_window import derive_consume_expectation

        if (
            "b" not in self._approvals
            or not self._a_done
            or self._b.outcomes
            or len(tokens) != 2
        ):
            raise ServiceRefused()
        binding = self._plan.case_b
        authorization, issued = self._issue(
            self._b, binding, self._plan.command_b, issue_bundle, tokens[0]
        )
        self._standing(
            self._b,
            authorization,
            issued.proof_digest,
            tokens[1],
            RehearsalIssuerAuthorizationStanding.VALID,
            binding.expectation,
            issue_bundle,
        )
        expected = derive_consume_expectation(
            binding, authorization, self._issuer_identity, self._authorization_verifier
        )
        self._b_authorization, self._b_expected, self._b_issue = (
            authorization,
            expected,
            issued,
        )
        self._b_issue_bundle = issue_bundle
        return authorization, expected

    def prepare_b(self, *, consume_bundle: bytes, token: str) -> None:
        from dotmac_deployment_control import RehearsalIssuerAuthorizationStanding

        # Called only after issue_b returns the actual signed authorization.
        # NS3 captures this proof while current approval still stands.
        if (
            self._b_authorization is None
            or self._b_expected is None
            or self._b_consume is not None
            or self._b_issue is None
            or self._b_issue_bundle is None
        ):
            raise ServiceRefused()
        self._proof(consume_bundle, self._b_expected)
        # A current held owner read after capture establishes that this valid
        # consume proof existed before approval ceased to stand. No spend occurs.
        self._standing(
            self._b,
            self._b_authorization,
            self._b_issue.proof_digest,
            token,
            RehearsalIssuerAuthorizationStanding.VALID,
            self._plan.case_b.expectation,
            self._b_issue_bundle,
        )
        self._b_consume = consume_bundle

    def observe_b_withdrawal(
        self, *, sessions: Callable[[], Session], withdrawal_ref: str
    ) -> bool:
        db: Session | None = None
        observed: bytes | None = None
        failed = False
        try:
            db = sessions()
            observed = self._read_b_withdrawal(db=db, withdrawal_ref=withdrawal_ref)
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
        if failed:
            raise ServiceRefused()
        if observed is None:
            return False
        self._b_revocation = observed
        return True

    def _read_b_withdrawal(self, *, db: Session, withdrawal_ref: str) -> bytes | None:
        """Bounded read of existing relay progress; never drain or mutate it."""
        from vendor_cp.relay.withdrawal_outcomes import (
            WithdrawalDisposition,
            outcomes_for_request,
        )

        if (
            self._b_expected is None
            or self._b_consume is None
            or self._b_issue is None
            or self._b_revocation is not None
        ):
            raise ServiceRefused()
        expected = self._b_expected
        self._withdrawal_reads += 1
        if self._withdrawal_reads > 16 or expected.window_freshness is None:
            raise ServiceRefused()
        expected.window_freshness.require_open()
        rows = outcomes_for_request(
            db, request_id=expected.approval_request_id, withdrawal_ref=withdrawal_ref
        )
        if not rows:
            return None
        authorization_id = strict_object(self._b_issue.result_bytes)["authorization_id"]
        if (
            len(rows) != 1
            or rows[0].disposition is not WithdrawalDisposition.APPLIED
            or rows[0].event_type != "approval.withdrawn"
            or rows[0].approval_request_id != expected.approval_request_id
            or rows[0].withdrawal_ref != withdrawal_ref
            or _DIGEST.fullmatch(rows[0].payload_digest) is None
            or rows[0].subject_type
            != strict_object(self._approvals["b"])["subject_type"]
            or rows[0].subject_id != strict_object(self._approvals["b"])["subject_id"]
            or str(rows[0].plan_id) != expected.operation.plan_id
            or rows[0].evidence.get("authorizations_revoked") != [authorization_id]
        ):
            raise ServiceRefused()
        return canonical(
            {
                "event_id": str(rows[0].event_id),
                "payload_digest": rows[0].payload_digest,
                "request_id": str(rows[0].approval_request_id),
                "withdrawal_ref": rows[0].withdrawal_ref,
                "plan_id": str(rows[0].plan_id),
                "disposition": rows[0].disposition.value,
                "authorizations_revoked": [authorization_id],
            }
        )

    def collect_b_later_use(self, *, token: str) -> CollectedEvidence:
        from vendor_cp.approvals.adapter import ApprovalHoldRefusal
        from vendor_cp.deployment.gate0_observation import encode

        if (
            self._b_use_started
            or self._b_revocation is None
            or self._b_authorization is None
            or self._b_consume is None
            or self._b_expected is None
        ):
            raise ServiceRefused()
        self._b_use_started = True
        expected = self._b_expected
        if expected.window_freshness is None:
            raise ServiceRefused()
        expected.window_freshness.require_open()
        outcome = self._b._exchange(
            {
                "schema": "Gate0IssuerSubmission.v1",
                "operation": "consume",
                "plan_id": expected.operation.plan_id,
                "authorization": encode(self._b_authorization),
                "proof": strict_object(self._b_consume),
                "workload_token": token,
            }
        )
        if (
            outcome.kind is not OutcomeKind.OWNER_REFUSED
            or outcome.window_digest != expected.window_digest
            or outcome.owner_namespace != "approvals"
            or outcome.owner_code != ApprovalHoldRefusal.WITHDRAWN.value
        ):
            raise ServiceRefused()
        return CollectedEvidence(
            self._a.outcomes,
            self._b.outcomes,
            tuple(self._bundles),
            self._b_revocation,
            (self._approvals["a"], self._approvals["b"]),
        )
