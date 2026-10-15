"""Historical retained-byte verification, never an E acceptance authority.

The independently supplied selection is inert. No constructor opens a window,
registers a proof, starts a process, consults a database, or authenticates a root.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import UUID

from vendor_cp.deployment.gate0_collection import (
    IssuerOutcome,
    OutcomeKind,
    digest,
    request_identity,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import RunDocument, parse_run_document
from vendor_cp.deployment.gate0_observation import decode, encode, parse_bundle
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_handoff import RootHostBinding
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.rehearsal_issuer_trust_state import TrustStateSnapshot


class RetainedEvidenceRefused(ProviderRefused):
    """Closed diagnostic: private evidence never enters an exception message."""


def _fields(value: object, names: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(names.split()):
        raise RetainedEvidenceRefused()
    return cast(dict[str, object], value)


def _list(value: object, count: int) -> list[object]:
    if type(value) is not list or len(value) != count:
        raise RetainedEvidenceRefused()
    return cast(list[object], value)


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise RetainedEvidenceRefused()
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise RetainedEvidenceRefused()
    return result.astimezone(UTC)


def _text(value: object, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or value.strip() != value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise RetainedEvidenceRefused()
    return value


def _hash(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise RetainedEvidenceRefused()
    return value


@dataclass(frozen=True, slots=True)
class EPublicTrust:
    """Exact original enrolled public snapshot, independently pinned by policy."""

    key_id: str
    public_key: bytes = field(repr=False)
    record: bytes = field(repr=False)
    minimum_version: int
    source_ref: str
    qualification_digest: str

    def __post_init__(self) -> None:
        _text(self.key_id)
        _text(self.source_ref)
        _hash(self.qualification_digest)
        if (
            type(self.public_key) is not bytes
            or len(self.public_key) != 32
            or type(self.record) is not bytes
            or type(self.minimum_version) is not int
            or self.minimum_version < 1
        ):
            raise RetainedEvidenceRefused()
        doc = _fields(
            strict_object(self.record, 65536),
            "version trusted_key_ids revoked_key_ids",
        )
        if canonical(doc) != self.record:
            raise RetainedEvidenceRefused()
        # The existing owner enforces rollback floors, revoked-wins and keys.
        self.trust_state()

    def trust_state(self) -> TrustStateSnapshot:
        """Return an inert original snapshot, never start or refresh live trust."""
        from vendor_cp.deployment.rehearsal_issuer_trust_state import (
            parse_trust_snapshot,
        )

        snapshot = parse_trust_snapshot(
            strict_object(self.record, 65536), minimum_version=self.minimum_version
        )
        if self.key_id in snapshot.revoked_key_ids or snapshot.trusted_key_ids.get(
            self.key_id
        ) != digest(self.public_key):
            raise RetainedEvidenceRefused()
        return snapshot

    def document(self) -> dict[str, object]:
        return dict(
            key_id=self.key_id,
            public_key=encode(self.public_key),
            record=encode(self.record),
            minimum_version=self.minimum_version,
            source_ref=self.source_ref,
            qualification_digest=self.qualification_digest,
        )


@dataclass(frozen=True, slots=True)
class ERetainedCase:
    """Original public case coordinates; contains no clock or session handle."""

    shared_packet: bytes = field(repr=False)
    frozen_window: bytes = field(repr=False)
    command_id: str
    roots: tuple[RootHostBinding, RootHostBinding]
    issuer_trust: EPublicTrust
    attester_trust: EPublicTrust

    def __post_init__(self) -> None:
        _text(self.command_id, 200)
        if (
            type(self.shared_packet) is not bytes
            or type(self.frozen_window) is not bytes
            or type(self.roots) is not tuple
            or len(self.roots) != 2
            or any(type(root) is not RootHostBinding for root in self.roots)
            or type(self.issuer_trust) is not EPublicTrust
            or type(self.attester_trust) is not EPublicTrust
        ):
            raise RetainedEvidenceRefused()
        packet, window = self.packet, self.window.document
        capture = packet["capture"]
        if (
            canonical(packet) != self.shared_packet
            or packet["case_kind"] != window["case_kind"]
            or capture["window_digest"] != self.window.digest
            or capture["target_id"] != window["target"]["id"]
            or packet["controller_ca_fingerprint"]
            != window["controller"]["ca_fingerprint"]
            or packet["run_id"] != window["github"]["run_id"]
            or packet["run_attempt"] != window["github"]["run_attempt"]
            or packet["not_before"] != window["not_before"]
            or packet["expires_at"] != window["expires_at"]
            or not 0 < (self.end - self.start).total_seconds() <= 300
        ):
            raise RetainedEvidenceRefused()
        for root, role in zip(self.roots, ("issuer", "attester"), strict=True):
            terms = root.terms
            if any(
                terms[k] != v
                for k, v in dict(
                    host_role=role,
                    case_kind=window["case_kind"],
                    launch_packet_digest=digest(self.shared_packet),
                    window_digest=self.window.digest,
                    not_before=window["not_before"],
                    expires_at=window["expires_at"],
                ).items()
            ):
                raise RetainedEvidenceRefused()
        for trust, role in zip(
            (self.issuer_trust, self.attester_trust),
            (packet["roles"]["issuer"], packet["roles"]["attester"]),
            strict=True,
        ):
            if role["key_id"] != trust.key_id or role["public_key_b64"] != encode(
                trust.public_key
            ):
                raise RetainedEvidenceRefused()
        if (
            self.issuer_trust.key_id == self.attester_trust.key_id
            or self.issuer_trust.public_key == self.attester_trust.public_key
        ):
            raise RetainedEvidenceRefused()

    @property
    def packet(self) -> RunDocument:
        return parse_run_document(self.shared_packet)

    @property
    def window(self) -> FrozenIssuerWindow:
        return FrozenIssuerWindow.parse(self.frozen_window)

    @property
    def start(self) -> datetime:
        return _instant(self.window.document["not_before"])

    @property
    def end(self) -> datetime:
        return _instant(self.window.document["expires_at"])

    def document(self) -> dict[str, object]:
        return dict(
            shared_packet=encode(self.shared_packet),
            frozen_window=encode(self.frozen_window),
        )


@dataclass(frozen=True, slots=True)
class ESourcePins:
    """Expected bytes supplied by reviewed installation; no producer claim."""

    cp_revision: str
    cp_source_digest: str
    cp_wheel_digest: str
    cp_image_digest: str
    module_bundle_digest: str
    workflow_revision: str
    workflow_digest: str

    def __post_init__(self) -> None:
        for revision in (self.cp_revision, self.workflow_revision):
            if (
                type(revision) is not str
                or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            ):
                raise RetainedEvidenceRefused()
        for value in (
            self.cp_source_digest,
            self.cp_wheel_digest,
            self.cp_image_digest,
            self.module_bundle_digest,
            self.workflow_digest,
        ):
            _hash(value)


@dataclass(frozen=True, slots=True)
class ESelection:
    """Inert independent pins for byte verification, NOT an installed policy loader.

    Producer/prerequisite acceptance formats remain their actual owners' work.
    No invented accepted-prerequisite flag or lifecycle is represented here.
    """

    policy_digest: str
    campaign_digest: str
    source: ESourcePins
    cases: tuple[ERetainedCase, ERetainedCase]
    withdrawal_reference: str
    environment: str

    def __post_init__(self) -> None:
        _hash(self.policy_digest)
        _hash(self.campaign_digest)
        _text(self.withdrawal_reference, 200)
        _text(self.environment)
        if (
            type(self.source) is not ESourcePins
            or type(self.cases) is not tuple
            or len(self.cases) != 2
            or any(type(case) is not ERetainedCase for case in self.cases)
        ):
            raise RetainedEvidenceRefused()
        a, b = self.cases
        wa, wb = a.window.document, b.window.document
        if (
            (wa["case_kind"], wb["case_kind"])
            != ("consume_replay", "withdrawal_later_use")
            or wa["github"] != wb["github"]
            or wa["github"]["environment"] != self.environment
            or wb["github"]["environment"] != self.environment
            or a.end > b.start
            or a.command_id == b.command_id
            or wa["window_id"] == wb["window_id"]
            or wa["controller"]["lease_id"] == wb["controller"]["lease_id"]
            or wa["controller"]["fingerprint"] == wb["controller"]["fingerprint"]
            or wa["controller"]["certificate_digest"]
            == wb["controller"]["certificate_digest"]
            or a.packet["capture"]["plan_id"] == b.packet["capture"]["plan_id"]
            or a.packet["capture"]["approval_request_id"]
            == b.packet["capture"]["approval_request_id"]
            or len(
                {r.terms["local_packet_digest"] for c in self.cases for r in c.roots}
            )
            != 4
        ):
            raise RetainedEvidenceRefused()


@dataclass(frozen=True, slots=True)
class VerifiedCollection:
    """A nonauthorizing result about exact historical retained bytes only."""

    collection_bytes: bytes = field(repr=False)
    policy_digest: str
    collection_digest: str
    bundle_digests: tuple[str, ...]
    root_record_digests: tuple[str, ...]
    join_digests: tuple[str, str]
    result: Literal["retained_bytes_verified"] = "retained_bytes_verified"

    @property
    def readiness_accepted(self) -> Literal[False]:
        return False


def _outcomes(
    case: ERetainedCase,
    documents: object,
    bundles: tuple[bytes, bytes],
    *,
    replay: bool,
) -> tuple[IssuerOutcome, ...]:
    """Rebuild every credential-free request, preserving actual owner refusals."""
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationStanding,
        RehearsalIssuerIssuanceRefusalCode,
    )

    from vendor_cp.approvals.adapter import ApprovalHoldRefusal
    from vendor_cp.deployment.gate0_composition import authorization_binding

    if type(documents) is not list or len(documents) != (5 if replay else 4):
        raise RetainedEvidenceRefused()
    outcomes = tuple(
        IssuerOutcome.parse(doc) for doc in _list(documents, 5 if replay else 4)
    )
    issue_doc, consume_doc = (strict_object(raw, 128 * 1024) for raw in bundles)
    proofs = tuple(parse_bundle(doc)[0] for doc in (issue_doc, consume_doc))
    pairs = tuple(
        (
            digest(decode(strict_object(p.control_document)["canonical_bytes"], 8192)),
            digest(raw),
        )
        for p, raw in zip(proofs, bundles, strict=True)
    )
    if pairs[0][0] == pairs[1][0]:
        raise RetainedEvidenceRefused()
    issued = strict_object(outcomes[0].result_bytes)
    authorization = decode(issued.get("authorization_document"), 128 * 1024)
    auth = authorization_binding(authorization)
    receipt_bytes = decode(issued.get("issuer_receipt"), 8192)
    receipt = _fields(
        strict_object(receipt_bytes, 8192),
        "id command_id verb request_fingerprint plan_id approval_request_id "
        "control_ref recorded_at",
    )
    if canonical(receipt) != receipt_bytes:
        raise RetainedEvidenceRefused()
    receipt_id = _text(receipt["id"], 36)
    if str(UUID(receipt_id)) != receipt_id:
        raise RetainedEvidenceRefused()
    _hash(receipt["request_fingerprint"])
    recorded = _instant(receipt["recorded_at"])
    if not case.start <= recorded < case.end:
        raise RetainedEvidenceRefused()
    capture = case.packet["capture"]
    if (
        any(
            receipt.get(k) != v
            for k, v in dict(
                verb="issue_authorization",
                command_id=case.command_id,
                plan_id=capture["plan_id"],
                approval_request_id=capture["approval_request_id"],
                control_ref=issued.get("authorization_id"),
            ).items()
        )
        or issued.get("authorization_id") != auth.parsed.statement.authorization_id
        or issued.get("lease_id") != case.window.document["controller"]["lease_id"]
    ):
        raise RetainedEvidenceRefused()
    base: dict[str, object] = {"schema": "Gate0IssuerSubmission.v1"}
    issue_request = base | dict(
        operation="issue",
        plan_id=capture["plan_id"],
        command_id=case.command_id,
        proof=issue_doc,
    )
    consume_request = base | dict(
        operation="consume",
        plan_id=capture["plan_id"],
        authorization=encode(authorization),
        proof=consume_doc,
    )

    def standing(pair: tuple[str, str]) -> dict[str, object]:
        return base | dict(
            operation="standing",
            authorization=encode(authorization),
            evidence_digest=pair[0],
        )

    kinds = (
        (
            OutcomeKind.ISSUE_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.CONSUME_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.OWNER_REFUSED,
        )
        if replay
        else (
            OutcomeKind.ISSUE_COMMITTED,
            OutcomeKind.STANDING,
            OutcomeKind.STANDING,
            OutcomeKind.OWNER_REFUSED,
        )
    )
    requests = (
        (
            issue_request,
            standing(pairs[0]),
            consume_request,
            standing(pairs[1]),
            consume_request,
        )
        if replay
        else (issue_request, standing(pairs[0]), standing(pairs[0]), consume_request)
    )
    for index, (outcome, kind, request) in enumerate(
        zip(outcomes, kinds, requests, strict=True)
    ):
        pair = pairs[0 if index < (2 if replay else 3) else 1]
        actual = outcome.proof_digest, outcome.bundle_digest
        if (
            outcome.ordinal != index + 1
            or outcome.kind is not kind
            or outcome.operation != request["operation"]
            or outcome.request_digest != request_identity(request)
            or outcome.window_digest != case.window.digest
            or (
                actual != pair
                and not (not replay and index == 3 and actual == (None, None))
            )
        ):
            raise RetainedEvidenceRefused()
        if kind is OutcomeKind.STANDING:
            state = (
                RehearsalIssuerAuthorizationStanding.CONSUMED
                if replay and index == 3
                else RehearsalIssuerAuthorizationStanding.VALID
            )
            if strict_object(outcome.result_bytes) != {
                "standing": state.value,
                "refusal": None,
            }:
                raise RetainedEvidenceRefused()
    final = outcomes[-1]
    if (
        final.owner_namespace != ("control.issuance" if replay else "approvals")
        or final.owner_code
        != (
            RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value
            if replay
            else ApprovalHoldRefusal.WITHDRAWN.value
        )
        or final.result_bytes != canonical({})
    ):
        raise RetainedEvidenceRefused()
    if replay:
        consumed = strict_object(outcomes[2].result_bytes)
        if (
            consumed["authorization_id"] != issued["authorization_id"]
            or consumed["lease_id"] != issued["lease_id"]
            or consumed["single_use_reference"]
            != auth.parsed.statement.single_use_reference
        ):
            raise RetainedEvidenceRefused()
    return outcomes


def verify_retained_collection(raw: bytes, selection: ESelection) -> VerifiedCollection:
    """Check historical bytes against independent pins; confer no eligibility.

    Actual protected producer provenance, prerequisites and runner key cleanup
    are outside this result. No final receipt or archive is prepared here.
    """
    try:
        return _verify_retained_collection(raw, selection)
    except Exception:
        raise RetainedEvidenceRefused() from None


def _verify_retained_collection(
    raw: bytes, selection: ESelection
) -> VerifiedCollection:
    from vendor_cp.deployment.gate0_runner_collector_handoff import (
        verify_retained_root_case,
    )
    from vendor_cp.deployment.gate0_runner_projection import (
        RetainedProjectionCase,
        decode_retained_approval,
        decode_retained_withdrawal,
    )
    from vendor_cp.deployment.gate0_runtime import verify_retained_bundle

    if type(raw) is not bytes or type(selection) is not ESelection:
        raise RetainedEvidenceRefused()
    doc = _fields(
        strict_object(raw, 8 * 1024 * 1024),
        "collection_complete readiness_accepted evidence root_records joins "
        "approval_projection_raw withdrawal_projection_raw original_selections "
        "public_trust",
    )
    evidence = _fields(
        doc["evidence"],
        "schema case_a case_b exact_bundles withdrawal_evidence approval_evidence "
        "producer_acceptance prerequisite_acceptance cleanup_acceptance "
        "publication_acceptance readiness_accepted",
    )
    if (
        canonical(doc) != raw
        or doc["collection_complete"] is not True
        or doc["readiness_accepted"] is not False
        or evidence["schema"] != "Gate0CollectedEvidence.v1"
        or evidence["readiness_accepted"] is not False
        or evidence["producer_acceptance"] != "pending"
        or evidence["prerequisite_acceptance"] != "pending"
        or evidence["cleanup_acceptance"] != "pending_root_integration"
        or evidence["publication_acceptance"] != "pending_owner_policy"
        or doc["original_selections"] != [case.document() for case in selection.cases]
        or doc["public_trust"]
        != [
            trust.document()
            for case in selection.cases
            for trust in (case.issuer_trust, case.attester_trust)
        ]
    ):
        raise RetainedEvidenceRefused()
    bundle_values = _list(evidence["exact_bundles"], 4)
    approval_values = _list(doc["approval_projection_raw"], 2)
    join_values = _list(doc["joins"], 2)
    root_values = _list(doc["root_records"], 14)
    bundles = tuple(decode(v, 128 * 1024) for v in bundle_values)
    if sum(map(len, bundles)) > 512 * 1024 or len(set(bundles)) != 4:
        raise RetainedEvidenceRefused()
    roots = tuple(decode(v, 270336) for v in root_values)
    rosters = (roots[:7], roots[7:])
    joins = tuple(decode(v, 196608) for v in join_values)
    approvals = tuple(decode(v, 196608) for v in approval_values)
    if evidence["approval_evidence"] != [strict_object(v) for v in approvals]:
        raise RetainedEvidenceRefused()
    all_outcomes = tuple(
        _outcomes(
            case, evidence[key], (bundles[2 * i], bundles[2 * i + 1]), replay=i == 0
        )
        for i, (case, key) in enumerate(
            zip(selection.cases, ("case_a", "case_b"), strict=True)
        )
    )
    from vendor_cp.deployment.gate0_runner_projection import RetainedApprovalProjection
    from vendor_cp.deployment.gate0_runtime import RetainedBundleVerification

    historical_approvals: list[RetainedApprovalProjection] = []
    verified_bundles: list[RetainedBundleVerification] = []
    for i, case in enumerate(selection.cases):
        projection_case = RetainedProjectionCase(case.shared_packet, case.frozen_window)
        approval = decode_retained_approval(approvals[i], projection_case)
        historical_approvals.append(approval)
        from vendor_cp.deployment.gate0_runner_projection import (
            derive_retained_consume_operation,
        )

        authorization = decode(
            strict_object(all_outcomes[i][0].result_bytes)["authorization_document"],
            128 * 1024,
        )
        consume = derive_retained_consume_operation(
            approval,
            authorization,
            key_id=case.issuer_trust.key_id,
            public_key=case.issuer_trust.public_key,
            trust_state=case.issuer_trust.trust_state(),
        )
        for phase, expected in enumerate((approval.facts, consume)):
            verified_bundles.append(
                verify_retained_bundle(
                    bundles[2 * i + phase],
                    expected=expected,
                    frozen_window=case.window,
                    key_id=case.attester_trust.key_id,
                    public_key=case.attester_trust.public_key,
                    trust_state=case.attester_trust.trust_state(),
                )
            )
        verify_retained_root_case(
            selection.campaign_digest,
            case.shared_packet,
            case.roots,
            rosters[i],
            joins[i],
            all_outcomes[i],
            (bundles[2 * i], bundles[2 * i + 1]),
        )
    if (
        len({proof.proof_digest for proof in verified_bundles}) != 4
        or len({proof.invocation_id for proof in verified_bundles}) != 4
    ):
        raise RetainedEvidenceRefused()
    withdrawals = doc["withdrawal_projection_raw"]
    if type(withdrawals) is not list or not 1 <= len(withdrawals) <= 16:
        raise RetainedEvidenceRefused()
    original_b = RetainedProjectionCase(
        selection.cases[1].shared_packet, selection.cases[1].frozen_window
    )
    issued_b = strict_object(all_outcomes[1][0].result_bytes)
    previous = selection.cases[1].start
    last_state = 0
    final_raw = b""
    for encoded in _list(withdrawals, len(withdrawals)):
        final_raw = decode(encoded, 196608)
        withdrawal = decode_retained_withdrawal(
            final_raw,
            original_b,
            reference=selection.withdrawal_reference,
            approval=historical_approvals[1],
            authorization_ref=_text(issued_b["authorization_id"]),
        )
        observed = _instant(strict_object(final_raw)["observed_at"])
        state = {"pending_withdrawal": 0, "pending_relay": 1, "applied": 2}[
            withdrawal.state
        ]
        if observed < previous or state < last_state or last_state == 2:
            raise RetainedEvidenceRefused()
        previous, last_state = observed, state
    if last_state != 2 or strict_object(final_raw) != evidence["withdrawal_evidence"]:
        raise RetainedEvidenceRefused()
    # B consume existed before the real withdrawal event, not a later repair.
    withdrawal_record = _fields(
        strict_object(final_raw)["withdrawal"],
        "request_id withdrawal_id actor_id authority_ref approved_at "
        "effective_at external_ref",
    )
    effective = _instant(withdrawal_record["effective_at"])
    if verified_bundles[3].observed_until > effective:
        raise RetainedEvidenceRefused()
    return VerifiedCollection(
        raw,
        selection.policy_digest,
        digest(raw),
        tuple(digest(v) for v in bundles),
        tuple(digest(v) for v in roots),
        (digest(joins[0]), digest(joins[1])),
    )
