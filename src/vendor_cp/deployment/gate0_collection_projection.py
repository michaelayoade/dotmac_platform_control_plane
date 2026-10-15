"""Finite, detached owner evidence for the protected A9 collector.

Installed selection and database/JWKS bounds require separate qualification.
Only the fixed protected boot loader configures reads; no owner mutation or polling.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from dotmac_kernel.session_runtime import DatabaseRuntime
from sqlalchemy import text
from sqlalchemy.orm import Session

from vendor_cp.approvals.adapter import (
    HeldPlatformApproval,
    RequestIdentityEvidence,
    approved_request_evidence,
    request_identity_evidence,
    withdrawal_for_reference,
)
from vendor_cp.deployment.approval_barrier import held_transition
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_github_jwt import VerifiedClaims, verify_github_claims
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
)
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment.issuer_receipts import issued_authorization_refs
from vendor_cp.deployment.protected_rehearsal_issuer import (
    SUBJECT_TYPE,
    issuer_approval_subject,
)
from vendor_cp.relay.withdrawal_outcomes import (
    WithdrawalDisposition,
    outcomes_for_event,
)

if TYPE_CHECKING:
    from dotmac_deployment_control import PlanView, TargetView

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class CollectionSelection:
    """CP protected installation coordinates; never constructed from HTTP input."""

    launch_packet_digest: str
    window_id: str
    window_digest: str
    plan_id: UUID
    target_id: UUID
    case_kind: str

    def __post_init__(self) -> None:
        if (
            any(
                type(v) is not str or _DIGEST.fullmatch(v) is None
                for v in (self.launch_packet_digest, self.window_digest)
            )
            or type(self.plan_id) is not UUID
            or type(self.target_id) is not UUID
            or type(self.window_id) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.window_id) is None
            or self.case_kind not in ("consume_replay", "withdrawal_later_use")
        ):
            raise ProviderRefused()


@dataclass(frozen=True, slots=True)
class CollectionCaseClock:
    """An inert per-case interval mapped from one original protected host anchor."""

    wall_origin: datetime
    monotonic_origin: float
    not_before: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if (
            any(
                type(v) is not datetime
                or v.tzinfo is None
                or v.utcoffset() != timedelta(0)
                for v in (self.wall_origin, self.not_before, self.expires_at)
            )
            or type(self.monotonic_origin) not in (int, float)
            or not math.isfinite(self.monotonic_origin)
            or not 0 <= self.monotonic_origin <= time.monotonic()
            or self.wall_origin > datetime.now(UTC)
            or not 0 < (self.expires_at - self.not_before).total_seconds() <= 300
        ):
            raise ProviderRefused()

    @property
    def start(self) -> float:
        return (
            self.monotonic_origin + (self.not_before - self.wall_origin).total_seconds()
        )

    @property
    def deadline(self) -> float:
        return (
            self.monotonic_origin + (self.expires_at - self.wall_origin).total_seconds()
        )

    def require_open(self, claims: VerifiedClaims | None = None) -> None:
        deadline = self.deadline
        wall_end = self.expires_at.timestamp()
        if claims is not None:
            deadline = min(
                deadline,
                self.monotonic_origin + claims["exp"] - self.wall_origin.timestamp(),
            )
            wall_end = min(wall_end, claims["exp"])
        if not (
            self.not_before.timestamp() <= datetime.now(UTC).timestamp() < wall_end
            and self.start <= time.monotonic() < deadline
        ):
            raise ProviderRefused()


@dataclass(frozen=True, slots=True)
class CollectionCase:
    selection: CollectionSelection
    clock: CollectionCaseClock
    shared_packet: bytes
    frozen_window: bytes

    def __post_init__(self) -> None:
        from vendor_cp.deployment.gate0_launch import parse_run_document

        if (
            type(self.selection) is not CollectionSelection
            or type(self.clock) is not CollectionCaseClock
        ):
            raise ProviderRefused()
        packet = parse_run_document(self.shared_packet)
        window = FrozenIssuerWindow.parse(self.frozen_window)
        document = window.document
        capture = packet["capture"]
        if (
            self.selection.launch_packet_digest
            != "sha256:" + hashlib.sha256(self.shared_packet).hexdigest()
            or self.selection.window_digest != window.digest
            or self.selection.window_id != document["window_id"]
            or self.selection.case_kind != packet["case_kind"]
            or self.selection.case_kind != document["case_kind"]
            or str(self.selection.plan_id) != capture["plan_id"]
            or str(self.selection.target_id) != capture["target_id"]
            or str(self.selection.target_id) != document["target"]["id"]
            or packet["controller_ca_fingerprint"]
            != document["controller"]["ca_fingerprint"]
            or capture["window_digest"] != window.digest
            or document["github"]["run_id"] != packet["run_id"]
            or document["github"]["run_attempt"] != packet["run_attempt"]
            or packet["not_before"] != document["not_before"]
            or packet["expires_at"] != document["expires_at"]
            or self.clock.not_before
            != datetime.fromisoformat(packet["not_before"].replace("Z", "+00:00"))
            or self.clock.expires_at
            != datetime.fromisoformat(packet["expires_at"].replace("Z", "+00:00"))
        ):
            raise ProviderRefused()


def validate_collection_cases(cases: tuple[CollectionCase, ...]) -> None:
    """Pure A/B semantic validation, before any configured runtime is consulted."""
    if (
        type(cases) is not tuple
        or len(cases) != 2
        or any(type(c) is not CollectionCase for c in cases)
        or tuple(c.selection.case_kind for c in cases)
        != ("consume_replay", "withdrawal_later_use")
        or len({c.selection.window_id for c in cases}) != 2
        or len({c.selection.plan_id for c in cases}) != 2
        or len({(c.clock.wall_origin, c.clock.monotonic_origin) for c in cases}) != 1
    ):
        raise ProviderRefused()

    first, second = (FrozenIssuerWindow.parse(c.frozen_window).document for c in cases)
    if any(
        a == b
        for a, b in (
            (first["controller"]["lease_id"], second["controller"]["lease_id"]),
            (
                first["controller"]["fingerprint"],
                second["controller"]["fingerprint"],
            ),
            (
                first["controller"]["certificate_digest"],
                second["controller"]["certificate_digest"],
            ),
        )
    ):
        raise ProviderRefused()
    from vendor_cp.deployment.gate0_launch import parse_run_document

    packet_a, packet_b = (parse_run_document(c.shared_packet) for c in cases)
    if (
        packet_a["capture"]["approval_request_id"]
        == packet_b["capture"]["approval_request_id"]
        or cases[0].selection.window_digest == cases[1].selection.window_digest
        or (
            first["github"]["repository_id"],
            first["github"]["run_id"],
            first["github"]["run_attempt"],
        )
        != (
            second["github"]["repository_id"],
            second["github"]["run_id"],
            second["github"]["run_attempt"],
        )
    ):
        raise ProviderRefused()


@dataclass(frozen=True, slots=True)
class CollectionInstallation:
    """Root-loaded immutable A/B schedules; neither is activated by construction."""

    runtime: DatabaseRuntime
    jwks: BoundedJSONTransport
    cases: tuple[CollectionCase, CollectionCase]

    def __post_init__(self) -> None:
        validate_collection_cases(self.cases)
        if (
            type(self.runtime) is not DatabaseRuntime
            or type(self.jwks) is not BoundedJSONTransport
        ):
            raise ProviderRefused()

    def select(self, window_id: str) -> CollectionCase:
        found = [c for c in self.cases if c.selection.window_id == window_id]
        if len(found) != 1:
            raise ProviderRefused()
        found[0].clock.require_open()
        return found[0]

    def authenticate(self, case: CollectionCase, token: str) -> VerifiedClaims:
        if self.select(case.selection.window_id) is not case:
            raise ProviderRefused()
        claims = verify_github_claims(
            token, transport=self.jwks, deadline=case.clock.deadline
        )
        document = FrozenIssuerWindow.parse(case.frozen_window).document
        if (
            any(claims.get(k) != v for k, v in document["github"].items())
            or claims["iat"] < case.clock.not_before.timestamp()
        ):
            raise ProviderRefused()
        case.clock.require_open(claims)
        return claims


def _owner_scope(
    db: Session, selected: CollectionSelection, claims: VerifiedClaims
) -> tuple[
    PlanView, TargetView, FrozenIssuerWindow, RequestIdentityEvidence, dict[str, object]
]:
    from dotmac_deployment_control import get_plan, get_target

    plan = get_plan(db, selected.plan_id)
    if (
        plan is None
        or plan.id != selected.plan_id
        or plan.target_id != selected.target_id
    ):
        raise ProviderRefused()
    target = get_target(db, selected.target_id)
    if target is None:
        raise ProviderRefused()
    window = FrozenIssuerWindow.from_plan(plan)
    window.check_plan(plan, target)
    document = window.document
    if (
        window.digest != selected.window_digest
        or document["window_id"] != selected.window_id
        or document["case_kind"] != selected.case_kind
        or any(claims.get(k) != v for k, v in document["github"].items())
        or claims["iat"]
        < datetime.fromisoformat(
            document["not_before"].replace("Z", "+00:00")
        ).timestamp()
        or datetime.now(UTC).timestamp() >= claims["exp"]
        or plan.approval_decision_ref is None
        or plan.plan_digest is None
    ):
        raise ProviderRefused()
    identity = request_identity_evidence(db, UUID(plan.approval_decision_ref))
    if (
        identity.request_id != UUID(plan.approval_decision_ref)
        or identity.subject_type != SUBJECT_TYPE
        or identity.subject_id != issuer_approval_subject(plan)
        or identity.content_digest != plan.plan_digest
        or identity.policy_code != plan.approval_policy_code
        or identity.policy_version != plan.approval_policy_version
        or identity.completed_at is None
        or not 0 < len(identity.decisions) <= 64
        or not any(
            d.action == "approve" and d.decided_at <= identity.completed_at
            for d in identity.decisions
        )
    ):
        raise ProviderRefused()
    binding = {
        "launch_packet_digest": selected.launch_packet_digest,
        "case_kind": selected.case_kind,
        "window_id": selected.window_id,
        "window_digest": window.digest,
        "plan_id": str(plan.id),
        "plan_digest": plan.plan_digest,
        "target_id": str(target.id),
        "approval_request_id": str(identity.request_id),
        "run_id": document["github"]["run_id"],
        "run_attempt": document["github"]["run_attempt"],
    }
    return plan, target, window, identity, binding


def _approval(
    db: Session, selected: CollectionSelection, claims: VerifiedClaims
) -> dict[str, object]:
    _, _, window, identity, binding = _owner_scope(db, selected, claims)

    def capture(_held: HeldPlatformApproval) -> dict[str, object]:
        current, _, checked_window, checked_identity, checked_binding = _owner_scope(
            db, selected, claims
        )
        if (
            checked_binding != binding
            or checked_window != window
            or checked_identity != identity
            or current.descriptor_digest is None
            or current.authorized_images is None
            or not 0 < len(current.authorized_images) <= 64
        ):
            raise ProviderRefused()
        approved = approved_request_evidence(
            db,
            request_id=identity.request_id,
            subject_type=identity.subject_type,
            subject_id=identity.subject_id,
            content_hash=identity.content_digest.removeprefix("sha256:"),
        )
        return {
            "schema": "Gate0CollectionApproval.v1",
            "binding": binding,
            "frozen_window_b64": base64.b64encode(window.canonical_bytes).decode(
                "ascii"
            ),
            "descriptor_digest": current.descriptor_digest,
            "authorized_image_digests": [
                i.digest.canonical for i in current.authorized_images
            ],
            "approval": {
                "request_id": str(identity.request_id),
                "subject_type": identity.subject_type,
                "subject_id": identity.subject_id,
                "content_digest": identity.content_digest,
                "policy_code": identity.policy_code,
                "policy_version": identity.policy_version,
                "state": identity.state,
                "decided_at": approved.decided_at.isoformat(),
                "decisions": [
                    {
                        "id": str(d.decision_id),
                        "actor_id": str(d.actor_id),
                        "action": d.action,
                        "decided_at": d.decided_at.isoformat(),
                    }
                    for d in identity.decisions
                ],
            },
            "observed_at": datetime.now(UTC).isoformat(),
        }

    return held_transition(
        db,
        request_id=identity.request_id,
        subject_type=identity.subject_type,
        subject_id=identity.subject_id,
        content_digest=identity.content_digest,
        transition=capture,
    )


def _withdrawal(
    db: Session,
    selected: CollectionSelection,
    claims: VerifiedClaims,
    external_ref: str,
) -> dict[str, object]:
    plan, _, _, identity, binding = _owner_scope(db, selected, claims)
    withdrawal = withdrawal_for_reference(
        db, request_id=identity.request_id, external_ref=external_ref
    )
    result: dict[str, object] = {
        "schema": "Gate0CollectionWithdrawal.v1",
        "binding": binding,
        "state": "pending_withdrawal",
        "withdrawal": None,
        "relay": None,
        "observed_at": datetime.now(UTC).isoformat(),
    }
    if withdrawal is None:
        return result
    if (
        withdrawal.request_id != identity.request_id
        or withdrawal.approved_at != identity.completed_at
        or not any(
            d.action == "approve" and d.decided_at <= withdrawal.approved_at
            for d in identity.decisions
        )
    ):
        raise ProviderRefused()
    result["withdrawal"] = {
        k: v.isoformat() if isinstance(v, datetime) else str(v)
        for k, v in asdict(withdrawal).items()
    }
    result["state"] = "pending_relay"
    rows = outcomes_for_event(db, withdrawal.withdrawal_id, limit=3)
    if not rows:
        return result
    refs = issued_authorization_refs(db, plan.id, max_count=2)
    if len(refs) != 1 or len(rows) != 1:
        raise ProviderRefused()
    row = rows[0]
    if (
        row.disposition is not WithdrawalDisposition.APPLIED
        or row.event_type != "approval.withdrawn"
        or row.approval_request_id != identity.request_id
        or row.event_id != withdrawal.withdrawal_id
        or row.withdrawal_ref != str(withdrawal.withdrawal_id)
        or _DIGEST.fullmatch(row.payload_digest) is None
        or row.subject_type != identity.subject_type
        or row.subject_id != identity.subject_id
        or row.plan_id != plan.id
        or row.evidence.get("authorizations_revoked") != list(refs)
    ):
        raise ProviderRefused()
    result["state"] = "applied"
    result["relay"] = {
        "event_id": str(row.event_id),
        "payload_digest": row.payload_digest,
        "event_type": row.event_type,
        "request_id": str(row.approval_request_id),
        "subject_type": row.subject_type,
        "subject_id": row.subject_id,
        "plan_id": str(row.plan_id),
        "withdrawal_ref": row.withdrawal_ref,
        "disposition": row.disposition.value,
        "authorizations_revoked": list(refs),
    }
    return result


def project(
    installation: CollectionInstallation,
    case: CollectionCase,
    claims: VerifiedClaims,
    *,
    external_ref: str | None = None,
) -> bytes:
    """No response survives failed rollback/close; approval never uses SQL READ ONLY."""
    selected = case.selection
    case.clock.require_open(claims)
    if installation.select(selected.window_id) is not case:
        raise ProviderRefused()
    if external_ref is not None and selected.case_kind != "withdrawal_later_use":
        raise ProviderRefused()
    db: Session | None = None
    raw: bytes | None = None
    window_deadline = 0.0
    failed = False
    try:
        db = installation.runtime.platform_session_factory()
        if db.get_bind().dialect.name != "postgresql":
            raise ProviderRefused()
        if external_ref is not None:
            db.execute(text("SET TRANSACTION READ ONLY"))
        request_deadline = min(
            case.clock.deadline,
            case.clock.monotonic_origin
            + claims["exp"]
            - case.clock.wall_origin.timestamp(),
        )
        milliseconds = max(
            1, min(2000, int((request_deadline - time.monotonic()) * 1000))
        )
        for setting in ("statement_timeout", "lock_timeout"):
            db.execute(
                text("SELECT set_config(:setting, :duration, true)"),
                {"setting": setting, "duration": str(milliseconds)},
            )
        _, _, original_window, _, owner_binding = _owner_scope(db, selected, claims)
        from vendor_cp.deployment.gate0_launch import parse_run_document

        capture = parse_run_document(case.shared_packet)["capture"]
        if (
            original_window.canonical_bytes != case.frozen_window
            or owner_binding["plan_digest"] != capture["plan_digest"]
            or owner_binding["approval_request_id"] != capture["approval_request_id"]
        ):
            raise ProviderRefused()
        window_end = datetime.fromisoformat(
            original_window.document["expires_at"].replace("Z", "+00:00")
        )
        window_deadline = (
            case.clock.monotonic_origin
            + (window_end - case.clock.wall_origin).total_seconds()
        )
        if time.monotonic() >= window_deadline:
            raise ProviderRefused()
        result = (
            _approval(db, selected, claims)
            if external_ref is None
            else _withdrawal(db, selected, claims, external_ref)
        )
        raw = canonical(result)
        if len(raw) > 65536:
            raise ProviderRefused()
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
    if failed or raw is None:
        raise ProviderRefused()
    case.clock.require_open(claims)
    if (
        datetime.now(UTC).timestamp() >= claims["exp"]
        or time.monotonic() >= window_deadline
    ):
        raise ProviderRefused()
    return raw
