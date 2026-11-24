"""Control-backed ports for the target API: credentials and observations.

Reads Control's `TargetCredential` (the target's own PUBLIC verification key,
enrolled by `enrol_credential` for the execution-observation purpose) through
Control's public surface. It holds no private material and writes nothing.
`credential_is_eligible` evaluates the stored half-open window at the STORE time
the caller supplies, so an expired or revoked credential refuses on database
time, never on the caller's clock.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime
from typing import Any

from dotmac_deployment_control import (
    EXECUTION_OBSERVATION_PURPOSE,
    RecordObservationCommand,
    TargetCredential,
    credential_is_eligible,
    record_observation,
)
from dotmac_kernel import write_platform_audit_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import AuthenticatedCall, CredentialRecord
from vendor_cp.deployment.target_api.handlers import HandlerResult

__all__ = [
    "TARGET_CREDENTIAL_ALGORITHM",
    "ControlCredentialDirectory",
    "OBSERVATION_MISMATCH_ACTION",
    "observation_claims",
    "ControlObservationSink",
]

TARGET_CREDENTIAL_ALGORITHM = "ed25519"


class ControlCredentialDirectory:
    def lookup(
        self, db: Session, credential_id: str, *, at: datetime
    ) -> CredentialRecord | None:
        row = db.execute(
            select(TargetCredential).where(TargetCredential.key_id == credential_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        eligible, target_ref = credential_is_eligible(db, credential_id, at=at)
        if target_ref is None:
            return None
        return CredentialRecord(
            credential_id=row.key_id,
            target_ref=target_ref,
            public_key_b64u=row.public_key_b64,
            eligible=eligible,
            purpose_ok=(
                row.purpose == EXECUTION_OBSERVATION_PURPOSE
                and row.algorithm == TARGET_CREDENTIAL_ALGORITHM
            ),
        )


OBSERVATION_MISMATCH_ACTION = "vendor.deploy_target_api.observation_principal_mismatch"


def observation_claims(body: bytes) -> tuple[str, str] | None:
    """`(key_id, target_ref)` an observation envelope CLAIMS, or None if unreadable.

    Both observation wires (v1 `ExecutionObservationEnvelopeV1` and v2
    `AgentObservationEnvelopeV2`, `contract/target_api_v2.json`) are
    `{"statement": {..., "key_id", "target_ref"}, "signature"}`. CP pins Control a17,
    which has no v2 parser, so the claims are read with the contract's own strict
    JSON rules (duplicate keys refused, as Control refuses them). Control remains
    the only verifier: this reads WHO the envelope says it is from, never whether
    it is true. When a18 is pinned, `AgentObservationEnvelopeV2.parse_bytes`
    replaces this reader.
    """
    try:
        document = c.parse_json_body(body)
    except c.TargetApiError:
        return None
    statement = document.get("statement") if isinstance(document, dict) else None
    if not isinstance(statement, dict):
        return None
    key_id, target_ref = statement.get("key_id"), statement.get("target_ref")
    if isinstance(key_id, str) and isinstance(target_ref, str):
        return key_id, target_ref
    return None


class ControlObservationSink:
    """`POST observations`: Control's own observation ingestion, over the exact bytes.

    A statement whose `key_id` is not the caller's credential, or whose
    `target_ref` is not the caller's target, is refused with a 403 and an audit
    row, and never reaches Control. A body whose claims cannot be read is still
    forwarded, so Control records the malformed arrival (it records EVERY
    arrival). Control derives the digest, verifies and stores those exact bytes;
    the command id is the body's digest, so a retried POST with a new nonce is the
    same command.
    """

    def __init__(
        self,
        claims: Callable[[bytes], tuple[str, str] | None] | None = None,
        record: Callable[..., Any] | None = None,
    ) -> None:
        self._claims = claims or observation_claims
        self._record = record or record_observation

    def record(
        self, db: Session, *, call: AuthenticatedCall, body: bytes
    ) -> HandlerResult:
        claimed = self._claims(body)
        if claimed is not None and claimed != (
            call.principal.credential_id,
            call.principal.target_ref,
        ):
            write_platform_audit_event(
                db,
                actor_admin_id=None,
                # a literal: the audit-vocabulary sweep reads `action=` literals
                action="vendor.deploy_target_api.observation_principal_mismatch",
                entity_type="target_credential",
                entity_id=call.principal.credential_id,
                details={
                    "principal_ref": call.principal.principal_ref,
                    "principal_target_ref": call.principal.target_ref,
                    "claimed_key_id": claimed[0],
                    "claimed_target_ref": claimed[1],
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                },
            )
            return HandlerResult(403, {"error": "observation_principal_mismatch"})
        verdict = self._record(
            db,
            RecordObservationCommand(
                command_id=f"target-observation:{hashlib.sha256(body).hexdigest()}",
                observation=body,
                actor_ref=call.principal.principal_ref,
            ),
        )
        return HandlerResult(
            200,
            {
                "disposition": verdict.disposition,
                "changed_state": verdict.changed_state,
                "attempt_id": str(verdict.attempt_id),
                "receipt_id": (
                    None if verdict.receipt_id is None else str(verdict.receipt_id)
                ),
                "verdict": verdict.verdict,
            },
        )
