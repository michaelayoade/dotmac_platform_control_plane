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
    ExecutionObservationEnvelopeV1,
    ExecutionObservationRefusedError,
    RecordObservationCommand,
    TargetCredential,
    credential_is_eligible,
    record_observation,
)
from dotmac_kernel import write_platform_audit_event
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import AuthenticatedCall, CredentialRecord
from vendor_cp.deployment.target_api.handlers import HandlerResult

__all__ = [
    "TARGET_CREDENTIAL_ALGORITHM",
    "ControlCredentialDirectory",
    "OBSERVATION_MISMATCH_ACTION",
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


class ControlObservationSink:
    """`POST observations`: Control's own observation ingestion, over the exact bytes.

    The body is parsed with Control's public parser, only to compare what the
    envelope CLAIMS with who is calling: a statement whose `key_id` is not the
    caller's credential, or whose `target_ref` is not the caller's target, is
    refused with a 403 and an audit row, and never reaches Control. A body that
    does not parse is still forwarded, so Control records the malformed arrival
    (it records EVERY arrival). Control derives the digest, verifies and stores
    those exact bytes; the command id is the body's digest, so a retried POST
    with a new nonce is the same command.
    """

    def __init__(
        self,
        parse: Callable[[bytes], Any] | None = None,
        record: Callable[..., Any] | None = None,
    ) -> None:
        self._parse = parse or ExecutionObservationEnvelopeV1.parse_bytes
        self._record = record or record_observation

    def record(
        self, db: Session, *, call: AuthenticatedCall, body: bytes
    ) -> HandlerResult:
        try:
            statement = self._parse(body).statement
        except ExecutionObservationRefusedError:
            statement = None
        if statement is not None and (
            statement.key_id != call.principal.credential_id
            or statement.target_ref != call.principal.target_ref
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
                    "claimed_key_id": str(statement.key_id),
                    "claimed_target_ref": str(statement.target_ref),
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
