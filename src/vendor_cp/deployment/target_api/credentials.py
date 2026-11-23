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
from collections.abc import Mapping
from datetime import datetime

from dotmac_deployment_control import (
    EXECUTION_OBSERVATION_PURPOSE,
    RecordObservationCommand,
    TargetCredential,
    credential_is_eligible,
    record_observation,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import AuthenticatedCall, CredentialRecord

__all__ = [
    "TARGET_CREDENTIAL_ALGORITHM",
    "ControlCredentialDirectory",
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


class ControlObservationSink:
    """`POST observations`: Control's own observation ingestion, over the exact bytes.

    Control derives the digest, parses, verifies and stores that one value, and
    records EVERY arrival (an unknown key, a bad signature and a replay all leave
    an attempt row). A byte-identical repeat returns the original verdict, so the
    command id is the body's digest: a retried POST with a new nonce is the same
    command.
    """

    def record(
        self, db: Session, *, call: AuthenticatedCall, body: bytes
    ) -> Mapping[str, object]:
        verdict = record_observation(
            db,
            RecordObservationCommand(
                command_id=f"target-observation:{hashlib.sha256(body).hexdigest()}",
                observation=body,
                actor_ref=call.principal.principal_ref,
            ),
        )
        return {
            "disposition": verdict.disposition,
            "changed_state": verdict.changed_state,
            "attempt_id": str(verdict.attempt_id),
            "receipt_id": None
            if verdict.receipt_id is None
            else str(verdict.receipt_id),
            "verdict": verdict.verdict,
        }
