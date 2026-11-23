"""Control-backed credential directory for the target API.

Reads Control's `TargetCredential` (the target's own PUBLIC verification key,
enrolled by `enrol_credential` for the execution-observation purpose) through
Control's public surface. It holds no private material and writes nothing.
`credential_is_eligible` evaluates the stored half-open window at the STORE time
the caller supplies, so an expired or revoked credential refuses on database
time, never on the caller's clock.
"""

from __future__ import annotations

from datetime import datetime

from dotmac_deployment_control import (
    EXECUTION_OBSERVATION_PURPOSE,
    TargetCredential,
    credential_is_eligible,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import CredentialRecord

__all__ = ["TARGET_CREDENTIAL_ALGORITHM", "ControlCredentialDirectory"]

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
