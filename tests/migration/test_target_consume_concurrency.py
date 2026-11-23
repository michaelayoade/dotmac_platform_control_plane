"""PostgreSQL proof: two concurrent consumes of one dispatch commit exactly once.

`test_consume_exactly_once_concurrent` (DESIGN-rev3 section 2.9). Two requests,
two sessions as the online `platform_api` role, one dispatch. A barrier holds both
INSIDE the finalizer, after each passed the "already committed?" check and before
either inserted its ledger row, so the unique index is what decides: one wins, the
loser's finalizer effect rolls back with its savepoint, and it is answered as a
replay (409 with the winner's marker).

The effect is a real row (`canary.consume.effect`): a loser whose effect survived
would leave a second one.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.deployment.target_api import contract as c
from vendor_cp.deployment.target_api.auth import AuthenticatedCall, TargetPrincipal
from vendor_cp.deployment.target_api.consumption import (
    CONSUME_LEDGER_SCOPE,
    ConsumptionService,
    Resolution,
)
from vendor_cp.deployment.target_api.handlers import HandlerResult

_TARGET = "dotmac-erp-v2/production/host-a"
_EFFECT_SCOPE = "canary.consume.effect"


class _Backend:
    def __init__(self, dispatch_id: str, barrier: threading.Barrier) -> None:
        self._dispatch_id = dispatch_id
        self._barrier = barrier

    def resolve(
        self, db: Session, *, request: Mapping[str, object], store_now: datetime
    ) -> Resolution:
        return Resolution(self._dispatch_id, _TARGET, "res-1", {"host": "host-a"})

    def reverify_attestation(
        self, db: Session, *, resolution: Resolution, request: Mapping[str, object]
    ) -> None:
        return None

    def covers_lease(
        self,
        db: Session,
        *,
        target_ref: str,
        dispatch_id: str,
        lease_id: str,
        store_now: datetime,
    ) -> bool:
        return True

    def finalize(
        self,
        db: Session,
        *,
        resolution: Resolution,
        request: Mapping[str, object],
        store_now: datetime,
    ) -> Mapping[str, object]:
        db.add(
            PlatformIdempotencyRecord(
                scope=_EFFECT_SCOPE,
                key=f"{self._dispatch_id}:{uuid.uuid4().hex}",
                operation="canary",
                status="executed",
                result={},
            )
        )
        db.flush()
        self._barrier.wait()
        return {"consumption_ref": f"control-dispatch:{self._dispatch_id}"}


def _call() -> AuthenticatedCall:
    now = datetime.now(UTC)
    coordinates = c.RequestCoordinates(
        method="POST",
        path=f"{c.BASE_PATH}/targets/{_TARGET}/consume",
        target_ref=_TARGET,
        route="consume",
        dispatch_id=None,
        credential_id="cred-0001",
        issued_at=c.format_stamp(now),
        nonce="0" * 32,
        signature_b64u="",
        signed_message=b"",
        nonce_ledger_key="",
    )
    return AuthenticatedCall(
        principal=TargetPrincipal(
            kind="target",
            principal_ref="target-credential:cred-0001",
            target_ref=_TARGET,
            credential_id="cred-0001",
        ),
        coordinates=coordinates,
        store_now=now,
        store_now_stamp=c.format_stamp(now),
    )


def test_consume_exactly_once_concurrent(postgres_url: str) -> None:
    dispatch_id = f"dispatch-{uuid.uuid4().hex}"
    barrier = threading.Barrier(2, timeout=30)
    service = ConsumptionService(_Backend(dispatch_id, barrier))
    engine = create_engine(
        make_url(postgres_url).set(username="platform_api", password=None)
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    request: dict[str, Any] = {
        "dispatch_id": dispatch_id,
        "resolution_id": "res-1",
        "lease_id": "lease-1",
    }
    results: list[HandlerResult] = []
    failures: list[BaseException] = []

    def consume() -> None:
        db: Session = factory()
        try:
            results.append(service.consume(_call(), db, request))
            db.commit()
        except BaseException as exc:
            db.rollback()
            failures.append(exc)
            barrier.abort()
        finally:
            db.close()

    threads = [threading.Thread(target=consume, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    try:
        assert all(not t.is_alive() for t in threads), "consume deadlocked"
        assert failures == []
        assert sorted(r.status for r in results) == [200, 409]
        winner = next(r for r in results if r.status == 200)
        loser = next(r for r in results if r.status == 409)
        assert loser.body["error"] == "already_consumed"
        assert loser.body["committed"] == winner.body["committed"]
        with factory() as db:
            ledger = db.scalar(
                select(func.count())
                .select_from(PlatformIdempotencyRecord)
                .where(
                    PlatformIdempotencyRecord.scope == CONSUME_LEDGER_SCOPE,
                    PlatformIdempotencyRecord.key == f"control-dispatch:{dispatch_id}",
                )
            )
            effects = db.scalar(
                select(func.count())
                .select_from(PlatformIdempotencyRecord)
                .where(
                    PlatformIdempotencyRecord.scope == _EFFECT_SCOPE,
                    PlatformIdempotencyRecord.key.like(f"{dispatch_id}:%"),
                )
            )
        assert ledger == 1
        assert effects == 1, "the loser's finalizer effect must roll back"
    finally:
        engine.dispose()
