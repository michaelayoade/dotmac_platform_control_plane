"""Covers-in-consume (WP5c, DESIGN-rev3 2.6.1 step 3 / 2.6.2).

5b's atomic consume asks its `ConsumptionBackend.covers_lease` port whether a live
lease held by THIS dispatch run covers the consumption, on store time, in the same
transaction as the spent nonce and the effect. `LeaseCoveringBackend` fills that one
port with `cp_deploy_lease.deploy_covers` and delegates the other three (resolve,
attestation re-verification, the approval-guarded finalizer) to the backend it
wraps, so consumption is impossible without a covering lease and the wrapped
backend never needs to know a lease exists.

The call runs inside a SAVEPOINT. A refusal (`lease-expired`: released or past its
store-time expiry, `lease-foreign-run`, `lease-role-unbound`: no such lease) rolls
back only the savepoint and answers `False`, which consume turns into
`no_covering_lease`; the surrounding transaction stays healthy so the nonce still
commits. A store fault (unreachable, error) is raised: the request rolls back and
the caller retries. A lease id that is not a UUID is not a covering lease.

The run is `deploy_lease.dispatch_run(target_ref, dispatch_id)`, built from the
dispatch's own target, never from the request.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Any, Final

from sqlalchemy.orm import Session

from vendor_cp.deployment.deploy_lease import (
    DeployLeaseRefused,
    DeployLeaseStore,
    dispatch_run,
)
from vendor_cp.deployment.target_api.consumption import ConsumptionBackend, Resolution

__all__ = ["COVERING_REFUSALS", "LeaseCoveringBackend"]

#: The store refusals that mean "no lease covers this run" (everything else a
#: `covers` can say is a store fault and is raised).
COVERING_REFUSALS: Final = frozenset(
    {"lease-expired", "lease-foreign-run", "lease-role-unbound"}
)
_UUID: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class LeaseCoveringBackend:
    def __init__(
        self,
        inner: ConsumptionBackend,
        *,
        store_factory: Callable[[Any], Any] = DeployLeaseStore,
        savepoint: Callable[[Any], AbstractContextManager[Any]] = lambda db: (
            db.begin_nested()
        ),
    ) -> None:
        self._inner = inner
        self._store_factory = store_factory
        self._savepoint = savepoint

    def resolve(
        self, db: Session, *, request: Mapping[str, object], store_now: datetime
    ) -> Resolution:
        return self._inner.resolve(db, request=request, store_now=store_now)

    def reverify_attestation(
        self, db: Session, *, resolution: Resolution, request: Mapping[str, object]
    ) -> None:
        self._inner.reverify_attestation(db, resolution=resolution, request=request)

    def covers_lease(
        self,
        db: Session,
        *,
        target_ref: str,
        dispatch_id: str,
        lease_id: str,
        store_now: datetime,
    ) -> bool:
        if _UUID.fullmatch(lease_id) is None:
            return False
        try:
            with self._savepoint(db):
                self._store_factory(db).covers(
                    lease_id=lease_id,
                    dispatch_run=dispatch_run(target_ref, dispatch_id),
                )
        except DeployLeaseRefused as refusal:
            if refusal.code in COVERING_REFUSALS:
                return False
            raise
        return True

    def commit_consumption(
        self,
        db: Session,
        *,
        resolution: Resolution,
        request: Mapping[str, object],
        store_now: datetime,
    ) -> Mapping[str, object]:
        return self._inner.commit_consumption(
            db, resolution=resolution, request=request, store_now=store_now
        )
