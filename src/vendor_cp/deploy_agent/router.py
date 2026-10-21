"""One platform bearer auth owner; public signed fetch and signed ingest."""

from collections.abc import Callable
from typing import Annotated, cast

from dotmac_kernel import PlatformAdmin
from dotmac_kernel.deps import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from . import contracts as c
from .contracts import ContractError, canonical_json, read_json
from .models import (
    ActivateKey,
    Drift,
    IngestOutcome,
    IssueCommand,
    KeyRecord,
    KeyState,
    PlanPreview,
    PreviewCommand,
    RegisterKey,
    RevokeKey,
    parse_command,
)
from .runtime import service

router = APIRouter(prefix="/platform/deploy", tags=["deploy-agent"])
Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


def call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ContractError as error:
        status = (
            503
            if error.code
            in {
                "feature_disabled",
                "ledger_unavailable",
                "ledger_dirty",
                "ledger_conflict",
            }
            else 409
        )
        raise HTTPException(status_code=status, detail=error.code) from None


async def body(request: Request) -> dict[str, object]:
    raw = await request.body()
    if len(raw) > 262144:
        raise HTTPException(413, "schema_violation")
    try:
        return read_json(raw)
    except ContractError as error:
        raise HTTPException(422, error.code) from None


@router.post("/desired-state")
async def issue(request: Request, admin: Admin, db: Db) -> c.Envelope | PlanPreview:
    raw = await body(request)
    model = PreviewCommand if raw.get("mode") == "preview" else IssueCommand
    command = call(lambda: parse_command(raw, model))
    return call(
        lambda: service().issue(
            db, cast(IssueCommand | PreviewCommand, command), actor_admin_id=admin.id
        )
    )


@router.get("/desired-state/{product}/{environment}/{host}")
def latest(product: str, environment: str, host: str, response: Response) -> c.Envelope:
    response.headers["Cache-Control"] = "no-store"
    result = call(lambda: service().latest(product, environment, host))
    if result is None:
        raise HTTPException(404, "desired_state_absent")
    return result


@router.post("/applied-state")
async def ingest(request: Request, db: Db) -> IngestOutcome:
    envelope = await body(request)
    if canonical_json(envelope) != await request.body():
        raise HTTPException(422, "noncanonical_envelope")
    command = call(lambda: parse_command(envelope, c.Envelope))
    return call(lambda: service().ingest(db, cast(c.Envelope, command)))


@router.post("/host-keys")
async def register(request: Request, admin: Admin, db: Db) -> KeyRecord | KeyState:
    raw = await body(request)
    model = RevokeKey if raw.get("operation") == "revoke" else RegisterKey
    command = call(lambda: parse_command(raw, model))
    return call(
        lambda: service().register(
            db, cast(RegisterKey | RevokeKey, command), actor_admin_id=admin.id
        )
    )


@router.post("/host-keys/{key_id}/challenge")
def challenge(key_id: str, admin: Admin, db: Db) -> c.Challenge:
    return call(lambda: service().challenge(db, key_id, actor_admin_id=admin.id))


@router.post("/host-keys/challenge-response")
async def activate(request: Request, admin: Admin, db: Db) -> KeyState:
    raw = await body(request)
    command = call(lambda: parse_command(raw, ActivateKey))
    return call(
        lambda: service().activate(
            db, cast(ActivateKey, command), actor_admin_id=admin.id
        )
    )


@router.get("/drift")
def drift(_admin: Admin) -> Drift:
    return call(lambda: service().drift())
