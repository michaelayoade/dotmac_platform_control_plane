"""Vendor-accounts JSON API — a thin, platform-admin-only adapter.

Every route depends on the kernel's `require_platform_admin` (deny-case D4: auth
THROUGH the kernel, never re-implemented) and gets its `Session` from the
kernel's `get_platform_db` (deny-case D1: the kernel owns the one engine). The
route does no data access itself — it builds a typed command and delegates to
`vendor_cp.accounts.service` (the one owner of account state). `ConflictError`
raised by the service is mapped to HTTP 409 by the kernel's error handlers.

Dependencies are wired as `Annotated` types (FastAPI's recommended form) so the
`Depends(...)` lives in the annotation, not a mutable default.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import NotFoundError, PlatformAdmin
from dotmac_kernel.db import get_platform_db
from dotmac_kernel.platform_auth import require_platform_admin
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.accounts import service
from vendor_cp.accounts.schemas import AccountResponse, CreateAccountRequest

router = APIRouter(prefix="/platform/vendor/accounts", tags=["vendor-accounts"])

# Platform-admin identity + the one control-plane session, injected by the kernel.
Admin = Annotated[PlatformAdmin, Depends(require_platform_admin)]
Db = Annotated[Session, Depends(get_platform_db)]


@router.post("", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
def create_account(body: CreateAccountRequest, admin: Admin, db: Db) -> AccountResponse:
    result = service.create_account(
        db,
        service.CreateAccountCommand(
            command_id=body.command_id,
            external_ref=body.external_ref,
            display_name=body.display_name,
            actor_admin_id=admin.id,
        ),
    )
    return AccountResponse.from_view(result.account)


@router.get("", response_model=list[AccountResponse])
def list_accounts(_admin: Admin, db: Db) -> list[AccountResponse]:
    return [AccountResponse.from_view(v) for v in service.list_accounts(db)]


@router.get("/{account_id}", response_model=AccountResponse)
def get_account(account_id: UUID, _admin: Admin, db: Db) -> AccountResponse:
    view = service.get_account(db, account_id)
    if view is None:
        raise NotFoundError(f"vendor account {account_id} not found")
    return AccountResponse.from_view(view)


__all__ = ["router"]
