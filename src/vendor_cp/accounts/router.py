"""Tenant-scoped vendor-accounts JSON API (option C spike) — a thin adapter.

The contrast with option A's platform router: this uses TENANT auth
(`require_user_auth` → the acting `Party`) and TENANT context (`require_tenant`
→ the `Tenant`), and the one control-plane session comes from `get_db` (the
tenant/`app_user` session, RLS-enforced) rather than `get_platform_db`. The
account is created in the CALLER's tenant — which only makes sense if the vendor
control plane is itself a tenant, the awkwardness this spike exists to show.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from dotmac_kernel import NotFoundError, Party, Tenant
from dotmac_kernel.deps import get_db, require_tenant, require_user_auth
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from vendor_cp.accounts import service
from vendor_cp.accounts.schemas import AccountResponse, CreateAccountRequest

router = APIRouter(prefix="/vendor/accounts", tags=["vendor-accounts"])

Actor = Annotated[Party, Depends(require_user_auth)]
TenantCtx = Annotated[Tenant, Depends(require_tenant)]
Db = Annotated[Session, Depends(get_db)]


@router.post("", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
def create_account(
    body: CreateAccountRequest, actor: Actor, tenant: TenantCtx, db: Db
) -> AccountResponse:
    result = service.create_account(
        db,
        service.CreateAccountCommand(
            command_id=body.command_id,
            tenant_id=tenant.id,
            external_ref=body.external_ref,
            display_name=body.display_name,
            actor_party_id=actor.id,
        ),
    )
    return AccountResponse.from_view(result.account)


@router.get("", response_model=list[AccountResponse])
def list_accounts(_actor: Actor, tenant: TenantCtx, db: Db) -> list[AccountResponse]:
    return [AccountResponse.from_view(v) for v in service.list_accounts(db, tenant.id)]


@router.get("/{account_id}", response_model=AccountResponse)
def get_account(
    account_id: UUID, _actor: Actor, _tenant: TenantCtx, db: Db
) -> AccountResponse:
    view = service.get_account(db, account_id)
    if view is None:
        raise NotFoundError(f"vendor account {account_id} not found")
    return AccountResponse.from_view(view)


__all__ = ["router"]
