"""Two workload-authenticated reads; installed authority is absent by default.

Withdrawal uses a fixed header instead of a URL query so a human reference is
not copied into ordinary access-log URLs. Neither operation changes owner state.
The installed ASGI entrypoint binds the fixed root-owned configuration once
before exposing these routes. HTTP cannot supply installation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from dotmac_kernel.features import FeatureManifest
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from vendor_cp.deployment.gate0_collection_projection import (
    CollectionCase,
    CollectionInstallation,
    project,
)
from vendor_cp.deployment.gate0_github_jwt import VerifiedClaims
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


@dataclass(frozen=True, slots=True)
class CollectionScope:
    installation: CollectionInstallation
    case: CollectionCase
    claims: VerifiedClaims


def require_gate0_collection_workload(
    request: Request, window_id: str
) -> CollectionScope:
    """The route's single auth owner; JWT verified before opening an owner session."""
    try:
        installation = getattr(request.app.state, "gate0_collection_installation", None)
        if type(installation) is not CollectionInstallation or request.query_params:
            raise ProviderRefused()
        headers = request.headers.getlist("authorization")
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            raise ProviderRefused()
        selected = installation.select(window_id)
        claims = installation.authenticate(selected, headers[0][7:])
        return CollectionScope(installation, selected, claims)
    except Exception:
        raise HTTPException(403, "gate0_collection_refused") from None


Scope = Annotated[CollectionScope, Depends(require_gate0_collection_workload)]
router = APIRouter(
    prefix="/platform/vendor/gate0/collection/windows", tags=["gate0_collection_reads"]
)


def _empty_request(request: Request) -> bool:
    lengths = request.headers.getlist("content-length")
    return not request.headers.getlist("transfer-encoding") and (
        not lengths or lengths == ["0"]
    )


def _response(scope: CollectionScope, external_ref: str | None = None) -> Response:
    try:
        raw = project(
            scope.installation, scope.case, scope.claims, external_ref=external_ref
        )
        return Response(
            raw, media_type="application/json", headers={"Cache-Control": "no-store"}
        )
    except Exception:
        raise HTTPException(403, "gate0_collection_refused") from None


@router.get("/{window_id}/approval")
def approval(request: Request, scope: Scope) -> Response:
    if request.headers.getlist(
        "x-dotmac-gate0-withdrawal-reference"
    ) or not _empty_request(request):
        raise HTTPException(403, "gate0_collection_refused")
    return _response(scope)


@router.get("/{window_id}/withdrawal")
def withdrawal(request: Request, scope: Scope) -> Response:
    refs = request.headers.getlist("x-dotmac-gate0-withdrawal-reference")
    if (
        len(refs) != 1
        or not 0 < len(refs[0]) <= 200
        or refs[0] != refs[0].strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in refs[0])
        or not _empty_request(request)
    ):
        raise HTTPException(403, "gate0_collection_refused")
    return _response(scope, refs[0])


feature = FeatureManifest(
    name="gate0_collection_reads",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
