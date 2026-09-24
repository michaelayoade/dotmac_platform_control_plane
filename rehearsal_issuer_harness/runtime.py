"""Thin invocation adapter: the installed Control owner makes every decision."""

from __future__ import annotations

from datetime import timedelta

from dotmac_deployment_control.rehearsal_issuer_authorization import (
    RehearsalIssuerAuthorizationV1,
)
from dotmac_deployment_control.rehearsal_issuer_issuance import (
    install_rehearsal_issuer_security,
    issue_rehearsal_issuer_authorization_for_plan,
)
from sqlalchemy.orm import Session

from rehearsal_issuer_harness.security import AuthorizationSecurity, HarnessSecurity
from vendor_cp.deployment.rehearsal_issuer_seam import RehearsalIssuerInvocation


def install_disposable_security() -> tuple[AuthorizationSecurity, HarnessSecurity]:
    authorization = AuthorizationSecurity()
    harness = HarnessSecurity()
    install_rehearsal_issuer_security(
        signer=authorization,
        authorization_verifier=authorization,
        harness_verifier=harness,
        authorization_ttl=timedelta(hours=1),
    )
    return authorization, harness


def issue_from_leaf(
    db: Session, invocation: RehearsalIssuerInvocation
) -> RehearsalIssuerAuthorizationV1:
    """Pass the exact leaf mapping and opaque evidence into real Control a14."""
    return issue_rehearsal_issuer_authorization_for_plan(
        db,
        dict(invocation.to_control_request()),
        harness_evidence_document=invocation.harness_evidence_document,
    )
