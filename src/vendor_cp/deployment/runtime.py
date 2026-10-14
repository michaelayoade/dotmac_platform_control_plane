"""Bind the installed Control/Foundation owners and the live approval barrier.

This is the startup seam, not a request-selected provider registry. It imports
only public owner objects and accepts local observation ports, never preverified
results or an alternative approval barrier. The application still needs an
eligible Foundation pin and an admitted immutable selection before execution.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.deployment.host_admission_adapter import (
    ControlFoundationV3Bindings,
    FoundationHostV3Bindings,
    FoundationV3ProviderPair,
    FoundationV3Sources,
    HostAdmissionObservation,
    compose_foundation_v3_providers,
)

if TYPE_CHECKING:
    from dotmac_deployment_foundation import AttestationVerifier, ExecutionContextV3


def _trust_policy_from_context(resolved: object) -> object:
    from dotmac_deployment_control import (
        HostAdmissionRootContextV1,
        HostAdmissionVerificationContextV1,
    )
    from dotmac_deployment_foundation import (
        AttestationTrustPolicy,
        AttestationTrustRootV2,
    )

    if type(resolved) is not HostAdmissionVerificationContextV1:
        raise TypeError("actual Control verification context required")

    def root(value: HostAdmissionRootContextV1) -> AttestationTrustRootV2:
        # Control already emits Foundation's standard padded-base64 key.
        # Copy all signed root coordinates without translating their encoding.
        return AttestationTrustRootV2(
            public_key_fingerprint=value.public_key_fingerprint,
            public_key_base64=value.public_key_base64,
            purpose=value.purpose,
            custody_domain=value.custody_domain,
            issuer=value.issuer,
            key_id=value.key_id,
            algorithm=value.algorithm,
            trust_root_version=value.root_version,
            not_before=value.not_before.isoformat().replace("+00:00", "Z"),
            not_after=value.not_after.isoformat().replace("+00:00", "Z"),
            revoked=value.revoked,
        )

    return AttestationTrustPolicy(
        candidate_roots=(root(resolved.candidate_root),),
        installed_roots=(root(resolved.installed_root),),
        candidate_audience=resolved.candidate_audience,
        installed_audience=resolved.installed_audience,
    )


def build_foundation_v3_providers(
    *,
    sessions: Callable[[], Session],
    host_admission: Callable[[], HostAdmissionObservation],
    execution_context: Callable[[], ExecutionContextV3],
    clock: Callable[[], datetime],
    attestation_verifier: AttestationVerifier,
) -> FoundationV3ProviderPair:
    """Build one F2/V3 pair using actual installed public owner contracts.

    Call once for an execution composition, and share the resulting pair across
    its executor constructors. These factories are startup-owned; no browser,
    CLI command or dispatch document may choose them. No import fallback or
    approval-exempt substitute exists when a required owner is absent.
    """
    import dotmac_deployment_control as control
    import dotmac_deployment_foundation as foundation

    from vendor_cp.deployment.foundation_approval import hold_foundation_transition

    def hold(
        db: Session,
        *,
        plan_id: UUID,
        transition: Callable[[object], object],
    ) -> object:
        return hold_foundation_transition(
            db, plan_id=plan_id, transition=lambda held: transition(held)
        )

    return compose_foundation_v3_providers(
        control=ControlFoundationV3Bindings(
            resolve_context=control.resolve_host_admission_context,
            finalize=control.admit_and_consume_host_admission,
            attest_pair=control.attest_foundation_execution_pair,
            lookup_committed=control.lookup_foundation_execution_consumption,
            get_plan=control.get_plan,
            foreign_root_type=control.HostAdmissionForeignRootV1,
            foreign_evidence_type=control.HostAdmissionForeignVerificationEvidenceV1,
            execution_context_type=control.FoundationExecutionContextV1,
            consumption_request_type=control.FoundationDispatchConsumptionV1,
        ),
        foundation=FoundationHostV3Bindings(
            admit_host_source=foundation.admit_host_source,
            trust_policy_from_context=_trust_policy_from_context,
            verifier=attestation_verifier,
            trace_type=foundation.HostSourceAdmissionTrace,
            pair_result_type=foundation.AttestationPairVerificationResultV1,
            consumption_request_type=foundation.ControlConsumptionRequestV3,
            execution_context_type=foundation.ExecutionContextV3,
        ),
        sources=FoundationV3Sources(
            sessions=sessions,
            host_admission=host_admission,
            execution_context=execution_context,
            clock=clock,
            held_transition=hold,
        ),
    )


__all__ = ["build_foundation_v3_providers"]
