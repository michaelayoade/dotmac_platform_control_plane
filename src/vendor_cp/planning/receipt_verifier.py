"""Process-held Integrator receipt verifier dependency.

The concrete held-key adapter is installed by the assembly. This module owns no
key loading and has no default: missing authentication material fails closed.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException

from vendor_cp.planning.service import IntegratorReceiptSignatureVerifier

_runtime_verifier: IntegratorReceiptSignatureVerifier | None = None


def install_runtime_integrator_receipt_verifier(
    verifier: IntegratorReceiptSignatureVerifier,
) -> None:
    global _runtime_verifier
    _runtime_verifier = verifier


def require_runtime_integrator_receipt_verifier() -> IntegratorReceiptSignatureVerifier:
    if _runtime_verifier is None:
        raise HTTPException(503, "Integrator receipt verifier is not installed")
    return _runtime_verifier


ReceiptVerifier = Annotated[
    IntegratorReceiptSignatureVerifier,
    Depends(require_runtime_integrator_receipt_verifier),
]

__all__ = [
    "ReceiptVerifier",
    "install_runtime_integrator_receipt_verifier",
    "require_runtime_integrator_receipt_verifier",
]
