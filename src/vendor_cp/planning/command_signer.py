"""Fail-closed runtime dependency for Vendor-owned command signing.

The assembly installs a held signer and custody policy. This module never loads
key material and has no fallback signer, audience or reused licence/session key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException

from vendor_cp.planning.service import (
    CommandKeySeparationPolicy,
    DeploymentCommandSigningKey,
)


@dataclass(frozen=True, slots=True)
class RuntimeCommandSigner:
    signer: DeploymentCommandSigningKey
    key_separation: CommandKeySeparationPolicy
    audience: str


_runtime: RuntimeCommandSigner | None = None


def install_runtime_command_signer(runtime: RuntimeCommandSigner) -> None:
    global _runtime
    if not runtime.audience or runtime.audience.strip() != runtime.audience:
        raise ValueError("Integrator command audience must be non-blank and trimmed")
    _runtime = runtime


def require_runtime_command_signer() -> RuntimeCommandSigner:
    if _runtime is None:
        raise HTTPException(503, "Integrator command signer is not installed")
    return _runtime


CommandSigner = Annotated[RuntimeCommandSigner, Depends(require_runtime_command_signer)]

__all__ = [
    "CommandSigner",
    "RuntimeCommandSigner",
    "install_runtime_command_signer",
    "require_runtime_command_signer",
]
