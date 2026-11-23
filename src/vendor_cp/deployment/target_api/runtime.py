"""Startup composition of the target API. Nothing is request-selected."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager

from sqlalchemy.orm import Session

from vendor_cp.deployment.target_api.auth import (
    CredentialDirectory,
    KernelNonceLedger,
    SlidingWindowRateLimiter,
    TargetRequestAuthenticator,
    database_store_now,
)
from vendor_cp.deployment.target_api.handlers import (
    NotImplementedHandlers,
    TargetHandlers,
)
from vendor_cp.deployment.target_api.response_signing import load_response_signer
from vendor_cp.deployment.target_api.router import TargetApiRuntime, build_router

__all__ = ["install_runtime", "router", "runtime"]

_runtime: TargetApiRuntime | None = None


def install_runtime(
    *,
    directory: CredentialDirectory,
    sessions: Callable[[], AbstractContextManager[Session]],
    handlers: TargetHandlers | None = None,
    environ: Mapping[str, str] | None = None,
) -> TargetApiRuntime:
    """Compose the production runtime: Kernel nonce ledger, DB clock, config key.

    The authenticator keeps its default denied-key set; nothing here can lower it.
    """
    global _runtime
    env = os.environ if environ is None else environ
    _runtime = TargetApiRuntime(
        authenticator=TargetRequestAuthenticator(
            directory=directory,
            nonces=KernelNonceLedger(),
            clock=database_store_now,
            limiter=SlidingWindowRateLimiter(),
        ),
        signer=load_response_signer(env),
        handlers=handlers or NotImplementedHandlers(),
        sessions=sessions,
    )
    return _runtime


def runtime() -> TargetApiRuntime:
    if _runtime is None:
        raise RuntimeError("the target API runtime is not installed")
    return _runtime


#: The router, bound to the installed runtime. Not part of any profile yet.
router = build_router(runtime)
