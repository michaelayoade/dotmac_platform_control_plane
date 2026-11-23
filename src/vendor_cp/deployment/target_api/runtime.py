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
from vendor_cp.deployment.target_api.consumption import (
    ConsumptionBackend,
    ConsumptionService,
    MaterialsHandler,
    MaterialsSource,
    ObservationHandler,
    ObservationSink,
    TargetApiHandlers,
    UnwiredBackend,
)
from vendor_cp.deployment.target_api.credentials import ControlObservationSink
from vendor_cp.deployment.target_api.handlers import TargetHandlers
from vendor_cp.deployment.target_api.response_signing import load_response_signer
from vendor_cp.deployment.target_api.router import TargetApiRuntime, build_router

__all__ = ["install_runtime", "router", "runtime"]

_runtime: TargetApiRuntime | None = None


def install_runtime(
    *,
    directory: CredentialDirectory,
    sessions: Callable[[], AbstractContextManager[Session]],
    handlers: TargetHandlers | None = None,
    backend: ConsumptionBackend | None = None,
    materials: MaterialsSource | None = None,
    observations: ObservationSink | None = None,
    environ: Mapping[str, str] | None = None,
) -> TargetApiRuntime:
    """Compose the production runtime: Kernel nonce ledger, DB clock, config key.

    The authenticator keeps its default denied-key set; nothing here can lower it.
    Without a composed `backend` (resolve, attestation re-verification, lease
    check, finalizer) consumption refuses closed; without a `materials` source
    the materials endpoint refuses. Observations go to Control's own ingestion.
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
        handlers=handlers
        or TargetApiHandlers(
            consumption=ConsumptionService(backend or UnwiredBackend()),
            materials=MaterialsHandler(materials),
            observations=ObservationHandler(observations or ControlObservationSink()),
        ),
        sessions=sessions,
    )
    return _runtime


def runtime() -> TargetApiRuntime:
    if _runtime is None:
        raise RuntimeError("the target API runtime is not installed")
    return _runtime


#: The router, bound to the installed runtime. Not part of any profile yet.
router = build_router(runtime)
