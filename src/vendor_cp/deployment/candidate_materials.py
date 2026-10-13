"""Accept candidate configuration and local signer files, without runtime startup.

Ready means only that existing configuration/material owners accepted their
inputs. This does not establish database, OpenBao, DNS or network availability.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from typing import Literal

from vendor_cp.config_errors import ProductionConfigurationError

Status = Literal["ready", "refused", "unavailable"]
Role = Literal["app", "relay"]

# Source-only coverage declaration, held against the accepted descriptor in tests.
ROLE_MATERIALS = {
    "app": frozenset({"DATABASE_URL", "PLATFORM_DATABASE_URL"}),
    "relay": frozenset(
        {
            "DATABASE_URL",
            "PLATFORM_DATABASE_URL",
            "VENDOR_RELAY_DISPATCHER_DATABASE_URL",
        }
    ),
}
CHECK_NAMES = frozenset(
    {
        "kernel_configuration",
        "vendor_configuration",
        "licence_signing",
        "licence_overlap_signing",
        "relay_dispatcher",
        "probe_execution",
    }
)


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: Status

    def __post_init__(self) -> None:
        if self.name not in CHECK_NAMES or self.status not in STATUS_EXITS:
            raise ValueError("invalid probe check")


STATUS_EXITS = {"ready": 0, "refused": 3, "unavailable": 4}


@dataclass(frozen=True, slots=True)
class CandidateMaterialProbeResult:
    checks: tuple[Check, ...]

    def __post_init__(self) -> None:
        names = [check.name for check in self.checks]
        if not names or len(set(names)) != len(names):
            raise ValueError("invalid probe checks")

    @property
    def status(self) -> Status:
        if any(check.status == "refused" for check in self.checks):
            return "refused"
        if any(check.status == "unavailable" for check in self.checks):
            return "unavailable"
        return "ready"

    @property
    def exit_code(self) -> int:
        return STATUS_EXITS[self.status]

    def json_document(self) -> str:
        return json.dumps(
            {
                "schema": "CandidateMaterialProbeResult.v1",
                "status": self.status,
                "checks": [
                    {"name": check.name, "status": check.status}
                    for check in self.checks
                ],
            },
            separators=(",", ":"),
            ensure_ascii=True,
        )


@contextmanager
def quiet_evaluation() -> Iterator[None]:
    """Discard diagnostics rather than retaining potentially sensitive prose."""
    previous = logging.root.manager.disable
    try:
        logging.disable(2**63 - 1)
        with (
            open(os.devnull, "w") as sink,
            redirect_stdout(sink),
            redirect_stderr(sink),
        ):
            yield
    finally:
        logging.disable(previous)


def unavailable_result() -> CandidateMaterialProbeResult:
    return CandidateMaterialProbeResult((Check("probe_execution", "unavailable"),))


def _evaluate(
    name: str, action: Callable[[], object], refusals: tuple[type[Exception], ...]
) -> Check:
    try:
        action()
    except refusals:
        return Check(name, "refused")
    except BaseException:
        return Check(name, "unavailable")
    return Check(name, "ready")


def probe(*, role: Role) -> CandidateMaterialProbeResult:
    """Read, validate and discard inputs through their existing owners."""
    with quiet_evaluation():
        try:
            return _probe(role=role)
        except BaseException:
            return unavailable_result()


def _kernel_configuration() -> Check:
    try:
        from pydantic import ValidationError
    except BaseException:
        return Check("kernel_configuration", "unavailable")
    try:
        from dotmac_kernel.config import settings, validate_settings
    except ValidationError:
        return Check("kernel_configuration", "refused")
    except BaseException:
        return Check("kernel_configuration", "unavailable")
    try:
        errors = validate_settings(settings)
    except BaseException:
        return Check("kernel_configuration", "unavailable")
    return Check("kernel_configuration", "refused" if errors else "ready")


def _probe(*, role: Role) -> CandidateMaterialProbeResult:
    if role not in ROLE_MATERIALS:
        return CandidateMaterialProbeResult((Check("probe_execution", "refused"),))
    checks = [_kernel_configuration()]

    try:
        from vendor_cp.config import load_vendor_settings

        vendor = load_vendor_settings()
    except (ValueError, ProductionConfigurationError):
        checks.append(Check("vendor_configuration", "refused"))
        return CandidateMaterialProbeResult(tuple(checks))
    except BaseException:
        checks.append(Check("vendor_configuration", "unavailable"))
        return CandidateMaterialProbeResult(tuple(checks))

    if role == "relay":
        try:
            from vendor_cp.relay.config import (
                RelayNotConfiguredError,
                require_dispatcher_dsn,
            )
        except BaseException:
            checks.append(Check("relay_dispatcher", "unavailable"))
        else:
            checks.append(
                _evaluate(
                    "relay_dispatcher",
                    lambda: require_dispatcher_dsn(vendor),
                    (RelayNotConfiguredError,),
                )
            )
    else:
        from vendor_cp.config import validate_runtime_configuration

        checks.append(
            _evaluate(
                "vendor_configuration",
                lambda: validate_runtime_configuration(
                    vendor, environment=os.getenv("ENVIRONMENT", "development")
                ),
                (ProductionConfigurationError,),
            )
        )
        try:
            from vendor_cp.licensing.signing_adapter import (
                SigningKeyUnavailableError,
                SigningModeNotPermittedError,
                build_licence_signer,
                build_overlap_signer,
            )
        except BaseException:
            checks.extend(
                Check(name, "unavailable")
                for name in ("licence_signing", "licence_overlap_signing")
            )
        else:
            refusals = (SigningKeyUnavailableError, SigningModeNotPermittedError)
            checks.extend(
                (
                    _evaluate(
                        "licence_signing",
                        lambda: build_licence_signer(settings=vendor),
                        refusals,
                    ),
                    _evaluate(
                        "licence_overlap_signing",
                        lambda: build_overlap_signer(settings=vendor),
                        refusals,
                    ),
                )
            )
    return CandidateMaterialProbeResult(tuple(checks))
