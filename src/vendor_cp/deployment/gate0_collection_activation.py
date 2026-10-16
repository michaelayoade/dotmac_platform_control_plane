"""Read-only installed-image checks for the existing host emergency executor.

The host owns image identity, protected files, locking, Compose and retirement.
This module only checks bounded descriptor bytes against its own image artifacts.
A successful mechanical result is never approval or runtime qualification.
"""

from __future__ import annotations

import hashlib
import sys
import time
from datetime import UTC, datetime
from typing import BinaryIO, Literal, cast

from vendor_cp.deployment.gate0_collection_installation import (
    installation_cases,
    installation_document,
)
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment_profile import deployment_profile

_MAXIMUM = 524288


def check_collection_input(
    raw: bytes, operation: Literal["activation", "retirement"]
) -> bytes:
    """Inert image-artifact comparison; no database or installed host I/O."""
    if operation not in ("activation", "retirement"):
        raise ProviderRefused()
    value = installation_document(raw)
    if any(
        type(value[name]) is not str or not 0 < len(cast(str, value[name])) <= 128
        for name in ("profile_code", "profile_version", "profile_digest")
    ):
        raise ProviderRefused()
    original_clock: dict[str, object] | None = None
    if operation == "activation":
        if type(value["profile_code"]) is not str:
            raise ProviderRefused()
        profile = deployment_profile(value["profile_code"])
        if (
            not profile.production_accepted
            or profile.laboratory
            or profile.version != value["profile_version"]
            or "gate0_collection_reads" not in profile.surface_inventory
            or "gate0_collection_reads" in profile.withheld_surfaces
        ):
            raise ProviderRefused()
        cases, _ = installation_cases(value)
        anchor = cast(dict[str, object], value["clock_anchor"])
        original_clock = {
            "boot_id": anchor["boot_id"],
            "wall_origin": cases[0]
            .clock.wall_origin.isoformat()
            .replace("+00:00", "Z"),
            "monotonic_origin": cases[0].clock.monotonic_origin,
            "a_expires_at": cases[0]
            .clock.expires_at.isoformat()
            .replace("+00:00", "Z"),
            "a_monotonic_end": cases[0].clock.deadline,
        }
        if (
            time.monotonic() >= cases[0].clock.deadline
            or datetime.now(UTC) >= cases[0].clock.expires_at
        ):
            raise ProviderRefused()
    # Retirement deliberately avoids live clocks, profile acceptance and DB
    # qualification. It still names the exact descriptor and its own artifacts.
    result = {
        "schema": "Gate0CollectionInputCheck.v1",
        "operation": operation,
        "input_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "original_clock": original_clock,
        **{
            name: value[name]
            for name in (
                "source_revision",
                "image_digest",
                "profile_code",
                "profile_version",
                "profile_digest",
            )
        },
    }
    return canonical(result)


def _run(operation: Literal["activation", "retirement"], stream: BinaryIO) -> int:
    try:
        raw = stream.read(_MAXIMUM + 1)
        result = check_collection_input(raw, operation)
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 3


def run_installed_collection_check_activation() -> int:
    """Fixed bounded stdin; host independently checks identity and cleanup."""
    return _run("activation", sys.stdin.buffer)


def run_installed_collection_check_retirement() -> int:
    """Read-only same-image descriptor check, also after case expiry."""
    return _run("retirement", sys.stdin.buffer)
