"""Closed root phase bytes; only the authenticated holder channel supplies origin."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from datetime import datetime, timedelta
from typing import Literal, TypedDict, cast
from uuid import UUID

from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused

MAX_PHASE_BYTES = 16384
RootPhaseName = Literal[
    "management_listening", "issuer_listening", "attester_listening_after_capture"
]


class RootListener(TypedDict):
    role: str
    interface: str
    local_address: str
    local_port: int
    remote_address: str


class RootLaunchPhase(TypedDict):
    schema: str
    host_role: str
    case_kind: str
    launch_packet_digest: str
    local_packet_digest: str
    window_digest: str
    machine_id_digest: str
    network_measurement_digest: str
    supervisor_pid: int
    supervisor_start: str
    not_before: str
    started_at: str
    expires_at: str
    monotonic_origin: float
    deadline: float
    emitted_at: str
    emitted_elapsed_seconds: float
    phase: RootPhaseName
    listener: RootListener
    management_capture: dict[str, object] | None


def _fields(value: object, names: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != names:
        raise ProviderRefused()
    return cast(dict[str, object], value)


def _text(value: object, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or value != value.strip()
    ):
        raise ProviderRefused()
    return value


def _digest(value: object) -> str:
    result = _text(value, 71)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", result) is None:
        raise ProviderRefused()
    return result


def _instant(value: object) -> datetime:
    result = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ProviderRefused()
    return result


def _number(value: object) -> float:
    if type(value) not in (int, float):
        raise ProviderRefused()
    result = float(cast(int | float, value))
    if not math.isfinite(result):
        raise ProviderRefused()
    return result


def _integer(value: object, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ProviderRefused()
    return value


def _address(value: object) -> str:
    raw = _text(value, 15)
    parsed = ipaddress.IPv4Address(raw)
    if (
        str(parsed) != raw
        or not parsed.is_private
        or parsed.is_loopback
        or parsed.is_unspecified
    ):
        raise ProviderRefused()
    return raw


def _management(value: object, document: RootLaunchPhase) -> dict[str, object]:
    result = _fields(value, {"readback", "readback_digest"})
    readback = _fields(
        result["readback"],
        {"schema", "launch_packet_digest", "capture", "effective_end"},
    )
    capture = _fields(
        readback["capture"],
        {
            "capture_digest",
            "window_digest",
            "plan_id",
            "plan_digest",
            "target_id",
            "approval_request_id",
        },
    )
    if (
        readback["schema"] != "Gate0CaptureInstalled.v1"
        or readback["launch_packet_digest"] != document["launch_packet_digest"]
        or capture["window_digest"] != document["window_digest"]
        or _digest(result["readback_digest"])
        != "sha256:" + hashlib.sha256(canonical(readback)).hexdigest()
        or not _instant(document["emitted_at"])
        < _instant(readback["effective_end"])
        <= _instant(document["expires_at"])
    ):
        raise ProviderRefused()
    for key in ("capture_digest", "window_digest", "plan_digest"):
        _digest(capture[key])
    for key in ("plan_id", "target_id", "approval_request_id"):
        raw = _text(capture[key], 36)
        if str(UUID(raw)) != raw:
            raise ProviderRefused()
    return result


def decode_phase(raw: bytes) -> RootLaunchPhase:
    """Validate shape and internal consistency, never authenticate root provenance."""
    try:
        value = _fields(
            strict_object(raw, MAX_PHASE_BYTES), set(RootLaunchPhase.__annotations__)
        )
        if canonical(value) != raw or value["schema"] != "Gate0RootLaunchPhase.v1":
            raise ProviderRefused()
        document = cast(RootLaunchPhase, value)
        phases = {
            "management_listening": ("attester", "management"),
            "issuer_listening": ("issuer", "issuer"),
            "attester_listening_after_capture": ("attester", "attester"),
        }
        phase = _text(value["phase"])
        if phase not in phases or value["case_kind"] not in (
            "consume_replay",
            "withdrawal_later_use",
        ):
            raise ProviderRefused()
        host, listener_role = phases[phase]
        if value["host_role"] != host:
            raise ProviderRefused()
        for name in (
            "launch_packet_digest",
            "local_packet_digest",
            "window_digest",
            "machine_id_digest",
            "network_measurement_digest",
        ):
            _digest(value[name])
        _integer(value["supervisor_pid"], 2**31 - 1)
        if re.fullmatch(r"[0-9]{1,32}", _text(value["supervisor_start"], 32)) is None:
            raise ProviderRefused()
        not_before, started, end, emitted = (
            _instant(value[k])
            for k in ("not_before", "started_at", "expires_at", "emitted_at")
        )
        origin, deadline, elapsed = (
            _number(value[k])
            for k in ("monotonic_origin", "deadline", "emitted_elapsed_seconds")
        )
        if (
            not not_before <= started <= emitted < end
            or not 0 < (end - not_before).total_seconds() <= 300
            or origin < 0
            or not 0 < deadline - origin <= 300
            or abs((end - started).total_seconds() - (deadline - origin)) > 0.001
            or not 0 <= elapsed < deadline - origin
        ):
            raise ProviderRefused()
        listener = _fields(value["listener"], set(RootListener.__annotations__))
        if (
            listener["role"] != listener_role
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", _text(listener["interface"], 15))
            is None
        ):
            raise ProviderRefused()
        _address(listener["local_address"])
        _address(listener["remote_address"])
        _integer(listener["local_port"], 65535)
        if phase == "attester_listening_after_capture":
            _management(value["management_capture"], document)
        elif value["management_capture"] is not None:
            raise ProviderRefused()
        return document
    except Exception:
        raise ProviderRefused() from None


def encode_phase(document: RootLaunchPhase) -> bytes:
    raw = canonical(document)
    decode_phase(raw)
    return raw
