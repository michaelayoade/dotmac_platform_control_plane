"""Fixed root-owned collection installation, loaded once before exposed routes serve.

No credentials, DSN, callback, provider URL or runtime qualification is accepted
from this file. Installed image identity and native I/O bounds remain trusted
launch measurements; file syntax alone cannot certify either.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import stat
import time
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from vendor_cp.deployment.gate0_database import (
    DatabaseExpectation,
    qualify_authority_database,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_github_jwt import GITHUB_ISSUER
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
)

if TYPE_CHECKING:
    from fastapi import FastAPI

    from vendor_cp.deployment.gate0_collection_projection import CollectionInstallation


class SelectedProfileIdentity(Protocol):
    """Identity handed off by composition; this module never selects a profile."""

    @property
    def code(self) -> str: ...

    @property
    def version(self) -> str: ...


_PINNED_BYTES: bytes | None = None


def _read_installation() -> bytes:
    """Walk the fixed root-owned descriptor chain without following symlinks."""
    descriptors: list[int] = []
    try:
        parent = os.open(
            "/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        descriptors.append(parent)
        directory = os.open(
            "dotmac-gate0-collection",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        descriptors.append(directory)
        file = os.open(
            "installation.json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        descriptors.append(file)
        for index, descriptor in enumerate(descriptors):
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or (
                    not stat.S_ISREG(metadata.st_mode)
                    if index == 2
                    else not stat.S_ISDIR(metadata.st_mode)
                )
                or (
                    index == 2 and (metadata.st_size > 524288 or metadata.st_nlink != 1)
                )
            ):
                raise ProviderRefused()
        raw = bytearray()
        while len(raw) <= 524288:
            chunk = os.read(file, min(65536, 524289 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not raw or len(raw) > 524288:
            raise ProviderRefused()
        return bytes(raw)
    except Exception:
        raise ProviderRefused() from None
    finally:
        close_failed = False
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                close_failed = True
        if close_failed:
            raise ProviderRefused()


def _fields(value: object, names: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != names:
        raise ProviderRefused()
    return cast(dict[str, object], value)


def _text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 262144:
        raise ProviderRefused()
    return value


def _decode(value: object) -> bytes:
    encoded = _text(value)
    raw = base64.b64decode(encoded, validate=True)
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ProviderRefused()
    return raw


def _instant(value: object) -> datetime:
    raw = _text(value)
    value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if (
        value.tzinfo is None
        or value.astimezone(UTC).isoformat().replace("+00:00", "Z") != raw
    ):
        raise ProviderRefused()
    return value


def _anchor(value: object) -> tuple[datetime, float]:
    anchor = _fields(value, {"wall_origin", "monotonic_origin", "boot_id"})
    wall = _instant(anchor["wall_origin"])
    raw_monotonic = anchor["monotonic_origin"]
    if type(raw_monotonic) not in (int, float):
        raise ProviderRefused()
    monotonic = float(cast(int | float, raw_monotonic))
    boot = _text(anchor["boot_id"])
    if (
        not math.isfinite(monotonic)
        or not 0 <= monotonic <= time.monotonic()
        or wall > datetime.now(UTC)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot
        )
        is None
        or Path("/proc/sys/kernel/random/boot_id").read_text().strip() != boot
        or abs(
            (datetime.now(UTC) - wall).total_seconds() - (time.monotonic() - monotonic)
        )
        > 2
    ):
        raise ProviderRefused()
    return wall, monotonic


def _database(value: object) -> DatabaseExpectation:
    document = _fields(value, {field.name for field in fields(DatabaseExpectation)})
    for name in ("schemas", "image_heads", "descriptor_heads"):
        values = document[name]
        if type(values) is not list or any(type(v) is not str for v in values):
            raise ProviderRefused()
        document[name] = tuple(values)
    # Dataclass validation checks every field; this does not construct authority.
    expectation = DatabaseExpectation(**document)  # type: ignore[arg-type]
    expectation.validate()
    return expectation


def load_installed_collection(
    profile: SelectedProfileIdentity,
) -> CollectionInstallation:
    """Measure the existing runtime and retain the fixed original clocks."""
    from uuid import UUID

    from vendor_cp.deployment.gate0_collection_projection import (
        CollectionCase,
        CollectionCaseClock,
        CollectionInstallation,
        CollectionSelection,
        validate_collection_cases,
    )
    from vendor_cp.deployment.gate0_launch import parse_run_document
    from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
    from vendor_cp.relay.runner import authority_database_runtime

    global _PINNED_BYTES
    raw = _read_installation()
    if _PINNED_BYTES is not None and _PINNED_BYTES != raw:
        raise ProviderRefused()
    value = _fields(
        strict_object(raw, 524288),
        {
            "schema",
            "source_revision",
            "image_digest",
            "profile_digest",
            "profile_code",
            "profile_version",
            "database",
            "clock_anchor",
            "cases",
        },
    )
    if (
        canonical(value) != raw
        or value["schema"] != "Gate0CollectionApiInstallation.v1"
    ):
        raise ProviderRefused()
    if (
        value["profile_code"] != profile.code
        or value["profile_version"] != profile.version
    ):
        raise ProviderRefused()
    source = _text(value["source_revision"])
    image = _text(value["image_digest"])
    if (
        re.fullmatch(r"[0-9a-f]{40}", source) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
    ):
        raise ProviderRefused()
    profile_bytes = Path("/app/application_foundation_profile.json").read_bytes()
    heads = strict_object(Path("/app/migration_heads.json").read_bytes())
    if (
        value["profile_digest"] != "sha256:" + hashlib.sha256(profile_bytes).hexdigest()
        or strict_object(profile_bytes)["source_revision"] != source
        or heads["source_revision"] != source
    ):
        raise ProviderRefused()
    wall, monotonic = _anchor(value["clock_anchor"])
    cases = value["cases"]
    if type(cases) is not list or len(cases) != 2:
        raise ProviderRefused()
    parsed: list[CollectionCase] = []
    for item in cases:
        declared = _fields(item, {"shared_packet_b64", "frozen_window_b64"})
        shared = _decode(declared["shared_packet_b64"])
        frozen = _decode(declared["frozen_window_b64"])
        packet = parse_run_document(shared)
        window = FrozenIssuerWindow.parse(frozen)
        capture = packet["capture"]
        selected = CollectionSelection(
            "sha256:" + hashlib.sha256(shared).hexdigest(),
            window.document["window_id"],
            capture["window_digest"],
            UUID(capture["plan_id"]),
            UUID(capture["target_id"]),
            packet["case_kind"],
        )
        parsed.append(
            CollectionCase(
                selected,
                CollectionCaseClock(
                    wall,
                    monotonic,
                    _instant(packet["not_before"]),
                    _instant(packet["expires_at"]),
                ),
                shared,
                frozen,
            )
        )
    expectation = _database(value["database"])
    if (
        expectation.source_revision != source
        or expectation.expected_source_revision != source
    ):
        raise ProviderRefused()
    selected_cases = (parsed[0], parsed[1])
    validate_collection_cases(selected_cases)
    runtime = authority_database_runtime()
    installed = CollectionInstallation(
        runtime, BoundedJSONTransport(GITHUB_ISSUER), selected_cases
    )
    measured = qualify_authority_database(expectation)
    measured.require_runtime(runtime)
    _PINNED_BYTES = raw
    return installed


def bind_installed_collection(app: FastAPI, profile: SelectedProfileIdentity) -> None:
    """Only the two actually constructed declared routes activate installation I/O."""
    from fastapi.routing import APIRoute

    from vendor_cp.deployment.gate0_collection_api import approval, withdrawal

    expected = {
        (
            "/platform/vendor/gate0/collection/windows/{window_id}/approval",
            "GET",
            approval,
        ),
        (
            "/platform/vendor/gate0/collection/windows/{window_id}/withdrawal",
            "GET",
            withdrawal,
        ),
    }
    mounted = {
        (r.path, method, r.endpoint)
        for r in app.routes
        if isinstance(r, APIRoute)
        for method in r.methods
        if r.endpoint in (approval, withdrawal)
    }
    if not mounted:
        return
    if mounted != expected or hasattr(app.state, "gate0_collection_installation"):
        raise ProviderRefused()
    app.state.gate0_collection_installation = load_installed_collection(profile)
