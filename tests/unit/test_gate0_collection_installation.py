"""Synthetic fixed-loader/boot-hook checks; no actual root/DB qualification."""

import base64
import hashlib
import os
import stat
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotmac_kernel.session_runtime import DatabaseRuntime
from fastapi import FastAPI
from test_gate0_collection_api import case as _case
from test_gate0_window import window_document as _window_document

from vendor_cp.deployment import gate0_collection_installation as loader
from vendor_cp.deployment.gate0_collection_api import router
from vendor_cp.deployment.gate0_database import DatabaseExpectation
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment_profile import (
    PRODUCTION_COMPOSED_V1,
    PRODUCTION_GATE0_COLLECTION_V1,
    deployment_profile,
)

case = _case
window_document = _window_document


@pytest.mark.parametrize(
    "invalid", [None, "owner", "writable", "symlink", "oversize", "directory"]
)
def test_fixed_descriptor_chain_refuses_unprotected_inputs(monkeypatch, invalid):
    closed = []
    opened = []
    raw = [b'{"synthetic":true}', b""]

    def open_fd(path, flags, **kwargs):
        assert flags & os.O_NOFOLLOW
        opened.append((path, kwargs))
        if invalid == "symlink" and path == "installation.json":
            raise OSError("symlink")
        return len(opened)

    def metadata(fd):
        mode = (stat.S_IFREG | 0o440) if fd == 3 else (stat.S_IFDIR | 0o750)
        if invalid == "writable" and fd == 3:
            mode |= 0o020
        if invalid == "directory" and fd == 3:
            mode = stat.S_IFDIR | 0o750
        return SimpleNamespace(
            st_uid=1 if invalid == "owner" else 0,
            st_mode=mode,
            st_size=524289 if invalid == "oversize" else 18,
            st_nlink=1,
        )

    monkeypatch.setattr(loader.os, "open", open_fd)
    monkeypatch.setattr(loader.os, "fstat", metadata)
    monkeypatch.setattr(loader.os, "read", lambda *a: raw.pop(0))
    monkeypatch.setattr(loader.os, "close", closed.append)
    if invalid is None:
        assert loader._read_installation() == b'{"synthetic":true}'
    else:
        with pytest.raises(ProviderRefused):
            loader._read_installation()
    assert closed == (
        list(range(len(opened), 0, -1)) if invalid != "symlink" else [2, 1]
    )
    assert opened[0][0] == "/run"


@pytest.mark.parametrize(
    "collision",
    [
        None,
        "lease_id",
        "fingerprint",
        "certificate_digest",
        "plan",
        "window",
        "approval",
        "run",
    ],
)
def test_fixed_loader_derives_future_b_and_same_runtime_from_measured_qualification(
    case,
    monkeypatch,
    collision,
):
    import vendor_cp.relay.runner as relay

    profile = deployment_profile(PRODUCTION_GATE0_COLLECTION_V1)
    now = datetime.now(UTC)
    window_b = case.window.document
    window_b["window_id"] = "future-b"
    window_b["not_before"] = (
        (now + timedelta(seconds=40)).isoformat().replace("+00:00", "Z")
    )
    window_b["expires_at"] = (
        (now + timedelta(seconds=100)).isoformat().replace("+00:00", "Z")
    )
    window_a = dict(
        case.window.document, case_kind="consume_replay", window_id="current-a"
    )
    window_a["controller"] = dict(
        window_a["controller"],
        lease_id="different-lease",
        fingerprint="SHA256:" + base64.b64encode(bytes([1]) * 32).decode().rstrip("="),
        certificate_digest="sha256:" + "8" * 64,
    )
    if collision in ("lease_id", "fingerprint", "certificate_digest"):
        window_b["controller"][collision] = window_a["controller"][collision]
    if collision == "window":
        window_b["window_id"] = window_a["window_id"]
    if collision == "run":
        window_b["github"]["run_attempt"] = "99"
    packets = []
    for index, document in enumerate((window_a, window_b)):
        frozen = FrozenIssuerWindow.parse(canonical(document))
        shared = strict_object(case.configured.shared_packet)
        shared.update(
            case_kind=document["case_kind"],
            not_before=document["not_before"],
            expires_at=document["expires_at"],
            run_id=document["github"]["run_id"],
            run_attempt=document["github"]["run_attempt"],
        )
        shared["capture"]["window_digest"] = frozen.digest
        shared["capture"]["plan_id"] = "00000000-0000-0000-0000-00000000000" + str(
            index + 1
        )
        shared["capture"]["approval_request_id"] = (
            "00000000-0000-0000-0000-00000000000"
            + str(3 if collision == "approval" else index + 3)
        )
        if collision == "plan":
            shared["capture"]["plan_id"] = "00000000-0000-0000-0000-000000000001"
        packets.append(
            {
                "shared_packet_b64": base64.b64encode(canonical(shared)).decode(),
                "frozen_window_b64": base64.b64encode(frozen.canonical_bytes).decode(),
            }
        )
    source = "a" * 40
    profile_bytes = canonical({"source_revision": source})
    expectation = DatabaseExpectation(
        "synthetic",
        "synthetic",
        "127.0.0.1",
        5432,
        True,
        ("public",),
        ("head",),
        ("head",),
        source,
        source,
        100,
        100,
    )
    document = {
        "schema": "Gate0CollectionApiInstallation.v1",
        "source_revision": source,
        "image_digest": "sha256:" + "b" * 64,
        "profile_digest": "sha256:" + hashlib.sha256(profile_bytes).hexdigest(),
        "profile_code": profile.code,
        "profile_version": profile.version,
        "database": asdict(expectation),
        "clock_anchor": {
            "wall_origin": now.isoformat().replace("+00:00", "Z"),
            "monotonic_origin": time.monotonic(),
            "boot_id": "00000000-0000-0000-0000-000000000001",
        },
        "cases": packets,
    }
    monkeypatch.setattr(loader, "_read_installation", lambda: canonical(document))
    monkeypatch.setattr(loader, "_PINNED_BYTES", None)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda p: (
            profile_bytes
            if str(p).endswith("application_foundation_profile.json")
            else canonical({"source_revision": source})
        ),
    )
    monkeypatch.setattr(
        Path, "read_text", lambda *a, **k: document["clock_anchor"]["boot_id"]
    )
    runtime = object.__new__(DatabaseRuntime)
    runtime_calls = []
    monkeypatch.setattr(
        relay,
        "authority_database_runtime",
        lambda: runtime_calls.append("runtime") or runtime,
    )
    measured = []

    def qualify(expected):
        assert expected == expectation

        def require_runtime(actual):
            assert actual is runtime
            measured.append(actual)

        return SimpleNamespace(require_runtime=require_runtime)

    monkeypatch.setattr(loader, "qualify_authority_database", qualify)
    if collision is not None:
        with pytest.raises(ProviderRefused):
            loader.load_installed_collection(profile)
        assert measured == []
        assert runtime_calls == []
        return
    first = loader.load_installed_collection(profile)
    second = loader.load_installed_collection(profile)
    assert first.runtime is second.runtime is runtime
    assert len(measured) == 2
    assert runtime_calls == ["runtime", "runtime"]
    assert tuple(c.clock.deadline for c in first.cases) == tuple(
        c.clock.deadline for c in second.cases
    )
    with pytest.raises(ProviderRefused):
        first.select("future-b")
    document["extra"] = True
    with pytest.raises(ProviderRefused):
        loader.load_installed_collection(profile)


@pytest.mark.parametrize("change", ["future", "boot", "drift"])
def test_original_anchor_rejects_different_boot_future_or_clock_domain(
    monkeypatch, change
):
    now = datetime.now(UTC)
    anchor = {
        "wall_origin": (now + timedelta(seconds=5) if change == "future" else now)
        .isoformat()
        .replace("+00:00", "Z"),
        "monotonic_origin": time.monotonic() - (10 if change == "drift" else 0),
        "boot_id": "00000000-0000-0000-0000-000000000001",
    }
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *a, **k: "other" if change == "boot" else anchor["boot_id"],
    )
    with pytest.raises(ProviderRefused):
        loader._anchor(anchor)


def test_boot_binder_withheld_reads_no_file_and_exposed_binds_exactly_once(monkeypatch):
    calls = []
    value = object()
    monkeypatch.setattr(
        loader,
        "load_installed_collection",
        lambda profile: calls.append(profile) or value,
    )
    withheld = FastAPI()
    loader.bind_installed_collection(
        withheld, deployment_profile(PRODUCTION_COMPOSED_V1)
    )
    assert calls == []
    assert not hasattr(withheld.state, "gate0_collection_installation")
    exposed = FastAPI()
    exposed.include_router(router)
    candidate = deployment_profile(PRODUCTION_GATE0_COLLECTION_V1)
    loader.bind_installed_collection(exposed, candidate)
    assert exposed.state.gate0_collection_installation is value
    assert calls == [candidate]
    with pytest.raises(ProviderRefused):
        loader.bind_installed_collection(exposed, candidate)
    incomplete = FastAPI()
    incomplete.include_router(router)
    incomplete.router.routes = [
        r
        for r in incomplete.routes
        if not getattr(r, "path", "").endswith("/withdrawal")
    ]
    with pytest.raises(ProviderRefused):
        loader.bind_installed_collection(incomplete, candidate)
