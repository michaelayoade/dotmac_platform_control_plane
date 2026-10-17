"""Hosted synthetic adapter checks; no daemon, installed qualification or approval.

The orchestration fixture substitutes protected-root layout and Docker boundaries.
Filesystem exclusivity, inode binding, retained records and descriptor parsing are
real. Separate sensitivity checks cover the root/user/lock/image boundary guards.
"""

import ast
import base64
import copy
import fcntl
import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from test_gate0_collection_api import case as _case
from test_gate0_window import window_document as _window_document

from vendor_cp.deployment import gate0_collection_activation as checker
from vendor_cp.deployment import gate0_collection_installation as loader
from vendor_cp.deployment import gate0_collection_projection as projection
from vendor_cp.deployment.gate0_database import DatabaseExpectation
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow
from vendor_cp.deployment_profile import (
    PRODUCTION_GATE0_COLLECTION_V1,
)

case = _case
window_document = _window_document
ROOT = Path(__file__).resolve().parents[2]


def _host_run(activation):
    try:
        (leaf._activate if activation else leaf._retire)()
        return 0
    except Exception:
        return 3


@pytest.fixture(autouse=True)
def host_leaf():
    """Execute only the embedded stdlib adapter in hosted synthetic tests."""
    global leaf
    script = (ROOT / "scripts/deploy_production.sh").read_text()
    source = script.split("<<'FINITE_COLLECTION'\n", 1)[1].split(
        "\nFINITE_COLLECTION", 1
    )[0]
    tree = ast.parse(source)
    tree.body = tree.body[
        :-1
    ]  # Drop the actual operation dispatch, retaining definitions.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module]
            )
            assert not any(
                str(name).startswith(("vendor_cp", "dotmac", "sqlalchemy"))
                for name in names
            )
    leaf = ModuleType("synthetic_host_collection_leaf")
    exec(compile(tree, "<hosted-stdlib-adapter>", "exec"), leaf.__dict__)  # noqa: S102 -- reviewed embedded source, hosted only
    leaf.ProviderRefused = ProviderRefused
    leaf.sys = SimpleNamespace(
        argv=["host", "0", "sha256:" + "b" * 64, "--gate0-collection-activate"]
    )


def _declarations_document():
    return {
        "schema": "DotmacDeploymentProfileDeclarations.v1",
        "source_revision": "a" * 40,
        "foundation_profile_digest": "sha256:"
        + hashlib.sha256(canonical({"source_revision": "a" * 40})).hexdigest(),
        "profiles": [
            {
                "code": PRODUCTION_GATE0_COLLECTION_V1,
                "version": "1",
                "production_accepted": True,
                "laboratory": False,
                "surface_inventory": ["gate0_collection_reads"],
                "withheld_surfaces": [],
            }
        ],
    }


@pytest.fixture
def descriptor(case, monkeypatch):
    now = datetime.now(UTC)
    windows = []
    for index, kind in enumerate(("consume_replay", "withdrawal_later_use")):
        document = copy.deepcopy(case.window.document)
        document.update(
            case_kind=kind,
            window_id=f"selected-{index}",
            not_before=(now + timedelta(seconds=index * 90 - 1))
            .isoformat()
            .replace("+00:00", "Z"),
            expires_at=(now + timedelta(seconds=index * 90 + 60))
            .isoformat()
            .replace("+00:00", "Z"),
        )
        if index == 0:
            document["controller"].update(
                lease_id="different-lease",
                fingerprint="SHA256:"
                + base64.b64encode(bytes([1]) * 32).decode().rstrip("="),
                certificate_digest="sha256:" + "8" * 64,
            )
        window = FrozenIssuerWindow.parse(canonical(document))
        packet = strict_object(case.configured.shared_packet)
        packet.update(
            case_kind=kind,
            not_before=document["not_before"],
            expires_at=document["expires_at"],
        )
        packet["capture"].update(
            window_digest=window.digest,
            plan_id=f"00000000-0000-0000-0000-00000000000{index + 1}",
            approval_request_id=f"00000000-0000-0000-0000-00000000000{index + 3}",
        )
        windows.append(
            {
                "shared_packet_b64": base64.b64encode(canonical(packet)).decode(),
                "frozen_window_b64": base64.b64encode(window.canonical_bytes).decode(),
            }
        )
    document = {
        "schema": "Gate0CollectionApiInstallation.v1",
        "source_revision": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "profile_digest": "sha256:"
        + hashlib.sha256(canonical({"source_revision": "a" * 40})).hexdigest(),
        "profile_code": PRODUCTION_GATE0_COLLECTION_V1,
        "profile_version": "1",
        "database": asdict(
            DatabaseExpectation(
                "synthetic",
                "synthetic",
                "127.0.0.1",
                5432,
                True,
                ("public",),
                ("head",),
                ("head",),
                "a" * 40,
                "a" * 40,
                100,
                100,
            )
        ),
        "clock_anchor": {
            "wall_origin": now.isoformat().replace("+00:00", "Z"),
            "monotonic_origin": time.monotonic(),
            "boot_id": "00000000-0000-0000-0000-000000000001",
        },
        "cases": windows,
    }
    monkeypatch.setenv("GATE0_COLLECTION_IMAGE_DIGEST", document["image_digest"])
    original_read = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            document["clock_anchor"]["boot_id"]
            if str(path) == "/proc/sys/kernel/random/boot_id"
            else original_read(path, *a, **kw)
        ),
    )
    original_bytes = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: (
            canonical({"source_revision": "a" * 40})
            if str(path)
            in ("/app/application_foundation_profile.json", "/app/migration_heads.json")
            else original_bytes(path)
        ),
    )
    original_open = Path.open
    monkeypatch.setattr(
        Path,
        "open",
        lambda path, *args, **kwargs: (
            io.BytesIO(canonical(_declarations_document()))
            if str(path) == "/app/deployment_profile_declarations.json"
            else original_open(path, *args, **kwargs)
        ),
    )
    return document


@pytest.fixture
def installed(tmp_path, monkeypatch, descriptor):
    source, state, runtime = (tmp_path / name for name in ("source", "state", "run"))
    source.mkdir(mode=0o700)
    raw = canonical(descriptor)
    (source / "installation.json").write_bytes(raw)
    monkeypatch.setattr(leaf, "_SOURCE", source / "installation.json")
    monkeypatch.setattr(leaf, "_STATE", state)
    monkeypatch.setattr(leaf, "_RUNTIME", runtime)
    monkeypatch.setattr(leaf, "_executor_lock", nullcontext)
    monkeypatch.setattr(leaf, "_assets", lambda: None)

    @contextmanager
    def directory(path, *, create=False):
        if create:
            path.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    def metadata(fd, *, directory=False):
        value = os.fstat(fd)
        assert stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
        assert directory or value.st_nlink == 1
        return value

    chowns = []
    monkeypatch.setattr(leaf, "_directory", directory)
    monkeypatch.setattr(leaf, "_metadata", metadata)
    monkeypatch.setattr(leaf.os, "fchown", lambda *args: chowns.append(args[1:]))
    reference = leaf._REPOSITORY + "@" + descriptor["image_digest"]
    image_id = "sha256:" + "d" * 64
    monkeypatch.setattr(leaf, "_image", lambda document: (reference, image_id))
    native_validate = leaf._validate_image_input
    monkeypatch.setattr(
        leaf,
        "_validate_image_input",
        lambda state, raw, document, reference, *, activation: strict_object(
            checker.check_collection_input(
                raw, "activation" if activation else "retirement"
            )
        ),
    )
    current = {
        "id": "initial",
        "running": True,
        "profiles": [
            "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap",
            None,
        ],
        "mounts": [],
    }
    calls = []

    def recreate(reference, profile, *, activation):
        calls.append((reference, profile, activation))
        current.update(
            id=f"app-{len(calls)}",
            profiles=[
                "VENDOR_DEPLOYMENT_PROFILE="
                + (profile if activation else leaf._BOOTSTRAP),
                None,
            ],
            mounts=(
                [
                    {
                        "Type": "bind",
                        "Source": str(runtime / "installation.json"),
                        "Destination": str(runtime / "installation.json"),
                        "RW": False,
                    }
                ]
                if activation
                else []
            ),
        )

    monkeypatch.setattr(leaf, "_app", lambda *a: dict(current))
    monkeypatch.setattr(leaf, "_recreate", recreate)
    return SimpleNamespace(
        native_validate=native_validate,
        raw=raw,
        state=state,
        runtime=runtime,
        source=source,
        calls=calls,
        current=current,
        chowns=chowns,
        reference=reference,
    )


def test_overlay_only_overrides_app_and_missing_file_cannot_be_created():
    # This deliberately closed source guard accepts no extra YAML fields,
    # aliases or alternate layout; Compose interpretation remains its owner.
    overlay = (ROOT / "docker-compose.gate0-collection.yml").read_text()
    meaningful = "\n".join(
        line
        for line in overlay.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    assert meaningful == (
        "services:\n"
        "  app:\n"
        "    environment:\n"
        "      VENDOR_DEPLOYMENT_PROFILE: ${VENDOR_GATE0_COLLECTION_PROFILE:?Set the "
        "exact accepted collection profile from the protected selection}\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: /run/dotmac-gate0-collection/installation.json\n"
        "        target: /run/dotmac-gate0-collection/installation.json\n"
        "        read_only: true\n"
        "        bind:\n"
        "          create_host_path: false"
    )
    base = (ROOT / "docker-compose.production.yml").read_text()
    assert "VENDOR_DEPLOYMENT_PROFILE" not in base
    assert "gate0-collection" not in base


def test_install_once_exact_original_bytes_runtime_group_and_terminal_retirement(
    installed,
):
    assert _host_run(True) == 0
    path = installed.runtime / "installation.json"
    assert path.read_bytes() == installed.raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert installed.chowns == [(0, 10001)]
    assert stat.S_IMODE(installed.runtime.stat().st_mode) == 0o700
    assert (installed.state / "installation.json").read_bytes() == installed.raw
    assert (installed.state / "activation-complete.json").exists()
    assert _host_run(True) == 3
    assert len(installed.calls) == 1
    assert _host_run(False) == 0
    assert not path.exists()
    assert (installed.state / "retirement-complete.json").exists()
    assert installed.calls == [
        (installed.reference, PRODUCTION_GATE0_COLLECTION_V1, True),
        (installed.reference, leaf._BOOTSTRAP, False),
    ]
    assert _host_run(True) == 3
    assert _host_run(False) == 3
    assert len(installed.calls) == 2


def test_missing_volatile_descriptor_never_allows_reinstall(installed):
    assert _host_run(True) == 0
    (installed.runtime / "installation.json").unlink()
    installed.current.update(
        profiles=["VENDOR_DEPLOYMENT_PROFILE=production-bootstrap", None], mounts=[]
    )
    assert _host_run(True) == 3
    assert len(installed.calls) == 1
    assert _host_run(False) == 0


@pytest.mark.parametrize("failure", ["image", "prestate", "mount", "stopped"])
def test_drift_refuses_before_persistent_install_or_recreation(
    installed, monkeypatch, failure
):
    if failure == "image":
        monkeypatch.setattr(
            leaf, "_image", lambda *a: (_ for _ in ()).throw(ProviderRefused())
        )
    elif failure == "prestate":
        installed.current["profiles"] = ["VENDOR_DEPLOYMENT_PROFILE=full", None]
    elif failure == "mount":
        installed.current["mounts"] = [{"Destination": str(installed.runtime)}]
    else:
        installed.current["running"] = False
    assert _host_run(True) == 3
    assert not installed.state.exists()
    assert not installed.calls


@pytest.mark.parametrize("failure", ["exception", "mounted", "profile"])
def test_failed_retirement_is_terminal_incomplete(installed, monkeypatch, failure):
    assert _host_run(True) == 0
    original = leaf._recreate

    def recreate(*args, **kw):
        if failure == "exception":
            raise OSError("synthetic unavailable")
        original(*args, **kw)
        if failure == "mounted":
            installed.current["mounts"] = [{"Destination": str(installed.runtime)}]
        else:
            installed.current["profiles"] = ["VENDOR_DEPLOYMENT_PROFILE=full", None]

    monkeypatch.setattr(leaf, "_recreate", recreate)
    assert _host_run(False) == 3
    assert (installed.state / "retirement-incomplete.json").exists()
    assert not (installed.state / "retirement-complete.json").exists()
    assert (installed.runtime / "installation.json").read_bytes() == installed.raw
    assert _host_run(False) == 3


@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "inode"])
def test_runtime_replacement_refuses_retirement_before_mutation(installed, replacement):
    assert _host_run(True) == 0
    path = installed.runtime / "installation.json"
    saved = installed.runtime / "saved"
    path.rename(saved)
    if replacement == "symlink":
        path.symlink_to(saved)
    elif replacement == "hardlink":
        os.link(saved, path)
    else:
        path.write_bytes(installed.raw)
    assert _host_run(False) == 3
    assert len(installed.calls) == 1


def test_retirement_ignores_expired_cases_and_keeps_original_bytes(
    installed, monkeypatch
):
    assert _host_run(True) == 0
    monkeypatch.setattr(
        checker,
        "installation_cases",
        lambda *a: pytest.fail("retirement parsed live clocks"),
    )
    monkeypatch.setattr(
        loader, "_anchor", lambda *a: pytest.fail("retirement consulted live anchor")
    )
    assert _host_run(False) == 0
    assert (installed.state / "installation.json").read_bytes() == installed.raw


@pytest.mark.parametrize("change", ["boot", "expired", "profile", "digest", "extra"])
def test_descriptor_checks_original_clock_and_selection_before_install(
    descriptor, monkeypatch, change
):
    raw = canonical(descriptor)
    assert strict_object(checker.check_collection_input(raw, "activation"))[
        "input_digest"
    ] == leaf._hash(raw)
    if change == "boot":
        monkeypatch.setattr(
            Path, "read_text", lambda *a, **kw: "00000000-0000-0000-0000-000000000002"
        )
    elif change == "expired":
        original = loader._anchor(descriptor["clock_anchor"])
        monkeypatch.setattr(
            loader,
            "_anchor",
            lambda *a: original,
        )
        # Keep the actual original mapping; elapsed time cannot extend expiry.
        monkeypatch.setattr(time, "monotonic", lambda: 10**12)
    elif change == "profile":
        descriptor["profile_version"] = "unadopted"
    elif change == "digest":
        leaf.sys.argv[2] = "sha256:" + "e" * 64
    else:
        descriptor["accepted"] = True
    with pytest.raises(ProviderRefused):
        (
            leaf._selected(canonical(descriptor))
            if change == "digest"
            else checker.check_collection_input(canonical(descriptor), "activation")
        )


@pytest.mark.parametrize("change", [None, "missing", "source", "user", "digest"])
def test_local_image_must_match_source_digest_and_runtime_user(
    descriptor, monkeypatch, change
):
    reference = leaf._REPOSITORY + "@" + descriptor["image_digest"]
    facts = {
        "id": "sha256:" + "d" * 64,
        "digests": [reference],
        "source": descriptor["source_revision"],
        "user": "10001:10001",
    }
    calls = []

    def docker(*args, **kw):
        calls.append(args)
        if change == "missing":
            raise ProviderRefused()
        return canonical(facts).decode()

    if change in {"source", "user", "digest"}:
        facts[{"source": "source", "user": "user", "digest": "digests"}[change]] = (
            "wrong"
        )
    monkeypatch.setattr(leaf, "_docker", docker)
    if change is None:
        assert leaf._image(descriptor) == (reference, facts["id"])
    else:
        with pytest.raises(ProviderRefused):
            leaf._image(descriptor)
    assert calls[0][:2] == ("image", "inspect")


def test_recreation_commands_only_app_no_build_pull_or_dependency_work(monkeypatch):
    calls = []
    monkeypatch.setenv("VENDOR_DB_BOOTSTRAP_PASSWORD", "synthetic-inherited-value")
    monkeypatch.setattr(leaf, "_docker", lambda *args, **kw: calls.append((args, kw)))
    reference = leaf._REPOSITORY + "@sha256:" + "b" * 64
    leaf._recreate(reference, PRODUCTION_GATE0_COLLECTION_V1, activation=True)
    leaf._recreate(reference, leaf._BOOTSTRAP, activation=False)
    for args, kw in calls:
        assert args[-9:] == (
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            "--wait",
            "app",
        )
        assert args[-1] == "app"
        assert not {
            "run",
            "exec",
            "db",
            "relay",
            "build",
            "migrate",
            "backup",
        }.intersection(args)
        assert kw["environment"]["VENDOR_APP_IMAGE"] == reference
        assert (
            kw["environment"]["VENDOR_DB_BOOTSTRAP_PASSWORD"]
            == "gate0-compose-parse-only"
        )
    assert leaf._OVERLAY in calls[0][0]
    assert leaf._OVERLAY not in calls[1][0]
    assert "VENDOR_GATE0_COLLECTION_PROFILE" not in calls[1][1]["environment"]


def test_expired_case_still_mounted_refuses_before_authentication_or_database(
    descriptor, monkeypatch
):
    from uuid import UUID

    from dotmac_kernel.session_runtime import DatabaseRuntime
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from vendor_cp.deployment import gate0_collection_api as api
    from vendor_cp.deployment.gate0_launch import parse_run_document
    from vendor_cp.deployment.gate0_role_custody import BoundedJSONTransport

    wall, monotonic = loader._anchor(descriptor["clock_anchor"])
    cases = []
    for item in descriptor["cases"]:
        shared = base64.b64decode(item["shared_packet_b64"])
        frozen = base64.b64decode(item["frozen_window_b64"])
        packet = parse_run_document(shared)
        window = FrozenIssuerWindow.parse(frozen)
        capture = packet["capture"]
        cases.append(
            projection.CollectionCase(
                projection.CollectionSelection(
                    leaf._hash(shared),
                    window.document["window_id"],
                    window.digest,
                    UUID(capture["plan_id"]),
                    UUID(capture["target_id"]),
                    packet["case_kind"],
                ),
                projection.CollectionCaseClock(
                    wall,
                    monotonic,
                    loader._instant(packet["not_before"]),
                    loader._instant(packet["expires_at"]),
                ),
                shared,
                frozen,
            )
        )
    installation = projection.CollectionInstallation(
        object.__new__(DatabaseRuntime),
        BoundedJSONTransport("https://token.actions.githubusercontent.com"),
        tuple(cases),
    )
    monkeypatch.setattr(
        projection, "time", SimpleNamespace(monotonic=lambda: monotonic + 10000)
    )
    monkeypatch.setattr(
        projection,
        "verify_github_claims",
        lambda *a, **kw: pytest.fail("expired auth I/O"),
    )
    monkeypatch.setattr(api, "project", lambda *a, **kw: pytest.fail("expired DB I/O"))
    app = FastAPI()
    app.include_router(api.router)
    app.state.gate0_collection_installation = installation
    response = TestClient(app).get(
        f"/platform/vendor/gate0/collection/windows/{cases[0].selection.window_id}/approval",
        headers={"Authorization": "Bearer synthetic"},
    )
    assert response.status_code == 403


def test_executor_and_full_deploy_share_existing_lock_before_finite_branch():
    script = (ROOT / "scripts/deploy_production.sh").read_text()
    assert script.index(
        "finite collection requires the canonical executor paths"
    ) < script.index("exec {LOCK_FD}>>")
    assert script.index("finite collection lock metadata refused") < script.index(
        'flock --nonblock "$LOCK_FD"'
    )
    assert script.index('BUNDLE_TMP=""') < script.index("trap cleanup_effector")
    assert script.index("<<'FINITE_COLLECTION'") < script.index("import secrets")
    assert "dotmac-platform gate0 collection-activate" not in script
    assert '/usr/bin/python3 -I - "$LOCK_FD"' in script


@pytest.mark.parametrize("kind", ["valid", "wrong_inode", "unprivileged", "held"])
def test_inherited_canonical_lock_serializes_existing_executor(
    tmp_path, monkeypatch, kind
):
    path = tmp_path / "lock"
    path.write_bytes(b"executor")
    fd = os.open(path, os.O_RDWR)
    other = os.open(path, os.O_RDWR)
    leaf.sys.argv[1] = str(fd)
    monkeypatch.setattr(leaf, "_LOCK", path)
    monkeypatch.setattr(leaf.os, "geteuid", lambda: 1 if kind == "unprivileged" else 0)
    monkeypatch.setattr(leaf, "_metadata", lambda value, **kw: os.fstat(value))

    @contextmanager
    def directory():
        directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield directory_fd
        finally:
            os.close(directory_fd)

    monkeypatch.setattr(leaf, "_lock_directory", directory)
    if kind == "held":
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if kind == "wrong_inode":
        path.unlink()
        path.write_bytes(b"replacement")
    try:
        if kind == "valid":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with leaf._executor_lock():
                with pytest.raises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            with pytest.raises((ProviderRefused, BlockingIOError)):
                with leaf._executor_lock():
                    pytest.fail("invalid lock admitted")
    finally:
        os.close(fd)
        os.close(other)


@pytest.mark.parametrize("change", [None, "owner", "writable", "hardlink", "directory"])
def test_protected_regular_file_guard(monkeypatch, change):
    metadata = SimpleNamespace(
        st_uid=1 if change == "owner" else 0,
        st_mode=(stat.S_IFDIR if change == "directory" else stat.S_IFREG)
        | (0o660 if change == "writable" else 0o640),
        st_nlink=2 if change == "hardlink" else 1,
    )
    monkeypatch.setattr(leaf.os, "fstat", lambda *a: metadata)
    if change is None:
        assert leaf._metadata(123) is metadata
    else:
        with pytest.raises(ProviderRefused):
            leaf._metadata(123)


@pytest.mark.parametrize(
    "layout", ["direct", "absolute", "relative", "other", "nonsticky", "symlink_file"]
)
def test_only_standard_root_sticky_lock_layout_is_permitted(
    tmp_path, monkeypatch, layout
):
    var, run = tmp_path / "var", tmp_path / "run"
    var.mkdir()
    run.mkdir()
    if layout in {"absolute", "relative", "other"}:
        (var / "lock").symlink_to(
            {
                "absolute": "/run/lock",
                "relative": "../run/lock",
                "other": "/elsewhere/lock",
            }[layout]
        )
        parent = run
    else:
        parent = var
    (parent / "lock").mkdir(mode=0o777)
    (parent / "lock").chmod(0o777 if layout == "nonsticky" else 0o1777)
    file = parent / "lock" / leaf._LOCK.name
    file.write_bytes(b"executor")
    if layout == "symlink_file":
        target = parent / "target"
        file.rename(target)
        file.symlink_to(target)
    fd = os.open(file, os.O_RDWR)
    leaf.sys.argv[1] = str(fd)
    proxy = SimpleNamespace(**vars(os))

    def root_owned(value):
        values = list(value)
        values[4] = 0
        return os.stat_result(values)

    proxy.stat = lambda *a, **kw: root_owned(os.stat(*a, **kw))
    proxy.fstat = lambda *a: root_owned(os.fstat(*a))
    proxy.geteuid = lambda: 0
    monkeypatch.setattr(leaf, "os", proxy)

    @contextmanager
    def directory(path, **kw):
        actual = {Path("/var"): var, Path("/run"): run}[path]
        directory_fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield directory_fd
        finally:
            os.close(directory_fd)

    monkeypatch.setattr(leaf, "_directory", directory)
    try:
        if layout in {"direct", "absolute", "relative"}:
            with leaf._executor_lock():
                pass
        else:
            with pytest.raises((ProviderRefused, OSError)):
                with leaf._executor_lock():
                    pytest.fail("unsafe lock layout admitted")
    finally:
        os.close(fd)


def test_interrupted_attempt_never_rearms_and_explicit_retirement_remains_possible(
    installed, monkeypatch
):
    original = leaf._recreate
    monkeypatch.setattr(
        leaf, "_recreate", lambda *a, **kw: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    with pytest.raises(KeyboardInterrupt):
        leaf._activate()
    assert (installed.state / "activation-attempt.json").exists()
    assert (installed.state / "activation-incomplete.json").exists()
    assert _host_run(True) == 3
    monkeypatch.setattr(leaf, "_recreate", original)
    assert _host_run(False) == 0


def test_restarting_descriptor_parse_reuses_identical_original_anchor(installed):
    assert _host_run(True) == 0
    raw = (installed.runtime / "installation.json").read_bytes()
    first, _ = loader.installation_cases(loader.installation_document(raw))
    second, _ = loader.installation_cases(loader.installation_document(raw))
    assert tuple(c.clock.deadline for c in first) == tuple(
        c.clock.deadline for c in second
    )
    assert (installed.runtime / "installation.json").read_bytes() == installed.raw


@pytest.mark.parametrize(
    "override", ["COMPOSE_FILE", "ENV_FILE", "HOST_ID_FILE", "LOCK_FILE"]
)
def test_finite_overrides_refuse_before_lock_touch_and_preserve_inherited_bundle(
    tmp_path, override, shell_fixture
):
    lock = tmp_path / "caller.lock"
    lock.write_bytes(b"caller-owned-lock")
    before = lock.stat()
    bundle = tmp_path / "caller-bundle"
    bundle.mkdir()
    sentinel = bundle / "sentinel"
    sentinel.write_bytes(b"caller-owned-data")
    shell_fixture.environment.update(BUNDLE_TMP=str(bundle), **{override: str(lock)})
    canonical_before = shell_fixture.lock.read_bytes()
    result = _shell_run(shell_fixture)
    assert result.returncode == 1
    assert "finite collection requires the canonical executor paths" in result.stderr
    assert lock.read_bytes() == b"caller-owned-lock"
    assert (lock.stat().st_dev, lock.stat().st_ino) == (before.st_dev, before.st_ino)
    assert sentinel.read_bytes() == b"caller-owned-data"
    assert shell_fixture.lock.read_bytes() == canonical_before


@pytest.fixture
def shell_fixture(tmp_path):
    """Private path/UID stand-ins only; real Bash/flock and inherited FD semantics.

    This is not installed host qualification. The unresolved host CP executable
    is a synthetic boundary that asserts the supplied lock description is held.
    No Docker command or daemon participates.
    """
    if shutil.which("flock") is None:
        pytest.skip("hosted Linux flock required")
    lock = tmp_path / "canonical.lock"
    lock.write_bytes(b"original-holder\n")
    lock.chmod(0o600)
    host = tmp_path / "host-id"
    host.write_text("vendor-cp-prod\n")
    source = (ROOT / "scripts/deploy_production.sh").read_text()
    source = source.replace(
        "/var/lock/dotmac_dotmac_vendor_control_plane_deploy.lock", str(lock)
    )
    source = source.replace("/etc/dotmac-host-id", str(host))
    # The protected-root metadata guard is separately sensitivity-tested. This
    # synthetic shell harness runs as the ordinary hosted runner, never root.
    source = source.replace("metadata.st_uid != 0", "metadata.st_uid != os.getuid()")
    script = tmp_path / "executor.sh"
    script.write_text(source)
    (tmp_path / ".env").write_text(
        "APP_ENV=production\nSERVER_NAME=vendor-cp-prod\nENVIRONMENT=production\n"
        "PLATFORM_ROOT_DOMAIN=vendor.dotmac.io\n"
        "VENDOR_DEPLOYMENT_PROFILE=production-bootstrap\nCSRF_ENABLED=true\n"
        + "CSRF_SECRET="
        + "c" * 32
        + "\nJWT_SECRET="
        + "j" * 32
        + "\nSESSION_HASH_SECRET="
        + "s" * 32
        + "\n"
    )
    embedded = source.split("<<'FINITE_COLLECTION'\n", 1)[1].split(
        "\nFINITE_COLLECTION", 1
    )[0]
    standin = """import fcntl, os, sys
fd = int(sys.argv[1])
assert os.fstat(fd).st_ino == os.stat(os.environ['SYNTHETIC_LOCK']).st_ino
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
other = os.open(os.environ['SYNTHETIC_LOCK'], os.O_RDWR)
try:
    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    raise AssertionError('parent did not retain canonical lock')
except BlockingIOError:
    pass
os.close(other)
sys.exit(int(os.environ['SYNTHETIC_STATUS']))
"""
    script.write_text(source.replace(embedded, standin))
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nprintf 'FORBIDDEN_DOCKER_ATTEMPT\\n' >&2\nexit 99\n")
    docker.chmod(0o700)
    bundle = tmp_path / "inherited-bundle"
    bundle.mkdir()
    (bundle / "sentinel").write_bytes(b"do-not-delete")
    environment = dict(
        os.environ,
        PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
        BUNDLE_TMP=str(bundle),
        SYNTHETIC_LOCK=str(lock),
        SYNTHETIC_STATUS="0",
    )
    for name in ("LOCK_FILE", "ENV_FILE", "HOST_ID_FILE", "COMPOSE_FILE"):
        environment.pop(name, None)
    return SimpleNamespace(
        root=tmp_path, script=script, lock=lock, bundle=bundle, environment=environment
    )


def _shell_run(fixture):
    result = subprocess.run(  # noqa: S603 -- reviewed source copy and synthetic fixed inputs
        (
            "bash",
            str(fixture.script),
            "sha256:" + "b" * 64,
            "synthetic-ref",
            "--gate0-collection-retire",
        ),  # noqa: S607 -- hosted Bash
        env=fixture.environment,
        cwd=fixture.root,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert "FORBIDDEN_DOCKER_ATTEMPT" not in result.stderr
    return result


@pytest.mark.parametrize("status", [0, 3])
def test_finite_shell_success_and_refusal_preserve_caller_bundle_and_hold_same_fd(
    shell_fixture, status
):
    shell_fixture.environment["SYNTHETIC_STATUS"] = str(status)
    before = shell_fixture.lock.stat()
    result = _shell_run(shell_fixture)
    assert result.returncode == status, result.stderr
    assert (shell_fixture.bundle / "sentinel").read_bytes() == b"do-not-delete"
    assert shell_fixture.lock.read_bytes().startswith(b"original-holder\n")
    assert (shell_fixture.lock.stat().st_dev, shell_fixture.lock.stat().st_ino) == (
        before.st_dev,
        before.st_ino,
    )


@pytest.mark.parametrize("metadata", ["writable", "hardlink", "owner", "contended"])
def test_finite_bad_lock_or_contention_never_writes_holder_marker(
    shell_fixture, metadata
):
    before = shell_fixture.lock.stat()
    original = shell_fixture.lock.read_bytes()
    descriptor = None
    if metadata == "writable":
        shell_fixture.lock.chmod(0o666)
    elif metadata == "hardlink":
        os.link(shell_fixture.lock, shell_fixture.root / "alias")
    elif metadata == "owner":
        source = shell_fixture.script.read_text().replace(
            "metadata.st_uid != os.getuid()", "metadata.st_uid != os.getuid() + 1"
        )
        shell_fixture.script.write_text(source)
    else:
        descriptor = os.open(shell_fixture.lock, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        result = _shell_run(shell_fixture)
        assert result.returncode == 1
        assert shell_fixture.lock.read_bytes() == original
        assert (shell_fixture.lock.stat().st_dev, shell_fixture.lock.stat().st_ino) == (
            before.st_dev,
            before.st_ino,
        )
        assert (shell_fixture.bundle / "sentinel").read_bytes() == b"do-not-delete"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def test_image_validator_is_inert_closed_and_binds_exact_input(descriptor, monkeypatch):
    monkeypatch.setattr(
        loader,
        "qualify_authority_database",
        lambda *a: pytest.fail("validator qualified DB"),
    )
    runner = ModuleType("vendor_cp.relay.runner")
    runner.authority_database_runtime = lambda: pytest.fail(
        "validator loaded configured DB runtime"
    )
    monkeypatch.setitem(sys.modules, "vendor_cp.relay.runner", runner)
    raw = canonical(descriptor)
    result = strict_object(checker.check_collection_input(raw, "activation"))
    original = result.pop("original_clock")
    assert original["boot_id"] == descriptor["clock_anchor"]["boot_id"]
    assert original["wall_origin"] == descriptor["clock_anchor"]["wall_origin"]
    assert (
        original["monotonic_origin"] == descriptor["clock_anchor"]["monotonic_origin"]
    )
    assert result == {
        "schema": "Gate0CollectionInputCheck.v1",
        "operation": "activation",
        "input_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        **{
            name: descriptor[name]
            for name in (
                "source_revision",
                "image_digest",
                "profile_code",
                "profile_version",
                "profile_digest",
            )
        },
    }
    descriptor["profile_version"] = "unadopted-version"
    descriptor["clock_anchor"]["boot_id"] = "different-original-boot"
    retirement = checker.check_collection_input(canonical(descriptor), "retirement")
    assert strict_object(retirement)["operation"] == "retirement"
    with pytest.raises(ProviderRefused):
        checker.check_collection_input(canonical(descriptor), "activation")


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "oversize",
        "malformed",
        "extra",
        "schema",
        "source",
        "digest",
        "duplicate",
        "duplicate_key",
        "duplicate_surface",
        "boolean",
        "version",
        "code",
        "unaccepted",
        "laboratory",
        "withheld",
        "uninventoried",
        "row_extra",
        "profiles_type",
        "surface_type",
        "empty_code",
    ],
)
def test_image_validator_refuses_declaration_artifact(descriptor, monkeypatch, failure):
    document = _declarations_document()
    row = document["profiles"][0]
    if failure in ("schema", "source", "digest"):
        key = {
            "schema": "schema",
            "source": "source_revision",
            "digest": "foundation_profile_digest",
        }[failure]
        document[key] = "wrong"
    elif failure == "extra":
        document["extra"] = True
    elif failure == "duplicate":
        document["profiles"].append(copy.deepcopy(row))
    elif failure == "duplicate_surface":
        row["surface_inventory"] *= 2
    elif failure == "boolean":
        row["production_accepted"] = 1
    elif failure in ("code", "version"):
        row[failure] = "different"
    elif failure == "unaccepted":
        row["production_accepted"] = False
    elif failure == "laboratory":
        row["laboratory"] = True
    elif failure == "withheld":
        row["surface_inventory"] = []
        row["withheld_surfaces"] = ["gate0_collection_reads"]
    elif failure == "uninventoried":
        row["surface_inventory"] = []
    elif failure == "row_extra":
        row["extra"] = True
    elif failure == "profiles_type":
        document["profiles"] = {}
    elif failure == "surface_type":
        row["surface_inventory"] = "gate0_collection_reads"
    elif failure == "empty_code":
        row["code"] = ""
    artifact = canonical(document)
    if failure == "oversize":
        artifact = b" " * 524289
    elif failure == "malformed":
        artifact = b"{"
    elif failure == "duplicate_key":
        artifact = artifact.replace(b'{"code":', b'{"code":"duplicate","code":', 1)

    def open_artifact(path, *args, **kwargs):
        assert str(path) == "/app/deployment_profile_declarations.json"
        if failure == "missing":
            raise FileNotFoundError()
        return io.BytesIO(artifact)

    monkeypatch.setattr(Path, "open", open_artifact)
    with pytest.raises(ProviderRefused):
        checker.check_collection_input(canonical(descriptor), "activation")


def test_retirement_does_not_read_declaration_artifact(descriptor, monkeypatch):
    def refuse_artifact(*args, **kwargs):
        pytest.fail("retirement read profile declarations")

    monkeypatch.setattr(Path, "open", refuse_artifact)
    descriptor.update(profile_code="retired-profile", profile_version="retired-version")
    checker.check_collection_input(canonical(descriptor), "retirement")


def test_activation_declaration_read_has_a_fixed_byte_budget(descriptor, monkeypatch):
    reads = []

    class BoundedArtifact(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    monkeypatch.setattr(
        Path,
        "open",
        lambda *args, **kwargs: BoundedArtifact(canonical(_declarations_document())),
    )
    checker.check_collection_input(canonical(descriptor), "activation")
    assert reads == [524289]


def test_consumer_import_and_data_reader_are_inert_in_fresh_process(descriptor):
    script = r"""
import importlib.abc
import io
import json
import socket
import sys
from pathlib import Path


class RefuseRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blocked = (
            "vendor_cp.assembly", "vendor_cp.config", "vendor_cp.deployment_profile",
            "vendor_cp.deployment.profile", "vendor_cp.main",
            "vendor_cp.licensing.signing_adapter", "dotmac_kernel.db",
            "dotmac_kernel.session_runtime", "dotmac_kernel.app_factory",
            "vendor_cp.relay.runner",
        )
        if any(fullname == name or fullname.startswith(name + ".") for name in blocked):
            raise AssertionError("consumer imported runtime owner: " + fullname)


sys.meta_path.insert(0, RefuseRuntime())
sys.path.insert(0, sys.argv[1])


def refuse_network(*args, **kwargs):
    raise AssertionError("consumer attempted network I/O")


socket.socket.connect = refuse_network
socket.socket.connect_ex = refuse_network
socket.create_connection = refuse_network
checker = importlib.import_module("vendor_cp.deployment.gate0_collection_activation")
canonical = checker.canonical
inputs = json.loads(sys.stdin.buffer.read())
value = inputs["descriptor"]
Path.open = lambda *args, **kwargs: io.BytesIO(canonical(inputs["declarations"]))
checker._require_collection_profile(value)
checker.installation_document = lambda raw: value
Path.open = refuse_network
checker.check_collection_input(canonical(value), "retirement")
"""
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    # Source-only subprocess: installed-image identity remains a separate obligation.
    result = subprocess.run(  # noqa: S603 -- fixed hosted source-check script, synthetic stdin, no host operations
        [sys.executable, "-c", script, str(ROOT / "src")],
        input=canonical(
            {"descriptor": descriptor, "declarations": _declarations_document()}
        ),
        capture_output=True,
        env=environment,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("change", ["source", "profile_digest", "oversize"])
def test_image_validator_refuses_artifact_or_input_mismatch(descriptor, change):
    if change == "source":
        descriptor["source_revision"] = "e" * 40
    elif change == "profile_digest":
        descriptor["profile_digest"] = "sha256:" + "e" * 64
    raw = canonical(descriptor) if change != "oversize" else b" " * 524289
    with pytest.raises(ValueError):
        checker.check_collection_input(raw, "retirement")


def test_host_stdout_is_bounded_while_collecting_and_exact_child_reaped(monkeypatch):
    original = subprocess.Popen
    children = []

    def popen(arguments, **kwargs):
        assert kwargs["close_fds"] is True
        assert not any("LOCK_FD" in key for key in kwargs["env"])
        child = original(
            (
                sys.executable,
                "-c",
                "import os,time; os.write(1,b'x'*65536); time.sleep(60)",
            ),
            **kwargs,
        )
        children.append(child)
        return child

    monkeypatch.setattr(leaf.subprocess, "Popen", popen)
    with pytest.raises(ProviderRefused):
        leaf._call(("synthetic-observation",), maximum=64)
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize("failure", [None, "verdict", "run", "cleanup", "missing_cid"])
def test_isolated_image_check_requires_exact_owned_container_cleanup(
    tmp_path, monkeypatch, descriptor, failure
):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(leaf, "_STATE", state)
    temporary = state / "activation-helper"
    reference = leaf._REPOSITORY + "@" + descriptor["image_digest"]
    cid = "d" * 64
    commands = []
    selected_name = []

    @contextmanager
    def directory(path, **kwargs):
        actual = path
        if kwargs.get("create"):
            actual.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(leaf, "_directory", directory)
    monkeypatch.setattr(leaf, "_metadata", lambda fd, **kwargs: os.fstat(fd))
    raw = canonical(descriptor)

    def call(arguments, **kwargs):
        commands.append((arguments, kwargs))
        if arguments[0] == "run":
            selected_name.append(arguments[arguments.index("--name") + 1])
            if failure == "missing_cid":
                raise ProviderRefused()
            Path(arguments[arguments.index("--cidfile") + 1]).write_text(cid)
            if failure == "run":
                raise ProviderRefused()
            result = strict_object(
                checker.check_collection_input(kwargs["input_bytes"], "activation")
            )
            if failure == "verdict":
                result["input_digest"] = "sha256:" + "f" * 64
            return canonical(result).decode()
        if arguments[0] == "inspect":
            return canonical(
                {
                    "id": cid,
                    "name": "/" + selected_name[0],
                    "image": reference,
                    "input": leaf._hash(raw),
                }
            ).decode()
        assert arguments == ("rm", "--force", cid)
        if failure == "cleanup":
            raise ProviderRefused()
        return cid

    monkeypatch.setattr(leaf, "_call", call)
    with directory(state) as state_fd:
        if failure is None:
            leaf._validate_image_input(
                state_fd, raw, descriptor, reference, activation=True
            )
            assert not temporary.exists()
        else:
            with pytest.raises((ValueError, OSError)):
                leaf._validate_image_input(
                    state_fd, raw, descriptor, reference, activation=True
                )
    run, kwargs = commands[0]
    assert run[0] == "run"
    assert run[-3:] == (reference, "gate0", "collection-check-activation")
    assert kwargs["input_bytes"] == raw and kwargs["maximum"] == 4096
    for option, value in (
        ("--pull", "never"),
        ("--user", "10001:10001"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--entrypoint", "/opt/venv/bin/dotmac-platform"),
    ):
        assert run[run.index(option) + 1] == value
    assert "--read-only" in run and "--memory" in run and "--pids-limit" in run
    assert not {
        "--mount",
        "--volume",
        "-v",
        "--env-file",
        "--pid",
        "--privileged",
    }.intersection(run)
    assert not any(
        "LOCK_FD" in str(argument)
        or ".env" == argument
        or "docker.sock" in str(argument)
        for argument in run
    )
    if failure != "missing_cid":
        assert commands[-1][0] == ("rm", "--force", cid)


@pytest.fixture
def actual_helper(installed, monkeypatch):
    """Keep real durable helper ownership and cleanup; substitute Docker only."""
    monkeypatch.setattr(leaf, "_validate_image_input", installed.native_validate)
    commands = []
    active = {}
    failure = {"kind": None}
    original_time = leaf.time
    original_datetime = leaf.datetime

    def call(arguments, **kwargs):
        commands.append(arguments)
        if arguments[0] == "run":
            operation = (
                "activation" if arguments[-1].endswith("activation") else "retirement"
            )
            assert (installed.state / (operation + "-attempt.json")).exists()
            owned = strict_object(
                (installed.state / (operation + "-helper-owned.json")).read_bytes()
            )
            assert owned["name"] == arguments[arguments.index("--name") + 1]
            assert owned["reference"] == installed.reference
            assert owned["operation"] == operation
            assert owned["installation_digest"] == leaf._hash(installed.raw)
            active.update(name=owned["name"], operation=operation, cid="d" * 64)
            if failure["kind"] == "missing_cid":
                raise ProviderRefused()
            Path(arguments[arguments.index("--cidfile") + 1]).write_text(active["cid"])
            result = strict_object(
                checker.check_collection_input(kwargs["input_bytes"], operation)
            )
            active["clock"] = result["original_clock"]
            return canonical(result).decode()
        if arguments[0] == "inspect":
            return canonical(
                {
                    "id": active["cid"],
                    "name": "/" + active["name"],
                    "image": installed.reference,
                    "input": leaf._hash(installed.raw),
                }
            ).decode()
        assert arguments == ("rm", "--force", active["cid"])
        if failure["kind"] == "cleanup":
            raise ProviderRefused()
        if (
            failure["kind"] == "monotonic_expiry"
            and active["operation"] == "activation"
        ):
            leaf.time = SimpleNamespace(
                monotonic=lambda: active["clock"]["a_monotonic_end"] + 1
            )
        if failure["kind"] == "wall_expiry" and active["operation"] == "activation":
            expiry = datetime.fromisoformat(
                active["clock"]["a_expires_at"].replace("Z", "+00:00")
            )

            class AfterExpiry(datetime):
                @classmethod
                def now(cls, tz=None):
                    return expiry + timedelta(seconds=1)

            leaf.datetime = AfterExpiry
        return active["cid"]

    monkeypatch.setattr(leaf, "_call", call)
    return SimpleNamespace(
        commands=commands,
        failure=failure,
        original_time=original_time,
        original_datetime=original_datetime,
    )


@pytest.mark.parametrize("operation", ["activation", "retirement"])
@pytest.mark.parametrize("failure", ["missing_cid", "cleanup"])
def test_uncertain_helper_is_sticky_before_second_invocation_or_other_operation(
    installed, actual_helper, operation, failure
):
    if operation == "retirement":
        # First complete activation with its own claimed and confirmed helper.
        assert _host_run(True) == 0
    prior = sum(command[0] == "run" for command in actual_helper.commands)
    actual_helper.failure["kind"] = failure
    assert _host_run(operation == "activation") == 3
    assert (installed.state / (operation + "-attempt.json")).exists()
    assert (installed.state / (operation + "-incomplete.json")).exists()
    assert (installed.state / (operation + "-helper-owned.json")).exists()
    assert (installed.state / (operation + "-helper-incomplete.json")).exists()
    assert not (installed.state / (operation + "-helper-complete.json")).exists()
    retained = {
        path.name: path.read_bytes()
        for path in installed.state.iterdir()
        if path.is_file()
    }
    assert _host_run(True) == 3
    assert _host_run(False) == 3
    assert sum(command[0] == "run" for command in actual_helper.commands) == prior + 1
    assert retained == {
        path.name: path.read_bytes()
        for path in installed.state.iterdir()
        if path.is_file()
    }


@pytest.mark.parametrize("clock", ["monotonic_expiry", "wall_expiry"])
def test_helper_cleanup_crossing_original_expiry_cannot_publish_or_recreate(
    installed, actual_helper, clock
):
    actual_helper.failure["kind"] = clock
    assert _host_run(True) == 3
    assert not installed.calls
    assert not (installed.runtime / "installation.json").exists()
    assert (installed.state / "activation-incomplete.json").exists()
    assert (installed.state / "activation-helper-complete.json").exists()
    assert not (installed.state / "activation-complete.json").exists()
    assert sum(command[0] == "run" for command in actual_helper.commands) == 1
    assert _host_run(True) == 3
    assert sum(command[0] == "run" for command in actual_helper.commands) == 1
    # A confirmed helper retirement permits explicit same-image app retirement,
    # which does not ask the expired activation clock for new permission.
    leaf.time = actual_helper.original_time
    leaf.datetime = actual_helper.original_datetime
    actual_helper.failure["kind"] = None
    assert _host_run(False) == 0
    assert installed.calls == [(installed.reference, leaf._BOOTSTRAP, False)]


def test_original_clock_projection_cannot_replace_anchor_or_boot(
    descriptor, monkeypatch
):
    result = strict_object(
        checker.check_collection_input(canonical(descriptor), "activation")
    )
    leaf._original_open(result, descriptor)
    forged = copy.deepcopy(result)
    forged["original_clock"]["monotonic_origin"] += 1
    with pytest.raises(ProviderRefused):
        leaf._original_open(forged, descriptor)
    monkeypatch.setattr(
        Path, "read_text", lambda *a, **kwargs: "00000000-0000-0000-0000-000000000002"
    )
    with pytest.raises(ProviderRefused):
        leaf._original_open(result, descriptor)


def test_missing_durable_helper_ownership_never_unblocks_an_incomplete_attempt(
    installed, actual_helper
):
    actual_helper.failure["kind"] = "missing_cid"
    assert _host_run(True) == 3
    (installed.state / "activation-helper-owned.json").unlink()
    assert _host_run(False) == 3
    assert sum(command[0] == "run" for command in actual_helper.commands) == 1
    assert not (installed.state / "retirement-attempt.json").exists()
