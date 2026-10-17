"""Synthetic source observations; none is official-runner native evidence."""

from __future__ import annotations

import ast
import os
import select
import socket
import sysconfig
import time
from collections.abc import MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_a9_native_fixture as fixture
from vendor_cp.deployment import gate0_runner_lifecycle as life
from vendor_cp.deployment import gate0_runner_lifecycle_courier as courier
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


class NamesOnly(MutableMapping):
    """MutableMapping membership/get/pop would read; record outside refusal path."""

    def __init__(self, names, broken=False):
        self.names = list(names)
        self.reads = 0
        self.broken = broken

    def __iter__(self):
        if self.broken:
            raise OSError("synthetic failure")
        return iter(self.names)

    def __len__(self):
        return len(self.names)

    def __getitem__(self, key):
        self.reads += 1
        raise AssertionError("value access forbidden")

    def __setitem__(self, key, value):
        raise AssertionError("mutation forbidden")

    def __delitem__(self, key):
        self.names.remove(key)


class SubjectEnvironment:
    """Trap subject value reads without replacing the reporter's environment."""

    def __init__(self, environment):
        self.environ = environment

    def getenv(self, key, default=None):
        return self.environ.get(key, default)

    def __getattr__(self, name):
        if name in {"environb", "getenvb"}:
            raise AssertionError("byte environment access forbidden")
        return getattr(os, name)


@pytest.mark.parametrize("subject", [fixture, courier, life])
def test_strict_environment_is_local_to_subject(monkeypatch, subject):
    original_environment = os.environ
    environment = NamesOnly(["SYNTHETIC_PRIVATE_VALUE"])
    monkeypatch.setattr(subject, "os", SubjectEnvironment(environment))
    process_environment_unchanged = os.environ is original_environment
    subject_environment_is_strict = subject.os.environ is environment
    assert process_environment_unchanged and subject_environment_is_strict
    # The reporter may query this public formatting flag even on a failure.
    os.getenv("PY_COLORS")
    with pytest.raises(AssertionError, match="value access forbidden"):
        subject.os.environ.get("SYNTHETIC_PRIVATE_VALUE")
    with pytest.raises(AssertionError, match="value access forbidden"):
        subject.os.getenv("SYNTHETIC_PRIVATE_VALUE")
    with pytest.raises(AssertionError, match="byte environment access forbidden"):
        subject.os.getenvb(b"SYNTHETIC_PRIVATE_VALUE")
    assert environment.reads == 2


@pytest.mark.parametrize("present", [False, True])
def test_probe_only_iterates_names(monkeypatch, capsys, present):
    env = NamesOnly(
        ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        + (["ACTIONS_ID_TOKEN_REQUEST_URL"] if present else [])
    )
    monkeypatch.setattr(fixture, "os", SubjectEnvironment(env))
    assert fixture.run_installed_url_presence_probe() == (3 if present else 0)
    assert env.reads == 0
    assert capsys.readouterr().out == "Gate0A9UrlPresence.v1 " + (
        "present\n" if present else "absent\n"
    )


def test_probe_unavailable_has_fixed_output_and_no_reads(monkeypatch, capsys):
    env = NamesOnly([], broken=True)
    monkeypatch.setattr(fixture, "os", SubjectEnvironment(env))
    assert fixture.run_installed_url_presence_probe() == 4
    assert env.reads == 0
    assert capsys.readouterr().out == "Gate0A9UrlPresence.v1 unavailable\n"


@pytest.fixture
def installed_inputs(monkeypatch):
    now = datetime.now(UTC) - timedelta(seconds=1)
    boot = "12345678-1234-1234-1234-123456789abc"
    bounds = dict(
        boot_id=boot,
        wall=now.isoformat(),
        monotonic=time.monotonic() - 1,
        provisioning_ends_at=(now + timedelta(seconds=60)).isoformat(),
        finalization_ends_at=(now + timedelta(seconds=90)).isoformat(),
    )
    files = {}

    def pin(path, raw=b"synthetic-public-code"):
        files[str(path)] = raw
        return dict(path=str(path), digest=life._hash(raw))

    cli = pin("/installed/bin/dotmac-platform", b"#!/installed/bin/python\nsynthetic\n")
    interpreter = pin("/installed/bin/python")
    listener = dict(path=str(life._RUNNER), digest=life._hash(b"listener"))
    tree = life._hash(b"actual-synthetic-tree")
    workflow = pin(fixture._ROOT / "workflow.yml", b"synthetic-workflow")
    script = pin(fixture._ROOT / "script.sh", b"synthetic-script")
    bash = pin("/usr/bin/bash")
    worker = pin("/opt/dotmac-gate0-jit/bin/Runner.Worker")
    runtime = dict(
        observer_module=pin(Path(fixture.__file__).absolute()),
        cli=cli,
        interpreter=interpreter,
        bash=bash,
        listener=listener,
        worker=worker,
        runner_tree_digest=tree,
        workflow=workflow,
        script_template=script,
    )
    inventory = dict(
        schema="Gate0A9NativeFixtureInventory.v1",
        disposition="UNQUALIFIED",
        boot_id=boot,
        kernel_release=os.uname().release,
        systemd_version="synthetic-external-inventory",
        runner_tree_digest=tree,
        runtime_pins_digest=life._hash(canonical(runtime)),
        observed_at_utc=now.isoformat(),
    )
    inventory_pin = pin(fixture._ROOT / "inventory.json", canonical(inventory))
    coordinates = dict(
        repository_id=1,
        owner_id=2,
        run_id=3,
        attempt=1,
        workflow_id=4,
        source_revision="a" * 40,
        environment_id=5,
        job_id=6,
        job_name="synthetic job",
        runner_id=7,
        runner_name="synthetic runner",
        runner_group_id=8,
    )
    launcher = dict(
        schema="Gate0A9JitLauncherSelection.v1",
        **{
            k: v
            for k, v in coordinates.items()
            if k not in ("repository_id", "run_id", "attempt")
        },
        cli=cli,
        interpreter=interpreter,
        systemctl=dict(path="/usr/bin/systemctl", digest=life._hash(b"unused")),
        manager=dict(path="/usr/lib/systemd/systemd", digest=life._hash(b"unused")),
        runner_binary=listener,
        runner_tree_digest=tree,
        unit_digest=life._hash(b"unused"),
        groups=[4002],
        native_receipt_digest=inventory_pin["digest"],
    )
    sources = {}
    for name in ("gate0_runner_lifecycle", "gate0_runner_lifecycle_courier"):
        sources[name] = pin(Path(fixture.__file__).parent / (name + ".py"))["digest"]
    courier_doc = dict(
        schema="Gate0A9CourierSelection.v1",
        lifecycle_binding_digest=life._hash(b"independent intent"),
        courier_uid=4001,
        courier_gid=4002,
        groups=[4002],
        original_bounds=bounds,
        launcher=launcher,
        source_files=sources,
    )
    policy = dict(
        schema="Gate0A9BrokerPolicy.v1",
        method=fixture._SUPPLIER_METHOD,
        amendment_digest=fixture._SUPPLIER_AMENDMENT,
        supplier_commit=fixture._SUPPLIER_SOURCE,
        origins=["https://synthetic.example"],
        profile=dict(
            worker_binary=worker,
            shell_binary=bash,
            script_template=script,
            script_directory="/run/dotmac-gate0-jit/work/_temp",
            workflow_source_digest=workflow["digest"],
            worker_pipe_handle_format="unix-decimal-fd.v1",
        ),
    )
    selection = dict(
        schema="Gate0A9NativeFixtureSelection.v1",
        procedure_digest=life._hash(b"reviewed procedure"),
        case="metadata-positive",
        fixture_id="synthetic-fixture",
        boot_id=boot,
        original_bounds=bounds,
        courier_selection=pin(
            fixture._SOCKET.parent / "installation.json", canonical(courier_doc)
        ),
        preliminary_inventory=inventory_pin,
        broker_policy=pin(
            fixture._SOCKET.parents[1] / "broker-policy.json", canonical(policy)
        ),
        runtime_pins=runtime,
        listener=dict(pid=400, start="40", boot_id=boot, cgroup=fixture._GROUP),
        coordinates=coordinates,
        github_observation=dict(
            path=str(fixture._GITHUB),
            observer_identity="synthetic-root-owner",
            read_provider_identity="existing-github-reader",
            max_age_seconds=30,
        ),
        negative_probe=None,
    )
    reads, mounts = [], []

    def protected(path, *args, **kwargs):
        reads.append(str(path))
        assert str(path) != str(
            life._RUNNER
        ), "runtime Listener has courier-owned ancestor"
        return files[str(path)]

    monkeypatch.setattr(fixture, "_protected", protected)
    original_stat = os.stat

    def protected_stat(path, *args, **kwargs):
        if str(path) in files and (
            Path(path).is_relative_to(fixture._ROOT)
            or str(path).endswith("/broker-policy.json")
        ):
            return SimpleNamespace(st_gid=0)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", protected_stat)
    monkeypatch.setattr(life, "_proc", lambda *_: (boot + "\n").encode())
    monkeypatch.setattr(fixture, "_proc", lambda *_: (boot + "\n").encode())
    monkeypatch.setattr(
        fixture, "_qualify_runner_mounts", lambda *args: mounts.append(args)
    )
    monkeypatch.setattr(os, "readlink", lambda *_: interpreter["path"])
    monkeypatch.setattr(
        sysconfig, "get_path", lambda *_: str(Path(fixture.__file__).parent)
    )
    return SimpleNamespace(
        selection=selection,
        files=files,
        pin=pin,
        reads=reads,
        mounts=mounts,
        policy=policy,
        inventory=inventory,
        courier=courier_doc,
        now=now,
    )


def test_actual_selection_validator_joins_inputs_without_qualification(
    installed_inputs,
):
    f = installed_inputs
    doc, courier_doc, policy, bounds = fixture._installed_inputs(canonical(f.selection))
    assert doc == f.selection and courier_doc == f.courier and policy == f.policy
    assert bounds.boot_id == doc["boot_id"]
    assert f.mounts == [(f.selection["runtime_pins"]["listener"]["digest"], 4001)]
    assert str(life._RUNNER) not in f.reads
    assert (
        doc["preliminary_inventory"]["digest"]
        == courier_doc["launcher"]["native_receipt_digest"]
    )
    with pytest.raises(life.LifecycleRefused):
        fixture._record(
            canonical(f.inventory),
            "schema boot_id kernel_release runner_tree_digest systemd_version "
            "supplier_observation supplier_review",
            "Gate0A9LifecycleNative.v2",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "boolean-id",
        "wrong-job",
        "bare-digest",
        "tree",
        "inventory-flag",
        "workflow",
        "origin",
        "listener-cgroup",
        "negative-outcome",
        "missing-pin",
        "old-schema",
    ],
)
def test_selection_refuses_changed_or_fabricated_inputs(installed_inputs, mutation):
    f, d = installed_inputs, installed_inputs.selection
    if mutation == "unknown":
        d["qualified"] = True
    elif mutation == "boolean-id":
        d["coordinates"]["job_id"] = True
    elif mutation == "wrong-job":
        d["coordinates"]["job_id"] += 1
    elif mutation == "bare-digest":
        d["procedure_digest"] = "a" * 64
    elif mutation == "tree":
        d["runtime_pins"]["runner_tree_digest"] = life._hash(b"changed")
    elif mutation == "inventory-flag":
        f.inventory["qualified"] = True
        d["preliminary_inventory"] = f.pin(
            fixture._ROOT / "inventory.json", canonical(f.inventory)
        )
    elif mutation == "workflow":
        f.files[str(fixture._ROOT / "workflow.yml")] = b"changed"
    elif mutation == "origin":
        f.policy["origins"].append("https://allowed.example@evil.example")
        d["broker_policy"] = f.pin(
            fixture._SOCKET.parents[1] / "broker-policy.json", canonical(f.policy)
        )
    elif mutation == "listener-cgroup":
        d["listener"]["cgroup"] = life._JIT_GROUP
    elif mutation == "negative-outcome":
        d["negative_probe"] = dict(absent=True)
    elif mutation == "missing-pin":
        del d["runtime_pins"]["worker"]
    else:
        d["schema"] = "Gate0A9NativeFixtureSelection.v0"
    with pytest.raises((life.LifecycleRefused, ProviderRefused, KeyError)):
        fixture._installed_inputs(canonical(d))


def github_packet(f):
    selection = f.selection
    observed = datetime.now(UTC) - timedelta(milliseconds=100)
    return dict(
        schema="Gate0A9NativeFixtureGitHubObservation.v1",
        observer_identity=selection["github_observation"]["observer_identity"],
        read_provider_identity=selection["github_observation"][
            "read_provider_identity"
        ],
        observed_at_utc=observed.isoformat(),
        valid_until_utc=(observed + timedelta(seconds=20)).isoformat(),
        fixture_id=selection["fixture_id"],
        coordinates=dict(selection["coordinates"]),
        job_status="in_progress",
        job_conclusion=None,
        environment_review=dict(state="approved", environment_ids=[5]),
        workflow_source_digest=selection["runtime_pins"]["workflow"]["digest"],
        evidence=dict(
            job_snapshot=f.pin(
                fixture._ROOT / "github-job-read.json",
                b"authenticated synthetic external job read",
            ),
            review=f.pin(
                fixture._ROOT / "github-review-read.json",
                b"authenticated synthetic external review read",
            ),
            workflow_source=selection["runtime_pins"]["workflow"],
        ),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "job",
        "review",
        "cancel",
        "stale",
        "future",
        "expiry",
        "provider",
        "source",
        "replaced",
    ],
)
def test_held_github_packet_freshness_and_selected_coordinates(
    installed_inputs, mutation
):
    f = installed_inputs
    doc, _, _, bounds = fixture._installed_inputs(canonical(f.selection))
    packet = github_packet(f)
    if mutation == "job":
        packet["coordinates"]["job_id"] += 1
    elif mutation == "review":
        packet["environment_review"]["state"] = "rejected"
    elif mutation == "cancel":
        packet["job_status"] = "cancelled"
    elif mutation == "stale":
        packet["observed_at_utc"] = (
            datetime.now(UTC) - timedelta(seconds=40)
        ).isoformat()
    elif mutation == "future":
        packet["observed_at_utc"] = (
            datetime.now(UTC) + timedelta(seconds=1)
        ).isoformat()
    elif mutation == "expiry":
        packet["valid_until_utc"] = datetime.now(UTC).isoformat()
    elif mutation == "provider":
        packet["read_provider_identity"] = "other"
    elif mutation == "source":
        packet["workflow_source_digest"] = life._hash(b"other")

    def recheck():
        if mutation == "replaced":
            raise life.LifecycleRefused()

    held = SimpleNamespace(raw=canonical(packet), recheck=recheck)
    if mutation is None:
        fixture._fresh_github(held, doc, bounds)
    else:
        with pytest.raises(life.LifecycleRefused):
            fixture._fresh_github(held, doc, bounds)


@pytest.mark.parametrize(
    "raw",
    [
        b"synthetic-unsolicited-secret-marker",
        b"{}",
        canonical(
            dict(
                schema="Gate0A9BrokerMetadata.v1",
                url="https://synthetic.example/p?x=1",
                extra=True,
            )
        ),
        canonical(
            dict(
                schema="Gate0A9BrokerMetadata.v1",
                url="https://synthetic.example/p?audience=x",
            )
        ),
        canonical(
            dict(
                schema="Gate0A9BrokerMetadata.v1",
                url="https://user@synthetic.example/p?x=1",
            )
        ),
        b"x" * 32769,
    ],
)
def test_metadata_refusals_do_not_accept_arbitrary_payloads(raw):
    with pytest.raises((ValueError, life.LifecycleRefused, ProviderRefused)):
        fixture._metadata(raw, "metadata-positive", ["https://synthetic.example"])
    with pytest.raises(life.LifecycleRefused):
        fixture._metadata(raw, "missing-url-negative", ["https://synthetic.example"])


def test_metadata_retains_only_hashes_and_independently_allowed_origin():
    raw = canonical(
        dict(
            schema="Gate0A9BrokerMetadata.v1",
            url="https://synthetic.example/opaque%41?x=selected",
        )
    )
    observed = fixture._metadata(
        raw, "metadata-positive", ["https://synthetic.example"]
    )
    assert observed == dict(
        frame_digest=life._hash(raw),
        origin="https://synthetic.example",
        path_digest=life._hash(b"/opaque%41"),
        query_digest=life._hash(b"x=selected"),
    )
    assert b"selected" not in canonical(observed)
    assert fixture._metadata(b"", "missing-url-negative", []) is None


@pytest.mark.parametrize(
    "flags,ancillary",
    [
        (socket.MSG_TRUNC, []),
        (socket.MSG_CTRUNC, []),
        (0, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"")]),
    ],
)
def test_frame_rejects_truncation_and_ancillary(monkeypatch, flags, ancillary):
    closed = []
    monkeypatch.setattr(
        fixture, "_close_received_descriptors", lambda x: closed.append(x)
    )
    channel = SimpleNamespace(
        settimeout=lambda _: None,
        recvmsg=lambda *_: (b"metadata", ancillary, flags, None),
    )
    with pytest.raises(life.LifecycleRefused):
        fixture._metadata_frame(channel, time.monotonic() + 1)
    assert closed == [ancillary]


def test_production_wrapper_retains_policy_measurement_current_order(monkeypatch):
    events = []
    native = SimpleNamespace(
        _supplier_policy=lambda: events.append("policy") or dict(profile={}),
        selection={},
        lifecycle=SimpleNamespace(_doc=dict(courier_uid=1, courier_gid=2)),
        pid=3,
        start="4",
        bounds=SimpleNamespace(provisioning_end=9.0),
        _retain_chain_process=object(),
        _require_current=lambda: events.append("current"),
    )
    expected = ((100, 200, "1", b"fixed-command"),)

    def measured(*args):
        assert args[5] == life._JIT_GROUP and args[-1] is native._retain_chain_process
        events.append("measurement")
        return expected

    monkeypatch.setattr(life, "_measure_supplier_chain_readonly", measured)
    assert (
        life.NativeJitInvocation._measure_supplier_chain_once(native, 100) == expected
    )
    assert events == ["policy", "measurement", "current"]


def test_fixture_has_no_activation_token_qualification_or_binding_reach():
    source = Path(fixture.__file__).read_text()
    tree = ast.parse(source)
    calls = [n.func for n in ast.walk(tree) if isinstance(n, ast.Call)]
    names = {
        n.id
        if isinstance(n, ast.Name)
        else n.attr
        if isinstance(n, ast.Attribute)
        else ""
        for n in calls
    }
    assert names.isdisjoint(
        {
            "NativeJitInvocation",
            "InstalledA9Lifecycle",
            "_qualify_installed",
            "_supplier_policy",
            "start_once",
            "bind_protected_job",
            "_bind_actual_job_installation",
            "InstalledJobTokens",
            "_token_child",
            "urlopen",
            "request",
            "Popen",
            "run",
        }
    )
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == "NativeJitInvocation"
        ):
            assert n.attr == "_selection"
    assert (
        "_SECRET_READY" not in source and "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in source
    )


class JobEnvironment(MutableMapping):
    def __init__(self):
        self.token_reads = 0
        self.deleted = False

    def __iter__(self):
        return iter(["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"])

    def __len__(self):
        return 2

    def __getitem__(self, key):
        if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
            self.token_reads += 1
            raise AssertionError("token value must remain untouched")
        return "https://synthetic.example/opaque?x=1"

    def __setitem__(self, key, value):
        raise AssertionError("no environment writes")

    def __delitem__(self, key):
        assert key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        self.deleted = True


def test_real_courier_refuses_observer_close_without_token_getter(monkeypatch):
    import struct

    env, sent = JobEnvironment(), []
    responses = [life._METADATA_READY, b""]
    channel = SimpleNamespace(
        settimeout=lambda _: None,
        connect=lambda _: None,
        getsockopt=lambda *_: struct.pack("3i", 1, 0, 0),
        recvmsg=lambda *_: (responses.pop(0), [], 0, None),
        send=lambda raw: sent.append(raw) or len(raw),
        close=lambda: None,
    )
    monkeypatch.setattr(
        courier,
        "_installed_public_selection",
        lambda: ({}, {}, SimpleNamespace(provisioning_end=time.monotonic() + 10)),
    )
    monkeypatch.setattr(courier.socket, "socket", lambda *_: channel)
    monkeypatch.setattr(courier, "os", SubjectEnvironment(env))
    assert courier.run_installed_job_courier() == 3
    assert env.token_reads == 0 and env.deleted
    assert len(sent) == 1 and b"Gate0A9BrokerMetadata.v1" in sent[0]


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "absent",
        "duplicate",
        "writable",
        "zero",
        "past-end",
        "oversize",
        "changed",
        "reused",
    ],
)
def test_actual_retained_descriptor_requires_unique_readonly_matching_script(
    monkeypatch, tmp_path, mutation
):
    path = tmp_path / "generated.sh"
    raw = b"synthetic-read-context\nbuiltin exit\n"
    if mutation == "oversize":
        raw = b"x" * 65537
    path.write_bytes(raw)
    fd = os.open(path, os.O_RDWR if mutation == "writable" else os.O_RDONLY)
    duplicate = -1
    observed = None
    try:
        if mutation != "zero":
            os.read(fd, 1)
        if mutation == "past-end":
            os.lseek(fd, len(raw) + 1, os.SEEK_SET)
        if mutation == "duplicate":
            duplicate = os.dup(fd)
        identity = life._stable(os.fstat(fd))
        monkeypatch.setattr(fixture, "_measure_generated_script", lambda *_: identity)
        monkeypatch.setattr(
            fixture,
            "measure_handoff_process",
            lambda _: (1, os.getuid(), "different" if mutation == "reused" else "same"),
        )
        if mutation == "absent":
            os.close(fd)
            fd = -1
        if mutation == "changed":
            path.write_bytes(b"changed-script")
        if mutation is None:
            observed = fixture._ScriptDescriptor(
                os.getpid(),
                "same",
                path,
                life._hash(raw),
                os.getuid(),
                time.monotonic() + 5,
            )
            record = observed.recheck()
            assert record["position_before"] == record["position_after"] == 1
            assert record["content_digest"] == life._hash(raw)
            assert (
                record["file"]["inode"] == record["path_file"]["inode"] == identity[1]
            )
            assert os.lseek(fd, 0, os.SEEK_CUR) == 1
        else:
            with pytest.raises((life.LifecycleRefused, OSError)):
                fixture._ScriptDescriptor(
                    os.getpid(),
                    "same",
                    path,
                    life._hash(raw),
                    os.getuid(),
                    time.monotonic() + 5,
                )
    finally:
        if observed is not None:
            observed.close()
        for owned in (fd, duplicate):
            if owned >= 0:
                os.close(owned)


def test_pidfd_unavailable_has_no_fallback(monkeypatch):
    monkeypatch.delattr(os, "pidfd_open")
    owned = fixture._LiveProcesses()
    with pytest.raises(OSError):
        owned.retain(100, "1")
    assert owned.owned == {}


@pytest.mark.parametrize("name", ["attempt", "observation.json"])
def test_createonce_never_overwrites_preexisting_file(tmp_path, name):
    (tmp_path / name).write_bytes(b"preexisting")
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            fixture._create_fixed(parent, name, b"new", time.monotonic() + 1)
        assert (tmp_path / name).read_bytes() == b"preexisting"
    finally:
        os.close(parent)


@pytest.mark.parametrize("name", ["attempt", "observation.json"])
def test_failed_output_write_rolls_back_only_owned_output_not_attempt(
    monkeypatch, tmp_path, name
):
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(
        os,
        "write",
        lambda *_: (_ for _ in ()).throw(OSError("synthetic write failure")),
    )
    try:
        with pytest.raises(OSError):
            fixture._create_fixed(parent, name, b"new", time.monotonic() + 1)
        assert (tmp_path / name).exists() is (name == "attempt")
    finally:
        os.close(parent)


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "withdrawn-before-ready",
        "script",
        "early-frame",
        "metadata",
        "second-peer",
        "extra-frame",
        "exit-timeout",
    ],
)
def test_actual_observer_protocol_publication_and_failure_cleanup(
    monkeypatch, tmp_path, installed_inputs, failure
):
    """Actual observer and actual create-once writer; only external boundaries fake."""
    import stat

    f = installed_inputs
    doc, selected_courier, policy, bounds = fixture._installed_inputs(
        canonical(f.selection)
    )
    packet = github_packet(f)
    socketdir = tmp_path / "courier"
    socketdir.mkdir()
    socketpath = socketdir / "oidc.sock"
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    original_stat, original_select = os.stat, select.select
    activity = []

    class Peer:
        def settimeout(self, _):
            pass

        def send(self, raw):
            activity.append(raw)
            assert raw == life._METADATA_READY
            return len(raw)

        def recvmsg(self, *_):
            return (
                b"malformed"
                if failure == "metadata"
                else canonical(
                    dict(
                        schema="Gate0A9BrokerMetadata.v1",
                        url="https://synthetic.example/opaque?x=1",
                    )
                ),
                [],
                0,
                None,
            )

        def close(self):
            activity.append("peer-closed")

    peer = Peer()

    class Server:
        def bind(self, _):
            socketpath.write_bytes(b"synthetic socket inode")

        def listen(self, _):
            pass

        def settimeout(self, _):
            pass

        def accept(self):
            return peer, None

        def close(self):
            activity.append("server-closed")

    server = Server()
    monkeypatch.setattr(fixture.socket, "socket", lambda *_: server)
    monkeypatch.setattr(
        fixture,
        "_directory",
        lambda path, **_: os.open(
            socketdir if path == fixture._SOCKET.parent else path,
            os.O_RDONLY | os.O_DIRECTORY,
        ),
    )
    monkeypatch.setattr(os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(os, "chmod", lambda *_args, **_kwargs: None)

    def stat_boundary(path, *args, **kwargs):
        mapped = socketpath if str(path) == str(fixture._SOCKET) else path
        value = original_stat(mapped, *args, **kwargs)
        if str(path) in ("oidc.sock", str(fixture._SOCKET)):
            return SimpleNamespace(
                st_dev=value.st_dev,
                st_ino=value.st_ino,
                st_uid=0,
                st_mode=stat.S_IFSOCK | 0o660,
            )
        return value

    monkeypatch.setattr(os, "stat", stat_boundary)
    counter = []

    def select_boundary(read, write, error, timeout=0):
        if read == [999]:
            return ([] if failure == "exit-timeout" else [999], [], [])
        if server in read or peer in read:
            counter.append(1)
            if (
                failure == "early-frame"
                or (failure == "extra-frame" and read == [peer])
                or (failure == "second-peer" and read == [server])
            ):
                return ([peer if peer in read else server], [], [])
            return [], [], []
        return original_select(read, write, error, timeout)

    monkeypatch.setattr(select, "select", select_boundary)
    monkeypatch.setattr(
        fixture, "_measure_courier_identity_readonly", lambda *_: (100, 200, "10")
    )
    chain = (
        (100, 200, "10", b"fixed-courier\0"),
        (200, 300, "20", b"/bin/bash\0/run/dotmac-gate0-jit/work/_temp/generated.sh\0"),
        (300, 400, "30", b"fixed-worker\0"),
        (400, 1, "40", b"fixed-listener\0"),
    )

    class Live:
        def __init__(self):
            self.owned = {}

        def retain(self, pid, start):
            self.owned[pid] = (start, 999)

        def recheck(self):
            pass

        def close(self):
            activity.append("pidfds-closed")
            self.owned = {}

    monkeypatch.setattr(fixture, "_LiveProcesses", Live)

    def chain_boundary(*args):
        for pid, _, start, _ in chain[:3]:
            args[-1](pid, start)
        return chain

    monkeypatch.setattr(fixture, "_measure_supplier_chain_readonly", chain_boundary)
    monkeypatch.setattr(
        fixture,
        "_chain_rows",
        lambda *_: [
            dict(role=name) for name in ("courier", "bash", "worker", "listener")
        ],
    )

    class Script:
        def __init__(self, *_):
            if failure == "script":
                raise life.LifecycleRefused()

        def recheck(self):
            return dict(content_digest=life._hash(b"synthetic descriptor boundary"))

        def close(self):
            activity.append("script-fd-closed")

    monkeypatch.setattr(fixture, "_ScriptDescriptor", Script)

    class Held:
        raw = canonical(packet)

        def __init__(self, *_):
            self.checks = 0

        def recheck(self):
            self.checks += 1
            if failure == "withdrawn-before-ready" and self.checks > 1:
                raise life.LifecycleRefused()

        def close(self):
            activity.append("github-fd-closed")

    monkeypatch.setattr(fixture, "_HeldRecord", Held)
    try:
        if failure is None:
            fixture._observe(
                doc,
                selected_courier,
                policy,
                bounds,
                SimpleNamespace(raw=canonical(doc), recheck=lambda: None),
                parent,
            )
            observation = fixture.strict_object(
                (tmp_path / "observation.json").read_bytes()
            )
            assert observation["completion"] == "CASE_OBSERVED"
            assert observation["courier_exit_observed"] is True
            assert [e["event"] for e in observation["protocol"]] == [
                "peer_accepted",
                "measurements_completed",
                "metadata_ready_sent",
                "metadata_received",
                "socket_closed",
                "courier_exited",
            ]
            assert activity.count(life._METADATA_READY) == 1
        else:
            expected_error = (
                TimeoutError if failure == "exit-timeout" else life.LifecycleRefused
            )
            with pytest.raises(expected_error):
                fixture._observe(
                    doc,
                    selected_courier,
                    policy,
                    bounds,
                    SimpleNamespace(raw=canonical(doc), recheck=lambda: None),
                    parent,
                )
            assert not (tmp_path / "observation.json").exists()
            if failure in ("withdrawn-before-ready", "script", "early-frame"):
                assert life._METADATA_READY not in activity
        assert (
            tmp_path / "attempt"
        ).read_bytes() == b"Gate0A9NativeFixtureAttempt.v1\n"
        assert not socketpath.exists()
        assert "pidfds-closed" in activity and "server-closed" in activity
        with pytest.raises(FileExistsError):
            fixture._observe(
                doc,
                selected_courier,
                policy,
                bounds,
                SimpleNamespace(raw=canonical(doc), recheck=lambda: None),
                parent,
            )
        assert activity.count(life._METADATA_READY) <= 1
    finally:
        os.close(parent)


def test_descriptor_enumeration_limit_has_no_partial_acceptance(monkeypatch, tmp_path):
    path = tmp_path / "script.sh"
    path.write_bytes(b"synthetic script")
    monkeypatch.setattr(
        fixture, "_measure_generated_script", lambda *_: life._stable(path.stat())
    )

    class Entries:
        def __enter__(self):
            return iter(SimpleNamespace(name=str(n)) for n in range(257))

        def __exit__(self, *_):
            pass

    monkeypatch.setattr(os, "scandir", lambda *_: Entries())
    with pytest.raises(life.LifecycleRefused):
        fixture._ScriptDescriptor(
            1,
            "1",
            path,
            life._hash(b"synthetic script"),
            os.getuid(),
            time.monotonic() + 1,
        )


def test_real_production_supplier_policy_rejects_actual_fixture_inventory(
    monkeypatch, installed_inputs
):
    """Reach the real native schema guard after valid preceding owner predicates."""
    f = installed_inputs
    # First prove these are the actual bytes accepted only as preliminary fixture
    # inventory, joined to the existing public launcher's receipt-digest field.
    fixture._installed_inputs(canonical(f.selection))
    inventory_bytes = f.files[str(fixture._ROOT / "inventory.json")]
    assert inventory_bytes == canonical(f.inventory)
    assert f.inventory["disposition"] == "UNQUALIFIED"
    assert life._hash(inventory_bytes) == f.courier["launcher"]["native_receipt_digest"]
    root = life._ROOT
    lifecycle = dict(
        lifecycle_binding_digest=life._hash(b"synthetic-owner-selection"),
        campaign_digest=life._hash(b"synthetic-campaign-selection"),
    )
    prelaunch = dict(schema="Gate0A9PrelaunchSelection.v1", **lifecycle)
    for name in (
        "collection_template",
        "bootstrap_template",
        "collection_native_qualification",
        "bootstrap_native_qualification",
    ):
        # This real prelaunch parser requires protected canonical pinned bytes,
        # not a native verdict. Label every synthetic preliminary input honestly.
        path = root / (name.replace("_", "-") + ".json")
        prelaunch[name] = f.pin(
            path,
            canonical(
                dict(schema="SyntheticUnqualifiedInput.v1", disposition="UNQUALIFIED")
            ),
        )
    prelaunch["broker_policy"] = f.selection["broker_policy"]
    f.files[str(life._PRELAUNCH)] = canonical(prelaunch)
    native_path = root / "lifecycle-native.json"
    # A synthetic external custody read feeds the exact same actual inventory
    # bytes to the production owner; no file is installed on a guest or host.
    f.files[str(native_path)] = inventory_bytes
    reads, reached_native_guard = [], []
    original_closed = life._closed

    def protected(path, *args, **kwargs):
        reads.append(str(path))
        return f.files[str(path)]

    def observed_closed(value, fields):
        if fields == (
            "schema boot_id kernel_release runner_tree_digest systemd_version "
            "supplier_observation supplier_review"
        ):
            reached_native_guard.append(value)
        return original_closed(value, fields)

    monkeypatch.setattr(life, "_protected", protected)
    monkeypatch.setattr(life, "_closed", observed_closed)
    environment = NamesOnly(["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])
    monkeypatch.setattr(life, "os", SubjectEnvironment(environment))
    context = SimpleNamespace(
        lifecycle=SimpleNamespace(_doc=lifecycle),
        selection=dict(native_receipt_digest=life._hash(inventory_bytes)),
        bounds=SimpleNamespace(provisioning_end=time.monotonic() + 10),
    )
    with pytest.raises(life.LifecycleRefused):
        life.NativeJitInvocation._supplier_policy(context)
    assert reached_native_guard == [f.inventory]
    assert reads[-1] == str(native_path)
    assert all(
        f.policy["profile"][name]["path"] in reads
        for name in ("worker_binary", "shell_binary", "script_template")
    )
    assert environment.reads == 0
