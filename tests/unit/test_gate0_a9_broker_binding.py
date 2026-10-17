"""Synthetic protocol fixtures; never native or supplier acceptance evidence."""

# ruff: noqa: F811 -- pytest injects imported fixtures.

import os
import socket
import struct
import time
from collections.abc import MutableMapping
from types import SimpleNamespace

import pytest
from test_gate0_runner_installation import installed_model  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_runner_lifecycle as life
from vendor_cp.deployment import gate0_runner_lifecycle_courier as courier
from vendor_cp.deployment import gate0_runner_tokens as tokens
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


class GuardedEnvironment(dict):
    def pop(self, key, *default):
        if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
            assert channel.secret_ready, "token read before metadata binding"
        return super().pop(key, *default)


class Channel:
    secret_ready = False

    def __init__(self, fail_metadata=False, root_uid=0):
        self.root_uid = root_uid
        self.sent = []
        self.responses = [
            life._METADATA_READY,
            b"\x00" if fail_metadata else life._SECRET_READY,
            b"\x01",
        ]

    def settimeout(self, _):
        pass

    def connect(self, _):
        pass

    def getsockopt(self, *_):
        return struct.pack("3i", 1, self.root_uid, 0)

    def recvmsg(self, *_):
        value = self.responses.pop(0)
        if value == life._SECRET_READY:
            self.secret_ready = True
        return value, [], 0, None

    def send(self, value):
        self.sent.append(value)
        return len(value)

    def shutdown(self, how):
        assert how == socket.SHUT_WR

    def recv(self, _):
        return b""

    def close(self):
        pass


channel = Channel()


def test_courier_metadata_before_any_secret_access(monkeypatch):
    global channel
    channel = Channel()
    monkeypatch.setattr(
        courier,
        "_installed_public_selection",
        lambda: ({}, {}, SimpleNamespace(provisioning_end=time.monotonic() + 10)),
    )
    environment = GuardedEnvironment(
        ACTIONS_ID_TOKEN_REQUEST_URL="https://broker.example/opaque/id?api-version=2",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="synthetic-token",
    )
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(courier.socket, "socket", lambda *_: channel)
    assert courier.run_installed_job_courier() == 0
    assert channel.sent == [
        canonical(
            {
                "schema": "Gate0A9BrokerMetadata.v1",
                "url": "https://broker.example/opaque/id?api-version=2",
            }
        ),
        b"synthetic-token",
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://broker.example/p?k=v",
        "https://broker.example:443/p?k=v",
        "https://u@broker.example/p?k=v",
        "https://broker.example/p?k=v#x",
        "https://broker.example/%252f?k=v",
        "https://broker.example/p?audience=x",
        "https://broker.example/p?k=v&K=x",
        "https://broker.example/p?k=%ff",
        "https://broker.example/p?k=%GG",
    ],
)
def test_opaque_supplier_url_rejects_ambiguous_transport(url):
    with pytest.raises(ProviderRefused):
        tokens._supplier_coordinates(url, ["https://broker.example"])


def test_supplier_path_is_opaque_and_preserved():
    assert tokens._supplier_coordinates(
        "https://broker.example/opaque/%41?key=%42", ["https://broker.example"]
    ) == ("https://broker.example", "/opaque/%41", "key=%42")


@pytest.mark.parametrize(
    "boundary_failure", [None, "approval-withdrawn", "expired", "cancelled"]
)
def test_prelaunch_lifecycle_courier_real_binder_and_final_loaders(
    installed_model,
    monkeypatch,
    tmp_path,
    boundary_failure,
):
    """Real owner composition; OS/GitHub/native proof are synthetic boundaries.

    Publication, lifecycle phase/journal/file ownership mechanics, handshake,
    private binder, immutable digest joins and both final loaders remain real.
    This test supplies no native qualification acceptance evidence.
    """
    import threading
    from datetime import UTC, datetime, timedelta
    from pathlib import Path

    from vendor_cp.deployment import gate0_e_github as github
    from vendor_cp.deployment import gate0_runner_bootstrap as bootstrap
    from vendor_cp.deployment import gate0_runner_installation as loader
    from vendor_cp.deployment import gate0_runner_supervisor as supervisor
    from vendor_cp.deployment.gate0_framing import strict_object

    model = installed_model
    root = Path(loader._A9_ROOT)
    inputs = model.files
    prelaunch = strict_object(inputs[str(root / "a9-prelaunch.json")])
    campaign, binding_digest = (
        prelaunch["campaign_digest"],
        prelaunch["lifecycle_binding_digest"],
    )
    wall, elapsed = datetime.now(UTC), time.monotonic()
    bounds = life._OriginalBounds(
        "00000000-0000-0000-0000-000000000001",
        wall,
        elapsed,
        wall + timedelta(seconds=10),
        wall + timedelta(seconds=20),
    )

    def pin(path):
        return {"path": path, "digest": "sha256:" + "1" * 64}

    launcher = dict(
        schema="Gate0A9JitLauncherSelection.v1",
        runner_id=3,
        runner_name=model.descriptor["job"]["runner_name"],
        runner_group_id=int(model.descriptor["job"]["runner_group_id"]),
        owner_id=int(model.descriptor["job"]["repository_owner_id"]),
        workflow_id=4,
        job_id=5,
        job_name="synthetic",
        environment_id=6,
        source_revision=model.descriptor["job"]["workflow_sha"],
        cli=pin("/opt/synthetic/cli"),
        interpreter=pin("/usr/bin/python3"),
        systemctl=pin("/usr/bin/systemctl"),
        manager=pin("/usr/lib/systemd/systemd"),
        runner_binary=pin(str(life._RUNNER)),
        runner_tree_digest="sha256:" + "2" * 64,
        unit_digest="sha256:" + "3" * 64,
        groups=[1003],
        native_receipt_digest="sha256:" + "4" * 64,
    )
    cli_raw = b"#!/usr/bin/python3\nsynthetic boundary\n"
    launcher["cli"]["digest"] = life._hash(cli_raw)
    inputs[launcher["cli"]["path"]] = cli_raw
    document = dict(
        lifecycle_binding_digest=binding_digest,
        campaign_digest=campaign,
        allocation_id="synthetic-allocation",
        collector_uid=1001,
        collector_gid=1002,
        courier_uid=1003,
        courier_gid=1003,
        repository_id=int(model.descriptor["job"]["repository_id"]),
        run_id=int(model.descriptor["job"]["run_id"]),
        launcher=launcher,
        source_files={},
        original_bounds={},
    )
    owner = life.InstalledA9Lifecycle(life._SEAL, document, bounds)
    policy = strict_object(inputs[str(root / "broker-policy.json")])
    policy["profile"] = {"workflow_source_digest": "sha256:" + "9" * 64}
    policy_raw = canonical(policy)
    inputs[str(root / "broker-policy.json")] = policy_raw
    prelaunch["broker_policy"]["digest"] = life._hash(policy_raw)
    runtime = {
        "manager_identity": dict(
            executable_digest=launcher["manager"]["digest"],
            version="synthetic",
            kernel_release=os.uname().release,
            boot_id=bounds.boot_id,
        )
    }
    for role in ("collection", "bootstrap"):
        name = str(root / (role + "-native-qualification.json"))
        qualification = strict_object(inputs[name])
        qualification.update(
            prelaunch_selection_digest=life._prelaunch_selection_digest(prelaunch),
            broker_policy_digest=life._hash(policy_raw),
            runtime_identity=runtime,
        )
        if role == "bootstrap":
            qualification["native_receipt"] = model.pin(
                str(root / "bootstrap-native.json"), b"SYNTHETIC-NATIVE"
            )
        inputs[name] = canonical(qualification)
        prelaunch[role + "_native_qualification"]["digest"] = life._hash(inputs[name])
    # Supply a complete real bootstrap template, using actual frozen windows and
    # source/unit pins. Native/runtime execution remains an explicit test seam.
    receiver = dict.fromkeys(
        k for k in bootstrap.ReceiverInstallation.__annotations__ if k != "collector"
    )
    receiver.update(
        schema="Gate0ReceiverInstallation.v1",
        campaign_digest=campaign,
        receiver_uid=model.descriptor["receiver_uid"],
        cases=[
            {h: c["hosts"][h]["binding"] for h in ("IDP3", "NS3")}
            for c in model.descriptor["cases"]
        ],
    )
    assets = Path(__file__).resolve().parents[2] / "deploy/gate0-a9"
    template = dict(
        schema="Gate0CollectorBootstrapTemplate.v1",
        campaign_digest=campaign,
        lifecycle_binding_digest=binding_digest,
        collector_binary=launcher["cli"],
        collector_gid=1002,
        collector_groups=[1002, 1003],
        socket_gid=1003,
        receiver_template=model.pin(
            str(root / "receiver-template.json"), canonical(receiver)
        ),
        native_receipt={
            "path": str(root / "bootstrap-native.json"),
            "digest": life._hash(b"SYNTHETIC-NATIVE"),
        },
        source_revision=launcher["source_revision"],
        source_files={
            name: model.pin(
                str(Path(bootstrap.__file__).with_name(name + ".py")),
                (name + "-synthetic").encode(),
            )
            for name in (
                "gate0_runner_bootstrap",
                "gate0_runner_credential",
                "gate0_runner_lifecycle",
            )
        },
        unit_assets={
            name: model.pin(str(root / name), (assets / (name + ".in")).read_bytes())
            for name in bootstrap._UNITS
        },
        manager_client=launcher["systemctl"],
        manager_binary=launcher["manager"],
    )
    for name in ("systemctl", "manager"):
        inputs[launcher[name]["path"]] = b"synthetic-executable"
        launcher[name]["digest"] = life._hash(b"synthetic-executable")
    template["manager_binary"] = launcher["manager"]
    template["manager_client"] = launcher["systemctl"]
    prelaunch["bootstrap_template"] = model.pin(
        str(root / "bootstrap-template.json"), canonical(template)
    )
    for role in ("collection", "bootstrap"):
        name = str(root / (role + "-native-qualification.json"))
        qualification = strict_object(inputs[name])
        qualification["prelaunch_selection_digest"] = life._prelaunch_selection_digest(
            prelaunch
        )
        qualification["template_digest"] = prelaunch[role + "_template"]["digest"]
        inputs[name] = canonical(qualification)
        prelaunch[role + "_native_qualification"]["digest"] = life._hash(inputs[name])
    inputs[str(root / "lifecycle/prelaunch.json")] = canonical(prelaunch)
    final_names = [
        "a9-prelaunch.json",
        "job-broker-binding.json",
        "installation.json",
        "bootstrap.json",
        "collection-qualification.json",
        "bootstrap-qualification.json",
        "job-broker-binding-complete.json",
    ]
    for name in final_names:
        inputs.pop(str(root / name), None)
    actual_stat = os.fstat

    def root_metadata(fd):
        value = actual_stat(fd)
        data = {key: getattr(value, key) for key in dir(value) if key.startswith("st_")}
        data.update(st_uid=0, st_gid=0)
        return SimpleNamespace(**data)

    monkeypatch.setattr(os, "fstat", root_metadata)
    actual_path_stat = os.stat

    def stat_boundary(path, *args, **kwargs):
        value = actual_path_stat(path, *args, **kwargs)
        data = {key: getattr(value, key) for key in dir(value) if key.startswith("st_")}
        data.update(st_uid=0, st_gid=0)
        return SimpleNamespace(**data)

    monkeypatch.setattr(os, "stat", stat_boundary)
    monkeypatch.setattr(os, "fchown", lambda *_: None)
    monkeypatch.setattr(os, "chown", lambda *_, **__: None)

    def mapped(path):
        path = Path(path)
        return tmp_path / path.relative_to(root) if path.is_relative_to(root) else path

    def read(path, *_, **__):
        path = Path(path)
        # Declared synthetic host pins must not collide with runner binaries.
        # Mapped A9 files still read their actual per-test temporary bytes first.
        if not path.is_relative_to(root) and str(path) in inputs:
            return inputs[str(path)]
        target = mapped(path)
        return target.read_bytes() if target.is_file() else inputs[str(path)]

    monkeypatch.setattr(life, "_protected", read)
    monkeypatch.setattr(supervisor, "_protected", read)
    monkeypatch.setattr(loader, "_protected_read", read)
    monkeypatch.setattr(bootstrap, "read_protected_handoff", read)

    def directory(path, **_):
        target = mapped(path)
        target.mkdir(parents=True, exist_ok=True)
        return os.open(target, os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(life, "_directory", directory)
    monkeypatch.setattr(
        supervisor, "_publication_parent", lambda path, _: directory(path)
    )
    actual_lexists = os.path.lexists
    monkeypatch.setattr(os.path, "lexists", lambda path: actual_lexists(mapped(path)))
    for slot, (parent, name) in life._ROSTER.items():
        monkeypatch.setitem(life._ROSTER, slot, (mapped(parent), name))
        mapped(parent).mkdir(parents=True, exist_ok=True)
    socket_path = tmp_path / "courier/oidc.sock"
    monkeypatch.setattr(life, "_SOCKET", socket_path)
    monkeypatch.setattr(courier, "_SOCKET", socket_path)
    journal_fd = directory(root / "lifecycle")
    owner._journal = life._Journal(journal_fd, binding_digest, campaign, bounds)
    for slot in (
        life.FileSlot.A_KEY,
        life.FileSlot.B_KEY,
        life.FileSlot.A_CERTIFICATE,
        life.FileSlot.B_CERTIFICATE,
        life.FileSlot.JIT_SOURCE,
    ):
        parent, name = life._ROSTER[slot]
        (parent / name).write_bytes(b"synthetic-preinstalled")
        owner._capture(slot)
    monkeypatch.setattr(
        supervisor.SupervisorInstallation,
        "load",
        lambda: SimpleNamespace(lifecycle=document),
    )
    monkeypatch.setattr(supervisor.SupervisorManager, "qualify", lambda *_: {})
    monkeypatch.setattr(life.NativeJitInvocation, "_qualify_installed", lambda *_: None)
    monkeypatch.setattr(life.NativeJitInvocation, "_supplier_policy", lambda *_: policy)
    monkeypatch.setattr(
        life.NativeJitInvocation, "_static_runtime_identity", lambda *_: runtime
    )
    monkeypatch.setattr(life.NativeJitInvocation, "_unit_predicates", lambda *_: None)
    monkeypatch.setattr(life, "_uid_processes", lambda *_: set())
    state = {
        "active": False,
        "starts": 0,
        "snapshots": 0,
        "token_reads": 0,
        "expired": False,
    }
    original_provisioning_end = bounds.provisioning_end
    original_monotonic = time.monotonic
    monkeypatch.setattr(
        time,
        "monotonic",
        lambda: bounds.provisioning_end + 0.1
        if state["expired"]
        else original_monotonic(),
    )
    actual_link = os.link

    def link_boundary(source, target, *args, **kwargs):
        result = actual_link(source, target, *args, **kwargs)
        if (
            target == "job-broker-binding-complete.json"
            and boundary_failure == "expired"
        ):
            state["expired"] = True
        return result

    monkeypatch.setattr(os, "link", link_boundary)
    result, threads = [], []
    monkeypatch.setattr(
        courier, "_installed_public_selection", lambda: ({}, launcher, bounds)
    )
    original_environment = dict(os.environ)

    class TokenTrap(dict):
        def pop(self, key, *default):
            if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
                state["token_reads"] += 1
                assert (tmp_path / "job-broker-binding-complete.json").is_file()
                assert state["snapshots"] >= 3
            return super().pop(key, *default)

    environment = TokenTrap(original_environment)
    environment.update(
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="synthetic-token",
        ACTIONS_ID_TOKEN_REQUEST_URL="https://broker.example/opaque/supplier?key=value",
    )
    monkeypatch.setattr(os, "environ", environment)
    actual_socket = socket.socket

    class NativeSocket(actual_socket):
        def getsockopt(self, level, option, *args):
            if option == socket.SO_PEERCRED:
                return struct.pack("3i", 777, 0 if self.getpeername() else 1003, 1003)
            return super().getsockopt(level, option, *args)

    monkeypatch.setattr(socket, "socket", NativeSocket)
    alive_read, alive_write = os.pipe()
    events = tmp_path / "events"
    events.write_bytes(b"populated 1\n")
    actual_open = os.open
    monkeypatch.setattr(
        os,
        "open",
        lambda path, *args, **kw: actual_open(events, *args, **kw)
        if str(path).endswith("/cgroup.events")
        else actual_open(path, *args, **kw),
    )
    monkeypatch.setattr(os, "pidfd_open", lambda *_: os.dup(alive_read))
    monkeypatch.setattr(
        life.NativeJitInvocation,
        "_show",
        lambda *_: dict(
            InvocationID="a" * 32 if state["starts"] else "",
            ControlGroup=life._JIT_GROUP if state["active"] else "",
            Result="success",
            ExecMainCode="1",
            ExecMainStatus="0",
            ActiveState="active" if state["active"] else "inactive",
            SubState="running" if state["active"] else "dead",
            MainPID="888" if state["active"] else "0",
        ),
    )
    monkeypatch.setattr(
        life.NativeJitInvocation, "_measure_main", lambda *_: (888, "10", "a" * 32)
    )

    def native_call(self, args, _):
        if args[0] == "start":
            assert not any((tmp_path / name).exists() for name in final_names)
            state.update(active=True, starts=state["starts"] + 1)
            thread = threading.Thread(
                target=lambda: result.append(courier.run_installed_job_courier())
            )
            threads.append(thread)
            thread.start()
        elif args[0] == "stop":
            state["active"] = False
            events.write_bytes(b"populated 0\n")
            os.write(alive_write, b"x")
        return b""

    monkeypatch.setattr(life.NativeJitInvocation, "_call", native_call)
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: launcher["runner_binary"]["path"]
        if str(path) == "/proc/888/exe"
        else launcher["interpreter"]["path"],
    )
    monkeypatch.setattr(life, "measure_handoff_process", lambda pid: (666, 1003, "11"))

    def proc(path, *_):
        path = str(path)
        if path.endswith("/cmdline"):
            return (
                b"/usr/bin/python3\0/opt/synthetic/cli\0gate0\0courier-original-oidc\0"
            )
        if path.endswith("/status"):
            return b"Groups:\t1003\n"
        if path.endswith("/cgroup"):
            return ("0::" + life._JIT_GROUP + "\n").encode()
        if path.endswith("/cgroup.procs"):
            return b"777\n"
        return (bounds.boot_id + "\n").encode()

    monkeypatch.setattr(life, "_proc", proc)
    monkeypatch.setattr(
        life.NativeJitInvocation,
        "_measure_supplier_chain",
        lambda *_: ((777, 666, "11", b"synthetic"),),
    )
    facts = SimpleNamespace(
        repository_id=document["repository_id"],
        owner_id=launcher["owner_id"],
        run_id=document["run_id"],
        attempt=1,
        workflow_id=4,
        head_sha=launcher["source_revision"],
        environment_id=6,
        stage=SimpleNamespace(value="PROTECTED_JOB_STARTED"),
        jobs=[
            SimpleNamespace(
                id=5,
                name="synthetic",
                runner_id=3,
                runner_name=launcher["runner_name"],
                runner_group_id=launcher["runner_group_id"],
                status="in_progress",
                conclusion=None,
                head_sha=launcher["source_revision"],
                run_id=document["run_id"],
            )
        ],
        review=SimpleNamespace(
            state="approved",
            environment_ids=(6,),
            reviewer_id=9,
            observation_sha256="9" * 64,
        ),
        workflow_source=SimpleNamespace(bytes_sha256="9" * 64),
        policy_observation_digests=(),
        observations=(),
    )

    class Reader:
        def protected_job_snapshot(self, **_):
            from copy import deepcopy

            state["snapshots"] += 1
            self.observed = deepcopy(facts)
            if state["snapshots"] >= 3:
                if boundary_failure == "approval-withdrawn":
                    self.observed.review.state = "pending"
                elif boundary_failure == "cancelled":
                    self.observed.jobs[0].status = "completed"
                    self.observed.jobs[0].conclusion = "cancelled"
            return self.observed

        def owns_facts(self, value):
            return value is self.observed

    monkeypatch.setattr(
        github.InstalledGate0GitHubReads, "from_installed", lambda: Reader()
    )
    try:
        if boundary_failure is None:
            owner.receive_original_job_credential()
        else:
            with pytest.raises(life.LifecycleRefused):
                owner.receive_original_job_credential()
        for thread in threads:
            thread.join(timeout=2)
        assert state["starts"] == 1
        assert bounds.provisioning_end == original_provisioning_end
        if boundary_failure is not None:
            assert result == [3] and state["token_reads"] == 0
            assert owner._failed and not state["active"]
            assert owner._jit._retirement is not None
            assert (tmp_path / "job-broker-binding-complete.json").exists()
            assert not (tmp_path / "oidc-request-token").exists()
            assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in environment
            return
        assert result == [0] and state["token_reads"] == 1
        assert (tmp_path / "oidc-request-token").read_bytes() == b"synthetic-token"
        original_readback = loader.InstalledRunnerCollection._load

        def diagnosed_readback() -> loader.InstalledRunnerCollection:
            try:
                return original_readback()
            except Exception as error:
                trace = error.__traceback__
                line = 0
                load_line = 0
                while trace is not None:
                    line = trace.tb_lineno
                    if trace.tb_frame.f_code.co_name == "_load":
                        load_line = trace.tb_lineno
                    trace = trace.tb_next
                # Class and line only: never exception text, values, or locals.
                pytest.fail(
                    f"installed_fixture_readback:{type(error).__name__}:"
                    f"load_line={load_line}:line={line}",
                    pytrace=False,
                )

        monkeypatch.setattr(
            loader.InstalledRunnerCollection,
            "_load",
            staticmethod(diagnosed_readback),
        )
        loaded = loader.InstalledRunnerCollection.from_installed()
        assert loaded.broker.path == "/opaque/supplier"
        monkeypatch.setattr(
            life.InstalledA9Lifecycle,
            "from_installed",
            lambda: life.InstalledA9Lifecycle(life._SEAL, document, bounds),
        )
        monkeypatch.setattr(os, "getuid", lambda: 0)
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        actual = bootstrap.BootstrapInstallation.from_installed()
        assert actual.clock.cutoff == bounds.finalization_end
        assert any(
            b"ACTIONS_ID_TOKEN_REQUEST_URL=https://broker.example/opaque/supplier?key=value"
            in raw
            for raw in actual.render()
        )
    finally:
        os.close(alive_read)
        os.close(alive_write)
        for item in list(owner._owned.values()):
            os.close(item.file_fd)
            os.close(item.parent_fd)
        if owner._jit is not None:
            owner._jit.close()
        os.close(journal_fd)


class AllReadTrap(MutableMapping):
    """Matches os._Environ's inherited membership behavior, unlike dict."""

    def __init__(self, values):
        self.values = values
        self.reads = 0

    def __getitem__(self, key):
        if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
            self.reads += 1
            raise AssertionError("token read before secret readiness")
        return self.values[key]

    def __setitem__(self, key, value):
        self.values[key] = value

    def __delitem__(self, key):
        del self.values[key]

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)


@pytest.mark.parametrize(
    "phase",
    [
        "root-refusal",
        "metadata-refusal",
        "missing-url",
        "secret-ready-refusal",
        "deadline",
    ],
)
def test_all_token_reads_trapped_on_failed_handshake(monkeypatch, phase):
    global channel
    channel = Channel(
        fail_metadata=phase == "secret-ready-refusal",
        root_uid=99 if phase == "root-refusal" else 0,
    )
    if phase == "metadata-refusal":
        channel.responses[0] = b"\x00"
    monkeypatch.setattr(
        courier,
        "_installed_public_selection",
        lambda: (
            {},
            {},
            SimpleNamespace(
                provisioning_end=time.monotonic() + (-1 if phase == "deadline" else 10)
            ),
        ),
    )
    values = {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-private-token"}
    if phase != "missing-url":
        values["ACTIONS_ID_TOKEN_REQUEST_URL"] = (
            "https://broker.example/opaque?key=value"
        )
    environment = AllReadTrap(values)
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(courier.socket, "socket", lambda *_: channel)
    assert courier.run_installed_job_courier() == 3
    assert environment.reads == 0
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in environment.values
    assert all(b"synthetic-private-token" not in value for value in channel.sent)


@pytest.mark.parametrize(
    "change",
    [
        "marker-missing",
        "marker-tamper",
        "binding-tamper",
        "policy-tamper",
        "template-tamper",
        "native-qualification-tamper",
        "bootstrap-tamper",
        "old-schema",
    ],
)
def test_final_join_refuses_partial_tampered_or_old_outputs(installed_model, change):
    from vendor_cp.deployment import gate0_runner_installation as loader
    from vendor_cp.deployment.gate0_framing import strict_object

    model = installed_model
    root = loader._A9_ROOT
    raw = model.files[root + "/installation.json"]
    if change == "old-schema":
        old = strict_object(raw)
        old["schema"] = "Gate0RunnerCollectionInstallation.v1"
        raw = canonical(old)
    elif change == "marker-missing":
        del model.files[root + "/job-broker-binding-complete.json"]
    else:
        name = {
            "marker-tamper": "job-broker-binding-complete.json",
            "binding-tamper": "job-broker-binding.json",
            "policy-tamper": "broker-policy.json",
            "template-tamper": "collection-template.json",
            "native-qualification-tamper": "collection-native-qualification.json",
            "bootstrap-tamper": "bootstrap.json",
        }[change]
        model.files[root + "/" + name] += b" "
    with pytest.raises((ProviderRefused, KeyError)):
        loader._a9_join(raw, "collection")


def test_prelaunch_case_reader_needs_no_final_descriptors(installed_model, monkeypatch):
    from test_gate0_runner_lifecycle import bounds

    from vendor_cp.deployment import gate0_runner_installation as loader

    model = installed_model
    for name in (
        "installation.json",
        "bootstrap.json",
        "job-broker-binding-complete.json",
        "job-broker-binding.json",
    ):
        del model.files[loader._A9_ROOT + "/" + name]
    descriptor = model.descriptor
    lifecycle = life.InstalledA9Lifecycle(
        life._SEAL,
        dict(
            lifecycle_binding_digest="sha256:" + "c" * 64,
            campaign_digest=descriptor["campaign_digest"],
            collector_uid=descriptor["collector_uid"],
            repository_id=int(descriptor["job"]["repository_id"]),
            run_id=int(descriptor["job"]["run_id"]),
        ),
        bounds(),
    )
    monkeypatch.setattr(
        life, "_protected", lambda path, *a, **kw: model.files[str(path)]
    )
    assert len(lifecycle._collection_cases()) == 2


def test_bootstrap_preserves_percent_and_quote_in_opaque_url(monkeypatch):
    from test_gate0_runner_bootstrap import candidate as candidate_fixture

    # Reuse the inert dataclass fixture; no project/native execution occurs.
    from vendor_cp.deployment import gate0_runner_bootstrap as bootstrap
    from vendor_cp.deployment.gate0_framing import strict_object

    candidate = candidate_fixture.__wrapped__()
    collection = strict_object(candidate.collection)
    collection["broker"].update(path="/opaque/%41's", query="key=%42")
    from dataclasses import replace

    candidate = replace(candidate, collection=canonical(collection))
    rendered = candidate.render()
    assert any(
        b'Environment="ACTIONS_ID_TOKEN_REQUEST_URL=https://test.invalid/opaque/%%41\'s?key=%%42"'
        in value
        for value in rendered
    )
    assert bootstrap._ROOT.name == "dotmac-gate0-collector"


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "parent",
        "uid",
        "groups",
        "cgroup",
        "worker-executable",
        "worker-argv",
        "worker-handle",
        "shell-argv",
        "script-identity",
        "listener-start",
    ],
)
def test_actual_supplier_ancestry_is_finite_pinned_and_remeasured(
    tmp_path, monkeypatch, mutation
):
    from pathlib import Path

    native = object.__new__(life.NativeJitInvocation)
    native.bounds = SimpleNamespace(provisioning_end=time.monotonic() + 10)
    native._chain_pidfds = {}
    native._started, native._closed, native._close_failed = True, False, False
    native._events = native._pidfd = -1
    native.lifecycle = SimpleNamespace(_doc={"courier_uid": 4001, "courier_gid": 4002})
    executable = tmp_path / "executable"
    executable.write_bytes(b"synthetic-executable")
    digest = life._hash(executable.read_bytes())
    profile = dict(
        worker_binary=dict(
            path="/opt/dotmac-gate0-jit/bin/Runner.Worker", digest=digest
        ),
        shell_binary=dict(path="/usr/bin/bash", digest=digest),
        script_template=dict(path="/protected/script", digest=life._hash(b"script")),
        script_directory="/run/dotmac-gate0-jit/work/_temp",
    )
    native.selection = dict(
        interpreter=dict(path="/usr/bin/python3", digest=digest),
        runner_binary=dict(path=str(life._RUNNER), digest=digest),
        groups=[4002],
    )
    native.pid, native.start = 400, "40"
    native._supplier_policy = lambda: dict(profile=profile)
    native._require_current = lambda: None
    parents = {100: 200, 200: 300, 300: 400, 400: 1}
    if mutation == "parent":
        parents[300] = 401

    def process(pid):
        return (
            parents.get(pid, 1),
            4003 if mutation == "uid" and pid == 200 else 4001,
            "41" if mutation == "listener-start" and pid == 400 else str(pid // 10),
        )

    monkeypatch.setattr(life, "measure_handoff_process", process)

    def proc(path, *_):
        path = Path(path)
        pid = int(path.parts[2])
        if path.name == "status":
            group = b"99" if mutation == "groups" and pid == 300 else b"4002"
            return (
                b"Groups:\t"
                + group
                + b"\nUid:\t4001 4001 4001 4001\nGid:\t4002 4002 4002 4002\n"
            )
        if path.name == "cgroup":
            return (
                b"0::/wrong\n"
                if mutation == "cgroup" and pid == 200
                else ("0::" + life._JIT_GROUP + "\n").encode()
            )
        if pid == 100:
            return b"/usr/bin/python3\0/installed/cli\0gate0\0courier-original-oidc\0"
        if pid == 200:
            return (
                b"/bin/bash\0--noprofile\0--norc\0"
                + (b"-x" if mutation == "shell-argv" else b"-p")
                + b"\0-e\0-o\0pipefail\0/run/dotmac-gate0-jit/work/_temp/generated.sh\0"
            )
        if pid == 300:
            return (
                str(life._RUNNER_ROOT / "bin/Runner.Worker").encode()
                + b"\0"
                + (b"other" if mutation == "worker-argv" else b"spawnclient")
                + b"\0"
                + (b"03" if mutation == "worker-handle" else b"3")
                + b"\x004\x00"
            )
        return str(life._RUNNER).encode() + b"\0run\0--startuptype\0service\0"

    monkeypatch.setattr(life, "_proc", proc)

    def readlink(path):
        path = str(path)
        if "/fd/" in path:
            return "pipe:[" + path.rsplit("/", 1)[1] + "]"
        pid = int(Path(path).parts[2])
        if mutation == "worker-executable" and pid == 300:
            return "/unqualified/worker"
        return (
            "/usr/bin/python3"
            if pid == 100
            else "/usr/bin/bash"
            if pid == 200
            else str(life._RUNNER_ROOT / "bin/Runner.Worker")
            if pid == 300
            else str(life._RUNNER)
        )

    monkeypatch.setattr(os, "readlink", readlink)
    actual_open, actual_fstat, actual_stat = os.open, os.fstat, os.stat
    monkeypatch.setattr(
        os,
        "open",
        lambda path, *args, **kwargs: actual_open(executable, *args, **kwargs)
        if str(path).startswith("/proc/")
        else actual_open(path, *args, **kwargs),
    )

    def fstat(fd):
        value = actual_fstat(fd)
        fields = {
            key: getattr(value, key) for key in dir(value) if key.startswith("st_")
        }
        fields["st_uid"] = 0
        return SimpleNamespace(**fields)

    monkeypatch.setattr(os, "fstat", fstat)
    paths = {
        "/usr/bin/python3",
        "/usr/bin/bash",
        str(life._RUNNER),
        profile["worker_binary"]["path"],
    }
    monkeypatch.setattr(
        os,
        "stat",
        lambda path, *args, **kwargs: actual_stat(executable, *args, **kwargs)
        if str(path) in paths
        else actual_stat(path, *args, **kwargs),
    )
    script_reads = []

    def script(*_):
        script_reads.append(1)
        return (1, len(script_reads)) if mutation == "script-identity" else (1, 2)

    monkeypatch.setattr(life, "_measure_generated_script", script)
    alive_read, alive_write = os.pipe()
    created = []

    def pidfd_open(*_):
        fd = os.dup(alive_read)
        created.append(fd)
        return fd

    monkeypatch.setattr(os, "pidfd_open", pidfd_open)
    try:
        if mutation is None:
            chain = native._measure_supplier_chain(100)
            assert [part[0] for part in chain] == [100, 200, 300, 400]
            assert len(script_reads) == 2 and len(created) == 3
            assert native._measure_supplier_chain(100) == chain
            assert len(script_reads) == 4 and len(created) == 3
        else:
            with pytest.raises(life.LifecycleRefused):
                native._measure_supplier_chain(100)
            assert native._chain_pidfds == {}
    finally:
        native.close()
        for fd in created:
            with pytest.raises(OSError):
                actual_fstat(fd)
        os.close(alive_read)
        os.close(alive_write)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "old-native",
        "worker-bytes",
        "missing-native",
        "missing-evidence",
        "evidence-bytes",
        "review-mismatch",
        "workflow-mismatch",
        "supplier-source",
        "worker-runtime-pin",
        "shell-symlink-pin",
    ],
)
def test_actual_supplier_policy_requires_v2_root_evidence_and_safe_approved_pins(
    installed_model, monkeypatch, mutation
):
    from copy import deepcopy
    from pathlib import Path

    from vendor_cp.deployment.gate0_framing import strict_object

    model = installed_model
    files = deepcopy(model.files)
    root = "/run/dotmac-gate0-collector"
    prelaunch = strict_object(files[root + "/lifecycle/prelaunch.json"])
    reads = []

    def pin(path, raw):
        files[path] = raw
        return dict(path=path, digest=life._hash(raw))

    profile = dict(
        worker_binary=pin(
            "/opt/dotmac-gate0-jit/bin/Runner.Worker", b"SYNTHETIC-APPROVED-WORKER"
        ),
        shell_binary=pin("/usr/bin/bash", b"SYNTHETIC-CANONICAL-BASH"),
        script_template=pin("/etc/dotmac-gate0-a9/script.sh", b"SYNTHETIC-SCRIPT"),
        script_directory="/run/dotmac-gate0-jit/work/_temp",
        workflow_source_digest="sha256:" + "9" * 64,
        worker_pipe_handle_format="unix-decimal-fd.v1",
    )
    policy = dict(
        schema="Gate0A9BrokerPolicy.v1",
        method=tokens._SUPPLIER_METHOD,
        amendment_digest=tokens._SUPPLIER_AMENDMENT,
        supplier_commit=tokens._SUPPLIER_SOURCE,
        origins=["https://broker.example"],
        profile=profile,
    )
    if mutation == "supplier-source":
        policy["supplier_commit"] = "a" * 40
    if mutation == "worker-runtime-pin":
        profile["worker_binary"] = pin(
            str(life._RUNNER_ROOT / "bin/Runner.Worker"), b"SYNTHETIC-APPROVED-WORKER"
        )
    if mutation == "shell-symlink-pin":
        profile["shell_binary"] = pin("/bin/bash", b"SYNTHETIC-CANONICAL-BASH")
    prelaunch["broker_policy"] = pin(root + "/broker-policy.json", canonical(policy))
    files[root + "/lifecycle/prelaunch.json"] = canonical(prelaunch)
    evidence_names = (
        "listener_clean_inheritance worker_clean_inheritance "
        "all_workflow_environment_scopes startup_hooks preceding_writes "
        "missing_supplier_injection shell_survival executed_script_identity "
        "worker_pipe_handles metadata_first_ipc"
    ).split()
    evidence = {
        name: pin(
            root + "/native-observations/" + name,
            b"SYNTHETIC-EXTERNAL-NATIVE-OBSERVATION:" + name.encode(),
        )
        for name in evidence_names
    }
    common = dict(
        method=tokens._SUPPLIER_METHOD,
        amendment_digest=tokens._SUPPLIER_AMENDMENT,
        supplier_commit=tokens._SUPPLIER_SOURCE,
        prelaunch_selection_digest=life._prelaunch_selection_digest(prelaunch),
        broker_policy_digest=prelaunch["broker_policy"]["digest"],
        profile_digest=life._hash(canonical(profile)),
        workflow_source_digest=profile["workflow_source_digest"],
    )
    observation = dict(
        schema="Gate0A9SupplierNativeObservation.v1", **common, evidence=evidence
    )
    if mutation == "missing-evidence":
        del observation["evidence"]["missing_supplier_injection"]
    if mutation == "workflow-mismatch":
        observation["workflow_source_digest"] = "sha256:" + "8" * 64
    observation_pin = pin(root + "/supplier-observation.json", canonical(observation))
    review = dict(
        schema="Gate0A9SupplierNativeReview.v1",
        **common,
        evidence=dict(
            supplier_observation_digest=observation_pin["digest"],
            reviewed_evidence={k: v["digest"] for k, v in evidence.items()},
        ),
    )
    if mutation == "review-mismatch":
        review["evidence"]["reviewed_evidence"]["worker_clean_inheritance"] = (
            "sha256:" + "8" * 64
        )
    native_record = dict(
        schema="Gate0A9LifecycleNative.v2",
        boot_id="00000000-0000-0000-0000-000000000001",
        kernel_release="SYNTHETIC",
        runner_tree_digest="sha256:" + "1" * 64,
        systemd_version="SYNTHETIC",
        supplier_observation=observation_pin,
        supplier_review=pin(root + "/supplier-review.json", canonical(review)),
    )
    if mutation == "old-native":
        native_record["schema"] = "Gate0A9LifecycleNative.v1"
    native_pin = pin(root + "/lifecycle-native.json", canonical(native_record))
    if mutation == "worker-bytes":
        files[profile["worker_binary"]["path"]] = b"SWAPPED-WORKER"
    if mutation == "missing-native":
        del files[root + "/lifecycle-native.json"]
    if mutation == "evidence-bytes":
        files[evidence["missing_supplier_injection"]["path"]] = (
            b"CHANGED-NATIVE-OBSERVATION"
        )
    native = object.__new__(life.NativeJitInvocation)
    native.lifecycle = SimpleNamespace(
        _doc={k: prelaunch[k] for k in ("campaign_digest", "lifecycle_binding_digest")}
    )
    native.bounds = SimpleNamespace(provisioning_end=time.monotonic() + 10)
    native.selection = dict(native_receipt_digest=native_pin["digest"])
    native._call = lambda *_: pytest.fail(
        "supplier policy attempted JIT start/manager action"
    )

    def protected(path, *_, **__):
        path = str(Path(path))
        reads.append(path)
        if path.startswith(str(life._RUNNER_ROOT)) or path == "/bin/bash":
            raise life.LifecycleRefused()
        return files[path]

    monkeypatch.setattr(life, "_protected", protected)
    environment = AllReadTrap({"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-token"})
    monkeypatch.setattr(os, "environ", environment)
    if mutation is None:
        assert native._supplier_policy() == policy
        assert "/opt/dotmac-gate0-jit/bin/Runner.Worker" in reads
        assert "/usr/bin/bash" in reads
        assert not any(path.startswith(str(life._RUNNER_ROOT)) for path in reads)
    else:
        with pytest.raises((life.LifecycleRefused, KeyError)):
            native._supplier_policy()
    assert environment.reads == 0


def test_native_close_attempts_all_chain_fds_and_records_cleanup_failure(monkeypatch):
    native = object.__new__(life.NativeJitInvocation)
    native._closed, native._close_failed = False, False
    native._events, native._pidfd = 10, 11
    native._chain_pidfds = {1: ("1", 12), 2: ("2", 13), 3: ("3", 14)}
    closed = []

    def close(fd):
        closed.append(fd)
        if fd == 12:
            raise OSError("synthetic-close-failure")

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(life.LifecycleRefused):
        native.close()
    assert closed == [10, 11, 12, 13, 14]
    assert native._chain_pidfds == {} and native._close_failed
    with pytest.raises(life.LifecycleRefused):
        native.close()
    assert closed == [10, 11, 12, 13, 14]
