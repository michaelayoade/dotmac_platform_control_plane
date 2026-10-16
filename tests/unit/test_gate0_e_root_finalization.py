"""Hosted-only real owner composition at protected-file/native process seams.

No native qualification, actual campaign, custody or human adoption is claimed.
Static authority is never a caller accepted flag or a constructor seal bypass.
"""

from __future__ import annotations

import copy
import math
import os
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_e_github import producer as github_producer  # noqa: F401
from test_gate0_e_preparation import inputs  # noqa: F401
from test_gate0_e_source_references import (
    installed as historical_installed,  # noqa: F401
)
from test_gate0_e_writer import a9_export, installed_composition  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_root_finalization as root
from vendor_cp.deployment import gate0_e_writer as writer
from vendor_cp.deployment import gate0_runner_bootstrap as bootstrap
from vendor_cp.deployment import gate0_runner_lifecycle as lifecycle
from vendor_cp.deployment import gate0_runner_supervisor as supervisor
from vendor_cp.deployment.gate0_framing import canonical, strict_object


@pytest.fixture
def original_native(installed_composition, historical_installed, monkeypatch):  # noqa: F811
    c = installed_composition
    c.load()  # Build selected static writer records through its actual loader.
    c.reader("producer", snapshot_stage="collection")
    # Requalify synthetic native file records for actual root execution.
    for name in ("getuid", "geteuid", "getgid", "getegid"):
        monkeypatch.setattr(os, name, lambda: 0)
    gh = writer.github_owner
    gdoc = gh._json(c.gh_files[gh._INSTALLATION])
    gqual = gh._json(c.gh_files[gdoc["qualification"]["path"]])
    gqual["runtime_uid"] = 0
    c.gh_files[gdoc["qualification"]["path"]] = canonical(gqual)
    gdoc["qualification"]["digest"] = gh._digest(
        c.gh_files[gdoc["qualification"]["path"]]
    )
    c.gh_files[gh._INSTALLATION] = canonical(gdoc)
    gbinding = gh._json(c.gh_files[gh._ROOT_BINDING])
    gbinding.update(
        runtime_uid=0,
        installation_sha256=gh._digest(c.gh_files[gh._INSTALLATION]),
        qualification_sha256=gdoc["qualification"]["digest"],
    )
    c.gh_files[gh._ROOT_BINDING] = canonical(gbinding)
    historical = writer.historical_owner
    hdoc, hfiles, _, _, _ = historical_installed
    hqual = historical._json(hfiles[historical._QUALIFICATION])
    hqual["runtime_uid"] = 0
    hfiles[historical._QUALIFICATION] = canonical(hqual)
    hdoc["qualification"]["sha256"] = historical._digest(
        hfiles[historical._QUALIFICATION]
    )
    hfiles[historical._INSTALLATION] = canonical(hdoc)
    hbind = historical._json(hfiles[historical._BINDING])
    hbind.update(
        runtime_uid=0,
        installation_sha256=historical._digest(hfiles[historical._INSTALLATION]),
        qualification_sha256=historical._digest(hfiles[historical._QUALIFICATION]),
    )
    hfiles[historical._BINDING] = canonical(hbind)

    files = c.files
    boot = "00000000-0000-0000-0000-000000000001"
    elapsed = time.monotonic()
    final_wall = c.selection.cases[1].end + timedelta(seconds=2)
    wall = final_wall - timedelta(seconds=120)
    bounds = dict(
        boot_id=boot,
        wall=wall.isoformat(),
        monotonic=elapsed,
        provisioning_ends_at=(wall + timedelta(seconds=15)).isoformat(),
        finalization_ends_at=final_wall.isoformat(),
    )
    end = elapsed + 120
    end_us = math.floor(end * 1_000_000)
    native_sources = {}
    for name in ("gate0_runner_lifecycle", "gate0_runner_lifecycle_courier"):
        path = str(Path(lifecycle.__file__).with_name(name + ".py"))
        files[path] = Path(path).read_bytes()
        native_sources[name] = writer._sha(files[path])

    def pin(path, raw):
        files[str(path)] = raw
        return dict(path=str(path), digest=writer._sha(raw))

    cli = pin("/opt/unit/cli", b"SOURCE-UNIT-CLI")
    interpreter = pin("/opt/unit/python", b"SOURCE-UNIT-INTERPRETER")
    systemctl = pin("/usr/bin/systemctl", b"SOURCE-UNIT-SYSTEMCTL")
    manager = pin("/usr/lib/systemd/systemd", b"SOURCE-UNIT-SYSTEMD")
    runner = pin(lifecycle._RUNNER, b"SOURCE-UNIT-RUNNER")
    keygen = pin(lifecycle._KEYGEN, b"SOURCE-UNIT-KEYGEN")
    units = {
        name: pin(Path("/run/systemd/system") / unit, unit.encode())
        for name, unit in supervisor._UNITS.items()
    }
    launcher = dict(
        schema="Gate0A9JitLauncherSelection.v1",
        runner_id=16,
        runner_name="dedicated",
        runner_group_id=15,
        owner_id=c.producer.owner_id,
        workflow_id=c.producer.workflow_id,
        job_id=c.producer.job_id,
        job_name="E job",
        environment_id=13,
        source_revision=c.producer.source_revision,
        cli=cli,
        interpreter=interpreter,
        systemctl=systemctl,
        manager=manager,
        runner_binary=runner,
        runner_tree_digest="sha256:" + "1" * 64,
        unit_digest=units["jit_service"]["digest"],
        groups=[1003],
        native_receipt_digest="sha256:" + "2" * 64,
    )
    ldoc = dict(
        schema="Gate0A9LifecycleInstallation.v1",
        lifecycle_binding_digest=c.document["a9"]["lifecycle_binding_digest"],
        campaign_digest=c.selection.campaign_digest,
        allocation_id="unit-original",
        repository_id=c.producer.repository_id,
        run_id=c.producer.run_id,
        attempt=1,
        collector_uid=1001,
        collector_gid=1005,
        courier_uid=1002,
        courier_gid=1003,
        original_bounds=bounds,
        keygen_digest=keygen["digest"],
        source_files=native_sources,
        ca_digest="sha256:" + "3" * 64,
        cleanup_reserve_microseconds=15_000_000,
        launcher=launcher,
    )
    files[str(lifecycle._INSTALLATION)] = canonical(ldoc)
    lnative = pin(
        lifecycle._ROOT / "lifecycle-native.json", b"SOURCE-UNIT-LIFECYCLE-NATIVE"
    )
    files[str(lifecycle._ROOT / "lifecycle-qualification.json")] = canonical(
        dict(
            schema="Gate0A9LifecycleQualification.v1",
            installation_digest=writer._sha(canonical(ldoc)),
            native_receipt_digest=lnative["digest"],
        )
    )
    cases = []
    for index, case in enumerate(c.selection.cases):
        shared = pin(lifecycle._ROOT / f"unit-{index}-shared.json", case.shared_packet)
        window = pin(lifecycle._ROOT / f"unit-{index}-window.json", case.frozen_window)
        cases.append(
            dict(
                shared_packet=shared,
                frozen_window=window,
                command_id=case.command_id,
                hosts={
                    host: dict(
                        binding=f"unit-{index}-{host}", local_packet=None, endpoint=None
                    )
                    for host in ("IDP3", "NS3")
                },
                ssh_binary=None,
                keygen=None,
                private_key=None,
                certificate=None,
                known_hosts=None,
                issuer_trust=None,
                attester_trust=None,
            )
        )
    job = {
        **c.selection.cases[0].window.document["github"],
        "runner_group_id": "15",
        "runner_name": "dedicated",
    }
    collection = dict(
        schema="Gate0RunnerCollectionInstallation.v1",
        campaign_digest=c.selection.campaign_digest,
        collector_uid=1001,
        receiver_uid=1004,
        executable=interpreter,
        cases=cases,
        job=job,
    )
    collection_pin = pin(lifecycle._COLLECTION, canonical(collection))
    receiver = {
        key: None
        for key in bootstrap.ReceiverInstallation.__annotations__
        if key != "collector"
    }
    receiver.update(
        schema="Gate0ReceiverInstallation.v1",
        campaign_digest=c.selection.campaign_digest,
        receiver_uid=1004,
        cases=[
            {h: case["hosts"][h]["binding"] for h in ("IDP3", "NS3")} for case in cases
        ],
    )
    receiver_pin = pin(supervisor._ROOT / "unit-receiver.json", canonical(receiver))
    bsources = {}
    for name in (
        "gate0_runner_bootstrap",
        "gate0_runner_credential",
        "gate0_runner_lifecycle",
    ):
        path = Path(bootstrap.__file__).with_name(name + ".py")
        bsources[name] = pin(path, path.read_bytes())
    bdoc = dict(
        schema="Gate0CollectorBootstrapInstallation.v2",
        campaign_digest=c.selection.campaign_digest,
        lifecycle_binding_digest=ldoc["lifecycle_binding_digest"],
        collection_installation=collection_pin,
        collector_binary=cli,
        collector_gid=1005,
        collector_groups=[1005, 1003],
        socket_gid=1003,
        receiver_template=receiver_pin,
        qualification=pin(
            supervisor._ROOT / "unit-bootstrap-qualification.json", b"{}"
        ),
        native_receipt=pin(
            supervisor._ROOT / "unit-bootstrap-native.json", b"SOURCE-UNIT-NATIVE"
        ),
        source_revision=c.producer.source_revision,
        source_files=bsources,
        unit_assets={
            name: pin(supervisor._ROOT / ("unit-" + name), name.encode())
            for name in bootstrap._UNITS
        },
        manager_client=systemctl,
        manager_binary=manager,
    )
    files[str(bootstrap._INSTALLATION)] = canonical(bdoc)
    source = pin(Path(supervisor.__file__), Path(supervisor.__file__).read_bytes())
    sdoc = dict(
        schema="Gate0A9SupervisorInstallation.v1",
        lifecycle_installation_digest=writer._sha(canonical(ldoc)),
        source_digest=source["digest"],
        cli=cli,
        interpreter=interpreter,
        systemctl=systemctl,
        manager=manager,
        unit_assets=units,
    )
    snative = pin(
        supervisor._ROOT / "supervisor-native.json", b"SOURCE-UNIT-SUPERVISOR-NATIVE"
    )
    identity = dict(
        uid=0,
        gid=0,
        cap_eff=supervisor._CAPABILITIES,
        executable_digest=interpreter["digest"],
        cgroup="0::/system.slice/" + supervisor._LIFECYCLE,
    )
    squal = dict(
        schema="Gate0A9SupervisorQualification.v1",
        installation_digest=writer._sha(canonical(sdoc)),
        source_digest=source["digest"],
        boot_id=boot,
        kernel_release=os.uname().release,
        systemd_version="unit-systemd",
        runtime_identity=identity,
        unit_assets=units,
        native_receipt_digest=snative["digest"],
    )
    sqpin = pin(supervisor._ROOT / "supervisor-qualification.json", canonical(squal))
    sdoc["qualification_digest"] = sqpin["digest"]
    files[str(supervisor._ROOT / "supervisor-installation.json")] = canonical(sdoc)

    def protected(path, maximum=65536, **kwargs):
        raw = files[str(path)]
        assert 0 < len(raw) <= maximum
        return raw

    monkeypatch.setattr(supervisor, "_protected", protected)
    monkeypatch.setattr(lifecycle, "_protected", protected)
    monkeypatch.setattr(
        bootstrap,
        "read_protected_handoff",
        lambda path, uid, maximum=65536, **kw: protected(path, maximum),
    )
    monkeypatch.setattr(lifecycle, "_proc", lambda path, *args: (boot + "\n").encode())
    monkeypatch.setattr(
        supervisor, "measure_handoff_process", lambda pid: ("unit", 0, "unit")
    )
    monkeypatch.setattr(
        supervisor.os,
        "readlink",
        lambda path: manager["path"] if path == "/proc/1/exe" else interpreter["path"],
    )

    def proc(path, *args):
        if str(path).endswith("/status"):
            return f"CapEff:\t{supervisor._CAPABILITIES:x}\n".encode()
        return ("0::/system.slice/" + supervisor._LIFECYCLE + "\n").encode()

    monkeypatch.setattr(supervisor, "_proc", proc)
    service = {key: "" for key in supervisor._SERVICE}
    service.update(
        LoadState="loaded",
        FragmentPath="/run/systemd/system/" + supervisor._LIFECYCLE,
        Type="exec",
        ExitType="main",
        Restart="no",
        RemainAfterExit="no",
        KillMode="control-group",
        KillSignal="9",
        FinalKillSignal="9",
        SendSIGKILL="yes",
        Delegate="no",
        NoNewPrivileges="yes",
        StandardOutput="null",
        StandardError="null",
        User="0",
        Group="0",
        MainPID=str(os.getpid()),
        ActiveState="active",
        InvocationID="a" * 32,
        ExecStart=(
            f"{{ path={cli['path']} ; argv[]={cli['path']} "
            "gate0 lifecycle-run ; ignore_errors=no ;"
        ),
        ExecStopPost=(
            f"{{ path={cli['path']} ; argv[]={cli['path']} "
            "gate0 lifecycle-retire-jit ; ignore_errors=no ;"
        ),
        CapabilityBoundingSet=(
            "cap_chown cap_dac_override cap_fowner cap_kill "
            "cap_setgid cap_setuid cap_sys_ptrace"
        ),
        LoadCredential="jit-config-delivery:/run/dotmac-gate0-provisioner/encoded-jit-config",
    )
    bootstrap_values = {key: "" for key in supervisor._SERVICE}
    bootstrap_values.update(
        ActiveState="inactive",
        SubState="dead",
        MainPID="0",
        Result="success",
        ExecMainCode="1",
        ExecMainStatus="0",
        InvocationID=c.document["a9"]["bootstrap_invocation_id"],
        BindsTo=supervisor._LIFECYCLE,
        After=supervisor._LIFECYCLE,
    )
    jit_values = {key: "" for key in supervisor._SERVICE}
    jit_values.update(BindsTo=supervisor._LIFECYCLE, After=supervisor._LIFECYCLE)
    native_manager = {
        supervisor._LIFECYCLE: service,
        supervisor._BOOTSTRAP: bootstrap_values,
        supervisor._JIT: jit_values,
        "": {"Version": "unit-systemd"},
    }

    def call(self, args, deadline):
        assert time.monotonic() < deadline <= end
        unit = args[3] if len(args) == 4 else ""
        values = native_manager[unit]
        return "".join(
            key + "=" + values[key] + "\n" for key in supervisor._SHOW[unit]
        ).encode()

    monkeypatch.setattr(supervisor.SupervisorManager, "_call", call)

    actual_bootstrap = bootstrap.BootstrapInstallation.from_installed()
    assert actual_bootstrap.clock.cutoff == end
    owned = strict_object(files[writer._EXPORT + "owned-files-retirement.json"])
    owned.update(boot_id=boot, original_deadline_microseconds=end_us)
    files[writer._EXPORT + "owned-files-retirement.json"] = canonical(owned)
    manifest = strict_object(files[writer._EXPORT + "manifest.json"])
    manifest["files"] = {
        name: dict(
            bytes=len(files[writer._EXPORT + name]),
            digest=writer._sha(files[writer._EXPORT + name]),
        )
        for name in c.document["a9"]["files"]
    }
    files[writer._EXPORT + "manifest.json"] = canonical(manifest)
    completion = strict_object(c.files[c.document["a9"]["completion"]["path"]])
    completion["original_cutoff_microseconds"] = end_us
    completion["timer"] = {"NextElapseUSecMonotonic": str(end_us)}
    completion["bootstrap_manager_observation"]["original_clock"] = strict_object(
        actual_bootstrap.original_clock
    )
    files[writer._ROOT_COMPLETION] = canonical(completion)
    identities = {
        name: dict(
            device=1,
            inode=200 + index,
            bytes=len(files[path]),
            digest=writer._sha(files[path]),
        )
        for index, (name, path) in enumerate(
            [
                *(
                    (name, writer._EXPORT + name)
                    for name in (*c.document["a9"]["files"], "manifest.json")
                ),
                ("bootstrap-observation.json", writer._ROOT_COMPLETION),
            ]
        )
    }

    def original_input(name, deadline):
        assert time.monotonic() < deadline <= end
        path = (
            writer._ROOT_COMPLETION
            if name == "bootstrap-observation.json"
            else writer._EXPORT + name
        )
        return files[path], copy.deepcopy(identities[name])

    monkeypatch.setattr(supervisor, "_read_original_e_input", original_input)

    template = copy.deepcopy(c.document)
    del template["qualification"]
    template["a9"] = {
        key: template["a9"][key]
        for key in ("lifecycle_binding_digest", "qualification_digest", "owned_slots")
    }
    profile = dict(
        schema="Gate0ERootStaticProfile.v1",
        writer=template,
        collector_uid=1001,
        courier_uid=1002,
        courier_gid=1003,
    )
    owners = {
        name: writer._sha(files[path])
        for name, path in {
            "writer": writer.__file__,
            "proof": writer.proof_owner.__file__,
            "archive": writer.archive_owner.__file__,
            "preparation": writer.preparation_owner.__file__,
            "historical": historical.__file__,
            "github": gh.__file__,
            "release": writer.release_owner.__file__,
            "handoff": writer.handoff_owner.__file__,
            "framing": writer.framing_owner.__file__,
        }.items()
    }
    for name, module in (
        ("supervisor", supervisor),
        ("bootstrap", bootstrap),
        ("lifecycle", lifecycle),
        ("root_finalization", root),
        ("transfer", root.transfer),
    ):
        files[module.__file__] = Path(module.__file__).read_bytes()
        owners[name] = writer._sha(files[module.__file__])
    native = c.pin(
        "root-native",
        canonical(
            dict(
                schema="Gate0ERootFinalizationNativeReview.v1",
                method_scope=writer._ROOT_SCOPE,
                owner_digests=owners,
                qualification_measurements_digest="1" * 64,
                runtime_identity_digest="2" * 64,
                reviewer_record_digest="3" * 64,
            )
        ),
    )
    qual = dict(
        schema="Gate0ERootStaticQualification.v1",
        static_profile_digest=writer._sha(canonical(profile)),
        policy_digest=c.selection.policy_digest,
        runtime_uid=0,
        owner_digests=owners,
        native_receipt=native,
        decision_provenance=c.provenance_pin,
        method_scope=writer._ROOT_SCOPE,
        dynamic_fields=list(writer._ROOT_DYNAMIC_FIELDS),
    )
    profile["qualification"] = c.pin("root-qualification", canonical(qual))
    files[writer._ROOT_STATIC] = canonical(profile)
    files[writer._ROOT_STATIC_BINDING] = canonical(
        dict(
            schema="Gate0ERootStaticBinding.v1",
            profile_digest=writer._sha(canonical(profile)),
            qualification_digest=profile["qualification"]["digest"],
            runtime_uid=0,
            owners=owners,
            native_receipt=native,
        )
    )
    return SimpleNamespace(
        c=c,
        files=files,
        profile=profile,
        qualification=qual,
        end=end,
        end_us=end_us,
        bounds=bounds,
        boot=boot,
        identities=identities,
        native_manager=native_manager,
        bootstrap=actual_bootstrap,
        lifecycle=ldoc,
        original_input=original_input,
    )


def test_actual_static_root_factory_prepares_private_archive_with_original_end(
    original_native,
):
    n = original_native
    owner = writer.InstalledEWriter.from_original_root_export()
    assert owner._root_deadline == n.end
    owner.prepare(deadline=n.end + 180)
    assert len(n.c.packages) == len(n.c.staged) == 1
    assert n.c.packages[0][3] == n.end
    assert set(n.c.staged[0]) == {"gate0-evidence.pgp", "gate0-evidence-public.json"}
    projection = strict_object(n.c.staged[0]["gate0-evidence-public.json"])
    assert projection["campaign_digest"] == n.c.selection.campaign_digest
    assert not hasattr(owner, "readiness_accepted")


def test_root_initialization_and_finalization_use_only_fixed_encrypted_handoff(
    original_native, monkeypatch
):
    n = original_native
    calls = []
    owned = []
    actual = writer.InstalledEWriter.from_original_root_export

    def load(cls):
        result = actual()
        owned.append(result)
        return result

    monkeypatch.setattr(
        writer.InstalledEWriter, "from_original_root_export", classmethod(load)
    )
    monkeypatch.setattr(
        root.transfer,
        "_initialize_original_transfer",
        lambda **values: calls.append(("ticket", values)),
    )
    monkeypatch.setattr(
        root.transfer,
        "_publish_original_encrypted_pair",
        lambda **values: calls.append(("pair", values)),
    )
    root.initialize_original_export()
    assert not n.c.staged
    root.prepare_original_export()
    assert [name for name, _ in calls] == ["ticket", "pair"]
    assert calls[0][1] == calls[1][1]
    assert set(calls[0][1]) == {
        "deadline",
        "boot_id",
        "campaign_digest",
        "lifecycle_binding_digest",
        "courier_uid",
        "courier_gid",
        "profile_digest",
        "source_bundle_digest",
    }
    assert calls[0][1]["deadline"] == n.end and calls[0][1]["courier_uid"] == 1002
    assert owned[0].__dict__ == {"_used": True}


@pytest.mark.parametrize(
    "failure",
    [
        "static_policy",
        "dynamic_a9",
        "source",
        "root_uid",
        "qualification_scope",
        "native",
    ],
)
def test_root_profile_substitution_refuses_before_encryption(
    original_native, monkeypatch, failure
):
    n = original_native
    if failure == "static_policy":
        doc = strict_object(n.files[writer._ROOT_STATIC])
        doc["writer"]["policy_digest"] = "sha256:" + "0" * 64
        n.files[writer._ROOT_STATIC] = canonical(doc)
    elif failure == "dynamic_a9":
        doc = strict_object(n.files[writer._ROOT_STATIC])
        doc["writer"]["a9"]["bootstrap_invocation_id"] = "f" * 32
        n.files[writer._ROOT_STATIC] = canonical(doc)
    elif failure == "source":
        n.files[str(Path(root.__file__).absolute())] += b"foreign source"
    elif failure == "root_uid":
        monkeypatch.setattr(os, "getuid", lambda: 1002)
    elif failure == "qualification_scope":
        n.files[n.profile["qualification"]["path"]] += b"foreign scope"
    else:
        binding = strict_object(n.files[writer._ROOT_STATIC_BINDING])
        binding["native_receipt"]["digest"] = "sha256:" + "0" * 64
        n.files[writer._ROOT_STATIC_BINDING] = canonical(binding)
    with pytest.raises(writer.EWriterRefused):
        writer.InstalledEWriter.from_original_root_export()
    assert not n.c.packages and not n.c.staged


@pytest.mark.parametrize(
    "failure",
    ["boot", "deadline", "timer", "campaign", "invocation", "window", "inode"],
)
def test_actual_root_export_runtime_scope_tamper_refuses(original_native, failure):
    n = original_native
    path = writer._ROOT_COMPLETION
    completion = strict_object(n.files[path])
    if failure == "boot":
        completion["bootstrap_manager_observation"]["original_clock"]["boot_id"] = (
            "f" * 36
        )
    elif failure == "deadline":
        completion["original_cutoff_microseconds"] += 1
    elif failure == "timer":
        completion["timer"]["NextElapseUSecMonotonic"] = str(n.end_us + 1)
    elif failure == "campaign":
        completion["campaign_digest"] = "sha256:" + "0" * 64
    elif failure == "invocation":
        completion["bootstrap_manager_observation"]["bootstrap"]["InvocationID"] = (
            "f" * 32
        )
    elif failure == "window":
        completion["bootstrap_manager_observation"]["original_clock"]["window_digests"][
            1
        ] = "sha256:" + "0" * 64
    else:
        n.identities["collection.json"]["inode"] += 1
    n.files[path] = canonical(completion)
    if failure == "inode":
        owner = writer.InstalledEWriter.from_original_root_export()
        n.identities["collection.json"]["inode"] += 1
        with pytest.raises(writer.EWriterRefused):
            owner.prepare(deadline=n.end)
    else:
        with pytest.raises(writer.EWriterRefused):
            writer.InstalledEWriter.from_original_root_export()
    assert not n.c.packages and not n.c.staged


@pytest.mark.parametrize("phase", ["historical", "github", "encryption", "output"])
def test_original_deadline_exhaustion_never_publishes_transfer(
    original_native, monkeypatch, phase
):
    n = original_native
    calls = []
    monkeypatch.setattr(
        root.transfer, "_publish_original_encrypted_pair", lambda **kw: calls.append(kw)
    )
    if phase == "historical":
        actual = writer.InstalledHistoricalSourceReads.verify

        def historical(self, *, deadline):
            assert deadline == n.end
            monkeypatch.setattr(time, "monotonic", lambda: n.end)
            return actual(self, deadline=deadline)

        monkeypatch.setattr(writer.InstalledHistoricalSourceReads, "verify", historical)
    elif phase == "github":
        actual = writer.InstalledGate0GitHubReads.producer_snapshot

        def github(self, stage, *, deadline=None):
            assert deadline == n.end
            monkeypatch.setattr(time, "monotonic", lambda: n.end)
            return actual(self, stage, deadline=deadline)

        monkeypatch.setattr(
            writer.InstalledGate0GitHubReads, "producer_snapshot", github
        )
    elif phase == "encryption":
        actual = writer.preparation_owner.package_private_collection

        def encryption(*args, deadline):
            assert deadline == n.end
            result = actual(*args, deadline=deadline)
            monkeypatch.setattr(time, "monotonic", lambda: n.end)
            return result

        monkeypatch.setattr(
            writer.preparation_owner, "package_private_collection", encryption
        )
    else:

        def output(files, *, deadline):
            assert deadline == n.end
            monkeypatch.setattr(time, "monotonic", lambda: n.end)
            writer._require(time.monotonic() < deadline)

        monkeypatch.setattr(writer, "_stage", output)
    with pytest.raises(writer.EWriterRefused):
        root.prepare_original_export()
    assert not calls


def test_completed_job_cannot_finalize_original_collection(original_native):
    n = original_native
    for (_path, binary), value in n.c.wire.items():
        if not binary and isinstance(value, dict) and "jobs" in value:
            value["jobs"][0].update(
                status="completed",
                conclusion="success",
                completed_at="2026-10-15T10:05:00Z",
            )
    owner = writer.InstalledEWriter.from_original_root_export()
    with pytest.raises(writer.EWriterRefused):
        owner.prepare(deadline=n.end)
    assert not n.c.packages and not n.c.staged


@pytest.mark.parametrize("bootstrap_failed", [False, True])
def test_actual_outer_sequence_finalizes_before_waiting_original_jit(
    original_native, monkeypatch, bootstrap_failed
):
    n = original_native
    events = []
    actual_call = supervisor.SupervisorManager._call
    exited = copy.deepcopy(n.native_manager[supervisor._BOOTSTRAP])
    n.native_manager[supervisor._BOOTSTRAP].update(
        InvocationID="", ActiveState="inactive", MainPID="0"
    )

    class Lock:
        def __init__(self, deadline):
            assert deadline <= n.end

        def close(self):
            pass

    class OriginalLifecycle:
        _jit = SimpleNamespace(invocation="b" * 32)

        def create_controller_keys(self):
            return tuple(
                SimpleNamespace(
                    case_kind=kind,
                    public_key=b"ssh-ed25519 SOURCE-UNIT",
                    controller_fingerprint="SOURCE-UNIT",
                )
                for kind in ("consume_replay", "withdrawal_later_use")
            )

        def install_controller_certificates(self):
            events.append("certificates")

        def _install_original_jit_config(self, raw):
            assert events.index("ticket") < len(events)
            events.append("jit-start")

        def receive_original_job_credential(self):
            events.append("courier")

        def close(self):
            pass

    def manager_call(self, args, deadline):
        if args == ("start", "--no-block", supervisor._BOOTSTRAP):
            values = copy.deepcopy(n.native_manager[supervisor._LIFECYCLE])
            values.update(
                FragmentPath="/run/systemd/system/" + supervisor._BOOTSTRAP,
                ExecStart=(
                    "{ path=/opt/unit/cli ; argv[]=/opt/unit/cli "
                    "gate0 bootstrap-collector ; ignore_errors=no ;"
                ),
                ExecStopPost="",
                BindsTo=supervisor._LIFECYCLE,
                After=supervisor._LIFECYCLE,
                SubState="running",
                InvocationID=exited["InvocationID"],
            )
            n.native_manager[supervisor._BOOTSTRAP] = values
            return b""
        return actual_call(self, args, deadline)

    def wait(self, unit, invocation, deadline):
        assert deadline == n.end
        if unit == supervisor._BOOTSTRAP:
            events.append("bootstrap-done")
            values = copy.deepcopy(exited)
            if bootstrap_failed:
                values.update(
                    ActiveState="failed", Result="exit-code", ExecMainStatus="1"
                )
            n.native_manager[unit] = values
            return values
        assert unit == supervisor._JIT and invocation == "b" * 32
        assert "pair" in events
        events.append("jit-done")
        return dict(Result="success", ExecMainCode="1", ExecMainStatus="0")

    actual_proc = supervisor._proc

    def proc(path, *args):
        if str(path) == f"/proc/{os.getpid()}/cgroup":
            return ("0::/system.slice/" + supervisor._BOOTSTRAP + "\n").encode()
        return actual_proc(path, *args)

    monkeypatch.setattr(supervisor, "_proc", proc)
    monkeypatch.setattr(supervisor, "JournalLock", Lock)
    monkeypatch.setattr(supervisor.SupervisorManager, "_call", manager_call)
    monkeypatch.setattr(
        supervisor.SupervisorManager, "arm", lambda self: events.append("timer")
    )
    monkeypatch.setattr(supervisor.SupervisorManager, "wait_inactive", wait)
    monkeypatch.setattr(
        supervisor.InstalledA9Lifecycle,
        "from_installed",
        classmethod(lambda cls: OriginalLifecycle()),
    )
    monkeypatch.setattr(supervisor, "_delivery", lambda installed: None)
    monkeypatch.setattr(
        supervisor, "_read_outer_credential", lambda deadline: b"SOURCE-UNIT-CONFIG"
    )
    monkeypatch.setattr(supervisor, "_publish", lambda *args, **kw: None)
    monkeypatch.setattr(
        supervisor,
        "_export_directory",
        lambda gid, deadline: supervisor._require(gid == 0),
    )
    monkeypatch.setattr(
        supervisor, "_retire_jit", lambda installed: events.append("retire")
    )
    monkeypatch.setattr(
        root.transfer,
        "_initialize_original_transfer",
        lambda **kw: events.append("ticket"),
    )
    monkeypatch.setattr(
        root.transfer,
        "_publish_original_encrypted_pair",
        lambda **kw: events.append("pair"),
    )
    assert supervisor.run_installed_lifecycle() == (3 if bootstrap_failed else 0)
    assert events.index("ticket") < events.index("jit-start")
    if bootstrap_failed:
        assert "pair" not in events and "jit-done" not in events and not n.c.packages
    else:
        assert (
            events.index("bootstrap-done")
            < events.index("pair")
            < events.index("jit-done")
            < events.index("retire")
        )
        assert n.c.packages[0][3] == n.end
