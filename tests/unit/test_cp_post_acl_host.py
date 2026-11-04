"""Post-ACL host composition over existing fence/measurement/runtime owners.

The core's already-validated historical context, Docker, PG and fence transports
are fixture boundaries. Host guards, complete measurement equality, immutable
runtime inputs and publication checks remain real. Hosted CI only.
"""

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, read_json
from vendor_cp.deployment import cp_transition_host as module
from vendor_cp.deployment.cp_transition import (
    ArtifactStore,
    CpFailedCandidateRequestV2,
    CpPostAclRecoveryRequestV1,
    FailedCandidateContextV2,
    HistoricalCommittedAuthorization,
    PostAclRecoveryContext,
    raw_digest,
)


@pytest.fixture
def post_acl(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module,
        "_protected_executable_digest",
        lambda path: (
            "sha256:" + ("5" * 64 if path == Path("/usr/bin/docker") else "6" * 64)
        ),
    )
    config = module.CpTransitionHostConfig(
        repository_root=tmp_path,
        deploy_directory=tmp_path,
        target_descriptor=tmp_path / "target.toml",
        source_image=f"{module.IMAGE_REPOSITORY}@sha256:{'1' * 64}",
        target_image=f"{module.IMAGE_REPOSITORY}@sha256:{'2' * 64}",
        postgres_image=f"postgres@sha256:{'3' * 64}",
        maintenance_helper=tmp_path / "maintenance",
        maintenance_helper_digest="sha256:" + "4" * 64,
        external_ready_url=module.EXTERNAL_READY_URL,
        candidate_port=18100,
        docker_binary_digest="sha256:" + "5" * 64,
        git_binary=Path("/usr/bin/git"),
        git_binary_digest="sha256:" + "6" * 64,
        operator_revision="f" * 40,
    )
    catalogue = b"complete retained catalogue"
    measurement = {
        "track_counts": True,
        "stats_reset": "reset",
        "server_start": "started",
        "relations": [
            ["public", "relay_heartbeats", 1, 2, 3, 4, 5],
            ["mod_approvals", "approvals", 7, 8, 9, 10, 11],
        ],
        "sequences": [["public", "sequence", 6]],
        "catalogue_digest": raw_digest(catalogue),
    }
    descriptor = b"unchanged target descriptor"
    old_nonce, new_nonce = "6" * 64, "7" * 64
    grants = (("owner", "CREATE", False, "owner"),)
    original_proof = SimpleNamespace(
        prior_grants=grants,
        prior_acl="original ACL",
        digest=lambda: "sha256:" + "a" * 64,
    )
    proof = SimpleNamespace(
        database="cp",
        fence_id=old_nonce,
        prior_grants=grants,
        prior_acl="original ACL",
        digest=lambda: "sha256:" + "b" * 64,
    )
    prior = {
        "schema": "dotmac.cp_failed_candidate_request/2",
        "host": "host",
        "database": "cp",
        "database_oid": 42,
        "cluster_system_identifier": "123",
        "source": {"heads": [f"source-{i}" for i in range(6)]},
        "target": {
            "heads": [f"target-{i}" for i in range(7)],
            "raw_descriptor_digest": raw_digest(descriptor),
            "image_digest": "sha256:" + "2" * 64,
        },
    }
    original_request = {**prior, "schema": "dotmac.cp_transition_request/1"}
    recovery = {module.request_digest(original_request): object()}
    original = SimpleNamespace(
        request=original_request, original_proof=original_proof, recovery=recovery
    )
    predecessor = cast(FailedCandidateContextV2, SimpleNamespace(original=original))
    snapshot = canonical_json(
        {
            "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
            "request_digest": "sha256:" + "c" * 64,
            "host_nonce": old_nonce,
            "measurement": measurement,
        }
    )
    proof_raw = canonical_json(
        {
            "schema": "dotmac.cp_candidate_quiescence/1",
            "request_digest": "sha256:" + "c" * 64,
            "host_nonce": old_nonce,
            "before_digest": raw_digest(snapshot),
            "after_digest": raw_digest(snapshot),
        }
    )
    records = {raw_digest(proof_raw): proof_raw, raw_digest(snapshot): snapshot}
    store = cast(
        ArtifactStore,
        SimpleNamespace(
            root=tmp_path / "prior", read=lambda checksum: records[checksum]
        ),
    )
    context = PostAclRecoveryContext(
        predecessor=predecessor,
        prior_store=store,
        request=cast(CpFailedCandidateRequestV2, prior),
        host_nonce=old_nonce,
        historical_authorization=cast(HistoricalCommittedAuthorization, object()),
        proof=proof,
        context_digest="sha256:" + "d" * 64,
        predecessor_frontier_claim_digest="sha256:" + "e" * 64,
        pre_routing_receipt_digest="sha256:" + "f" * 64,
        evidence={},
        quiescence_digest=raw_digest(proof_raw),
        inventory={},
    )
    request = cast(
        CpPostAclRecoveryRequestV1,
        {
            **deepcopy(prior),
            "schema": "dotmac.cp_post_acl_recovery_request/1",
            "operator_revision": config.operator_revision,
            "basis": {
                "context_digest": context.context_digest,
                "current_fence_digest": proof.digest(),
                "current_fence_id": old_nonce,
                "original_fence_digest": original_proof.digest(),
                "frontier_measurement_digest": raw_digest(canonical_json(measurement)),
            },
        },
    )
    host = module.ExistingCpTransitionHost(
        config,
        store=ArtifactStore(tmp_path),
        recovery={},
        post_acl_recovery_context=context,
        post_acl_contexts={context.context_digest: context},
    )
    events = []
    state = SimpleNamespace(
        host=host,
        request=request,
        context=context,
        measurement=measurement,
        catalogue=catalogue,
        descriptor=descriptor,
        events=events,
        nonce=new_nonce,
        residual=None,
        measures=0,
        retained=[],
        docker_calls=[],
        queries=[],
        core_claimed=False,
        candidate_container=False,
        candidate_renamed=False,
    )
    connection = SimpleNamespace(
        execute=lambda statement: SimpleNamespace(all=lambda: [])
    )

    def execute(statement):
        sql = str(statement)
        state.queries.append(sql)
        return SimpleNamespace(
            all=lambda: ["present"] if state.residual and state.residual in sql else []
        )

    connection.execute = execute
    monkeypatch.setattr(host, "_connect", lambda *args: nullcontext(connection))
    monkeypatch.setattr(host, "_identity", lambda *args: events.append("identity"))
    monkeypatch.setattr(
        host, "_check_fence_baseline", lambda *args: events.append("acl")
    )
    monkeypatch.setattr(
        host, "_strict", lambda *args: events.append("strict") or host.proof
    )
    monkeypatch.setattr(
        host,
        "_http",
        lambda *args, **kwargs: events.append(("http", kwargs["expected"])),
    )
    monkeypatch.setattr(
        host, "_inspect_installation", lambda *args: events.append("installation")
    )
    monkeypatch.setattr(module, "_read_protected", lambda path: state.descriptor)
    monkeypatch.setattr(
        module,
        "read_current_migration_heads",
        lambda connection: request["target"]["heads"],
    )
    monkeypatch.setattr(
        module.candidate_roles,
        "require_planned_target_only_connect",
        lambda *args, **kwargs: events.append("forecast"),
    )

    def measure(connection):
        state.measures += 1
        events.append("measure")
        measured = deepcopy(state.measurement)
        measured.pop("catalogue_digest")
        measured["catalogue_bytes"] = state.catalogue
        return measured

    monkeypatch.setattr(module, "measure_candidate_quiescence", measure)
    monkeypatch.setattr(
        host,
        "_source_image_identity",
        lambda image, side: events.append(("image", image)) or "target-id",
    )
    spec = {
        "services": {
            service: {"image": config.target_image, "environment": {}, "volumes": []}
            for service in ("app", "relay")
        }
    }
    spec["services"]["app"]["ports"] = [
        {
            "host_ip": "127.0.0.1",
            "target": 8000,
            "published": str(config.app_port),
            "protocol": "tcp",
        }
    ]
    ports = {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(config.app_port)}]}
    writers = [
        {
            "Id": service,
            "Image": "target-id",
            "Config": {
                "Image": config.target_image,
                "Env": [],
                "Labels": {
                    "com.docker.compose.project": "dotmac_vendor_control_plane",
                    "com.docker.compose.service": service,
                },
            },
            "State": {
                "Running": True,
                "Restarting": True,
                "Health": {"Status": "unhealthy"},
            },
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
            "Mounts": [],
        }
        for service in ("app", "relay")
    ]
    writers[0]["HostConfig"]["PortBindings"] = deepcopy(ports)
    writers[0]["NetworkSettings"] = {"Ports": {}}
    state.writers, state.specification = writers, spec
    monkeypatch.setattr(host, "_runtime_specification", lambda: spec)
    monkeypatch.setattr(host, "_writers", lambda: writers)

    def docker(*args):
        state.docker_calls.append(args)
        if args[0] == "update":
            assert state.core_claimed
            events.append("update")
            next(info for info in writers if info["Id"] == args[-1])["HostConfig"][
                "RestartPolicy"
            ]["Name"] = "no"
        elif args[0] == "stop":
            assert state.core_claimed
            events.append("stop")
            next(info for info in writers if info["Id"] == args[-1])["State"].update(
                Running=False, Restarting=False
            )
        else:
            assert args[0] == "ps", "readonly admission issued a mutation"
            if state.candidate_container and "name=vcp-d16-" in args:
                return "candidate-id"
            if state.candidate_renamed and "label=com.docker.compose.project" in args:
                return "renamed-id"
        return ""

    monkeypatch.setattr(
        host,
        "_container",
        lambda identifier: {
            "Config": {"Labels": {"com.docker.compose.project": "vcp-d16-renamed"}}
        },
    )
    monkeypatch.setattr(
        module.transition_fence,
        "fence_writers",
        lambda *args, **kwargs: pytest.fail("unapproved fence mutation"),
    )
    monkeypatch.setattr(host, "_docker", docker)
    monkeypatch.setattr(
        host, "_run", lambda *args, **kwargs: pytest.fail("unapproved process")
    )
    monkeypatch.setattr(
        host.store, "put", lambda raw: state.retained.append(raw) or raw_digest(raw)
    )
    monkeypatch.setattr(
        host.store,
        "read",
        lambda *args, **kwargs: canonical_json({"host_nonce": new_nonce}),
    )
    return state


def test_post_acl_admission_is_readonly_and_accepts_fenced_target_restart(post_acl):
    state = post_acl
    observed = read_json(
        state.host.inspect_post_acl_recovery(state.request, state.context)
    )
    assert observed == {
        "source": state.request["source"],
        "target": state.request["target"],
        "measurement": state.measurement,
    }
    assert state.measures == 1 and not state.retained
    assert "stop" not in state.events and "update" not in state.events
    assert all(call[0] == "ps" for call in state.docker_calls)
    assert all(query.startswith("SELECT") for query in state.queries)
    assert ("image", state.host.config.source_image) not in state.events
    assert (
        state.host._request is state.request and state.host.proof is state.context.proof
    )


@pytest.mark.parametrize(
    "field",
    [
        "track_counts",
        "stats_reset",
        "server_start",
        "relations",
        "sequences",
        "catalogue_digest",
    ],
)
def test_post_acl_admission_preserves_every_measurement_dimension(
    post_acl, monkeypatch, field
):
    state = post_acl
    if field == "catalogue_digest":
        state.catalogue = b"changed catalogue"
    else:
        state.measurement = {
            **state.measurement,
            field: False if field == "track_counts" else "changed",
        }
    with pytest.raises(ContractError):
        state.host.inspect_post_acl_recovery(state.request, state.context)
    assert (
        state.host._request is None
        and not state.retained
        and "stop" not in state.events
    )


def test_post_acl_measurement_unavailable_cannot_claim_admission(post_acl, monkeypatch):
    def unavailable(connection):
        raise RuntimeError("statistics unavailable")

    monkeypatch.setattr(module, "measure_candidate_quiescence", unavailable)
    with pytest.raises(RuntimeError):
        post_acl.host.inspect_post_acl_recovery(post_acl.request, post_acl.context)
    assert post_acl.host._request is None


@pytest.mark.parametrize(
    "fault",
    [
        "fence",
        "proof_nonce",
        "grants",
        "target",
        "candidate_roles",
        "candidate_sessions",
        "unknown_writer",
        "wrong_image",
        "wrong_env",
        "wrong_mount",
        "duplicate",
    ],
)
def test_post_acl_admission_refuses_current_state_drift(post_acl, fault):
    state = post_acl
    if fault == "fence":
        state.host.proof = object()
    elif fault == "proof_nonce":
        state.context.proof.fence_id = "changed"
    elif fault == "grants":
        state.context.proof.prior_acl = "changed"
    elif fault == "target":
        state.request["target"] = {**state.request["target"], "heads": ["other"]}
    elif fault == "candidate_roles":
        state.residual = "pg_roles"
    elif fault == "candidate_sessions":
        state.residual = "pg_stat_activity"
    elif fault == "unknown_writer":
        state.writers[0]["Config"]["Labels"]["com.docker.compose.service"] = "unknown"
    elif fault == "wrong_image":
        state.writers[0]["Image"] = "source-id"
    elif fault == "wrong_env":
        state.specification["services"]["app"]["environment"]["REQUIRED"] = "value"
    elif fault == "wrong_mount":
        state.writers[0]["Mounts"] = [{"Destination": "/unexpected"}]
    else:
        state.writers.append(deepcopy(state.writers[1]))
    with pytest.raises(ContractError):
        state.host.inspect_post_acl_recovery(state.request, state.context)
    assert (
        state.host._request is None
        and not state.retained
        and "stop" not in state.events
    )


def stop_after_core_claim(state):
    state.host.inspect_post_acl_recovery(state.request, state.context)
    # The core owns and tests durable reservation/claim ordering separately.
    state.core_claimed = True
    state.host.stop_and_drain_writers(state.request, state.nonce)


def test_post_acl_rebind_remeasures_after_stop_and_uses_existing_fence_owner(
    post_acl, monkeypatch
):
    state = post_acl
    stop_after_core_claim(state)
    replacement = SimpleNamespace(**vars(state.context.proof))
    replacement.fence_id = state.nonce
    replacement.to_document = lambda: {"fence_id": state.nonce}

    def fence(connection, **kwargs):
        assert kwargs["prior"] is state.context.proof
        assert kwargs["expected_prior_fence_id"] == state.context.host_nonce
        assert kwargs["fence_id"] == state.nonce
        state.events.append("rebind")
        return replacement

    monkeypatch.setattr(module.transition_fence, "fence_writers", fence)
    observed = read_json(
        state.host.rebind_post_acl_recovery(state.request, state.nonce, state.context)
    )
    assert observed["kind"] == "post-acl-rebound"
    assert observed["result"] == {
        "prior_fence_id": state.context.host_nonce,
        "fence_id": state.nonce,
        "original_fence_digest": state.request["basis"]["original_fence_digest"],
        "current_fence_digest": state.request["basis"]["current_fence_digest"],
        "measurement": state.measurement,
    }
    assert state.measures == 2
    assert (
        state.events.index("stop")
        < max(i for i, event in enumerate(state.events) if event == "measure")
        < state.events.index("rebind")
    )
    assert state.retained == [canonical_json(replacement.to_document())]
    assert state.host.proof.prior_acl == state.context.original_proof.prior_acl


@pytest.mark.parametrize(
    "field",
    ["stats_reset", "server_start", "relations", "sequences", "catalogue_digest"],
)
def test_post_stop_drift_refuses_before_any_fence_rebind(post_acl, monkeypatch, field):
    state = post_acl
    stop_after_core_claim(state)
    if field == "catalogue_digest":
        state.catalogue = b"post-stop drift"
    else:
        state.measurement = {**state.measurement, field: "post-stop drift"}
    monkeypatch.setattr(
        module.transition_fence,
        "fence_writers",
        lambda *args, **kwargs: pytest.fail("fence mutated"),
    )
    with pytest.raises(ContractError):
        state.host.rebind_post_acl_recovery(state.request, state.nonce, state.context)
    assert not state.retained


def test_rebind_cannot_skip_new_stop_owner(post_acl, monkeypatch):
    state = post_acl
    state.host.inspect_post_acl_recovery(state.request, state.context)
    monkeypatch.setattr(
        module.transition_fence,
        "fence_writers",
        lambda *args, **kwargs: pytest.fail("fence mutated"),
    )
    with pytest.raises(ContractError, match="post_acl_writers_stop_required"):
        state.host.rebind_post_acl_recovery(state.request, state.nonce, state.context)


@pytest.mark.parametrize(
    "running,restarting,live,accepted",
    [
        (False, False, {}, True),
        (True, True, {}, True),
        (True, False, {}, False),
        (
            False,
            False,
            {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8100"}]},  # noqa: S104
            False,
        ),
    ],
)
def test_fenced_lineage_publication_only_allows_genuinely_inactive_empty_bindings(
    post_acl, running, restarting, live, accepted
):
    state = post_acl
    app = state.writers[0]
    app["State"].update(Running=running, Restarting=restarting)
    app["NetworkSettings"]["Ports"] = live
    if accepted:
        state.host.inspect_post_acl_recovery(state.request, state.context)
    else:
        with pytest.raises(ContractError, match="runtime_port_binding_mismatch"):
            state.host.inspect_post_acl_recovery(state.request, state.context)


def test_post_acl_constructor_exclusivity_and_registry_identity(post_acl):
    state = post_acl
    with pytest.raises(ContractError, match="continuation_contexts_mutually_exclusive"):
        module.ExistingCpTransitionHost(
            state.host.config,
            store=state.host.store,
            recovery={},
            failed_candidate_context=state.context.predecessor,
            post_acl_recovery_context=state.context,
        )
    with pytest.raises(ContractError, match="post_acl_context_registry_conflict"):
        module.ExistingCpTransitionHost(
            state.host.config,
            store=state.host.store,
            recovery={},
            post_acl_recovery_context=state.context,
            post_acl_contexts={state.context.context_digest: object()},
        )


def test_post_acl_routing_threads_typed_context_registry(post_acl, monkeypatch):
    state = post_acl
    state.host._request, state.host._nonce = state.request, state.nonce
    receipt = b"retained closed typed receipt"
    forwarded = []
    monkeypatch.setattr(
        module, "verify_any_receipt", lambda raw, **kwargs: forwarded.append(kwargs)
    )
    monkeypatch.setattr(state.host.store, "read", lambda *args, **kwargs: receipt)
    monkeypatch.setattr(state.host, "_full_runtime", lambda request: None)
    monkeypatch.setattr(state.host, "_evidence", lambda *args: b"verified")
    assert state.host.verify_pre_routing(receipt) == b"verified"
    assert forwarded[0]["post_acl_contexts"] == {
        state.context.context_digest: state.context
    }
    assert forwarded[0]["routing_gate"] is True


def test_post_acl_new_candidate_uses_original_recovery_without_rekey(
    post_acl, monkeypatch
):
    state = post_acl
    state.host._request, state.host._nonce = state.request, state.nonce
    monkeypatch.setattr(state.host, "target_heads", lambda *args: b"heads")
    monkeypatch.setattr(state.host, "_quiescence_snapshot", lambda *args: b"snapshot")
    monkeypatch.setattr(state.host, "_retain", lambda *args: "retained")

    def reached_new_candidate(*args):
        raise RuntimeError("fresh candidate materialization")

    monkeypatch.setattr(
        state.host, "_materialize_candidate_environment", reached_new_candidate
    )
    with pytest.raises(RuntimeError, match="fresh candidate materialization"):
        state.host.candidate_ready(state.request, state.nonce)
    assert state.host.recovery == {}


@pytest.mark.parametrize("after_stop", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        "heartbeat_ins",
        "heartbeat_upd",
        "heartbeat_del",
        "business_ins",
        "relation_oid",
        "relation_filenode",
        "sequence",
    ],
)
def test_valid_typed_measurement_drift_has_no_table_or_counter_exceptions(
    post_acl, after_stop, change
):
    state = post_acl
    if after_stop:
        stop_after_core_claim(state)
    state.measurement = deepcopy(state.measurement)
    if change.startswith("heartbeat_"):
        column = {"heartbeat_ins": 4, "heartbeat_upd": 5, "heartbeat_del": 6}[change]
        state.measurement["relations"][0][column] += 1
    elif change == "business_ins":
        state.measurement["relations"][1][4] += 1
    elif change == "relation_oid":
        state.measurement["relations"][0][2] += 1
    elif change == "relation_filenode":
        state.measurement["relations"][0][3] += 1
    else:
        state.measurement["sequences"][0][2] += 1
    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        if after_stop:
            state.host.rebind_post_acl_recovery(
                state.request, state.nonce, state.context
            )
        else:
            state.host.inspect_post_acl_recovery(state.request, state.context)
    assert not state.retained
