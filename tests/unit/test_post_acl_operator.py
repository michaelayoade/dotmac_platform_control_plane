"""Real finite post-ACL loader, canonical ancestry, dispatch and redaction."""

# ruff: noqa: F811 - pytest fixtures intentionally share imported owner names
from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cp_committed_continuation import committed, fresh_store  # noqa: F401
from test_cp_failed_candidate_recovery import (
    RecoveryHost,
    failed,  # noqa: F401
)
from test_cp_post_acl_recovery import sign
from test_cp_transition import request, store, trust  # noqa: F401
from test_failed_candidate_operator import protected_failed, protected_v2  # noqa: F401
from test_transition_operator import document, load  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_operator as op


@pytest.fixture
def protected_post_acl(protected_v2, trust, monkeypatch):
    """Materialize the signed failed V2 attempt via its real suffix executor."""
    p = protected_v2
    predecessor = op._load_failed_candidate_context(p.active)
    prior = copy.deepcopy(p.successor)
    sign(prior, trust, p.predecessor.request_path)
    verifier, request_path = trust[:2]
    now = p.predecessor.now
    latest = fresh_store(predecessor.original, "post-acl-latest")
    host = RecoveryHost(predecessor, latest, fail="full-ready")
    with pytest.raises(RuntimeError, match="full-ready"):
        cp.execute_failed_candidate_recovery(
            canonical_json(prior),
            request_path=request_path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=latest,
            recovery={},
            context=predecessor,
            clock=lambda: now,
        )
    proof = replace(predecessor.proof, fence_id=host.nonce)
    latest.put(canonical_json(proof.to_document()))
    trusted_base = (latest.root.parent / "post-acl-trusted-installations").resolve()
    monkeypatch.setattr(cp, "POST_ACL_INSTALLATION_ROOT", trusted_base)
    operator_root = cp.post_acl_failed_installation_path(prior).parent
    operator_root.mkdir(parents=True)
    latest.root.rename(operator_root / "artifact-store")
    latest.root = operator_root / "artifact-store"
    installation_path = operator_root / "installation.json"
    installation_document = copy.deepcopy(p.installation_document)
    installation_document["failed_candidate_context"] = dict(
        p.active.failed_candidate_context
    )
    installation_document["artifact_directory"] = str(latest.root)
    installation_document["operator_revision"] = prior["operator_revision"]
    failed_installation = replace(
        p.active,
        store=latest,
        failed_candidate_context=installation_document["failed_candidate_context"],
    )
    work = operator_root / (
        f"native-attempt-{prior['authorization_run_id']}-"
        f"{prior['authorization_run_attempt']}"
    )
    stdout, stderr = (
        b'{"synthetic_owner_result":"refused"}',
        b"synthetic private child diagnostics",
    )
    invocation = {
        "status": "ONE_ATTEMPT_STARTED",
        "run_id": prior["authorization_run_id"],
        "started_unix": int(now.timestamp()),
        "request_sha256": cp.request_digest(prior)[7:],
        "bundle_sha256": cp.raw_digest(b"synthetic E4 bundle")[7:],
    }
    result = {
        "status": "OWNER_RETURNED",
        "exit": 3,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": cp.raw_digest(stdout)[7:],
        "stderr_sha256": cp.raw_digest(stderr)[7:],
        "work": str(work),
        "completed_unix": int(now.timestamp()),
    }
    authority_path, context_path = (
        operator_root / "authority.json",
        operator_root / "post-acl-context.json",
    )
    historical_document = {
        **p.historical_document,
        "invocation_file": str(work / "invocation.json"),
        "result_file": str(work / "result.json"),
        "invocation_digest": cp.raw_digest(canonical_json(invocation)),
        "result_digest": cp.raw_digest(canonical_json(result)),
    }
    evidence = {}
    for item in latest.root.glob("*.evidence.json"):
        # The retained verifier report is a JSON array, not a stage envelope.
        value = json.loads(item.read_bytes())
        if (
            isinstance(value, dict)
            and value.get("schema") == "dotmac.cp_transition_evidence/2"
        ):
            evidence[value["kind"]] = cp.raw_digest(item.read_bytes())
    quiescence = cp.read_json(latest.read(evidence["candidate-removed-fenced"]))[
        "result"
    ]["quiescence_digest"]
    (pre_routing,) = latest.root.glob("*.receipt.json")
    spent = predecessor.prior_store.read(
        cp.failed_candidate_frontier_key(predecessor), kind="reservation"
    )
    context_document = {
        "schema": "dotmac.cp_post_acl_recovery_context/1",
        "failed_installation": {
            "path": str(installation_path),
            "digest": cp.raw_digest(canonical_json(installation_document)),
        },
        "request": prior,
        "host_nonce": host.nonce,
        "reservation_digest": cp.raw_digest(
            latest.read(cp.request_digest(prior), kind="reservation")
        ),
        "authorization_verification_digest": cp.read_json(
            latest.read(cp.request_digest(prior), kind="reservation")
        )["verification_digest"],
        "authorization_context": {
            "path": str(authority_path),
            "digest": cp.raw_digest(canonical_json(historical_document)),
        },
        "predecessor_context_digest": predecessor.context_digest,
        "predecessor_frontier_claim_digest": cp.raw_digest(spent),
        "original_context_digest": predecessor.original.context_digest,
        "original_frontier_claim_digest": predecessor.original_frontier_claim_digest,
        "current_fence_digest": proof.digest(),
        "current_fence_id": proof.fence_id,
        "evidence": evidence,
        "quiescence_digest": quiescence,
        "inventory": {
            item.name: cp.raw_digest(item.read_bytes())
            for item in latest.root.iterdir()
        },
        "pre_routing_receipt_digest": cp.raw_digest(pre_routing.read_bytes()),
    }
    p.reads.update(
        {
            installation_path: canonical_json(installation_document),
            authority_path: canonical_json(historical_document),
            context_path: canonical_json(context_document),
            work / "invocation.json": canonical_json(invocation),
            work / "result.json": canonical_json(result),
            work / "request.json": canonical_json(prior),
            work / "bundle.json": b"synthetic E4 bundle",
            work / "stdout.json": stdout,
            work / "stderr.log": stderr,
        }
    )
    active = replace(
        p.active,
        store=fresh_store(predecessor.original, "post-acl-current"),
        failed_candidate_context=None,
        post_acl_recovery_context={
            "path": str(context_path),
            "digest": cp.raw_digest(p.reads[context_path]),
        },
    )
    original_load = op.load_installation
    config_path = Path("/opt/current/post-acl-installation.json")
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: (
            failed_installation
            if path == installation_path
            else active
            if path == config_path
            else original_load(path)
        ),
    )
    loaded = op._load_post_acl_recovery_context(active)
    successor = copy.deepcopy(prior)
    successor.update(
        schema="dotmac.cp_post_acl_recovery_request/1",
        authorization_run_id=901,
        basis=cp.post_acl_recovery_basis(loaded),
    )
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    p.reads[request_path] = canonical_json(successor)
    return SimpleNamespace(
        active=active,
        failed_installation=failed_installation,
        document=context_document,
        installation_document=installation_document,
        historical_document=historical_document,
        invocation=invocation,
        result=result,
        work=work,
        reads=p.reads,
        path=context_path,
        authority_path=authority_path,
        installation_path=installation_path,
        request_path=request_path,
        config_path=config_path,
        successor=successor,
        predecessor=p,
        loaded=loaded,
        now=now,
    )


def repin(p):
    p.reads[p.installation_path] = canonical_json(p.installation_document)
    p.document["failed_installation"]["digest"] = cp.raw_digest(
        p.reads[p.installation_path]
    )
    p.reads[p.work / "invocation.json"] = canonical_json(p.invocation)
    p.reads[p.work / "result.json"] = canonical_json(p.result)
    p.historical_document["invocation_digest"] = cp.raw_digest(
        p.reads[p.work / "invocation.json"]
    )
    p.historical_document["result_digest"] = cp.raw_digest(
        p.reads[p.work / "result.json"]
    )
    p.reads[p.authority_path] = canonical_json(p.historical_document)
    p.document["authorization_context"]["digest"] = cp.raw_digest(
        p.reads[p.authority_path]
    )
    p.reads[p.path] = canonical_json(p.document)
    return replace(
        p.active,
        post_acl_recovery_context={
            "path": str(p.path),
            "digest": cp.raw_digest(p.reads[p.path]),
        },
    )


def test_real_loader_accepts_actual_hashed_result_and_exact_fifteen_records(
    protected_post_acl,
):
    p = protected_post_acl
    loaded = op._load_post_acl_recovery_context(p.active)
    assert type(loaded) is cp.PostAclRecoveryContext
    assert type(loaded.predecessor) is cp.FailedCandidateContextV2
    assert type(loaded.predecessor.predecessor) is cp.FailedCandidateContext
    assert loaded.prior_store is p.failed_installation.store
    assert len(loaded.inventory) == 15
    loaded.historical_authorization.verify(loaded.request)
    cp.verify_post_acl_recovery_frontier(loaded, p.successor)
    assert loaded.historical_authorization.execution_window_start == p.now
    assert loaded.historical_authorization.execution_window_end == p.now


@pytest.mark.parametrize(
    "mutation",
    [
        "stdout-hash",
        "stderr-hash",
        "stdout-length",
        "stderr-length",
        "stdout-bytes",
        "stderr-bytes",
        "work",
        "window",
        "run",
        "request",
        "bundle",
        "trust",
        "operator",
        "identity",
        "predecessor-version",
        "predecessor-pin",
        "reservation",
        "authorization",
        "fence",
        "receipt",
        "unknown-context",
        "unknown-result",
    ],
)
def test_repinning_cannot_authorize_crossed_historical_inputs(
    protected_post_acl, mutation
):
    p = protected_post_acl
    if mutation.endswith("-hash"):
        p.result[mutation.split("-")[0] + "_sha256"] = "f" * 64
    elif mutation.endswith("-length"):
        p.result[mutation.split("-")[0] + "_bytes"] += 1
    elif mutation.endswith("-bytes"):
        p.reads[
            p.work / ("stdout.json" if mutation.startswith("stdout") else "stderr.log")
        ] += b"changed"
    elif mutation == "work":
        p.result["work"] += "-crossed"
    elif mutation == "window":
        p.invocation["started_unix"] -= 25 * 3600
    elif mutation == "run":
        p.invocation["run_id"] += 1
    elif mutation in {"request", "bundle"}:
        p.reads[p.work / (mutation + ".json")] += b"changed"
    elif mutation == "trust":
        p.historical_document["trust"] = {
            **p.historical_document["trust"],
            "workflow_revision": "a" * 40,
        }
    elif mutation == "operator":
        p.document["request"] = {**p.document["request"], "operator_revision": "a" * 40}
    elif mutation == "identity":
        p.document["request"] = {**p.document["request"], "database_oid": 99999}
    elif mutation == "predecessor-version":
        p.reads[p.predecessor.path] = canonical_json(
            {**p.predecessor.document, "schema": "dotmac.cp_failed_candidate_context/1"}
        )
    elif mutation == "predecessor-pin":
        p.document["predecessor_context_digest"] = "sha256:" + "f" * 64
    elif mutation == "reservation":
        p.document["reservation_digest"] = "sha256:" + "f" * 64
    elif mutation == "authorization":
        p.document["authorization_verification_digest"] = "sha256:" + "f" * 64
    elif mutation == "fence":
        p.document["current_fence_id"] = "f" * 64
    elif mutation == "receipt":
        p.document["pre_routing_receipt_digest"] = p.document["evidence"][
            "acl-restored"
        ]
    elif mutation == "unknown-context":
        p.document["unknown"] = True
    else:
        p.result["unknown"] = True
    active = repin(p)
    with pytest.raises((ContractError, FileNotFoundError)):
        loaded = op._load_post_acl_recovery_context(active)
        value = copy.deepcopy(p.successor)
        value["basis"] = cp.post_acl_recovery_basis(loaded)
        value["plan_digest"] = cp.transition_plan_digest(value)
        cp.verify_post_acl_recovery_frontier(loaded, value)


@pytest.mark.parametrize(
    "kind",
    ["committed_migration_context", "held_fence_context", "post_acl_recovery_context"],
)
def test_failed_installation_cannot_select_another_protocol(protected_post_acl, kind):
    p = protected_post_acl
    p.installation_document[kind] = {
        "path": "/opt/crossed/context.json",
        "digest": "sha256:" + "f" * 64,
    }
    with pytest.raises(ContractError, match="post_acl_predecessor_kind"):
        op._load_post_acl_recovery_context(repin(p))


def test_legacy_result_contract_rejects_new_hash_fields(protected_post_acl):
    p = protected_post_acl
    with pytest.raises(ContractError):
        cp._shape(p.result, op.OriginalResultV1)
    cp._shape(p.result, op.OriginalHashedResultV1)


def test_only_post_acl_executor_receives_shared_original_registries(
    protected_post_acl, monkeypatch
):
    p = protected_post_acl
    monkeypatch.setattr(op, "_load_recovery", lambda installed, **kwargs: {})
    calls = {}

    def host(config, **kwargs):
        calls["host"] = kwargs
        return SimpleNamespace()

    def execute(raw, **kwargs):
        assert cp.read_json(raw) == p.successor
        calls["execute"] = kwargs
        return "sha256:" + "d" * 64

    def forbidden(*args, **kwargs):
        pytest.fail("a different transition owner was called")

    from vendor_cp.deployment import cp_transition_host

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", host)
    monkeypatch.setattr(cp, "execute_post_acl_recovery", execute)
    for name in (
        "execute_transition",
        "execute_committed_continuation",
        "execute_failed_candidate_recovery",
    ):
        monkeypatch.setattr(cp, name, forbidden)
    assert (
        op.run_transition(config_file=p.config_path, request_file=p.request_path)
        == "sha256:" + "d" * 64
    )
    args, host_args = calls["execute"], calls["host"]
    loaded = args["context"]
    assert host_args["post_acl_recovery_context"] is loaded
    assert args["post_acl_contexts"] == {loaded.context_digest: loaded}
    assert args["committed_contexts"] == {
        loaded.original.context_digest: loaded.original
    }
    assert args["failed_candidate_contexts"] == {
        loaded.predecessor.context_digest: loaded.predecessor,
        loaded.predecessor.predecessor.context_digest: loaded.predecessor.predecessor,
    }
    assert loaded.predecessor.original is loaded.original
    assert loaded.predecessor.predecessor.original is loaded.original
    for key in ("post_acl_contexts", "committed_contexts", "failed_candidate_contexts"):
        assert host_args[key] is args[key]
    assert args["store"] is p.active.store
    assert args["recovery"] == dict(loaded.original.recovery)


def test_wrong_operator_refuses_before_host_or_executor(
    protected_post_acl, monkeypatch
):
    p = protected_post_acl
    original_load = op.load_installation
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: (
            replace(p.active, operator_revision="a" * 40)
            if path == p.config_path
            else original_load(path)
        ),
    )
    from vendor_cp.deployment import cp_transition_host

    def forbidden(*args, **kwargs):
        pytest.fail("host or executor constructed before operator admission")

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", forbidden)
    monkeypatch.setattr(cp, "execute_post_acl_recovery", forbidden)
    with pytest.raises(op.TransitionOperatorRefused):
        op.run_transition(config_file=p.config_path, request_file=p.request_path)
    assert list(p.active.store.root.iterdir()) == []


@pytest.mark.parametrize(
    "phase",
    [
        *op.RuntimeReadinessPhase,
        None,
        "postgresql://NEVER_ECHO",
        "compose_launch",
        {},
        1,
    ],
)
def test_cli_runtime_phase_is_closed_and_private_messages_are_redacted(
    monkeypatch, capsys, phase
):
    from vendor_cp.cli import main

    def denied(**kwargs):
        error = op.TransitionOperatorRefused("NEVER_ECHO_EXCEPTION")
        error.runtime_phase = phase
        raise error

    monkeypatch.setattr(op, "run_transition", denied)
    assert (
        main(
            [
                "--format",
                "json",
                "admin",
                "cp-transition",
                "--config-file",
                "/config",
                "--request-file",
                "/request",
            ]
        )
        == 3
    )
    output = capsys.readouterr()
    assert "NEVER_ECHO" not in output.out + output.err
    message = "CP_TRANSITION_REFUSED"
    if type(phase) is op.RuntimeReadinessPhase:
        message += f" runtime_phase={phase.value}"
    assert json.loads(output.out)["message"] == message


@pytest.mark.parametrize(
    "other",
    ["failed_candidate_context", "committed_migration_context", "held_fence_context"],
)
def test_active_installation_context_pins_are_mutually_exclusive(load, other):
    value = document()
    value["operator_revision"] = "f" * 40
    pins = {"path": "/opt/current/context.json", "digest": "sha256:" + "a" * 64}
    value["post_acl_recovery_context"] = pins
    value[other] = pins
    with pytest.raises(ContractError):
        load(value)


@pytest.mark.parametrize(
    "alias", ["active", "predecessor", "original", "renamed-owner"]
)
def test_canonical_store_and_owner_cannot_be_aliased(
    protected_post_acl, monkeypatch, alias
):
    p = protected_post_acl
    if alias == "renamed-owner":
        crossed = p.installation_path.with_name("renamed.json")
        p.reads[crossed] = p.reads[p.installation_path]
        p.document["failed_installation"]["path"] = str(crossed)
        active = repin(p)
    else:
        chosen = {
            "active": p.active.store,
            "predecessor": p.loaded.predecessor.prior_store,
            "original": p.loaded.original.prior_store,
        }[alias]
        original_load = op.load_installation
        monkeypatch.setattr(
            op,
            "load_installation",
            lambda path: (
                replace(p.failed_installation, store=chosen)
                if path == p.installation_path
                else original_load(path)
            ),
        )
        active = p.active
    with pytest.raises(ContractError):
        op._load_post_acl_recovery_context(active)


def test_repinned_clone_of_failed_installation_store_and_execution_is_refused(
    protected_post_acl, monkeypatch
):
    p = protected_post_acl
    copied_owner = p.installation_path.parent.parent / "repinned-copied-owner"
    copied_store = copied_owner / "artifact-store"
    shutil.copytree(p.failed_installation.store.root, copied_store)
    assert len(list(copied_store.iterdir())) == 15
    copied_installation_path = copied_owner / "installation.json"
    installation_document = copy.deepcopy(p.installation_document)
    installation_document["artifact_directory"] = str(copied_store)
    copied_work = copied_owner / p.work.name
    for name in ("request.json", "bundle.json", "stdout.json", "stderr.log"):
        p.reads[copied_work / name] = p.reads[p.work / name]
    invocation = copy.deepcopy(p.invocation)
    result = {**p.result, "work": str(copied_work)}
    p.reads[copied_work / "invocation.json"] = canonical_json(invocation)
    p.reads[copied_work / "result.json"] = canonical_json(result)
    authority_path = copied_owner / "authority.json"
    authority = {
        **p.historical_document,
        "invocation_file": str(copied_work / "invocation.json"),
        "result_file": str(copied_work / "result.json"),
        "invocation_digest": cp.raw_digest(p.reads[copied_work / "invocation.json"]),
        "result_digest": cp.raw_digest(p.reads[copied_work / "result.json"]),
    }
    p.reads[authority_path] = canonical_json(authority)
    p.reads[copied_installation_path] = canonical_json(installation_document)
    document = {
        **p.document,
        "failed_installation": {
            "path": str(copied_installation_path),
            "digest": cp.raw_digest(p.reads[copied_installation_path]),
        },
        "authorization_context": {
            "path": str(authority_path),
            "digest": cp.raw_digest(p.reads[authority_path]),
        },
    }
    context_path = copied_owner / "context.json"
    p.reads[context_path] = canonical_json(document)
    active = replace(
        p.active,
        post_acl_recovery_context={
            "path": str(context_path),
            "digest": cp.raw_digest(p.reads[context_path]),
        },
    )
    original_load = op.load_installation

    def cannot_select_copied_owner(path):
        if path == copied_installation_path:
            pytest.fail("copied failed owner selected before canonical path admission")
        return original_load(path)

    monkeypatch.setattr(op, "load_installation", cannot_select_copied_owner)
    with pytest.raises(ContractError, match="post_acl_failed_owner_path_mismatch"):
        op._load_post_acl_recovery_context(active)
