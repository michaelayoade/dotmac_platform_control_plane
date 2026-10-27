"""Protected successor loader and routing; existing Installation parsing is reused.

The canonical Installation loader and original committed loader are boundary
fixtures here. New context, invocation and historical-authorization decisions
execute their real owners over the producer-shaped failed-attempt fixture.
"""

# ruff: noqa: F811 - fixtures intentionally share imported owner names
from __future__ import annotations

import copy
import shutil
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cp_committed_continuation import committed  # noqa: F401
from test_cp_failed_candidate_recovery import (
    failed,  # noqa: F401
    make_failed_v1,
    run_recovery,
)
from test_cp_transition import NOW, request, store, trust  # noqa: F401
from test_transition_operator import document, load  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_operator as op
from vendor_cp.deployment.transition_fence import FenceRefused


@pytest.fixture
def protected_failed(failed, monkeypatch):
    context, successor, now, verifier, request_path = failed

    class FixtureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    # Keep the real request expiry guard deterministic at this fixture's window.
    monkeypatch.setattr(op, "datetime", FixtureClock)
    canonical_operator_root = context.prior_store.root.parent / "failed-operator"
    canonical_operator_root.mkdir()
    canonical_store = canonical_operator_root / "artifact-store"
    context.prior_store.root.rename(canonical_store)
    context.prior_store.root = canonical_store
    failed_path = canonical_operator_root / "installation.json"
    run_id = context.request["authorization_run_id"]
    run_attempt = context.request["authorization_run_attempt"]
    work = failed_path.parent / f"native-attempt-{run_id}-{run_attempt}"
    installation_document = document()
    installation_document["committed_migration_context"] = {
        "path": "/opt/original/context.json",
        "digest": context.original.context_digest,
    }
    installation_document["operator_revision"] = context.request["operator_revision"]
    installation_document["artifact_directory"] = str(context.prior_store.root)
    policy = context.historical_authorization.policy
    trust_document = installation_document["trust"]
    for key in trust_document:
        item = getattr(policy, key)
        trust_document[key] = str(item) if isinstance(item, Path) else item
    installation_document["identity"] = {
        name: getattr(policy.identity, name)
        for name in installation_document["identity"]
    }
    failed_installation = op.Installation(
        policy,
        SimpleNamespace(),
        context.prior_store,
        (),
        committed_migration_context=installation_document[
            "committed_migration_context"
        ],
        operator_revision=context.request["operator_revision"],
    )
    invocation = {
        "status": "ONE_ATTEMPT_STARTED",
        "run_id": context.request["authorization_run_id"],
        "started_unix": int(now.timestamp()),
        "request_sha256": cp.request_digest(context.request)[7:],
        "bundle_sha256": cp.raw_digest(b"synthetic bundle")[7:],
    }
    result = {
        "status": "OWNER_RETURNED",
        "exit": 3,
        "stdout_bytes": 201,
        "stderr_bytes": 200,
        "work": str(work),
        "completed_unix": int(now.timestamp()),
    }
    historical_document = {
        "schema": "dotmac.cp_historical_authorization_context/1",
        "trust": copy.deepcopy(trust_document),
        "request_name": "request.json",
        "invocation_file": str(work / "invocation.json"),
        "invocation_digest": cp.raw_digest(canonical_json(invocation)),
        "result_file": str(work / "result.json"),
        "result_digest": cp.raw_digest(canonical_json(result)),
    }
    context_path, authority_path = (
        Path("/opt/current/failed.json"),
        Path("/opt/current/authority.json"),
    )
    context_document = {
        "schema": "dotmac.cp_failed_candidate_context/1",
        "failed_installation": {
            "path": str(failed_path),
            "digest": cp.raw_digest(canonical_json(installation_document)),
        },
        "request": context.request,
        "host_nonce": context.host_nonce,
        "reservation_digest": cp.raw_digest(
            context.prior_store.read(
                cp.request_digest(context.request), kind="reservation"
            )
        ),
        "authorization_verification_digest": cp.raw_digest(
            context.historical_authorization.verification_bytes
        ),
        "authorization_context": {
            "path": str(authority_path),
            "digest": cp.raw_digest(canonical_json(historical_document)),
        },
        "original_context_digest": context.original.context_digest,
        "original_frontier_claim_digest": context.original_frontier_claim_digest,
        "current_fence_digest": context.proof.digest(),
        "current_fence_id": context.proof.fence_id,
        "evidence": dict(context.evidence),
        "quiescence_digest": context.quiescence_digest,
        "inventory": dict(context.inventory),
    }
    fresh_root = context.prior_store.root.parent / "operator-fresh"
    fresh_root.mkdir()
    active = op.Installation(
        verifier.policy,
        SimpleNamespace(),
        cp.ArtifactStore(fresh_root),
        (),
        operator_revision=successor["operator_revision"],
        failed_candidate_context={
            "path": str(context_path),
            "digest": cp.raw_digest(canonical_json(context_document)),
        },
    )
    reads = {
        failed_path: canonical_json(installation_document),
        context_path: canonical_json(context_document),
        authority_path: canonical_json(historical_document),
        work / "invocation.json": canonical_json(invocation),
        work / "result.json": canonical_json(result),
        work / "request.json": canonical_json(context.request),
        work / "bundle.json": b"synthetic bundle",
    }
    original_read = cp._read_protected
    monkeypatch.setattr(
        cp,
        "_read_protected",
        lambda path: reads[path] if path in reads else original_read(path),
    )
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: failed_installation if path == failed_path else active,
    )
    monkeypatch.setattr(
        op, "_load_committed_context", lambda installed: context.original
    )
    return SimpleNamespace(
        context=context,
        successor=successor,
        active=active,
        failed_installation=failed_installation,
        document=context_document,
        installation_document=installation_document,
        historical_document=historical_document,
        invocation=invocation,
        result=result,
        reads=reads,
        path=context_path,
        authority_path=authority_path,
        failed_path=failed_path,
        work=work,
        request_path=request_path,
        now=now,
    )


def repin(p):
    p.reads[p.failed_path] = canonical_json(p.installation_document)
    p.document["failed_installation"]["digest"] = cp.raw_digest(p.reads[p.failed_path])
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
        failed_candidate_context={
            "path": str(p.path),
            "digest": cp.raw_digest(p.reads[p.path]),
        },
    )


def test_failed_loader_derives_spent_store_and_real_historical_authority(
    protected_failed,
):
    p = protected_failed
    loaded = op._load_failed_candidate_context(p.active)
    assert loaded.prior_store is p.failed_installation.store
    assert loaded.original is p.context.original
    assert loaded.request == p.context.request
    assert isinstance(
        loaded.historical_authorization, cp.HistoricalCommittedAuthorization
    )
    assert not isinstance(loaded.historical_authorization, cp.VerifiedAuthorization)
    loaded.historical_authorization.verify(loaded.request)
    assert loaded.historical_authorization.execution_window_start == p.now
    assert loaded.historical_authorization.execution_window_end == p.now


@pytest.mark.parametrize(
    "mutation",
    [
        "context_pin",
        "installation_pin",
        "original_pin",
        "reservation_pin",
        "authority_pin",
        "proof_pin",
        "fence_id",
        "caller_store",
        "successor_request",
        "inventory_path",
        "inventory_receipt",
        "unknown_field",
    ],
)
def test_failed_context_pins_and_closed_shapes(protected_failed, mutation):
    p = protected_failed
    if mutation == "context_pin":
        p.reads[p.path] += b" "
    elif mutation == "installation_pin":
        p.reads[p.failed_path] += b" "
    elif mutation == "original_pin":
        p.document["original_context_digest"] = "sha256:" + "d" * 64
    elif mutation == "reservation_pin":
        p.document["reservation_digest"] = "sha256:" + "d" * 64
    elif mutation == "authority_pin":
        p.document["authorization_context"]["digest"] = "sha256:" + "d" * 64
    elif mutation == "proof_pin":
        p.document["current_fence_digest"] = p.context.evidence["failure"]
    elif mutation == "fence_id":
        p.document["current_fence_id"] = "d" * 64
    elif mutation == "caller_store":
        p.document["prior_artifact_directory"] = "/opt/attacker/store"
    elif mutation == "successor_request":
        p.document["request"] = p.successor
    elif mutation.startswith("inventory"):
        p.document["inventory"][
            "../escape" if mutation == "inventory_path" else "d" * 64 + ".receipt.json"
        ] = "sha256:" + "d" * 64
    else:
        p.document["unknown"] = True
    if mutation not in {"context_pin", "installation_pin"}:
        p.reads[p.path] = canonical_json(p.document)
        p.active = replace(
            p.active,
            failed_candidate_context={
                "path": str(p.path),
                "digest": cp.raw_digest(p.reads[p.path]),
            },
        )
    with pytest.raises((ContractError, FileNotFoundError, FenceRefused)):
        op._load_failed_candidate_context(p.active)


@pytest.mark.parametrize("mutation", ["missing_committed", "held", "second_generation"])
def test_failed_installation_must_be_only_committed_predecessor(
    protected_failed, mutation
):
    p = protected_failed
    if mutation == "missing_committed":
        del p.installation_document["committed_migration_context"]
    elif mutation == "held":
        p.installation_document["held_fence_context"] = {
            "path": "/opt/held",
            "digest": "sha256:" + "d" * 64,
            "proof_digest": "sha256:" + "d" * 64,
            "fence_id": "d" * 64,
        }
    else:
        p.installation_document["failed_candidate_context"] = {
            "path": "/opt/failed",
            "digest": "sha256:" + "d" * 64,
        }
    with pytest.raises(ContractError, match="failed_candidate_predecessor_kind"):
        op._load_failed_candidate_context(repin(p))


@pytest.mark.parametrize(
    "mutation",
    [
        "trust",
        "subject",
        "invocation_path",
        "result_path",
        "run",
        "request_digest",
        "request_bytes",
        "bundle_digest",
        "bundle_bytes",
        "work",
        "negative_stdout",
        "negative_stderr",
        "reversed_window",
        "expired_window",
        "invocation_pin",
        "result_pin",
    ],
)
def test_failed_historical_authority_is_bound_to_invocation_and_inputs(
    protected_failed, mutation
):
    p = protected_failed
    if mutation == "trust":
        p.historical_document["trust"]["repository_id"] = "99999"
    elif mutation == "subject":
        p.historical_document["request_name"] = "other.json"
    elif mutation in {"invocation_path", "result_path"}:
        p.historical_document[mutation.replace("_path", "_file")] = (
            "/opt/other/" + mutation + ".json"
        )
    elif mutation == "run":
        p.invocation["run_id"] += 1
    elif mutation == "request_digest":
        p.invocation["request_sha256"] = "d" * 64
    elif mutation == "request_bytes":
        p.reads[p.work / "request.json"] += b" "
    elif mutation == "bundle_digest":
        p.invocation["bundle_sha256"] = "d" * 64
    elif mutation == "bundle_bytes":
        p.reads[p.work / "bundle.json"] += b" "
    elif mutation == "work":
        p.result["work"] = "/opt/caller-selected"
    elif mutation == "negative_stdout":
        p.result["stdout_bytes"] = -1
    elif mutation == "negative_stderr":
        p.result["stderr_bytes"] = -1
    elif mutation == "reversed_window":
        p.result["completed_unix"] -= 1
    elif mutation == "expired_window":
        p.result["completed_unix"] += 86400 * 3
    active = repin(p)
    if mutation in {"invocation_pin", "result_pin"}:
        p.reads[p.work / (mutation.removesuffix("_pin") + ".json")] += b" "
    with pytest.raises(ContractError):
        op._load_failed_candidate_context(active)


@pytest.mark.parametrize(
    "alias", ["failed_current", "original_current", "original_failed"]
)
def test_loader_refuses_same_store_aliases(protected_failed, monkeypatch, alias):
    p = protected_failed
    active = p.active
    if alias == "failed_current":
        active = replace(active, store=p.failed_installation.store)
    else:
        original = replace(
            p.context.original,
            prior_store=p.active.store
            if alias == "original_current"
            else p.failed_installation.store,
        )
        monkeypatch.setattr(op, "_load_committed_context", lambda installed: original)
    with pytest.raises(ContractError, match="recovery_store_reused"):
        op._load_failed_candidate_context(active)


@pytest.mark.parametrize(
    "mutation", ["identity", "operator_revision", "issuer_revision"]
)
def test_loader_binds_failed_identity_and_operator_issuer(
    protected_failed, monkeypatch, mutation
):
    p = protected_failed
    failed_installation = p.failed_installation
    if mutation == "identity":
        failed_installation = replace(
            failed_installation,
            policy=replace(
                failed_installation.policy,
                identity=replace(
                    failed_installation.policy.identity, database_oid=99999
                ),
            ),
        )
    elif mutation == "operator_revision":
        failed_installation = replace(failed_installation, operator_revision="d" * 40)
    else:
        failed_installation = replace(
            failed_installation,
            policy=replace(failed_installation.policy, workflow_revision="d" * 40),
        )
    monkeypatch.setattr(op, "load_installation", lambda path: failed_installation)
    with pytest.raises(ContractError, match="historical_identity_mismatch"):
        op._load_failed_candidate_context(p.active)


def test_active_installation_requires_operator_pin_and_excludes_conflicting_contexts(
    load,
):
    value = document()
    value["failed_candidate_context"] = {
        "path": "/opt/current/failed.json",
        "digest": "sha256:" + "d" * 64,
    }
    with pytest.raises(ContractError, match="operator_revision_required"):
        load(value)
    value["operator_revision"] = "f" * 40
    installed = load(value)
    assert installed.failed_candidate_context == value["failed_candidate_context"]
    value["committed_migration_context"] = {
        "path": "/opt/committed",
        "digest": "sha256:" + "d" * 64,
    }
    with pytest.raises(ContractError, match="contexts_conflict"):
        load(value)
    del value["committed_migration_context"]
    value["held_fence_context"] = {
        "path": "/opt/held",
        "digest": "sha256:" + "d" * 64,
        "proof_digest": "sha256:" + "d" * 64,
        "fence_id": "d" * 64,
    }
    with pytest.raises(ContractError, match="contexts_conflict"):
        load(value)


def test_successor_dispatch_uses_only_new_executor_and_exact_context_maps(
    protected_failed, monkeypatch
):
    p = protected_failed
    value = copy.deepcopy(p.successor)
    value["basis"]["context_digest"] = p.active.failed_candidate_context["digest"]
    value["plan_digest"] = cp.transition_plan_digest(value)
    p.reads[p.request_path] = canonical_json(value)
    monkeypatch.setattr(op, "_load_recovery", lambda installed, **kwargs: {})
    calls = {}

    def host(config, **kwargs):
        calls["host"] = kwargs
        return SimpleNamespace()

    def execute(raw, **kwargs):
        calls["execute"] = kwargs
        assert cp.read_json(raw) == value
        return "sha256:" + "d" * 64

    def forbidden(*args, **kwargs):
        pytest.fail("a different transition executor was called")

    from vendor_cp.deployment import cp_transition_host

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", host)
    monkeypatch.setattr(cp, "execute_failed_candidate_recovery", execute)
    monkeypatch.setattr(cp, "execute_transition", forbidden)
    monkeypatch.setattr(cp, "execute_committed_continuation", forbidden)
    assert (
        op.run_transition(
            config_file=Path("/opt/current/install.json"), request_file=p.request_path
        )
        == "sha256:" + "d" * 64
    )
    execute_args, host_args = calls["execute"], calls["host"]
    loaded = execute_args["context"]
    assert host_args["failed_candidate_context"] is loaded
    assert execute_args["committed_contexts"] == {
        loaded.original.context_digest: loaded.original
    }
    assert execute_args["failed_candidate_contexts"] == {loaded.context_digest: loaded}
    assert host_args["committed_contexts"] is execute_args["committed_contexts"]
    assert (
        host_args["failed_candidate_contexts"]
        is execute_args["failed_candidate_contexts"]
    )
    assert execute_args["recovery"] == dict(p.context.original.recovery)
    assert execute_args["store"] is p.active.store


def test_dispatch_refuses_wrong_current_operator_before_host_or_executor(
    protected_failed, monkeypatch
):
    p = protected_failed
    p.reads[p.request_path] = canonical_json(p.successor)
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: replace(p.active, operator_revision="d" * 40),
    )
    monkeypatch.setattr(op, "_load_recovery", lambda installed, **kwargs: {})
    with pytest.raises(op.TransitionOperatorRefused):
        op.run_transition(
            config_file=Path("/opt/current/install.json"), request_file=p.request_path
        )
    assert list(p.active.store.root.iterdir()) == []


def test_future_v1_loads_real_successor_history_and_forwards_both_registries(
    protected_failed, failed, monkeypatch
):
    p = protected_failed
    context, successor, *_ = failed
    fresh, host, receipt_digest = run_recovery(failed)
    history_path = Path("/opt/future/history.json")
    p.reads[history_path] = canonical_json(
        {
            "schema": "dotmac.cp_failed_candidate_recovery_context/1",
            "receipt_digest": receipt_digest,
            "failed_candidate_context": {
                "path": str(p.path),
                "digest": context.context_digest,
            },
        }
    )
    active = replace(
        p.active,
        store=fresh,
        historical_context_files=(history_path,),
        failed_candidate_context=None,
    )
    monkeypatch.setattr(op, "load_installation", lambda path: active)
    monkeypatch.setattr(
        op, "_load_failed_candidate_context", lambda installed, pins=None: context
    )
    following = request()
    following["source"] = successor["target"]
    following["target"] = context.original.request["source"]
    following["expires_at"] = successor["expires_at"]
    following["previous_receipt_digest"] = receipt_digest
    following["plan_digest"] = cp.transition_plan_digest(following)
    p.reads[p.request_path] = canonical_json(following)
    calls = {}
    from vendor_cp.deployment import cp_transition_host

    monkeypatch.setattr(
        cp_transition_host,
        "ExistingCpTransitionHost",
        lambda config, **kwargs: calls.setdefault("host", kwargs),
    )

    def execute(raw, **kwargs):
        calls["execute"] = kwargs
        return "sha256:" + "e" * 64

    monkeypatch.setattr(cp, "execute_transition", execute)
    assert (
        op.run_transition(
            config_file=Path("/opt/future/install.json"), request_file=p.request_path
        )
        == "sha256:" + "e" * 64
    )
    args = calls["execute"]
    assert args["failed_candidate_contexts"] == {context.context_digest: context}
    assert args["committed_contexts"] == {
        context.original.context_digest: context.original
    }
    assert args["recovery"] == dict(context.original.recovery)
    assert len(args["recovery"]) == 1
    assert (
        calls["host"]["failed_candidate_contexts"] is args["failed_candidate_contexts"]
    )
    assert calls["host"]["committed_contexts"] is args["committed_contexts"]
    contexts, recovery = args["committed_contexts"], args["recovery"]
    assert (
        op._register_original_context(contexts, recovery, replace(context.original))
        is context.original
    )
    assert len(recovery) == 1


def test_shared_original_registration_rejects_conflicting_authority(protected_failed):
    original = protected_failed.context.original
    contexts, recovery = {}, {}
    op._register_original_context(contexts, recovery, original)
    changed = replace(
        original,
        historical_authorization=replace(
            original.historical_authorization, context_digest="sha256:" + "d" * 64
        ),
    )
    with pytest.raises(ContractError, match="conflicting_historical_recovery"):
        op._register_original_context(contexts, recovery, changed)


def test_renamed_installation_under_same_historical_parent_is_refused(protected_failed):
    p = protected_failed
    alias = p.failed_path.with_name("alias-installation.json")
    p.reads[alias] = p.reads[p.failed_path]
    p.document["failed_installation"]["path"] = str(alias)
    # Repinning the whole protected context cannot choose another filename.
    active = repin(p)
    with pytest.raises(ContractError, match="failed_installation_path_mismatch"):
        op._load_failed_candidate_context(active)


def test_same_parent_installation_cannot_choose_copied_spent_store(
    protected_failed, monkeypatch
):
    p = protected_failed
    copied_root = p.failed_path.parent / "copied-artifact-store"
    shutil.copytree(p.context.prior_store.root, copied_root)
    assert {
        item.name: cp.raw_digest(item.read_bytes()) for item in copied_root.iterdir()
    } == dict(p.context.inventory)
    p.installation_document["artifact_directory"] = str(copied_root)
    active = repin(p)
    copied_installation = replace(
        p.failed_installation, store=cp.ArtifactStore(copied_root)
    )
    monkeypatch.setattr(op, "load_installation", lambda path: copied_installation)
    with pytest.raises(
        ContractError, match="failed_candidate_canonical_store_mismatch"
    ):
        op._load_failed_candidate_context(active)


@pytest.fixture
def protected_v2(protected_failed, trust, monkeypatch):
    """Real loader path for both generations and actual-schema authorization."""
    p = protected_failed
    predecessor = op._load_failed_candidate_context(p.active)
    prior = copy.deepcopy(p.successor)
    prior["basis"]["context_digest"] = predecessor.context_digest
    prior["plan_digest"] = cp.transition_plan_digest(prior)
    context, successor, now, verifier, request_path = make_failed_v1(
        (predecessor, prior, p.now, trust[0], p.request_path), trust
    )
    operator_root = context.prior_store.root.parent / "latest-operator"
    operator_root.mkdir()
    canonical_store = operator_root / "artifact-store"
    context.prior_store.root.rename(canonical_store)
    context.prior_store.root = canonical_store
    installation_path = operator_root / "installation.json"
    installation_document = copy.deepcopy(p.installation_document)
    installation_document.pop("committed_migration_context")
    installation_document["failed_candidate_context"] = dict(
        p.active.failed_candidate_context
    )
    installation_document["artifact_directory"] = str(canonical_store)
    installation_document["operator_revision"] = context.request["operator_revision"]
    latest_installation = op.Installation(
        verifier.policy,
        SimpleNamespace(),
        context.prior_store,
        (),
        operator_revision=context.request["operator_revision"],
        failed_candidate_context=installation_document["failed_candidate_context"],
    )
    work = operator_root / (
        f"native-attempt-{context.request['authorization_run_id']}-"
        f"{context.request['authorization_run_attempt']}"
    )
    invocation = {
        "status": "ONE_ATTEMPT_STARTED",
        "run_id": context.request["authorization_run_id"],
        "started_unix": int(now.timestamp()),
        "request_sha256": cp.request_digest(context.request)[7:],
        "bundle_sha256": cp.raw_digest(b"synthetic bundle")[7:],
    }
    result = {**p.result, "work": str(work), "completed_unix": int(now.timestamp())}
    authority_path = operator_root / "authorization.json"
    historical_document = {
        **p.historical_document,
        "invocation_file": str(work / "invocation.json"),
        "result_file": str(work / "result.json"),
        "invocation_digest": cp.raw_digest(canonical_json(invocation)),
        "result_digest": cp.raw_digest(canonical_json(result)),
    }
    context_path = operator_root / "v2-context.json"
    context_document = {
        "schema": "dotmac.cp_failed_candidate_context/2",
        "failed_installation": {
            "path": str(installation_path),
            "digest": cp.raw_digest(canonical_json(installation_document)),
        },
        "request": context.request,
        "host_nonce": context.host_nonce,
        "reservation_digest": cp.raw_digest(
            context.prior_store.read(
                cp.request_digest(context.request), kind="reservation"
            )
        ),
        "authorization_verification_digest": cp.raw_digest(
            context.historical_authorization.verification_bytes
        ),
        "authorization_context": {
            "path": str(authority_path),
            "digest": cp.raw_digest(canonical_json(historical_document)),
        },
        "predecessor_context_digest": predecessor.context_digest,
        "predecessor_frontier_claim_digest": context.predecessor_frontier_claim_digest,
        "original_context_digest": context.original.context_digest,
        "original_frontier_claim_digest": context.original_frontier_claim_digest,
        "current_fence_digest": context.proof.digest(),
        "current_fence_id": context.proof.fence_id,
        "evidence": dict(context.evidence),
        "quiescence_digest": context.quiescence_digest,
        "inventory": dict(context.inventory),
    }
    reads = {
        installation_path: canonical_json(installation_document),
        context_path: canonical_json(context_document),
        authority_path: canonical_json(historical_document),
        work / "invocation.json": canonical_json(invocation),
        work / "result.json": canonical_json(result),
        work / "request.json": canonical_json(context.request),
        work / "bundle.json": b"synthetic bundle",
    }
    p.reads.update(reads)
    active = replace(
        p.active,
        failed_candidate_context={
            "path": str(context_path),
            "digest": cp.raw_digest(reads[context_path]),
        },
    )
    monkeypatch.setattr(
        op,
        "load_installation",
        lambda path: (
            latest_installation
            if str(latest_installation.store.root)
            == installation_document["artifact_directory"]
            else replace(
                latest_installation,
                store=cp.ArtifactStore(
                    Path(installation_document["artifact_directory"])
                ),
            )
        )
        if path == installation_path
        else p.failed_installation
        if path == p.failed_path
        else active,
    )
    successor["basis"]["context_digest"] = active.failed_candidate_context["digest"]
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    return SimpleNamespace(
        active=active,
        context=context,
        successor=successor,
        document=context_document,
        path=context_path,
        reads=p.reads,
        predecessor=p,
        installation_document=installation_document,
        installation_path=installation_path,
        authority_path=authority_path,
        historical_document=historical_document,
        invocation=invocation,
        work=work,
    )


def test_v2_loader_validates_both_canonical_installations_and_full_frontier(
    protected_v2,
):
    p = protected_v2
    loaded = op._load_failed_candidate_context(p.active)
    assert isinstance(loaded, cp.FailedCandidateContextV2)
    assert type(loaded.predecessor) is cp.FailedCandidateContext
    assert loaded.prior_store is p.context.prior_store
    assert loaded.predecessor.prior_store is p.predecessor.context.prior_store
    loaded.historical_authorization.verify(loaded.request)
    cp.verify_failed_candidate_frontier(loaded, p.successor)


@pytest.mark.parametrize(
    "mutation",
    [
        "predecessor_pin",
        "v2_predecessor",
        "skipped_predecessor",
        "latest_installation_alias",
        "request_schema",
        "execution_window",
        "reservation",
        "authorization",
    ],
)
def test_v2_loader_rejects_mutated_ancestry(protected_v2, mutation):
    p = protected_v2
    if mutation == "predecessor_pin":
        p.document["predecessor_context_digest"] = "sha256:" + "0" * 64
    elif mutation == "v2_predecessor":
        prior = copy.deepcopy(p.predecessor.document)
        prior["schema"] = "dotmac.cp_failed_candidate_context/2"
        p.reads[p.predecessor.path] = canonical_json(prior)
    elif mutation == "skipped_predecessor":
        p.installation_document.pop("failed_candidate_context")
        p.installation_document["committed_migration_context"] = {
            "path": "/opt/skipped",
            "digest": "sha256:" + "0" * 64,
        }
    elif mutation == "latest_installation_alias":
        p.installation_document["artifact_directory"] = str(
            p.predecessor.context.prior_store.root
        )
    elif mutation == "request_schema":
        p.document["request"] = p.successor
    elif mutation == "execution_window":
        p.invocation["started_unix"] -= 25 * 3600
        p.reads[p.work / "invocation.json"] = canonical_json(p.invocation)
        p.historical_document["invocation_digest"] = cp.raw_digest(
            p.reads[p.work / "invocation.json"]
        )
        p.reads[p.authority_path] = canonical_json(p.historical_document)
        p.document["authorization_context"]["digest"] = cp.raw_digest(
            p.reads[p.authority_path]
        )
    elif mutation == "reservation":
        p.document["reservation_digest"] = "sha256:" + "0" * 64
    else:
        p.document["authorization_verification_digest"] = "sha256:" + "0" * 64
    p.reads[p.installation_path] = canonical_json(p.installation_document)
    p.document["failed_installation"]["digest"] = cp.raw_digest(
        p.reads[p.installation_path]
    )
    p.reads[p.path] = canonical_json(p.document)
    active = replace(
        p.active,
        failed_candidate_context={
            "path": str(p.path),
            "digest": cp.raw_digest(p.reads[p.path]),
        },
    )
    successor = copy.deepcopy(p.successor)
    successor["basis"]["context_digest"] = active.failed_candidate_context["digest"]
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    expected = {
        "predecessor_pin": "failed_candidate_ancestry_mismatch",
        "v2_predecessor": "schema_violation",
        "skipped_predecessor": "failed_candidate_predecessor_kind",
        "latest_installation_alias": "failed_candidate_canonical_store_mismatch",
        "request_schema": "schema_violation",
        "execution_window": "expired",
        "reservation": "failed_candidate_reservation_mismatch",
    }
    if mutation == "authorization":
        with pytest.raises(FileNotFoundError):
            op._load_failed_candidate_context(active)
    else:
        with pytest.raises(ContractError, match=expected[mutation]):
            loaded = op._load_failed_candidate_context(active)
            cp.verify_failed_candidate_frontier(loaded, successor)
