"""Finite post-ACL recovery retains the actual fifteen-record suffix shape."""

# ruff: noqa: F811 - pytest fixtures intentionally share imported owner names
from __future__ import annotations

import copy
import json
import shutil
from dataclasses import replace

import pytest
from test_cp_committed_continuation import (  # noqa: F401
    SuffixHost,
    committed,
    fresh_store,
)
from test_cp_failed_candidate_recovery import (
    RecoveryHost,
    failed,  # noqa: F401
    failed_v1,  # noqa: F401
)
from test_cp_transition import request, store, trust  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, digest
from vendor_cp.deployment import cp_transition as cp


def sign(value, trust, path):
    _, _, report, cert, files = trust
    files[path] = canonical_json(value)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(value)
    cert["runInvocationURI"] = (
        f"https://github.com/example/cp/actions/runs/{value['authorization_run_id']}/attempts/1"
    )


@pytest.fixture
def post_acl(failed_v1, trust, monkeypatch):
    predecessor, prior, now, verifier, path = failed_v1
    latest = fresh_store(predecessor.original, "failed-v2-post-acl")
    historical = cp.HistoricalCommittedAuthorization(
        verifier.policy,
        verifier.verify(
            prior, request_path=path, bundle_path=None, now=now
        ).verification_bytes,
        now,
        now,
        "request.json",
        cp._read_protected(verifier.policy.environment_protection_proof),
        digest({"authority": "failed V2 post ACL"}),
    )
    host = RecoveryHost(predecessor, latest, fail="full-ready")
    with pytest.raises(RuntimeError, match="full-ready"):
        cp.execute_failed_candidate_recovery(
            canonical_json(prior),
            request_path=path,
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
    canonical_store = (
        cp.post_acl_failed_installation_path(prior).parent / "artifact-store"
    )
    canonical_store.parent.mkdir(parents=True)
    latest.root.rename(canonical_store)
    latest.root = canonical_store
    evidence = {}
    for item in latest.root.glob("*.evidence.json"):
        # The retained verifier report is a JSON array, not a stage envelope.
        document = json.loads(item.read_bytes())
        if (
            isinstance(document, dict)
            and document.get("schema") == "dotmac.cp_transition_evidence/2"
        ):
            evidence[document["kind"]] = cp.raw_digest(item.read_bytes())
    cleanup = cp.read_json(latest.read(evidence["candidate-removed-fenced"]))["result"]
    receipts = list(latest.root.glob("*.receipt.json"))
    assert len(receipts) == 1
    spent = predecessor.prior_store.read(
        cp.failed_candidate_frontier_key(predecessor), kind="reservation"
    )
    context = cp.PostAclRecoveryContext(
        predecessor=predecessor,
        prior_store=latest,
        request=prior,
        host_nonce=host.nonce,
        historical_authorization=historical,
        proof=proof,
        context_digest=digest({"post ACL": "context"}),
        predecessor_frontier_claim_digest=cp.raw_digest(spent),
        pre_routing_receipt_digest=cp.raw_digest(receipts[0].read_bytes()),
        evidence=evidence,
        quiescence_digest=cleanup["quiescence_digest"],
        inventory={
            p.name: cp.raw_digest(p.read_bytes()) for p in latest.root.iterdir()
        },
    )
    value = copy.deepcopy(prior)
    value.update(
        schema="dotmac.cp_post_acl_recovery_request/1", authorization_run_id=901
    )
    value["basis"] = cp.post_acl_recovery_basis(context)
    value["plan_digest"] = cp.transition_plan_digest(value)
    sign(value, trust, path)
    return context, value, now, verifier, path


class PostAclHost(SuffixHost):
    def inspect_post_acl_recovery(self, request, context):
        self.request = request
        self.events.append("inspect")
        return canonical_json(
            {
                "source": request["source"],
                "target": request["target"],
                "measurement": context.measurement,
            }
        )

    def stop_and_drain_writers(self, request, nonce):
        self.request, self.nonce = request, nonce
        # Every target-writer mutation follows durable exclusive consumption.
        self.context.prior_store.read(
            cp.post_acl_recovery_frontier_key(self.context), kind="reservation"
        )
        return self.envelope(
            "writers-stopped", {"running_writers": [], "restart_enabled": []}
        )

    def rebind_post_acl_recovery(self, request, nonce, context):
        return self.envelope(
            "post-acl-rebound",
            {
                "prior_fence_id": context.proof.fence_id,
                "fence_id": nonce,
                "original_fence_digest": request["basis"]["original_fence_digest"],
                "current_fence_digest": request["basis"]["current_fence_digest"],
                "measurement": context.measurement,
            },
        )

    def verify_pre_routing(self, raw):
        cp.verify_any_receipt(
            raw,
            store=self.store,
            request=self.request,
            host_nonce=self.nonce,
            recovery={},
            routing_gate=True,
            post_acl_contexts={self.context.context_digest: self.context},
        )
        return self.envelope(
            "pre-routing-verified", {"receipt_digest": cp.raw_digest(raw)}
        )


def run_post_acl(
    post_acl, *, name="post-acl-success", fail=None, host_type=PostAclHost
):
    context, value, now, verifier, path = post_acl
    fresh = fresh_store(context.original, name)
    host = host_type(context, fresh, fail=fail)
    result = cp.execute_post_acl_recovery(
        canonical_json(value),
        request_path=path,
        bundle_path=None,
        verifier=verifier,
        host=host,
        store=fresh,
        recovery={},
        context=context,
        clock=lambda: now,
    )
    return fresh, host, result


def test_actual_shape_full_success_and_preserved_ancestry(post_acl):
    context, value, *_ = post_acl
    assert len(context.inventory) == 15
    assert len(context.evidence) == 8
    cp.verify_post_acl_recovery_frontier(context, value)
    ancestors = (
        context,
        context.predecessor,
        context.predecessor.predecessor,
        context.original,
    )
    before = [
        {p.name: p.read_bytes() for p in x.prior_store.root.iterdir() if p.is_file()}
        for x in ancestors
    ]
    fresh, host, result = run_post_acl(post_acl)
    complete = cp.verify_any_receipt(
        fresh.read(result, kind="receipt"),
        store=fresh,
        request=value,
        host_nonce=host.nonce,
        recovery={},
        routing_gate=True,
        post_acl_contexts={context.context_digest: context},
    )
    assert complete["phase"] == "complete"
    assert host.events.index("writers-stopped") < host.events.index("post-acl-rebound")
    assert host.events.index("post-acl-rebound") < host.events.index("candidate-ready")
    assert host.events.index("pre-routing-verified") < host.events.index(
        "routing-restored"
    )
    for index, ancestor in enumerate(ancestors):
        after = {
            p.name: p.read_bytes()
            for p in ancestor.prior_store.root.iterdir()
            if p.is_file()
        }
        assert all(after[name] == raw for name, raw in before[index].items())
        assert len(after) == len(before[index]) + (1 if index == 0 else 0)


@pytest.mark.parametrize("field", list(cp.PostAclRecoveryBasisV1.__annotations__))
def test_every_new_basis_binding_refuses(post_acl, field):
    context, value, *_ = post_acl
    value = copy.deepcopy(value)
    value["basis"][field] = (
        "f" * 64
        if field.endswith("_id") or field.endswith("_nonce")
        else "sha256:" + "f" * 64
    )
    value["plan_digest"] = cp.transition_plan_digest(value)
    with pytest.raises(ContractError):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "name",
    [
        "inspection",
        "authorization",
        "failed-candidate-rebound",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "failure",
    ],
)
def test_every_retained_stage_tamper_refuses(post_acl, name):
    context, value, *_ = post_acl
    path = context.prior_store.root / context.prior_store._name(
        context.evidence[name], "evidence"
    )
    path.write_bytes(b"{}")
    with pytest.raises(ContractError):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "receipt", "nonce", "generation", "claim", "fence"]
)
def test_closed_frontier_cannot_be_reinterpreted(post_acl, mutation):
    context, value, *_ = post_acl
    if mutation == "missing":
        (context.prior_store.root / next(iter(context.inventory))).unlink()
    elif mutation == "extra":
        context.prior_store.put(canonical_json({"unknown": True}))
        context = replace(
            context,
            inventory={
                p.name: cp.raw_digest(p.read_bytes())
                for p in context.prior_store.root.iterdir()
            },
        )
    elif mutation == "receipt":
        context = replace(
            context, pre_routing_receipt_digest=context.evidence["acl-restored"]
        )
    elif mutation == "nonce":
        context = replace(context, host_nonce="f" * 64)
    elif mutation == "generation":
        context = replace(context, predecessor=context)
    elif mutation == "claim":
        context = replace(
            context, predecessor_frontier_claim_digest="sha256:" + "f" * 64
        )
    else:
        context = replace(context, proof=replace(context.proof, fence_id="f" * 64))
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "failure",
    [
        "writers-stopped",
        "post-acl-rebound",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
        "routing-restored",
    ],
)
def test_each_suffix_failure_compensates_and_consumes(post_acl, failure):
    context, value, *_ = post_acl
    fresh = fresh_store(context.original, "failure-" + failure)
    host = PostAclHost(context, fresh, fail=failure)
    _, _, now, verifier, path = post_acl
    with pytest.raises(RuntimeError, match=failure):
        cp.execute_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert "failure" in host.events
    context.prior_store.read(
        cp.post_acl_recovery_frontier_key(context), kind="reservation"
    )
    assert not any(
        cp.read_json(p.read_bytes()).get("phase") == "complete"
        for p in fresh.root.glob("*.receipt.json")
    )


@pytest.mark.parametrize("when", ["inspection", "rebind"])
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
def test_full_measurement_drift_or_unavailability_refuses(post_acl, when, field):
    class DriftHost(PostAclHost):
        def drift(self, raw, *, envelope):
            document = cp.read_json(raw)
            result = document["result"] if envelope else document
            measured = result["measurement"]
            measured[field] = "changed" if field == "stats_reset" else None
            return canonical_json(document)

        def inspect_post_acl_recovery(self, request, context):
            raw = super().inspect_post_acl_recovery(request, context)
            return self.drift(raw, envelope=False) if when == "inspection" else raw

        def rebind_post_acl_recovery(self, request, nonce, context):
            raw = super().rebind_post_acl_recovery(request, nonce, context)
            return self.drift(raw, envelope=True) if when == "rebind" else raw

    context, *_ = post_acl
    with pytest.raises(ContractError):
        run_post_acl(post_acl, host_type=DriftHost)
    claim_path = context.prior_store.root / context.prior_store._name(
        cp.post_acl_recovery_frontier_key(context), "reservation"
    )
    assert claim_path.exists() == (when == "rebind")


def test_claim_replay_across_context_store_and_authorization_refuses(post_acl, trust):
    context, value, now, verifier, path = post_acl
    run_post_acl(post_acl)
    sibling = replace(context, context_digest=digest({"sibling": "intent"}))
    fresh_value = copy.deepcopy(value)
    fresh_value.update(
        authorization_run_id=902, basis=cp.post_acl_recovery_basis(sibling)
    )
    fresh_value["plan_digest"] = cp.transition_plan_digest(fresh_value)
    sign(fresh_value, trust, path)
    assert cp.post_acl_recovery_frontier_key(
        sibling
    ) == cp.post_acl_recovery_frontier_key(context)
    with pytest.raises(ContractError):
        run_post_acl((sibling, fresh_value, now, verifier, path), name="sibling")


def test_old_v1_v2_validators_remain_closed(post_acl):
    _, value, now, verifier, _ = post_acl
    for validator in (
        cp.validate_failed_candidate_request,
        cp.validate_failed_candidate_request_v2,
    ):
        with pytest.raises(ContractError):
            validator(value, identity=verifier.policy.identity, now=now)


@pytest.mark.parametrize(
    "record",
    [
        "reservation",
        "authorization-report",
        "fence",
        "quiescence",
        "snapshot",
        "catalogue",
        "receipt",
    ],
)
def test_every_nonstage_record_is_required(post_acl, record):
    context, value, *_ = post_acl
    key, kind = {
        "reservation": (cp.request_digest(context.request), "reservation"),
        "authorization-report": (
            cp.raw_digest(context.historical_authorization.verification_bytes),
            "evidence",
        ),
        "fence": (context.proof.digest(), "evidence"),
        "quiescence": (context.quiescence_digest, "evidence"),
        "snapshot": (
            cp.read_json(context.prior_store.read(context.quiescence_digest))[
                "after_digest"
            ],
            "evidence",
        ),
        "catalogue": (context.measurement["catalogue_digest"], "evidence"),
        "receipt": (context.pre_routing_receipt_digest, "receipt"),
    }[record]
    (context.prior_store.root / context.prior_store._name(key, kind)).unlink()
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "field",
    [
        "phase",
        "host_nonce",
        "historical_context_digest",
        "successor_reservation_digest",
        "request_digest",
        "full-ready",
        "pre-routing-verified",
        "writers-stopped",
    ],
)
def test_complete_receipt_cannot_drop_or_cross_evidence(post_acl, field):
    context, value, *_ = post_acl
    fresh, host, result = run_post_acl(post_acl)
    document = cp.read_json(fresh.read(result, kind="receipt"))
    if field in document["evidence"]:
        del document["evidence"][field]
    else:
        document[field] = (
            "pre-routing"
            if field == "phase"
            else "f" * 64
            if field == "host_nonce"
            else "sha256:" + "f" * 64
        )
    with pytest.raises(ContractError):
        cp.verify_post_acl_recovery_receipt(
            canonical_json(document),
            store=fresh,
            request=value,
            host_nonce=host.nonce,
            recovery={},
            context=context,
            routing_gate=True,
        )


def test_complete_post_acl_receipt_can_anchor_next_ordinary_transition(post_acl):
    context, value, *_ = post_acl
    fresh, _, result = run_post_acl(post_acl)
    future = request()
    future["source"] = value["target"]
    future["previous_receipt_digest"] = result
    cp.verify_predecessor(
        future,
        store=fresh,
        recovery={},
        post_acl_contexts={context.context_digest: context},
    )
    with pytest.raises(ContractError, match="post_acl_context_missing"):
        cp.verify_predecessor(future, store=fresh, recovery={})


@pytest.mark.parametrize(
    "boundary", ["claim-create", "claim-readback", "owned-frontier"]
)
def test_prehost_reservation_failures_preserve_containment_without_mutating(
    post_acl, monkeypatch, boundary
):
    context, value, now, verifier, path = post_acl
    fresh = fresh_store(context.original, "claim-boundary-" + boundary)

    class ClaimHost(PostAclHost):
        def fail_closed(self, request, nonce, *, acl_may_be_restored):
            self.request, self.nonce = request, nonce
            return super().fail_closed(
                request, nonce, acl_may_be_restored=acl_may_be_restored
            )

    host = ClaimHost(context, fresh)
    if boundary in {"claim-create", "claim-readback"}:
        real = cp.ArtifactStore.reserve_post_acl_recovery_frontier

        def fail_claim(self, *args, **kwargs):
            if boundary == "claim-readback":
                real(self, *args, **kwargs)
            raise RuntimeError(boundary)

        monkeypatch.setattr(
            cp.ArtifactStore, "reserve_post_acl_recovery_frontier", fail_claim
        )
    else:
        real = cp.verify_post_acl_recovery_frontier

        def fail_owned(*args, **kwargs):
            real(*args, **kwargs)
            if kwargs.get("owned_successor_claim") is not None:
                raise RuntimeError(boundary)

        monkeypatch.setattr(cp, "verify_post_acl_recovery_frontier", fail_owned)
    with pytest.raises(RuntimeError, match=boundary):
        cp.execute_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert "failure" not in host.events
    assert "writers-stopped" not in host.events
    fresh.read(cp.request_digest(value), kind="reservation")


@pytest.mark.parametrize(
    "ancestor", ["failed-v2", "failed-v1", "committed", "original"]
)
def test_fresh_store_must_be_distinct_from_every_ancestor(post_acl, ancestor):
    context, value, now, verifier, path = post_acl
    chosen = {
        "failed-v2": context.prior_store,
        "failed-v1": context.predecessor.prior_store,
        "committed": context.predecessor.predecessor.prior_store,
        "original": context.original.prior_store,
    }[ancestor]
    host = PostAclHost(context, chosen)
    with pytest.raises(ContractError, match="recovery_store_reused"):
        cp.execute_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=chosen,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert not host.events


@pytest.mark.parametrize(
    "mutation",
    [
        "operator",
        "expired-window",
        "authorization-context",
        "database",
        "source",
        "target",
    ],
)
def test_historical_protected_identity_and_execution_are_required(post_acl, mutation):
    context, value, *_ = post_acl
    if mutation == "operator":
        context = replace(
            context, request={**context.request, "operator_revision": "f" * 40}
        )
    elif mutation == "expired-window":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization,
                execution_window_end=cp.timestamp(context.request["expires_at"]),
            ),
        )
    elif mutation == "authorization-context":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization,
                context_digest=context.predecessor.historical_authorization.context_digest,
            ),
        )
    else:
        value = copy.deepcopy(value)
        if mutation == "database":
            value[mutation] = "another_database"
        else:
            value[mutation]["revision"] = "f" * 40
        value["plan_digest"] = cp.transition_plan_digest(value)
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_post_acl_recovery_frontier(context, value)


@pytest.mark.parametrize(
    "ancestor", ["failed-v2", "failed-v1", "committed", "original"]
)
def test_fresh_nonce_cannot_reuse_any_historical_attempt(
    post_acl, monkeypatch, ancestor
):
    context, *_ = post_acl
    nonce = {
        "failed-v2": context.host_nonce,
        "failed-v1": context.predecessor.host_nonce,
        "committed": context.predecessor.predecessor.host_nonce,
        "original": context.original.host_nonce,
    }[ancestor]
    monkeypatch.setattr(cp.secrets, "token_hex", lambda _: nonce)
    with pytest.raises(ContractError, match="failed_candidate_nonce_reused"):
        run_post_acl(post_acl)
    context.prior_store.read(
        cp.post_acl_recovery_frontier_key(context), kind="reservation"
    )


@pytest.mark.parametrize("kind", ["inspection", "authorization"])
def test_early_evidence_write_failure_never_mutates_host(post_acl, monkeypatch, kind):
    context, value, now, verifier, path = post_acl
    fresh = fresh_store(context.original, "early-retain-" + kind)
    host = PostAclHost(context, fresh)
    real = cp.ArtifactStore.put

    def fail_stage(self, raw, **kwargs):
        if self is fresh and f'"kind":"{kind}"'.encode() in raw:
            raise RuntimeError("early-evidence-write")
        return real(self, raw, **kwargs)

    monkeypatch.setattr(cp.ArtifactStore, "put", fail_stage)
    with pytest.raises(RuntimeError, match="early-evidence-write"):
        cp.execute_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert host.events == ["inspect"]
    context.prior_store.read(
        cp.post_acl_recovery_frontier_key(context), kind="reservation"
    )
    fresh.read(cp.request_digest(value), kind="reservation")


def test_claim_creation_race_never_mutates_host(post_acl, monkeypatch):
    context, value, now, verifier, path = post_acl
    fresh = fresh_store(context.original, "claim-collision")
    host = PostAclHost(context, fresh)
    real = cp.ArtifactStore.reserve_post_acl_recovery_frontier

    def raced(self, *args, **kwargs):
        real(self, *args, **kwargs)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(cp.ArtifactStore, "reserve_post_acl_recovery_frontier", raced)
    with pytest.raises(FileExistsError):
        cp.execute_post_acl_recovery(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert host.events == ["inspect"]
    context.prior_store.read(
        cp.post_acl_recovery_frontier_key(context), kind="reservation"
    )
    fresh.read(cp.request_digest(value), kind="reservation")


def test_byte_cloned_failed_store_cannot_replay_claim_in_another_owner(post_acl, trust):
    context, value, now, verifier, path = post_acl
    cloned_root = (
        context.prior_store.root.parent.parent / "copied-owner" / "artifact-store"
    )
    shutil.copytree(context.prior_store.root, cloned_root)
    assert len(list(cloned_root.iterdir())) == 15
    assert {p.name: p.read_bytes() for p in cloned_root.iterdir()} == {
        p.name: p.read_bytes() for p in context.prior_store.root.iterdir()
    }
    # Consume the canonical owner only after making an exact pre-claim copy.
    run_post_acl(post_acl)
    copied = replace(
        context,
        prior_store=cp.ArtifactStore(cloned_root),
        context_digest=digest({"copied": "failed-owner-context"}),
    )
    fresh_request = copy.deepcopy(value)
    fresh_request.update(
        authorization_run_id=902, basis=cp.post_acl_recovery_basis(copied)
    )
    fresh_request["plan_digest"] = cp.transition_plan_digest(fresh_request)
    sign(fresh_request, trust, path)
    fresh = fresh_store(context.original, "cloned-owner-successor")
    host = PostAclHost(copied, fresh)
    with pytest.raises(ContractError, match="post_acl_canonical_store_mismatch"):
        cp.execute_post_acl_recovery(
            canonical_json(fresh_request),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=fresh,
            recovery={},
            context=copied,
            clock=lambda: now,
        )
    assert host.events == []
    assert list(fresh.root.iterdir()) == []
    # Even the claim-writing API cannot select the copied directory directly.
    with pytest.raises(ContractError, match="post_acl_canonical_store_mismatch"):
        copied.prior_store.reserve_post_acl_recovery_frontier(
            copied,
            fresh_request,
            host_nonce="f" * 64,
            fresh_reservation_digest="sha256:" + "f" * 64,
        )
    assert len(list(cloned_root.iterdir())) == 15
    context.prior_store.read(
        cp.post_acl_recovery_frontier_key(context), kind="reservation"
    )


def test_failed_owner_path_comes_only_from_closed_signed_v2_operator(post_acl):
    context, *_ = post_acl
    expected = (
        cp.POST_ACL_INSTALLATION_ROOT
        / context.request["operator_revision"][:8]
        / "installation.json"
    )
    assert cp.post_acl_failed_installation_path(context.request) == expected
    for crossed in (
        {**context.request, "schema": "dotmac.cp_failed_candidate_request/1"},
        {**context.request, "owner_root": "/opt/another-owner"},
    ):
        with pytest.raises(ContractError):
            cp.post_acl_failed_installation_path(crossed)
