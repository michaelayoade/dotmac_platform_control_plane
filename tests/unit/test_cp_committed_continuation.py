"""Two-context continuation admission, durable frontier consumption and suffix."""

# ruff: noqa: F811 - pytest fixtures intentionally share imported owner names

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import timedelta

import pytest
from test_cp_transition import (  # noqa: F401, F811 - owner fixtures
    NOW,
    Host,
    execute,
    request,
    store,
    trust,
)

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, digest
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_fence as fence


@pytest.fixture
def committed(store, trust, monkeypatch):
    verifier, path, report, cert, files = trust
    historical_bytes = verifier.verify(
        request(), request_path=path, bundle_path=None, now=NOW
    ).verification_bytes
    old_host = Host(fail="candidate-ready")
    with pytest.raises(RuntimeError, match="candidate-ready"):
        execute(store, trust, monkeypatch, old_host)
    evidence = {}
    quiescence = None
    for item in store.root.glob("*.evidence.json"):
        try:
            value = cp.read_json(item.read_bytes())
        except ValueError:
            continue
        if value.get("schema") == "dotmac.cp_transition_evidence/2":
            evidence[value["kind"]] = cp.raw_digest(item.read_bytes())
        if value.get("schema") == "dotmac.cp_candidate_quiescence/1":
            quiescence = cp.raw_digest(item.read_bytes())
    proof = fence.FenceProof(
        database="platform",
        fence_id=old_host.nonce,
        prior_acl="original",
        prior_grants=frozenset(
            {
                ("", "CONNECT", False, "app_admin"),
                ("app_user", "CONNECT", True, "app_admin"),
            }
        ),
        fenced_roles=("app_user",),
        member_roles=(),
        absent_roles=tuple(role for role in fence.WRITER_ROLES if role != "app_user"),
        terminated_count=0,
        fenced_at=NOW,
    )
    store.put(canonical_json(proof.to_document()))
    tree = store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_migration_tree/1",
                "revision": request()["target"]["revision"],
                "files": {"migrations/v001.py": "sha256:" + "d" * 64},
            }
        )
    )
    claim = store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_migration_claim/1",
                "request_digest": cp.request_digest(request()),
                "host_nonce": old_host.nonce,
                "migration_tree_digest": tree,
            }
        )
    )
    historical = cp.HistoricalAuthorization(
        verifier.policy,
        historical_bytes,
        NOW,
        NOW,
        "request.json",
        files[verifier.policy.environment_protection_proof],
        digest({"old": "authority"}),
    )
    context = cp.CommittedMigrationContext(
        store,
        request(),
        old_host.nonce,
        evidence,
        historical,
        store.recovery,
        proof,
        proof,
        digest({"context": 1}),
        claim,
        tree,
        quiescence,
    )
    fresh = copy.deepcopy(request())
    fresh.update(
        schema="dotmac.cp_committed_migration_request/1",
        operator_revision="e" * 40,
        authorization_run_id=456,
        authorization_run_attempt=1,
        expires_at="2026-10-27T00:00:00Z",
        basis={
            "context_digest": context.context_digest,
            "prior_request_digest": cp.request_digest(context.request),
            "prior_host_nonce": context.host_nonce,
            "prior_reservation_digest": cp.raw_digest(
                store.read(cp.request_digest(context.request), kind="reservation")
            ),
            "prior_authorization_digest": cp.raw_digest(historical_bytes),
            "original_fence_digest": proof.digest(),
            "current_fence_digest": proof.digest(),
            "current_fence_id": proof.fence_id,
            "frontier_measurement_digest": digest(context.measurement),
        },
    )
    fresh["plan_digest"] = cp.transition_plan_digest(fresh)
    # The old request has expired by the time the new authorization executes.
    fresh_now = NOW + timedelta(days=2)
    files[path] = canonical_json(fresh)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(fresh)
    cert["runInvocationURI"] = (
        "https://github.com/example/cp/actions/runs/456/attempts/1"
    )
    report["verifiedTimestamps"][0]["timestamp"] = "2026-10-26T00:00:00Z"
    protection = cp.read_json(files[verifier.policy.environment_protection_proof])
    protection["expires_at"] = "2026-10-28T00:00:00Z"
    files[verifier.policy.environment_protection_proof] = canonical_json(protection)
    verifier.policy = replace(
        verifier.policy,
        environment_protection_digest=cp.raw_digest(
            files[verifier.policy.environment_protection_proof]
        ),
    )
    return context, fresh, fresh_now, verifier, path


class SuffixHost:
    def __init__(self, context, store, fail=None):
        self.context, self.store, self.fail = context, store, fail
        self.events = []
        self.nonce = None
        self.request = None
        self.pre_routing = None
        self.acl_may_be_restored = False

    def lock(self):
        from contextlib import nullcontext

        return nullcontext()

    def inspect_committed(self, request, context):
        self.events.append("inspect")
        assert context is self.context
        return canonical_json(
            {"source": request["source"], "target": request["target"]}
        )

    def envelope(self, kind, result):
        self.events.append(kind)
        if kind == self.fail:
            raise RuntimeError(kind)
        return canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": cp.request_digest(self.request),
                "host_nonce": self.nonce,
                "kind": kind,
                "result": result,
            }
        )

    def rebind_committed(self, request, nonce, context):
        self.request, self.nonce = request, nonce
        return self.envelope(
            "committed-rebound",
            {
                "prior_fence_id": context.proof.fence_id,
                "fence_id": nonce,
                "original_fence_digest": request["basis"]["original_fence_digest"],
                "current_fence_digest": request["basis"]["current_fence_digest"],
            },
        )

    def target_heads(self, request, nonce):
        return self.envelope("migrated-target-heads", request["target"])

    def candidate_ready(self, request, nonce):
        return self.envelope(
            "candidate-ready",
            {"side": request["target"], "status": 200, "writer_sessions": 0},
        )

    def close_candidate_and_refence(self, request, nonce):
        snapshot = self.store.put(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                    "request_digest": cp.request_digest(request),
                    "host_nonce": nonce,
                    "measurement": self.context.measurement,
                }
            )
        )
        # Fresh store also retains the measured catalogue bytes independently.
        catalogue = self.context.measurement["catalogue_digest"]
        try:
            self.store.put(self.context.prior_store.read(catalogue))
        except FileExistsError:
            pass
        quiescence = self.store.put(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence/1",
                    "request_digest": cp.request_digest(request),
                    "host_nonce": nonce,
                    "before_digest": snapshot,
                    "after_digest": snapshot,
                }
            )
        )
        return self.envelope(
            "candidate-removed-fenced",
            {
                "candidate_sessions": 0,
                "candidate_roles": [],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
                "quiescence_digest": quiescence,
            },
        )

    def restore_acl(self, request, nonce):
        return self.envelope(
            "acl-restored", {"database": request["database"], "acl_difference": []}
        )

    def full_ready(self, request, nonce):
        return self.envelope("full-ready", {"side": request["target"], "status": 200})

    def verify_pre_routing(self, raw):
        cp.verify_any_receipt(
            raw,
            store=self.store,
            request=self.request,
            host_nonce=self.nonce,
            recovery={},
            context=self.context,
            routing_gate=True,
        )
        return self.envelope(
            "pre-routing-verified", {"receipt_digest": cp.raw_digest(raw)}
        )

    def restore_routing(self, request, nonce):
        return self.envelope(
            "routing-restored", {"side": request["target"], "external_status": 200}
        )

    def fail_closed(self, request, nonce, *, acl_may_be_restored):
        self.acl_may_be_restored = acl_may_be_restored
        return self.envelope(
            "failure",
            {
                "external_status": 503,
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        )


def fresh_store(context, name):
    root = context.prior_store.root / name
    root.mkdir()
    return cp.ArtifactStore(root)


def run(committed, name="fresh", fail=None):
    context, request, now, verifier, path = committed
    store = fresh_store(context, name)
    host = SuffixHost(context, store, fail)
    checksum = cp.execute_committed_continuation(
        canonical_json(request),
        request_path=path,
        bundle_path=None,
        verifier=verifier,
        host=host,
        store=store,
        recovery={},
        context=context,
        clock=lambda: now,
    )
    return store, host, checksum


def test_historical_expiry_is_not_renewed_and_fresh_expiry_is_required(committed):
    context, value, now, *_ = committed
    cp.verify_committed_frontier(context, value)
    with pytest.raises(ContractError, match="expired"):
        cp.validate_request(
            context.request,
            identity=context.historical_authorization.policy.identity,
            now=now,
        )
    expired = copy.deepcopy(value)
    expired["expires_at"] = context.request["expires_at"]
    with pytest.raises(ContractError, match="expired"):
        cp.validate_committed_request(
            expired, identity=context.historical_authorization.policy.identity, now=now
        )


def test_success_distinct_receipt_and_suffix_only(committed):
    context, value, *_ = committed
    store, host, checksum = run(committed)
    raw = store.read(checksum, kind="receipt")
    receipt = cp.verify_any_receipt(
        raw,
        store=store,
        request=value,
        host_nonce=host.nonce,
        recovery={},
        routing_gate=True,
        context=context,
    )
    assert receipt["schema"] == "dotmac.cp_committed_migration_receipt/1"
    assert host.events == [
        "inspect",
        "committed-rebound",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
        "routing-restored",
    ]
    assert (
        set(receipt["evidence"])
        == cp.COMMITTED_PRE_ACL_EVIDENCE | cp.RUNTIME_EVIDENCE | cp.ROUTING_EVIDENCE
    )
    assert host.nonce != context.host_nonce
    with pytest.raises(ContractError):
        cp.verify_receipt(
            raw,
            store=store,
            request=value,
            host_nonce=host.nonce,
            recovery={},
        )


@pytest.mark.parametrize(
    "pin",
    [
        "prior_host_nonce",
        "prior_request_digest",
        "prior_authorization_digest",
        "prior_reservation_digest",
        "original_fence_digest",
        "current_fence_digest",
        "current_fence_id",
        "context_digest",
        "frontier_measurement_digest",
    ],
)
def test_basis_tamper_refused(committed, pin):
    context, value, *_ = committed
    tampered = copy.deepcopy(value)
    tampered["basis"][pin] = (
        "f" * 64
        if pin.endswith("nonce") or pin.endswith("id")
        else "sha256:" + "f" * 64
    )
    tampered["plan_digest"] = cp.transition_plan_digest(tampered)
    with pytest.raises(ContractError):
        cp.verify_committed_frontier(context, tampered)


@pytest.mark.parametrize(
    "field", ["image_digest", "revision", "raw_descriptor_digest", "heads"]
)
def test_target_substitution_refused_even_with_new_plan(committed, field):
    context, value, *_ = committed
    tampered = copy.deepcopy(value)
    tampered["target"][field] = (
        ["other"]
        if field == "heads"
        else ("f" * 40 if field == "revision" else "sha256:" + "f" * 64)
    )
    tampered["plan_digest"] = cp.transition_plan_digest(tampered)
    with pytest.raises(ContractError, match="target_or_identity"):
        cp.verify_committed_frontier(context, tampered)


@pytest.mark.parametrize(
    "kind",
    sorted(cp.PRE_MIGRATION_EVIDENCE | {"migrate", "migrated-target-heads", "failure"}),
)
def test_missing_prefix_refused(committed, kind):
    context, value, *_ = committed
    evidence = dict(context.evidence)
    evidence.pop(kind)
    with pytest.raises(ContractError, match="frontier_evidence"):
        cp.verify_committed_frontier(replace(context, evidence=evidence), value)


@pytest.mark.parametrize(
    "kind",
    [
        "candidate-ready",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
        "routing-restored",
        "candidate-removed-fenced",
    ],
)
def test_contradictory_later_checkpoint_refused(committed, kind):
    context, value, *_ = committed
    context.prior_store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": cp.request_digest(context.request),
                "host_nonce": context.host_nonce,
                "kind": kind,
                "result": {},
            }
        )
    )
    with pytest.raises(ContractError, match="contradiction"):
        cp.verify_committed_frontier(context, value)


def test_sibling_context_across_distinct_fresh_stores_consumes_once(committed):
    context, value, *_ = committed
    store, host, checksum = run(committed)
    sibling = replace(context, context_digest=digest({"sibling": True}))
    other = copy.deepcopy(value)
    other["basis"]["context_digest"] = sibling.context_digest
    with pytest.raises(ContractError, match="frontier_consumed"):
        cp.verify_committed_frontier(sibling, other)
    with pytest.raises(ContractError, match="frontier_consumed"):
        run(committed, "sibling")
    # The owner can still verify its exact retained claim after use.
    cp.verify_any_receipt(
        store.read(checksum, kind="receipt"),
        store=store,
        request=value,
        host_nonce=host.nonce,
        recovery={},
        context=context,
    )


def test_partial_frontier_write_consumes_fresh_request_and_frontier(
    committed, monkeypatch
):
    context, value, now, verifier, path = committed
    store = fresh_store(context, "partial")
    original_create = context.prior_store._create

    def partial(name, raw):
        original_create(name, b"{")
        raise OSError("disk full")

    monkeypatch.setattr(context.prior_store, "_create", partial)
    host = SuffixHost(context, store)
    with pytest.raises(OSError, match="disk full"):
        cp.execute_committed_continuation(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=store,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert cp.read_json(store.read(cp.request_digest(value), kind="reservation"))[
        "request_digest"
    ] == cp.request_digest(value)
    assert host.events == ["inspect"]
    with pytest.raises(ContractError, match="frontier_consumed"):
        cp.verify_committed_frontier(context, value)


@pytest.mark.parametrize(
    "stage,acl",
    [("candidate-ready", False), ("full-ready", True), ("routing-restored", True)],
)
def test_suffix_failure_is_contained_and_not_resumable(committed, stage, acl):
    context, value, *_ = committed
    store = fresh_store(context, "failed")
    host = SuffixHost(context, store, stage)
    _, _, now, verifier, path = committed
    with pytest.raises(RuntimeError, match=stage):
        cp.execute_committed_continuation(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=store,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    assert host.events[-1] == "failure"
    assert host.acl_may_be_restored == acl
    with pytest.raises(ContractError, match="frontier_consumed"):
        cp.verify_committed_frontier(context, value)


def test_new_complete_receipt_is_explicitly_validated_as_future_v1_predecessor(
    committed,
):
    context, value, *_ = committed
    store, _, checksum = run(committed)
    successor = copy.deepcopy(context.request)
    successor["source"] = value["target"]
    successor["target"] = {**value["target"], "image_digest": "sha256:" + "f" * 64}
    successor["previous_receipt_digest"] = checksum
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    cp.verify_predecessor(
        successor,
        store=store,
        recovery={},
        committed_contexts={context.context_digest: context},
    )
    with pytest.raises(ContractError, match="committed_context_missing"):
        cp.verify_predecessor(successor, store=store, recovery={})


@pytest.mark.parametrize(
    "field", ["migration_claim_digest", "migration_tree_digest", "quiescence_digest"]
)
def test_missing_original_claim_tree_or_quiescence_refused(committed, field):
    context, value, *_ = committed
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_committed_frontier(
            replace(context, **{field: "sha256:" + "f" * 64}), value
        )


def test_tampered_original_artifact_refused(committed):
    context, value, *_ = committed
    checksum = context.evidence["migrate"]
    (
        context.prior_store.root / context.prior_store._name(checksum, "evidence")
    ).write_bytes(b"tampered")
    with pytest.raises(ContractError, match="artifact_digest_mismatch"):
        cp.verify_committed_frontier(context, value)


@pytest.mark.parametrize("field", ["certificate", "timestamp", "predicate", "subject"])
def test_historical_report_still_checks_original_certification(committed, field):
    context, *_ = committed
    authority = context.historical_authorization
    report = json.loads(authority.verification_bytes)[0]["verificationResult"]
    if field == "certificate":
        report["signature"]["certificate"]["runnerEnvironment"] = "self-hosted"
    elif field == "timestamp":
        report["verifiedTimestamps"][0]["timestamp"] = "2026-10-24T00:00:01Z"
    elif field == "predicate":
        report["statement"]["predicate"]["request_digest"] = "sha256:" + "f" * 64
    else:
        report["statement"]["subject"][0]["name"] = "other.json"
    modified = json.dumps([{"verificationResult": report}]).encode()
    with pytest.raises(ContractError):
        replace(authority, verification_bytes=modified).verify(context.request)


def test_historical_original_execution_window_is_required(committed):
    context, _, now, *_ = committed
    with pytest.raises(ContractError):
        replace(context.historical_authorization, execution_window_end=now).verify(
            context.request
        )
    assert not isinstance(context.historical_authorization, cp.VerifiedAuthorization)


def test_other_or_partial_reservation_in_original_attempt_denies(committed):
    context, value, *_ = committed
    context.prior_store._create(
        context.prior_store._name("sha256:" + "f" * 64, "reservation"), b"{"
    )
    with pytest.raises(ContractError, match="frontier_consumed"):
        cp.verify_committed_frontier(context, value)


def test_owned_frontier_claim_cannot_be_used_by_another_request(committed):
    context, value, *_ = committed
    run(committed)
    owned = context.prior_store.read(
        cp.committed_frontier_key(context), kind="reservation"
    )
    sibling = copy.deepcopy(value)
    sibling["authorization_run_id"] += 1
    with pytest.raises(ContractError, match="frontier_owner_mismatch"):
        cp.verify_committed_frontier(context, sibling, owned_frontier_claim=owned)


def test_failed_fresh_reservation_never_starts_or_consumes_prior_frontier(
    committed, monkeypatch
):
    context, value, now, verifier, path = committed
    store = fresh_store(context, "fresh-write-failure")

    def failed_write(name, raw):
        cp.ArtifactStore._create(store, name, b"{")
        raise OSError("disk full")

    monkeypatch.setattr(store, "_create", failed_write)
    host = SuffixHost(context, store)
    with pytest.raises(OSError, match="disk full"):
        cp.execute_committed_continuation(
            canonical_json(value),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=store,
            recovery={},
            context=context,
            clock=lambda: now,
        )
    with pytest.raises(FileNotFoundError):
        context.prior_store.read(cp.committed_frontier_key(context), kind="reservation")
    assert store.read(cp.request_digest(value), kind="reservation") == b"{"
    assert host.events == ["inspect"]
