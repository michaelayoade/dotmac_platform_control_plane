"""One-generation recovery proves both spent histories before a fresh suffix."""

# ruff: noqa: F811 - pytest fixtures intentionally share imported owner names
from __future__ import annotations

import copy
from dataclasses import replace

import pytest
from test_cp_committed_continuation import (
    SuffixHost,
    committed,  # noqa: F401
    fresh_store,
)
from test_cp_transition import NOW, request, store, trust  # noqa: F401

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, digest
from vendor_cp.deployment import cp_transition as cp


@pytest.fixture
def failed(committed, trust):
    original, prior, now, verifier, path = committed
    prior = copy.deepcopy(prior)
    prior["operator_revision"] = verifier.policy.workflow_revision
    prior["plan_digest"] = cp.transition_plan_digest(prior)
    _, _, report, cert, files = trust
    files[path] = canonical_json(prior)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(prior)
    historical = cp.HistoricalCommittedAuthorization(
        verifier.policy,
        verifier.verify(
            prior, request_path=path, bundle_path=None, now=now
        ).verification_bytes,
        now,
        now,
        "request.json",
        cp._read_protected(verifier.policy.environment_protection_proof),
        digest({"authority": "failed committed"}),
    )
    failed_store = fresh_store(original, "failed")
    host = SuffixHost(original, failed_store, fail="candidate-ready")
    with pytest.raises(RuntimeError, match="candidate-ready"):
        cp.execute_committed_continuation(
            canonical_json(prior),
            request_path=path,
            bundle_path=None,
            verifier=verifier,
            host=host,
            store=failed_store,
            recovery={},
            context=original,
            clock=lambda: now,
        )
    # Materialize the host producer's retained failed-fence + quiescence bytes.
    proof = replace(original.proof, fence_id=host.nonce)
    failed_store.put(canonical_json(proof.to_document()))
    catalogue = original.measurement["catalogue_digest"]
    failed_store.put(original.prior_store.read(catalogue))
    snapshot = failed_store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                "request_digest": cp.request_digest(prior),
                "host_nonce": host.nonce,
                "measurement": original.measurement,
            }
        )
    )
    quiescence = failed_store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence/1",
                "request_digest": cp.request_digest(prior),
                "host_nonce": host.nonce,
                "before_digest": snapshot,
                "after_digest": snapshot,
            }
        )
    )
    evidence = {}
    for item in failed_store.root.glob("*.evidence.json"):
        try:
            value = cp.read_json(item.read_bytes())
        except ValueError:
            continue
        if value.get("schema") == "dotmac.cp_transition_evidence/2":
            evidence[value["kind"]] = cp.raw_digest(item.read_bytes())
    original_claim = original.prior_store.read(
        cp.committed_frontier_key(original), kind="reservation"
    )
    context = cp.FailedCandidateContext(
        original,
        failed_store,
        prior,
        host.nonce,
        evidence,
        historical,
        proof,
        digest({"failed": "context"}),
        cp.raw_digest(original_claim),
        quiescence,
        {p.name: cp.raw_digest(p.read_bytes()) for p in failed_store.root.iterdir()},
    )
    successor = copy.deepcopy(prior)
    successor.update(
        schema="dotmac.cp_failed_candidate_request/1",
        operator_revision="f" * 40,
        authorization_run_id=789,
        authorization_run_attempt=1,
    )
    successor["basis"] = {
        "context_digest": context.context_digest,
        "original_context_digest": original.context_digest,
        "original_frontier_key": cp.committed_frontier_key(original),
        "original_frontier_claim_digest": context.original_frontier_claim_digest,
        "failed_request_digest": cp.request_digest(prior),
        "failed_host_nonce": context.host_nonce,
        "failed_reservation_digest": cp.raw_digest(
            failed_store.read(cp.request_digest(prior), kind="reservation")
        ),
        "failed_authorization_digest": cp.raw_digest(historical.verification_bytes),
        "failure_digest": evidence["failure"],
        "quiescence_digest": quiescence,
        "original_fence_digest": original.original_proof.digest(),
        "current_fence_digest": proof.digest(),
        "current_fence_id": proof.fence_id,
        "frontier_measurement_digest": digest(context.measurement),
    }
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    # Update the synthetic protected verifier boundary for the fresh signature.
    _, _, report, cert, files = trust
    files[path] = canonical_json(successor)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(successor)
    cert["runInvocationURI"] = (
        "https://github.com/example/cp/actions/runs/789/attempts/1"
    )
    return context, successor, now, verifier, path


class RecoveryHost(SuffixHost):
    def inspect_failed_candidate(self, request, context):
        return self.inspect_committed(request, context)

    def rebind_failed_candidate(self, request, nonce, context):
        self.request, self.nonce = request, nonce
        return self.envelope(
            "failed-candidate-rebound",
            {
                "prior_fence_id": context.proof.fence_id,
                "fence_id": nonce,
                "original_fence_digest": request["basis"]["original_fence_digest"],
                "current_fence_digest": request["basis"]["current_fence_digest"],
            },
        )

    def verify_pre_routing(self, raw):
        cp.verify_any_receipt(
            raw,
            store=self.store,
            request=self.request,
            host_nonce=self.nonce,
            recovery={},
            failed_candidate_context=self.context,
            routing_gate=True,
        )
        return self.envelope(
            "pre-routing-verified", {"receipt_digest": cp.raw_digest(raw)}
        )


def run_recovery(failed, *, name="successor", fail=None):
    context, value, now, verifier, path = failed
    root = context.prior_store.root.parent / name
    root.mkdir()
    fresh = cp.ArtifactStore(root)
    host = RecoveryHost(context, fresh, fail=fail)
    result = cp.execute_failed_candidate_recovery(
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


def original_inventory(context):
    return {
        p.name: p.read_bytes()
        for p in context.original.prior_store.root.iterdir()
        if p.is_file()
    }


def test_successor_suffix_uses_both_histories_without_replaying_prefix(failed):
    context, value, *_ = failed
    old = original_inventory(context)
    cp.verify_failed_candidate_frontier(context, value)
    assert len(context.inventory) == 11
    fresh, host, checksum = run_recovery(failed)
    receipt = cp.verify_any_receipt(
        fresh.read(checksum, kind="receipt"),
        store=fresh,
        request=value,
        host_nonce=host.nonce,
        recovery={},
        routing_gate=True,
        failed_candidate_contexts={context.context_digest: context},
    )
    assert receipt["phase"] == "complete"
    assert "migrate" not in host.events and "capture" not in host.events
    assert original_inventory(context) == old
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize("field", list(cp.FailedCandidateBasisV1.__annotations__))
def test_each_signed_history_pin_is_enforced(failed, field):
    context, value, *_ = failed
    changed = copy.deepcopy(value)
    changed["basis"][field] = (
        "e" * 64
        if field in {"failed_host_nonce", "current_fence_id"}
        else "sha256:" + "e" * 64
    )
    changed["plan_digest"] = cp.transition_plan_digest(changed)
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, changed)


@pytest.mark.parametrize(
    "kind",
    ["candidate-ready", "acl-restored", "full-ready", "routing-restored", "unknown"],
)
def test_later_or_unknown_artifact_refuses_even_if_inventory_is_re_pinned(failed, kind):
    context, value, *_ = failed
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
    changed = replace(
        context,
        inventory={
            p.name: cp.raw_digest(p.read_bytes())
            for p in context.prior_store.root.iterdir()
        },
    )
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(changed, value)


def test_second_generation_predecessor_is_refused(failed):
    context, value, *_ = failed
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(replace(context, request=value), value)


def test_existing_committed_entrypoint_remains_consumed(failed):
    context, *_ = failed
    with pytest.raises(ContractError):
        cp.verify_committed_frontier(context.original, context.request)


@pytest.mark.parametrize(
    "failure",
    [
        "failed-candidate-rebound",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "routing-restored",
    ],
)
def test_suffix_failure_is_contained_and_claim_stays_spent(failed, failure):
    context, value, *_ = failed
    before = original_inventory(context)
    with pytest.raises(RuntimeError, match=failure):
        run_recovery(failed, fail=failure)
    assert original_inventory(context) == before
    assert context.prior_store.read(
        cp.failed_candidate_frontier_key(context), kind="reservation"
    )
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "original_claim",
        "reservation",
        "historical_report",
        "historical_window",
        "fence_lineage",
        "failure",
        "quiescence",
        "measurement",
    ],
)
def test_retained_history_cannot_be_re_pinned_into_eligibility(failed, mutation):
    context, value, *_ = failed
    if mutation == "original_claim":
        context = replace(context, original_frontier_claim_digest="sha256:" + "e" * 64)
    elif mutation == "reservation":
        path = context.prior_store.root / cp.ArtifactStore._name(
            cp.request_digest(context.request), "reservation"
        )
        document = cp.read_json(path.read_bytes())
        document["host_nonce"] = "e" * 64
        path.write_bytes(canonical_json(document))
    elif mutation == "historical_report":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization, verification_bytes=b"[]"
            ),
        )
    elif mutation == "historical_window":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization, execution_window_end=NOW
            ),
        )
    elif mutation == "fence_lineage":
        changed = replace(context.proof, prior_grants=frozenset())
        context.prior_store.put(canonical_json(changed.to_document()))
        context = replace(context, proof=changed)
    elif mutation == "failure":
        evidence = dict(context.evidence)
        evidence["failure"] = evidence["inspection"]
        context = replace(context, evidence=evidence)
    elif mutation == "quiescence":
        context = replace(context, quiescence_digest=context.evidence["failure"])
    else:
        document = cp.read_json(context.prior_store.read(context.quiescence_digest))
        snapshot = cp.read_json(context.prior_store.read(document["after_digest"]))
        snapshot["measurement"]["relations"][0][2] += 1
        checksum = context.prior_store.put(canonical_json(snapshot))
        document.update(before_digest=checksum, after_digest=checksum)
        context = replace(
            context, quiescence_digest=context.prior_store.put(canonical_json(document))
        )
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize(
    "partial", ["successor_claim", "unknown_name", "receipt", "other_reservation"]
)
def test_partial_and_unknown_store_entries_are_not_a_frontier(failed, partial):
    context, value, *_ = failed
    if partial == "successor_claim":
        name = cp.ArtifactStore._name(
            cp.failed_candidate_frontier_key(context), "reservation"
        )
    elif partial == "other_reservation":
        name = cp.ArtifactStore._name("sha256:" + "d" * 64, "reservation")
    elif partial == "receipt":
        name = cp.ArtifactStore._name("sha256:" + "d" * 64, "receipt")
    else:
        name = "attempt-closeout.PARTIAL"
    (context.prior_store.root / name).write_bytes(b"{")
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, value)


def test_sibling_context_and_destination_cannot_select_another_claim(failed):
    context, value, *_ = failed
    key = cp.failed_candidate_frontier_key(context)
    sibling = replace(context, context_digest=digest({"sibling": 1}))
    sibling_request = copy.deepcopy(value)
    sibling_request["basis"]["context_digest"] = sibling.context_digest
    sibling_request["authorization_run_id"] += 1
    sibling_request["plan_digest"] = cp.transition_plan_digest(sibling_request)
    assert cp.failed_candidate_frontier_key(sibling) == key
    cp.verify_failed_candidate_frontier(sibling, sibling_request)
    run_recovery(failed)
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(sibling, sibling_request)
    with pytest.raises(FileExistsError):
        context.prior_store.reserve_failed_candidate_frontier(
            sibling,
            sibling_request,
            host_nonce="c" * 64,
            fresh_reservation_digest="sha256:" + "d" * 64,
        )


@pytest.mark.parametrize(
    "boundary", ["fresh_reservation", "claim_partial", "after_claim"]
)
def test_crash_boundary_never_reuses_reserved_bytes(failed, monkeypatch, boundary):
    context, value, *_ = failed
    prior = original_inventory(context)
    original_create = cp.ArtifactStore._create
    key_name = cp.ArtifactStore._name(
        cp.failed_candidate_frontier_key(context), "reservation"
    )

    def crash(self, name, raw):
        if boundary == "fresh_reservation" and self.root.name == "successor":
            original_create(self, name, raw)
            raise RuntimeError("crash")
        if (
            boundary == "claim_partial"
            and self.root == context.prior_store.root
            and name == key_name
        ):
            original_create(self, name, b"{")
            raise RuntimeError("crash")
        original_create(self, name, raw)
        if (
            boundary == "after_claim"
            and self.root == context.prior_store.root
            and name == key_name
        ):
            raise RuntimeError("crash")

    monkeypatch.setattr(cp.ArtifactStore, "_create", crash)
    with pytest.raises(RuntimeError, match="crash"):
        run_recovery(failed)
    assert original_inventory(context) == prior
    fresh = context.prior_store.root.parent / "successor"
    assert (
        fresh / cp.ArtifactStore._name(cp.request_digest(value), "reservation")
    ).is_file()
    assert (context.prior_store.root / key_name).exists() is (
        boundary != "fresh_reservation"
    )
    if boundary != "fresh_reservation":
        with pytest.raises(ContractError):
            cp.verify_failed_candidate_frontier(context, value)


def test_future_v1_predecessor_dispatches_successor_receipt(failed):
    context, value, *_ = failed
    fresh, host, checksum = run_recovery(failed)
    following = request()
    following["source"] = value["target"]
    following["previous_receipt_digest"] = checksum
    following["plan_digest"] = cp.transition_plan_digest(following)
    cp.verify_predecessor(
        following,
        store=fresh,
        recovery={},
        failed_candidate_contexts={context.context_digest: context},
    )
    with pytest.raises(ContractError, match="failed_candidate_context_missing"):
        cp.verify_predecessor(following, store=fresh, recovery={})


def test_closed_schema_and_plan_domain_are_distinct(failed):
    context, value, now, verifier, _ = failed
    assert (
        cp.validate_any_request(value, identity=verifier.policy.identity, now=now)
        == value
    )
    for validate in (cp.validate_request, cp.validate_committed_request):
        with pytest.raises(ContractError):
            validate(value, identity=verifier.policy.identity, now=now)
    extra = dict(value, extra=True)
    with pytest.raises(ContractError):
        cp.validate_failed_candidate_request(
            extra, identity=verifier.policy.identity, now=now
        )
    old_plan = copy.deepcopy(value)
    old_plan["schema"] = "dotmac.cp_committed_migration_request/1"
    assert cp.transition_plan_digest(old_plan) != cp.transition_plan_digest(value)


def test_historical_failed_operator_must_match_its_protected_issuer(failed):
    context, value, *_ = failed
    authority = replace(
        context.historical_authorization,
        policy=replace(
            context.historical_authorization.policy, workflow_revision="e" * 40
        ),
    )
    with pytest.raises(ContractError, match="historical_operator_revision_mismatch"):
        cp.verify_failed_candidate_frontier(
            replace(context, historical_authorization=authority), value
        )


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "target",
        "host",
        "database",
        "database_oid",
        "cluster_system_identifier",
        "previous_receipt_digest",
    ],
)
def test_successor_cannot_change_application_or_database(failed, field):
    context, value, *_ = failed
    changed = copy.deepcopy(value)
    if field in {"source", "target"}:
        changed[field]["revision"] = "d" * 40
    elif field == "database_oid":
        changed[field] += 1
    elif field == "previous_receipt_digest":
        changed[field] = "sha256:" + "d" * 64
    else:
        changed[field] += "1"
    changed["plan_digest"] = cp.transition_plan_digest(changed)
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, changed)


@pytest.mark.parametrize("original", [False, True])
def test_successor_cannot_reuse_either_historical_authorization(failed, original):
    context, value, *_ = failed
    changed = copy.deepcopy(value)
    prior = context.original.request if original else context.request
    changed["authorization_run_id"] = prior["authorization_run_id"]
    changed["authorization_run_attempt"] = prior["authorization_run_attempt"]
    changed["plan_digest"] = cp.transition_plan_digest(changed)
    with pytest.raises(ContractError, match="failed_candidate_authorization_reused"):
        cp.verify_failed_candidate_frontier(context, changed)


def test_inspection_refusal_precedes_any_reservation_or_rebind(failed, monkeypatch):
    context, *_ = failed
    before = dict(context.inventory)

    def refused(*args):
        raise ContractError("live_frontier_refused")

    monkeypatch.setattr(RecoveryHost, "inspect_failed_candidate", refused)
    with pytest.raises(ContractError, match="live_frontier_refused"):
        run_recovery(failed)
    assert {
        p.name: cp.raw_digest(p.read_bytes())
        for p in context.prior_store.root.iterdir()
    } == before
    assert list((context.prior_store.root.parent / "successor").iterdir()) == []


@pytest.mark.parametrize(
    "field",
    [
        "historical_context_digest",
        "successor_reservation_digest",
        "host_nonce",
        "evidence",
    ],
)
def test_successor_receipt_rejects_tampered_history_or_suffix(failed, field):
    context, value, *_ = failed
    fresh, host, checksum = run_recovery(failed)
    receipt = cp.read_json(fresh.read(checksum, kind="receipt"))
    receipt[field] = {} if field == "evidence" else "sha256:" + "d" * 64
    with pytest.raises(ContractError):
        cp.verify_any_receipt(
            canonical_json(receipt),
            store=fresh,
            request=value,
            host_nonce=host.nonce,
            recovery={},
            failed_candidate_context=context,
            routing_gate=True,
        )


def make_failed_v1(failed, trust):
    """Synthetic failed V1 successor, retaining both immutable ancestor stores."""
    predecessor, prior, now, verifier, path = failed
    prior = copy.deepcopy(prior)
    prior["operator_revision"] = verifier.policy.workflow_revision
    prior["plan_digest"] = cp.transition_plan_digest(prior)
    _, _, report, cert, files = trust
    files[path] = canonical_json(prior)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(prior)
    latest = fresh_store(predecessor.original, "latest-v1")
    host = RecoveryHost(predecessor, latest, fail="candidate-ready")
    historical = cp.HistoricalCommittedAuthorization(
        verifier.policy,
        verifier.verify(
            prior, request_path=path, bundle_path=None, now=now
        ).verification_bytes,
        now,
        now,
        "request.json",
        cp._read_protected(verifier.policy.environment_protection_proof),
        digest({"authority": "failed V1"}),
    )
    with pytest.raises(RuntimeError, match="candidate-ready"):
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
    catalogue = predecessor.measurement["catalogue_digest"]
    latest.put(predecessor.prior_store.read(catalogue))
    snapshot = latest.put(
        canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                "request_digest": cp.request_digest(prior),
                "host_nonce": host.nonce,
                "measurement": predecessor.measurement,
            }
        )
    )
    quiescence = latest.put(
        canonical_json(
            {
                "schema": "dotmac.cp_candidate_quiescence/1",
                "request_digest": cp.request_digest(prior),
                "host_nonce": host.nonce,
                "before_digest": snapshot,
                "after_digest": snapshot,
            }
        )
    )
    evidence = {}
    for item in latest.root.glob("*.evidence.json"):
        try:
            value = cp.read_json(item.read_bytes())
        except ValueError:
            continue
        if value.get("schema") == "dotmac.cp_transition_evidence/2":
            evidence[value["kind"]] = cp.raw_digest(item.read_bytes())
    spent = predecessor.prior_store.read(
        cp.failed_candidate_frontier_key(predecessor), kind="reservation"
    )
    context = cp.FailedCandidateContextV2(
        predecessor=predecessor,
        predecessor_frontier_claim_digest=cp.raw_digest(spent),
        original=predecessor.original,
        prior_store=latest,
        request=prior,
        host_nonce=host.nonce,
        evidence=evidence,
        historical_authorization=historical,
        proof=proof,
        context_digest=digest({"V2": "context"}),
        original_frontier_claim_digest=predecessor.original_frontier_claim_digest,
        quiescence_digest=quiescence,
        inventory={
            p.name: cp.raw_digest(p.read_bytes()) for p in latest.root.iterdir()
        },
    )
    successor = copy.deepcopy(prior)
    successor.update(
        schema="dotmac.cp_failed_candidate_request/2", authorization_run_id=890
    )
    successor["basis"] = {
        **prior["basis"],
        "context_digest": context.context_digest,
        "predecessor_context_digest": predecessor.context_digest,
        "predecessor_frontier_claim_digest": cp.raw_digest(spent),
        "failed_request_digest": cp.request_digest(prior),
        "failed_host_nonce": host.nonce,
        "failed_reservation_digest": cp.raw_digest(
            latest.read(cp.request_digest(prior), kind="reservation")
        ),
        "failed_authorization_digest": cp.raw_digest(historical.verification_bytes),
        "failure_digest": evidence["failure"],
        "quiescence_digest": quiescence,
        "current_fence_digest": proof.digest(),
        "current_fence_id": proof.fence_id,
    }
    successor["plan_digest"] = cp.transition_plan_digest(successor)
    _, _, report, cert, files = trust
    files[path] = canonical_json(successor)
    report["statement"]["subject"][0]["digest"]["sha256"] = cp.raw_digest(files[path])[
        7:
    ]
    report["statement"]["predicate"]["request_digest"] = cp.request_digest(successor)
    cert["runInvocationURI"] = (
        "https://github.com/example/cp/actions/runs/890/attempts/1"
    )
    return context, successor, now, verifier, path


@pytest.fixture
def failed_v1(failed, trust):
    return make_failed_v1(failed, trust)


def test_v2_full_ancestry_and_ancestor_bytes(failed_v1):
    context, request, *_ = failed_v1
    ancestors = [context.original.prior_store, context.predecessor.prior_store]
    before = [
        {p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()}
        for store in ancestors
    ]
    cp.verify_failed_candidate_frontier(context, request)
    fresh, host, result = run_recovery(failed_v1)
    receipt = cp.read_json(fresh.read(result, kind="receipt"))
    assert receipt["schema"] == "dotmac.cp_failed_candidate_receipt/2"
    assert receipt["phase"] == "complete"
    assert before == [
        {p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()}
        for store in ancestors
    ]
    assert not {"capture", "restore", "migrate"} & set(host.events)


@pytest.mark.parametrize("field", list(cp.FailedCandidateBasisV2.__annotations__))
def test_v2_every_basis_join_is_bound(failed_v1, field):
    context, request, *_ = failed_v1
    altered = copy.deepcopy(request)
    value = altered["basis"][field]
    altered["basis"][field] = (
        "0" * 64 if not value.startswith("sha256:") else "sha256:" + "0" * 64
    )
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, altered)


def test_v2_cannot_recover_v2(failed_v1):
    context, request, *_ = failed_v1
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(replace(context, request=request), request)


def test_v2_sibling_context_and_destination_cannot_select_another_claim(failed_v1):
    context, value, *_ = failed_v1
    key = cp.failed_candidate_frontier_key(context)
    sibling = replace(context, context_digest=digest({"sibling": 1}))
    sibling_request = copy.deepcopy(value)
    sibling_request["basis"]["context_digest"] = sibling.context_digest
    sibling_request["authorization_run_id"] += 1
    sibling_request["plan_digest"] = cp.transition_plan_digest(sibling_request)
    assert cp.failed_candidate_frontier_key(sibling) == key
    cp.verify_failed_candidate_frontier(sibling, sibling_request)
    run_recovery(failed_v1)
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(sibling, sibling_request)
    with pytest.raises(FileExistsError):
        context.prior_store.reserve_failed_candidate_frontier(
            sibling,
            sibling_request,
            host_nonce="c" * 64,
            fresh_reservation_digest="sha256:" + "d" * 64,
        )


@pytest.mark.parametrize(
    "boundary", ["fresh_reservation", "claim_partial", "after_claim"]
)
def test_v2_crash_boundary_never_reuses_reserved_bytes(
    failed_v1, monkeypatch, boundary
):
    context, value, *_ = failed_v1
    prior = original_inventory(context)
    original_create = cp.ArtifactStore._create
    key_name = cp.ArtifactStore._name(
        cp.failed_candidate_frontier_key(context), "reservation"
    )

    def crash(self, name, raw):
        if boundary == "fresh_reservation" and self.root.name == "successor":
            original_create(self, name, raw)
            raise RuntimeError("crash")
        if (
            boundary == "claim_partial"
            and self.root == context.prior_store.root
            and name == key_name
        ):
            original_create(self, name, b"{")
            raise RuntimeError("crash")
        original_create(self, name, raw)
        if (
            boundary == "after_claim"
            and self.root == context.prior_store.root
            and name == key_name
        ):
            raise RuntimeError("crash")

    monkeypatch.setattr(cp.ArtifactStore, "_create", crash)
    with pytest.raises(RuntimeError, match="crash"):
        run_recovery(failed_v1)
    assert original_inventory(context) == prior
    fresh = context.prior_store.root.parent / "successor"
    assert (
        fresh / cp.ArtifactStore._name(cp.request_digest(value), "reservation")
    ).is_file()
    assert (context.prior_store.root / key_name).exists() is (
        boundary != "fresh_reservation"
    )
    if boundary != "fresh_reservation":
        with pytest.raises(ContractError):
            cp.verify_failed_candidate_frontier(context, value)


def test_v2_future_ordinary_predecessor_dispatches_receipt(failed_v1):
    context, value, *_ = failed_v1
    fresh, host, checksum = run_recovery(failed_v1)
    following = request()
    following["source"] = value["target"]
    following["previous_receipt_digest"] = checksum
    following["plan_digest"] = cp.transition_plan_digest(following)
    cp.verify_predecessor(
        following,
        store=fresh,
        recovery={},
        failed_candidate_contexts={context.context_digest: context},
    )
    with pytest.raises(ContractError, match="failed_candidate_context_missing"):
        cp.verify_predecessor(following, store=fresh, recovery={})


@pytest.mark.parametrize(
    "failure",
    [
        "failed-candidate-rebound",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "routing-restored",
    ],
)
def test_v2_suffix_failure_is_contained_and_claim_stays_spent(failed_v1, failure):
    context, value, *_ = failed_v1
    before = original_inventory(context)
    with pytest.raises(RuntimeError, match=failure):
        run_recovery(failed_v1, fail=failure)
    assert original_inventory(context) == before
    assert context.prior_store.read(
        cp.failed_candidate_frontier_key(context), kind="reservation"
    )
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "original_claim",
        "reservation",
        "historical_report",
        "historical_window",
        "fence_lineage",
        "failure",
        "quiescence",
        "measurement",
    ],
)
def test_v2_retained_history_cannot_be_re_pinned_into_eligibility(failed_v1, mutation):
    context, value, *_ = failed_v1
    if mutation == "original_claim":
        context = replace(context, original_frontier_claim_digest="sha256:" + "e" * 64)
    elif mutation == "reservation":
        path = context.prior_store.root / cp.ArtifactStore._name(
            cp.request_digest(context.request), "reservation"
        )
        document = cp.read_json(path.read_bytes())
        document["host_nonce"] = "e" * 64
        path.write_bytes(canonical_json(document))
    elif mutation == "historical_report":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization, verification_bytes=b"[]"
            ),
        )
    elif mutation == "historical_window":
        context = replace(
            context,
            historical_authorization=replace(
                context.historical_authorization, execution_window_end=NOW
            ),
        )
    elif mutation == "fence_lineage":
        changed = replace(context.proof, prior_grants=frozenset())
        context.prior_store.put(canonical_json(changed.to_document()))
        context = replace(context, proof=changed)
    elif mutation == "failure":
        evidence = dict(context.evidence)
        evidence["failure"] = evidence["inspection"]
        context = replace(context, evidence=evidence)
    elif mutation == "quiescence":
        context = replace(context, quiescence_digest=context.evidence["failure"])
    else:
        document = cp.read_json(context.prior_store.read(context.quiescence_digest))
        snapshot = cp.read_json(context.prior_store.read(document["after_digest"]))
        snapshot["measurement"]["relations"][0][2] += 1
        checksum = context.prior_store.put(canonical_json(snapshot))
        document.update(before_digest=checksum, after_digest=checksum)
        context = replace(
            context, quiescence_digest=context.prior_store.put(canonical_json(document))
        )
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize(
    "partial", ["successor_claim", "unknown_name", "receipt", "other_reservation"]
)
def test_v2_partial_and_unknown_store_entries_are_not_a_frontier(failed_v1, partial):
    context, value, *_ = failed_v1
    if partial == "successor_claim":
        name = cp.ArtifactStore._name(
            cp.failed_candidate_frontier_key(context), "reservation"
        )
    elif partial == "other_reservation":
        name = cp.ArtifactStore._name("sha256:" + "d" * 64, "reservation")
    elif partial == "receipt":
        name = cp.ArtifactStore._name("sha256:" + "d" * 64, "receipt")
    else:
        name = "attempt-closeout.PARTIAL"
    (context.prior_store.root / name).write_bytes(b"{")
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(context, value)


@pytest.mark.parametrize(
    "kind",
    ["candidate-ready", "acl-restored", "full-ready", "routing-restored", "unknown"],
)
def test_v2_later_or_unknown_artifact_refuses_even_if_inventory_is_re_pinned(
    failed_v1, kind
):
    context, value, *_ = failed_v1
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
    changed = replace(
        context,
        inventory={
            p.name: cp.raw_digest(p.read_bytes())
            for p in context.prior_store.root.iterdir()
        },
    )
    with pytest.raises(ContractError):
        cp.verify_failed_candidate_frontier(changed, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_context",
        "duplicate_authorization",
        "repeated_nonce",
        "aliased_store",
        "cycle",
        "missing_spent_claim",
        "substituted_spent_claim",
    ],
)
def test_v2_duplicate_and_missing_ancestry_refused(failed_v1, mutation):
    context, value, *_ = failed_v1
    value = copy.deepcopy(value)
    if mutation == "duplicate_context":
        context = replace(context, context_digest=context.predecessor.context_digest)
        value["basis"]["context_digest"] = context.context_digest
    elif mutation == "duplicate_authorization":
        value["authorization_run_id"] = context.predecessor.request[
            "authorization_run_id"
        ]
        value["authorization_run_attempt"] = context.predecessor.request[
            "authorization_run_attempt"
        ]
    elif mutation == "repeated_nonce":
        context = replace(context, host_nonce=context.predecessor.host_nonce)
        value["basis"]["failed_host_nonce"] = context.host_nonce
    elif mutation == "aliased_store":
        context = replace(context, prior_store=context.predecessor.prior_store)
    elif mutation == "cycle":
        context = replace(context, predecessor=context)
    else:
        claim_path = context.predecessor.prior_store.root / cp.ArtifactStore._name(
            cp.failed_candidate_frontier_key(context.predecessor), "reservation"
        )
        if mutation == "missing_spent_claim":
            claim_path.unlink()
        else:
            claim_path.write_bytes(canonical_json({"substituted": True}))
    value["plan_digest"] = cp.transition_plan_digest(value)
    with pytest.raises((ContractError, FileNotFoundError)):
        cp.verify_failed_candidate_frontier(context, value)


def test_v2_frontier_key_does_not_add_protocol_domain(failed_v1):
    context, *_ = failed_v1
    # The alternate context is intentionally ineligible; choosing its protocol
    # cannot provide another reservation key for this same spent frontier.
    v1_shaped = cp.FailedCandidateContext(
        original=context.original,
        prior_store=context.prior_store,
        request=context.request,
        host_nonce=context.host_nonce,
        evidence=context.evidence,
        historical_authorization=context.historical_authorization,
        proof=context.proof,
        context_digest=digest({"alternate": "protocol"}),
        original_frontier_claim_digest=context.original_frontier_claim_digest,
        quiescence_digest=context.quiescence_digest,
        inventory=context.inventory,
    )
    assert cp.failed_candidate_frontier_key(
        v1_shaped
    ) == cp.failed_candidate_frontier_key(context)


def test_v2_duplicate_historical_authorization_context_is_refused(failed_v1):
    context, value, *_ = failed_v1
    changed = replace(
        context,
        historical_authorization=replace(
            context.historical_authorization,
            context_digest=context.predecessor.historical_authorization.context_digest,
        ),
    )
    with pytest.raises(ContractError, match="duplicate_authorization_context"):
        cp.verify_failed_candidate_frontier(changed, value)


@pytest.mark.parametrize("ancestor", ["latest", "predecessor", "original"])
def test_v2_fresh_store_cannot_alias_any_ancestor(failed_v1, ancestor):
    context, value, now, verifier, path = failed_v1
    store = {
        "latest": context.prior_store,
        "predecessor": context.predecessor.prior_store,
        "original": context.original.prior_store,
    }[ancestor]
    before = {p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()}
    host = RecoveryHost(context, store)
    with pytest.raises(ContractError, match="recovery_store_reused"):
        cp.execute_failed_candidate_recovery(
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
    assert before == {
        p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()
    }


@pytest.mark.parametrize("ancestor", ["latest", "predecessor", "original"])
def test_v2_fresh_nonce_cannot_repeat_any_ancestor(failed_v1, monkeypatch, ancestor):
    context, *_ = failed_v1
    nonce = {
        "latest": context.host_nonce,
        "predecessor": context.predecessor.host_nonce,
        "original": context.original.host_nonce,
    }[ancestor]
    monkeypatch.setattr(cp.secrets, "token_hex", lambda _: nonce)
    with pytest.raises(ContractError, match="failed_candidate_nonce_reused"):
        run_recovery(failed_v1)
    assert context.prior_store.read(
        cp.failed_candidate_frontier_key(context), kind="reservation"
    )
