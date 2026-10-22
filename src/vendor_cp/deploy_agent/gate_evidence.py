"""Closed public Gate0 facts and an authenticated, origin-pinned CP adapter."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal, TypedDict, cast
from uuid import UUID

from . import contracts as c

UUIDText = Annotated[
    str, r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
]


class HostObservation(TypedDict):
    observed_at: str
    observed: c.Observed
    health: c.Health
    executor_count: int


class RefusalEvidence(TypedDict):
    case: Literal["bad_signature", "nonce_replay", "rollback_digest"]
    submitted_sha256: c.Digest
    nonce: c.BoundedText
    report_id: UUIDText
    report_sha256: c.Digest
    classification: Literal["accepted", "quarantined"]
    expected_code: Literal["bad_signature", "nonce_replay", "rollback_digest"]
    observed_code: Literal["bad_signature", "nonce_replay", "rollback_digest"]
    journal_start: c.BoundedText
    journal_end: c.BoundedText
    normal_poll_journal_start: c.BoundedText
    normal_poll_journal_end: c.BoundedText
    cleanup_observed_at: str
    ledger_commit: c.Revision
    before: HostObservation
    after: HostObservation


class TransitionEvidence(TypedDict):
    nonce: c.BoundedText
    desired_sha256: c.Digest
    source_preparation_sha256: c.Digest
    report_id: UUIDText
    report_sha256: c.Digest
    receipt_sha256: c.Digest
    ledger_commit: c.Revision
    before: HostObservation
    after: HostObservation
    signatures_verified: bool
    runners_stopped: bool


class DNSRecord(TypedDict):
    family: Literal["A", "AAAA"]
    address: c.BoundedText
    ttl: int
    kernel_timeout_ms: int
    kernel_expires_ms: int


class EgressEvidence(TypedDict):
    hostname: c.BoundedText
    started_at: str
    old_expiry_observed_at: str
    finished_at: str
    transition_report_id: UUIDText
    transition_report_sha256: c.Digest
    probe_rule_handle: int
    probe_source_port: int
    probe_rule_removed: bool
    before: list[DNSRecord]
    after: list[DNSRecord]
    elapsed_seconds: int
    kernel_rules_sha256: c.Digest
    terminal_drop: bool
    counter_before: int
    counter_after: int
    disallowed_address: c.BoundedText
    disallowed_port: int
    fresh_connection_failed: bool
    allowed_deployment_succeeded: bool


class RestoreEvidence(TypedDict):
    source_identity: c.BoundedText
    test_host_identity: c.BoundedText
    bundle_sha256: c.Digest
    capture_sha256: c.Digest
    capture_started_at: str
    capture_finished_at: str
    source_inventory_sha256: c.Digest
    restored_inventory_sha256: c.Digest | None
    no_ddl_enforced: bool
    source_parity: bool | None
    scratch_absent: bool | None


class OIDCEvidence(TypedDict):
    main_run_id: int
    negative_run_id: int
    main_sha256: c.Digest
    negative_sha256: c.Digest
    main_accepted: bool
    negative_refused: bool


class ProofOutcome(TypedDict):
    proof: Literal[1, 2, 3, 4, 5]
    outcome: Literal["pass", "fail"]
    failure_code: Literal[
        "none",
        "evidence_missing",
        "observation_mismatch",
        "cleanup_failed",
        "transport_failed",
    ]
    cleanup: Literal["pass", "fail"]
    oidc: OIDCEvidence | None
    refusals: list[RefusalEvidence]
    transition: TransitionEvidence | None
    egress: EgressEvidence | None
    restore: RestoreEvidence | None


class GateContext(TypedDict):
    run_id: UUIDText
    phase: Literal["initial", "next_morning"]
    prior_run_id: UUIDText | None
    source_revision: c.Revision
    source_tree: c.Revision
    deployment_ref: c.BoundedText
    tool_revision: c.Revision
    host_key_id: c.Identifier
    action_refs: list[c.Identifier]
    deadline: str


class GateEvidence(GateContext):
    command_id: UUIDText
    proofs: list[ProofOutcome]


class PublishedReceipt(TypedDict):
    run_id: UUIDText
    command_sha256: c.Digest
    ledger_commit: c.Revision
    evidence_sha256: c.Digest
    published: Literal[True]
    verdict: Literal["PASS", "FAIL"]
    evidence: GateEvidence


def raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate(value: object) -> GateEvidence:
    c.require(len(c.canonical_json(value)) <= 131072)
    c._shape(value, GateEvidence)
    request = cast(GateEvidence, value)
    for key in ("run_id", "command_id", "prior_run_id"):
        if request[key] is not None:
            c.require(str(UUID(request[key])) == request[key])
    c.require((request["prior_run_id"] is None) == (request["phase"] == "initial"))
    c.require(request["prior_run_id"] != request["run_id"])
    c.require(
        1 <= len(request["action_refs"]) <= 16
        and len(set(request["action_refs"])) == len(request["action_refs"])
    )
    c.timestamp(request["deadline"])
    proofs = request["proofs"]
    c.require(
        1 <= len(proofs) <= 5 and len({p["proof"] for p in proofs}) == len(proofs)
    )
    for proof in proofs:
        c.require(len(proof["refusals"]) <= 3)
        c.require((proof["failure_code"] == "none") == (proof["outcome"] == "pass"))
        c.require(proof["cleanup"] == "pass" or proof["outcome"] == "fail")
        for field, expected in (
            ("oidc", proof["proof"] == 1),
            ("refusals", proof["proof"] == 2),
            ("transition", proof["proof"] in (3, 4)),
            ("egress", proof["proof"] == 4),
            ("restore", proof["proof"] == 5),
        ):
            present = bool(proof[field])
            c.require(not present or expected)
            if expected and not present:
                c.require(
                    proof["outcome"] == "fail"
                    and proof["failure_code"]
                    in {"evidence_missing", "transport_failed"}
                )
    return request
