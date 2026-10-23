"""Existing CP authority admits attributed, campaign-bound machine evidence.

This owner neither executes host probes nor creates human acceptance/signoff.
"""

from __future__ import annotations

import ipaddress
import os
import stat
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict, TypeGuard, cast
from uuid import UUID

from sqlalchemy.orm import Session

from . import contracts as c
from . import gate_evidence as g
from .models import KeyRecord, Receipt

if TYPE_CHECKING:
    from .service import DeployAgentService


class CampaignScope(TypedDict):
    context: g.GateContext
    actor_admin_ids: list[g.UUIDText]
    host_public_key_sha256: c.Digest
    candidates: list[c.Plan]
    restore_source_identity: c.BoundedText
    restore_test_host_identity: c.BoundedText
    oidc_main_run_id: int
    oidc_negative_run_id: int
    oidc_main_sha256: c.Digest
    oidc_negative_sha256: c.Digest
    restore_bundle_sha256: c.Digest
    restore_capture_sha256: c.Digest
    restore_inventory_sha256: c.Digest
    source_preparation_sha256: c.Digest
    egress_hostname: c.BoundedText
    egress_disallowed_address: c.BoundedText
    egress_disallowed_port: int
    observation_not_before: str
    prior_evidence_sha256: c.Digest | None


class CommandRecord(TypedDict):
    fingerprint: c.Digest
    actor_admin_id: g.UUIDText
    evidence_path: c.BoundedText
    scope: CampaignScope


def scope_bytes(value: object, *, historical: bool = False) -> bytes:
    """Validate once and retain immutable canonical public configuration bytes."""
    c._shape(value, CampaignScope)
    scope = cast(CampaignScope, value)
    context = scope["context"]
    c.require(historical or context["phase"] != "next_morning", "retired_phase")
    c.require(
        bool(scope["actor_admin_ids"]) and bool(scope["candidates"]),
        "campaign_configuration",
    )
    c.require(
        len(set(scope["actor_admin_ids"])) == len(scope["actor_admin_ids"]),
        "campaign_configuration",
    )
    c.require(
        len(set(context["action_refs"])) == len(context["action_refs"])
        and bool(context["action_refs"]),
        "campaign_configuration",
    )
    c.require(
        c.timestamp(scope["observation_not_before"]) < c.timestamp(context["deadline"]),
        "campaign_configuration",
    )
    c.require(
        (context["phase"] == "initial") == (context["prior_run_id"] is None),
        "campaign_configuration",
    )
    c.require(
        (context["prior_run_id"] is None) == (scope["prior_evidence_sha256"] is None),
        "campaign_configuration",
    )
    c.require(
        scope["oidc_main_run_id"] > 0
        and scope["oidc_negative_run_id"] > 0
        and scope["oidc_main_run_id"] != scope["oidc_negative_run_id"],
        "campaign_configuration",
    )
    c.require(
        c.timestamp(context["deadline"]) - c.timestamp(scope["observation_not_before"])
        <= timedelta(hours=24),
        "campaign_configuration",
    )
    for plan in scope["candidates"]:
        c.require(
            plan["product"] == "dotmac_sub"
            and plan["environment"] == "staging"
            and context["deployment_ref"] == f"dotmac_sub/staging/{plan['host']}",
            "candidate_scope",
        )
        c.require(
            plan["build_run_id"] > 0 and plan["evidence_run_id"] > 0, "candidate_scope"
        )
        c.plan_digest(plan)
    return c.canonical_json(scope)


def load_scope(path: str) -> bytes:
    """Root-owned regular public scope; root-protected canonical parent chain."""
    target = Path(path)
    try:
        c.require(
            target.is_absolute() and target.resolve() == target, "campaign_permissions"
        )
        for parent in target.parents:
            info = parent.stat()
            c.require(
                info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                "campaign_permissions",
            )
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            c.require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022,
                "campaign_permissions",
            )
            raw = source.read(262145)
        c.require(len(raw) <= 262144, "campaign_configuration")
        return scope_bytes(c.read_json(raw))
    except OSError:
        raise c.ContractError("campaign_unavailable") from None


def evidence_path(request: g.GateEvidence) -> str:
    date = c.timestamp(request["deadline"]).date().isoformat()
    return f"gate0/{date}/{request['run_id']}/evidence.json"


def command_path(request: g.GateEvidence) -> str:
    return f"gate0/commands/{request['command_id']}.json"


def addition_commit(owner: DeployAgentService, path: str) -> str:
    commits = (
        owner.ledger.git("log", "--format=%H", "--diff-filter=A", "--", path)
        .decode()
        .splitlines()
    )
    c.require(len(commits) == 1, "ledger_identity")
    return commits[0]


def is_envelope(value: object) -> TypeGuard[c.Envelope]:
    c._shape(value, c.Envelope)
    return True


def is_key_record(value: object) -> TypeGuard[KeyRecord]:
    c._shape(value, KeyRecord)
    return True


def enrolled_key(
    owner: DeployAgentService, request: g.GateEvidence, *, before: str | None = None
) -> KeyRecord:
    key = None
    for path, event in owner.ledger.events():
        if path == before:
            break
        if path.startswith("keys/") and event["key_id"] == request["host_key_id"]:
            key = event
    c.require(
        key is not None
        and key["state"] == "active"
        and key["deployment_ref"] == request["deployment_ref"],
        "host_key_inactive",
    )
    if not is_key_record(key):
        raise c.ContractError("host_key_inactive")
    return key


def healthy(observation: g.HostObservation, *, passed: bool = True) -> None:
    c.timestamp(observation["observed_at"])
    c.require(observation["executor_count"] >= 0, "observation_mismatch")
    health = observation["health"]
    for check in (health["live"], health["ready"]):
        c.timestamp(check["checked_at"])
    if not passed:
        return
    background = health["background"]
    c.require(
        health["live"]["status"] == health["ready"]["status"] == 200
        and health["ready"]["body_status"] == "ready"
        and background["celery_inspect_ok"]
        and background["restart_counts_zero"]
        and {"app", "celery-worker"} <= set(background["containers"])
        and all(status == "running" for status in background["containers"].values()),
        "observation_mismatch",
    )
    observed = observation["observed"]
    c.require(
        observed["running_image"] is not None
        and observed["running_image"] == observed["pinned_image"]
        and observed["running_revision_label"] is not None
        and observed["running_revision_label"] == observed["pinned_git_sha"],
        "observation_mismatch",
    )


def observed_interval(
    before: g.HostObservation,
    after: g.HostObservation,
    scope: CampaignScope,
    *,
    passed: bool = True,
) -> None:
    healthy(before, passed=passed)
    healthy(after, passed=passed)
    for observation in (before, after):
        for field in ("live", "ready"):
            c.require(
                c.timestamp(scope["observation_not_before"])
                <= c.timestamp(observation["health"][field]["checked_at"])
                <= c.timestamp(observation["observed_at"]),
                "observation_interval",
            )
    c.require(
        c.timestamp(scope["observation_not_before"])
        <= c.timestamp(before["observed_at"])
        <= c.timestamp(after["observed_at"])
        <= c.timestamp(scope["context"]["deadline"]),
        "observation_interval",
    )


def report_reference(
    owner: DeployAgentService,
    request: g.GateEvidence,
    ref: g.RefusalEvidence | g.TransitionEvidence,
    key: KeyRecord,
    scope: CampaignScope,
    *,
    before: str | None = None,
) -> tuple[c.AppliedState, c.DesiredState, c.Envelope, str]:
    """Resolve exact signed bytes from derived paths, never caller-supplied paths."""
    classification = ref.get("classification", "accepted")
    if classification == "accepted":
        path = f"applied/{request['deployment_ref']}/{ref['report_id']}.json"
        raw = owner.ledger.read(path)
        if raw is None:
            raise c.ContractError("evidence_missing")
        envelope_value: object = c.read_json(raw)
    else:
        path = f"quarantine/{ref['report_sha256'][7:]}.json"
        raw = owner.ledger.read(path)
        if raw is None:
            raise c.ContractError("evidence_missing")
        record = c.read_json(raw)
        c.exact(record, {"code", "envelope"})
        c.require(
            record["code"] == "nonce_replay"
            and dict(ref).get("case") == "nonce_replay",
            "evidence_classification",
        )
        envelope_value = record["envelope"]
    if not is_envelope(envelope_value):
        raise c.ContractError("evidence_substitution")
    envelope = envelope_value
    c.require(
        c.digest(envelope) == ref["report_sha256"]
        and envelope["key_id"] == request["host_key_id"],
        "evidence_substitution",
    )
    report = c.validate_applied(c.verify(c.APPLIED, envelope, key["public_key_b64"]))
    c.require(
        report["host_key_id"] == request["host_key_id"]
        and report["report_id"] == ref["report_id"]
        and report["deployment_ref"] == request["deployment_ref"]
        and report["desired"]["nonce"] == ref["nonce"],
        "evidence_substitution",
    )
    desired_path = f"desired/{request['deployment_ref']}/{ref['nonce']}.json"
    # Nonces are base64url contract values; no caller-controlled filesystem traversal.
    c.require(
        "/" not in ref["nonce"] and ".." not in ref["nonce"], "evidence_substitution"
    )
    desired_raw = owner.ledger.read(desired_path)
    if desired_raw is None:
        raise c.ContractError("desired_unknown")
    desired_envelope = c.read_json(desired_raw)
    if not is_envelope(desired_envelope):
        raise c.ContractError("evidence_substitution")
    desired = c.validate_desired(
        c.verify(c.DESIRED, desired_envelope, owner.signer.public_key_b64)
    )
    c.require(
        all(
            dict(desired)[field] == value for field, value in report["desired"].items()
        ),
        "evidence_substitution",
    )
    c.require(c.plan_document(desired) in scope["candidates"], "candidate_scope")
    if before:
        for record_path, record_raw in ((path, raw), (desired_path, desired_raw)):
            commit = addition_commit(owner, record_path)
            owner.ledger.git("merge-base", "--is-ancestor", commit, before)
            c.require(
                owner.ledger.git("show", f"{before}:{record_path}") == record_raw,
                "evidence_substitution",
            )
    return report, desired, desired_envelope, path


def signed_interval(
    report: c.AppliedState,
    desired: c.DesiredState,
    ref: g.RefusalEvidence | g.TransitionEvidence,
    scope: CampaignScope,
) -> None:
    """New daemon evidence must be signed during its actual campaign attempt."""
    lower, upper = (
        c.timestamp(scope["observation_not_before"]),
        c.timestamp(scope["context"]["deadline"]),
    )
    observed = c.timestamp(report["observed_at"])
    c.require(
        lower <= c.timestamp(desired["issued_at"]) <= observed <= upper
        and c.timestamp(ref["before"]["observed_at"])
        <= observed
        <= c.timestamp(ref["after"]["observed_at"]),
        "signed_observation_interval",
    )


def verify_refusals(
    owner: DeployAgentService,
    request: g.GateEvidence,
    proof: g.ProofOutcome,
    key: KeyRecord,
    scope: CampaignScope,
    *,
    before: str | None = None,
) -> None:
    refs = proof["refusals"]
    for ref in refs:
        c.require(ref["case"] == ref["expected_code"], "evidence_substitution")
    passed = proof["outcome"] == "pass"
    c.require(len({ref["case"] for ref in refs}) == len(refs), "proof_failed")
    if passed:
        c.require(
            len(refs) == 3
            and {ref["case"] for ref in refs}
            == {"bad_signature", "nonce_replay", "rollback_digest"},
            "proof_failed",
        )
    for ref in refs:
        report, desired, envelope, path = report_reference(
            owner, request, ref, key, scope, before=before
        )
        historical_replay = (
            ref["case"] == "nonce_replay"
            and ref["classification"] == "accepted"
            and report["disposition"] == "applied"
            and report["reason"] is None
        )
        if not historical_replay:
            signed_interval(report, desired, ref, scope)
        submitted = dict(envelope)
        if ref["case"] == "bad_signature":
            signature = bytearray(c.unb64(envelope["signature_b64"]))
            signature[0] ^= 1
            submitted["signature_b64"] = c.b64(bytes(signature))
        c.require(c.digest(submitted) == ref["submitted_sha256"], "submitted_mismatch")
        owner.ledger.git(
            "merge-base", "--is-ancestor", ref["ledger_commit"], before or "HEAD"
        )
        c.require(
            owner.ledger.git("show", f"{ref['ledger_commit']}:{path}")
            == owner.ledger.read(path),
            "receipt_mismatch",
        )
        c.require(
            c.timestamp(ref["after"]["observed_at"])
            <= c.timestamp(ref["cleanup_observed_at"])
            <= c.timestamp(request["deadline"]),
            "observation_interval",
        )
        observed_interval(ref["before"], ref["after"], scope, passed=passed)
        if passed:
            c.require(
                ref["normal_poll_journal_start"] != ref["normal_poll_journal_end"]
                and c.timestamp(ref["after"]["observed_at"])
                <= c.timestamp(ref["cleanup_observed_at"])
                <= c.timestamp(request["deadline"]),
                "cleanup_failed",
            )
            c.require(
                ref["case"] == ref["expected_code"] == ref["observed_code"]
                and ref["before"]["executor_count"] == ref["after"]["executor_count"]
                and ref["before"]["observed"] == ref["after"]["observed"]
                and ref["journal_start"] != ref["journal_end"],
                "proof_failed",
            )
        if ref["case"] == "nonce_replay":
            if passed:
                c.require(
                    c.timestamp(desired["issued_at"])
                    <= c.timestamp(ref["before"]["observed_at"])
                    <= c.timestamp(ref["after"]["observed_at"])
                    < c.timestamp(desired["expires_at"]),
                    "replay_expired",
                )
                c.require(
                    ref["classification"] == "accepted"
                    and report["disposition"] == "applied"
                    and report["reason"] is None,
                    "evidence_classification",
                )
        else:
            c.require(
                ref["classification"] == "accepted"
                and report["disposition"] == "refused"
                and report["reason"] == ref["observed_code"],
                "evidence_classification",
            )


def verify_transition(
    owner: DeployAgentService,
    request: g.GateEvidence,
    ref: g.TransitionEvidence,
    key: KeyRecord,
    scope: CampaignScope,
    *,
    passed: bool = True,
    before: str | None = None,
) -> None:
    report, desired, envelope, path = report_reference(
        owner, request, ref, key, scope, before=before
    )
    c.require(
        desired["source_revision"] == request["source_revision"]
        and desired["source_tree"] == request["source_tree"],
        "source_target_mismatch",
    )
    signed_interval(report, desired, ref, scope)
    c.require(
        c.timestamp(ref["before"]["observed_at"]) <= c.timestamp(desired["issued_at"]),
        "signed_observation_interval",
    )
    c.require(
        c.digest(envelope) == ref["desired_sha256"]
        and ref["source_preparation_sha256"] == scope["source_preparation_sha256"],
        "evidence_substitution",
    )
    if passed:
        c.require(
            report["disposition"] == "applied"
            and desired["from_image_digest"] != desired["image_digest"]
            and ref["signatures_verified"]
            and ref["runners_stopped"],
            "proof_failed",
        )
    observed_interval(ref["before"], ref["after"], scope, passed=passed)
    expected_before = desired["image_reference"] + "@" + desired["from_image_digest"]
    if passed:
        c.require(
            ref["before"]["observed"]["running_image"] == expected_before
            and ref["after"]["observed"] == report["observed"]
            and ref["after"]["executor_count"] == ref["before"]["executor_count"] + 1,
            "observation_mismatch",
        )
    receipt: Receipt = {
        "deployment_ref": request["deployment_ref"],
        "report_id": report["report_id"],
        "path": path,
        "fingerprint": ref["report_sha256"],
    }
    c.require(c.digest(receipt) == ref["receipt_sha256"], "receipt_mismatch")
    owner.ledger.git(
        "merge-base", "--is-ancestor", ref["ledger_commit"], before or "HEAD"
    )
    c.require(
        owner.ledger.git("show", f"{ref['ledger_commit']}:{path}")
        == owner.ledger.read(path),
        "receipt_mismatch",
    )
    desired_path = f"desired/{request['deployment_ref']}/{ref['nonce']}.json"
    c.require(
        owner.ledger.git("show", f"{ref['ledger_commit']}:{desired_path}")
        == c.canonical_json(envelope),
        "receipt_mismatch",
    )


def verify_egress(
    evidence: g.EgressEvidence,
    transition: g.TransitionEvidence,
    scope: CampaignScope,
    *,
    passed: bool = True,
) -> None:
    c.require(
        evidence["hostname"] == scope["egress_hostname"]
        and evidence["disallowed_address"] == scope["egress_disallowed_address"]
        and evidence["disallowed_port"] == scope["egress_disallowed_port"],
        "egress_binding",
    )
    c.require(
        evidence["transition_report_id"] == transition["report_id"]
        and evidence["transition_report_sha256"] == transition["report_sha256"]
        and evidence["probe_rule_handle"] > 0
        and 1 <= evidence["probe_source_port"] <= 65535
        and 1 <= evidence["disallowed_port"] <= 65535
        and evidence["counter_before"] >= 0
        and evidence["counter_after"] >= evidence["counter_before"],
        "egress_binding",
    )
    if passed:
        c.require(
            evidence["terminal_drop"]
            and evidence["counter_after"] > evidence["counter_before"]
            and evidence["fresh_connection_failed"]
            and evidence["allowed_deployment_succeeded"]
            and evidence["probe_rule_removed"],
            "proof_failed",
        )
    started, finished = (
        c.timestamp(evidence["started_at"]),
        c.timestamp(evidence["finished_at"]),
    )
    c.require(
        c.timestamp(scope["observation_not_before"])
        <= started
        <= c.timestamp(transition["after"]["observed_at"])
        <= finished
        <= c.timestamp(scope["context"]["deadline"])
        and 0 <= evidence["elapsed_seconds"] <= (finished - started).total_seconds(),
        "observation_interval",
    )
    records = (evidence["before"], evidence["after"])
    for values in records:
        c.require(len(values) <= 32, "dns_evidence")
        if passed:
            c.require(
                bool(values) and {r["family"] for r in values} == {"A", "AAAA"},
                "dns_evidence",
            )
        for record in values:
            c.require(
                0 < record["ttl"] <= 86400
                and 0 <= record["kernel_expires_ms"] <= record["kernel_timeout_ms"],
                "dns_evidence",
            )
            if passed:
                c.require(
                    record["ttl"] <= 300
                    and 0
                    < record["kernel_expires_ms"]
                    <= record["kernel_timeout_ms"]
                    <= (record["ttl"] + 2) * 1000,
                    "dns_evidence",
                )
            try:
                address = ipaddress.ip_address(record["address"])
            except ValueError:
                raise c.ContractError("dns_evidence") from None
            c.require(
                address.version == (4 if record["family"] == "A" else 6), "dns_evidence"
            )
    expired = c.timestamp(evidence["old_expiry_observed_at"])
    c.require(started <= expired <= finished, "observation_interval")
    if passed:
        c.require(
            expired
            <= started + timedelta(seconds=max(r["ttl"] for r in records[0]) + 3)
            and evidence["elapsed_seconds"] >= max(r["ttl"] for r in records[0]),
            "dns_expiry",
        )
        for family in ("A", "AAAA"):
            c.require(
                {
                    ipaddress.ip_address(r["address"])
                    for r in records[0]
                    if r["family"] == family
                }.isdisjoint(
                    ipaddress.ip_address(r["address"])
                    for r in records[1]
                    if r["family"] == family
                ),
                "dns_evidence",
            )
    try:
        ipaddress.ip_address(evidence["disallowed_address"])
    except ValueError:
        raise c.ContractError("dns_evidence") from None


def terminal_verdict(request: g.GateEvidence) -> Literal["PASS", "FAIL"]:
    required = {1, 2, 3, 4, 5} if request["phase"] == "initial" else {2, 3, 4}
    passed = all(p["outcome"] == "pass" for p in request["proofs"])
    c.require(
        not passed or {p["proof"] for p in request["proofs"]} == required, "proof_set"
    )
    c.require({p["proof"] for p in request["proofs"]} <= required, "proof_set")
    return "PASS" if passed else "FAIL"


def verify_proofs(
    owner: DeployAgentService,
    request: g.GateEvidence,
    scope: CampaignScope,
    *,
    before: str | None = None,
) -> None:
    terminal_verdict(request)
    key = enrolled_key(
        owner, request, before=evidence_path(request) if before else None
    )
    c.require(
        g.raw_digest(c.unb64(key["public_key_b64"])) == scope["host_public_key_sha256"],
        "host_key_mismatch",
    )
    transitions = []
    for proof in request["proofs"]:
        passed = proof["outcome"] == "pass"
        if proof["proof"] == 1 and proof["oidc"] is not None:
            evidence = proof["oidc"]
            c.require(
                evidence["main_run_id"] == scope["oidc_main_run_id"]
                and evidence["negative_run_id"] == scope["oidc_negative_run_id"]
                and evidence["main_sha256"] == scope["oidc_main_sha256"]
                and evidence["negative_sha256"] == scope["oidc_negative_sha256"],
                "evidence_substitution",
            )
            if passed:
                c.require(
                    evidence["main_accepted"] and evidence["negative_refused"],
                    "proof_failed",
                )
        elif proof["proof"] == 2:
            verify_refusals(owner, request, proof, key, scope, before=before)
        elif proof["proof"] in {3, 4}:
            if proof["transition"] is not None:
                verify_transition(
                    owner,
                    request,
                    proof["transition"],
                    key,
                    scope,
                    passed=passed,
                    before=before,
                )
                transitions.append(proof["transition"])
            if proof["proof"] == 4 and proof["egress"] is not None:
                if proof["transition"] is None:
                    raise c.ContractError("evidence_missing")
                verify_egress(
                    proof["egress"], proof["transition"], scope, passed=passed
                )
        elif proof["proof"] == 5 and proof["restore"] is not None:
            restore_evidence = proof["restore"]
            c.require(
                restore_evidence["source_identity"] == scope["restore_source_identity"]
                and restore_evidence["test_host_identity"]
                == scope["restore_test_host_identity"]
                and restore_evidence["bundle_sha256"] == scope["restore_bundle_sha256"]
                and restore_evidence["capture_sha256"]
                == scope["restore_capture_sha256"]
                and restore_evidence["source_inventory_sha256"]
                == scope["restore_inventory_sha256"],
                "evidence_substitution",
            )
            if passed:
                c.require(
                    restore_evidence["no_ddl_enforced"]
                    and restore_evidence["source_parity"] is True
                    and restore_evidence["scratch_absent"] is True
                    and restore_evidence["restored_inventory_sha256"] is not None
                    and restore_evidence["source_inventory_sha256"]
                    == restore_evidence["restored_inventory_sha256"],
                    "proof_failed",
                )
            c.require(
                c.timestamp(scope["observation_not_before"])
                <= c.timestamp(restore_evidence["capture_started_at"])
                <= c.timestamp(restore_evidence["capture_finished_at"])
                <= c.timestamp(request["deadline"]),
                "observation_interval",
            )
    if len(transitions) == 2:
        c.require(transitions[0] == transitions[1], "transition_mismatch")
    if terminal_verdict(request) == "PASS":
        transition = transitions[0]
        refusals = next(p["refusals"] for p in request["proofs"] if p["proof"] == 2)
        replay = next(ref for ref in refusals if ref["case"] == "nonce_replay")
        c.require(
            all(
                dict(replay)[field] == dict(transition)[field]
                for field in ("nonce", "report_id", "report_sha256")
            ),
            "replay_transition_mismatch",
        )
        c.require(
            c.timestamp(transition["after"]["observed_at"])
            <= c.timestamp(replay["before"]["observed_at"]),
            "replay_order",
        )


def verify_prior(
    owner: DeployAgentService,
    request: g.GateEvidence,
    scope: CampaignScope,
    *,
    before: str | None = None,
) -> None:
    if request["phase"] == "initial":
        return
    matches = [
        (path, raw)
        for path, raw in owner.ledger.records("gate0/")
        if path.endswith("/evidence.json")
        and c.read_json(raw)["run_id"] == request["prior_run_id"]
    ]
    c.require(
        len(matches) == 1
        and g.raw_digest(matches[0][1]) == scope["prior_evidence_sha256"],
        "prior_run_missing",
    )
    prior = g.validate(c.read_json(matches[0][1]), historical=True)
    c.require(
        prior["phase"] == "initial"
        and terminal_verdict(prior) == "PASS"
        and all(
            dict(prior)[key] == dict(request)[key]
            for key in (
                "deployment_ref",
                "host_key_id",
                "tool_revision",
            )
        )
        and (
            request["phase"] != "next_morning"
            or c.timestamp(prior["deadline"]).date()
            < c.timestamp(request["deadline"]).date()
        ),
        "prior_run_mismatch",
    )
    if before:
        owner.ledger.git(
            "merge-base", "--is-ancestor", addition_commit(owner, matches[0][0]), before
        )
    if terminal_verdict(request) == "FAIL":
        return
    prior_transition = next(p["transition"] for p in prior["proofs"] if p["proof"] == 3)
    transition = next(p["transition"] for p in request["proofs"] if p["proof"] == 3)
    c.require(
        request["source_revision"] != prior["source_revision"]
        and request["source_tree"] != prior["source_tree"],
        "source_reused",
    )
    if transition is None or prior_transition is None:
        raise c.ContractError("evidence_missing")
    c.require(transition["nonce"] != prior_transition["nonce"], "transition_replay")
    c.require(
        transition["after"]["observed"]["running_image"]
        != prior_transition["after"]["observed"]["running_image"],
        "target_reused",
    )
    c.require(
        transition["before"]["observed"]["running_image"]
        == prior_transition["after"]["observed"]["running_image"],
        "image_discontinuity",
    )


def history(owner: DeployAgentService) -> None:
    """Validate retained gate pairs, actor attribution and original crypto joins."""
    events = dict(owner.ledger.events())
    for path, value in events.items():
        if path.startswith("gate0/commands/"):
            c._shape(value, CommandRecord)
            command = cast(CommandRecord, value)
            raw = owner.ledger.read(command["evidence_path"])
            if raw is None:
                raise c.ContractError("ledger_identity")
            request = g.validate(c.read_json(raw), historical=True)
            c.require(
                path == command_path(request)
                and command["evidence_path"] == evidence_path(request),
                "ledger_identity",
            )
            c.require(
                command["fingerprint"]
                == c.digest(
                    {"request": request, "actor_admin_id": command["actor_admin_id"]}
                ),
                "ledger_identity",
            )
        elif path.startswith("gate0/"):
            request = g.validate(value, historical=True)
            c.require(
                path == evidence_path(request) and command_path(request) in events,
                "ledger_identity",
            )
            c._shape(events[command_path(request)], CommandRecord)
            command = cast(CommandRecord, events[command_path(request)])
            scope = cast(
                CampaignScope,
                c.read_json(scope_bytes(command["scope"], historical=True)),
            )
            authorize(request, scope, UUID(command["actor_admin_id"]))
            commit = addition_commit(owner, path)
            c.require(
                addition_commit(owner, command_path(request)) == commit,
                "ledger_identity",
            )
            verify_proofs(owner, request, scope, before=commit)
            verify_prior(owner, request, scope, before=commit)


def authorize(
    request: g.GateEvidence, scope: CampaignScope, actor_admin_id: UUID
) -> None:
    c.require(str(actor_admin_id) in scope["actor_admin_ids"], "campaign_actor")
    c.require(
        all(dict(request)[key] == value for key, value in scope["context"].items()),
        "campaign_scope",
    )


def admit(
    owner: DeployAgentService,
    db: Session,
    request: g.GateEvidence,
    *,
    actor_admin_id: UUID,
) -> g.PublishedReceipt:
    request = g.validate(request)
    if owner.gate_scope is None:
        raise c.ContractError("campaign_unavailable")
    scope = cast(CampaignScope, c.read_json(owner.gate_scope))
    authorize(request, scope, actor_admin_id)
    fingerprint = c.digest({"request": request, "actor_admin_id": str(actor_admin_id)})
    path, command = evidence_path(request), command_path(request)
    with owner.ledger.transaction():
        owner.validate_history()
        previous = owner.ledger.read(command)
        if previous:
            c.require(
                c.read_json(previous)["fingerprint"] == fingerprint, "command_reused"
            )
        else:
            c.require(owner.ledger.read(path) is None, "run_reused")
            c.require(
                c.timestamp(scope["observation_not_before"])
                <= owner.clock()
                <= c.timestamp(request["deadline"]),
                "campaign_expired",
            )
            verify_proofs(owner, request, scope)
            verify_prior(owner, request, scope)
            owner._record(
                db,
                {
                    path: request,
                    command: {
                        "fingerprint": fingerprint,
                        "actor_admin_id": str(actor_admin_id),
                        "evidence_path": path,
                        "scope": scope,
                    },
                },
            )
        # Projection repairs a commit->database crash also on identical retries.
        owner._record(db, {})
        evidence = owner.ledger.read(path)
        if evidence is None or evidence != c.canonical_json(request):
            raise c.ContractError("ledger_conflict")
        return {
            "run_id": request["run_id"],
            "command_sha256": c.digest(request),
            "ledger_commit": addition_commit(owner, path),
            "evidence_sha256": g.raw_digest(evidence),
            "published": True,
            "verdict": terminal_verdict(request),
            "evidence": request,
        }
