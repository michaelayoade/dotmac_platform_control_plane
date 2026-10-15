"""Strict, non-authorizing inspection of E's retained case reports.

This is one source slice, not the protected harness or a receipt authenticator.
Hashes detect changed bytes; they authenticate neither producer nor assertions.
No result from this module closes Gate 0. Control evidence stays opaque; its
published verifier and lease ledger remain the sole authorization owners.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal

CASE_OUTCOMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "approved_issue_standing_consume": "succeeded",
        "consumption_replay": "refused",
        "separate_lease_withdrawal_convergence": "succeeded",
        "revoked_lease_use": "refused",
        "missing_approval": "refused",
        "withdrawn_approval": "refused",
        "wrong_plan_approval": "refused",
        "withdrawal_consumption_race": "refused",
        "missing_custody": "refused",
        "incorrect_custody": "refused",
        "stale_revoked_unknown_key": "refused",
        "trust_floor_rollback": "refused",
        "trust_refresh_failure": "refused",
        "wrong_controller_or_substituted_key": "refused",
        "repository_run_attempt_lease_target_plan_mismatch": "refused",
        "invalid_or_tampered_attestation": "refused",
        "stale_certificate_nonce_lease": "refused",
        "cross_lease_controller_reuse": "refused",
        "exchange_overwrite_concurrency_bounds": "refused",
        "restart_cancel_incomplete": "refused",
        "cleanup": "succeeded",
    }
)

# Concrete integration obligations are mapped to source in e-requirements.json.
FINALIZATION_BLOCKERS: Final = (
    "authenticated_human_decision_route",
    "controller_possession_contract",
    "adopted_transport",
    "hosted_custody_bootstrap",
    "receipt_producer_trust",
    "immutable_receipt_destination",
    "accepted_prerequisite_oracles",
)
_MAX_REPORT: Final = 128 * 1024
_MAX_EVIDENCE: Final = 8 * 1024 * 1024
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[1-9][0-9]{0,19}\Z")
_PREREQUISITES: Final = ("B", "C1", "C2", "D")


class ReportRefusal(StrEnum):
    MALFORMED = "malformed"
    SHAPE = "shape"
    BINDING = "binding"
    CASES = "cases"
    EVIDENCE = "evidence"
    INCOMPLETE = "incomplete"
    PREREQUISITES = "prerequisites"


class Gate0ReportRefused(ValueError):
    """A bounded code only; never reflects input or protected evidence."""

    def __init__(self, refusal: ReportRefusal):
        self.refusal = refusal
        super().__init__(refusal.value)


@dataclass(frozen=True, slots=True)
class InspectedCaseReport:
    """Byte consistency only. Even a protected report remains non-authorizing."""

    report_digest: str
    evidence_class: str
    unknown_prerequisites: tuple[str, ...]

    @property
    def readiness_accepted(self) -> Literal[False]:
        return False

    @property
    def finalization_blockers(self) -> tuple[str, ...]:
        return FINALIZATION_BLOCKERS


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Gate0ReportRefused(ReportRefusal.MALFORMED)
        result[key] = value
    return result


def _nonfinite(_: str) -> object:
    raise Gate0ReportRefused(ReportRefusal.MALFORMED)


def _shape(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise Gate0ReportRefused(ReportRefusal.SHAPE)
    return value


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def inspect_case_report(
    encoded: bytes,
    *,
    evidence: Mapping[str, bytes],
    expected_source_bundle_digest: str,
    expected_run: tuple[str, str, str],
) -> InspectedCaseReport:
    """Inspect exact case coverage and retained bytes against caller-pinned inputs.

    The expected inputs must come from the reviewer's frozen source/run packet,
    independently of this report. `protected_live` is an asserted evidence class,
    not proof of origin. Prerequisite digest references are also assertions until
    their owners supply accepted oracles. This deliberately offers no receipt
    writer, signature adapter, runtime default or readiness-PASS return value.
    """
    if type(encoded) is not bytes or len(encoded) > _MAX_REPORT:
        raise Gate0ReportRefused(ReportRefusal.MALFORMED)
    try:
        document = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_nonfinite,
        )
    except (ValueError, UnicodeError, RecursionError):
        # Discard parser errors: they may reflect sensitive input in context.
        document = None
    if document is None:
        raise Gate0ReportRefused(ReportRefusal.MALFORMED)
    document = _shape(
        document,
        {
            "schema",
            "evidence_class",
            "source_bundle_digest",
            "repository_id",
            "run_id",
            "run_attempt",
            "prerequisites",
            "cases",
            "completion",
        },
    )
    if document["schema"] != "Gate0CaseReport.v1":
        raise Gate0ReportRefused(ReportRefusal.SHAPE)
    if document["evidence_class"] not in ("synthetic_ci", "protected_live"):
        raise Gate0ReportRefused(ReportRefusal.SHAPE)
    run = tuple(document[name] for name in ("repository_id", "run_id", "run_attempt"))
    if (
        not _digest(expected_source_bundle_digest)
        or document["source_bundle_digest"] != expected_source_bundle_digest
        or len(expected_run) != 3
        or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in run)
        or run != expected_run
    ):
        raise Gate0ReportRefused(ReportRefusal.BINDING)
    if document["completion"] != "complete":
        raise Gate0ReportRefused(ReportRefusal.INCOMPLETE)
    prerequisites = _shape(document["prerequisites"], set(_PREREQUISITES))
    unknown = []
    for name in _PREREQUISITES:
        prerequisite = _shape(prerequisites[name], {"state", "evidence_digest"})
        state = prerequisite["state"]
        if state not in ("accepted", "unknown", "blocked"):
            raise Gate0ReportRefused(ReportRefusal.PREREQUISITES)
        if state == "accepted":
            if not _digest(prerequisite["evidence_digest"]):
                raise Gate0ReportRefused(ReportRefusal.PREREQUISITES)
        else:
            if prerequisite["evidence_digest"] is not None:
                raise Gate0ReportRefused(ReportRefusal.PREREQUISITES)
            unknown.append(name)
    if unknown and document["evidence_class"] == "protected_live":
        raise Gate0ReportRefused(ReportRefusal.PREREQUISITES)
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_OUTCOMES):
        raise Gate0ReportRefused(ReportRefusal.CASES)
    if set(evidence) != set(CASE_OUTCOMES):
        raise Gate0ReportRefused(ReportRefusal.EVIDENCE)
    # Bound total bytes before hashing; report inspection never fetches URLs.
    if any(type(blob) is not bytes for blob in evidence.values()):
        raise Gate0ReportRefused(ReportRefusal.EVIDENCE)
    if sum(len(blob) for blob in evidence.values()) > _MAX_EVIDENCE:
        raise Gate0ReportRefused(ReportRefusal.EVIDENCE)
    seen: set[str] = set()
    for item in cases:
        case = _shape(item, {"case", "outcome", "evidence_digest"})
        name = case["case"]
        if not isinstance(name, str) or name not in CASE_OUTCOMES or name in seen:
            raise Gate0ReportRefused(ReportRefusal.CASES)
        seen.add(name)
        if case["outcome"] != CASE_OUTCOMES[name]:
            raise Gate0ReportRefused(ReportRefusal.CASES)
        blob = evidence[name]
        if (
            not blob
            or case["evidence_digest"] != "sha256:" + hashlib.sha256(blob).hexdigest()
        ):
            raise Gate0ReportRefused(ReportRefusal.EVIDENCE)
    return InspectedCaseReport(
        report_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        evidence_class=document["evidence_class"],
        unknown_prerequisites=tuple(unknown),
    )
