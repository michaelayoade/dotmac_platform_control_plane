"""Require every named installed Foundation composition case, without skips."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TypeVar
from xml.etree import ElementTree

HOST = "conformance.test_host_admission_conformance"
RENDERER = "conformance.test_candidate_renderer_real_foundation"
EXPECTED = frozenset(
    {
        (HOST, name)
        for name in (
            "test_valid_signed_attestations_complete_the_full_flow",
            "test_a_trust_policy_genuinely_derived_from_resolved_context_completes_the_full_flow",
            "test_an_invalid_signature_stops_inside_real_foundation_code",
            "test_a_sentinel_foundation_failure_has_no_fallback",
            "test_an_altered_evidence_digest_is_refused",
            "test_a_substituted_verified_host_identity_is_refused",
            "test_a_substituted_verified_candidate_root_field_is_refused",
            "test_a_state_change_between_resolve_and_admission_consumes_nothing",
            "test_expiry_between_foundation_verification_and_final_admission_is_refused",
            "test_component_observer_runs_only_after_the_admission_transaction_commits",
            "test_real_cp_v3_missing_startup_barrier_refuses_before_finalization",
            "test_real_cp_v3_held_finalizer_commits_once_and_lookup_recovers",
            "test_real_cp_v3_withdrawal_first_refuses_before_owner_finalizer",
            "test_real_cp_v3_transition_first_holds_withdrawal_through_owner_commit",
            "test_real_cp_v3_autocommit_refuses_before_owner_finalizer",
            "test_real_cp_v3_ambiguous_commit_uses_fresh_committed_lookup",
        )
    }
    | {
        (RENDERER, name)
        for name in (
            "test_synthetic_installed_renderer_preserves_exact_two_field_derivation",
            "test_synthetic_frozen_coordinates_change_real_foundation_plan[prestate]",
            "test_synthetic_frozen_coordinates_change_real_foundation_plan[profile]",
            "test_dictionary_prestate_cannot_substitute_for_foundation_value",
            "test_actual_production_descriptor_row_counts_without_executor_is_refused",
        )
    }
)


APPROVAL_EXPECTED = frozenset(
    {
        "test_real_approval_has_distinct_subject_and_one_caller_commit[deploy]",
        "test_real_approval_has_distinct_subject_and_one_caller_commit[rollback]",
        "test_withdrawal_first_refuses_approval_or_later_carried_transition[False]",
        "test_withdrawal_first_refuses_approval_or_later_carried_transition[True]",
        "test_live_carried_barrier_blocks_withdrawal_until_caller_commit",
        "test_commit_measurement_ignores_savepoint_release_but_counts_root_commit",
        "test_withdrawal_router_revokes_and_replays_exact_event_then_conflicts",
        "test_approval_exempt_plan_is_not_a_foundation_approval_subject",
        *(
            f"test_subject_refuses_missing_or_wrong_frozen_terms[changed{index}]"
            for index in range(6)
        ),
        "test_sibling_withdrawal_is_not_carried_and_does_not_revoke_selected_decision",
        *(
            f"test_owner_transition_first_holds_withdrawal_until_single_commit[{stage}]"
            for stage in ("approve", "rollout", "dispatch")
        ),
        *(
            f"test_withdrawal_first_refuses_real_owner_transition_without_signed_output[{stage}]"
            for stage in ("approve", "rollout", "dispatch")
        ),
    }
)


_Identity = TypeVar("_Identity")


def _require_exact_identities(
    identities: list[_Identity], expected: frozenset[_Identity]
) -> None:
    if len(identities) != len(expected) or frozenset(identities) != expected:
        raise ValueError(
            f"Foundation composition collected {identities!r}; expected "
            f"{sorted(map(str, expected))!r} exactly once"
        )


def check_report(path: Path, *, approval: bool = False) -> None:
    # The XML is the runner-local pytest report, never an external document.
    root = ElementTree.parse(path).getroot()  # noqa: S314
    cases = root.findall(".//testcase")
    if approval:
        cases = [
            case
            for case in cases
            if case.get("classname", "").endswith(".test_foundation_approval")
        ]
        _require_exact_identities(
            [case.get("name") for case in cases], APPROVAL_EXPECTED
        )
    else:
        _require_exact_identities(
            [(case.get("classname"), case.get("name")) for case in cases], EXPECTED
        )
    for case in cases:
        if any(
            case.find(outcome) is not None
            for outcome in ("skipped", "failure", "error")
        ):
            raise ValueError(f"Foundation composition did not pass: {case.get('name')}")


def main() -> int:
    arguments = sys.argv[1:]
    approval = bool(arguments and arguments[0] == "--approval")
    if approval:
        arguments = arguments[1:]
    if len(arguments) != 1:
        raise SystemExit(
            "usage: python -m vendor_cp.deployment.conformance_report "
            "[--approval] JUNIT_XML"
        )
    try:
        check_report(Path(arguments[0]), approval=approval)
    except (OSError, ElementTree.ParseError, ValueError) as error:
        raise SystemExit(str(error)) from error
    count = len(APPROVAL_EXPECTED if approval else EXPECTED)
    print(f"Foundation composition: all {count} named cases passed; zero skips")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
