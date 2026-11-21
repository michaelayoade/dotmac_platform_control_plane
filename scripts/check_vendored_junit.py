"""Refuse a vendored-verifier run whose test set is not EXACTLY the expected one (H1).

A minimum count passes after a test is deleted and another added. This compares the
full set of `classname::name` cases and refuses any skipped, failed, errored, missing
or unexpected case. Adding a test means adding its name here, in the same change.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

DIFF = "tests.differential.test_vendored_foundation_differential"
PINS = "tests.unit.test_vendored_foundation_pins"
EXPECTED = frozenset(
    {
        f"{DIFF}::test_the_wheel_is_the_pinned_foundation_and_not_the_checkout",
        f"{DIFF}::test_same_accept_refuse_codes_and_digests_over_the_corpus",
        f"{DIFF}::test_forged_and_stale_fixtures_agree_end_to_end_with_the_signature_check",
        f"{DIFF}::test_the_differential_can_still_fail",
        f"{PINS}::test_the_pin_records_the_provisional_e5_source",
        f"{PINS}::test_exactly_the_closure_is_vendored_and_every_file_is_pinned",
        f"{PINS}::test_every_vendored_file_equals_its_pinned_digests[digest.py]",
        f"{PINS}::test_every_vendored_file_equals_its_pinned_digests[errors.py]",
        f"{PINS}::test_every_vendored_file_equals_its_pinned_digests[trusted_host_source.py]",
        f"{PINS}::test_the_pin_check_can_still_fail",
        f"{PINS}::test_the_closure_imports_only_itself_and_the_standard_library",
        f"{PINS}::test_step_eight_does_not_import_the_foundation_distribution",
        f"{PINS}::test_the_vendored_files_equal_the_pinned_starter_checkout",
    }
)


def check_report(path: Path) -> set[str]:
    # The local pytest output just written into RUNNER_TEMP, not network input.
    root = ElementTree.parse(path).getroot()  # noqa: S314
    ran: set[str] = set()
    for case in root.findall(".//testcase"):
        name = f"{case.get('classname')}::{case.get('name')}"
        for outcome in ("skipped", "failure", "error"):
            if case.find(outcome) is not None:
                raise ValueError(f"{name} {outcome}")
        ran.add(name)
    if ran != EXPECTED:
        raise ValueError(
            f"missing {sorted(EXPECTED - ran)}, unexpected {sorted(ran - EXPECTED)}"
        )
    return ran


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_vendored_junit.py JUNIT_XML")
    try:
        ran = check_report(Path(sys.argv[1]))
    except (OSError, ElementTree.ParseError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(f"{len(ran)} vendored-verifier cases passed, exactly the expected set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
