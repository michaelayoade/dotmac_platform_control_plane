"""Refuse a D16 bundle conformance run that skipped or omitted a case.

Pytest exits zero when every collected test skips.  The normal migration suite
may skip the optional Foundation import, but the explicit CI lane must prove
that its four named cases actually executed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

EXPECTED = frozenset(
    {
        "test_build_bundle_produces_a_foundation_valid_manifest",
        "test_recovery_bundle_cli_handler_round_trips_through_load_manifest",
        "test_capture_dump_evidence_proves_a_real_custom_format_dump",
        "test_capture_dump_evidence_reports_a_corrupt_dump_as_unproved_not_a_refusal",
    }
)


def check_report(path: Path) -> None:
    # This is the local pytest output just written into RUNNER_TEMP by the
    # preceding CI command, not a network-supplied XML document.
    root = ElementTree.parse(path).getroot()  # noqa: S314
    cases = root.findall(".//testcase")
    names = [case.get("name") for case in cases]
    if len(cases) != len(EXPECTED) or set(names) != EXPECTED:
        raise ValueError(
            f"D16 bundle conformance collected {names!r}, expected "
            f"{sorted(EXPECTED)!r} exactly once"
        )
    for case in cases:
        if any(
            case.find(outcome) is not None
            for outcome in ("skipped", "failure", "error")
        ):
            raise ValueError(f"D16 bundle conformance did not pass: {case.get('name')}")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_d16_bundle_junit.py JUNIT_XML")
    try:
        check_report(Path(sys.argv[1]))
    except (OSError, ElementTree.ParseError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print("D16 bundle conformance: all four named tests passed without skips")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
