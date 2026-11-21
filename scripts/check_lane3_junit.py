"""Refuse a Lane 3 store conformance run that skipped, failed or omitted a file.

Pytest exits zero when every collected test skips, and the Lane 3 database files
skip themselves when Foundation is not importable (the ordinary migration step has
no Foundation). The dedicated CI step sets `LANE3_REQUIRE_FOUNDATION=1`, so a missing
import fails; this checks the other half: that each named file actually executed
tests, and that none of them was skipped, failed or errored. A skipped security test
is not a passing one.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

#: The files the dedicated step runs, by JUnit `classname` prefix, and the fewest
#: cases each must contribute. The floors are deliberately far below today's counts:
#: they exist to catch a file that collected nothing, not to freeze a number.
EXPECTED_FILES = {
    "tests.migration.test_lane3_lease_store": 20,
    "tests.migration.test_lane3_e10_database": 10,
    "tests.migration.test_lane3_store_catalogue": 10,
    "tests.migration.test_lane3_cp6_export": 5,
    "tests.unit.test_lane3_vendored_pins": 3,
    "tests.unit.test_lane3_host_admission_vector": 5,
}


def check_report(path: Path) -> dict[str, int]:
    # The local pytest output just written into RUNNER_TEMP by the preceding CI
    # command, not a network-supplied XML document.
    root = ElementTree.parse(path).getroot()  # noqa: S314
    counts = dict.fromkeys(EXPECTED_FILES, 0)
    for case in root.findall(".//testcase"):
        classname = case.get("classname") or ""
        for outcome in ("skipped", "failure", "error"):
            if case.find(outcome) is not None:
                raise ValueError(f"{classname}::{case.get('name')} {outcome}")
        for prefix in counts:
            if classname == prefix or classname.startswith(prefix + "."):
                counts[prefix] += 1
    for prefix, floor in EXPECTED_FILES.items():
        if counts[prefix] < floor:
            raise ValueError(
                f"{prefix} ran {counts[prefix]} case(s), at least {floor} required"
            )
    return counts


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_lane3_junit.py JUNIT_XML")
    try:
        counts = check_report(Path(sys.argv[1]))
    except (OSError, ElementTree.ParseError, ValueError) as error:
        raise SystemExit(str(error)) from error
    for name, count in counts.items():
        print(f"{name}: {count} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
