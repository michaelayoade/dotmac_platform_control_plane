"""The Lane 3 JUnit gate refuses a skip, a failure and a file that ran nothing."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_lane3_junit.py"
spec = importlib.util.spec_from_file_location("check_lane3_junit", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _report(
    tmp_path: Path, *, skip: str | None = None, drop: str | None = None
) -> Path:
    cases = []
    for prefix, floor in gate.EXPECTED_FILES.items():
        if prefix == drop:
            continue
        for index in range(floor):
            inner = "<skipped/>" if prefix == skip and index == 0 else ""
            cases.append(
                f'<testcase classname="{prefix}" name="t{index}">{inner}</testcase>'
            )
    path = tmp_path / "report.xml"
    path.write_text(f"<testsuites><testsuite>{''.join(cases)}</testsuite></testsuites>")
    return path


def test_a_complete_unskipped_report_passes(tmp_path: Path) -> None:
    counts = gate.check_report(_report(tmp_path))
    assert counts == gate.EXPECTED_FILES


def test_one_skipped_case_fails_the_gate(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="skipped"):
        gate.check_report(
            _report(tmp_path, skip="tests.migration.test_lane3_lease_store")
        )


def test_a_file_that_collected_nothing_fails_the_gate(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least"):
        gate.check_report(
            _report(tmp_path, drop="tests.migration.test_lane3_cp6_export")
        )


def test_a_failure_fails_the_gate(tmp_path: Path) -> None:
    path = tmp_path / "r.xml"
    path.write_text(
        '<testsuite><testcase classname="tests.migration.test_lane3_lease_store" '
        'name="t"><failure/></testcase></testsuite>'
    )
    with pytest.raises(ValueError, match="failure"):
        gate.check_report(path)
