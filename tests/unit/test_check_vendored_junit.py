"""The vendored-verifier JUnit gate demands EXACTLY the expected test set (L1, N4)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_vendored_junit.py"
spec = importlib.util.spec_from_file_location("check_vendored_junit", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _report(
    tmp_path: Path, names: set[str], *, outcome: dict[str, str] | None = None
) -> Path:
    cases = []
    for full in sorted(names):
        classname, _, name = full.partition("::")
        inner = (outcome or {}).get(full, "")
        cases.append(
            f'<testcase classname="{classname}" name="{name}">{inner}</testcase>'
        )
    path = tmp_path / "report.xml"
    path.write_text(f"<testsuites><testsuite>{''.join(cases)}</testsuite></testsuites>")
    return path


def test_exactly_the_expected_set_passes(tmp_path: Path) -> None:
    assert gate.check_report(_report(tmp_path, set(gate.EXPECTED))) == gate.EXPECTED


def test_a_missing_name_is_refused(tmp_path: Path) -> None:
    names = set(gate.EXPECTED)
    gone = sorted(names)[0]
    names.discard(gone)
    with pytest.raises(ValueError, match="missing") as refused:
        gate.check_report(_report(tmp_path, names))
    assert gone in str(refused.value)


def test_an_extra_name_is_refused_even_when_the_count_is_unchanged(
    tmp_path: Path,
) -> None:
    names = set(gate.EXPECTED)
    names.discard(sorted(names)[0])
    names.add("tests.unit.test_other::test_something_else")
    with pytest.raises(ValueError, match="unexpected"):
        gate.check_report(_report(tmp_path, names))


def test_a_pure_addition_is_refused(tmp_path: Path) -> None:
    names = set(gate.EXPECTED) | {"tests.unit.test_other::test_new"}
    with pytest.raises(ValueError, match="unexpected"):
        gate.check_report(_report(tmp_path, names))


@pytest.mark.parametrize("outcome", ["skipped", "failure", "error"])
def test_a_skipped_failed_or_errored_case_is_refused(
    tmp_path: Path, outcome: str
) -> None:
    target = sorted(gate.EXPECTED)[0]
    report = _report(tmp_path, set(gate.EXPECTED), outcome={target: f"<{outcome}/>"})
    with pytest.raises(ValueError, match=outcome):
        gate.check_report(report)
