"""Sensitivity checks for the explicit D16 no-skip CI gate."""

from __future__ import annotations

from pathlib import Path
from runpy import run_path
from xml.etree import ElementTree

import pytest

_checker = run_path(
    str(Path(__file__).resolve().parents[2] / "scripts" / "check_d16_bundle_junit.py")
)
EXPECTED = _checker["EXPECTED"]
check_report = _checker["check_report"]


def _report(
    path: Path, *, names: set[str] | None = None, skip: str | None = None
) -> None:
    suite = ElementTree.Element("testsuite")
    for name in sorted(EXPECTED if names is None else names):
        case = ElementTree.SubElement(suite, "testcase", name=name)
        if name == skip:
            ElementTree.SubElement(case, "skipped")
    ElementTree.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def test_complete_report_passes(tmp_path: Path) -> None:
    path = tmp_path / "d16.xml"
    _report(path)
    check_report(path)


@pytest.mark.parametrize("missing", sorted(EXPECTED))
def test_missing_case_refuses(tmp_path: Path, missing: str) -> None:
    path = tmp_path / "d16.xml"
    _report(path, names=set(EXPECTED) - {missing})
    with pytest.raises(ValueError, match="collected"):
        check_report(path)


@pytest.mark.parametrize("skipped", sorted(EXPECTED))
def test_skipped_case_refuses(tmp_path: Path, skipped: str) -> None:
    path = tmp_path / "d16.xml"
    _report(path, skip=skipped)
    with pytest.raises(ValueError, match="did not pass"):
        check_report(path)


def test_duplicate_case_refuses(tmp_path: Path) -> None:
    path = tmp_path / "d16.xml"
    suite = ElementTree.Element("testsuite")
    for name in sorted(EXPECTED):
        ElementTree.SubElement(suite, "testcase", name=name)
    ElementTree.SubElement(suite, "testcase", name=next(iter(EXPECTED)))
    ElementTree.ElementTree(suite).write(path)
    with pytest.raises(ValueError, match="collected"):
        check_report(path)


def test_malformed_report_refuses(tmp_path: Path) -> None:
    path = tmp_path / "d16.xml"
    path.write_text("<testsuite>", encoding="utf-8")
    with pytest.raises(ElementTree.ParseError):
        check_report(path)
