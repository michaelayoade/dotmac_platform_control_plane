"""The installed Foundation/CP acceptance gate cannot pass by omission."""

from __future__ import annotations

import ast
from pathlib import Path
from runpy import run_path
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check_foundation_composition_junit.py"
_checker = run_path(str(CHECKER))
EXPECTED = _checker["EXPECTED"]
check_report = _checker["check_report"]
APPROVAL_EXPECTED = _checker["APPROVAL_EXPECTED"]


def _report(path, *, omitted=None, skipped=None, extra=None):
    suite = ElementTree.Element("testsuite")
    for identity in sorted(EXPECTED):
        if identity == omitted:
            continue
        classname, name = identity
        case = ElementTree.SubElement(suite, "testcase", classname=classname, name=name)
        if identity == skipped:
            ElementTree.SubElement(case, "skipped")
    if extra is not None:
        ElementTree.SubElement(suite, "testcase", classname=extra[0], name=extra[1])
    ElementTree.ElementTree(suite).write(path)


def test_named_gate_accepts_complete_run_and_refuses_skip_omission_duplicate(tmp_path):
    path = tmp_path / "composition.xml"
    _report(path)
    check_report(path)
    identity = min(EXPECTED)
    for kwargs in ({"omitted": identity}, {"skipped": identity}, {"extra": identity}):
        _report(path, **kwargs)
        with pytest.raises(ValueError):
            check_report(path)
    # Same name, wrong module is also an omitted required case.
    _report(path, omitted=identity, extra=("different.module", identity[1]))
    with pytest.raises(ValueError):
        check_report(path)


def test_gate_names_every_host_and_renderer_case_including_parameter_variants():
    host_tree = ast.parse(
        (ROOT / "conformance/test_host_admission_conformance.py").read_text()
    )
    host_cases = {
        node.name
        for node in host_tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    assert {
        name
        for module, name in EXPECTED
        if module.endswith("test_host_admission_conformance")
    } == host_cases
    renderer_cases = {
        name
        for module, name in EXPECTED
        if module.endswith("test_candidate_renderer_real_foundation")
    }
    assert len(renderer_cases) == 4
    assert (
        "test_changed_frozen_coordinates_change_real_foundation_plan[prestate]"
        in renderer_cases
    )
    assert (
        "test_changed_frozen_coordinates_change_real_foundation_plan[profile]"
        in renderer_cases
    )


def test_required_postgres_job_installs_complete_closure_and_runs_outside_checkout():
    source = (ROOT / ".github/workflows/ci.yml").read_text()
    postgres = source.split("  postgres:\n", 1)[1].split("  kernel-pin:\n", 1)[0]
    assert "runs-on: ubuntu-latest" in postgres
    assert "poetry install" in postgres
    assert "Installed Foundation renderer and CP approval composition" in postgres
    assert "--no-index --no-deps --force-reinstall" in postgres
    assert "poetry build --format wheel" in postgres
    assert 'cd "$acceptance_root"' in postgres
    assert (
        "assert any(origin.is_relative_to(root) for root in installed_roots)"
        in postgres
    )
    assert '("dotmac-deployment-control", "0.1.0a17")' in postgres
    assert '("dotmac-approvals", "0.1.0a8")' in postgres
    assert "conformance/test_candidate_renderer_real_foundation.py" in postgres
    assert "conformance/test_host_admission_conformance.py" in postgres
    assert "scripts/check_foundation_composition_junit.py" in postgres
    assert "d74bf8dd8c399dd92047174365403b861f82ddd0" in postgres
    assert "PYTHONPATH:" not in postgres.split("Installed Foundation renderer", 1)[1]
    assert postgres.index("dotmac-platform admin migrate") < postgres.index(
        "Installed Foundation renderer"
    )
    harness = (ROOT / ".github/workflows/rehearsal-issuer-harness.yml").read_text()
    assert "conformance/test_host_admission_conformance.py" not in harness


def test_host_suite_uses_real_approval_closure_and_no_passthrough_barrier():
    source = (ROOT / "conformance/test_host_admission_conformance.py").read_text()
    assert "open_foundation_approval(" in source
    assert "approve_foundation_plan(" in source
    assert "request_foundation_rollout(" in source
    assert "dispatch_foundation_attempt(" in source
    assert "build_foundation_v3_providers(" in source
    assert "compose_foundation_v3_providers(" not in source
    assert "approvals.record_decision(" in source
    assert "with pytest.raises(approvals.ApprovalNotHeld)" in source
    assert "\"SET LOCAL lock_timeout = '500ms'\"" in source
    assert "approvals_module" in source


def test_named_approval_gate_cannot_skip_an_owner_race(tmp_path):
    path = tmp_path / "approval.xml"

    def report(skipped=None):
        suite = ElementTree.Element("testsuite")
        for name in sorted(APPROVAL_EXPECTED):
            case = ElementTree.SubElement(
                suite,
                "testcase",
                classname="migration.test_foundation_approval",
                name=name,
            )
            if name == skipped:
                ElementTree.SubElement(case, "skipped")
        ElementTree.ElementTree(suite).write(path)

    report()
    check_report(path, approval=True)
    for stage in ("approve", "rollout", "dispatch"):
        skipped = (
            f"test_owner_transition_first_holds_withdrawal_until_single_commit[{stage}]"
        )
        report(skipped)
        with pytest.raises(ValueError, match="did not pass"):
            check_report(path, approval=True)
    report()
    suite = ElementTree.parse(path).getroot()  # noqa: S314 - this test wrote the XML
    suite.remove(suite[0])
    ElementTree.ElementTree(suite).write(path)
    with pytest.raises(ValueError, match="collected"):
        check_report(path, approval=True)
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "check_foundation_composition_junit.py --approval" in workflow
    assert '--junitxml="$RUNNER_TEMP/foundation-approval.xml"' in workflow
