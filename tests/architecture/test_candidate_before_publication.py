"""Nothing reaches the registry that has not already been accepted.

The pipeline this file guards replaced one that pushed and then smoked. That
ordering has a specific consequence, and it is not a style question: a failing
smoke left PUBLISHED bytes nobody had accepted, with no mechanism for unpublishing
them and every downstream consumer free to pin the result. The registry recorded
what was built rather than what passed.

So the assertions here are mostly about ORDER. A step list can contain every
correct step and still be wrong.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE_WORKFLOW = ROOT / ".github" / "workflows" / "production-image.yml"
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "production-deploy.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
STANDARDS_WORKFLOW = ROOT / ".github" / "workflows" / "engineering-standards.yml"
ACCEPTANCE = ROOT / ".github" / "candidate" / "acceptance.sh"
VERIFIER = ROOT / ".github" / "candidate" / "verify_source_revision.py"
GATES = ROOT / ".github" / "candidate" / "required-gates.json"
UI_EXPECTED = ROOT / ".github" / "candidate" / "ui-assets.expected"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── the ordering, which is the whole point ──────────────────────────────────


def test_the_candidate_is_accepted_before_anything_is_published() -> None:
    """Build, record, TEST, publish, read back, compare, receipt — in that order.

    Every index below is a step that must not move. If acceptance drifted after
    publication the workflow would still contain the word "acceptance" and would
    still pass a naive presence check, which is how the previous pipeline read
    as correct.
    """
    workflow = _text(IMAGE_WORKFLOW)
    build = workflow.index("Build the candidate")
    identity = workflow.index("Record the candidate's identity")
    accept = workflow.index("Accept the candidate, or refuse it")
    login = workflow.index("Authenticate to GHCR")
    publish = workflow.index("Publish the accepted candidate")
    readback = workflow.index("Prove the registry holds the accepted candidate")
    receipt = workflow.index("Emit the release receipt")
    assert build < identity < accept < login < publish < readback < receipt


def test_nothing_is_pushed_before_the_candidate_is_accepted() -> None:
    """The single assertion that would have caught the previous design."""
    workflow = _text(IMAGE_WORKFLOW)
    accept = workflow.index("Accept the candidate, or refuse it")
    pushes = [
        index
        for index in range(len(workflow))
        if workflow.startswith("docker push", index)
    ]
    assert pushes, "no publication step was found at all"
    assert all(index > accept for index in pushes), (
        "a `docker push` appears before the acceptance step; a failing "
        "acceptance would leave published bytes nobody accepted"
    )
    assert "docker login" not in workflow[:accept], (
        "the registry credential is acquired before acceptance, which is the "
        "shape that makes an early push possible"
    )


def test_the_identity_recorded_is_the_identity_compared() -> None:
    """Recording a digest nobody compares is bookkeeping, not a proof."""
    workflow = _text(IMAGE_WORKFLOW)
    for field in ("config_digest", "rootfs_chain", "lock_digest", "dockerfile_digest"):
        assert f"{field}=" in workflow, field
    assert "steps.identity.outputs.config_digest" in workflow
    assert "steps.identity.outputs.rootfs_chain" in workflow
    assert "source_revision" in workflow


def test_the_read_back_actually_leaves_the_runner() -> None:
    """Comparing a local tag with itself passes without consulting the registry.

    So the local references are removed and their absence asserted before the
    pull. Without that the equality check is a tautology — and a tautology that
    reads exactly like a proof.
    """
    workflow = _text(IMAGE_WORKFLOW)
    remove = workflow.index("docker image rm -f")
    inspect_guard = workflow.index("the candidate is still resident locally")
    pull = workflow.index('docker pull "$reference"')
    compare = workflow.index("registry config $pulled_config != accepted")
    assert remove < inspect_guard < pull < compare


def test_the_receipt_binds_the_revision_the_run_and_the_bytes() -> None:
    workflow = _text(IMAGE_WORKFLOW)
    receipt = workflow[workflow.index("Emit the release receipt") :]
    for field in (
        "source_revision",
        "ci_run_id",
        "release_run_id",
        "registry_digest",
        "config_digest",
        "rootfs_chain",
        "lock_digest",
        "dockerfile_digest",
    ):
        assert field in receipt, field
    assert "dotmac-candidate-release-receipt/1" in receipt


# ── admission: which revisions may be built at all ──────────────────────────


def test_the_required_gate_set_matches_the_workflows_in_both_directions() -> None:
    """A list that can only shrink silently is not an admission rule.

    Declared gates must be jobs that exist, and every job that exists must be
    declared. A gate added to CI and forgotten here would be a required check
    the publication path never looks at.
    """
    declared = set(json.loads(_text(GATES))["gates"])
    # Sliced from `jobs:` onward, because `on:` and `permissions:` also carry
    # two-space keys and a parser that took every one of them would report
    # `push` and `workflow_dispatch` as required gates.
    ci_body = _text(CI_WORKFLOW).split("\njobs:\n", 1)[1]
    ci_jobs = {
        line.strip().rstrip(":")
        for line in ci_body.splitlines()
        if line.startswith("  ")
        and not line.startswith("   ")
        and line.rstrip().endswith(":")
    }
    external = {
        name
        for name in (
            "Governance pin is a real approved revision",
            "Dotmac engineering standards",
        )
        if name in _text(STANDARDS_WORKFLOW)
    }
    assert declared == ci_jobs | external, {
        "declared_only": sorted(declared - (ci_jobs | external)),
        "undeclared": sorted((ci_jobs | external) - declared),
    }


def test_the_required_gate_set_is_not_empty() -> None:
    """NON-VACUITY. An admission rule requiring nothing admits everything."""
    assert json.loads(_text(GATES))["gates"]


def test_the_verifier_makes_all_seven_checks() -> None:
    """Seven separate ways a pasted run id can be wrong.

    Named individually because each has a failure the others do not catch, and
    the seventh — a required gate that SKIPPED — is invisible at the run level,
    which is exactly why it is easiest to leave out.
    """
    verifier = _text(VERIFIER)
    assert "belongs to" in verifier  # 1 repository
    assert "not {workflow_path!r}" in verifier  # 2 workflow
    assert "not completed" in verifier  # 3 terminal status
    assert "not success" in verifier  # 3 conclusion
    assert "head repository" in verifier  # 4 protected main, no fork
    assert "is not a 40-hex SHA" in verifier  # 5 SHA shape
    assert "current {branch} is" in verifier  # 6 still current main
    assert "produced no check-run" in verifier  # 7 gate absent
    assert "even when a required job skipped" in verifier  # 7 gate skipped


def test_skipped_is_refused_by_name() -> None:
    """`skipped` reads as success at the workflow level. It is listed first in
    the non-passing set for that reason, and this holds it there."""
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("candidate_verifier", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert "skipped" in module.NON_PASSING
    assert module.NON_PASSING[0] == "skipped"
    for conclusion in (
        "neutral",
        "cancelled",
        "timed_out",
        "action_required",
        "failure",
    ):
        assert conclusion in module.NON_PASSING
    assert "success" not in module.NON_PASSING


def test_the_deploy_requires_a_receipt_rather_than_a_pasted_digest() -> None:
    workflow = _text(DEPLOY_WORKFLOW)
    assert "ci_run_id" in workflow
    assert "verify_source_revision.py" in workflow
    verify = workflow.index("Verify the source revision earned its way here")
    receipt = workflow.index("Require a release receipt binding this digest")
    deploy = workflow.index("Deploy the approved digest")
    assert verify < receipt < deploy
    assert 'receipt.get("registry_digest") != os.environ["IMAGE_DIGEST"]' in workflow


# ── the acceptance battery covers what it claims to ─────────────────────────


#: Every property the candidate must demonstrate, with the marker that proves
#: the battery still asks for it. Declared as data so a check quietly deleted
#: from the script fails here rather than disappearing.
REQUIRED_CHECKS: dict[str, str] = {
    "installed CLI": "the console script is not installed in the candidate",
    "app import": "from vendor_cp.main import app",
    "fresh zero-to-head migration": "could not migrate an empty database to heads",
    "restored-production migration": (
        "restored copy owned by postgres migrated successfully"
    ),
    "restored-production reason": "permission denied for database",
    "database ownership": "app_admin|app_admin",
    "role contract": "false|false|true|true",
    "grant isolation": "the plane boundary is open",
    "dependency-aware readiness": (
        "readiness returned $ready_code with an unreachable database"
    ),
    "liveness as control": "liveness should answer 200 even with no database",
    "browser journey": "form login yields a session that reaches the console",
    "api journey": "the API did not issue a bearer token",
    "cli journey": "a read reaches the same owner the browser and API just used",
    "wrong credential": "a wrong password returned $bad_code",
    "wrong standing": "an inactive administrator with the CORRECT password",
    "exact UI assets": "UI asset manifest digest",
    "documentation routes absent": "'/docs', '/docs/oauth2-redirect', '/redoc'",
    "documentation gate bidirectional": "the gate is not discriminating",
    "no fake provisioning surface": "/platform/vendor/provisioning",
    "no checkout dependency": "the same command refuses a checkout with 6",
}


@pytest.mark.parametrize(("what", "marker"), sorted(REQUIRED_CHECKS.items()))
def test_the_acceptance_battery_still_asks_this(what: str, marker: str) -> None:
    assert marker in _text(ACCEPTANCE), f"the battery no longer checks {what}"


def test_the_restored_migration_test_has_both_lanes() -> None:
    """Lane A alone proves nothing about the trap.

    A correctly-owned restored copy upgrading successfully is compatible with a
    world where the wrong-owner failure has silently stopped being detectable.
    Lane B plants the exact defect the 2026-08-31 rehearsal hit and REQUIRES the
    failure, and requires it to be the right failure rather than any failure.
    """
    acceptance = _text(ACCEPTANCE)
    lane_a = acceptance.index("lane A: a correctly-owned restored copy upgrades")
    lane_b = acceptance.index("lane B: a wrongly-owned restored copy is refused")
    assert lane_a < lane_b
    assert "CREATE DATABASE restored_wrong_owner OWNER postgres" in acceptance
    assert "failed for some OTHER reason" in acceptance


def test_the_readiness_check_runs_its_negative_case_first() -> None:
    """A probe that returned 200 unconditionally would pass a positive-only test.

    So the unreachable-database case runs BEFORE the reachable one, and the
    liveness route is asserted alongside it as a positive control — otherwise
    "not ready" and "not answering" would be indistinguishable.
    """
    acceptance = _text(ACCEPTANCE)
    negative = acceptance.index("database unreachable: /health 200")
    positive = acceptance.index("database reachable: /health/ready 200")
    assert negative < positive


def test_the_acceptance_battery_is_not_under_scripts() -> None:
    """`scripts/` is production instructions, and those are being retired.

    A CI harness there would be the first new occurrence of the shape
    `vendor_cp.installed_surface` refuses.
    """
    assert ACCEPTANCE.exists()
    assert not (ROOT / "scripts" / "acceptance.sh").exists()
    assert ACCEPTANCE.stat().st_mode & 0o111, "the battery is not executable"


def test_the_declared_ui_asset_expectation_is_exact() -> None:
    lines = _text(UI_EXPECTED).split()
    assert len(lines) == 2, "expected a count and a digest"
    assert lines[0].isdigit() and int(lines[0]) > 0
    assert len(lines[1]) == 64 and all(c in "0123456789abcdef" for c in lines[1])
