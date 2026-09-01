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


def test_the_read_back_compares_like_for_like() -> None:
    """`.Id` means two different things on the two sides of a push.

    For a locally built image it is the CONFIG digest; for an image pulled by
    digest, docker reports the MANIFEST digest in the same field. Measured on a
    real published artifact those are distinct values, so comparing the recorded
    config digest against the pulled `.Id` compares two different KINDS of value
    and can never hold — a false refusal on every correct publication, arriving
    after the push had already happened.

    The equality therefore rests on the RootFS layer chain, which is the same
    object on both sides, and the registry's own config digest is READ from the
    manifest rather than inferred from a field that changes meaning.
    """
    workflow = _text(IMAGE_WORKFLOW)
    readback = workflow[
        workflow.index("Prove the registry holds the accepted candidate") :
    ]
    compare = readback[: readback.index("Emit the release receipt")]
    assert "registry RootFS chain" in compare
    assert "docker manifest inspect" in compare
    assert '["config"]["digest"]' in compare
    # The retired comparison must stay retired.
    assert "pulled_config" not in compare
    assert "!= accepted $accepted_config" not in compare
    assert "deliberately NOT compared" in compare


def test_the_receipt_records_the_registrys_own_config_digest() -> None:
    """Recorded, not guessed: it is the value the registry stores, and it is not
    the digest the image is pulled by."""
    workflow = _text(IMAGE_WORKFLOW)
    assert "registry_config_digest" in workflow
    assert "steps.readback.outputs.registry_config" in workflow


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
    compare = workflow.index("registry RootFS chain $pulled_chain != accepted")
    assert remove < inspect_guard < pull < compare


def test_the_receipt_records_per_file_distribution_digests() -> None:
    """Bundle granularity names the container, not what is inside it.

    The config digest and the layer chain identify an image. Neither answers
    "which wheel is installed in it?", so a receipt carrying only those cannot
    be checked against a distribution artifact at all — which is the granularity
    a prior release record called out as missing.
    """
    workflow = _text(IMAGE_WORKFLOW)
    receipt = workflow[workflow.index("Emit the release receipt") :]
    assert "distributions:$distributions" in receipt
    assert "candidate-distributions.json" in receipt


def test_the_distribution_digests_are_read_from_the_candidate_not_remeasured() -> None:
    """A second `poetry build` describes different bytes.

    A wheel is a zip and a zip carries timestamps, so rebuilding to measure
    would produce a digest for an archive this image does not contain — a
    receipt field that looks like evidence and is not. The image computes them
    in the stage that installed them; the pipeline READS them out.
    """
    workflow = _text(IMAGE_WORKFLOW)
    identity = workflow[
        workflow.index("Record the candidate's identity") : workflow.index(
            "Accept the candidate, or refuse it"
        )
    ]
    assert "/app/distributions.json" in identity
    # The property is that nothing INVOKES a second build, not that the words
    # are unmentionable — the comment explaining why it must not is the
    # documentation this rule most wants written. Same mistake, and same
    # correction, as the Dockerfile's PYTHONPATH guard.
    invocations = [
        line
        for line in identity.splitlines()
        if "poetry build" in line and not line.lstrip().startswith("#")
    ]
    assert invocations == [], invocations
    # And a receipt that recorded an empty list, or one format, would be a
    # narrowing nobody would notice. Both are required where they are read.
    assert 'endswith(".whl")' in identity
    assert 'endswith(".tar.gz")' in identity


def test_the_manifest_the_receipt_reads_is_checked_before_publication() -> None:
    """The read happens only on the publication path, so the battery holds it.

    A malformed or silently narrowed `/app/distributions.json` would otherwise
    first be discovered by the step that reads it — after the push, with the
    receipt unemitted. That is the exact failure shape the ordering exists to
    prevent, so the property belongs to acceptance rather than to publication.
    """
    acceptance = _text(ACCEPTANCE)
    assert "/app/distributions.json" in acceptance
    assert "dotmac-distribution-digests/1" in acceptance
    # Tied to the installed distribution, not free-floating.
    assert "importlib.metadata import version" in acceptance


def test_the_registry_read_back_is_preflighted_before_the_push() -> None:
    """A tool that is missing must not be discovered with bytes already published."""
    workflow = _text(IMAGE_WORKFLOW)
    preflight = workflow.index("docker manifest inspect --help")
    push = workflow.index("docker push")
    assert preflight < push


def test_the_image_carries_the_distributions_the_receipt_describes() -> None:
    """The claim is re-derivable from a pulled image, not only from a run log."""
    dockerfile = _text(ROOT / "Dockerfile")
    assert (
        "--format wheel" not in dockerfile
    ), "only a wheel is built, so the receipt cannot carry an sdist digest"
    assert "dotmac-distribution-digests/1" in dockerfile
    assert "no wheel was built" in dockerfile
    assert "no sdist was built" in dockerfile
    assert "/app/distributions.json ./distributions.json" in dockerfile


def test_the_battery_is_reachable_from_the_pull_request_path() -> None:
    """Every defect this battery has had was found by a publication run.

    Three of them, each costing a merge to protected main to discover: a restore
    lane that landed zero tables, a read-back that compared two different kinds
    of digest, and a role-contract assertion that compared PostgreSQL's boolean
    OUTPUT (`t`/`f`) against its boolean CAST (`true`/`false`) and could not
    hold on any correct database. All three were defects in the CHECK, and all
    three were unreachable from the pull-request path.

    The rehearsal does not weaken the ordering: acceptance is still the run
    against the exact candidate about to be published, asserted above. This only
    makes the battery's own defects fail in review.
    """
    ci = _text(CI_WORKFLOW)
    assert "Rehearse the acceptance battery" in ci
    assert ".github/candidate/acceptance.sh" in ci
    # One script, two callers. A rehearsal that had its own copy would drift,
    # and a drifting rehearsal is worse than no rehearsal.
    assert "acceptance.sh" in _text(IMAGE_WORKFLOW)
    assert not (ROOT / ".github" / "candidate" / "acceptance-ci.sh").exists()


def test_the_rehearsal_does_not_become_the_acceptance() -> None:
    """CI proves the battery runs; it does not prove the published bytes.

    The image CI builds is not the candidate — it is built from a pull-request
    head, and nothing publishes it. If acceptance were ever deleted from the
    publication path on the grounds that "CI already runs it", the registry
    would again hold bytes nothing accepted.
    """
    workflow = _text(IMAGE_WORKFLOW)
    accept = workflow.index("Accept the candidate, or refuse it")
    assert ".github/candidate/acceptance.sh" in workflow[accept:]
    assert workflow.index("docker push") > accept


def test_the_role_contract_query_renders_the_form_it_declares() -> None:
    """PostgreSQL renders a boolean two ways, and they do not agree.

    `format('%s', ...)` calls the type's output function and emits `t`/`f`; the
    boolean-to-text CAST emits `true`/`false`. Written without the casts this
    assertion compared `f|f|t|t` against `false|false|true|true` — measured
    failing in run 33407635872, at the FIRST assertion of step 5, which is why
    nothing after it in the battery had ever executed.

    The readable spelling is kept in the declaration, because it is what an
    operator reads in the failure message, and the QUERY is the half corrected.
    """
    acceptance = _text(ACCEPTANCE)
    contract = acceptance[acceptance.index('step "5  database ownership') :]
    contract = contract[: contract.index("owner_contract=")]
    for flag in ("rolsuper", "rolcreaterole", "rolbypassrls", "rolcanlogin"):
        assert f"{flag}::text" in contract, (
            f"{flag} is rendered by the boolean output function, which emits "
            "t/f and can never equal the declared true/false"
        )
    assert 'test "$role_contract" = "false|false|true|true"' in acceptance


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
        "distributions",
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
    "restored-production single variable": (
        "the lanes must differ only in DATABASE ownership"
    ),
    "restored-production not a table fault": "failed on TABLE privileges",
    "database ownership": "app_admin|app_admin",
    "role contract": "false|false|true|true",
    "grant isolation": "the plane boundary is open",
    # A column named `tenant_id` is not the same as a tenant-SCOPED table, and
    # the one exception is DECLARED as an equality so the ratchet fails when the
    # set grows AND when it shrinks.
    "rls declared, not assumed": "the declared resolver-input set is",
    "rls non-vacuity": "so the equality above is satisfied by the declaration",
    # Production-fatal under kernel a98 and absent from `.env.production.example`;
    # the battery supplies its own so the rest of the run is reachable.
    "production csrf secret": "CSRF_SECRET=candidate-csrf-secret",
    "dependency-aware readiness": (
        "readiness returned $ready_code with an unreachable database"
    ),
    "liveness as control": "liveness should answer 200 even with no database",
    "browser journey": "form login yields a session that reaches the console",
    # Replaying `Set-Cookie` is what lets a production `__Host-`/Secure cookie
    # survive a plain-HTTP runner. The refusal case is what proves the
    # protection is still on after doing it.
    "csrf still refuses without proof": "a form POST with no CSRF proof returned",
    # The distribution manifest the receipt reads is produced on every path,
    # but only READ on the publication path — so the candidate demonstrates it.
    "distribution manifest": "dotmac-distribution-digests/1",
    "api journey": "the API did not issue a bearer token",
    # A refusal that names nothing costs a whole run to diagnose, and a refusal
    # that names too much echoes a credential. Both halves are required.
    "refusals name their reason": "refusal_reason",
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


def test_the_two_restore_lanes_differ_in_exactly_one_variable() -> None:
    """A two-variable experiment cannot attribute its own result.

    The first construction left `public` owned by `postgres` in lane B as well,
    so `app_admin` could create nothing and the restore landed zero tables. The
    non-empty guard caught it — but had it not, lane B would have failed with
    the right message for entirely the wrong reason, and the battery would have
    reported a trap it was no longer testing.

    Both copies now carry `public` owned by `app_admin`; only `datdba` differs,
    and the script asserts both halves of that rather than assuming them.
    """
    acceptance = _text(ACCEPTANCE)
    assert "ALTER SCHEMA public OWNER TO app_admin" in acceptance
    assert 'test "$ok_owners" = "app_admin|app_admin"' in acceptance
    assert 'test "$bad_owners" = "postgres|app_admin"' in acceptance
    setup = acceptance.index("the lanes must differ only in DATABASE ownership")
    migrate = acceptance.index("lane B: a wrongly-owned restored copy is refused")
    assert setup < migrate


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
