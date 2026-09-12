"""No `${{` opener may sit inside a `run:` body, and the pre-existing
exceptions are a frozen, two-directional, named baseline rather than a
silent allowlist.

`kernel-lock.yml` line 558 was a shell comment —

    # Every coordinate crosses as a shell variable, never as a `${{ }}`

— that made `gh workflow run` refuse the whole file with
`HTTP 422: failed to parse workflow ... An expression was expected`. GitHub
templates `${{ ... }}` anywhere in a `run:` body before bash ever runs, and an
empty pair of braces is not a valid expression. The comment is prose, not an
interpolation, and PyYAML parses the file cleanly — the defect is invisible to
anything that only asks "is this valid YAML".

`env:`, `with:`, and `if:` remain the sanctioned path for a real expression:
this module only ever inspects a step's own `run:` field.
"""

from __future__ import annotations

from pathlib import Path

from run_block_expressions import (
    RUN_BLOCK_EXPRESSION_BASELINE,
    WORKFLOWS_DIR,
    ExpressionSite,
    baseline_mismatches,
    run_block_expression_sites,
)


def _write(tmp_path: Path, text: str) -> Path:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / "plant.yml").write_text(text)
    return workflow_dir


# ── the guard, against the real tree ────────────────────────────────────────


def test_the_workflow_directory_holds_every_file_the_guard_must_reach() -> None:
    """SENSITIVITY. If this directory were empty or missing, every assertion
    below would pass over nothing."""

    names = {path.name for path in WORKFLOWS_DIR.glob("*.yml")}
    assert names == {
        "ci.yml",
        "engineering-standards.yml",
        "kernel-lock.yml",
        "production-deploy.yml",
        "production-image.yml",
    }, names


def test_only_the_frozen_baseline_carries_a_run_block_expression() -> None:
    """The two-directional check. A site the baseline does not name, a
    baseline entry the tree no longer carries, and a count that moved without
    the baseline moving with it are each a distinct, named failure."""

    measured = {site.key: site.count for site in run_block_expression_sites()}
    extra, missing, drifted = baseline_mismatches(
        measured, RUN_BLOCK_EXPRESSION_BASELINE
    )
    assert not extra, (
        "a `${{` opener sits inside a run: body with no baseline entry — "
        f"either it is a new defect (repair it) or a retirement only partly "
        f"landed (move the row into the baseline in this same change): {extra}"
    )
    assert not missing, (
        "the baseline still names a run: block that no longer carries a `${{` "
        "opener — lower RUN_BLOCK_EXPRESSION_BASELINE in the same change that "
        f"retired the site, or the retirement is not actually recorded: {missing}"
    )
    assert not drifted, (
        "a baselined site's `${{` count moved without the baseline moving "
        f"with it: {drifted}"
    )


def test_kernel_lock_workflow_carries_no_baseline_entry() -> None:
    """`kernel-lock.yml`'s one site was a shell comment, repaired (not
    retired) in this same change — it must never appear in the baseline, and
    the tree must no longer carry a site for it either."""

    assert not any(key[0] == "kernel-lock.yml" for key in RUN_BLOCK_EXPRESSION_BASELINE)
    assert not [
        site
        for site in run_block_expression_sites()
        if site.workflow == "kernel-lock.yml"
    ]


def test_the_measured_shape_matches_the_recorded_eight_sites_and_nineteen_openers() -> (
    None
):
    """NON-VACUITY. This is the measured shape, not an assumption — a guard
    that always found zero sites would pass for the wrong reason."""

    sites = run_block_expression_sites()
    assert len(sites) == 8, sites
    assert sum(site.count for site in sites) == 19, sites


# ── the extraction itself: sensitivity, near-miss, structured-field scope ──


def test_a_shell_comment_containing_the_literal_delimiters_is_refused(
    tmp_path: Path,
) -> None:
    """THE PLANT. The exact shape of the kernel-lock.yml defect: a shell
    comment, not a real interpolation."""

    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Assemble something\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          # never as a `${{ }}` interpolation\n"
        "          echo done\n",
    )
    sites = run_block_expression_sites(workflow_dir)
    assert sites == [ExpressionSite("plant.yml", "demo", "Assemble something", 1)]


def test_the_actual_repair_prose_is_not_a_near_miss(tmp_path: Path) -> None:
    """The exact replacement text this change makes in kernel-lock.yml must
    not itself trip the guard — a check that fired on its own repair would be
    unusable."""

    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Assemble something\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          # never as a GitHub Actions expression\n"
        "          echo done\n",
    )
    assert run_block_expression_sites(workflow_dir) == []


def test_a_heredoc_body_is_not_missed(tmp_path: Path) -> None:
    """The extraction does not try to parse the body as shell, so a heredoc's
    payload is just more text inside the `run:` field — no separate case is
    needed for it."""

    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Emit a doc\n"
        "        run: |\n"
        "          cat <<'EOF' > out.txt\n"
        "          token: ${{ inputs.thing }}\n"
        "          EOF\n",
    )
    sites = run_block_expression_sites(workflow_dir)
    assert sites == [ExpressionSite("plant.yml", "demo", "Emit a doc", 1)]


def test_a_single_line_run_without_a_block_scalar_is_caught(tmp_path: Path) -> None:
    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: One liner\n"
        '        run: echo "${{ inputs.thing }}"\n',
    )
    sites = run_block_expression_sites(workflow_dir)
    assert sites == [ExpressionSite("plant.yml", "demo", "One liner", 1)]


def test_an_unnamed_step_gets_a_stable_index_key(tmp_path: Path) -> None:
    """A step with no `name:` proposes its own key: `<unnamed step index N>`,
    stable under any edit that does not touch step order — the same guarantee
    a step NAME gives, since nothing here is keyed by line number either."""

    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo ${{ inputs.thing }}\n",
    )
    sites = run_block_expression_sites(workflow_dir)
    assert sites == [ExpressionSite("plant.yml", "demo", "<unnamed step index 0>", 1)]


def test_expressions_in_env_with_and_if_are_not_run_body_sites(tmp_path: Path) -> None:
    """SENSITIVITY the other way. `env:`, `with:`, and `if:` are the
    sanctioned path for a real GitHub Actions expression — a guard that
    refused them would refuse every ordinary workflow."""

    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Structured only\n"
        "        if: ${{ github.event_name == 'push' }}\n"
        "        env:\n"
        "          X: ${{ secrets.TOKEN }}\n"
        "        with:\n"
        "          value: ${{ inputs.thing }}\n"
        "        run: echo hi\n",
    )
    assert run_block_expression_sites(workflow_dir) == []


def test_a_run_body_with_no_opener_at_all_is_clean(tmp_path: Path) -> None:
    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Ordinary step\n"
        "        run: |\n"
        "          echo hi\n"
        "          echo bye\n",
    )
    assert run_block_expression_sites(workflow_dir) == []


def test_multiple_openers_in_one_body_are_all_counted(tmp_path: Path) -> None:
    workflow_dir = _write(
        tmp_path,
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Three openers\n"
        "        run: |\n"
        "          echo ${{ a }} ${{ b }}\n"
        "          echo ${{ c }}\n",
    )
    sites = run_block_expression_sites(workflow_dir)
    assert sites == [ExpressionSite("plant.yml", "demo", "Three openers", 3)]


# ── the baseline comparison in isolation ────────────────────────────────────


def test_a_new_unbaselined_site_is_named() -> None:
    measured = {("w.yml", "job", "New step"): 2}
    extra, missing, drifted = baseline_mismatches(measured, {})
    assert extra == measured
    assert missing == {}
    assert drifted == {}


def test_a_retired_site_left_in_the_baseline_is_named() -> None:
    """Half two of the ratchet: a site the tree no longer carries, but the
    baseline still names — the retirement did not actually lower the table."""

    baseline = {("w.yml", "job", "Retired step"): 3}
    extra, missing, drifted = baseline_mismatches({}, baseline)
    assert extra == {}
    assert missing == baseline
    assert drifted == {}


def test_a_count_that_moved_without_the_baseline_moving_is_named() -> None:
    baseline = {("w.yml", "job", "Step"): 1}
    measured = {("w.yml", "job", "Step"): 2}
    extra, missing, drifted = baseline_mismatches(measured, baseline)
    assert extra == {} and missing == {}
    assert drifted == {("w.yml", "job", "Step"): (1, 2)}


def test_an_exactly_matching_baseline_reports_nothing() -> None:
    """SENSITIVITY. A baseline that matches the tree exactly must report all
    three dicts empty, or a clean tree could never pass."""

    baseline = {("w.yml", "job", "Step"): 1}
    extra, missing, drifted = baseline_mismatches(dict(baseline), baseline)
    assert extra == {} and missing == {} and drifted == {}
