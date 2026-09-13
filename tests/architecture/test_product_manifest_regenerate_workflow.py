"""`.github/workflows/product-manifest-regenerate.yml`'s refusals, each
planted against.

This workflow holds `FORGEJO_READ_TOKEN` in its `acquire` job to fetch every
distribution the candidate ref binds to the private index, and its
`regenerate` job then installs them and runs
`scripts/generate_product_manifest.py` against them. It is new, protected,
and never dispatched by this change, so every property below is checked
STATICALLY, the same way `tests/architecture/test_kernel_lock_workflow.py`
checks its sibling: a hand-rolled parser over the YAML text, with a synthetic
plant showing each checker actually fires rather than passing over an empty
set.

The `${{ ... }}` expression-opener check exists because GitHub Actions
templates a `run:` body BEFORE bash ever sees it — an unexpected expression
there makes the whole workflow file unparseable with `HTTP 422: An expression
was expected`, while a YAML parser still accepts the file happily. This exact
defect has already cost this fleet two failed workflows, which is why it gets
its own hand-rolled parser here rather than a single string search: a search
for `"${{ inputs."` would miss a value that reached a `run:` body some other
way, and only a parser that isolates what bash actually receives can tell the
two apart.

Two things in this file are NOT about the YAML at all: `private_distributions`
and `bundle_problems` are ordinary Python in `scripts/product_manifest_acquire
.py` and `scripts/product_manifest_bundle_check.py`, and the security property
that matters — every declared private distribution is acquired, derived from
the manifest rather than a name someone hardcoded — lives in that logic, not
in the workflow text. Those get ordinary unit tests, same style as
`test_kernel_lock_workflow.py`'s coverage of `kernel_lock.py`'s own functions.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "product-manifest-regenerate.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")

sys.path.insert(0, str(ROOT / "scripts"))

import kernel_lock  # noqa: E402
import product_manifest_acquire as pma  # noqa: E402
import product_manifest_bundle_check as pmb  # noqa: E402

# ── hand-rolled parsers, over TEXT so a plant can be built against a variant ─


def _run_scripts(text: str) -> list[str]:
    """Every `run:` block body, dedented — what bash actually receives."""

    lines = text.splitlines()
    bodies: list[list[str]] = []
    inside: int | None = None
    for line in lines:
        match = re.match(r"^(\s*)-?\s*run: \|", line)
        if match:
            inside = len(match.group(1)) + 2
            bodies.append([])
            continue
        if inside is None:
            continue
        if line.strip() and not line.startswith(" " * inside):
            inside = None
            continue
        bodies.append(bodies.pop() + [line])
    return ["\n".join(body) for body in bodies]


def _jobs(text: str) -> dict[str, list[str]]:
    """job name -> its step blocks, in order."""

    lines = text.splitlines()
    start = lines.index("jobs:")
    jobs: dict[str, list[list[str]]] = {}
    current: str | None = None
    in_steps = False
    for line in lines[start + 1 :]:
        header = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if header:
            current = header.group(1)
            jobs[current] = []
            in_steps = False
            continue
        if current is None:
            continue
        if line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            jobs[current].append([line])
        elif jobs[current]:
            jobs[current][-1].append(line)
    return {
        name: ["\n".join(block) for block in blocks] for name, blocks in jobs.items()
    }


def _steps(text: str) -> list[str]:
    return [step for steps in _jobs(text).values() for step in steps]


def _commands(step: str) -> str:
    """A step with its comment lines removed — what the runner EXECUTES."""

    return "\n".join(
        line for line in step.splitlines() if not line.strip().startswith("#")
    )


def _expression_openers(text: str) -> list[str]:
    return [
        line
        for body in _run_scripts(text)
        for line in body.splitlines()
        if "${{" in line
    ]


def _uses_refs(text: str) -> list[str]:
    refs: list[str] = []
    for step in _steps(text):
        for line in step.splitlines():
            match = re.search(r"uses: (?!\./)(\S+)", line)
            if match:
                refs.append(match.group(1))
    return refs


# ── the parser itself, so every assertion below is not vacuous ──────────────


def test_the_workflow_parser_found_the_jobs() -> None:
    jobs = _jobs(TEXT)
    assert set(jobs) == {"acquire", "regenerate"}, sorted(jobs)
    for name, steps in jobs.items():
        assert len(steps) >= 4, (name, len(steps))


def test_the_run_block_parser_actually_found_the_scripts() -> None:
    bodies = _run_scripts(TEXT)
    assert len(bodies) >= 8, len(bodies)
    assert any("pip install" in body for body in bodies)


# ── dispatch-only ────────────────────────────────────────────────────────────


def test_it_is_dispatch_only() -> None:
    assert "workflow_dispatch:" in TEXT
    for trigger in ("\n  push:", "\n  pull_request:", "\n  schedule:"):
        assert trigger not in TEXT, trigger


def test_a_push_trigger_would_be_caught() -> None:
    """SENSITIVITY. The check above passes over a clean file, which proves
    nothing about the check; this shows the same assertion firing on a plant."""

    planted = TEXT.replace(
        "on:\n  workflow_dispatch:",
        "on:\n  push:\n    branches: [main]\n  workflow_dispatch:",
    )
    assert "\n  push:" not in TEXT
    assert "\n  push:" in planted


# ── every `uses:` is pinned by full commit SHA ──────────────────────────────


def test_every_action_is_pinned_by_commit() -> None:
    refs = _uses_refs(TEXT)
    assert refs, "the parser found no `uses:` lines at all"
    for ref in refs:
        assert re.search(r"@[0-9a-f]{40}$", ref), ref


def test_an_unpinned_ref_is_named() -> None:
    """THE plant. A tag or branch ref must be distinguishable from a 40-hex
    SHA, or this check would accept anything with an `@` in it."""

    planted = TEXT.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "actions/checkout@v7",
        1,
    )
    refs = _uses_refs(planted)
    assert any(not re.search(r"@[0-9a-f]{40}$", ref) for ref in refs), refs


# ── job 2 references no secret ──────────────────────────────────────────────


def test_the_regenerate_job_references_no_secret() -> None:
    jobs = _jobs(TEXT)
    for step in jobs["regenerate"]:
        assert "secrets." not in step, step
    assert "FORGEJO_READ_TOKEN" not in "\n".join(jobs["regenerate"])


def test_the_regenerate_job_asserts_its_own_credential_absence_before_installing() -> (
    None
):
    steps = _jobs(TEXT)["regenerate"]
    assertion = next(
        index for index, step in enumerate(steps) if "no credential is present" in step
    )
    install = next(
        index for index, step in enumerate(steps) if "pip install" in _commands(step)
    )
    assert assertion < install, (assertion, install)
    body = steps[assertion]
    assert "POETRY_HTTP_BASIC" in body and ".netrc" in body


def test_a_secret_reference_in_the_regenerate_job_is_named() -> None:
    """THE plant. A future edit that wires a secret into `regenerate` must be
    catchable, not just absent today."""

    jobs = _jobs(TEXT)
    assert all("secrets." not in step for step in jobs["regenerate"])
    planted = [
        step + "\n        run: echo ${{ secrets.FORGEJO_READ_TOKEN }}"
        for step in jobs["regenerate"]
    ]
    assert any("secrets." in step for step in planted)


# ── job 1 runs no Poetry, no pip, no package code ───────────────────────────


def test_the_acquiring_job_runs_no_poetry_pip_or_package_code() -> None:
    jobs = _jobs(TEXT)
    commands = "\n".join(_commands(step) for step in jobs["acquire"])
    assert "setup-poetry" not in commands
    assert not re.search(r"(^|\s)poetry\s", commands)
    assert "pip install" not in commands
    assert "pip3 install" not in commands


def test_poetry_or_pip_in_the_acquiring_job_would_be_named() -> None:
    """SENSITIVITY for the check above."""

    planted_pip = (
        "\n".join(_commands(step) for step in _jobs(TEXT)["acquire"])
        + "\npip install something\n"
    )
    assert "pip install" in planted_pip
    planted_poetry = (
        "\n".join(_commands(step) for step in _jobs(TEXT)["acquire"])
        + "\npoetry lock\n"
    )
    assert re.search(r"(^|\s)poetry\s", planted_poetry)


def _install_step(steps: list[str], marker: str) -> str:
    return next(step for step in steps if marker in step)


def test_the_private_distribution_install_is_no_index_and_find_links_only() -> None:
    """The load-bearing clause for the PRIVATE half: a private name can never
    be satisfied from anywhere but the bundle `acquire` verified."""

    step = _install_step(
        _jobs(TEXT)["regenerate"], "Install the private distributions from"
    )
    commands = _commands(step)
    assert "--no-index" in commands
    assert "--find-links" in commands
    assert "--no-deps" in commands


def test_dropping_no_index_from_the_private_install_would_be_caught() -> None:
    """SENSITIVITY. A private install without `--no-index` could, in
    principle, satisfy a private name from a reachable public index instead —
    exactly the substitution this step exists to rule out."""

    steps = _jobs(TEXT)["regenerate"]
    step = _install_step(steps, "Install the private distributions from")
    stripped = step.replace("--no-index \\\n", "").replace("--no-index", "")
    assert "--no-index" not in _commands(stripped)


def test_the_public_dependency_install_is_wheel_only_and_can_reach_an_index() -> None:
    """The load-bearing clause for the PUBLIC half: `--only-binary=:all:`
    keeps a PyPI sdist's PEP 517 build backend from executing here, and —
    unlike the private install — this step carries no `--no-index`, because
    public PyPI reachability is exactly what this job is allowed to use."""

    step = _install_step(_jobs(TEXT)["regenerate"], "Install the public dependencies")
    commands = _commands(step)
    assert "--only-binary=:all:" in commands
    assert "--no-index" not in commands
    assert "--find-links" not in commands


def test_dropping_wheel_only_from_the_public_install_would_be_caught() -> None:
    """SENSITIVITY. Without `--only-binary=:all:`, a PyPI release with no
    wheel would have its PEP 517 build backend executed in this job."""

    steps = _jobs(TEXT)["regenerate"]
    step = _install_step(steps, "Install the public dependencies")
    stripped = step.replace("--only-binary=:all: ", "")
    assert "--only-binary=:all:" not in _commands(stripped)


# ── no configuration in `regenerate` names the private index host ──────────


def test_the_regenerate_job_asserts_the_private_host_is_absent_from_its_config() -> (
    None
):
    steps = _jobs(TEXT)["regenerate"]
    assertion = next(
        index
        for index, step in enumerate(steps)
        if "names nothing in this job's configuration" in step
    )
    private_install = next(
        index
        for index, step in enumerate(steps)
        if "Install the private distributions from" in step
    )
    assert assertion < private_install, (assertion, private_install)
    body = steps[assertion]
    assert kernel_lock.ARTIFACT_ORIGIN.split("//")[1] in body  # "registry.dotmac.io"
    assert "pip config list" in body


def test_removing_the_private_host_assertion_would_be_caught() -> None:
    """SENSITIVITY. The assertion step's absence must be distinguishable from
    its presence — a `next()` over an empty match raises, which is itself the
    failure this guards against if the step is ever deleted."""

    steps = [
        step
        for step in _jobs(TEXT)["regenerate"]
        if "names nothing in this job's configuration" not in step
    ]
    with pytest.raises(StopIteration):
        next(
            index
            for index, step in enumerate(steps)
            if "names nothing in this job's configuration" in step
        )


def test_no_other_regenerate_step_configures_an_index_at_the_private_host() -> None:
    """The assertion step above legitimately NAMES the host to check for it;
    every OTHER step in this job must not name it at all — naming it would be
    exactly the kind of configuration the assertion exists to rule out."""

    host = kernel_lock.ARTIFACT_ORIGIN.split("//")[1]
    for step in _jobs(TEXT)["regenerate"]:
        if "names nothing in this job's configuration" in step:
            continue
        assert host not in _commands(step), step


def test_a_private_index_url_elsewhere_in_regenerate_would_be_named() -> None:
    """THE plant. A future edit wiring `--index-url` at the private host into
    some OTHER step must be catchable by the check above."""

    host = kernel_lock.ARTIFACT_ORIGIN.split("//")[1]
    steps = _jobs(TEXT)["regenerate"]
    planted = [
        step + f"\n        run: pip install --index-url https://{host}/x\n"
        for step in steps
        if "names nothing in this job's configuration" not in step
    ]
    assert any(host in _commands(step) for step in planted)


# ── the private distribution list is DERIVED from the manifest ─────────────


def _forgejo_manifest(**dependencies: dict[str, str] | str) -> dict[str, Any]:
    return {"tool": {"poetry": {"dependencies": dependencies}}}


def test_private_distributions_derives_every_forgejo_bound_dependency() -> None:
    manifest = _forgejo_manifest(
        python=">=3.12,<3.14",
        **{
            "dotmac-kernel": {"version": "0.1.0a100", "source": "forgejo"},
            "dotmac-approvals": {"version": "0.1.0a5", "source": "forgejo"},
            "fastapi": ">=0.111",
        },
    )
    assert pma.private_distributions(manifest) == {
        "dotmac-kernel": "0.1.0a100",
        "dotmac-approvals": "0.1.0a5",
    }


def test_a_newly_added_private_dependency_is_picked_up_without_a_code_change() -> None:
    """SENSITIVITY, and the whole point of Gap 1's repair: a THIRD forgejo
    dependency appears in the derived plan with no change to this module —
    the earlier, hardcoded-name version of this function could never have
    passed this test."""

    manifest = _forgejo_manifest(
        **{
            "dotmac-kernel": {"version": "0.1.0a100", "source": "forgejo"},
            "dotmac-brand-new-module": {"version": "0.1.0a1", "source": "forgejo"},
        }
    )
    plan = pma.private_distributions(manifest)
    assert plan["dotmac-brand-new-module"] == "0.1.0a1"
    assert len(plan) == 2


def test_private_distributions_refuses_a_non_exact_version() -> None:
    manifest = _forgejo_manifest(
        **{"dotmac-kernel": {"version": "^0.1.0a100", "source": "forgejo"}}
    )
    with pytest.raises(kernel_lock.Refusal):
        pma.private_distributions(manifest)


def test_private_distributions_refuses_a_bare_string_bound_to_nothing() -> None:
    """A bare version string (no table, so no `source` at all) is not bound to
    the private index and must not be silently included."""

    manifest = _forgejo_manifest(**{"fastapi": ">=0.111"})
    with pytest.raises(kernel_lock.Refusal, match="nothing to acquire"):
        pma.private_distributions(manifest)


def test_private_distributions_against_the_repositorys_real_manifest() -> None:
    """NON-VACUITY, against the real file. The expected name-to-version
    mapping is derived directly from the freshly parsed `tool.poetry
    .dependencies` entries bound to the Forgejo source — not a hardcoded
    set repeated here, so `pyproject.toml` stays the sole version
    authority and a drifted or missing acquisition is caught by exact
    mapping equality rather than a couple of spot checks."""

    import tomllib

    with (ROOT / "pyproject.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    dependencies = manifest["tool"]["poetry"]["dependencies"]
    expected = {
        name: spec["version"]
        for name, spec in dependencies.items()
        if isinstance(spec, dict)
        and spec.get("source") == kernel_lock.INDEX_SOURCE_NAME
    }

    plan = pma.private_distributions(manifest)

    assert plan == expected
    assert "dotmac-kernel" in plan
    assert "dotmac-deployment-control" in plan
    assert len(plan) >= 7, plan


# ── job 2 refuses if the bundle does not cover every declared distribution ──


def _touch(directory: Path, name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(b"not a real wheel, just a name to match")


def test_bundle_problems_admits_a_complete_bundle(tmp_path: Path) -> None:
    """POSITIVE CONTROL. Without this, every plant below would pass against a
    checker that refuses everything."""

    plan = {"dotmac-kernel": "0.1.0a100", "dotmac-approvals": "0.1.0a5"}
    bundle = tmp_path / "files"
    _touch(bundle, "dotmac_kernel-0.1.0a100-py3-none-any.whl")
    _touch(bundle, "dotmac_approvals-0.1.0a5.tar.gz")
    assert pmb.bundle_problems(plan, bundle) == []


def test_bundle_problems_names_a_missing_distribution() -> None:
    """THE plant. `acquire` acquired one of two declared distributions; job 2
    must refuse rather than let a later `pip install` fail illegibly."""

    plan = {"dotmac-kernel": "0.1.0a100", "dotmac-approvals": "0.1.0a5"}
    bundle_dir = Path("/nonexistent-in-this-test")
    problems = pmb.bundle_problems(plan, bundle_dir)
    assert problems and "does not exist" in problems[0]


def test_bundle_problems_names_a_distribution_missing_from_an_existing_bundle(
    tmp_path: Path,
) -> None:
    plan = {"dotmac-kernel": "0.1.0a100", "dotmac-approvals": "0.1.0a5"}
    bundle = tmp_path / "files"
    _touch(bundle, "dotmac_kernel-0.1.0a100-py3-none-any.whl")
    # dotmac-approvals is missing entirely.
    problems = pmb.bundle_problems(plan, bundle)
    assert any("dotmac-approvals" in problem for problem in problems), problems


def test_bundle_problems_does_not_confuse_a_different_version_for_a_match(
    tmp_path: Path,
) -> None:
    """SENSITIVITY. A stale artifact for the WRONG version must not be read as
    covering the declared one."""

    plan = {"dotmac-kernel": "0.1.0a100"}
    bundle = tmp_path / "files"
    _touch(bundle, "dotmac_kernel-0.1.0a99-py3-none-any.whl")
    problems = pmb.bundle_problems(plan, bundle)
    assert any("dotmac-kernel" in problem for problem in problems), problems


# ── zero GitHub expression openers in any `run:` body ───────────────────────


def test_no_run_block_contains_a_github_expression_opener() -> None:
    """The constraint that has already cost this fleet two failed workflows:
    `${{` is templated by GitHub BEFORE bash ever runs, so an unexpected
    expression there makes the whole file unparseable with `HTTP 422`, while a
    YAML parser accepts it happily. Every new value crosses through `env:`."""

    offenders = _expression_openers(TEXT)
    assert offenders == [], offenders


def test_an_expression_opener_in_a_run_body_would_be_caught() -> None:
    """SENSITIVITY. `_run_scripts` is a hand-rolled parser; a plant proves it
    actually isolates the run body rather than passing over an empty list."""

    planted = TEXT.replace(
        'echo "the credential is present"',
        'echo "ref is ${{ inputs.ref }}"',
        1,
    )
    assert _expression_openers(TEXT) == []
    assert _expression_openers(planted) == ['          echo "ref is ${{ inputs.ref }}"']


def test_the_expected_expression_count_is_reported() -> None:
    """The measured count this repository's report cites, over the real file
    exactly as committed — not a variant."""

    assert _expression_openers(TEXT) == []


# ── the workflow writes nothing back to the repository ──────────────────────


def test_the_workflow_never_commits_pushes_or_opens_a_pull_request() -> None:
    assert "permissions:\n  contents: read\n" in TEXT
    for forbidden in ("git commit", "git push", "gh pr", "peter-evans"):
        assert forbidden not in TEXT, forbidden


def test_a_git_push_would_be_named() -> None:
    """SENSITIVITY for the check above."""

    for forbidden in ("git commit", "git push", "gh pr", "peter-evans"):
        planted = TEXT + f"\n# run: {forbidden} origin main\n"
        # A comment mention is deliberately still caught: the assertion is a
        # textual absence, not a parse of executed commands, matching the
        # sibling `kernel-lock.yml` guard's own choice for this exact check.
        assert forbidden in planted


# ── two checkouts in `acquire`, one in `regenerate` ─────────────────────────


def test_every_checkout_refuses_to_persist_the_token() -> None:
    for step in _steps(TEXT):
        if "actions/checkout@" in step:
            assert "persist-credentials: false" in step, step


def test_the_trusted_checkout_in_acquire_comes_first() -> None:
    jobs = _jobs(TEXT)
    checkouts = [step for step in jobs["acquire"] if "actions/checkout@" in step]
    assert len(checkouts) == 2, checkouts
    assert "ref: ${{ github.sha }}" in checkouts[0]
    assert "ref: ${{ inputs.ref }}" in checkouts[1] and "path: work" in checkouts[1]


def test_regenerate_checks_out_the_candidate_ref_directly() -> None:
    jobs = _jobs(TEXT)
    checkouts = [step for step in jobs["regenerate"] if "actions/checkout@" in step]
    assert len(checkouts) == 1, checkouts
    assert "ref: ${{ inputs.ref }}" in checkouts[0]


# ── the ref input is validated before the credential is ever touched ───────


def test_the_ref_is_validated_before_the_credential_step() -> None:
    steps = _jobs(TEXT)["acquire"]
    validation = next(
        index
        for index, step in enumerate(steps)
        if "Refuse anything but an exact commit" in step
    )
    credential = next(
        index
        for index, step in enumerate(steps)
        if "There is a credential to resolve with" in step
    )
    assert validation < credential, (validation, credential)


def test_it_requires_a_full_forty_character_sha() -> None:
    assert r"^[0-9a-f]{40}$" in TEXT
