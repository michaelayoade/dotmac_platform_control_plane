"""Every third-party GitHub Action is pinned to an immutable commit SHA.

Deny-case D7. A `uses:` reference like `snok/install-poetry@v1` resolves a
MUTABLE tag: whoever controls the tag controls code executing on the
self-hosted `dotmac-s3` runner — the same runner deliberately kept out of the
docker group precisely so workflow code cannot reach root-equivalent host
control. A tag is a pointer; only a full commit SHA is an immutable reference.

This repo already applied that rule to the governance source it pins by exact
commit (AGENTS.md rule 9, which names mutable tags as an unacceptable
substitute). The rule simply had not reached the workflows enforcing it: two
`snok/install-poetry@v1` call sites ran unpinned until 2026-08-04.

Local composite actions (`./.github/actions/...`) are exempt from the SHA rule,
because there is no external reference that can move under them.

The premise behind that exemption is narrower than it reads, and one workflow
broke it. `./...` resolves against `$GITHUB_WORKSPACE`, so a local action is
this repository's own code at this commit ONLY while the workspace holds this
commit. `.github/workflows/kernel-lock.yml` checked out a caller-supplied
`inputs.ref` and then loaded `./.github/actions/setup-poetry` from it, in a job
holding `FORGEJO_READ_TOKEN` — the dispatched ref's own code, running with the
credential. The repair puts the trusted commit at the workspace root and the
ref under resolution at `work/`; `test_kernel_lock_workflow.py` holds that
shape. This module's exemption still stands for every workflow whose workspace
root is its own commit, which is every other one here — it is an exemption with
a premise, not a blanket.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
ACTIONS = REPO / ".github" / "actions"

_SHA = re.compile(r"^[0-9a-f]{40}$")
# Deliberately textual rather than a YAML parse: this repo does not depend on
# PyYAML, and adding a dependency so a lint test can read four files would be a
# worse trade than a regex over a line shape GitHub Actions fixes anyway. The
# trailing `# v7.0.0` comment is stripped, not matched.
_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>[^\s#]+)")


def _workflow_files() -> list[Path]:
    """Every file GitHub would treat as a workflow or a local action manifest.

    BOTH extensions, RECURSIVELY. GitHub accepts `.yml` and `.yaml` for
    workflows, and `action.yml` or `action.yaml` for action metadata — so a
    checker scanning only `*.yml` one directory deep can be bypassed by a
    perfectly valid `.yaml` file, which would then escape every assertion in
    this module. That is a silent hole in a supply-chain guard, not mere
    laxity.
    """
    files: list[Path] = []
    for ext in ("yml", "yaml"):
        files += WORKFLOWS.rglob(f"*.{ext}")
        files += ACTIONS.rglob(f"action.{ext}")
    return sorted(set(files))


def _iter_uses() -> list[tuple[str, str]]:
    """(source file, `uses:` value) for every step in every workflow and every
    local composite action."""
    found: list[tuple[str, str]] = []
    for path in _workflow_files():
        rel = str(path.relative_to(REPO))
        for line in path.read_text().splitlines():
            match = _USES.match(line)
            if match:
                found.append((rel, match.group("ref").strip("'\"")))
    return found


def test_every_third_party_action_is_pinned_to_a_full_sha() -> None:
    violations: list[str] = []
    for rel, uses in _iter_uses():
        if uses.startswith("./"):
            continue  # this repo's own code at this commit
        if "@" not in uses:
            violations.append(f"{rel}: `{uses}` has no ref at all")
            continue
        ref = uses.rsplit("@", 1)[1]
        if not _SHA.match(ref):
            violations.append(
                f"{rel}: `{uses}` is pinned to `{ref}`, which is a MUTABLE tag "
                "or branch, not an immutable commit SHA"
            )
    assert not violations, (
        "Third-party actions must be pinned to a full 40-character commit SHA "
        "(add the human-readable version as a trailing comment):\n  "
        + "\n  ".join(violations)
    )


def test_the_checker_would_catch_a_mutable_tag() -> None:
    """Sensitivity proof — the assertion above is only meaningful if the SHA
    pattern actually rejects what it is supposed to reject."""
    assert not _SHA.match("v1")
    assert not _SHA.match("main")
    assert not _SHA.match("v7.0.0")
    assert not _SHA.match("3d3c42e5aac5ba805825da76410c181273ba90b1x")  # 41
    assert not _SHA.match("3D3C42E5AAC5BA805825DA76410C181273BA90B1")  # uppercase
    assert _SHA.match("3d3c42e5aac5ba805825da76410c181273ba90b1")


def test_poetry_is_installed_from_the_hash_locked_bootstrap() -> None:
    """No workflow may reinstate a network Poetry installer alongside the
    pinned one — the bootstrap is worthless if something else also installs
    Poetry unpinned."""
    offenders = [
        f"{rel}: {uses}"
        for rel, uses in _iter_uses()
        # `./.github/actions/setup-poetry` IS the sanctioned path — only a
        # THIRD-PARTY action mentioning poetry is an offender.
        if not uses.startswith("./") and "poetry" in uses.lower().split("@")[0]
    ]
    assert not offenders, (
        "Poetry must come from .github/bootstrap/poetry-requirements.txt via "
        "./.github/actions/setup-poetry, not a third-party installer action:\n  "
        + "\n  ".join(offenders)
    )


def test_the_bootstrap_requirements_are_fully_hash_pinned() -> None:
    """Every requirement carries `==` and at least one sha256 hash. A single
    unpinned line disables --require-hashes for the whole file."""
    req = (REPO / ".github" / "bootstrap" / "poetry-requirements.txt").read_text()
    # Join the backslash continuations so each requirement is one logical line.
    logical = [
        line.strip()
        for line in req.replace("\\\n", " ").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert logical, "the bootstrap requirements file is empty"
    for line in logical:
        name = line.split()[0]
        assert "==" in name, f"{name!r} is not pinned to an exact version"
        assert "--hash=sha256:" in line, f"{name!r} carries no sha256 hash"


def test_the_bootstrap_installs_into_a_fresh_venv_not_the_interpreter() -> None:
    """pip leaves an already-satisfied requirement untouched, and hashes cover
    archives being INSTALLED — not packages already on disk. Installing into
    the interpreter's own site-packages therefore verifies nothing on a
    persistent runner, which is exactly what happened on the self-hosted
    `dotmac-s3` runner on 2026-08-04: every package "Requirement already
    satisfied" from the shared tool cache, nothing downloaded, no hash checked.
    Only a freshly created venv makes skipping impossible."""
    action = (ACTIONS / "setup-poetry" / "action.yml").read_text()
    assert 'rm -rf "$venv"' in action, "the venv is not recreated, so pip may skip"
    assert "python -m venv" in action, "no venv is created"
    assert (
        '"$venv/bin/python" -m pip install' in action
    ), "pip must install into the venv's interpreter, not the job's"
    assert "--require-hashes" in action
    assert (
        'echo "${venv}/bin" >> "$GITHUB_PATH"' in action
    ), "the verified venv is never published on PATH"
    assert (
        "command -v poetry" in action
    ), "nothing asserts that the poetry on PATH is the verified one"


def test_a_dot_yaml_workflow_cannot_bypass_the_checks() -> None:
    """Sensitivity proof for the extension coverage. GitHub runs `.yaml`
    workflows exactly as it runs `.yml`, so prove discovery picks one up rather
    than trusting the glob by inspection."""
    probe = WORKFLOWS / "_pinning_probe_.yaml"
    probe.write_text(
        "name: probe\njobs:\n  p:\n    steps:\n"
        "      - uses: snok/install-poetry@v1\n"
    )
    try:
        assert probe in _workflow_files(), ".yaml workflows are not discovered"
        refs = [uses for rel, uses in _iter_uses() if "_pinning_probe_" in rel]
        assert refs == [
            "snok/install-poetry@v1"
        ], "a .yaml workflow's `uses:` was not read"
    finally:
        probe.unlink(missing_ok=True)


def test_a_dot_yaml_action_manifest_is_also_scanned() -> None:
    """Same hole one level down: action metadata may be `action.yaml`."""
    probe_dir = ACTIONS / "_pinning_probe_"
    probe = probe_dir / "action.yaml"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe.write_text(
        "name: probe\nruns:\n  using: composite\n  steps:\n"
        "      - uses: some/action@main\n"
    )
    try:
        assert probe in _workflow_files(), "action.yaml manifests are not scanned"
    finally:
        probe.unlink(missing_ok=True)
        probe_dir.rmdir()
