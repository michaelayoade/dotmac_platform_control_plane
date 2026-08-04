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

Local composite actions (`./.github/actions/...`) are exempt — they are this
repository's own code at this commit, so there is no external reference that
can move under them.
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


def _iter_uses() -> list[tuple[str, str]]:
    """(source file, `uses:` value) for every step in every workflow and every
    local composite action."""
    found: list[tuple[str, str]] = []
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(ACTIONS.glob("*/action.yml"))
    for path in files:
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
