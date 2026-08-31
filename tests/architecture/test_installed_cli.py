"""The installed CLI is an adapter, and its production shapes are ratcheted.

Three groups of checks, and they answer three different questions.

**Is it an adapter?** The command surface is compared against the declared
owner table in both directions, no mutating owner may live inside
`vendor_cp.cli`, and no mutating symbol may be claimed by two commands. Together
those make "the CLI implements no policy" a property rather than a sentence.

**Is its contract stable?** The exit codes, the refusal vocabulary, and the rule
that a secret never arrives as the value of a flag.

**Is it actually installed?** The two-directional ratchet over the production
shapes that mean "running from a checkout", plus the sensitivity proofs that
keep the ratchet from passing because its detector broke.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from vendor_cp.cli import GROUPS, build_parser
from vendor_cp.cli.delegate import FOUNDATION_OWNED_VERBS
from vendor_cp.cli.exits import REFUSAL_CODES, STATUS, ExitCode
from vendor_cp.cli.owners import DELEGATED_COMMANDS, OWNERS, by_command
from vendor_cp.identity import DISTRIBUTION
from vendor_cp.installed_surface import (
    BASELINE,
    BASELINE_REASONS,
    LEDGERS,
    SHAPES,
    sanctioned_entry_points,
    scan,
)

ROOT = Path(__file__).resolve().parents[2]

#: Option names that would mean a secret had arrived on argv. Substring match on
#: the option's own name, and the two safe suffixes are named exactly — an
#: allowlist matched loosely would re-admit the thing it was carved out of.
SECRET_OPTION_MARKERS = ("password", "secret", "token", "credential", "passphrase")
SAFE_SECRET_SUFFIXES = ("-file", "-stdin")


def _parsers() -> dict[str, argparse.ArgumentParser]:
    """Every leaf command parser, keyed by `"<group> <command>"`."""
    found: dict[str, argparse.ArgumentParser] = {}

    def walk(parser: argparse.ArgumentParser) -> None:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    command = child.get_default("command")
                    if command:
                        found[command] = child
                    walk(child)

    walk(build_parser())
    return found


# ── is it an adapter? ───────────────────────────────────────────────────────


def test_every_command_has_a_declared_owner_and_every_owner_a_command() -> None:
    """Both directions. A command with no owner is a decision with no home, and
    an owner with no command is a claim about a surface that does not exist."""
    assert set(_parsers()) == set(by_command())


def test_the_groups_are_exactly_the_ones_declared() -> None:
    parser = build_parser()
    groups = {
        name
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
        for name in action.choices
    }
    assert groups == set(GROUPS)


def test_no_mutating_command_names_an_owner_inside_the_cli() -> None:
    """A decision that existed only in the CLI would be a second authority.

    The browser, the API and a terminal must reach the same owner, so every
    mutating command's owner module is outside this package. `deployment
    foundation` is the one owner inside it and is explicitly not a mutation
    here: it forwards an argument vector to another distribution's console
    script and computes nothing.
    """
    inside = sorted(
        owner.command
        for owner in OWNERS
        if owner.mutates and owner.module.startswith("vendor_cp.cli")
    )
    assert inside == [], inside
    assert all(command in by_command() for command in DELEGATED_COMMANDS)


def test_no_mutating_owner_is_claimed_by_two_commands() -> None:
    """One symbol under two command names is how a second spelling starts."""
    seen: dict[str, list[str]] = {}
    for owner in OWNERS:
        if owner.mutates:
            seen.setdefault(f"{owner.module}:{owner.symbol}", []).append(owner.command)
    duplicates = {key: value for key, value in seen.items() if len(value) > 1}
    assert duplicates == {}, duplicates


def test_owner_modules_all_resolve() -> None:
    """A declared owner that cannot be located is a table describing nothing."""
    import importlib.util

    unresolved = sorted(
        {
            owner.module
            for owner in OWNERS
            if importlib.util.find_spec(owner.module) is None
        }
    )
    assert unresolved == [], unresolved


def test_the_foundation_verbs_are_not_reimplemented_as_commands() -> None:
    """Render, apply, observe and rollback belong to the Foundation.

    They are reached through the one passthrough, never re-grown here. A verb of
    ours colliding with one of theirs is the first step of a second renderer.
    """
    ours = {command.split(" ", 1)[1] for command in by_command()}
    assert ours.isdisjoint(FOUNDATION_OWNED_VERBS), ours & set(FOUNDATION_OWNED_VERBS)


# ── is its contract stable? ─────────────────────────────────────────────────


def test_the_exit_codes_are_the_declared_six_and_three_is_not_four() -> None:
    """A refusal and an absence look identical from outside and mean opposite
    things about whether to retry, so they are different numbers."""
    assert {int(code) for code in ExitCode} == {0, 2, 3, 4, 5, 6}
    assert int(ExitCode.REFUSED) != int(ExitCode.UNAVAILABLE)
    assert set(STATUS) == set(ExitCode)
    assert len(set(STATUS.values())) == len(STATUS)


def test_every_refusal_code_maps_to_a_declared_exit_code() -> None:
    assert set(REFUSAL_CODES.values()) <= set(ExitCode)
    assert ExitCode.OK not in set(REFUSAL_CODES.values())


def test_every_declared_refusal_code_is_raised_somewhere() -> None:
    """A vocabulary entry nobody raises is a promise to an operator that no code
    keeps. Two-directional against the source, so a retired raiser fails until
    its code is retired too."""
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "vendor_cp").rglob("*.py"))
        if path.name != "exits.py"
    )
    unused = sorted(code for code in REFUSAL_CODES if f'"{code}"' not in sources)
    assert unused == [], unused


def test_no_option_accepts_a_secret_as_its_value() -> None:
    """`/proc/<pid>/cmdline` is world-readable for as long as a process lives.

    So there is no `--password`, and this builds the real parser and inspects
    every option rather than grepping for the string: a flag added tomorrow in a
    module nobody thought to grep is exactly the one that would leak.
    """
    offenders: list[str] = []
    for command, parser in _parsers().items():
        for action in parser._actions:
            for option in action.option_strings:
                name = option.lstrip("-").lower()
                if not any(marker in name for marker in SECRET_OPTION_MARKERS):
                    continue
                takes_a_value = action.nargs != 0 and not isinstance(
                    action, argparse._StoreTrueAction
                )
                if takes_a_value and not option.endswith(SAFE_SECRET_SUFFIXES):
                    offenders.append(f"{command} {option}")
    assert offenders == [], offenders


def test_the_secret_option_guard_can_still_see_one(tmp_path: Path) -> None:
    """SENSITIVITY. An empty offender list is also what a broken check returns."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--password")
    action = next(a for a in parser._actions if a.option_strings == ["--password"])
    name = action.option_strings[0].lstrip("-").lower()
    assert any(marker in name for marker in SECRET_OPTION_MARKERS)
    assert not action.option_strings[0].endswith(SAFE_SECRET_SUFFIXES)


# ── is it actually installed? ───────────────────────────────────────────────


def test_the_production_shape_ratchet_is_exact() -> None:
    """Two-directional and SET-shaped.

    Set-shaped rather than counted, because a count survives a swap: retire one
    checkout-relative command while another gains the same ability and the
    number is unchanged, which is precisely the move worth catching. Comparing
    the matched TEXT means a new occurrence fails until declared, a retired one
    fails until the declaration is lowered, and an exchange fails both ways.
    """
    assert scan(ROOT) == BASELINE


def test_every_baselined_file_states_why_and_what_retires_it() -> None:
    """An exemption that cannot say what would remove it is one nobody removes."""
    baselined = {path for _, path in BASELINE}
    assert baselined == set(BASELINE_REASONS)
    assert all(reason.strip() for reason in BASELINE_REASONS.values())


def test_no_shape_is_declared_without_a_reason_to_refuse_it() -> None:
    assert all(shape.why.strip() for shape in SHAPES)
    assert len({shape.kind for shape in SHAPES}) == len(SHAPES)


def test_the_ledgers_it_skips_all_exist() -> None:
    """A skip naming a file that is not there stops skipping anything real."""
    missing = sorted(name for name in LEDGERS if not (ROOT / name).exists())
    assert missing == [], missing


@pytest.mark.parametrize(
    ("kind", "planted"),
    [
        ("pythonpath_src", "PYTHONPATH=src python3 scripts/thing.py\n"),
        ("python_scripts", "poetry run python scripts/thing.py\n"),
        ("ops_container_script_path", "compose run --rm ops scripts/thing.py\n"),
        ("checkout_relative_production_command", "cd /opt/dotmac/thing && ls\n"),
    ],
)
def test_the_ratchet_fires_on_a_planted_violation(
    tmp_path: Path, kind: str, planted: str
) -> None:
    """SENSITIVITY, direction one. An empty result is also what a broken
    detector produces, so prove each shape can still be seen."""
    (tmp_path / "deploy.sh").write_text(planted, encoding="utf-8")
    found = scan(tmp_path)
    assert any(found_kind == kind for found_kind, _ in found), (kind, found)


def test_the_ratchet_fires_on_a_planted_rsync_of_an_executable(tmp_path: Path) -> None:
    """SENSITIVITY, the shape with state in it."""
    (tmp_path / "deploy.sh").write_text(
        'rsync -azR -e ssh \\\n  scripts/deploy_production.sh \\\n  "$remote:$DIR/"\n',
        encoding="utf-8",
    )
    found = scan(tmp_path)
    assert ("rsync_executable_asset", "deploy.sh") in found
    assert found[("rsync_executable_asset", "deploy.sh")] == (
        "scripts/deploy_production.sh",
    )


@pytest.mark.parametrize(
    "conforming",
    [
        "docker compose run --rm --no-deps ops dotmac-platform admin migrate\n",
        "poetry run dotmac-platform admin migrate\n",
        "docker compose run --rm ops dotmac-platform diagnose self --strict\n",
        "rsync -az README.md \\\n  remote:/srv/\n",
        "cd /srv/app && docker compose up -d\n",
    ],
)
def test_the_ratchet_stays_silent_on_the_conforming_form(
    tmp_path: Path, conforming: str
) -> None:
    """SENSITIVITY, direction two — the half that is usually skipped.

    A detector that fires on everything passes the planted-violation test and is
    useless. The replacement shapes this lane introduced must be invisible to
    it, or every conversion would show up as new debt and the ratchet would
    train people to raise the baseline.
    """
    (tmp_path / "deploy.sh").write_text(conforming, encoding="utf-8")
    assert scan(tmp_path) == {}


def test_the_ratchet_catches_a_swap_that_leaves_the_count_unchanged(
    tmp_path: Path,
) -> None:
    """The reason it is set-shaped, stated as a test.

    One refused command replaced by a different refused command: same file, same
    kind, same count, different ability. A counted ratchet reports no change.
    """
    path = tmp_path / "deploy.sh"
    path.write_text("python3 scripts/alpha.py\n", encoding="utf-8")
    before = scan(tmp_path)
    path.write_text("python3 scripts/beta.py\n", encoding="utf-8")
    after = scan(tmp_path)
    assert {key: len(value) for key, value in before.items()} == {
        key: len(value) for key, value in after.items()
    }
    assert before != after


# ── entry-point identity ────────────────────────────────────────────────────


def test_a_sanctioned_entry_point_is_read_from_metadata_not_written_down() -> None:
    """Identity, not a substring.

    A sanctioned invocation runs code inside the installed distribution, which
    is not in this tree, so it can never appear in a scan of it; an unsanctioned
    one is in the tree and always does. No question of intent is asked anywhere.

    An unresolvable distribution is UNMONITORED rather than a pass — this test
    says so explicitly instead of skipping, because an absent guard reported as
    a passed guard is the failure the `None` return exists to prevent.
    """
    names = sanctioned_entry_points()
    if names is None:
        pytest.skip(
            "UNMONITORED: this distribution is not installed in the running "
            "environment, so the sanctioned entry-point set cannot be resolved. "
            "This is an absent guard, not a passed one."
        )
    assert names, "an installed distribution with no console script is a broken build"
    surface = (ROOT / "src" / "vendor_cp" / "installed_surface.py").read_text(
        encoding="utf-8"
    )
    for name in names:
        assert name not in surface, (
            f"{name!r} is written down in the ledger; it must be read from "
            "installed metadata, or the check degrades to substring matching"
        )


def test_no_console_script_name_is_a_substring_of_the_distribution_name() -> None:
    """The near-match hazard, checked rather than assumed.

    A console script's name can be a PREFIX of its own distribution name —
    `dotmac-deploy` inside `dotmac-deployment-foundation` is the live example —
    and a naive substring test then passes on the very line that makes it an
    identity check. This pair does not collide, and this test is what makes that
    a fact rather than a hope.
    """
    names = sanctioned_entry_points()
    if names is None:
        pytest.skip("UNMONITORED: distribution not installed; see the test above.")
    collisions = sorted(name for name in names if name in DISTRIBUTION)
    assert collisions == [], collisions


def test_the_console_script_is_declared_in_pyproject() -> None:
    """The one place the name IS written, and the only one."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.poetry.scripts]" in pyproject
    assert re.search(r"^dotmac-platform = ", pyproject, re.M)


# ── the clean-install acceptance is wired, and stays wired ──────────────────


def test_ci_runs_the_clean_install_acceptance_against_the_built_image() -> None:
    """The six acceptance steps, held to the workflow that performs them.

    Step 3 — remove access to the repository root — is the one that cannot be
    faked, and it is satisfied STRUCTURALLY: the runtime stage installs a wheel
    and copies no `src` and no `scripts`, so the checkout is not merely off the
    import path, it is not in the image. This test fails if any of that is
    quietly dropped, because a canary run against a checkout passes for the
    wrong reason and that is precisely how a package can report one identity
    while being another.
    """
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Clean-install acceptance" in workflow
    # 3 — the checkout is absent from the image, asserted rather than assumed.
    assert "test ! -e /app/src && test ! -e /app/scripts" in workflow
    # 1 + 2 — installed, and reporting a version the installer recorded.
    assert "platform --version" in workflow
    # 5 + 6 — purelib/platlib resolution and single mutation ownership.
    assert "diagnose self --strict" in workflow
    # 4 — every documented command's help, driven from the artifact's own table.
    assert "--help > /dev/null" in workflow
    # the 3-versus-4 split survives the container boundary.
    assert 'test "$status" -eq 4' in workflow
    # and it runs with no network, so nothing here can reach a database.
    assert "--network none --entrypoint dotmac-platform" in workflow


def test_the_image_job_still_builds_the_thing_the_acceptance_inspects() -> None:
    """An acceptance that ran against a different artifact would prove nothing."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--tag dotmac-vendor-control-plane:ci ." in workflow
    assert workflow.count("image=dotmac-vendor-control-plane:ci") == 1
