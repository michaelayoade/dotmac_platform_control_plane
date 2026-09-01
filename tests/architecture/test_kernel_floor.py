"""The kernel pin is derived and falsifiable, not compared by eye.

The census that recorded the composed modules' declared kernel floors ended by
refusing to upgrade them: "The floors above are declarations, not contracts, and
this census does not upgrade them by repeating them." These are the contract.

Two directions, and both have to be able to fail:

* pinned too LOW — `dotmac-deployment-control 0.1.0a5` shipped byte-perfect
  bytes that could not boot here, because it imported a kernel module its
  declared floor did not require. The static half below refuses a pin that does
  not satisfy every composed distribution's own `Requires-Dist`.
* pinned too HIGH — a kernel upgrade nobody asked for still owes the migration
  rehearsal a kernel upgrade owes. `missing-from` refuses when every module the
  composition imports is already present in the excluded kernel, and the pin is
  held equal to the highest floor anything composed declares.

Every refusal path here is executed against a planted violation. A parser whose
error branch has never run is prose.
"""

from __future__ import annotations

import re
import sys
import textwrap
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from kernel_floor import (  # noqa: E402
    DEPENDENCY,
    FloorError,
    absent_from_kernel,
    binding_distribution,
    composed_distributions,
    declared_kernel_floors,
    declared_pin,
    index_versions,
    kernel_imports,
    newest_excluded,
    parse,
)

WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _pyproject(tmp_path: Path, kernel: str) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        textwrap.dedent(
            f"""
            [tool.poetry.dependencies]
            python = ">=3.12,<3.14"
            {kernel}
            dotmac-approvals = {{ version = "0.1.0a5", source = "forgejo" }}
            """
        ).strip()
    )
    return path


# ── the pin, and what binds it ──────────────────────────────────────────────


def test_the_pin_is_exactly_the_highest_floor_anything_composed_declares() -> None:
    """Neither under- nor over-constrained, and the module that asked is named.

    Held as equality rather than as `>=`. A pin above every declared floor is
    not obviously safe: it is a kernel upgrade taken on nobody's behalf, and it
    carries a migration rehearsal obligation somebody has to have discharged. If
    this assembly's OWN imports ever require a kernel higher than any composed
    module asks for, that becomes a second input to this assertion and must be
    added here in the same change — not worked around by loosening it.
    """

    pin = declared_pin()
    name, floor = binding_distribution()

    assert pin == floor, (
        f"this assembly pins {DEPENDENCY} {pin} while the highest floor any "
        f"composed distribution declares is {floor}, from {name}. Declared "
        f"floors: {sorted(declared_kernel_floors().items())}."
    )


def test_every_composed_distribution_declares_a_readable_kernel_floor() -> None:
    """A composed module with an unreadable floor is unmonitored, not satisfied."""

    composed = set(composed_distributions())
    assert composed, "the dependency table names no forgejo-sourced module"
    assert set(declared_kernel_floors()) == composed


def test_the_declared_floors_are_read_from_metadata_and_not_from_the_census() -> None:
    """The sensitivity half: an injected declaration changes the answer.

    Without this, `declared_kernel_floors` returning today's numbers is equally
    consistent with it returning a constant.
    """

    floors = declared_kernel_floors(
        distributions=("pretend-module",),
        requirements_of=lambda _: ["dotmac-kernel (>=0.1.0a12)"],
    )
    assert floors == {"pretend-module": "0.1.0a12"}
    assert binding_distribution(floors) == ("pretend-module", "0.1.0a12")


@pytest.mark.parametrize(
    "requirement",
    [
        "dotmac-kernel (>=0.1.0a98,<0.2)",
        "dotmac-kernel (==0.1.0a98)",
        "dotmac-kernel (^0.1.0a98)",
        "dotmac-kernel",
    ],
)
def test_a_kernel_requirement_shape_it_was_not_taught_is_refused(
    requirement: str,
) -> None:
    """A ceiling or an exact pin in a MODULE changes what its floor means."""

    with pytest.raises(FloorError, match="readable kernel floor"):
        declared_kernel_floors(
            distributions=("pretend-module",),
            requirements_of=lambda _: [requirement],
        )


@pytest.mark.parametrize(
    "declared",
    [
        'dotmac-kernel = { version = ">=0.1.0a98", source = "forgejo" }',
        'dotmac-kernel = { version = "^0.1.0a98", source = "forgejo" }',
        'dotmac-kernel = { version = "*", source = "forgejo" }',
        'dotmac-kernel = ">=0.1.0a98"',
        'dotmac-kernel = { git = "https://example.invalid/k.git" }',
    ],
)
def test_a_pin_that_is_not_an_exact_version_is_refused(
    tmp_path: Path, declared: str
) -> None:
    with pytest.raises(FloorError):
        declared_pin(_pyproject(tmp_path, declared))


def test_a_missing_kernel_dependency_is_refused(tmp_path: Path) -> None:
    with pytest.raises(FloorError, match="declares no dotmac-kernel"):
        declared_pin(_pyproject(tmp_path, "# no kernel here"))


def test_a_dependency_table_with_no_composed_module_is_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[tool.poetry.dependencies]\ndotmac-kernel = { version = "0.1.0a98", '
        'source = "forgejo" }\n'
    )
    with pytest.raises(FloorError, match="absent-as-success"):
        composed_distributions(path)


# ── the mutation target ─────────────────────────────────────────────────────


def test_versions_are_ordered_numerically_and_not_textually() -> None:
    """`0.1.0a97` sorts above `0.1.0a100` as text; the kernel is past a100."""

    listing = " ".join(
        f"dotmac_kernel-{version}-py3-none-any.whl"
        for version in ("0.1.0a97", "0.1.0a98", "0.1.0a100")
    )
    versions = index_versions(listing)

    assert versions == ["0.1.0a97", "0.1.0a98", "0.1.0a100"]
    assert versions != sorted(versions)  # the textual order would differ
    assert newest_excluded("0.1.0a100", versions) == "0.1.0a98"
    assert newest_excluded("0.1.0a98", versions) == "0.1.0a97"


def test_the_mutation_target_skips_a_gap_in_the_index() -> None:
    """The index has holes — there is no published `0.1.0a96`.

    Computing "the pin minus one" would name a version that was never published
    and the lane would fail on a resolver error while reporting the pin proven.
    """

    listing = " ".join(
        f"dotmac_kernel-{version}.tar.gz" for version in ("0.1.0a95", "0.1.0a97")
    )
    assert newest_excluded("0.1.0a98", index_versions(listing)) == "0.1.0a97"


def test_an_index_with_nothing_below_the_pin_is_refused() -> None:
    with pytest.raises(FloorError, match="nobody has seen refuse"):
        newest_excluded("0.1.0a1", index_versions("dotmac_kernel-0.1.0a5.tar.gz"))


def test_an_unorderable_version_is_refused_rather_than_guessed_at() -> None:
    with pytest.raises(FloorError):
        parse("0.1.0b1")
    with pytest.raises(FloorError):
        parse("0.1.0")


# ── the imports the mutation's failure must name ────────────────────────────


def test_kernel_imports_are_parsed_and_not_grepped(tmp_path: Path) -> None:
    """A docstring naming a module is not an import of it.

    This module's own docstring names `dotmac_kernel.transactions` repeatedly
    and imports none of it.
    """

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "prose.py").write_text(
        '"""Mentions dotmac_kernel.transactions and dotmac_kernel.licensing."""\n'
    )
    (package / "real.py").write_text(
        "from dotmac_kernel.db import conflict_savepoint\nimport dotmac_kernel.audit\n"
    )

    assert kernel_imports([package]) == {
        "dotmac_kernel.db",
        "dotmac_kernel.audit",
    }


def test_absent_from_kernel_is_sensitive_in_both_directions(tmp_path: Path) -> None:
    kernel = tmp_path / "dotmac_kernel"
    (kernel / "migrations").mkdir(parents=True)
    (kernel / "__init__.py").write_text("")
    (kernel / "db.py").write_text("")
    (kernel / "migrations" / "catalog.py").write_text("")

    imported = ("dotmac_kernel", "dotmac_kernel.db", "dotmac_kernel.migrations.catalog")
    assert absent_from_kernel(kernel, imported) == ()
    assert absent_from_kernel(kernel, (*imported, "dotmac_kernel.transactions")) == (
        "dotmac_kernel.transactions",
    )


def test_comparing_against_a_directory_that_is_not_a_kernel_is_refused(
    tmp_path: Path,
) -> None:
    """Every module absent reads as a proof, and is the absence of one."""

    with pytest.raises(FloorError, match="reads as a proof"):
        absent_from_kernel(tmp_path / "nowhere", ("dotmac_kernel.db",))


# ── the lane may not restate what it is supposed to derive ──────────────────


def _executable_workflow() -> str:
    return "\n".join(
        line
        for line in WORKFLOW.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_mutation_lane_derives_its_versions_and_module_names() -> None:
    """A literal here is how a lane stops testing anything and says nothing.

    Bumping the pin without touching a hard-coded mutation target leaves the
    lane installing a version the pin no longer excludes; bumping it without
    touching a hard-coded module name leaves the lane demanding a failure that
    cannot happen. Both are silent.
    """

    executable = _executable_workflow()

    pinned = re.findall(r"dotmac-kernel==0\.1\.0a\d+", executable)
    assert not pinned, (
        f"the workflow pins {pinned} literally. The pin comes from the "
        "declaration and the mutation target from the index, or the lanes stop "
        "tracking what they claim to test."
    )
    named = re.findall(r"dotmac_kernel\.[a-z_]+", executable)
    assert not named, (
        f"the workflow names {named} literally. The module the mutation's "
        "failure must carry is derived from the composition's real imports, for "
        "the same reason as the two versions."
    )


def test_the_mutation_lane_calls_every_verb_it_needs() -> None:
    executable = _executable_workflow()

    for verb in ("pinned", "excluded", "missing-from"):
        assert f"kernel_floor.py {verb}" in executable, (
            f"the mutation lane never asks for `{verb}`. All three derived facts "
            "are load-bearing: the pin it installs, the version it must be "
            "refused against, and the name its failure has to carry."
        )


def test_the_pin_the_tests_read_is_the_pin_the_lockfile_resolved() -> None:
    """One authority for the version, checked against the resolved lock.

    `test_release_catalog_composition` asserts the literal pin, which is what
    makes a repin a reviewed change. This asserts the LOCK agrees with it, so a
    pin edited without `poetry lock` cannot pass both.
    """

    pin = declared_pin()
    lock = (ROOT / "poetry.lock").read_text()
    match = re.search(
        r'\[\[package\]\]\nname = "dotmac-kernel"\nversion = "([^"]+)"', lock
    )
    assert match is not None, "poetry.lock names no dotmac-kernel package"
    assert match.group(1) == pin

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())
    table = declared["tool"]["poetry"]["dependencies"][DEPENDENCY]
    assert table["source"] == "forgejo"


# ── a version in canonical prose is a claim, and claims go stale ────────────

#: Documents a reader treats as a statement of what this checkout IS. Prose
#: elsewhere is UNMONITORED rather than exempt: the ADRs deliberately keep the
#: pin they were decided against, because rewriting a decision record to match
#: today is how the record stops being one.
CANONICAL_PIN_DOCUMENTS = (
    "docs/ARCHITECTURE.md",
    "docs/cutover-readiness.md",
)

_STATED_VERSION = re.compile(r"0\.1\.0a\d+")


def _stated_kernel_versions(text: str) -> set[str]:
    """Versions stated on a line that is also talking about the kernel.

    Line-scoped because both shapes occur: the inline `dotmac-kernel==0.1.0a98`
    and the pin-state table's `| \`dotmac-kernel\` | \`0.1.0a98\` |`. A bare
    `a85` with no `0.1.0` prefix is NOT matched and is therefore unmonitored
    rather than checked — say so rather than implying a coverage this does not
    have.
    """

    return {
        version
        for line in text.splitlines()
        if "dotmac-kernel" in line
        for version in _STATED_VERSION.findall(line)
    }


def test_no_canonical_document_states_a_kernel_version_that_is_not_the_pin() -> None:
    """The pin moved a77 -> a98 and two as-built documents kept saying a77.

    Nothing broke, which is the problem: a document that confidently states last
    month's pin is worse than one that says nothing, because a reader trusts it.
    `test_stale_claims.py` checks canonical claims against computed fact for
    lineage counts and selection state; the pin was simply not one of the facts
    it computed.
    """

    pin = declared_pin()
    for relative in CANONICAL_PIN_DOCUMENTS:
        stated = _stated_kernel_versions((ROOT / relative).read_text())
        assert stated, (
            f"{relative} states no dotmac-kernel version at all. It is listed "
            "here because a reader treats it as saying which kernel this "
            "checkout runs; if that is no longer true, remove it from "
            "CANONICAL_PIN_DOCUMENTS in the same change rather than leaving a "
            "check that passes over an empty set."
        )
        assert stated == {pin}, (
            f"{relative} states dotmac-kernel {sorted(stated)} while "
            f"pyproject.toml pins {pin}."
        )


def test_the_prose_check_is_sensitive_to_a_version_that_drifted() -> None:
    """A check over prose that happens to agree proves nothing on its own."""

    assert _stated_kernel_versions("- The kernel is `dotmac-kernel==0.1.0a98`.") == {
        "0.1.0a98"
    }
    assert _stated_kernel_versions(
        "| `dotmac-kernel` | `0.1.0a77` | a85 | satisfies every floor |"
    ) == {"0.1.0a77"}
    # A version on a line that is not about the kernel is not the kernel's.
    assert _stated_kernel_versions("`dotmac-approvals` is pinned at `0.1.0a5`") == set()
