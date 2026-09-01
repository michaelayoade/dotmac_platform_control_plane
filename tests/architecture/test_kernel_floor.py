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
* the EQUALITY ITSELF wrong — `pin == max(composed floors)` is only the whole
  rule while the assembly's own imports are satisfied by that maximum. That was
  a coincidence nothing checked. `assembly-satisfied` executes it, and a planted
  assembly import of a kernel name first shipped above the maximum turns the
  lane red.

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
    assembly_kernel_requirements,
    binding_distribution,
    composed_distributions,
    declared_kernel_floors,
    declared_pin,
    index_versions,
    kernel_imports,
    newest_excluded,
    parse,
    unsatisfied_kernel_requirements,
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
    carries a migration rehearsal obligation somebody has to have discharged.

    THE PREMISE THIS ASSERTION RESTS ON. Governance ADR 0021 § 10, as RULED on
    2026-09-01, makes the effective floor the maximum of the composed
    distributions' declared floors AND the assembly's own direct kernel
    constraint. § 10 as written says the opposite and names THIS TEST as the
    place the premise is "recorded ... as a condition to be added in the same
    change that first breaks it"; the ruling adds it now instead, without
    waiting to be broken. Equality with the composed maximum alone is therefore correct
    only while the assembly's own imports are satisfied by that maximum — true
    today, and true by coincidence. `assembly-satisfied` in the `kernel-pin` job
    executes exactly that premise against the installed kernel, so an assembly
    import of a kernel name first shipped above the maximum turns the lane red
    instead of quietly making this assertion drag the pin down to a kernel this
    assembly cannot run on. When that day comes the answer is to record the
    assembly as a floor contributor and move the pin — never to loosen this.
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


# ── the assembly's own imports, the other half of the maximum ───────────────


class _Surface:
    """A stand-in for an installed kernel module, carrying exactly these names."""

    def __init__(self, *names: str) -> None:
        for name in names:
            setattr(self, name, object())


def test_the_assembly_declares_names_and_not_only_modules(tmp_path: Path) -> None:
    """A new NAME in an existing module is how a kernel surface usually grows.

    `kernel_imports` answers at module granularity, which is all the mutation
    lane needs of the excluded kernel. The assembly's own floor needs finer:
    `ProductAssemblySpec.api_documentation` — the field this repository is
    waiting on — arrived in a module that already existed, and a
    module-granularity check would have seen nothing.
    """

    package = tmp_path / "vendor_cp"
    package.mkdir()
    (package / "a.py").write_text(
        "from dotmac_kernel import create_app, ProductAssemblySpec\n"
        "from dotmac_kernel.db import conflict_savepoint\n"
    )
    (package / "b.py").write_text(
        "import dotmac_kernel.audit\n"
        "from dotmac_kernel.db import platform_session\n"
        '"""prose naming dotmac_kernel.transactions, which is not an import"""\n'
    )

    assert assembly_kernel_requirements(package) == {
        "dotmac_kernel": frozenset({"create_app", "ProductAssemblySpec"}),
        "dotmac_kernel.audit": frozenset(),
        "dotmac_kernel.db": frozenset({"conflict_savepoint", "platform_session"}),
    }


def test_a_source_root_that_is_not_there_is_refused(tmp_path: Path) -> None:
    """No source reads as 'the assembly needs nothing', which is a pass."""

    with pytest.raises(FloorError, match="absent-as-success"):
        assembly_kernel_requirements(tmp_path / "nowhere")


def test_an_assembly_import_above_the_installed_kernel_is_reported() -> None:
    """The planted case, at unit scale, in both directions.

    The lane-scale version of this is a real assembly import of a kernel module
    first published above the composed maximum, observed red in CI. This is the
    same statement without an install, so the reporting logic itself is not
    taken on trust.
    """

    provided = {
        "dotmac_kernel": _Surface("create_app"),
        "dotmac_kernel.db": _Surface("conflict_savepoint"),
    }

    satisfied = {
        "dotmac_kernel": frozenset({"create_app"}),
        "dotmac_kernel.db": frozenset({"conflict_savepoint"}),
    }
    assert unsatisfied_kernel_requirements(satisfied, provided.__getitem__) == ()

    def _import(module: str) -> object:
        try:
            return provided[module]
        except KeyError:
            raise ModuleNotFoundError(name=module) from None

    # A module the installed kernel does not carry at all.
    assert unsatisfied_kernel_requirements(
        {**satisfied, "dotmac_kernel.api_documentation": frozenset({"POLICIES"})},
        _import,
    ) == ("dotmac_kernel.api_documentation",)

    # A NAME the installed kernel does not carry, in a module it does.
    assert unsatisfied_kernel_requirements(
        {
            **satisfied,
            "dotmac_kernel": frozenset({"create_app", "ProductAssemblySpec"}),
        },
        _import,
    ) == ("dotmac_kernel.ProductAssemblySpec",)


def test_an_empty_requirement_set_is_refused() -> None:
    """Satisfied by every kernel ever published, which is not a proof."""

    with pytest.raises(FloorError, match="reads as a proof"):
        unsatisfied_kernel_requirements({}, lambda module: object())


def test_a_missing_driver_is_not_reported_as_a_missing_kernel_symbol() -> None:
    """The confusion this whole programme turned on, refused in one place.

    Kernel a98, a99 and a100 alike reach a product-owned PostgreSQL driver when
    the public `create_app` symbol is imported with a DSN set, and answer
    `ModuleNotFoundError: psycopg`. That is a property of the ENVIRONMENT the
    kernel is installed into, not of the kernel's own surface — and counting it
    as an unsatisfied kernel requirement is exactly how an artifact gets blamed
    for a boundary its predecessors share.
    """

    def _import(module: str) -> object:
        raise ModuleNotFoundError(name="psycopg")

    with pytest.raises(FloorError, match="property of THIS ENVIRONMENT"):
        unsatisfied_kernel_requirements(
            {"dotmac_kernel": frozenset({"create_app"})}, _import
        )


def test_an_unimportable_kernel_module_is_refused_rather_than_counted() -> None:
    """`create_app` with no DSN raises `ArgumentError`, not `ImportError`.

    Recording that as an unsatisfied requirement would report a floor violation
    on a run where the only thing that happened was an unset environment
    variable.
    """

    def _import(module: str) -> object:
        raise ValueError("Could not parse SQLAlchemy URL from given URL string")

    with pytest.raises(FloorError, match="refusing"):
        unsatisfied_kernel_requirements(
            {"dotmac_kernel": frozenset({"create_app"})}, _import
        )


def test_the_assembly_really_does_import_the_kernel() -> None:
    """The premise check is not vacuous on the real tree.

    If this ever returns nothing, `assembly-satisfied` would be asking an empty
    question and passing — so the emptiness is refused there too, and asserted
    here against the actual source rather than against a fixture.
    """

    required = assembly_kernel_requirements()
    assert required, "src/vendor_cp imports no kernel module at all"
    assert any(names for names in required.values()), (
        "the assembly imports kernel modules but binds no name out of any of "
        "them, so the name half of the check would be inert"
    )


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

    for verb in ("pinned", "excluded", "missing-from", "assembly-satisfied"):
        assert f"kernel_floor.py {verb}" in executable, (
            f"the mutation lane never asks for `{verb}`. All four derived facts "
            "are load-bearing: the pin it installs, the version it must be "
            "refused against, the name its failure has to carry, and the "
            "premise that makes the equality rule the whole rule."
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
