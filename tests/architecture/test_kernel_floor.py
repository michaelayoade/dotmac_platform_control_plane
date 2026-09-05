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
import subprocess
import sys
import textwrap
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
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

    THE PREMISE THIS ASSERTION RESTS ON. Governance ADR 0021 § 10.1, settled
    2026-09-01, makes the effective floor the maximum of the composed
    distributions' declared floors AND the assembly's own direct kernel
    constraint — the latter read from the assembly's own SOURCE, because its
    declaration is this very pin and a maximum that reads the pin as its own
    input agrees with itself. § 10 previously named THIS TEST as the place the
    premise was "recorded ... as a condition to be added in the same change that
    first breaks it"; it is executed now instead, without waiting to be broken.

    Equality with the composed maximum alone is therefore correct only while
    the assembly's own imports are satisfied by that maximum — true
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


# ── a version in prose is a claim: which claims, and about WHEN ─────────────
#
# What was here before was a regex over two hand-listed files, and it read as if
# it covered the estate. It did not, in two independent ways.
#
# It monitored `docs/ARCHITECTURE.md` and `docs/cutover-readiness.md` and
# nothing else, while nineteen other tracked documents stated a kernel version.
# And inside the two it did monitor it matched only `0\.1\.0a\d+` on a line that
# also said `dotmac-kernel` — so the bare `a100` in the pin-state table, in a
# file the gate had open, was not seen. Its own docstring admitted the second
# half. A guard that reports a coverage it does not have is worse than no guard,
# because the next reader stops looking.
#
# The regex is no longer the mechanism. Two structures are:
#
#   CURRENT_VERSION_ASSERTIONS — an INVENTORY of the exact sentences that assert
#   what this checkout runs RIGHT NOW, held as templates the pin is rendered
#   into. A repin that does not update the prose leaves a recorded sentence
#   absent, and absence is what fails. This is a positive check: it cannot pass
#   by finding nothing.
#
#   SNAPSHOTS — documents that record what was true when they were written.
#   Classified BY RULE (see `snapshot_premise`), never by a hand-kept list. A
#   hand-kept list is precisely how a live claim gets reclassified into silence,
#   and the rules are checked in both directions: a snapshot must carry the
#   premise its rule asserts, and a live document may satisfy NO snapshot rule.
#
# The residue check that remains is scoped and its residue is DECLARED. Inside a
# current-version document, every kernel version on a line that names the kernel
# — in full `0.1.0a98` form or bare `a98` form, which is the half that was blind
# — must be either the pin or an explicitly declared non-pin version with a
# reason. A kernel version stated on a line that does NOT name the kernel is
# UNMONITORED rather than exempt. The premise for that boundary is enforceable
# and satisfiable: to state the kernel's version, name the kernel on the line.


@dataclass(frozen=True)
class CurrentVersionClaim:
    """One document that a reader treats as saying what this checkout IS."""

    #: Sentences asserting the CURRENT pin, with `{pin}` where the version goes.
    #: Rendered against the derived pin and required verbatim. May be empty for
    #: a live document that states kernel versions WITHOUT claiming any of them
    #: is the pin — `AGENTS.md` states three as a worked example. Such a
    #: document is still monitored: every version it states must be declared
    #: below, so a stale pin claim cannot be added to it silently.
    assertions: tuple[str, ...] = ()
    #: Kernel versions this document states that are NOT claims about the pin —
    #: each with the reason, because "grandfathered" is not "reviewed".
    other_kernel_versions: dict[str, str] = field(default_factory=dict)


CURRENT_VERSION_ASSERTIONS: dict[str, CurrentVersionClaim] = {
    "docs/ARCHITECTURE.md": CurrentVersionClaim(
        assertions=("`dotmac-kernel=={pin}`",),
        other_kernel_versions={
            "0.1.0a60": "a kernel behaviour this assembly crossed, past tense",
            "0.1.0a68": "the kernel release whose audit-registry enforcement is "
            "described",
            "0.1.0a77": "the previous pin, named in past tense while explaining what "
            "pinning alone does NOT do",
            "0.1.0a5": "not the kernel at all — `a5/a6` here are the composed "
            "commercial modules' versions, on a line that happens to say kernel",
            "0.1.0a6": "not the kernel at all — see `a5`",
        },
    ),
    "docs/cutover-readiness.md": CurrentVersionClaim(
        assertions=("| `dotmac-kernel` | `{pin}` |",),
        other_kernel_versions={
            "0.1.0a100": "the newest PUBLISHED kernel, in the table's `Released` "
            "column — a different fact from the pin, and stating it is the point",
            "0.1.0a101": "the unpublished repair, named as not-yet-available",
            "0.1.0a61": "a LANDED migration step in the cutover table's history "
            "column (`Kernel a61 -> a77`), not a claim about now",
            "0.1.0a77": "the other end of that landed step — see `a61`",
        },
    ),
    # No assertion: the hard-rules file states kernel versions only as the
    # worked example behind a rule ("a98, a99 and a100 reach a product-owned
    # driver identically"). It claims nothing about what this checkout runs, so
    # there is no sentence for a repin to make stale — but it is monitored, so
    # a pin claim cannot be added to it without being declared.
    "AGENTS.md": CurrentVersionClaim(
        other_kernel_versions={
            # `0.1.0a98` is deliberately NOT declared here. It equals the pin
            # today, so nothing consults it — and the sentence around it says
            # "a98 is what runs in production", which a repin makes FALSE.
            # Declaring it would suppress exactly the failure that should
            # happen on the day the pin moves.
            "0.1.0a99": "a published kernel the example compares against",
            "0.1.0a100": "a published kernel the example compares against",
        },
    ),
}

#: Documents that state a kernel version and are neither a current-version
#: document nor a snapshot by rule. EMPTY, and a two-directional ratchet: an
#: entry appearing is a document nobody classified, and an entry that stopped
#: being needed must be removed in the change that classified it.
UNMONITORED_PIN_PROSE: frozenset[str] = frozenset()

SNAPSHOT_MARKER = "<!-- kernel-pin: snapshot -->"
_DATED_STEM = re.compile(r"-(\d{4}-\d{2}-\d{2})$")
_STATUS_PREAMBLE = re.compile(r"^>\s*\*\*", re.MULTILINE)

_FULL_VERSION = re.compile(r"\b0\.1\.0a(\d+)\b")
#: The bare form the old gate could not see. Bounded on both sides so that
#: `kernel-a100-assessment-2026-09-01.md` — a PATH, not a claim — is not a hit.
_BARE_VERSION = re.compile(r"(?<![\w.\-])a(\d+)(?![\w\-])")


def _canonical(alpha: str) -> str:
    """`a77` and `0.1.0a77` are ONE version stated two ways.

    Keyed canonically so a declaration cannot cover one spelling and leave the
    other firing — which is exactly the trap the old line-scoped regex set, in
    reverse: it read one spelling and was blind to the other.
    """

    return f"0.1.0a{alpha}"


def _tracked_documents() -> tuple[str, ...]:
    """Every present, non-ignored Markdown file.

    `--others` as well as `--cached`: a document added in the working tree is
    exactly the case this gate exists for, and a sensitivity proof that plants
    one would prove nothing if the enumeration could not see it.
    """

    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        (
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "*.md",
        ),
        capture_output=True,
        text=True,
        check=True,
    )
    return tuple(sorted(set(line for line in result.stdout.splitlines() if line)))


def stated_kernel_versions(text: str) -> dict[str, tuple[int, ...]]:
    """Kernel versions stated in prose, by version, with the lines they sit on.

    Line-scoped on the word `kernel`, which is a rule an author can satisfy: to
    state the kernel's version, name the kernel. Both spellings are read — the
    full `0.1.0a98` and the bare `a98` that the previous gate was blind to.
    """

    found: dict[str, list[int]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if "kernel" not in line.lower():
            continue
        for pattern in (_FULL_VERSION, _BARE_VERSION):
            for alpha in pattern.findall(line):
                found.setdefault(_canonical(alpha), []).append(number)
    return {version: tuple(lines) for version, lines in sorted(found.items())}


def snapshot_premise(relative: str, text: str) -> str | None:
    """Why this document records a moment rather than the present — BY RULE.

    Four rules, every one a property of the path or the bytes. None is a list of
    filenames, because a list is how a live claim gets quietly reclassified.
    """

    if relative.startswith("docs/adr/"):
        return "an accepted decision record: it states the kernel it was decided on"
    if relative.startswith("docs/design/"):
        return "a design record, carrying its own status/amendment preamble"
    dated = _DATED_STEM.search(Path(relative).stem)
    if dated:
        return f"a dated record: measured {dated.group(1)}"
    if SNAPSHOT_MARKER in text:
        return "declares itself a snapshot"
    return None


# ── the inventory: a positive check that cannot pass by finding nothing ─────


def test_every_recorded_current_version_assertion_is_present() -> None:
    """The pin moved a77 -> a98 and two as-built documents kept saying a77.

    Nothing broke, which is the problem: a document that confidently states last
    month's pin is worse than one that says nothing, because a reader trusts it.
    Held as PRESENCE of a rendered sentence rather than as absence of a stale
    one — a repin then fails here for the plain reason that the sentence the
    inventory records is no longer in the file.
    """

    pin = declared_pin()
    missing = [
        f"{relative}: `{template.format(pin=pin)}`"
        for relative, claim in CURRENT_VERSION_ASSERTIONS.items()
        for template in claim.assertions
        if template.format(pin=pin) not in (ROOT / relative).read_text()
    ]
    assert not missing, (
        f"pyproject.toml pins dotmac-kernel {pin} and these recorded "
        f"current-version assertions are not in their documents: {missing}. "
        "Either the prose went stale, or the sentence moved and the inventory "
        "has to move with it — do not delete the entry to make this pass."
    )


def test_the_inventory_is_derived_and_non_empty() -> None:
    """NON-VACUITY. A hard-coded version in an assertion template would make the
    check above agree with itself forever, and an empty inventory would make it
    pass over nothing."""

    assert any(claim.assertions for claim in CURRENT_VERSION_ASSERTIONS.values()), (
        "no live document records a sentence asserting the current pin, so the "
        "positive half of this gate passes over nothing"
    )
    for relative, claim in CURRENT_VERSION_ASSERTIONS.items():
        assert claim.assertions or claim.other_kernel_versions, (
            f"{relative} is listed as a live document and neither asserts the "
            "pin nor declares a version — it does not belong here"
        )
        for template in claim.assertions:
            assert "{pin}" in template, (
                f"{relative} records `{template}`, which states a version "
                "literally. Then it agrees with itself and tracks nothing."
            )
            assert not _FULL_VERSION.search(template)


# ── the residue inside a current-version document ──────────────────────────


def test_a_current_version_document_states_no_undeclared_kernel_version() -> None:
    """Every kernel version in a live document is the pin or is declared.

    This is where the bare form is read. `docs/cutover-readiness.md` states
    `a100` in its `Released` column — correct, and a DIFFERENT fact from the
    pin — inside a file the old gate had open and could not see it in.
    """

    pin = declared_pin()
    undeclared: list[str] = []
    for relative, claim in CURRENT_VERSION_ASSERTIONS.items():
        stated = stated_kernel_versions((ROOT / relative).read_text())
        for version, lines in stated.items():
            if version == pin or version in claim.other_kernel_versions:
                continue
            undeclared.append(f"{relative}:{lines[0]} states kernel `{version}`")
    assert not undeclared, (
        f"this checkout pins dotmac-kernel {pin}. These documents state a "
        f"kernel version that is neither the pin nor declared as something "
        f"else: {undeclared}. If the version is a stale pin claim, fix the "
        "prose; if it is a different fact — a released version, a floor, a "
        "past state — say so in `other_kernel_versions` with the reason."
    )


def test_every_declared_non_pin_version_is_actually_stated() -> None:
    """Two directions. A declaration for a version the document no longer states
    is an exemption nobody is using and everybody inherits."""

    pin = declared_pin()
    stale: list[str] = []
    for relative, claim in CURRENT_VERSION_ASSERTIONS.items():
        stated = stated_kernel_versions((ROOT / relative).read_text())
        stale += [
            f"{relative}: `{version}` ({why})"
            for version, why in claim.other_kernel_versions.items()
            if version not in stated and version != pin
        ]
    assert not stale, (
        f"these non-pin declarations describe versions their document no longer "
        f"states: {stale}. Remove them in the change that removed the prose."
    )


# ── snapshots: classified by rule, and unable to hold a live claim ──────────


def test_every_document_stating_a_kernel_version_is_classified() -> None:
    """Current-version, snapshot, or declared unmonitored — nothing else.

    This is the half the old two-entry list did not have. Nineteen documents
    stated a kernel version and every one of them was invisible; being invisible
    is not the same as being exempt, and the difference is this test.
    """

    unclassified: list[str] = []
    for relative in _tracked_documents():
        text = (ROOT / relative).read_text()
        if not stated_kernel_versions(text):
            continue
        if relative in CURRENT_VERSION_ASSERTIONS:
            continue
        if snapshot_premise(relative, text) is not None:
            continue
        if relative in UNMONITORED_PIN_PROSE:
            continue
        unclassified.append(relative)
    assert not unclassified, (
        f"these documents state a kernel version and nothing says what kind of "
        f"claim it is: {unclassified}. Add the document to "
        "CURRENT_VERSION_ASSERTIONS if a reader treats it as saying what this "
        f"checkout runs; mark it `{SNAPSHOT_MARKER}` if it records a moment; "
        "or record it in UNMONITORED_PIN_PROSE and say why it cannot be either."
    )


def test_unmonitored_pin_prose_is_a_two_directional_ratchet() -> None:
    """The backlog only shrinks, and only deliberately."""

    assert UNMONITORED_PIN_PROSE == frozenset(), (
        "UNMONITORED_PIN_PROSE is no longer empty. Every kernel-version claim "
        "in this repository is currently classified; an entry here is a "
        f"deliberate step backwards: {sorted(UNMONITORED_PIN_PROSE)}"
    )


def test_a_live_document_cannot_also_claim_a_snapshot_premise() -> None:
    """The escape, closed: a live document may not be reclassified into silence.

    The gate skips snapshots BY RULE, so the rules are also the way out of it.
    Rename `docs/cutover-readiness.md` to carry an ISO date, drop
    `<!-- kernel-pin: snapshot -->` into `docs/ARCHITECTURE.md`, or move either
    under `docs/adr/`, and the document stops being read while still reading, to
    a human, as a statement of what this checkout runs. This refuses that: a
    path recorded as live must satisfy NO snapshot rule.

    THE RESIDUE, STATED. A snapshot may legitimately contain the same characters
    as a live assertion — `docs/operations/composition-census-2026-08-30.md`
    records `| `dotmac-kernel` | `0.1.0a98` |` because that was the pin on
    2026-08-30, and that row is exactly what a census is for. No machine can
    tell that row from a present-tense claim; the DOCUMENT's classification is
    what tells them apart. So the classification is what is held here, and the
    remaining move — deleting a live entry and dating its document in one change
    — is a REVIEW boundary, not a checked one. It is named rather than implied.
    """

    laundered = []
    for relative in CURRENT_VERSION_ASSERTIONS:
        premise = snapshot_premise(relative, (ROOT / relative).read_text())
        if premise is not None:
            laundered.append(f"{relative}: now reads as {premise}")
    assert not laundered, (
        "these documents are recorded as stating what this checkout runs, and "
        f"they now satisfy a snapshot rule as well: {laundered}. A document "
        "cannot both assert the present and record a moment; whichever it is, "
        "only one of the two classifications may apply."
    )


def test_a_snapshot_premise_is_checkable_where_the_rule_claims_one() -> None:
    """Each classification rule asserts something about the document. Read it.

    A path rule that nothing verifies is a filename convention pretending to be
    a premise: `docs/adr/` claims a decision record, `docs/design/` claims a
    status preamble, and a dated stem claims the document states its own date.
    """

    broken: list[str] = []
    for relative in _tracked_documents():
        text = (ROOT / relative).read_text()
        if not stated_kernel_versions(text) or relative in CURRENT_VERSION_ASSERTIONS:
            continue
        if snapshot_premise(relative, text) is None:
            continue
        if relative.startswith("docs/adr/") and "Status" not in text:
            broken.append(f"{relative}: classified a decision record, states no Status")
        if relative.startswith("docs/design/") and not _STATUS_PREAMBLE.search(text):
            broken.append(f"{relative}: classified a design record, has no preamble")
        dated = _DATED_STEM.search(Path(relative).stem)
        if dated and dated.group(1) not in text:
            broken.append(
                f"{relative}: named for {dated.group(1)} and never states that date"
            )
    assert not broken, (
        f"a snapshot classification rests on a premise the document does not "
        f"carry: {broken}"
    )


# ── sensitivity: every branch, planted ─────────────────────────────────────


@pytest.fixture
def edited() -> Iterator[Callable[[str, str], None]]:
    """Rewrite a real document for one test and restore it afterwards.

    Against the REAL file, because the gate reads real files and a fixture copy
    would prove only that the fixture is well-formed.
    """

    saved: list[tuple[Path, str]] = []

    def rewrite(relative: str, text: str) -> None:
        path = ROOT / relative
        saved.append((path, path.read_text()))
        path.write_text(text)

    try:
        yield rewrite
    finally:
        for path, original in reversed(saved):
            path.write_text(original)


def test_a_planted_stale_full_version_is_named(
    edited: Callable[[str, str], None],
) -> None:
    """SENSITIVITY. The case the old gate DID catch, kept so the repair is not
    a regression."""

    relative = "docs/ARCHITECTURE.md"
    original = (ROOT / relative).read_text()
    edited(relative, original + "\nThe kernel here is `dotmac-kernel==0.1.0a55`.\n")

    stated = stated_kernel_versions((ROOT / relative).read_text())
    assert "0.1.0a55" in stated
    with pytest.raises(AssertionError, match=r"docs/ARCHITECTURE\.md:\d+"):
        test_a_current_version_document_states_no_undeclared_kernel_version()


def test_a_planted_bare_version_is_named(edited: Callable[[str, str], None]) -> None:
    """SENSITIVITY — THE DEFECT. `a77` with no `0.1.0` prefix, on a kernel line,
    in a monitored file, was invisible. It is the exact shape of the `a100`
    already sitting in `docs/cutover-readiness.md`."""

    relative = "docs/ARCHITECTURE.md"
    original = (ROOT / relative).read_text()
    edited(relative, original + "\nThis assembly runs kernel a55 in production.\n")

    stated = stated_kernel_versions((ROOT / relative).read_text())
    assert "0.1.0a55" in stated, (
        "the bare form is still unreadable, or it is not being canonicalised "
        "onto the same key as the full form — nothing was fixed"
    )
    with pytest.raises(AssertionError, match=r"states kernel `0\.1\.0a55`"):
        test_a_current_version_document_states_no_undeclared_kernel_version()


def test_a_removed_assertion_is_named(edited: Callable[[str, str], None]) -> None:
    """SENSITIVITY. The positive half: prose that stops asserting the pin fails,
    which is what a repin-without-a-doc-edit looks like."""

    relative = "docs/ARCHITECTURE.md"
    text = (ROOT / relative).read_text()
    edited(relative, text.replace(f"dotmac-kernel=={declared_pin()}", "dotmac-kernel"))

    with pytest.raises(AssertionError, match=r"docs/ARCHITECTURE\.md"):
        test_every_recorded_current_version_assertion_is_present()


def test_a_live_document_marked_as_a_snapshot_is_refused(
    edited: Callable[[str, str], None],
) -> None:
    """SENSITIVITY. The anti-escape half, planted: a live document given the
    snapshot marker must be refused, not quietly skipped."""

    relative = "docs/ARCHITECTURE.md"
    text = (ROOT / relative).read_text()
    edited(relative, f"{SNAPSHOT_MARKER}\n{text}")

    assert snapshot_premise(relative, (ROOT / relative).read_text()) is not None
    with pytest.raises(AssertionError, match=r"docs/ARCHITECTURE\.md: now reads as"):
        test_a_live_document_cannot_also_claim_a_snapshot_premise()


def test_an_unclassified_document_is_named(edited: Callable[[str, str], None]) -> None:
    """SENSITIVITY. A NEW document stating a kernel version, in a directory no
    rule covers, must be refused rather than silently unmonitored."""

    relative = "docs/ARCHITECTURE.md"
    original = (ROOT / relative).read_text()
    edited(relative, original)
    probe = ROOT / "docs" / "_pin_prose_probe.md"
    probe.write_text("This runs kernel `0.1.0a77`.\n")
    try:
        with pytest.raises(AssertionError, match=r"_pin_prose_probe\.md"):
            test_every_document_stating_a_kernel_version_is_classified()
    finally:
        probe.unlink()


# ── the near misses, permanent ─────────────────────────────────────────────


def test_a_version_on_a_line_that_is_not_about_the_kernel_is_not_read() -> None:
    """PERMANENT NEGATIVE CONTROL. `dotmac-approvals 0.1.0a5` is not a kernel
    claim, and a gate that read it would be widened until it read nothing."""

    assert stated_kernel_versions("`dotmac-approvals` is pinned at `0.1.0a5`") == {}
    assert stated_kernel_versions("| `dotmac-release-catalog` | a4 | current |") == {}


def test_a_version_inside_a_path_is_not_read_as_a_claim() -> None:
    """PERMANENT NEGATIVE CONTROL. `kernel-a100-assessment-2026-09-01.md` names
    a100 as part of a FILENAME. A bare-version reader that matched inside an
    identifier would fire on every reference to that document."""

    assert (
        stated_kernel_versions(
            "see `docs/operations/kernel-a100-assessment-2026-09-01.md`"
        )
        == {}
    )


def test_a_stale_version_inside_a_snapshot_stays_silent() -> None:
    """PERMANENT NEGATIVE CONTROL, in the real tree. ADR-0013 records
    `dotmac-kernel >=0.1.0a77` as a floor it was decided against. Rewriting that
    to today's pin would destroy the record. The gate must not ask it to."""

    relative = "docs/adr/0013-operator-authorization-issuer-and-its-bootstrap.md"
    text = (ROOT / relative).read_text()
    assert "0.1.0a77" in stated_kernel_versions(text)
    assert snapshot_premise(relative, text) is not None
    assert relative not in CURRENT_VERSION_ASSERTIONS


def test_the_bare_reader_still_bites_over_the_real_tree() -> None:
    """NON-VACUITY. If nothing in the tree stated a bare kernel version, the
    repair for defect 3 would pass without ever having been exercised. It does:
    `docs/cutover-readiness.md` states `a100` in its `Released` column."""

    readiness = (ROOT / "docs" / "cutover-readiness.md").read_text()
    stated = stated_kernel_versions(readiness)
    assert "0.1.0a100" in stated, (
        "no bare kernel version is stated anywhere in the pin-state table any "
        "more. Point this control at whatever states one, or delete it and say "
        "in the same change that the bare form is no longer exercised."
    )
    assert (
        "0.1.0a100"
        in CURRENT_VERSION_ASSERTIONS["docs/cutover-readiness.md"].other_kernel_versions
    )
    # And the bare spelling really is the only one on that line: if the document
    # ever writes it in full, this control stops exercising the repaired half.
    assert "a100" in readiness
    assert "0.1.0a100" not in readiness
