"""The exact kernel pin, what binds it, and the newest kernel it excludes.

## Why this file exists

`docs/operations/composition-census-2026-08-30.md` § 1 recorded the five
composed modules' declared kernel floors, read out of published wheel metadata,
and then said the only honest thing available at the time:

    None of the five carries a minimum-floor canary of the kind
    `dotmac-deployment-control` a6 acquired after a5's declared floor turned
    out to be wrong — resolution succeeded, the lock wrote cleanly, the hashes
    matched, and the container died at boot. The floors above are declarations,
    not contracts, and this census does not upgrade them by repeating them.

This module is the upgrade the census declined to fake. It turns the pin from a
number a reviewer compares by eye into three derived facts a lane can execute.

`dotmac-deployment-control` `0.1.0a5` is the case that names the cost. Its bytes
were beyond doubt — peeled commit, both artifact digests, publisher read-back,
an independent consumer install, seven behavioural canaries against the
registry-served wheel. It still could not boot here: it imported
`dotmac_kernel.transactions`, first shipped in kernel `0.1.0a98`, while
declaring `dotmac-kernel >=0.1.0a77`. **A hash comparison proves you got the
published bytes; it cannot prove they import.**

## What this assembly's floor actually is, which is not what a library's is

`dotmac-deployment-control` is a library: its floor is a lower bound it declares
for its own imports, and its canary installs that minimum. This repository is an
ASSEMBLY. It pins the kernel EXACTLY, and the pin has to equal the maximum of
every composed distribution's declared lower bound and the assembly's own
direct constraint. A pin too LOW dies at boot the way a5 did; a pin too HIGH
has taken a kernel upgrade no named owner asked for.

Both halves are derived, and neither is copied into a document:

* `declared_pin()` — the exact version `pyproject.toml` pins. Any other
  constraint shape is refused rather than interpreted.
* `declared_kernel_floors()` — every composed distribution's `Requires-Dist`
  lower bound, read from INSTALLED METADATA. Not from a source tree, not from a
  changelog and not from the census's prose: the artifact's own declaration is
  the thing that binds a resolver.
* `binding_distribution()` — the maximum after adding the assembly's direct
  exact constraint under the named `assembly:vendor_cp` owner. That declaration
  would be circular by itself, so the source-derived checks below must prove it.
* `newest_excluded()` — the highest version the private index actually lists
  below the pin. That is the mutation target, and reading it from the index
  rather than computing "the pin minus one" matters: the index has gaps
  (there is no `0.1.0a96`), and a target that was never published would make
  the mutation lane fail on a resolver error while reporting the pin proven.
* `kernel_imports()` / `absent_from_kernel()` — every `dotmac_kernel`
  submodule the composed code imports, and which of them a given kernel
  installation lacks. The mutation lane requires its failure to NAME one of
  those, so "the boot failed" cannot stand in for "the boot failed at the
  boundary the pin describes".
* `assembly_kernel_requirements()` / `unsatisfied_kernel_requirements()` —
  the OTHER half of that maximum, and the half nothing executed until now.
  See "The assembly's own imports join the maximum" below.

That last pair is deliberately NOT a hand-maintained version→module table. Such
a table is incomplete by construction: an import added without a matching row is
invisible, and the pin quietly goes under-constrained in exactly a5's shape.
Comparing the composition's real imports against a real installation of the
excluded kernel has no rows to forget.

## The assembly's own imports join the maximum

Governance ADR 0021 § 10.1, settled by Michael on 2026-09-01 and transcribed
into the record the same day (`dotmac_governance` PR #58, `d46d3a6`):

> The effective floor is the MAXIMUM of every composed distribution's INSTALLED
> `Requires-Dist` and the assembly's own declared direct constraint on that
> dependency.

Two things in § 10.1 shape this implementation rather than merely licensing it:

* **The assembly contribution is stated by the exact constraint and established
  from ITS OWN SOURCE.** Reading the pin as the third input does return the pin
  and proves nothing alone. `assembly_kernel_requirements` derives what
  `src/vendor_cp` imports, while the excluded-kernel plant proves the immediately
  lower published version lacks a surface the source actually needs.
* **The plant is the rule.** "A planted assembly import first shipped ABOVE that
  floor must turn the lane RED" is § 10.1's own sentence, and it is "the only
  part of § 10 that cannot be satisfied by a number somebody wrote down". The
  plant is separate from the composed-set plants, those are left intact, and the
  finding is DISTINCT — an assembly that out-imports its composition is repaired
  in a different repository by a different person than a composed module that
  raised its floor.

One accurate caveat: this repository's PINNED governance revision
(`a19259b1`, `.dotmac/standards-profile.json`) predates § 10 altogether. The
binding text is therefore ahead of the pin. Repinning is a deliberate change
under rule 15 — it would also pull in every other decision accepted since — and
is not taken here.

Today the assembly is the binding owner at a100 while the highest module floor
is a98. `unsatisfied_kernel_requirements()` verifies every kernel module and
top-level name `src/vendor_cp` imports is present in the effective maximum. The
separate excluded-version check observes that a99 lacks a source-imported
surface, so the assembly contribution is not merely a number agreeing with
itself. A future move raises the declared contribution and its source-derived
plant together; it never loosens the equality.

Two deliberate limits, stated rather than implied:

* the check asks the INSTALLED kernel by importing it and reading the attribute,
  because the kernel's package root resolves its public names through a module
  `__getattr__`; a static read of the installed source would answer "absent" for
  every lazily re-exported symbol. Importing means the environment must be able
  to import kernel modules at all, which is a premise this module refuses on
  rather than absorbs (see the `ModuleNotFoundError` branch below — a driver
  missing from the ENVIRONMENT is not a symbol missing from the KERNEL, and
  conflating the two is precisely the confusion that made a100 look like a
  regression when it is not one).
* it sees the imports of `src/vendor_cp` only. A kernel symbol reached from a
  test, a script or a migration is UNMONITORED by this check rather than
  exempt — those do not run in the deployed artifact, and saying so is cheaper
  than implying a coverage this does not have.
"""

from __future__ import annotations

import argparse
import ast
import importlib.metadata
import re
import sys
import tomllib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
PYPROJECT: Final = REPO_ROOT / "pyproject.toml"
ASSEMBLY_PACKAGE: Final = REPO_ROOT / "src" / "vendor_cp"
ASSEMBLY_FLOOR_OWNER: Final = "assembly:vendor_cp"

DEPENDENCY: Final = "dotmac-kernel"
#: The import name behind that distribution name.
KERNEL_PACKAGE: Final = "dotmac_kernel"

#: `0.1.0a98`, and nothing else.
_ALPHA: Final = re.compile(r"\A(\d+)\.(\d+)\.(\d+)a(\d+)\Z")
#: `dotmac-kernel (>=0.1.0a98)` and `dotmac-kernel>=0.1.0a98`; extras and
#: environment markers are tolerated, a ceiling or a second clause is not.
_REQUIRES_KERNEL: Final = re.compile(
    r"\Adotmac[-_]kernel\s*(?:\[[^\]]*\])?\s*\(?\s*>=\s*(\d+\.\d+\.\d+a\d+)\s*\)?"
    r"\s*(?:;.*)?\Z"
)
#: How the private index renders a file link for the kernel. Keyed on the
#: FILENAME, because both the normalized and the underscored project name appear.
_INDEX_FILE: Final = re.compile(
    r"dotmac[-_]kernel-(\d+\.\d+\.\d+a\d+)(?:-py3-none-any\.whl|\.tar\.gz)"
)


class FloorError(ValueError):
    """The pin, a declared floor or the index is not a thing this may reason about."""


def parse(version: str) -> tuple[int, int, int, int]:
    """An orderable key. Raises rather than returning a sentinel.

    Ordering is the whole reason this exists rather than a string compare:
    `0.1.0a97` sorts ABOVE `0.1.0a100` as text, so a textual comparison names
    the wrong mutation target the moment the kernel reaches its hundredth alpha
    — which it has.
    """

    match = _ALPHA.fullmatch(version.strip())
    if match is None:
        raise FloorError(
            f"{version!r} is not a shape this module can order. It accepts "
            "`<major>.<minor>.<patch>a<n>` only, and refuses anything else "
            "rather than guessing at it."
        )
    major, minor, patch, alpha = match.groups()
    return (int(major), int(minor), int(patch), int(alpha))


def _dependency_table(pyproject: Path = PYPROJECT) -> dict[str, object]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return dict(data["tool"]["poetry"]["dependencies"])


def declared_pin(pyproject: Path = PYPROJECT) -> str:
    """The exact kernel version this assembly pins.

    An EXACT version is required. A range would make "the version this assembly
    runs" a resolver outcome rather than a declaration, and every lane below
    installs the pin literally. ADR-0007 and the a5 post-mortem both turn on the
    pin being one version somebody chose, so an unfamiliar constraint shape is
    refused here and extended deliberately in the change that introduces it.
    """

    dependencies = _dependency_table(pyproject)
    if DEPENDENCY not in dependencies:
        raise FloorError(
            f"{pyproject} declares no {DEPENDENCY} dependency at all. This "
            "module exists to keep that pin honest; it cannot report a pin for "
            "a dependency that is not declared."
        )
    declared = dependencies[DEPENDENCY]
    version = (
        declared.get("version")
        if isinstance(declared, dict)
        else (declared if isinstance(declared, str) else None)
    )
    if not isinstance(version, str):
        raise FloorError(
            f"the {DEPENDENCY} dependency is declared as {declared!r}, which is "
            "neither a version string nor a table carrying one. Refusing rather "
            "than reaching into an unfamiliar shape."
        )
    if _ALPHA.fullmatch(version.strip()) is None:
        raise FloorError(
            f"{DEPENDENCY} is declared as {version!r}. This assembly pins the "
            "kernel EXACTLY (`AGENTS.md` rule 1); a caret, a lower bound or a "
            "range each make the running version a resolver outcome, and every "
            "lane here installs the pin literally."
        )
    return version.strip()


def composed_distributions(pyproject: Path = PYPROJECT) -> tuple[str, ...]:
    """Every Dotmac distribution this assembly composes, besides the kernel.

    Derived from the dependency table's `source = "forgejo"` marker rather than
    listed, so a module pinned in a later change is included without anyone
    remembering to add it here — the omission that a hand-kept list makes
    silent.
    """

    found = []
    for name, declared in _dependency_table(pyproject).items():
        if name == DEPENDENCY or not isinstance(declared, dict):
            continue
        if declared.get("source") == "forgejo":
            found.append(name)
    if not found:
        raise FloorError(
            f"{pyproject} names no forgejo-sourced distribution besides "
            f"{DEPENDENCY}. An empty set reads as 'nothing constrains the pin', "
            "which is the absent-as-success shape this repository refuses."
        )
    return tuple(sorted(found))


def installed_requirements(distribution: str) -> list[str]:
    """The `Requires-Dist` lines of an INSTALLED distribution."""

    return [
        str(requirement)
        for requirement in (
            importlib.metadata.metadata(distribution).get_all("Requires-Dist") or []
        )
    ]


def declared_kernel_floors(
    distributions: Iterable[str] | None = None,
    requirements_of: Callable[[str], list[str]] = installed_requirements,
) -> dict[str, str]:
    """Each composed distribution's declared kernel lower bound.

    Read from INSTALLED metadata — the artifact's own `Requires-Dist` — and
    never from a source tree or from a document. The census recorded these by
    hand and said so; a hand-copied floor is a number that was true once.

    `requirements_of` is injectable for one reason: the refusal path below is
    the half that matters, and a parser whose refusal has never been executed
    is a parser nobody has seen refuse.
    """

    names = (
        tuple(distributions) if distributions is not None else composed_distributions()
    )
    floors: dict[str, str] = {}
    for name in names:
        requirements = requirements_of(name)
        matched = [
            match.group(1)
            for requirement in requirements
            for match in [_REQUIRES_KERNEL.fullmatch(str(requirement).strip())]
            if match
        ]
        if not matched:
            kernel_requirements = [
                str(requirement)
                for requirement in requirements
                if "dotmac-kernel" in str(requirement)
                or "dotmac_kernel" in str(requirement)
            ]
            raise FloorError(
                f"{name} declares no plain `>={DEPENDENCY}` lower bound this "
                f"module can read (its kernel requirements are "
                f"{kernel_requirements}). A distribution composed here without a "
                "readable kernel floor is unmonitored rather than satisfied: "
                "extend this parser deliberately for the shape it actually uses."
            )
        floors[name] = max(matched, key=parse)
    return floors


def binding_distribution(floors: dict[str, str] | None = None) -> tuple[str, str]:
    """The owner whose declared floor is the effective maximum, and it.

    Naming it matters as much as the number. When the pin has to move, the
    reviewer needs to know WHICH module asked — a bump nobody can attribute is
    a kernel upgrade taken on nobody's behalf.
    """

    resolved = (
        {**declared_kernel_floors(), ASSEMBLY_FLOOR_OWNER: declared_pin()}
        if floors is None
        else floors
    )
    if not resolved:
        raise FloorError("no composed distribution or assembly declares a kernel floor")
    name = max(resolved, key=lambda key: (parse(resolved[key]), key))
    return name, resolved[name]


def index_versions(html: str) -> list[str]:
    """Every kernel version the private index listing names, ordered."""

    versions = {match.group(1) for match in _INDEX_FILE.finditer(html)}
    return sorted(versions, key=parse)


def newest_excluded(pin: str, versions: list[str]) -> str:
    """The highest published kernel STRICTLY BELOW the pin.

    "Highest below" and not "any below": it is the closest possible near-miss,
    so a pin one alpha higher than anything the composition needs is caught.
    Something far below would fail for a dozen reasons and prove only that
    ancient kernels are ancient.
    """

    key = parse(pin)
    below = [version for version in versions if parse(version) < key]
    if not below:
        raise FloorError(
            f"the index lists no {DEPENDENCY} version below the pin {pin}, so "
            "there is nothing the pin can be shown to exclude. The mutation "
            "lane must fail here rather than pass over an empty set: a canary "
            "nobody has seen refuse is not a canary."
        )
    return max(below, key=parse)


def kernel_imports(roots: Iterable[Path]) -> set[str]:
    """Every `dotmac_kernel.*` module imported anywhere under the given roots.

    Parsed, never grepped: a substring scan is satisfied by the prose in a
    docstring, and this file's own docstring names `dotmac_kernel.transactions`
    several times without importing it.
    """

    found: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:  # a vendored sample, not code this composition runs
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    module = node.module or ""
                    if module == KERNEL_PACKAGE or module.startswith(
                        f"{KERNEL_PACKAGE}."
                    ):
                        found.add(module)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == KERNEL_PACKAGE or alias.name.startswith(
                            f"{KERNEL_PACKAGE}."
                        ):
                            found.add(alias.name)
    return found


def composed_package_roots(
    distributions: Iterable[str] | None = None,
) -> tuple[Path, ...]:
    """The installed package directory of every composed distribution.

    The assembly's own source plus the modules it composes: a boot failure under
    an excluded kernel can arise in either, and the a5 defect arose in the
    second.
    """

    names = (
        tuple(distributions) if distributions is not None else composed_distributions()
    )
    roots = [ASSEMBLY_PACKAGE]
    for name in names:
        module = name.replace("-", "_")
        for entry in importlib.metadata.files(name) or []:
            parts = Path(str(entry)).parts
            if parts and parts[0] == module:
                roots.append(
                    Path(str(importlib.metadata.distribution(name).locate_file(module)))
                )
                break
    return tuple(dict.fromkeys(roots))


def absent_from_kernel(kernel_root: Path, imported: Iterable[str]) -> tuple[str, ...]:
    """Which imported kernel submodules a given kernel INSTALLATION lacks.

    Compared against a real installation rather than against a recorded
    version→module table. A table has rows somebody must remember to add; an
    installation has files. The names this returns are what the mutation lane
    requires the failure to mention.
    """

    if not kernel_root.is_dir():
        raise FloorError(
            f"{kernel_root} is not an installed {KERNEL_PACKAGE} package "
            "directory. Comparing against nothing would return every imported "
            "module as absent, which reads as a proof and is not one."
        )
    missing = []
    for module in sorted(imported):
        if module == KERNEL_PACKAGE:
            continue
        relative = Path(*module.split(".")[1:])
        if (kernel_root / relative).is_dir():
            continue
        if (kernel_root / relative.with_suffix(".py")).is_file():
            continue
        missing.append(module)
    return tuple(missing)


def assembly_kernel_requirements(
    root: Path = ASSEMBLY_PACKAGE,
) -> dict[str, frozenset[str]]:
    """Every kernel module THIS ASSEMBLY'S OWN source imports, and the top-level
    names it binds out of each.

    The second input to the effective floor (Governance ADR 0021 § 10.1).
    `kernel_imports()` above answers "what does the COMPOSITION
    import", which is the question the mutation lane asks of the excluded
    kernel; this answers "what does the ASSEMBLY ITSELF import", which is the
    question nobody was asking of the pinned one.

    Names matter here and do not in `kernel_imports`. A module that exists is
    enough to say the boot got past the import; it is not enough to say the
    assembly's floor is satisfied, because the way a kernel surface grows is
    usually a NEW NAME in an EXISTING module rather than a new module.

    Parsed, never grepped, for the same reason as `kernel_imports`: a docstring
    naming a module is not an import of it, and this file's own prose names
    several.
    """

    required: dict[str, set[str]] = {}
    if not root.is_dir():
        raise FloorError(
            f"{root} is not a directory, so the assembly's own kernel imports "
            "cannot be read. An empty answer would read as 'the assembly needs "
            "nothing', which is the absent-as-success shape this refuses."
        )
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                module = node.module or ""
                if module == KERNEL_PACKAGE or module.startswith(f"{KERNEL_PACKAGE}."):
                    required.setdefault(module, set()).update(
                        alias.name for alias in node.names if alias.name != "*"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == KERNEL_PACKAGE or alias.name.startswith(
                        f"{KERNEL_PACKAGE}."
                    ):
                        required.setdefault(alias.name, set())
    return {module: frozenset(names) for module, names in sorted(required.items())}


def unsatisfied_kernel_requirements(
    required: dict[str, frozenset[str]] | None = None,
    import_module: Callable[[str], object] = importlib.import_module,
) -> tuple[str, ...]:
    """Which of the assembly's own kernel requirements an INSTALLED kernel lacks.

    Non-empty means the assembly out-imports whatever kernel is installed. Run
    against an installation of the effective maximum, this verifies that the
    assembly's declared contribution is real rather than a circular restatement
    of its exact pin.  The excluded-version plant independently proves that a
    source import first shipped at this floor makes the immediately lower
    published kernel fail for the named missing surface.

    `import_module` is injectable because the interesting half is the failure
    half, and an importer whose refusal has never run is prose.

    A `ModuleNotFoundError` naming something OUTSIDE the kernel is re-raised as
    a refusal rather than counted. A missing PostgreSQL driver is a fact about
    the environment this runs in, not about the kernel's surface, and reporting
    it as an unsatisfied kernel requirement is how a boundary defect gets
    attributed to the wrong artifact.
    """

    needed = assembly_kernel_requirements() if required is None else required
    if not needed:
        raise FloorError(
            f"the assembly imports no {KERNEL_PACKAGE} module at all. An empty "
            "requirement set is satisfied by every kernel ever published, which "
            "reads as a proof and is the absence of one."
        )
    unsatisfied: list[str] = []
    for module, names in sorted(needed.items()):
        try:
            installed = import_module(module)
        except ModuleNotFoundError as exc:
            # `exc.name` is what makes this attributable. An unnamed
            # ModuleNotFoundError is refused for the same reason a named
            # non-kernel one is: this may not guess which artifact is missing.
            if exc.name is None or not (
                exc.name == KERNEL_PACKAGE or exc.name.startswith(f"{KERNEL_PACKAGE}.")
            ):
                raise FloorError(
                    f"importing {module} failed because {exc.name!r} is not "
                    "installed, which is a property of THIS ENVIRONMENT and not "
                    "of the kernel's surface. Install it, or run this where the "
                    "assembly's own dependencies are present; do not let an "
                    "environment gap be recorded as a missing kernel symbol."
                ) from exc
            unsatisfied.append(module)
            continue
        except Exception as exc:  # reported, never absorbed
            raise FloorError(
                f"importing {module} raised {type(exc).__name__}: {exc}. This "
                "check can only speak about a kernel it can import; refusing "
                "rather than recording an unimportable module as an unsatisfied "
                "requirement."
            ) from exc
        unsatisfied.extend(
            f"{module}.{name}" for name in sorted(names) if not hasattr(installed, name)
        )
    return tuple(unsatisfied)


def installed_kernel_version() -> str:
    """The kernel version actually installed where this is running."""

    try:
        return importlib.metadata.version(DEPENDENCY)
    except importlib.metadata.PackageNotFoundError as exc:
        raise FloorError(
            f"{DEPENDENCY} is not installed here, so there is no kernel surface "
            "to ask. An uninstalled kernel is an unmonitored check, not a "
            "passed one."
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="the kernel pin, derived")
    parser.add_argument(
        "what",
        choices=(
            "pinned",
            "binding",
            "floors",
            "excluded",
            "imports",
            "missing-from",
            "assembly-needs",
            "assembly-satisfied",
        ),
    )
    parser.add_argument("--pyproject", type=Path, default=PYPROJECT)
    parser.add_argument(
        "--index-html",
        type=Path,
        help=(
            "the simple-index listing for dotmac-kernel, already fetched. "
            "Required for `excluded`; this module performs no network I/O of "
            "its own, so the credential stays in the step that owns it."
        ),
    )
    parser.add_argument(
        "--kernel-root",
        type=Path,
        help=(
            "an installed dotmac_kernel package directory. Required for "
            "`missing-from`."
        ),
    )
    args = parser.parse_args(argv)

    try:
        pin = declared_pin(args.pyproject)
        if args.what == "pinned":
            print(pin)
            return 0
        if args.what == "floors":
            for name, floor in sorted(declared_kernel_floors().items()):
                print(f"{name} >={floor}")
            return 0
        if args.what == "binding":
            name, floor = binding_distribution()
            print(f"{name} {floor}")
            return 0
        if args.what == "assembly-needs":
            for module, names in assembly_kernel_requirements().items():
                print(f"{module}: {' '.join(sorted(names)) or '(module only)'}")
            return 0
        if args.what == "assembly-satisfied":
            # The premise, held where it can fail. This answers "is the
            # assembly's own declared floor is provided by the effective maximum",
            # so it may only be asked of an installation OF that maximum — asking a
            # different kernel answers a different question and would report
            # the equality rule proven on a run that never tested it.
            binding_name, effective_maximum = binding_distribution()
            installed = installed_kernel_version()
            if installed != effective_maximum:
                raise FloorError(
                    f"the installed {DEPENDENCY} is {installed} while the "
                    f"effective assembly floor is {effective_maximum} "
                    f"(from {binding_name}). This check only "
                    "means something against an installation of that maximum."
                )
            needed = assembly_kernel_requirements()
            unsatisfied = unsatisfied_kernel_requirements(needed)
            if unsatisfied:
                raise FloorError(
                    "this assembly's own source imports "
                    f"{list(unsatisfied)}, which {DEPENDENCY} {installed} does "
                    "not provide. The assembly's OWN floor is therefore ABOVE "
                    f"the declared effective floor. Raise the pin and the "
                    "assembly contribution together to a kernel that provides "
                    "these. Do NOT loosen the equality assertion."
                )
            print(
                f"{sum(len(names) for names in needed.values())} kernel names "
                f"across {len(needed)} modules, all provided by {DEPENDENCY} "
                f"{installed} — the effective maximum, from {binding_name}"
            )
            return 0
        if args.what == "imports":
            for module in sorted(kernel_imports(composed_package_roots())):
                print(module)
            return 0
        if args.what == "missing-from":
            if args.kernel_root is None:
                raise FloorError("`missing-from` requires --kernel-root")
            missing = absent_from_kernel(
                args.kernel_root, kernel_imports(composed_package_roots())
            )
            if not missing:
                raise FloorError(
                    f"every {KERNEL_PACKAGE} module this composition imports is "
                    f"present in {args.kernel_root}. The pin {pin} is then higher "
                    "than anything the composition needs, and the mutation lane "
                    "would be requiring a failure that cannot happen. Lower the "
                    "pin to the version the composition actually requires, or "
                    "record why it was raised anyway."
                )
            for module in missing:
                print(module)
            return 0
        if args.index_html is None:
            raise FloorError("`excluded` requires --index-html")
        versions = index_versions(
            args.index_html.read_text(encoding="utf-8", errors="replace")
        )
        if not versions:
            raise FloorError(
                f"{args.index_html} names no {DEPENDENCY} version at all. An "
                "empty listing reads as 'nothing is excluded', which is the "
                "absent-as-success shape this repository refuses everywhere."
            )
        print(newest_excluded(pin, versions))
        return 0
    except FloorError as exc:
        print(f"error {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
