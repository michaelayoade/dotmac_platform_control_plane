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
ASSEMBLY. It pins the kernel EXACTLY, and the pin has to satisfy every composed
distribution's declared lower bound at once. So the question here is not "does
the declared minimum import" but "is the exact pin the tightest version that
still satisfies everything composed" — an assembly that pins too LOW dies at
boot the way a5 did, and one that pins too HIGH has taken a kernel upgrade
nothing asked for and owes the migration rehearsal that comes with it.

Both halves are derived, and neither is copied into a document:

* `declared_pin()` — the exact version `pyproject.toml` pins. Any other
  constraint shape is refused rather than interpreted.
* `declared_kernel_floors()` — every composed distribution's `Requires-Dist`
  lower bound, read from INSTALLED METADATA. Not from a source tree, not from a
  changelog and not from the census's prose: the artifact's own declaration is
  the thing that binds a resolver. The assembly is never added to this dict: one
  number comes from an artifact's metadata and the other from a source tree, and
  conflating them would make a source-tree number read as an artifact's claim.
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

* **The assembly's contribution is read from ITS OWN SOURCE, never from its
  declaration.** § 10.1 is explicit that "an assembly's declared direct
  constraint on the dependency IS the `==` pin: a maximum that reads the pin as
  its own third input returns the pin, agrees with itself, and proves nothing."
  So the contribution here is derived from what `src/vendor_cp` imports.
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

Today those two agree, and the equality held only because of a coincidence:
nothing in `src/vendor_cp` imported a kernel symbol its composed modules did not
already require. That coincidence was an UNSTATED PREMISE — the equality
assertion was true for a reason nothing checked, and the day somebody imports
`dotmac_kernel.<something first shipped above the pin>` here, the equality rule
would drag the pin DOWN to a version this assembly cannot run on, and would do
it silently. That is a5's defect wearing the assembly's clothes.

## The three values

The rule's subject is now NAMED rather than implied, in three values instead of
one, because a reader could not previously tell whether the assembly had been
considered and found to contribute nothing or simply never asked:

* `composed_distribution_maximum()` — the highest floor any composed
  distribution's installed metadata declares, and which one.
* `assembly_import_floor()` — the floor this repository's OWN source
  establishes, from a closed declaration of every kernel name it imports.
  `None` when every one of them sits at or below the composed maximum, which is
  today's state and a measured one rather than an assumption.
* `effective_kernel_floor()` — the maximum of the two. THE PIN MUST EQUAL THIS.

The equality is unchanged and stays `==`. What moved is what it ranges over.

`assembly-satisfied` holds the premise where a lane can fail on it, in five
steps that fail separately: the installed kernel must BE the effective floor;
the assembly's executable source is scanned; the scan must equal the closed
declaration in both directions; every declared name must resolve against the
INSTALLED artifact; and the application must actually compose.

Four deliberate limits, stated rather than implied:

* the scan reads EXECUTABLE SOURCE BY PROPERTY, never by file extension. A
  `*.py` glob of `src/vendor_cp` misses `dotmac_kernel.security` entirely and
  four names out of `dotmac_kernel.db`, all reached from `.pyprogram` payloads
  that this product's own interpreter executes. `is_python_source` in
  `tests/architecture/python_entrypoints.py` is the one classifier, imported
  rather than copied.
* the check asks the INSTALLED kernel by importing it and reading the attribute,
  because the kernel's package root resolves its public names through a module
  `__getattr__`; a static read of the installed source would answer "absent" for
  every lazily re-exported symbol, and a read of a SIBLING CHECKOUT would answer
  about a tree this product does not run. Importing means the environment must
  be able to import kernel modules at all, which is a premise this module
  refuses on rather than absorbs (see the `ModuleNotFoundError` branch below —
  a driver missing from the ENVIRONMENT is not a symbol missing from the KERNEL,
  and conflating the two is precisely the confusion that made a100 look like a
  regression when it is not one).
* a name the scan finds and the declaration does not carry is REFUSED, not
  counted. Its first-shipping version is unestablished, and an unestablished
  floor must not exit the same way as an established one.
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
    """The composed distribution whose declared floor is the highest, and it.

    Naming it matters as much as the number. When the pin has to move, the
    reviewer needs to know WHICH module asked — a bump nobody can attribute is
    a kernel upgrade taken on nobody's behalf.
    """

    resolved = declared_kernel_floors() if floors is None else floors
    if not resolved:
        raise FloorError("no composed distribution declares a kernel floor")
    name = max(resolved, key=lambda key: (parse(resolved[key]), key))
    return name, resolved[name]


# ── the assembly's own floor: scan, declaration, and the three values ───────
#
# Governance ADR 0021 § 10.1 makes the effective floor the maximum of TWO
# inputs. Until now only one of them had a name in code, and the other was a
# coincidence nothing measured. Both are named here, and so is the maximum:
#
#   composed_distribution_maximum()  — the composed distributions' Requires-Dist
#   assembly_import_floor()          — what THIS repository's own source needs
#   effective_kernel_floor()         — the maximum, and the pin must equal it
#
# Naming the third is the point. `pin == max(...)` was previously written
# against the first alone, which made the rule's subject implicit and therefore
# unreviewable: a reader could not tell whether the assembly had been considered
# and found to contribute nothing, or simply never asked.


#: The name the assembly travels under when IT is the binding contributor.
#: Deliberately unlike a distribution name, because the whole point is that this
#: floor comes from a source tree rather than from an artifact's metadata.
ASSEMBLY_FLOOR_KEY: Final = "src/vendor_cp (this assembly)"


def composed_distribution_maximum() -> tuple[str, str]:
    """The highest kernel floor any COMPOSED DISTRIBUTION declares, and which.

    A named alias for `binding_distribution()`, so that the three values the
    equality rests on can be read side by side. `declared_kernel_floors()` keeps
    its exact meaning — installed `Requires-Dist` — and the assembly is never
    added to it: one number comes from an artifact's own metadata, the other
    from a source tree, and letting a source-tree number sit in that dict would
    make it read as something an artifact declared.
    """

    return binding_distribution()


#: Every `dotmac_kernel` module the assembly's own executable source imports,
#: and every top-level name it binds out of each. A CLOSED declaration: the
#: property-based scan below must equal this EXACTLY, in both directions.
#:
#: Set equality, never a count. A symbol swapped for another symbol leaves the
#: count identical and the set different, and a count-based ratchet would pass
#: over exactly the edit most likely to change what the kernel has to provide.
#:
#: Why it is written out rather than derived: derived-from-source is what the
#: scan already is, and a check that compares a scan with itself agrees with
#: whatever the source happens to say. This is the half a human reviewed.
ASSEMBLY_KERNEL_SYMBOLS: Final[dict[str, frozenset[str]]] = {
    "dotmac_kernel": frozenset(
        {
            "BadRequestError",
            "Base",
            "CapabilityCatalogue",
            "ConflictError",
            "DomainError",
            "FeatureManifest",
            "LocalizedText",
            "ModuleManifest",
            "Money",
            "MoneyError",
            "NotFoundError",
            "PlatformAdmin",
            "PlatformScope",
            "ProductAssemblySpec",
            "ProductManifestError",
            "ProductManifestSnapshot",
            "TimestampMixin",
            "UndeclaredCapabilityError",
            "WebNavItem",
            "WebSurfaceContribution",
            "create_app",
            "currency",
            "hash_password",
            "uuid_pk",
            "write_platform_audit_event",
        }
    ),
    "dotmac_kernel.audit": frozenset({"write_platform_audit_event"}),
    "dotmac_kernel.db": frozenset(
        {
            "PlatformSessionLocal",
            "SessionLocal",
            "conflict_savepoint",
            "engine",
            "get_platform_db",
            "platform_engine",
            "platform_session",
            "runtime",
        }
    ),
    "dotmac_kernel.features": frozenset({"FeatureManifest"}),
    "dotmac_kernel.idempotency": frozenset(
        {"IdempotentOutcome", "execute_once_platform", "fingerprint_of"}
    ),
    "dotmac_kernel.licensing": frozenset({"LicenceKeyRing"}),
    "dotmac_kernel.messaging": frozenset(
        {
            "ClaimedPlatformEvent",
            "OutboxStatus",
            "PlatformOutboxEvent",
            "RelayPolicy",
            "enqueue_platform_event",
            "process_once_platform",
        }
    ),
    "dotmac_kernel.messaging.platform_worker": frozenset(
        {"PlatformDeliveryTransport", "SessionFactory", "run_once"}
    ),
    "dotmac_kernel.migrations": frozenset({"versions_dir"}),
    "dotmac_kernel.migrations.catalog": frozenset(
        {"ROLE_TABLE_PRIVILEGES_SQL", "TABLE_PRIVILEGES"}
    ),
    "dotmac_kernel.models": frozenset({"Base", "TimestampMixin", "uuid_pk"}),
    "dotmac_kernel.planes": frozenset(
        {"MODULE_PLANES_ENV_VAR", "ModulePlane", "ModulePlaneSelection"}
    ),
    "dotmac_kernel.platform_auth": frozenset({"require_platform_admin"}),
    "dotmac_kernel.prerequisites": frozenset(
        {
            "BINDINGS_ENV_VAR",
            "IDEMPOTENCY_LEDGER_V1",
            "MODULE_DATABASE_ROLES_V1",
            "OUTBOX_RELAY_V1",
            "PLATFORM_AUDIT_LOG_V1",
            "PrerequisiteBinding",
            "TENANT_SCOPE_CATALOG_V1",
        }
    ),
    "dotmac_kernel.providers.provisioning": frozenset(
        {
            "ApplyResult",
            "CompensationDisposition",
            "CompensationResult",
            "ObserveResult",
            "PlanResult",
            "ProvisioningPlanError",
            "ProvisioningProvider",
            "ProvisioningRequest",
            "ProvisioningStatus",
            "ProvisioningStep",
            "StepStatus",
        }
    ),
    "dotmac_kernel.security": frozenset({"decode_access_token", "hash_token"}),
    "dotmac_kernel.session_runtime": frozenset({"DatabaseRuntime"}),
}

#: The subset of the above whose FIRST-SHIPPING kernel version is established
#: and lies ABOVE the composed maximum — the only symbols that can raise this
#: assembly's own floor. Keyed `module:name`, or `module:` for a whole module.
#:
#: EMPTY TODAY, and that is the assembly's floor being *measured* rather than
#: assumed: every name above is provided by the composed maximum, so this
#: assembly contributes nothing and `effective_kernel_floor()` is the composed
#: maximum. Empty is not "unchecked" — `assembly_import_floor()` proves the
#: emptiness by resolving all of `ASSEMBLY_KERNEL_SYMBOLS` against the INSTALLED
#: artifact, and an unresolvable name is a refusal.
#:
#: An entry here must be above the composed maximum. One at or below it would
#: claim to raise a floor while raising nothing, and be indistinguishable from a
#: floor that had gone stale downward; `assembly_import_floor()` refuses it.
ASSEMBLY_SYMBOL_FLOORS: Final[dict[str, str]] = {}


def _entrypoint_classifier() -> (
    tuple[
        Callable[[Path], bool],
        Callable[[Path], tuple[tuple[str, str | None, int], ...]],
    ]
):
    """`is_python_source` and `imports_of`, from the module that owns them.

    Imported from `tests/architecture/python_entrypoints.py` rather than
    reimplemented. That module is the repository's ONE answer to "what does this
    product's Python interpreter execute", it is itself ratcheted, and a second
    copy of the classifier here would be a second writer that drifts — which is
    the defect this whole file exists to police, in miniature.
    """

    location = REPO_ROOT / "tests" / "architecture"
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))
    try:
        import python_entrypoints  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - a broken checkout
        raise FloorError(
            f"cannot import the Python entry-point classifier from {location}: "
            f"{exc}. Falling back to a `*.py` glob would silently reintroduce "
            "the extension blindness it exists to repair, so this refuses."
        ) from exc
    return python_entrypoints.is_python_source, python_entrypoints.imports_of


def assembly_source_symbols(
    root: Path = ASSEMBLY_PACKAGE,
) -> dict[str, frozenset[str]]:
    """Every kernel module and name the assembly's EXECUTABLE source imports.

    By PROPERTY, not by suffix. `src/vendor_cp` carries four tracked payloads
    that are not named `.py`, and two of them are Python that this product's own
    interpreter executes:

    * `rotation_runtime_oracle.pyprogram` binds four more names out of
      `dotmac_kernel.db` than any `.py` file does;
    * `rotation_runtime_material_oracle.pyprogram` imports
      `dotmac_kernel.security`, an ENTIRE MODULE that a `*.py` glob of this tree
      never sees at all.

    A floor computed from a `*.py` glob is therefore a floor computed from an
    inventory known to be short — and short in the direction that matters, since
    an unseen import is an unseen requirement. `is_python_source` answers the
    question actually being asked.

    Parsed, never grepped: `cli/commands.py` names `dotmac_kernel.db` in prose
    explaining why its real import is deferred, and a substring census counts
    that paragraph as an importer.
    """

    if not root.is_dir():
        raise FloorError(
            f"{root} is not a directory, so the assembly's own kernel imports "
            "cannot be read. An empty answer would read as 'the assembly needs "
            "nothing', which is the absent-as-success shape this refuses."
        )
    is_python_source, imports_of = _entrypoint_classifier()
    prefix = f"{root.as_posix()}/"
    found: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if not path.as_posix().startswith(prefix):
            continue
        if not is_python_source(path):
            continue
        for module, name, _line in imports_of(path):
            if module != KERNEL_PACKAGE and not module.startswith(f"{KERNEL_PACKAGE}."):
                continue
            found.setdefault(module, set())
            if name is not None and name != "*":
                found[module].add(name)
    if not found:
        raise FloorError(
            f"no {KERNEL_PACKAGE} import was found anywhere under {root}. An "
            "empty scan is satisfied by every kernel ever published, which "
            "reads as a proof and is the absence of one."
        )
    return {module: frozenset(names) for module, names in sorted(found.items())}


def undeclared_assembly_symbols(
    scanned: dict[str, frozenset[str]] | None = None,
    declared: dict[str, frozenset[str]] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """`(in the source but not declared, declared but not in the source)`.

    Both directions, because both are defects and they fail for different
    reasons. An UNDECLARED import is a kernel requirement whose first-shipping
    version nobody established — refused, never passed, since "we did not look"
    and "we looked and it is fine" must not produce the same exit code. A
    DECLARED-BUT-ABSENT entry is a requirement that outlived its import, which
    is how a floor stays raised on a surface nothing uses.
    """

    found = assembly_source_symbols() if scanned is None else scanned
    known = ASSEMBLY_KERNEL_SYMBOLS if declared is None else declared

    undeclared: list[str] = []
    stale: list[str] = []
    for module in sorted(set(found) | set(known)):
        in_source = found.get(module)
        in_declaration = known.get(module)
        if in_source is None:
            stale.append(f"{module}:")
            continue
        if in_declaration is None:
            undeclared.append(f"{module}:")
            undeclared.extend(f"{module}:{name}" for name in sorted(in_source))
            continue
        undeclared.extend(
            f"{module}:{name}" for name in sorted(in_source - in_declaration)
        )
        stale.extend(f"{module}:{name}" for name in sorted(in_declaration - in_source))
    return tuple(undeclared), tuple(stale)


def assembly_import_floor(
    floors: dict[str, str] | None = None,
    composed_maximum: str | None = None,
) -> str | None:
    """The kernel floor the assembly's OWN imports establish, or `None`.

    `None` means every name the assembly imports is provided at or below the
    composed maximum, so this input does not move the answer. That is today's
    state and it is a MEASURED one: the caller has already required the scan to
    equal the closed declaration, and `assembly-satisfied` resolves every
    declared name against the installed artifact.

    A declared floor at or below the composed maximum is refused. It raises
    nothing, so keeping it would be indistinguishable from a floor that had
    silently gone stale downward — and it would let a reviewer believe the
    assembly was contributing when it was not.
    """

    entries = ASSEMBLY_SYMBOL_FLOORS if floors is None else floors
    if not entries:
        return None
    ceiling = (
        composed_distribution_maximum()[1]
        if composed_maximum is None
        else composed_maximum
    )
    for coordinate, version in sorted(entries.items()):
        parse(version)
        if parse(version) <= parse(ceiling):
            raise FloorError(
                f"the assembly declares a floor of {version} for {coordinate}, "
                f"which is at or below the composed maximum {ceiling}. Such an "
                "entry raises nothing while claiming to: delete it, or correct "
                "the version it actually needs."
            )
    return max(entries.values(), key=parse)


def effective_kernel_floor() -> tuple[str, str]:
    """The floor the pin must EQUAL, and the contributor that established it.

    `max(composed_distribution_maximum, assembly_import_floor)`. Naming the
    contributor matters as much as the number: a pin move nobody can attribute
    is a kernel upgrade taken on nobody's behalf.
    """

    composed_name, composed_floor = composed_distribution_maximum()
    own = assembly_import_floor(composed_maximum=composed_floor)
    if own is not None and parse(own) > parse(composed_floor):
        return ASSEMBLY_FLOOR_KEY, own
    return composed_name, composed_floor


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
    """Every kernel module THIS ASSEMBLY'S OWN source imports, and the names it
    binds out of each.

    The second input to the effective floor (Governance ADR 0021 § 10.1).
    `kernel_imports()` above answers "what does the COMPOSITION import", which is
    the question the mutation lane asks of the excluded kernel; this answers
    "what does the ASSEMBLY ITSELF import", which is the question nobody was
    asking of the pinned one.

    Names matter here and do not in `kernel_imports`. A module that exists is
    enough to say the boot got past the import; it is not enough to say the
    assembly's floor is satisfied, because the way a kernel surface grows is
    usually a NEW NAME in an EXISTING module rather than a new module.

    ONE scanner, delegated. This used to `rglob("*.py")` and was short by an
    entire kernel module as a result — see `assembly_source_symbols`. Keeping a
    second, suffix-based implementation alive under this name would be exactly
    the two-writers-one-answer defect this file polices.
    """

    return assembly_source_symbols(root)


def unsatisfied_kernel_requirements(
    required: dict[str, frozenset[str]] | None = None,
    import_module: Callable[[str], object] = importlib.import_module,
) -> tuple[str, ...]:
    """Which of the assembly's own kernel requirements an INSTALLED kernel lacks.

    Non-empty means the assembly out-imports whatever kernel is installed. Run
    against an installation of the composed maximum, that is the statement the
    equality rule needs and has never had: the assembly's own floor is at or
    below the composed maximum, so the maximum of the two IS the composed
    maximum, so `pin == max(composed floors)` is the whole rule and not an
    accident.

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


def drive_composition(
    import_module: Callable[[str], object] = importlib.import_module,
) -> str:
    """Boot the real application, so the answer covers what actually runs.

    A static scan plus a `hasattr` sweep proves that every name the source
    NAMES is present. It does not prove the assembly composes: a kernel whose
    symbol still exists but whose signature, dataclass field set or refusal
    behaviour changed satisfies every check above and fails at boot. That gap is
    where a pin move actually breaks, so the last step is to build the
    application rather than to describe it.

    `vendor_cp.main` is the deployed entrypoint and it is `create_app(
    build_spec())` at module scope, so importing it IS the boot — profile
    admission, prerequisite binding, key custody, router mounting and every
    refusal the factory performs.

    Refuses rather than absorbs. An ImportError naming something outside the
    kernel is a property of THIS ENVIRONMENT, and recording it as a kernel
    finding is how a boundary defect gets attributed to the wrong artifact —
    the same distinction `unsatisfied_kernel_requirements` draws, drawn again
    here because this step can fail for many more reasons than that one can.
    """

    try:
        import_module("vendor_cp.main")
    except ModuleNotFoundError as exc:
        if exc.name is not None and (
            exc.name == KERNEL_PACKAGE or exc.name.startswith(f"{KERNEL_PACKAGE}.")
        ):
            raise FloorError(
                f"composing the application failed: {exc.name!r} is missing "
                f"from the installed {DEPENDENCY}. The assembly's own floor is "
                "above the kernel installed here."
            ) from exc
        raise FloorError(
            f"composing the application failed because {exc.name!r} is not "
            "installed, which is a property of THIS ENVIRONMENT and not of the "
            "kernel's surface. Run this where the assembly's own dependencies "
            "and configuration are present; do not let an environment gap be "
            "recorded as a satisfied floor OR as a kernel defect."
        ) from exc
    except Exception as exc:
        raise FloorError(
            f"composing the application raised {type(exc).__name__}: {exc}. "
            "The kernel provides every name this assembly imports and the "
            "application still does not boot on it, which is precisely what a "
            "name-level check cannot see. Refusing rather than reporting the "
            "floor satisfied."
        ) from exc
    return "vendor_cp.main imported: create_app(build_spec()) composed"


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
            "assembly-floor",
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
        if args.what == "assembly-floor":
            composed_name, composed_floor = composed_distribution_maximum()
            own = assembly_import_floor(composed_maximum=composed_floor)
            contributor, effective = effective_kernel_floor()
            print(f"composed_distribution_maximum {composed_floor} ({composed_name})")
            print(f"assembly_import_floor         {own or '(contributes nothing)'}")
            print(f"effective_kernel_floor        {effective} ({contributor})")
            return 0
        if args.what == "assembly-satisfied":
            # The premise, held where it can fail — in five steps, each of which
            # can fail on its own.
            #
            # It used to ask "is the assembly's own floor at or below the
            # COMPOSED MAXIMUM". That was the same question as the one below
            # only while the assembly contributed nothing; the day it
            # contributes, the old wording would make this refuse to run at all
            # on exactly the change it exists to police. The subject is the
            # EFFECTIVE floor now. Nothing was softened — every refusal below is
            # new or unchanged, and two of them did not exist before.
            contributor, effective = effective_kernel_floor()
            installed = installed_kernel_version()
            if installed != effective:
                raise FloorError(
                    f"the installed {DEPENDENCY} is {installed} while the "
                    f"effective floor is {effective} (from {contributor}). "
                    "This check only means something against an installation "
                    "of that floor."
                )

            # 1. Scan the assembly's executable source BY PROPERTY. A `*.py`
            #    glob here was short by `dotmac_kernel.security` and by four
            #    names out of `dotmac_kernel.db`, all reached from `.pyprogram`
            #    payloads this product's own interpreter executes.
            scanned = assembly_source_symbols()

            # 2 & 3. Compare with the CLOSED declaration, both directions. An
            #    undeclared import is a requirement whose first-shipping version
            #    nobody established: refused, because "we did not look" must not
            #    exit the same way as "we looked and it is fine". A declared
            #    entry with no import behind it is a requirement that outlived
            #    its call site.
            undeclared, stale = undeclared_assembly_symbols(scanned)
            if undeclared:
                raise FloorError(
                    f"the assembly imports {list(undeclared)}, which "
                    "`ASSEMBLY_KERNEL_SYMBOLS` does not declare. The kernel "
                    "version each of these first shipped at is therefore "
                    "unestablished, and an unestablished floor is a refusal "
                    "rather than a pass: declare them, and record any that is "
                    "above the composed maximum in `ASSEMBLY_SYMBOL_FLOORS`."
                )
            if stale:
                raise FloorError(
                    f"`ASSEMBLY_KERNEL_SYMBOLS` declares {list(stale)}, which "
                    "the assembly no longer imports. A declaration that "
                    "outlives its import keeps a floor raised on a surface "
                    "nothing uses; delete the entries."
                )

            # 4. Resolve every DECLARED name against the INSTALLED artifact —
            #    not against a sibling checkout's source. What this product runs
            #    on is the wheel it installed.
            unsatisfied = unsatisfied_kernel_requirements(dict(ASSEMBLY_KERNEL_SYMBOLS))
            if unsatisfied:
                raise FloorError(
                    "this assembly's own source imports "
                    f"{list(unsatisfied)}, which {DEPENDENCY} {installed} does "
                    "not provide. The assembly's OWN floor is therefore ABOVE "
                    f"the effective floor {effective}, so the maximum is wrong: "
                    "the effective floor is the maximum of the composed floors "
                    "AND the assembly's own direct constraint (Governance ADR "
                    "0021 § 10). Raise the pin to a kernel that provides these "
                    "and record them in `ASSEMBLY_SYMBOL_FLOORS`. Do NOT loosen "
                    "the equality assertion."
                )

            # 5. Boot it. Every check above is about NAMES; this is about
            #    whether the application composes on the kernel it names.
            composed = drive_composition()

            print(
                f"{sum(len(names) for names in scanned.values())} kernel names "
                f"across {len(scanned)} modules, declared, and all provided by "
                f"{DEPENDENCY} {installed} — the effective floor, from "
                f"{contributor}. {composed}"
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
