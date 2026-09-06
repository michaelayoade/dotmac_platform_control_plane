#!/usr/bin/env python3
"""This assembly's Kernel-adoption observation. The whole product-side surface.

Governance owns the Kernel-adoption runner, the declaration contract and every
refusal. A product owns exactly two things: its own
`.dotmac/kernel-adoption.json`, and one callable of this shape. `observe`
classifies nothing and decides nothing, and it structurally CANNOT state a
declaration -- `ProductObservation` carries no declaration field, so the runner
reads the document itself and a product cannot hand Governance a convenient
one.

Three choices a copy of this file has to make, each stated because each is a
place a product could quietly narrow what is measured.

**The inventory is this repository's own answer to "what does the interpreter
execute", not a second one.** `tests/architecture/python_entrypoints.py` owns
that question: it enumerates the declared Python entry-point FAMILIES and
classifies a file as Python by parsing it rather than by its suffix. That
module exists because `src/vendor_cp/rotation_runtime_oracle.pyprogram` imports
four names out of `dotmac_kernel.db` and every `*.py` glob walked past it.
Reimplementing the sweep here would be a second writer of the one fact, and the
first sign of the drift would be a census that disagrees with the ratchet built
to police it -- so it is imported, exactly as `scripts/kernel_floor.py` imports
it and for the same reason.

**`tests/` is outside the observation, and the premise is REACHABILITY rather
than a claim about a directory.** `PYTHON_ENTRYPOINT_FAMILIES` names
`src/vendor_cp`, `scripts` and `alembic`: what this product's interpreter runs
in production. A file outside those families contributes iff something inside
them imports it, which is computed rather than asserted and held as a
two-directional ratchet in `ASSEMBLED_EXTERNAL_MODULES`/
`kernel_floor.ABSORBED_EXTERNAL_MODULES`. This matters for one surface in
particular: `dotmac_kernel.testing` is imported by more than ten modules under
`tests/` and by nothing the product ships. It is governed by the profile's
`testing_kit_boundary`, which already permits a test import and refuses a
runtime one. It is deliberately NOT declared a prohibited surface: a
`ProhibitedSurface` carries no scope, so declaring it would report every
legitimate test import as a violation -- a guard that fires on correct code
teaches its readers to delete it.

**The catalogue is READ from the installed distribution, never typed here.**
`KernelSurfaceCatalogue` is the Kernel's own `SUPPORTED_MODULES` and
`INTERNAL_MODULES`. A hardcoded subset would make an unknown-surface verdict an
artefact of this file's staleness rather than a fact about the product. The
peeled commit those lists were published at is not derivable from the
distribution -- a wheel does not carry the commit that built it -- so it comes
from `docs/inventories/kernel-release-coordinates.json`, which records it with
the external oracle AGENTS.md rule 30 requires, and this file refuses if the
recorded version is not the version actually installed.
"""

from __future__ import annotations

import json
import re
import sys
from importlib import metadata
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[1]

#: Where the peeled commit of the pinned Kernel release is recorded, with the
#: oracle that established it.
RELEASE_COORDINATES: Final = PurePosixPath(
    "docs/inventories/kernel-release-coordinates.json"
)

DISTRIBUTION: Final = "dotmac-kernel"
KERNEL_PACKAGE: Final = "dotmac_kernel"

#: `name = "dotmac-kernel"` ... `{file = "...whl", hash = "sha256:..."}` in
#: `poetry.lock`. The digest of the distribution this assembly RESOLVES, which
#: is a repository-local read and not a registry attestation.
_WHEEL_HASH: Final = re.compile(
    r'\{file = "dotmac_kernel-(?P<version>[^"]+)-py3-none-any\.whl", '
    r'hash = "(?P<digest>sha256:[0-9a-f]{64})"\}'
)


class ObservationError(RuntimeError):
    """The observation could not be made. Never softened into a partial one.

    An observer that returned what it managed to read would hand the runner a
    narrowed inventory and every arm would answer cleanly about a subject
    nobody chose -- a clean run over the wrong source, which is worse than no
    run at all.
    """


def _entrypoints_module() -> ModuleType:
    """The module that owns "what does this product's interpreter execute".

    Imported rather than reimplemented, for the reason `scripts/kernel_floor.py`
    gives at its own copy of this function: that module is the repository's ONE
    answer, it is itself ratcheted, and a second copy here would drift.
    """
    location = REPO_ROOT / "tests" / "architecture"
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))
    try:
        import python_entrypoints
    except ImportError as error:  # pragma: no cover - a broken checkout
        raise ObservationError(
            f"cannot import the Python entry-point classifier from {location}: "
            f"{error}. Falling back to a `*.py` glob would reintroduce the "
            "extension blindness that hid a live `dotmac_kernel.db` importer, "
            "so this refuses rather than measuring less."
        ) from error
    return python_entrypoints


def _recorded_release(root: Path, version: str) -> str:
    """The peeled commit recorded for `version`, or a refusal."""
    path = root / RELEASE_COORDINATES
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ObservationError(
            f"cannot read {RELEASE_COORDINATES.as_posix()}: {error}. It carries "
            "the peeled commit the Kernel's module lists were published at, "
            "and a catalogue with no revision cannot be re-derived by anyone "
            "who was not present."
        ) from error
    for release in document.get("releases", []):
        if release.get("version") == version:
            return str(release["peeled_commit"])
    raise ObservationError(
        f"{RELEASE_COORDINATES.as_posix()} records no peeled commit for "
        f"{DISTRIBUTION} {version}, which is the version actually installed. "
        "Recording one requires an external oracle -- a peeled tag in the "
        "Kernel's own repository -- and inventing a coordinate here would put "
        "a commit nobody read into a bound report."
    )


def _artifact_digest(root: Path, version: str) -> str:
    """The wheel digest `poetry.lock` resolves for the installed version."""
    try:
        lock = (root / "poetry.lock").read_text(encoding="utf-8")
    except OSError as error:
        raise ObservationError(f"cannot read poetry.lock: {error}") from error
    for match in _WHEEL_HASH.finditer(lock):
        if match.group("version") == version:
            return match.group("digest")
    raise ObservationError(
        f"poetry.lock resolves no wheel for {DISTRIBUTION} {version}, the "
        "version this environment has installed. The lock and the environment "
        "disagree about which Kernel this assembly composes, and a catalogue "
        "bound to either one would describe a distribution the product is not "
        "installing."
    )


def _catalogue(root: Path) -> object:
    """The Kernel's published module lists, at the revision they were cut."""
    from kernel_adoption_control.contracts import KernelSurfaceCatalogue

    try:
        import dotmac_kernel
    except ImportError as error:
        raise ObservationError(
            f"cannot import {KERNEL_PACKAGE}: {error}. Its SUPPORTED_MODULES "
            "and INTERNAL_MODULES are what every surface verdict is taken "
            "against; typing a substitute here would make an unknown-surface "
            "finding an artefact of this file's staleness rather than a fact "
            "about the product. Install the composed environment and re-run."
        ) from error

    version = metadata.version(DISTRIBUTION)
    return KernelSurfaceCatalogue(
        revision=_recorded_release(root, version),
        version=version,
        supported=frozenset(dotmac_kernel.SUPPORTED_MODULES),
        internal=frozenset(dotmac_kernel.INTERNAL_MODULES),
        artifact_digest=_artifact_digest(root, version),
    )


def _pin_sites(root: Path) -> tuple[object, ...]:
    """Every place this assembly states the Kernel version it adopts.

    Two KINDS, carried separately so a disagreement can name which two
    disagree: the dependency declaration in `pyproject.toml` and the resolution
    in `poetry.lock`. A pin stated once is a pin nothing can contradict.
    """
    from kernel_adoption_control.contracts import PinSite

    sites: list[object] = []
    declaration = re.compile(r'dotmac-kernel\s*=\s*\{?\s*version\s*=\s*"([^"]+)"')
    for number, line in enumerate(
        (root / "pyproject.toml").read_text(encoding="utf-8").splitlines(), start=1
    ):
        found = declaration.search(line)
        if found is not None:
            sites.append(
                PinSite(
                    path=PurePosixPath("pyproject.toml"),
                    line=number,
                    version=found.group(1),
                    kind="dependency-declaration",
                )
            )
    for number, line in enumerate(
        (root / "poetry.lock").read_text(encoding="utf-8").splitlines(), start=1
    ):
        found = _WHEEL_HASH.search(line)
        if found is not None:
            sites.append(
                PinSite(
                    path=PurePosixPath("poetry.lock"),
                    line=number,
                    version=found.group("version"),
                    kind="lock-resolution",
                )
            )
    return tuple(sites)


def observe(root: Path) -> object:
    """Read this assembly's executable Python surface and its Kernel catalogue."""
    from kernel_adoption_control.runner import ProductObservation

    entrypoints = _entrypoints_module()
    sources: dict[PurePosixPath, str] = {}
    for path in entrypoints.python_sources():
        relative = PurePosixPath(path.relative_to(entrypoints.ROOT).as_posix())
        # An unreadable file is NOT skipped. Its bytes go through as a source
        # the engine will fail to parse and report; dropping it here would be
        # the observation quietly deciding what is measured.
        sources[relative] = path.read_text(encoding="utf-8", errors="replace")
    return ProductObservation(
        sources=sources,
        catalogue=_catalogue(root),
        pin_sites=_pin_sites(root),
    )
