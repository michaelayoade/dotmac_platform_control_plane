"""Eleven sites reach `dotmac_kernel.db`, and one of them was invisible.

The programme retires this import: the kernel's module-level engine is built at
import time from `DATABASE_URL`, which is why `cli/runtime.py` defers its import
into a function body and why the routers can only take the dependency the kernel
hands them. Getting from eleven to zero is a cutover, and a cutover is measured
against a census.

The census was wrong. `src/vendor_cp/rotation_runtime_oracle.pyprogram` imports
`SessionLocal`, `PlatformSessionLocal`, `engine` and `platform_engine` out of
`dotmac_kernel.db` and is executed by the deployed application's own interpreter
— and every scan in `tests/architecture/` globbed `*.py`, so it reported ten.
A cutover that closed ten sites would have declared the import retired with a
live importer still in the tree.

## What is held here

The recorded inventory is PATHS AND SYMBOLS, not a count. A change that swaps
one site for another leaves the count at eleven and must still fail — that is
the whole reason a count is the wrong baseline.

Two directions, both able to fail:

* a site APPEARS — a new importer, in any entry-point family, in any file the
  product's interpreter executes. Fails.
* a site DISAPPEARS without `KERNEL_DATABASE_IMPORTERS` being lowered in the
  same change. Fails. Retiring a site is the goal; retiring it silently means
  the next person reads a census that no longer describes the tree.
* a site KEEPS its path and CHANGES its symbols. Fails.

The equality is allowed to reach `{}` — that is where the programme is going.
Its non-vacuity therefore cannot rest on the set being non-empty, because it
will legitimately be empty one day. It rests on planted violations instead
(below), and on `test_the_scanned_surface_is_not_only_dot_py`, which fails if
anyone re-narrows the surface to `.py` after the sites are gone.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from python_entrypoints import (
    ROOT,
    family_of,
    imports_of,
    is_python_source,
    python_sources,
)

KERNEL_DATABASE_MODULE = "dotmac_kernel.db"

#: Every site that imports `dotmac_kernel.db`, with the names it takes.
#: Measured 2026-09-05 against `origin/main` 74dab8a8. Eleven, including the
#: `.pyprogram` payload no `.py` glob could see.
KERNEL_DATABASE_IMPORTERS: dict[str, frozenset[str]] = {
    # The seven routers take the kernel's request-scoped platform session.
    "src/vendor_cp/accounts/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/allocations/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/approvals/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/contracts/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/licensing/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/offers/router.py": frozenset({"get_platform_db"}),
    "src/vendor_cp/readiness/router.py": frozenset({"get_platform_db"}),
    # Conflict handling, on the service side.
    "src/vendor_cp/release_evidence/service.py": frozenset({"conflict_savepoint"}),
    # Deferred into a function body: importing at module scope would build the
    # engine from `DATABASE_URL` merely to print `--help`.
    "src/vendor_cp/cli/runtime.py": frozenset({"platform_session"}),
    # The worker family, same deferral.
    "src/vendor_cp/relay/runner.py": frozenset({"runtime"}),
    # THE ELEVENTH. Not a `.py` file, and executed by the deployed
    # application's interpreter rather than this one.
    "src/vendor_cp/rotation_runtime_oracle.pyprogram": frozenset(
        {"SessionLocal", "PlatformSessionLocal", "engine", "platform_engine"}
    ),
}

#: A file that NAMES the module in prose and does not import it. Permanent
#: negative control: the census is parsed, and a paragraph is not a site.
PROSE_MENTION = "src/vendor_cp/cli/commands.py"

#: A real non-`.py` payload, in the scanned surface, importing a DIFFERENT
#: kernel module. Permanent negative control for the widened surface: widening
#: must not turn every payload into a hit.
NEAR_MISS_PAYLOAD = "src/vendor_cp/rotation_runtime_material_oracle.pyprogram"


def observed_importers() -> dict[str, frozenset[str]]:
    """Path -> names taken from `dotmac_kernel.db`, across every family."""

    found: dict[str, set[str]] = {}
    for path in python_sources():
        relative = path.relative_to(ROOT).as_posix()
        for module, name, _line in imports_of(path):
            if module == KERNEL_DATABASE_MODULE and name is not None:
                found.setdefault(relative, set()).add(name)
            elif module == KERNEL_DATABASE_MODULE and name is None:
                found.setdefault(relative, set()).add("<whole module>")
    return {relative: frozenset(names) for relative, names in found.items()}


def describe_sites(observed: dict[str, frozenset[str]]) -> list[str]:
    """`family path:line symbol` for every observed site, so a failure NAMES it.

    A guard that reports "a violation exists" sends the reader looking. Line and
    symbol are recomputed here rather than recorded, because a recorded line
    number goes stale on the first unrelated edit above it and a stale one sends
    the reader somewhere wrong, which is worse than sending them nowhere.
    """

    out: list[str] = []
    for relative in sorted(observed):
        for module, name, line in imports_of(ROOT / relative):
            if module == KERNEL_DATABASE_MODULE:
                out.append(
                    f"[{family_of(relative)}] {relative}:{line} "
                    f"{KERNEL_DATABASE_MODULE}.{name or '*'}"
                )
    return out


# ── the ratchet ─────────────────────────────────────────────────────────────


def test_the_kernel_database_importers_are_exactly_the_recorded_inventory() -> None:
    observed = observed_importers()

    appeared = sorted(set(observed) - set(KERNEL_DATABASE_IMPORTERS))
    vanished = sorted(set(KERNEL_DATABASE_IMPORTERS) - set(observed))
    changed = sorted(
        f"{relative}: recorded {sorted(KERNEL_DATABASE_IMPORTERS[relative])}, "
        f"found {sorted(observed[relative])}"
        for relative in set(observed) & set(KERNEL_DATABASE_IMPORTERS)
        if observed[relative] != KERNEL_DATABASE_IMPORTERS[relative]
    )

    assert not appeared, (
        f"a new `{KERNEL_DATABASE_MODULE}` importer appeared: {appeared}. This "
        "import is being retired, not extended. Sites now in the tree:\n  "
        + "\n  ".join(describe_sites(observed))
    )
    assert not vanished, (
        f"{vanished} no longer imports `{KERNEL_DATABASE_MODULE}` — which is "
        "the goal — but KERNEL_DATABASE_IMPORTERS still records it. Lower the "
        "inventory in the SAME change, so the census keeps describing the tree."
    )
    assert not changed, (
        "a recorded site now takes different names out of "
        f"`{KERNEL_DATABASE_MODULE}`. A swap keeps the count identical and is "
        f"exactly what a count-only ratchet cannot see: {changed}"
    )


def test_the_scanned_surface_is_not_only_dot_py() -> None:
    """The defect, held open after the sites are gone.

    When the eleven reach zero the inventory above legitimately becomes empty,
    and an empty equality passes for the wrong reason — including if someone
    narrows the surface back to `*.py`. This does not depend on any site
    existing: it asserts the SURFACE still contains a file the old glob missed.
    """

    scanned = {path.relative_to(ROOT).as_posix() for path in python_sources()}
    non_py = sorted(name for name in scanned if not name.endswith(".py"))
    assert non_py, (
        "the scanned surface is `.py` only again. A file executed by the "
        "product's interpreter is Python whatever it is named; that is the "
        "defect this guard was written for."
    )
    assert NEAR_MISS_PAYLOAD in scanned


# ── sensitivity: a planted violation, in a non-`.py` file ───────────────────


@pytest.fixture
def plant() -> Iterator[Callable[[str, str], Path]]:
    """Write a payload into the assembly family; remove it however the test ends."""

    created: list[Path] = []

    def make(name: str, body: str) -> Path:
        path = ROOT / "src" / "vendor_cp" / name
        path.write_text(body, encoding="utf-8")
        created.append(path)
        return path

    try:
        yield make
    finally:
        for path in created:
            path.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("name", "symbol"),
    [
        pytest.param("_sensitivity_probe.pyprogram", "platform_engine", id="pyprogram"),
        # The suffix is not the rule — the property is. A payload named
        # anything at all is covered on the day it lands.
        pytest.param("_sensitivity_probe.payload", "engine", id="unknown-suffix"),
        pytest.param("_sensitivity_probe.py", "SessionLocal", id="plain-python"),
    ],
)
def test_a_planted_importer_is_seen_and_named(
    plant: Callable[[str, str], Path], name: str, symbol: str
) -> None:
    """SENSITIVITY. A planted `.py` violation would prove nothing here: the
    defect is that a NON-`.py` payload was invisible. So the first two cases
    carry the weight, and the guard must name file, LINE and SYMBOL — not
    merely report that something somewhere is wrong."""

    path = plant(name, f"from {KERNEL_DATABASE_MODULE} import {symbol}\n")
    relative = path.relative_to(ROOT).as_posix()

    observed = observed_importers()
    assert relative in observed, (
        f"the census cannot see {relative}. That is the original defect: a file "
        "the product's interpreter executes, skipped because of its name."
    )
    assert observed[relative] == frozenset({symbol})

    described = describe_sites(observed)
    assert f"[assembly] {relative}:1 {KERNEL_DATABASE_MODULE}.{symbol}" in described, (
        "the failure must name the exact file, line and symbol; a reader who "
        f"has to go looking is why this was missed. Got: {described}"
    )


@pytest.mark.parametrize(
    ("name", "body"),
    [
        pytest.param(
            "_near_miss.pyprogram",
            "from dotmac_kernel.security import hash_token\n",
            id="different-kernel-module",
        ),
        pytest.param(
            "_near_miss.pyprogram",
            '"""Explains why `from dotmac_kernel.db import runtime` is deferred."""\n'
            "import json\n",
            id="prose-only",
        ),
        pytest.param(
            "_near_miss.pyprogram",
            "from dotmac_kernel.database import get_platform_db\n",
            id="similarly-named-module",
        ),
        pytest.param(
            "_near_miss.shprogram",
            "umask 077\nprintf 'from dotmac_kernel.db import engine'\n",
            id="not-python-at-all",
        ),
    ],
)
def test_a_near_miss_stays_silent(
    plant: Callable[[str, str], Path], name: str, body: str
) -> None:
    """The other half. A guard that fires on anything adjacent teaches its
    readers to widen the allowlist, and then it protects nothing."""

    path = plant(name, body)
    relative = path.relative_to(ROOT).as_posix()

    assert relative not in observed_importers()


# ── the permanent negative controls, in the real tree ───────────────────────


def test_the_prose_mention_is_not_counted_as_a_site() -> None:
    """PERMANENT NEGATIVE CONTROL. `cli/commands.py` explains, in a docstring,
    why the real import is deferred — and names the module to do it. A substring
    census counts that paragraph and reports a twelfth site that is not there."""

    text = (ROOT / PROSE_MENTION).read_text(encoding="utf-8")
    assert KERNEL_DATABASE_MODULE in text, (
        f"{PROSE_MENTION} no longer mentions `{KERNEL_DATABASE_MODULE}`, so it "
        "is no longer a control. Find another prose mention or delete this "
        "test — do not leave a control that controls nothing."
    )
    assert PROSE_MENTION not in observed_importers()


def test_the_other_payload_is_scanned_and_still_clean() -> None:
    """PERMANENT NEGATIVE CONTROL. The material oracle is a non-`.py` payload
    the widened surface DOES read. It imports `dotmac_kernel.security`, not the
    database — so it proves the widening is discriminating rather than
    indiscriminate."""

    path = ROOT / NEAR_MISS_PAYLOAD
    assert is_python_source(path), (
        f"{NEAR_MISS_PAYLOAD} is no longer recognised as Python source, so it "
        "is no longer a control for the widened surface."
    )
    modules = {module for module, _name, _line in imports_of(path)}
    assert "dotmac_kernel.security" in modules
    assert NEAR_MISS_PAYLOAD not in observed_importers()


def test_a_swapped_symbol_at_an_existing_site_is_named() -> None:
    """SENSITIVITY for the reason this is an inventory and not a count.

    Eleven sites before, eleven after — a count-only ratchet sees nothing. The
    site still imports `dotmac_kernel.db`; it just takes a different name out of
    it, which is a different dependency on the module being retired.
    """

    victim = ROOT / "src" / "vendor_cp" / "contracts" / "router.py"
    original = victim.read_text(encoding="utf-8")
    victim.write_text(
        original.replace(
            f"from {KERNEL_DATABASE_MODULE} import get_platform_db",
            f"from {KERNEL_DATABASE_MODULE} import platform_session",
        ),
        encoding="utf-8",
    )
    try:
        observed = observed_importers()
        assert len(observed) == len(KERNEL_DATABASE_IMPORTERS), (
            "the swap changed the COUNT, so this proves nothing about the "
            "inventory being paths-and-symbols rather than a number"
        )
        with pytest.raises(AssertionError, match=r"contracts/router\.py"):
            test_the_kernel_database_importers_are_exactly_the_recorded_inventory()
    finally:
        victim.write_text(original, encoding="utf-8")


def test_a_retired_site_is_named_until_the_inventory_is_lowered() -> None:
    """SENSITIVITY, the other direction. Reaching zero is the GOAL, and it still
    has to be a recorded step: a site that quietly disappears leaves a census
    that no longer describes the tree, which is how the count reached ten."""

    victim = ROOT / "src" / "vendor_cp" / "contracts" / "router.py"
    original = victim.read_text(encoding="utf-8")
    victim.write_text(
        original.replace(f"from {KERNEL_DATABASE_MODULE} import get_platform_db\n", ""),
        encoding="utf-8",
    )
    try:
        with pytest.raises(AssertionError, match=r"still records it"):
            test_the_kernel_database_importers_are_exactly_the_recorded_inventory()
    finally:
        victim.write_text(original, encoding="utf-8")
