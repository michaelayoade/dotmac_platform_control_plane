"""The surface guards read is itself ratcheted, because the property is a
heuristic and says so.

`is_python_source` answers "do these bytes parse as a Python module that
declares or imports something". That is a real property and it is the right
question — but it is not an oracle. The five shell scripts under `scripts/` fail
to parse only because `umask 077` and `chmod 0600` are not valid Python integer
literals. A shell script written without a leading-zero literal could parse, and
would then be scanned as Python; a Python payload written as a single expression
would be skipped.

So the CLASSIFICATION is held, not just trusted. Every present, non-ignored file
under a Python entry-point family is either Python source (scanned) or an entry
in `NON_PYTHON_TRACKED_SOURCE` with the interpreter that runs it. A file in
neither fails, in both directions:

* a new file arrives and is neither -> fails. This is the half that matters:
  `rotation_runtime_oracle.pyprogram` was invisible for exactly as long as no
  check asked "what is this file, then?"
* a declared non-Python file disappears, or becomes parseable Python, without
  `NON_PYTHON_TRACKED_SOURCE` being edited in the same change -> fails. An
  exemption that outlives its subject is one the next author inherits without
  the argument that justified it.

"Grandfathered" is not "reviewed and correct": each entry names the interpreter
that actually executes it, and that claim is falsifiable by reading the file.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from python_entrypoints import (
    NON_PYTHON_TRACKED_SOURCE,
    PYTHON_ENTRYPOINT_FAMILIES,
    ROOT,
    candidate_source,
    family_of,
    is_python_source,
    python_sources,
)


@pytest.fixture
def plant() -> Iterator[Callable[[str, str], Path]]:
    created: list[Path] = []

    def make(relative: str, body: str) -> Path:
        path = ROOT / relative
        path.write_text(body, encoding="utf-8")
        created.append(path)
        return path

    try:
        yield make
    finally:
        for path in created:
            path.unlink(missing_ok=True)


def test_every_candidate_file_is_classified() -> None:
    """No file under a Python entry-point family is unclassified."""

    scanned = {path.relative_to(ROOT).as_posix() for path in python_sources()}
    declared = set(NON_PYTHON_TRACKED_SOURCE)

    unclassified = sorted(
        f"[{family_of(relative)}] {relative}"
        for relative in candidate_source()
        if relative not in scanned and relative not in declared
    )
    assert not unclassified, (
        "these files sit in a Python entry-point family and are neither read as "
        "Python source nor declared non-Python. Decide which, in this change — "
        "an unclassified file is an UNMONITORED region, and the last one was a "
        f"live `dotmac_kernel.db` importer: {unclassified}"
    )


def test_the_non_python_declarations_are_still_true() -> None:
    """Two directions. A declaration that no longer describes anything, and a
    declared non-Python file that has become Python, both fail here."""

    present = set(candidate_source())

    stale = sorted(set(NON_PYTHON_TRACKED_SOURCE) - present)
    assert not stale, (
        "NON_PYTHON_TRACKED_SOURCE names files that are gone. Remove them in "
        f"the change that removed the files: {stale}"
    )

    now_python = sorted(
        relative
        for relative in NON_PYTHON_TRACKED_SOURCE
        if is_python_source(ROOT / relative)
    )
    assert not now_python, (
        "these are declared to be run by something other than Python, and they "
        f"now parse as Python modules that import or declare something: "
        f"{now_python}. Either the declaration is wrong or the file is."
    )


def test_every_family_exists_and_is_reached() -> None:
    """A family that names nothing is a guard reporting coverage it lacks."""

    for family, prefix in PYTHON_ENTRYPOINT_FAMILIES:
        assert (ROOT / prefix).exists(), f"family `{family}` names missing {prefix}"
    reached = {family_of(relative) for relative in candidate_source()}
    missing = sorted({family for family, _ in PYTHON_ENTRYPOINT_FAMILIES} - reached)
    assert not missing, (
        f"no file was attributed to these families: {missing}. Either the "
        "surface moved or the enumeration is decorative."
    )
    assert "unattributed" not in reached


# ── sensitivity ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("relative", "body"),
    [
        pytest.param(
            "src/vendor_cp/_probe.pyprogram",
            "import json\n",
            id="python-payload-unknown-suffix",
        ),
        pytest.param(
            "scripts/_probe.shprogram",
            "cd /tmp && rm -f x\n",
            id="shell-payload",
        ),
        pytest.param(
            "alembic/_probe.sql",
            "CREATE TABLE t (id int);\n",
            id="sql-payload",
        ),
    ],
)
def test_an_unclassified_new_file_fails(
    plant: Callable[[str, str], Path], relative: str, body: str
) -> None:
    """SENSITIVITY. The Python payload must become SCANNED without anyone
    touching a list; the two non-Python payloads must land in the unclassified
    set, which is what forces a human to say what runs them."""

    plant(relative, body)

    scanned = {path.relative_to(ROOT).as_posix() for path in python_sources()}
    if is_python_source(ROOT / relative):
        assert relative in scanned, (
            "a Python payload with a suffix nobody listed must be scanned on "
            "the day it lands — that is the whole point of a property"
        )
        return

    unclassified = [
        candidate
        for candidate in candidate_source()
        if candidate not in scanned and candidate not in NON_PYTHON_TRACKED_SOURCE
    ]
    assert (
        relative in unclassified
    ), f"{relative} arrived and nothing asked what executes it"


def test_the_declaration_property_is_load_bearing(
    plant: Callable[[str, str], Path],
) -> None:
    """SENSITIVITY / NEAR-MISS. Parsing alone is not the property.

    A configuration fragment is valid Python (`key = "value"` is an assignment)
    and must NOT be read as source, or every `.toml` under a family becomes a
    file the guards claim to have checked. A payload that declares something is.
    """

    config = plant("src/vendor_cp/_probe_config.toml", 'name = "vendor"\n')
    assert not is_python_source(config)

    payload = plant("src/vendor_cp/_probe_code.payload", "import json\n")
    assert is_python_source(payload)


def test_the_real_tree_contains_a_non_py_python_payload() -> None:
    """NON-VACUITY. `test_every_candidate_file_is_classified` would pass over a
    tree with no payloads at all, and passed for years over a tree that had
    one. This fails if the widened surface stops actually widening anything."""

    scanned = {path.relative_to(ROOT).as_posix() for path in python_sources()}
    payloads = sorted(name for name in scanned if not name.endswith(".py"))
    assert payloads, (
        "no non-`.py` file is being read as Python source. If the payloads were "
        "genuinely retired, delete this test in that change and say so — do not "
        "leave a widened surface that widens nothing."
    )


# ── the one place that stays `.py`-scoped, and why ──────────────────────────

#: `scripts/kernel_floor.py::kernel_imports` scans `*.py` and is NOT widened.
#: This is UNMONITORED, not exempt, and the premise is stated and enforced
#: below rather than assumed.
#:
#: That function answers one question: which `dotmac_kernel.*` modules must the
#: kernel THIS composition installs provide? The `assembly-satisfied` verb in
#: the `kernel-pin` job turns its answer into a pass or a fail. A payload is
#: handed as text to ANOTHER application's interpreter, in another image, whose
#: kernel is not this pin — so its imports are not a requirement on this
#: assembly's kernel, and folding them in would make the pin answer for a
#: composition it does not own.
#:
#: THE ENFORCEABLE PREMISE: a payload is never imported by this assembly. It
#: cannot be, and `test_no_payload_is_imported_by_this_assembly` holds it — the
#: day one becomes an ordinary module, the premise fails here rather than
#: silently widening what the pin has to satisfy.
KERNEL_FLOOR_SCAN_IS_PY_SCOPED = "scripts/kernel_floor.py"

#: Declared exclusions from any PYTHON-import guard, with what runs each. Stated
#: because an unstated exclusion is the shape rule 23 refuses; `capture_catalog`
#: is SQL executed by PostgreSQL and `rotation_database_auth_oracle` is a shell
#: program executed by `sh` inside the label-selected database container, so
#: neither can carry a Python import at all.
NOT_A_PYTHON_IMPORT_SURFACE = (
    "src/vendor_cp/recovery/capture_catalog.sql",
    "src/vendor_cp/rotation_database_auth_oracle.shprogram",
)


def test_no_payload_is_imported_by_this_assembly() -> None:
    """The premise under the one `.py`-scoped kernel scan.

    Every payload is referenced by FILENAME and handed to another interpreter.
    If one were ever imported, its kernel imports would become this
    composition's requirement and `kernel_imports`' `.py` scope would start
    hiding a real obligation. That is the day this must fail.
    """

    payload_modules = {
        Path(path.relative_to(ROOT)).stem
        for path in python_sources()
        if not path.name.endswith(".py")
    } | {Path(relative).stem for relative in NOT_A_PYTHON_IMPORT_SURFACE}
    assert payload_modules, "there are no payloads, so this premise guards nothing"

    importers: list[str] = []
    for path in python_sources():
        if not path.name.endswith(".py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[-1] in payload_modules:
                    importers.append(
                        f"{path.relative_to(ROOT).as_posix()}:{node.lineno} -> {name}"
                    )
    assert not importers, (
        "a payload is imported as a module by this assembly, so its kernel "
        "imports are now this composition's requirement — and "
        f"`{KERNEL_FLOOR_SCAN_IS_PY_SCOPED}` scans `*.py` and cannot see them: "
        f"{importers}"
    )


def test_the_declared_non_python_import_surface_is_still_non_python() -> None:
    """A stated exclusion has to keep being true. Both files are declared as
    carrying no Python import because no Python interpreter reads them; if
    either became Python source the exclusion would be silently wrong."""

    for relative in NOT_A_PYTHON_IMPORT_SURFACE:
        path = ROOT / relative
        assert path.exists(), f"{relative} is gone; remove the declaration with it"
        assert not is_python_source(path), (
            f"{relative} now parses as Python source, and is declared to carry "
            "no Python import. One of the two is wrong."
        )
        assert relative in NON_PYTHON_TRACKED_SOURCE


def test_a_payload_turned_into_an_import_is_named(
    plant: Callable[[str, str], Path],
) -> None:
    """SENSITIVITY for the premise above. If it cannot see a payload becoming an
    ordinary import, it is a comment rather than a check."""

    plant(
        "src/vendor_cp/_premise_probe.py",
        "from vendor_cp.rotation_runtime_oracle import engine\n",
    )
    with pytest.raises(AssertionError, match=r"_premise_probe\.py:1"):
        test_no_payload_is_imported_by_this_assembly()


def test_an_ordinary_import_does_not_trip_the_premise(
    plant: Callable[[str, str], Path],
) -> None:
    """NEAR-MISS. The premise must fire on a payload becoming a module, not on
    every module whose name is vaguely adjacent."""

    plant(
        "src/vendor_cp/_premise_near_miss.py",
        "from vendor_cp.production_secrets import ROTATION_RUNTIME_ORACLE_PAYLOAD\n"
        "import json\n",
    )
    test_no_payload_is_imported_by_this_assembly()
