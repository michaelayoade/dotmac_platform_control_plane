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
