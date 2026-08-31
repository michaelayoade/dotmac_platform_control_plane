"""The catalogue capture query, as package data.

It used to be `scripts/recovery/capture_catalog.sql`, reachable only from a
checkout — which meant the one host where a recovery matters was the one host
that could not run it without someone rsyncing a file there first. It ships
inside the wheel now and is read through `importlib.resources`, so it resolves
from wherever the distribution is installed and from nowhere else.

This module runs nothing. It emits SQL for an operator to feed to `psql`,
because a control plane that could execute an arbitrary catalogue read against
its own database is a capability nobody asked this CLI to have — and deny case
D1 keeps the connecting-entrypoint allowlist empty for exactly that reason.
"""

from __future__ import annotations

from importlib import resources
from typing import Final

#: The packaged file name. One place, so the resource lookup and any test that
#: checks the bytes cannot drift on which file they mean.
CAPTURE_FILE: Final[str] = "capture_catalog.sql"


def capture_sql() -> str:
    """The capture query's exact bytes, decoded as UTF-8."""
    return (
        resources.files("vendor_cp.recovery")
        .joinpath(CAPTURE_FILE)
        .read_text(encoding="utf-8")
    )


__all__ = ["CAPTURE_FILE", "capture_sql"]
