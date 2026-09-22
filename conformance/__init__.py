"""Conformance suite against the REAL dotmac_deployment_control and
dotmac_deployment_foundation packages.

Deliberately outside `tests/` (this repository's `pyproject.toml` pins
`testpaths = ["tests"]`), so it is never collected by a normal `pytest`
invocation in this repository. See `conformance/README.md` for how and when
to actually run it.
"""

from __future__ import annotations
