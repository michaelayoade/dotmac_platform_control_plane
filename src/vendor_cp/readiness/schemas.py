"""The probe's response shape — two fields, both closed.

`detail` is typed as a plain string on the wire but is only ever populated from
`ReadinessDetail`, which `tests/unit/test_readiness.py` holds to. The schema
does not import the enum as its annotation because a probe response that gained
new members with a library upgrade would change an operator's contract without
anyone editing this file.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReadinessResponse(BaseModel):
    """Ready or not, and the single word that says which."""

    ready: bool = Field(description="Whether every checked dependency answered")
    detail: str = Field(
        description=(
            "One member of the closed ReadinessDetail vocabulary. Never a "
            "driver message: an unauthenticated probe must not publish the "
            "database host, role or failure mode."
        )
    )
