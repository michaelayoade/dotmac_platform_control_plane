"""Canonical deployment-local identity for a reusable capability contract."""

from __future__ import annotations

import re

CAPABILITY_INSTANCE_REF_PATTERN = r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"
_CAPABILITY_INSTANCE_REF = re.compile(CAPABILITY_INSTANCE_REF_PATTERN, re.ASCII)


def is_capability_instance_ref(value: object) -> bool:
    """Return whether *value* is the exact cross-repository wire grammar."""

    return (
        isinstance(value, str)
        and 1 <= len(value) <= 200
        and value.isascii()
        and _CAPABILITY_INSTANCE_REF.fullmatch(value) is not None
    )


__all__ = ["CAPABILITY_INSTANCE_REF_PATTERN", "is_capability_instance_ref"]
