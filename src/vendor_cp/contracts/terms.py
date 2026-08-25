"""Vendor's one commercial term-boundary translation.

Commercial Agreements publishes ``expiry_date`` as the last covered day: its
expiry transition is refused while ``as_of <= expiry_date``. Composed
commercial consumers use an end-exclusive contract instead, where the end is
the first uncovered day. Translate at the Vendor adapter boundary once; source
rows, reports and downstream APIs must not carry a second convention switch.
"""

from __future__ import annotations

from datetime import date


class TermEndNotRepresentable(ValueError):
    """An inclusive end has no representable following ``date``."""


def end_exclusive_from_inclusive(end_inclusive: date) -> date:
    """Return the first uncovered day for an inclusive Vendor term end."""
    try:
        return date.fromordinal(end_inclusive.toordinal() + 1)
    except ValueError as exc:
        raise TermEndNotRepresentable(
            "the inclusive term end has no representable exclusive successor"
        ) from exc


__all__ = ["TermEndNotRepresentable", "end_exclusive_from_inclusive"]
