"""The five transformations, each returning a CATEGORY rather than a value.

Cadence, proration, currency, frozen content, product identity. Every function
here reads one source row and returns a member of that dimension's enum. None of
them returns a converted amount, a target identifier or a target date, and that
is the design rather than an omission: a dry-run planner that produced target
VALUES would be a backfill that had already happened in memory, and its report
could not honour the no-emission constraint without stripping them again.

Conversion belongs to whatever executes the backfill, under the authority that
owns the target. This module decides only whether a row CAN be converted, and
says exactly why when it cannot.

## Everything here is pure

No session, no clock, no environment. Given the same row these functions return
the same category forever, which is what lets the planner be replayed and
compared. The one import outside the standard library is the digest translation
rule, taken from `vendor_cp.approvals_authority` rather than restated — see
`frozen_content_outcome`.
"""

from __future__ import annotations

import calendar
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Final

from vendor_cp.approvals_authority import digest_rejection_reason
from vendor_cp.commercial_backfill.vocabulary import (
    CadenceOutcome,
    CurrencyOutcome,
    FrozenContentOutcome,
    ProductIdentityOutcome,
    ProrationOutcome,
)

# ── Product identity ───────────────────────────────────────────────────────

_PRODUCT_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def product_identity_outcome(
    product_code: str | None,
    *,
    sibling_product_codes: tuple[str, ...],
    declared_product_codes: frozenset[str],
) -> ProductIdentityOutcome:
    """Vendor's product-qualified identity, as read.

    Mirrors the two refusals already in the assembly rather than inventing a
    third: `vendor_cp.offers.service._require_product_code` refuses a blank or
    untrimmed code, and `vendor_cp.contracts.adapter._single_product` refuses an
    agreement naming more than one product.

    `declared_product_codes` is the configured product catalogue. Membership is
    EXACT — no case folding, no normalisation. `acme` and `ACME` are different
    identities and folding them together invents one that nobody published.
    """
    if product_code is None or not product_code:
        return ProductIdentityOutcome.CODE_ABSENT
    if product_code != product_code.strip() or not _PRODUCT_CODE.fullmatch(
        product_code
    ):
        return ProductIdentityOutcome.CODE_UNTRIMMED
    if len({product_code, *sibling_product_codes}) > 1:
        return ProductIdentityOutcome.MULTI_PRODUCT_AGREEMENT
    if product_code not in declared_product_codes:
        return ProductIdentityOutcome.CODE_UNDECLARED
    return ProductIdentityOutcome.QUALIFIED


# ── Currency ───────────────────────────────────────────────────────────────

#: ISO-4217 minor-unit exponents, declared for the currencies this cohort may
#: contain. FAIL CLOSED on anything else: an unknown code is `CODE_UNKNOWN`
#: rather than "assume two decimals", because the assumption is wrong for JPY in
#: one direction and for KWD in the other, and both are wrong by a factor of a
#: hundred or a thousand.
CURRENCY_MINOR_UNITS: Final[dict[str, int]] = {
    "NGN": 2,
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
    "ZAR": 2,
    "GHS": 2,
    "KES": 2,
    "CAD": 2,
    "AUD": 2,
    "CHF": 2,
    "ZMW": 2,
    # Zero-decimal.
    "JPY": 0,
    "KRW": 0,
    "XOF": 0,
    "XAF": 0,
    "RWF": 0,
    "UGX": 0,
    "VND": 0,
    "CLP": 0,
    "ISK": 0,
    # Three-decimal.
    "BHD": 3,
    "IQD": 3,
    "JOD": 3,
    "KWD": 3,
    "LYD": 3,
    "OMR": 3,
    "TND": 3,
}

#: A plain decimal string. No sign prefix, no exponent, no thousands separator,
#: no whitespace. `1E+2` and `+10.00` are `NOT_DECIMAL`: both parse under
#: `Decimal` and neither is what was stored, and accepting a spelling the writer
#: never produced means accepting one some other writer did.
_PLAIN_DECIMAL = re.compile(r"-?\d+(\.\d+)?")


def currency_outcome(
    amount: str,
    currency_code: str,
    *,
    sibling_currency_codes: tuple[str, ...] = (),
) -> CurrencyOutcome:
    """Exact money, or a refusal — never a rounding.

    `NOT_QUANTIZED` blocks rather than repairs. Quantizing an over-precise
    amount here would invent money silently, across the whole cohort, in a run
    whose entire output is counts.

    A zero amount is `EXACT_ZERO_AMOUNT` rather than `EXACT` so it is visible: a
    cohort with unexpected zero-price lines is a cohort worth looking at again
    before it becomes the target's opening balance.
    """
    if currency_code not in CURRENCY_MINOR_UNITS:
        return CurrencyOutcome.CODE_UNKNOWN
    if len({currency_code, *sibling_currency_codes}) > 1:
        return CurrencyOutcome.MIXED_CURRENCY_AGREEMENT
    if not _PLAIN_DECIMAL.fullmatch(amount):
        return CurrencyOutcome.NOT_DECIMAL
    try:
        value = Decimal(amount)
    except InvalidOperation:  # pragma: no cover - the regex already refused it
        return CurrencyOutcome.NOT_DECIMAL
    if value < 0:
        return CurrencyOutcome.NEGATIVE
    exponent = CURRENCY_MINOR_UNITS[currency_code]
    fractional_digits = len(amount.split(".")[1]) if "." in amount else 0
    if fractional_digits != exponent:
        return CurrencyOutcome.NOT_QUANTIZED
    if value == 0:
        return CurrencyOutcome.EXACT_ZERO_AMOUNT
    return CurrencyOutcome.EXACT


# ── Cadence ────────────────────────────────────────────────────────────────

#: Whole-month term lengths the target has a cadence for. A term of 2, 4 or 24
#: months is INDETERMINATE rather than folded into the nearest cadence: the
#: number of periods a term becomes is the target's decision, and a 24-month
#: term silently backfilled as ANNUAL is a contract billed twice.
CADENCE_BY_WHOLE_MONTHS: Final[dict[int, CadenceOutcome]] = {
    1: CadenceOutcome.MONTHLY,
    3: CadenceOutcome.QUARTERLY,
    6: CadenceOutcome.SEMI_ANNUAL,
    12: CadenceOutcome.ANNUAL,
}

#: How far out to look for a whole-month match. Beyond this a term is
#: INDETERMINATE anyway, since nothing above 12 is in the table.
_MAX_MONTHS: Final[int] = 24


def add_months(anchor: date, months: int) -> date:
    """Calendar month addition, clamping the day to the target month's length.

    31 January plus one month is 28 (or 29) February — the same clamping every
    billing system does, stated here rather than depending on one. It is why
    `whole_months` searches for a match instead of dividing: clamping is not
    invertible, and dividing a day count by 30 turns February into a rounding
    error.
    """
    total = anchor.month - 1 + months
    year = anchor.year + total // 12
    month = total % 12 + 1
    day = min(anchor.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def whole_months(start: date, exclusive_end: date) -> int | None:
    """`n` where `add_months(start, n) == exclusive_end`, or `None`."""
    for months in range(1, _MAX_MONTHS + 1):
        if add_months(start, months) == exclusive_end:
            return months
    return None


def cadence_outcome(
    term_start: date | None,
    term_end_exclusive: date | None,
) -> CadenceOutcome:
    """Derive cadence from an already-normalized end-exclusive term.

    Vendor stores a whole-period price and no recurrence at all, so cadence is
    not carried — it is DERIVED, and only where the derivation is exact. A term
    that is not a whole number of months, or is a whole number the target has no
    cadence for, is `INDETERMINATE`. Inclusive Vendor expiry is translated once
    by ``vendor_cp.contracts.adapter``; this function has no convention switch
    and therefore cannot apply that translation twice.
    """
    if term_start is None or term_end_exclusive is None:
        return CadenceOutcome.TERM_OPEN_ENDED
    if term_end_exclusive <= term_start:
        return CadenceOutcome.TERM_NOT_POSITIVE
    months = whole_months(term_start, term_end_exclusive)
    if months is None:
        return CadenceOutcome.INDETERMINATE
    return CADENCE_BY_WHOLE_MONTHS.get(months, CadenceOutcome.INDETERMINATE)


# ── Proration ──────────────────────────────────────────────────────────────

#: The highest day-of-month every month has. A term anchored on 29, 30 or 31
#: cannot repeat its own anchor in every month of the year, so the target's
#: clamping and proration policy decides what the short period costs.
LAST_UNIVERSAL_DAY: Final[int] = 28


def proration_outcome(
    term_start: date | None, cadence: CadenceOutcome
) -> ProrationOutcome:
    """Whether the target will have to apply its own proration policy.

    **The backfill carries no proration.** Vendor has no proration concept to
    carry: it holds one whole-period price. What this dimension records is
    whether the target is going to face a short first period, which is a fact
    its owner needs BEFORE the cutover rather than in the first invoice run.

    `ANCHOR_INDETERMINATE` follows a blocking cadence, because a period boundary
    cannot be placed without a period length. It is a blocker in its own right
    so the report shows how many rows are affected by the cadence problem
    downstream, not just how many rows have it.
    """
    if term_start is None or cadence not in CADENCE_BY_WHOLE_MONTHS.values():
        return ProrationOutcome.ANCHOR_INDETERMINATE
    if term_start.day > LAST_UNIVERSAL_DAY:
        return ProrationOutcome.TARGET_OWNED_MISALIGNED
    return ProrationOutcome.NONE_REQUIRED


# ── Frozen content ─────────────────────────────────────────────────────────

#: The approvals module's digest-rejection vocabulary, mapped one for one onto
#: this dimension's categories. IMPORTED rather than restated: `translate_digest`
#: is the assembly's one opinion about what a content digest is, and a second
#: opinion here would drift from it in exactly the way that rule exists to stop.
DIGEST_REJECTION_OUTCOMES: Final[dict[str, FrozenContentOutcome]] = {
    "empty": FrozenContentOutcome.DIGEST_EMPTY,
    "already_prefixed": FrozenContentOutcome.DIGEST_ALREADY_PREFIXED,
    "wrong_length": FrozenContentOutcome.DIGEST_WRONG_LENGTH,
    "uppercase": FrozenContentOutcome.DIGEST_UPPERCASE,
    "non_hex": FrozenContentOutcome.DIGEST_NON_HEX,
}


def frozen_content_outcome(
    content_hash: str | None, activation_content_hash: str | None
) -> FrozenContentOutcome:
    """The frozen snapshot, and whether its digest can travel to the target.

    Two separate questions, and both must hold:

    * the agreement HAS a frozen snapshot — `content_hash` is set at propose,
      and an agreement without one was never content-bound;
    * the snapshot the activation event bound to is still the CURRENT one. This
      is `vendor_cp.contracts.adapter.active_snapshot`'s stale-event rule,
      applied to a whole cohort instead of one delivery. A row that fails it is
      carrying an approval for content that has since changed.
    """
    if content_hash is None or not content_hash:
        return FrozenContentOutcome.NOT_FROZEN
    reason = digest_rejection_reason(content_hash)
    if reason is not None:
        return DIGEST_REJECTION_OUTCOMES[reason]
    if activation_content_hash is not None and activation_content_hash != content_hash:
        return FrozenContentOutcome.STALE_AGAINST_ACTIVATION
    return FrozenContentOutcome.TRANSLATABLE


__all__ = [
    "CADENCE_BY_WHOLE_MONTHS",
    "CURRENCY_MINOR_UNITS",
    "DIGEST_REJECTION_OUTCOMES",
    "LAST_UNIVERSAL_DAY",
    "add_months",
    "cadence_outcome",
    "currency_outcome",
    "frozen_content_outcome",
    "product_identity_outcome",
    "proration_outcome",
    "whole_months",
]
