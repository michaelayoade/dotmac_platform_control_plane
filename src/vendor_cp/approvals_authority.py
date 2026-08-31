"""Who owns approvals here, and the mapping the adapter speaks through.

`dotmac-approvals` is the authority. `vendor_cp.approvals.adapter` is the only
seam Vendor speaks to it through, and the declarations it needs live here.

## The path actually taken was GREENFIELD

This file replaces the sealed-cutover contract that ADR-0004 originally
specified. That contract was correct for the situation it assumed — a running
system with real approval history to seal, compare and dispose of. Vendor CP
turned out not to be that system.

A direct authorized check against the designated sole target found
`TARGET_ABSENT`: no Compose `db` service and no data volume. There is no legacy
estate, so there was nothing to seal, nothing to compare and nothing to migrate —
and building parity machinery against an empty set would have been elaborate work
producing no information.

(A read-only inventory tool was built for this question and never ran. Its
contribution was refusing to report an absence it had not observed — see
ADR-0005.)

So the switch is a straight authority transfer, verified on the one fact that
makes it valid: the legacy tables are EMPTY, checked under lock in the same
transaction that drops them. If that check ever failed, nothing would happen at
all. See `alembic/versions/v013_approvals_authority_switch.py`.

What survives from the cutover design is the part that was about MAPPING rather
than about migration — the eligibility rule and the digest translation. Both were
written before there was any code to use them, and both are used unchanged by the
adapter, which is the whole reason for having declared them.

## Lifecycle

Composed and authoritative in code is **not** adopted. The new owner has not run
in production, so this assembly's approvals lifecycle stays below adopted until
it has.
"""

from __future__ import annotations

from typing import Final

from dotmac_kernel.migrations.catalog import (
    ROLE_TABLE_PRIVILEGES_SQL,
    TABLE_PRIVILEGES,
)

# ── The authority ───────────────────────────────────────────────────────────

#: Authoritative for approvals, as of the switch.
AUTHORITY: Final[str] = "dotmac_approvals"

#: The only Vendor module permitted to speak to it. Everything else goes through
#: this seam, so the mapping is reviewable in one place.
ADAPTER_MODULE: Final[str] = "vendor_cp.approvals.adapter"

#: The retired local writer. Its package is gone; the name is kept so the guard
#: that keeps its call sites at zero has something to look for.
RETIRED_LOCAL_WRITER: Final[str] = "vendor_cp.approvals.service"

#: Zero, and it stays zero. This was the cutover's retirement gate — "the legacy
#: `evaluate` has no remaining caller" — and it is now satisfied by the module
#: not existing. The ratchet is kept because a guard that only mattered until it
#: passed is a guard that stops mattering exactly when regressions become
#: invisible.
RETIRED_WRITER_CALL_SITES: Final[frozenset[str]] = frozenset()


# ── The eligibility mapping (assembly-owned, and now live) ──────────────────

#: Vendor's rule, in Vendor's own terms: `approvals/router.py` guards every
#: decision with `require_platform_admin`, so the rule is real — "any
#: authenticated platform admin may approve" — and coarse rather than absent.
COARSE_ELIGIBILITY_RULE: Final[str] = "any_authenticated_platform_admin"

#: The module's `ApprovalLevel.approver_kind` / `approver_id` are REQUIRED, and a
#: blank approver is refused, so the mapping cannot be left implicit. This
#: assembly therefore NAMES the role.
#:
#: Stable and arbitrary, in that order: it is not recovered from anywhere and does
#: not pretend to be. It must never change, because it is what the module's
#: eligibility check compares an actor's roles against.
PLATFORM_ADMIN_ROLE_ID: Final[str] = "6f1d2a7c-9b34-4f5e-8c21-0d7a5e3b41f9"

#: How a Vendor approver becomes a module `Actor`. Every approver holds the role
#: by construction: reaching a decision route at all means the guard passed.
ACTOR_MAPPING: Final[tuple[str, ...]] = (
    "actor_id := the acting PlatformAdmin id",
    f"role_ids := {{{PLATFORM_ADMIN_ROLE_ID}}}",
    "mfa_verified := False (never recorded; no level requires it)",
)


# ── Digest translation ──────────────────────────────────────────────────────

#: Vendor computes `hashlib.sha256(...).hexdigest()` — bare lowercase hex.
VENDOR_DIGEST_LENGTH: Final[int] = 64

#: The module requires `sha256:` + 64 lowercase hex, enforced by its own
#: `validate_digest`, which raises `ContentChanged` on anything else.
MODULE_DIGEST_PREFIX: Final[str] = "sha256:"

#: Every way a Vendor digest can fail to translate.
DIGEST_REJECTION_REASONS: Final[tuple[str, ...]] = (
    "empty",
    "already_prefixed",
    "wrong_length",
    "uppercase",
    "non_hex",
)

_HEX_LOWER: Final[frozenset[str]] = frozenset("0123456789abcdef")


def digest_rejection_reason(vendor_content_hash: str) -> str | None:
    """Why this digest cannot translate, or `None` when it can.

    FAIL CLOSED: every branch that is not a clean 64-character lowercase hex
    string returns a reason. There is no tolerant path, because a digest that
    needed repairing is a digest whose provenance is unknown.
    """
    if not vendor_content_hash:
        return "empty"
    if vendor_content_hash.startswith(MODULE_DIGEST_PREFIX):
        return "already_prefixed"
    if len(vendor_content_hash) != VENDOR_DIGEST_LENGTH:
        return "wrong_length"
    if any(character.isupper() for character in vendor_content_hash):
        return "uppercase"
    if any(character not in _HEX_LOWER for character in vendor_content_hash):
        return "non_hex"
    return None


#: The reverse direction, added when the deployment issuer arrived.
#:
#: `translate_digest` above exists because VENDOR computes bare hex and the
#: approvals module requires the prefixed form. Deployment Control computes the
#: PREFIXED form already — `plan_digest_of(snapshot).canonical` — so a plan
#: digest reaching the approvals seam is `already_prefixed`, which
#: `digest_rejection_reason` correctly refuses.
#:
#: That refusal is right and stays. What was missing is the declared way IN for
#: a value that is already canonical, and this is it. It is not a relaxation of
#: the rule: it is the same fail-closed shape running the other way, and it is
#: the ONLY place in this assembly that removes a `sha256:` prefix.
#:
#: It is emphatically not a normalizer. Deployment Control's own docstring warns
#: that "a consumer that normalizes has forked this parser, and the fork
#: surfaces as a false 'the plan changed'" — so the value handed BACK to that
#: module is always the untouched original. This function's output goes only to
#: the approvals seam.
#: The reverse direction's vocabulary, declared SEPARATELY rather than bolted
#: onto the tuple above. `DIGEST_REJECTION_REASONS` is the vendor -> module
#: alphabet, and `dotmac-commercial-agreements`' backfill imports it verbatim as
#: its own outcome set — so widening it to carry a reason only this direction
#: can produce would have silently widened a vocabulary two other owners hold
#: themselves to. Two directions, two alphabets, each reachable in full.
#:
#: `not_prefixed` is this direction's own. The remaining five are whatever the
#: shared checker returns on the stripped remainder, and all of them are
#: genuinely reachable: `sha256:sha256:...` produces `already_prefixed`, and a
#: bare `sha256:` produces `empty`.
MODULE_DIGEST_REJECTION_REASONS: Final[tuple[str, ...]] = (
    "not_prefixed",
    *DIGEST_REJECTION_REASONS,
)


def module_digest_rejection_reason(module_digest: str) -> str | None:
    """Why this canonical digest cannot be read, or `None` when it can."""
    if not module_digest:
        return "empty"
    if not module_digest.startswith(MODULE_DIGEST_PREFIX):
        return "not_prefixed"
    return digest_rejection_reason(module_digest[len(MODULE_DIGEST_PREFIX) :])


def bare_content_hash(module_digest: str) -> str:
    """`sha256:<64 lowercase hex>` -> `<64 lowercase hex>`, or raise.

    Fail-closed in exactly the way `translate_digest` is: an uppercase, short or
    unprefixed value is refused rather than repaired, because a digest that
    needed repairing is a digest whose provenance is unknown.
    """
    reason = module_digest_rejection_reason(module_digest)
    if reason is not None:
        raise ValueError(
            f"module digest is not translatable to a vendor content hash ({reason})"
        )
    return module_digest[len(MODULE_DIGEST_PREFIX) :]


def translate_digest(vendor_content_hash: str) -> str:
    """`<64 lowercase hex>` -> `sha256:<64 lowercase hex>`, or raise.

    Nothing is normalised on the way through: an uppercase or short value is not
    lowercased or padded into validity. Pure and dependency-free, so it is
    testable without a database and without the module.
    """
    reason = digest_rejection_reason(vendor_content_hash)
    if reason is not None:
        raise ValueError(
            f"content hash is not translatable to a module digest ({reason})"
        )
    return f"{MODULE_DIGEST_PREFIX}{vendor_content_hash}"


# ── Privileges ──────────────────────────────────────────────────────────────

#: IMPORTED from the kernel, never re-declared. `ROLE_TABLE_PRIVILEGES_SQL`
#: returns its answers POSITIONALLY in this order, so a local copy that drifted
#: by one position would mislabel privileges — reporting "DELETE is revoked"
#: while DELETE was granted.
ALL_TABLE_PRIVILEGES: Final[tuple[str, ...]] = TABLE_PRIVILEGES

#: The query that answers a privilege question — the kernel's, by import, so this
#: module and the composed live-catalogue audit cannot drift on what "granted"
#: means.
EFFECTIVE_PRIVILEGE_QUERY: Final[str] = ROLE_TABLE_PRIVILEGES_SQL


__all__ = [
    "ACTOR_MAPPING",
    "ADAPTER_MODULE",
    "ALL_TABLE_PRIVILEGES",
    "AUTHORITY",
    "COARSE_ELIGIBILITY_RULE",
    "DIGEST_REJECTION_REASONS",
    "MODULE_DIGEST_REJECTION_REASONS",
    "EFFECTIVE_PRIVILEGE_QUERY",
    "MODULE_DIGEST_PREFIX",
    "PLATFORM_ADMIN_ROLE_ID",
    "RETIRED_LOCAL_WRITER",
    "RETIRED_WRITER_CALL_SITES",
    "VENDOR_DIGEST_LENGTH",
    "bare_content_hash",
    "digest_rejection_reason",
    "module_digest_rejection_reason",
    "translate_digest",
]
