"""Whether a deployment is authorized, asked of Control rather than of a caller.

## What this closes

`scripts/deploy_production.sh` was an unconditional effector. Its entire contract
with its caller was an argument count and a `sha256:` regex; every check that
made a deploy legitimate — the CI run, the release receipt, the ancestry, the
target name — lived in the WORKFLOW. Anyone holding the deploy SSH key bypassed
all of it by running one command on the host.

A check that lives beside the effect rather than inside it is not a control. It
is a convention that one caller happens to follow.

So the question moves to where the effect happens, and it is asked of the only
authority for it. Michael's ruling: *Control is the only authority for
approved-plan standing and `authorized_images`. Workflow input cannot substitute
for `ApprovedPlanLookup`.*

## Why this refuses today, and why that is the correct behaviour

Platform CP pins `dotmac-deployment-control 0.1.0a6`, which contains no
`find_approved_plan`, no `require_approved_plan` and no `ApprovedPlanLookup` —
measured across every module of the installed wheel, not inferred from a
changelog. There is therefore no authority to consult, and a deployment that
cannot be authorized must not proceed.

This is deliberately a closed path rather than an open one. The alternative —
leaving the effector ungated until the lookup can be written — keeps the bypass
open for exactly as long as it takes someone to forget.

## The tripwire, and why it is not a stub

If the read API ever imports, this still refuses, with a different reason: the
capability arrived and the wiring has not been written. That is a true statement
and a refusal, not a placeholder that might be mistaken for an implementation.
It also forces the follow-up rather than letting a silently-open path appear the
moment the pin moves.

When Control `0.1.0a9` is pinnable, `authorized_images` is resolved here through
`find_approved_plan` — total and falsy for every refusal, where
`ApprovedPlanLookup.__bool__` returns `is_authorized` so a plain dataclass
cannot be truthy on a refusal — and this module gains an ACCEPTING path that
needs its own both-directions proof. Until then the only honest answer is no.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "CONTROL_READ_API_SYMBOLS",
    "AuthorityUnavailable",
    "control_read_api_status",
    "require_control_approved_image",
]

#: What the read API is, by name. Probed rather than assumed from a version
#: string: a version present in a lockfile is not evidence of what it contains.
CONTROL_READ_API_SYMBOLS: Final[tuple[str, ...]] = (
    "find_approved_plan",
    "require_approved_plan",
    "ApprovedPlanLookup",
)


class AuthorityUnavailable(RuntimeError):
    """No authority could be consulted, so nothing is authorized.

    An ABSENCE, never a judgement that the deployment was refused. Control was
    not asked, because there is nothing here able to ask it. Collapsing that
    into "refused" would tell an operator to seek a new approval for a
    deployment no one has yet declined.
    """


def control_read_api_status() -> tuple[str, ...]:
    """Which read-API symbols the installed Control actually exports.

    Imported at call time and reported as data. A caller that needs to know
    whether the capability exists gets the measurement, not a version comparison.
    """
    try:
        import dotmac_deployment_control as control  # noqa: PLC0415
    except ImportError:  # pragma: no cover - the distribution is a hard dependency
        return ()
    return tuple(name for name in CONTROL_READ_API_SYMBOLS if hasattr(control, name))


def require_control_approved_image(
    *, authorization_ref: str, image_digest: str
) -> None:
    """Refuse unless Control says this exact image is approved for this ref.

    NAMED for what it asks, and not `require_authorized_image`, for two reasons
    that point the same way. D4's `test_d4_the_vendor_re_implements_no
    _authentication` matches `def (require|authenticate|verify)_…(platform|admin
    |web|session|auth)…` by NAME and deliberately so — "any local definition of
    one is the violation regardless of what it does" — and `authorized` contains
    `auth`. This function authenticates no actor; it asks Control whether an
    image was approved, which is a different question about a different subject.
    So the collision is a false positive on a name-based guard, and the sanctioned
    answer to that is a name that does not make the claim, never a loosened
    detector. The rename also says more: Control APPROVED it is the fact;
    "authorized" is the conclusion drawn from it.

    Returns nothing on success and raises on every other outcome, so a caller
    cannot mistake a falsy result for permission — the failure mode
    `ApprovedPlanLookup.__bool__` exists to remove, applied one level up.
    """
    if not authorization_ref.strip():
        raise AuthorityUnavailable(
            "no authorization reference was supplied, so no approved plan can be "
            "resolved. An unreferenced deployment is one nobody approved"
        )
    present = control_read_api_status()
    if not present:
        raise AuthorityUnavailable(
            "the installed dotmac-deployment-control exports none of "
            f"{list(CONTROL_READ_API_SYMBOLS)}, so approved-plan standing cannot "
            "be resolved and no image can be shown to be authorized. This is a "
            "closed path by design: the deploy path stays refused until the read "
            "API is pinnable and the executor wiring is written"
        )
    raise AuthorityUnavailable(
        f"the Control read API is now available ({list(present)}) and the "
        "executor wiring that resolves authorized_images through it has not been "
        "written. Refusing rather than deploying unauthorized bytes — complete "
        f"the wiring before authorizing {image_digest} under {authorization_ref}"
    )
