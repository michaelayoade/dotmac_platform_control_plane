"""Which vendor SURFACES a deployment exposes — declared once, composed once.

A deployment profile here is a composition input, not a runtime switch. It is
read exactly once, in `assembly.build_spec()`, to decide which routers and
navigation entries each feature manifest contributes to the
`ProductAssemblySpec`. The manifest itself remains installed so declarations
and hooks do not disappear with a surface. Nothing downstream may read the
profile: ADR-0003 is explicit that profile names are conveniences over
independent axes and that feature code must never branch on one, and deny-case
D6 already fails the build if a commercial decision compares a mode or plan
string.

## Why a profile at all, and why now

Publishing an HTTP route is a commitment. The moment an external caller depends
on `POST /licences`, this assembly owns the adapter and delivery contract even
though the composed module owns issuer behavior. That operator surface should
be published deliberately, with its compatibility burden understood.

`licence_delivery` and `offers` are the two high-consequence operator surfaces
still withheld during production bootstrap. Licensing's issuer is now the
composed shared module; Vendor retains the route adapter, product-held signing
custody and delivery projection. Withholding a route never changes that
ownership.

So `production-bootstrap` withholds those two features' routers. It withholds
nothing else, and it disables no behaviour: the services, their tables, the
event-driven allocation staging and the signing key custody are all composed
and working. What is withheld is the public surface, which is the only part
that is expensive to take back.

## What a profile may never do

A profile selects SURFACES. It may not drop a persistence owner: Release
Catalog, Entitlement Allocation, Approvals, Commercial Agreements, Licensing,
Deployment Control, Billing and Subscriptions carry migration lineages and
schema ownership, so withholding one would mean an assembly whose database is
no longer described by its composition.
`withheld_surfaces` is validated against the surface-only feature names for
that reason, and the assembly test asserts all eight stateful modules survive
every profile.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

#: The one knob. Everything else about a profile is checked in, not configured.
PROFILE_ENV_VAR: Final[str] = "VENDOR_DEPLOYMENT_PROFILE"

FULL: Final[str] = "full"
PRODUCTION_BOOTSTRAP: Final[str] = "production-bootstrap"

#: Feature names a profile is allowed to withhold. A persistence owner is
#: deliberately absent: see the module docstring.
WITHHOLDABLE_SURFACES: Final[frozenset[str]] = frozenset(
    {"licence_delivery", "offers", "provisioning", "console"}
)


class UnknownDeploymentProfileError(RuntimeError):
    """A profile code was configured that this assembly does not declare.

    Fail closed rather than falling back to `full`: a typo'd profile silently
    exposing every surface in production is the failure this whole module
    exists to make impossible.
    """


@dataclass(frozen=True, slots=True)
class VendorDeploymentProfile:
    """One declared composition. `version` is part of the contract: a profile
    whose effective surface set changes is a version bump, never a silent
    redefinition of a name someone already deployed."""

    code: str
    version: str
    withheld_surfaces: frozenset[str]
    rationale: str

    def __post_init__(self) -> None:
        undeclared = self.withheld_surfaces - WITHHOLDABLE_SURFACES
        if undeclared:
            raise ValueError(
                f"profile {self.code!r} withholds {sorted(undeclared)}, which is "
                "not a surface-only feature — a profile selects surfaces and "
                "may never drop a persistence owner"
            )
        if not self.rationale.strip():
            raise ValueError(
                f"profile {self.code!r} needs a rationale: a withheld surface "
                "is a decision someone must be able to review and retire"
            )

    def exposes(self, feature_name: str) -> bool:
        return feature_name not in self.withheld_surfaces


PROFILES: Final[tuple[VendorDeploymentProfile, ...]] = (
    VendorDeploymentProfile(
        code=FULL,
        version="1",
        withheld_surfaces=frozenset(),
        rationale=(
            "Development, CI and the migration rehearsals compose every surface "
            "so the tests exercise what the code actually offers."
        ),
    ),
    VendorDeploymentProfile(
        code=PRODUCTION_BOOTSTRAP,
        version="2",
        withheld_surfaces=frozenset({"licence_delivery", "offers"}),
        rationale=(
            "Licence issuance/revocation is module-owned, while Vendor retains "
            "its high-consequence route and delivery surface. Priced offers "
            "remain Vendor-owned. Both behaviours run during bootstrap, but "
            "their operator routes are withheld until explicitly published."
        ),
    ),
)

_BY_CODE: Final[dict[str, VendorDeploymentProfile]] = {p.code: p for p in PROFILES}


def deployment_profile(code: str) -> VendorDeploymentProfile:
    """Resolve a declared profile, or fail closed naming the valid codes."""
    try:
        return _BY_CODE[code]
    except KeyError:
        raise UnknownDeploymentProfileError(
            f"{PROFILE_ENV_VAR}={code!r} is not a declared profile; "
            f"expected one of {sorted(_BY_CODE)}"
        ) from None


def load_deployment_profile() -> VendorDeploymentProfile:
    """The profile this process composes.

    Defaults to `full`, because a developer running the app locally should see
    the whole assembly. Production does not rely on that default: the deploy
    script requires the profile line in the host env file, so a production host
    that forgot it fails before the image starts rather than quietly serving
    every surface.
    """
    return deployment_profile(os.getenv(PROFILE_ENV_VAR, FULL).strip() or FULL)


__all__ = [
    "FULL",
    "PRODUCTION_BOOTSTRAP",
    "PROFILES",
    "PROFILE_ENV_VAR",
    "WITHHOLDABLE_SURFACES",
    "UnknownDeploymentProfileError",
    "VendorDeploymentProfile",
    "deployment_profile",
    "load_deployment_profile",
]
