"""Which vendor SURFACES a deployment exposes — declared once, composed once.

A deployment profile here is a composition input, not a runtime switch. It is
read exactly once, in `assembly.build_spec()`, to decide which routers and
navigation entries each feature manifest contributes to the
`ProductAssemblySpec`. The manifest itself remains installed so declarations
and hooks do not disappear with a surface. Nothing downstream may read the
profile: `dotmac_starter_mt` ADR-0003 is explicit that profile names are
conveniences over independent axes and that feature code must never branch on
one, and deny-case D6 already fails the build if a commercial decision compares
a mode or plan string.

## Why a profile at all, and why now

Publishing an HTTP route is a commitment. The moment an external caller depends
on `POST /licences`, this assembly owns the adapter and delivery contract even
though the composed module owns issuer behavior. That operator surface should
be published deliberately, with its compatibility burden understood.

## The provisioning laboratory is not a production surface (ADR-0015)

`vendor_cp.providers` builds ONE implementation of the kernel's provisioning
contract, and it is a side-effect-free simulation: `LaboratoryProvisioningProvider`
returns invented plans and pretends to apply them. `VENDOR_PROVIDER_MODE=fake`
is not a stub awaiting a real driver behind the same routes — it is the only
implementation that exists, and `validate_runtime_configuration` fails startup
for anything else.

So `POST /platform/vendor/provisioning/apply` on a production host answers an
operator with a fabricated result. Nothing warns them; the response shape is
the real one. `production-bootstrap` published exactly that, and calling it a
withheld-surface question would be generous: the surface was published, and
what it published was fiction.

Two rules now hold it closed, and they are deliberately separate:

* **Structural.** A profile that exposes `provisioning` must declare
  `laboratory=True`, and a laboratory profile can never be
  `production_accepted`. The pairing is checked at construction, so the
  combination cannot be written down at all.
* **Environmental.** `validate_profile_for_environment` REFUSES, at boot, a
  production environment whose effective profile mounts provisioning while the
  provider mode is `fake`. It names the provider mode rather than trusting the
  flag above, because the harm is the fake result reaching an operator — not
  the flag being mis-set.

The second check would be implied by the first today. It is written anyway:
the structural rule protects the profiles declared HERE, and the environmental
one protects the process actually booting.

## Production never falls back to `full`

`load_deployment_profile` defaults to `full` so a developer sees the whole
assembly. That default is fine everywhere except the one place it matters: a
production host that lost the `VENDOR_DEPLOYMENT_PROFILE` line would inherit
`full` and publish every withheld surface, including the provisioning
laboratory. `scripts/deploy_production.sh` greps for the line, but the grep
runs on the deploy path only — a container restarted by any other route never
sees it. So the loader itself refuses: in a production environment an unset or
blank profile is an error, not a default.

## What a profile may never do

A profile selects SURFACES. It may not drop a persistence owner: every module
in `assembly.STATEFUL_MODULES` carries a migration lineage and a schema this
database already contains, so withholding one would mean an assembly whose
database is no longer described by its composition. `withheld_surfaces` is
validated against the surface-only vendor feature names for that reason, and
`tests/architecture/test_deployment_profile.py` asserts, for every declared
profile, that each stateful module manifest is still registered AND that its
migration lineage head is still reachable in the composed revision graph.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

#: The one knob. Everything else about a profile is checked in, not configured.
PROFILE_ENV_VAR: Final[str] = "VENDOR_DEPLOYMENT_PROFILE"

#: The environment name that turns the refusals below on. Compared
#: case-insensitively against `ENVIRONMENT`, which `.env.production.example`
#: sets and `docker-compose.production.yml` passes through.
PRODUCTION_ENVIRONMENT: Final[str] = "production"

#: The provisioning provider mode that makes the laboratory a laboratory. It is
#: the ONLY mode `vendor_cp.config.validate_runtime_configuration` permits, so
#: naming it here is naming the simulation, not one branch of a driver.
FAKE_PROVIDER_MODE: Final[str] = "fake"

#: The surface whose exposure is a laboratory declaration.
PROVISIONING_SURFACE: Final[str] = "provisioning"

FULL: Final[str] = "full"
PRODUCTION_BOOTSTRAP: Final[str] = "production-bootstrap"
PRODUCTION_COMPOSED_V1: Final[str] = "production-composed-v1"

#: Every vendor surface this assembly composes, by manifest name. Declared here
#: rather than imported from `assembly` (which imports this module), and held in
#: sync by `test_the_surface_roster_matches_the_composed_assembly`. It exists so
#: a profile's `surface_inventory` can be checked for COMPLETENESS: adding a
#: tenth vendor feature fails every declared profile until someone says, per
#: profile, whether production publishes it.
VENDOR_SURFACE_CODES: Final[frozenset[str]] = frozenset(
    {
        "release_evidence",
        "readiness",
        "console",
        "accounts",
        "offers",
        "vendor_approvals",
        "contracts",
        "allocations",
        "licence_delivery",
        "provisioning",
    }
)

#: Surface names a profile is allowed to withhold. A persistence owner is
#: deliberately absent: see the module docstring. `release_evidence` is absent
#: for the opposite reason — it contributes no router at all, so "withholding"
#: it would be a declaration that changes nothing.
#:
#: `readiness` is absent for a third reason, and it is the interesting one. It
#: IS a route-bearing surface, so it could be withheld — and must not be. A
#: deployment whose readiness probe can be switched off is a deployment that
#: reports healthy while unable to serve, which is exactly the state
#: `docker compose up -d app --wait` used to accept. A probe with an off switch
#: is not a probe.
WITHHOLDABLE_SURFACES: Final[frozenset[str]] = frozenset(
    {
        "accounts",
        "console",
        "contracts",
        "licence_delivery",
        "offers",
        "provisioning",
        "vendor_approvals",
    }
)


class UnknownDeploymentProfileError(RuntimeError):
    """A profile code was configured that this assembly does not declare.

    Fail closed rather than falling back to `full`: a typo'd profile silently
    exposing every surface in production is the failure this whole module
    exists to make impossible.
    """


class ProductionProfileRefusedError(RuntimeError):
    """A production environment resolved a profile it may not run.

    Three ways to get here, all refusals rather than downgrades: the profile
    mounts the fake provisioning laboratory, the profile is not
    production-accepted, or no profile was configured at all and the `full`
    fallback would have applied.
    """


@dataclass(frozen=True, slots=True)
class VendorDeploymentProfile:
    """One declared composition.

    `version` is part of the contract: a profile whose effective surface set
    changes is a version bump, never a silent redefinition of a name someone
    already deployed.

    `surface_inventory` is the same fact stated positively. A withheld set says
    what a profile removes and is silent about everything added since it was
    written; the inventory says what a deployment PUBLISHES, and is checked
    against the full roster so a new vendor feature cannot join a production
    profile by simply existing.

    `laboratory` and `production_accepted` are the two halves of the
    provisioning rule and are mutually exclusive by construction.
    """

    code: str
    version: str
    withheld_surfaces: frozenset[str]
    surface_inventory: tuple[str, ...]
    laboratory: bool
    production_accepted: bool
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
        if len(set(self.surface_inventory)) != len(self.surface_inventory):
            raise ValueError(
                f"profile {self.code!r} lists a surface twice in its inventory"
            )
        expected = VENDOR_SURFACE_CODES - self.withheld_surfaces
        if set(self.surface_inventory) != expected:
            missing = sorted(expected - set(self.surface_inventory))
            extra = sorted(set(self.surface_inventory) - expected)
            raise ValueError(
                f"profile {self.code!r} has an inventory that does not describe "
                f"its own composition (unlisted: {missing}, not composed: "
                f"{extra}) — the inventory is what a reviewer reads, so it is "
                "required to be complete rather than indicative"
            )
        if self.exposes(PROVISIONING_SURFACE) and not self.laboratory:
            raise ValueError(
                f"profile {self.code!r} mounts the {PROVISIONING_SURFACE!r} "
                "surface, whose only implementation is a side-effect-free "
                "simulation — a profile that publishes it must declare "
                "laboratory=True (ADR-0015)"
            )
        if self.laboratory and self.production_accepted:
            raise ValueError(
                f"profile {self.code!r} is declared both a laboratory and "
                "production-accepted; a laboratory answers operators with "
                "fabricated results and is never accepted in production"
            )

    def exposes(self, feature_name: str) -> bool:
        return feature_name not in self.withheld_surfaces


PROFILES: Final[tuple[VendorDeploymentProfile, ...]] = (
    VendorDeploymentProfile(
        code=FULL,
        version="3",
        withheld_surfaces=frozenset(),
        surface_inventory=(
            "accounts",
            "allocations",
            "console",
            "contracts",
            "licence_delivery",
            "offers",
            "provisioning",
            "readiness",
            "release_evidence",
            "vendor_approvals",
        ),
        laboratory=True,
        production_accepted=False,
        rationale=(
            "Development, CI and the migration rehearsals compose every surface "
            "so the tests exercise what the code actually offers. That includes "
            "the fake provisioning laboratory, which is why this profile is "
            "declared a laboratory and can never be production-accepted. "
            "Version 3 adds the readiness surface, which every profile "
            "publishes and none may withhold."
        ),
    ),
    VendorDeploymentProfile(
        code=PRODUCTION_BOOTSTRAP,
        version="4",
        withheld_surfaces=frozenset({"licence_delivery", "offers", "provisioning"}),
        surface_inventory=(
            "accounts",
            "allocations",
            "console",
            "contracts",
            "readiness",
            "release_evidence",
            "vendor_approvals",
        ),
        laboratory=False,
        production_accepted=True,
        rationale=(
            "The deployed transitional profile. Licence issuance/revocation is "
            "module-owned, while Vendor retains its high-consequence route and "
            "delivery surface; priced offers remain Vendor-owned. Both "
            "behaviours run during bootstrap, but their operator routes are "
            "withheld until explicitly published. Version 3 additionally "
            "withholds the provisioning laboratory, which versions 1 and 2 "
            "published on the production host: its only implementation "
            "simulates, so every plan and apply an operator ran there returned "
            "a fabricated result (ADR-0015). Version 4 adds the readiness "
            "surface: until it existed, `docker compose up -d app --wait` was "
            "satisfied by a liveness route that does not touch the database, "
            "so a deploy could be declared successful while the application "
            "could not serve a single request."
        ),
    ),
    VendorDeploymentProfile(
        code=PRODUCTION_COMPOSED_V1,
        version="2",
        withheld_surfaces=frozenset(
            {
                "accounts",
                "contracts",
                "licence_delivery",
                "offers",
                "provisioning",
                "vendor_approvals",
            }
        ),
        surface_inventory=(
            "console",
            "allocations",
            "readiness",
            "release_evidence",
        ),
        laboratory=False,
        production_accepted=True,
        rationale=(
            "The target production composition. It publishes the platform-admin "
            "console, the read-only allocation view and the declarations-only "
            "release-evidence feature, and nothing else. Every withheld surface "
            "is withheld for a stated reason rather than by default: the "
            "provisioning laboratory simulates; offers and licence delivery "
            "wait on the complete browser and API evidence ADR-0015 requires "
            "before either is published; accounts, contracts and vendor "
            "approvals are operator WRITE surfaces whose production evidence is "
            "the empty estate recorded in the 2026-08-30 composition census, so "
            "publishing them now would create the first production data through "
            "a path nobody has exercised end to end. The console is listed "
            "because ADR-0014 gave it exactly one browser authentication owner "
            "— accepted, not yet usable: no session can currently be obtained, "
            "because the assembly declares no form-parsing library and "
            "`POST /platform/login` cannot read its own form. Declared, not "
            "adopted: `scripts/deploy_production.sh` still pins "
            "`production-bootstrap`, and adoption additionally requires a "
            "working login path and an explicit operator action "
            "(ADR-0015 § 6). Version 2 adds the readiness surface, published "
            "here for the same reason it is published everywhere: a "
            "dependency-aware probe is what makes a successful deploy mean the "
            "application can serve."
        ),
    ),
)

_BY_CODE: Final[dict[str, VendorDeploymentProfile]] = {p.code: p for p in PROFILES}


def is_production_environment(environment: str) -> bool:
    """One definition of "this is production", shared by both refusals."""
    return environment.strip().lower() == PRODUCTION_ENVIRONMENT


def deployment_profile(code: str) -> VendorDeploymentProfile:
    """Resolve a declared profile, or fail closed naming the valid codes."""
    try:
        return _BY_CODE[code]
    except KeyError:
        raise UnknownDeploymentProfileError(
            f"{PROFILE_ENV_VAR}={code!r} is not a declared profile; "
            f"expected one of {sorted(_BY_CODE)}"
        ) from None


def load_deployment_profile(
    *, environment: str | None = None
) -> VendorDeploymentProfile:
    """The profile this process composes.

    Defaults to `full` OUTSIDE production, because a developer running the app
    locally should see the whole assembly. Production has no default: an unset
    or blank profile there raises rather than inheriting a composition that
    publishes every withheld surface including the provisioning laboratory.
    """
    effective_environment = (
        os.getenv("ENVIRONMENT", "development") if environment is None else environment
    )
    configured = os.getenv(PROFILE_ENV_VAR, "").strip()
    if not configured:
        if is_production_environment(effective_environment):
            raise ProductionProfileRefusedError(
                f"{PROFILE_ENV_VAR} is unset in a production environment. There "
                f"is no fallback here: {FULL!r} publishes every withheld "
                "surface, including the fake provisioning laboratory, so an "
                "omitted profile fails the boot instead of choosing one."
            )
        return deployment_profile(FULL)
    return deployment_profile(configured)


def validate_profile_for_environment(
    profile: VendorDeploymentProfile, *, environment: str, provider_mode: str
) -> None:
    """Refuse, at boot, a production composition that must not run.

    The provisioning check is stated in terms of the PROVIDER MODE rather than
    the profile's `laboratory` flag. The flag is this module's own bookkeeping;
    the provider mode is what decides whether an operator calling
    `POST /platform/vendor/provisioning/apply` receives a real result or an
    invented one, and that is the harm being prevented.
    """
    if not is_production_environment(environment):
        return
    if (
        profile.exposes(PROVISIONING_SURFACE)
        and provider_mode.strip().lower() == FAKE_PROVIDER_MODE
    ):
        raise ProductionProfileRefusedError(
            f"profile {profile.code!r} mounts the {PROVISIONING_SURFACE!r} "
            f"surface while VENDOR_PROVIDER_MODE={provider_mode!r}: in "
            "production that publishes routes whose only implementation "
            "fabricates plans and applies. Withhold the surface or run a "
            "non-production environment (ADR-0015)."
        )
    if not profile.production_accepted:
        raise ProductionProfileRefusedError(
            f"profile {profile.code!r} is not production-accepted; production "
            f"runs one of {sorted(p.code for p in PROFILES if p.production_accepted)}"
        )


__all__ = [
    "FAKE_PROVIDER_MODE",
    "FULL",
    "PRODUCTION_BOOTSTRAP",
    "PRODUCTION_COMPOSED_V1",
    "PRODUCTION_ENVIRONMENT",
    "PROFILES",
    "PROFILE_ENV_VAR",
    "PROVISIONING_SURFACE",
    "ProductionProfileRefusedError",
    "UnknownDeploymentProfileError",
    "VENDOR_SURFACE_CODES",
    "VendorDeploymentProfile",
    "WITHHOLDABLE_SURFACES",
    "deployment_profile",
    "is_production_environment",
    "load_deployment_profile",
    "validate_profile_for_environment",
]
