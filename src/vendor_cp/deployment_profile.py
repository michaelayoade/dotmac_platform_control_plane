"""Which SURFACES a deployment exposes — declared once, composed once.

A deployment profile here is a composition input, not a runtime switch. It is
read exactly once, in `assembly.build_spec()`, to decide which routers and
navigation entries each composed manifest contributes to the
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

## Every route-bearing composed module, not only the Vendor adapters (ADR-0019)

For its first three versions this module selected surfaces among the VENDOR
features and nothing else. `build_spec` filtered `assembly.VENDOR_SURFACES`
through the profile and spliced `assembly.STATEFUL_MODULES` in RAW, and the
completeness check compared a profile's `surface_inventory` against a
hand-written roster of vendor feature NAMES. A composed module's code could not
enter that roster's universe at all, so "a composed module mounts a surface no
profile declares" was not a case the guard could fail on — it was a case the
guard could not express.

That was survivable only while no composed module bore a route, which was true
by accident and is ending from four directions at once. `dotmac-release-catalog`,
`dotmac-entitlement-allocation`, `dotmac-commercial-agreements` and
`dotmac-approvals` each say in their own manifest prose that the release which
ships their routers is still ahead of them, and `dotmac-deployment-control` has
shipped an operator browser surface since `0.1.0a8` — four `platform_admin`
screens and two navigation entries, landing in the same facet and the same
sidebar as the console, which every production profile publishes. Pinning any
of those would have force-published an operator UI into
`production-composed-v1` with no line in any inventory and no test able to see
it.

So the roster is DERIVED. `route_bearing_codes` reads the composed manifests and
returns the codes that actually contribute routes; `admit_surfaces` compares a
profile's declared inventory against that. The repair is derivation rather than
a roster entry deliberately: a roster entry closes one omission, and the
omission is a class.

### What `bears_routes` reads, and the limit of the claim

`bears_routes` is duck-typed over the five route fields a manifest can carry —
`routers`, `api_routers`, `web_routers`, `nav`, `web_surfaces`. For the kernel
this assembly composes, that is EXACT rather than a proxy: `mount_features` and
`mount_web_surfaces` mount from those manifest fields and from nothing else, so
a manifest bearing none of them can mount nothing. It would stop being exact if
a kernel gained a route source outside the manifest, and the claim here is
scoped to the kernel — not to routing in general.

## What a profile may never do

A profile selects SURFACES. It may not drop a persistence owner: a module's
manifest, tables, prerequisites, audit vocabulary, migration prefix and branch
label survive withholding untouched, because withholding clears ROUTE FIELDS
and only route fields. That is the invariant, and it is now asserted directly
against a withheld route-bearing module rather than approximated by keeping
persistence owners out of the withheld set — see
`tests/architecture/test_deployment_profile.py`.

`NEVER_WITHHELD_SURFACES` is the one set still written by hand, and it holds one
name. `readiness` IS a route-bearing surface, so it could be withheld — and must
not be. A deployment whose readiness probe can be switched off is a deployment
that reports healthy while unable to serve, which is exactly the state
`docker compose up -d app --wait` used to accept. A probe with an off switch is
not a probe.

A surface that bears no route is absent from every inventory, and that absence
is derived rather than explained. `release_evidence` contributes declarations
and no router; an inventory says what a deployment PUBLISHES, and it publishes
nothing.

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

## Where each check lives, and why they are not in one place

`__post_init__` holds what a profile can be judged on ALONE: it has a rationale,
it does not list a surface twice, it does not both publish and withhold the same
name, and it does not pair the provisioning laboratory with a production claim.

`admit_surfaces` holds what needs the COMPOSITION, because a roster derived from
composed manifests cannot be reached from a dataclass literal — `assembly`
imports this module, so this module may not import `assembly`. It runs at boot,
inside `build_spec`, against the UNPROFILED manifest set: after profiling, a
withheld module bears no routes and would read as silent, which is the one thing
admission must not conclude on its own output.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum, auto
from typing import Final, Protocol

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

#: The route fields a manifest can carry, and — for the kernel this assembly
#: composes — the complete set of places a mounted route can come from. See the
#: module docstring for the scope of that claim.
#:
#: Both `routers` and `api_routers` appear because the two manifest generations
#: spell the same thing differently: a legacy `FeatureManifest` declares
#: `routers`, a contract-v2 `ModuleManifest` declares `api_routers` and exposes
#: `routers` as a read-only alias. Reading both is how one predicate covers both
#: shapes without asking which it was handed.
ROUTE_FIELDS: Final[tuple[str, ...]] = (
    "routers",
    "api_routers",
    "web_routers",
    "nav",
    "web_surfaces",
)

#: The surfaces no profile may withhold. One name, and it is the whole list.
#:
#: `readiness` is route-bearing, so derivation alone would make it withholdable.
#: A readiness probe a deployment can switch off is not a readiness probe — it is
#: a readiness probe plus a way back to the failure it exists to end, where
#: `docker compose up -d app --wait` was satisfied by a liveness route that never
#: touched the database.
NEVER_WITHHELD_SURFACES: Final[frozenset[str]] = frozenset({"readiness"})


class SurfaceManifest(Protocol):
    """The shape `admit_surfaces` needs, and no more.

    Deliberately not `ModuleManifest | FeatureManifest`: this module is imported
    BY the assembly and states the smallest contract that lets a manifest be
    admitted, so a planted probe in a test is admitted by exactly the code a real
    manifest is. Read-only, so it is satisfied by a legacy `FeatureManifest`'s
    dataclass field and by a contract-v2 `ModuleManifest`'s `code` alias alike.

    Not `@runtime_checkable`: nothing here uses `isinstance` against it, and a
    data protocol that advertised runtime checking would raise for the first
    caller who tried.
    """

    @property
    def name(self) -> str: ...


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


class AdmissionRefusal(Enum):
    """Why a profile was refused against a composition.

    Members carry `auto()` so a member value is never text, and callers assert
    the MEMBER rather than the message: this module refuses in four distinct
    ways, and a test matching prose would pass on the wrong one.
    """

    #: A composed manifest bears routes, the profile does not withhold it, and
    #: no line of its inventory names it. This is the defect ADR-0019 closes:
    #: a surface mounted in every profile that no profile ever declared.
    SURFACE_NOT_INVENTORIED = auto()

    #: An inventory names something this composition does not publish — an
    #: uncomposed code, a typo, or a manifest that bears no route at all. An
    #: inventory a reader trusts may not describe surfaces that do not exist.
    INVENTORY_NAMES_A_SILENT_SURFACE = auto()

    #: The profile withholds a surface `NEVER_WITHHELD_SURFACES` protects.
    WITHHOLDS_A_MANDATORY_SURFACE = auto()

    #: The profile withholds something that publishes nothing. Either a typo
    #: that silently withholds no route, or a declaration that changes nothing
    #: and will read to the next operator as though it did.
    WITHHOLDS_A_SILENT_SURFACE = auto()


class SurfaceAdmissionError(RuntimeError):
    """A declared profile does not describe the composition it was given.

    Carries the typed `refusal` and the exact `surfaces` at fault, so a caller
    can react to the KIND of disagreement without reading the sentence.
    """

    def __init__(
        self,
        refusal: AdmissionRefusal,
        surfaces: Iterable[str],
        message: str,
    ) -> None:
        super().__init__(message)
        self.refusal = refusal
        self.surfaces = tuple(surfaces)


def bears_routes(manifest: object) -> bool:
    """Does this manifest contribute at least one route or nav entry?

    Reads `ROUTE_FIELDS` and nothing else. `getattr` with a default rather than
    an isinstance ladder, because the two manifest generations carry different
    subsets of those names and a predicate that had to know which it was holding
    would be a third place that learns about a new manifest shape.
    """
    return any(tuple(getattr(manifest, field, ()) or ()) for field in ROUTE_FIELDS)


def route_bearing_codes(manifests: Iterable[SurfaceManifest]) -> frozenset[str]:
    """The surface roster, derived from the composition rather than declared."""
    return frozenset(manifest.name for manifest in manifests if bears_routes(manifest))


def withholdable_surfaces(manifests: Iterable[SurfaceManifest]) -> frozenset[str]:
    """What this composition allows a profile to withhold.

    Derived, so a module that starts shipping routes becomes withholdable in the
    same change that makes it publishable. The old hand-written allowlist failed
    silently in the direction that matters: a new route-bearing module was not on
    it, so it could not be withheld, so it was force-published everywhere.
    """
    return route_bearing_codes(manifests) - NEVER_WITHHELD_SURFACES


@dataclass(frozen=True, slots=True)
class VendorDeploymentProfile:
    """One declared composition.

    `version` is part of the contract: a profile whose effective surface set
    changes is a version bump, never a silent redefinition of a name someone
    already deployed.

    `surface_inventory` is the same fact stated positively. A withheld set says
    what a profile removes and is silent about everything added since it was
    written; the inventory says what a deployment PUBLISHES, and `admit_surfaces`
    checks it against the surfaces the composition actually bears, so a new
    route-bearing module — vendor feature or composed module — cannot join a
    production profile by simply existing.

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
        if not self.rationale.strip():
            raise ValueError(
                f"profile {self.code!r} needs a rationale: a withheld surface "
                "is a decision someone must be able to review and retire"
            )
        if len(set(self.surface_inventory)) != len(self.surface_inventory):
            raise ValueError(
                f"profile {self.code!r} lists a surface twice in its inventory"
            )
        contradiction = sorted(set(self.surface_inventory) & self.withheld_surfaces)
        if contradiction:
            raise ValueError(
                f"profile {self.code!r} both publishes and withholds "
                f"{contradiction} — the inventory and the withheld set are two "
                "statements of one composition, so they may not disagree"
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
        version="4",
        withheld_surfaces=frozenset(),
        surface_inventory=(
            "accounts",
            "allocations",
            "console",
            "contracts",
            "deployment_control",
            "licence_delivery",
            "offers",
            "provisioning",
            "readiness",
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
            "publishes and none may withhold. Version 4 adds "
            "`deployment_control`: pinning Control a12 composes the first module "
            "in this assembly that bears routes, and this profile's whole "
            "premise is that the tests exercise what the code actually offers — "
            "a surface withheld here would be a surface no test drives."
        ),
    ),
    VendorDeploymentProfile(
        code=PRODUCTION_BOOTSTRAP,
        version="4",
        withheld_surfaces=frozenset(
            {
                "deployment_control",
                "licence_delivery",
                "offers",
                "provisioning",
            }
        ),
        surface_inventory=(
            "accounts",
            "allocations",
            "console",
            "contracts",
            "readiness",
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
            "could not serve a single request. `deployment_control` arrives "
            "route-bearing with Control a12 and is WITHHELD here, at the same "
            "version: its surface carries `POST /deployments/{id}/plans`, which "
            "freezes a real execution plan, and the pin that composes it is "
            "explicitly not deployment authorization until the restored-database "
            "rehearsal is discharged. Publishing a plan-freezing route on the "
            "running host before that gate clears would let an operator author "
            "deployment intent through a path no rehearsal has covered. The "
            "version does not move because the EFFECTIVE surface set does not: "
            "nothing was mounted here before and nothing is mounted now, and a "
            "bump signalling a change nobody made would be its own kind of lie."
        ),
    ),
    VendorDeploymentProfile(
        code=PRODUCTION_COMPOSED_V1,
        version="2",
        withheld_surfaces=frozenset(
            {
                "accounts",
                "contracts",
                "deployment_control",
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
        ),
        laboratory=False,
        production_accepted=True,
        rationale=(
            "The target production composition. It publishes the platform-admin "
            "console and the read-only allocation view, and nothing else. Every "
            "withheld surface "
            "is withheld for a stated reason rather than by default: the "
            "provisioning laboratory simulates; offers and licence delivery "
            "wait on the complete browser and API evidence ADR-0015 requires "
            "before either is published; accounts, contracts and vendor "
            "approvals are operator WRITE surfaces whose production evidence is "
            "the empty estate recorded in the 2026-08-30 composition census, so "
            "publishing them now would create the first production data through "
            "a path nobody has exercised end to end. `deployment_control` is "
            "withheld on exactly that rule and not on a new one: its "
            "`POST /deployments/{id}/plans` freezes a real execution plan, which "
            "is operator WRITE, and the pin composing it states it is not "
            "deployment authorization until the restored-database rehearsal is "
            "discharged. Publishing it here would be the first production "
            "deployment intent authored through an unrehearsed path. The version "
            "does not move: this profile mounted nothing of Control's before and "
            "mounts nothing now, so the effective surface set is unchanged. The console is listed "
            "because ADR-0014 gave it exactly one browser authentication owner. "
            "The login path now WORKS, and that is a measured correction rather "
            "than a re-reading: this rationale used to say no session could be "
            "obtained because the assembly declared no form-parsing library and "
            "`POST /platform/login` could not read its own form. "
            "`python-multipart` is a main dependency, and the candidate "
            "acceptance battery drives that exact form login to a session that "
            "reaches `/platform/console` inside the built artifact "
            "(`.github/candidate/acceptance.sh` step 7; first observed green in "
            "release run 33474406793 at `2c9800d2`). Declared, not adopted: "
            "`scripts/deploy_production.sh` still pins `production-bootstrap`, "
            "and adoption remains an explicit operator action under ADR-0015 "
            "§ 6 — the blocker that sentence described is gone, and whether "
            "its removal is sufficient to adopt is not settled here. "
            "Version 2 adds the readiness surface, published "
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


def admit_surfaces(
    profile: VendorDeploymentProfile, manifests: Sequence[SurfaceManifest]
) -> None:
    """Refuse a profile that does not describe the composition it was handed.

    `manifests` is the UNPROFILED set — every manifest this assembly composes,
    with its routes still attached. Handing this the profiled output would ask
    admission to check a profile against its own effect, and every withheld
    surface would read as a module that publishes nothing.

    Four refusals, each with a typed `AdmissionRefusal`, ordered so the most
    specific misdeclaration is the one reported: withholding something protected,
    withholding something silent, publishing something uninventoried, and
    inventorying something unpublished.
    """
    route_bearing = route_bearing_codes(manifests)

    mandatory = sorted(profile.withheld_surfaces & NEVER_WITHHELD_SURFACES)
    if mandatory:
        raise SurfaceAdmissionError(
            AdmissionRefusal.WITHHOLDS_A_MANDATORY_SURFACE,
            mandatory,
            f"profile {profile.code!r} withholds {mandatory}, which no profile "
            "may withhold. A readiness probe a deployment can switch off is not "
            "a probe.",
        )

    silent_withheld = sorted(profile.withheld_surfaces - route_bearing)
    if silent_withheld:
        raise SurfaceAdmissionError(
            AdmissionRefusal.WITHHOLDS_A_SILENT_SURFACE,
            silent_withheld,
            f"profile {profile.code!r} withholds {silent_withheld}, which this "
            "composition does not publish. Either the name is a typo that "
            "withholds nothing, or it is a declaration that changes nothing and "
            f"reads as though it did. Composed and route-bearing: "
            f"{sorted(route_bearing)}.",
        )

    published = route_bearing - profile.withheld_surfaces
    inventory = set(profile.surface_inventory)

    uninventoried = sorted(published - inventory)
    if uninventoried:
        raise SurfaceAdmissionError(
            AdmissionRefusal.SURFACE_NOT_INVENTORIED,
            uninventoried,
            f"profile {profile.code!r} mounts {uninventoried} and its inventory "
            "does not name them. A surface mounted but not inventoried is a "
            "surface nobody decided to publish — say, per profile, whether this "
            "deployment publishes it, or add it to `withheld_surfaces` "
            "(ADR-0019).",
        )

    unpublished = sorted(inventory - published)
    if unpublished:
        raise SurfaceAdmissionError(
            AdmissionRefusal.INVENTORY_NAMES_A_SILENT_SURFACE,
            unpublished,
            f"profile {profile.code!r} inventories {unpublished}, which this "
            "composition does not publish. An inventory is what a reviewer "
            "reads, so it may not describe surfaces that do not exist. Composed "
            f"and route-bearing: {sorted(route_bearing)}.",
        )


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
    "NEVER_WITHHELD_SURFACES",
    "PRODUCTION_BOOTSTRAP",
    "PRODUCTION_COMPOSED_V1",
    "PRODUCTION_ENVIRONMENT",
    "PROFILES",
    "PROFILE_ENV_VAR",
    "PROVISIONING_SURFACE",
    "ROUTE_FIELDS",
    "AdmissionRefusal",
    "ProductionProfileRefusedError",
    "SurfaceAdmissionError",
    "SurfaceManifest",
    "UnknownDeploymentProfileError",
    "VendorDeploymentProfile",
    "admit_surfaces",
    "bears_routes",
    "deployment_profile",
    "is_production_environment",
    "load_deployment_profile",
    "route_bearing_codes",
    "withholdable_surfaces",
]
