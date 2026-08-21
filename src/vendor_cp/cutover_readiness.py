"""What the next two cutovers need, declared before either of them is taken.

ADR-0007 sequences the remaining recompositions: Deployment Control, then the
ADR-0010 licence-delivery transfer to Dotmac Integrator, then Brand Profiles'
platform plane. ADR-0011 contracts the first. This module is the
machine-readable half of that preparation, held to the repository by
`tests/architecture/test_cutover_readiness.py`.

## The rule these declarations are written under

Fleet rule, approved 2026-08-21, and `AGENTS.md` rule 17:

    Repository-local transition claims must be derived from repository-local
    facts. Release, registry and production-adoption claims require an
    authoritative external oracle.

Everything declared below is the first kind. A test here can prove which tables
this assembly's models declare, which symbols reference which files, and what
appears in `pyproject.toml`. It cannot observe a registry tag, another product's
cutover, or a row in a production database, so nothing here is named as if it
could.

`DEFERRED_BY_LOCAL_DECISION` records a decision THIS repository took and can
hold itself to. It deliberately does NOT encode "dotmac_sub has not adopted yet"
— an absence describes a moment, and that one is about a repository this code
cannot see. `TARGET_ESTATE_MEASUREMENT` names an obligation discharged by an
operator against a target Michael names explicitly, and says so rather than
pretending a unit test discharges it. The release and adoption claims that
belong to this work live in `docs/cutover-readiness.md`, each beside its oracle
with an exact commit, run id or peeled tag commit.

Proposed fleet-wide as `dotmac_governance` ADR 0013, which defines the typed
oracle kinds. That record is `Proposed` and not yet normative.

An earlier draft of this module declared `AWAITING_RELEASE_TAG` and described it
as gating on a release tag. It read `pyproject.toml` and nothing else, so the
tag was published and it stayed green. It is deleted, not reworded.

## The subject overlap this module exists to keep visible

Deployment Control is a greenfield composition for plans, rollouts, credentials
and observations — none of which has ever had a Vendor owner. It is NOT
greenfield for deployment-target identity. `register_delivery_target` is a named
authority over that subject today: it holds the ref, customer, connection and
status, enforces the customer-repointing invariant, and writes two audit
actions. Its own docstring already anticipates becoming a subscriber rather than
a source of truth.

That half is an authority cutover, and it is inventoried at SYMBOL level below
rather than by file. A path-level ledger would stay green if
`register_delivery_target` were deleted while `projection.py` remained, which is
exactly the transition that needs catching.
"""

from __future__ import annotations

from typing import Final

# ── Composition decisions this repository has taken ────────────────────────

#: Distributions this assembly deliberately leaves unpinned, and the reason,
#: which is a decision recorded HERE rather than a fact measured elsewhere.
#:
#: `dotmac-brand-profiles` 0.1.0a1 is tagged and installable. ADR-0007 § 6 keeps
#: this assembly second behind the extraction dossier's named first adopter, and
#: reversing that order needs an amendment at the extraction source. Nothing in
#: this repository can observe whether that adopter has finished; what this
#: entry holds is that Vendor has not unilaterally decided it has.
DEFERRED_BY_LOCAL_DECISION: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "dotmac-brand-profiles",
        "ADR-0007 § 6",
        "deferred behind the extraction dossier's named first adopter "
        "(dotmac_sub); the adoption evidence lives in that dossier and is not "
        "observable from this repository",
    ),
)

# ── What this assembly still owns in `public` ───────────────────────────────

#: Every table a Vendor model still declares, after the v013–v016 authority
#: switches. Derived by scanning `__tablename__` in `src/`, and asserted in both
#: directions: a table cannot be added or removed without this list moving.
VENDOR_OWNED_TABLES: Final[frozenset[str]] = frozenset(
    {
        "vendor_accounts",
        "offer_versions",
        "licence_deliveries",
        "licence_delivery_states",
        "licence_delivery_targets",
        "licence_delivery_attempts",
        "licence_ack_records",
    }
)

#: The five ADR-0010 names in its retirement definition. They are a strict
#: subset of the above, and the delivery cutover empties them from it.
DELIVERY_ESTATE: Final[frozenset[str]] = frozenset(
    {
        "licence_deliveries",
        "licence_delivery_states",
        "licence_delivery_targets",
        "licence_delivery_attempts",
        "licence_ack_records",
    }
)

#: Substrings that would mean this assembly had grown a table belonging to an
#: independent module. `deployment`/`rollout` are Deployment Control's
#: (`mod_deploy`); `brand` is Brand Profiles' (`mod_brand`).
#:
#: `target` is deliberately NOT in this list. `licence_delivery_targets` is not
#: a near miss to be waved through — it is a real second authority over
#: Deployment Control's subject, and it is inventoried as one below rather than
#: grandfathered here. A marker list is the wrong instrument for a fact that
#: needs a migration.
FOREIGN_TABLE_MARKERS: Final[tuple[str, ...]] = (
    "deployment",
    "fleet",
    "rollout",
    "brand",
    "theme",
)

# ── The deployment-target authority, after the cutover ─────────────────────

#: RETIRED by ADR-0011, and ratcheted at ZERO. These are the symbols that made
#: `licence_delivery_targets` a second authority over deployment-target
#: identity: each took `target_ref`, `customer_ref`, `connection_ref` and
#: `status` from its caller.
#:
#: Zero call sites, asserted — not "the file is gone". Deleting
#: `register_delivery_target` while `projection.py` survives is exactly the
#: transition a path-level ledger misses, and `projection.py` survives here
#: because it still owns the projection.
RETIRED_TARGET_AUTHORITY_SYMBOLS: Final[tuple[str, ...]] = (
    "register_delivery_target",
    "RegisterTargetCommand",
    "RegisterTargetRequest",
)

#: The replacement seam, and the reason the ratchet above can be zero without
#: the delivery path breaking. `DeploymentTargetFacts` is constructible only in
#: `vendor_cp.deployment.adapter`, from a record `mod_deploy` returned, so the
#: projection's values carry a provenance the type system enforces.
#:
#: This is the single-writer guarantee, and it is WEAKER than a grant: ADR-0011
#: § 4 keeps `INSERT`/`UPDATE` with `platform_api` because the reconciler needs
#: them. Only `DELETE` is revoked. Recorded plainly rather than described as a
#: seal it is not.
TARGET_RECONCILIATION_SYMBOLS: Final[dict[str, dict[str, int]]] = {
    "DeploymentTargetFacts": {
        "src/vendor_cp/deployment/adapter.py": 5,
        "src/vendor_cp/licensing/projection.py": 3,
        "tests/unit/test_licence_delivery.py": 3,
    },
    "resolve_target": {
        "src/vendor_cp/deployment/adapter.py": 3,
        "src/vendor_cp/licensing/router.py": 1,
        "tests/unit/test_licence_delivery.py": 2,
    },
    "reconcile_delivery_target": {
        "src/vendor_cp/deployment/adapter.py": 1,
        "src/vendor_cp/licensing/router.py": 1,
        "src/vendor_cp/licensing/projection.py": 2,
        "tests/unit/test_licence_delivery.py": 3,
    },
    "ReconcileTargetRequest": {
        "src/vendor_cp/licensing/schemas.py": 2,
        "src/vendor_cp/licensing/router.py": 2,
    },
}

#: The READ and projection path. It survives as a rebuildable projection
#: reconciled from `mod_deploy`, and retires with the rest of the delivery
#: estate at ADR-0010.
TARGET_PROJECTION_SYMBOLS: Final[dict[str, dict[str, int]]] = {
    "list_delivery_targets": {
        "src/vendor_cp/licensing/router.py": 1,
        "src/vendor_cp/licensing/projection.py": 2,
        "tests/unit/test_licence_delivery.py": 1,
    },
    "_authorised_target": {
        "src/vendor_cp/deployment/adapter.py": 1,
        "src/vendor_cp/licensing/projection.py": 4,
    },
    "DeliveryTargetResponse": {
        "src/vendor_cp/licensing/schemas.py": 2,
        "src/vendor_cp/licensing/router.py": 7,
    },
    "LicenceDeliveryTarget": {
        "src/vendor_cp/licensing/delivery_models.py": 2,
        "src/vendor_cp/licensing/projection.py": 11,
        "tests/unit/test_licence_delivery.py": 4,
        "tests/unit/test_licence_transport_ops.py": 4,
    },
    "TargetStatus": {
        "src/vendor_cp/deployment/adapter.py": 8,
        "src/vendor_cp/licensing/delivery_models.py": 3,
        "src/vendor_cp/licensing/projection.py": 2,
        "tests/unit/test_licence_delivery.py": 5,
    },
}

#: The declared platform-audit vocabulary the reconciler owns. ONE code replaced
#: the registrar's two: `registered` and `updated` distinguished create from
#: update on a caller's claim, and a reconciliation against an authority that
#: already decided has no such difference to name.
TARGET_RECONCILIATION_AUDIT_ACTION: Final[str] = (
    "vendor.licence.delivery_target_reconciled"
)

#: Retired with the writer. ADR-0008's every-declared-code-has-a-consumer rule
#: means these had to go in the same change, or the boot would fail on a
#: declaration nothing writes.
RETIRED_AUDIT_ACTIONS: Final[tuple[str, ...]] = (
    "vendor.licence.delivery_target_registered",
    "vendor.licence.delivery_target_updated",
)

#: DISCHARGED 2026-08-21 — measured empty on the host Michael named, and
#: re-verified after the deploy that took production to `af9fcf6`. Retained
#: because `v017` re-checks these same tables under `ACCESS EXCLUSIVE`: the
#: observation licensed writing that revision, and the revision is what
#: licenses applying it.
TARGET_ESTATE_MEASUREMENT: Final[frozenset[str]] = frozenset(
    {"licence_delivery_targets", "licence_deliveries"}
)

#: The revision that seals the write path. Named so the readiness declaration
#: and the lineage cannot drift apart silently.
SEALING_REVISION: Final[str] = "v017_deployment_target_authority"

# ── Whole modules ADR-0010 retires ─────────────────────────────────────────

#: Path-level is correct HERE, because these modules retire entirely rather
#: than losing a symbol. Each must exist: an inventory naming something already
#: gone is describing a retirement somebody else did.
DELIVERY_TRANSPORT_MODULES: Final[tuple[tuple[str, str], ...]] = (
    (
        "src/vendor_cp/licensing/delivery_models.py",
        "the five delivery/evidence tables, including the local deployment "
        "identity claim held on LicenceAckRecord",
    ),
    (
        "src/vendor_cp/licensing/transport.py",
        "delivery attempts, parking and replay generations — Integrator's "
        "under hard rule 28",
    ),
    (
        "src/vendor_cp/licensing/delivery_ops.py",
        "pipeline health and acknowledgement lag, computed from the local "
        "attempt ledger that moves with it",
    ),
)

#: The V6 brief ADR-0011 retires as a design to implement. Not a writer — it
#: was never merged — but it names a Vendor-owned credential registry that
#: `dc_0001` now owns, and a document promising an implementation is how one
#: gets built.
RETIRED_DESIGN_BRIEFS: Final[tuple[str, ...]] = (
    "docs/design/deployment-credentials.md",
)

# ── Brand: an absence, measured ────────────────────────────────────────────

#: EMPTY, and measured. No model, service, table, migration or template in this
#: assembly holds a brand record. The Brand Profiles extraction dossier reached
#: the same conclusion independently and rejected `deployment_profile.py` as
#: composition rather than presentation. Vendor therefore composes the platform
#: plane greenfield, with no migration and no writer retirement.
BRAND_WRITERS_TO_RETIRE: Final[tuple[str, ...]] = ()

#: Substrings that would betray a brand record if one appeared. Scanned across
#: `src/` and the vendor migration lineage.
BRAND_WRITER_MARKERS: Final[tuple[str, ...]] = (
    "BrandProfile",
    "brand_profile",
    "primary_hex",
    "accent_hex",
    "logo_ref",
    "custom_css",
)

#: `console/web.py` carries the product name in a `<title>`. It is a literal in
#: one template string, not a stored record, and it is named here so the scan
#: above cannot be read as claiming this assembly displays no name at all.
BRAND_ADJACENT_LITERALS: Final[tuple[str, ...]] = ("src/vendor_cp/console/web.py",)

# ── Not to be confused with the above ──────────────────────────────────────

#: The provisioning laboratory is NOT a deployment writer and does not retire
#: with either cutover. It drives the kernel's `ProvisioningProvider` contract
#: against a side-effect-free simulator and owns no table at all (deny case D3).
#: `deployment_profile.py` selects which vendor SURFACES are mounted and nothing
#: else. Both are named because the words invite the confusion.
NOT_A_DEPLOYMENT_WRITER: Final[tuple[str, ...]] = (
    "src/vendor_cp/provisioning",
    "src/vendor_cp/deployment_profile.py",
)

__all__ = [
    "BRAND_ADJACENT_LITERALS",
    "BRAND_WRITERS_TO_RETIRE",
    "BRAND_WRITER_MARKERS",
    "DEFERRED_BY_LOCAL_DECISION",
    "DELIVERY_ESTATE",
    "DELIVERY_TRANSPORT_MODULES",
    "FOREIGN_TABLE_MARKERS",
    "NOT_A_DEPLOYMENT_WRITER",
    "RETIRED_DESIGN_BRIEFS",
    "RETIRED_AUDIT_ACTIONS",
    "RETIRED_TARGET_AUTHORITY_SYMBOLS",
    "SEALING_REVISION",
    "TARGET_RECONCILIATION_AUDIT_ACTION",
    "TARGET_RECONCILIATION_SYMBOLS",
    "TARGET_ESTATE_MEASUREMENT",
    "TARGET_PROJECTION_SYMBOLS",
    "VENDOR_OWNED_TABLES",
]
