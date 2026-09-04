"""`PlatformDataGovernanceV1` — one owner for what this database may destroy.

Ruled 2026-09-04: *"Data governance: for first production, explicitly classify
every table. Authoritative control/evidence records use enforced retain: no
automated hard deletion and no `DELETE` for online roles. Any transient table
that does not fit must receive an explicit policy rather than inheriting this
one. New unclassified tables fail admission."*

Four requirements, and the last two are the ones that make it enforcement rather
than description.

## Two enforcements, and only one of them is code

**The grant is the enforcement.** `REVOKE DELETE, TRUNCATE` from the online
roles is refused by PostgreSQL on every statement, whoever wrote it and whatever
they intended. `enforce_retention` issues it and then reads
`has_table_privilege` back, because issuing a `REVOKE` proves only that a
statement ran — the same both-directions discipline vendor `v017` and `v012`
already hold themselves to.

**The code rule is our own discipline, and is weaker.** "No automated hard
deletion" is a claim about call sites, and a call site is a fact about the code
this assembly happens to compose today.
`tests/architecture/test_data_governance.py` enumerates every row-deletion site
in this repository and in the composed distributions and holds the set
two-directionally, so a kernel repin that adds one fails the build. That is a
real ratchet and it is still second: it cannot see a psql session, and it dies
the moment something is composed that this scan does not reach. Which is exactly
why the privilege is taken away as well.

## Why the classification is an enumeration and the AUDIT is not

`AGENTS.md` rule 10 says a privilege proof over a hand-listed set of TABLES is
the regression, and it is right. Nothing here lists which tables get checked:
:func:`enforce_retention` reads the live catalogue and checks what it finds. The
enumeration below is the other half rule 10 blesses — the named, justified,
two-directionally ratcheted set of DECISIONS — and a table the catalogue holds
and this list does not is an admission REFUSAL, never a quiet pass.

That is requirement 4, and it is enforced at two different moments for two
different reasons. In CI, `tests/migration/test_data_governance_catalogue.py`
fails the build when a new migration creates an unclassified table. At deploy,
`enforce_retention` runs inside the composed upgrade's single transaction, so a
database that grew a table nobody classified ROLLS BACK rather than starting.
Breaking the build is the cheap answer; refusing the deploy is the one that
still holds when the table arrived from a repinned module rather than from this
repository.

## Requirement 3 — a transient table does not inherit retain

Retain is not a default here, and a table is not classified by what would be
convenient. The criterion is a measured one: **does a composed, mounted code
path delete rows from this table as an online role?** Where the answer is yes,
retain does not fit, and the table gets :data:`Disposition.LIFECYCLE_DELETE`
with the deleting owner and the trigger named — a policy of its own, which the
enforcement then PROVES by checking that the online role still holds `DELETE`
there. A revoke checked only in the denial direction is satisfied by revoking
everything; a transient policy asserted but not exercised is satisfied by never
having been true.

There is exactly one such table today (`public.feature_flag_overrides`), and two
more that are transient in a different way: a current-state gauge replaced by
`UPDATE` is not a record and is not retained for its own sake, so calling it
"retained" would make retain the answer to a question nobody asked. It gets
:data:`Disposition.SUPERSEDED_IN_PLACE`, which reaches the same grant by a
different and stated route.

## Two escapes a table grant does not close, named rather than assumed

Both are checked on the live catalogue by :func:`enforce_retention`, because
neither is stopped by the revoke:

* **`ON DELETE CASCADE`.** A referential action executes with the privileges of
  the referencing table's OWNER, not of the role that issued the parent
  `DELETE`. Revoking `DELETE` on a child therefore does not stop a cascade from
  a parent the role may delete. The check is that no withheld table is the child
  of a `CASCADE` edge whose parent is deletable.
* **`SECURITY DEFINER`.** The kernel's outbox claim/settle functions run as
  `app_admin` by design, which is what makes them safe to grant `EXECUTE` on —
  and is also a way for a `DELETE` to reach a withheld table with the online
  role's grant never consulted. The check is that no `SECURITY DEFINER` function
  in the database mentions a `DELETE` against a withheld table.

## The census, and why there are no savepoints here

CI has already produced the failure that per-table reads invite: a table census
run in one transaction reported every table after the first denial as `UNKNOWN`,
because a failed statement aborts a PostgreSQL transaction until it is rolled
back. `vendor_cp.deployment.table_inventory` fixed that with a savepoint per
table, and :func:`govern_observation` consumes ITS output rather than re-reading
rows here.

The live reads in this module issue ONE set-returning statement per question —
the catalogue, the effective privileges, the cascade edges, the definer
functions — so no per-table failure can abort anything. That is why there are no
savepoints, and it is stated because copying the fix where its premise does not
hold would look like diligence and mean nothing.

## What this does NOT decide

Retention PERIODS. Nothing below says how long a platform audit event or a
delivery attempt may be kept, because "enforced retain" as ruled needs no
period: no automated hard deletion, full stop. A future decision to dispose of
anything on a schedule is a policy change here plus a disposer with a named
owner, and it will have to move a table out of `ENFORCED_RETAIN` in this file to
get the privilege it needs.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from vendor_cp.deployment.table_inventory import (
    ReadOutcome,
    TableInventoryObservation,
)

__all__ = [
    "CONTRACT",
    "GOVERNED_TABLES",
    "ONLINE_ROLES",
    "ONLINE_ROLES_PRESENT_SQL",
    "POLICY_BY_TABLE",
    "PRESERVED_PRIVILEGES",
    "WITHHELD_PRIVILEGES",
    "DELETION_SITES",
    "UNSCANNED_FUNCTIONS",
    "DataGovernanceRefusal",
    "DeletionSite",
    "Disposition",
    "GovernanceVerdict",
    "ObservationReport",
    "Reachability",
    "RetentionOutcome",
    "TablePolicy",
    "admission_refusal",
    "effective_privileges_sql",
    "enforce_retention",
    "govern_observation",
    "policy_for",
    "tables_permitting_online_deletion",
    "tables_withholding_online_deletion",
    "unclassified",
    "unobserved",
]

#: The versioned name the `ApplicationFoundationProfile`'s `data_governance`
#: concern binds to. Declared once, here, so a profile document and this owner
#: cannot spell it differently.
CONTRACT: Final = "PlatformDataGovernanceV1"

#: The roles a request is served by. `app_admin` is deliberately NOT one: it is
#: the migration and offline-operations role, it is the role this very function
#: runs as, and a governance rule that revoked its own ability to act would be
#: self-defeating rather than strict. Where a disposal is eventually decided, it
#: runs here, under an operator, with a named owner — not on a request.
ONLINE_ROLES: Final[tuple[str, ...]] = ("platform_api", "app_user")

#: Taken away from every online role on every table retain applies to.
#: `TRUNCATE` is included because it destroys rows without issuing a `DELETE`,
#: which is exactly the gap a `DELETE`-only revoke leaves open.
WITHHELD_PRIVILEGES: Final[tuple[str, ...]] = ("DELETE", "TRUNCATE")

#: Read back after the revoke and compared with the reading taken before it. A
#: revoke checked only in the denial direction is satisfied by revoking
#: everything, and a control plane that cannot read or write its own tables is a
#: broken deployment rather than a governed one (vendor `v017`'s lesson).
PRESERVED_PRIVILEGES: Final[tuple[str, ...]] = ("SELECT", "INSERT", "UPDATE")


class Disposition(StrEnum):
    """What may happen to a row in this table, and by whose hand."""

    #: An authoritative control or evidence record. No automated hard deletion,
    #: and no `DELETE`/`TRUNCATE` for any online role. This is the ruling's
    #: category and it is applied by NAME, never inherited.
    ENFORCED_RETAIN = "enforced_retain"

    #: A current-state gauge, replaced by `UPDATE`. Not a record, so it is not
    #: RETAINED — it is simply never deleted, which reaches the same grant by a
    #: different and stated route. Requirement 3's second shape: calling this
    #: "retain" would make retention the answer to a question nobody asked.
    SUPERSEDED_IN_PLACE = "superseded_in_place"

    #: Deleting the row IS the operation the table exists for, so an online role
    #: MUST keep `DELETE`. Requirement 3's first shape: an explicit policy of
    #: its own, naming the deleting owner and the trigger, and PROVED by the
    #: enforcement rather than merely declared.
    LIFECYCLE_DELETE = "lifecycle_delete"

    #: Alembic's own version table. Not a record of anything this deployment
    #: governs; rewritten by the migration runner as `app_admin`, and no online
    #: role holds any privilege on it at all.
    MIGRATION_BOOKKEEPING = "migration_bookkeeping"


#: The dispositions from which no online role may delete. Everything except
#: `LIFECYCLE_DELETE`, and derived rather than listed so a fifth disposition
#: cannot be added on the permissive side by omission.
_WITHHOLDING: Final[frozenset[Disposition]] = frozenset(
    d for d in Disposition if d is not Disposition.LIFECYCLE_DELETE
)


@dataclass(frozen=True, slots=True)
class TablePolicy:
    """One table's disposition, stated rather than derived.

    `rationale` is not decoration: it is what makes the next reader able to tell
    a decision from an omission, and the constructor refuses a policy without
    one.
    """

    schema: str
    table: str
    disposition: Disposition
    rationale: str
    #: Set exactly when the disposition is `LIFECYCLE_DELETE`. A retained table
    #: naming a deleting owner has not decided which it is.
    deleting_owner: str = ""
    trigger: str = ""

    def __post_init__(self) -> None:
        if not self.schema or not self.table:
            raise ValueError("a table policy must name a schema and a table")
        if not self.rationale.strip():
            raise ValueError(
                f"{self.schema}.{self.table}: a classification with no rationale "
                "is an omission wearing a decision's shape"
            )
        named = bool(self.deleting_owner.strip()) and bool(self.trigger.strip())
        if self.disposition is Disposition.LIFECYCLE_DELETE:
            if not named:
                raise ValueError(
                    f"{self.schema}.{self.table}: a lifecycle-delete policy must "
                    "name the deleting owner AND the trigger. 'Something deletes "
                    "this' is the inherited policy requirement 3 refuses"
                )
        elif self.deleting_owner.strip() or self.trigger.strip():
            raise ValueError(
                f"{self.schema}.{self.table}: a table nothing may delete cannot "
                "carry a deleting owner or a trigger"
            )

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def withholds_online_deletion(self) -> bool:
        return self.disposition in _WITHHOLDING


def _retain(schema: str, table: str, rationale: str) -> TablePolicy:
    return TablePolicy(schema, table, Disposition.ENFORCED_RETAIN, rationale)


def _gauge(schema: str, table: str, rationale: str) -> TablePolicy:
    return TablePolicy(schema, table, Disposition.SUPERSEDED_IN_PLACE, rationale)


#: THE ENUMERATION. Every table the composed lineages build, classified by name.
#:
#: Ratcheted in BOTH directions against the live catalogue: a table here that the
#: database does not have is a classification describing nothing, which is the
#: exemption shape `dotmac_starter_mt` ADR-0018 refuses, and a table the database
#: has that is not here refuses admission.
GOVERNED_TABLES: Final[tuple[TablePolicy, ...]] = (
    # ── `public`, kernel lineage ─────────────────────────────────────────
    _retain(
        "public",
        "audit_events",
        "the tenant-plane audit trail. Kernel 0001 grants the online roles "
        "SELECT and INSERT only, so this arrives already sealed; naming it "
        "keeps that a decision rather than an accident of one migration",
    ),
    _retain(
        "public",
        "auth_sessions",
        "session provenance. Kernel 0025 made the row a forensic record and "
        "`platform_auth` REVOKES by setting `revoked_at`; ending a session is a "
        "state change, and deleting the row would erase how it was obtained",
    ),
    _retain(
        "public",
        "communication_deliveries",
        "delivery receipts — evidence that a message was or was not delivered",
    ),
    _retain(
        "public",
        "communication_suppressions",
        "consent and suppression records. `dotmac_kernel.consent.unsuppress` "
        "deletes rows, and this assembly mounts no consent surface to reach it; "
        "composing one is a reclassification here, not a grant to add quietly",
    ),
    _retain(
        "public",
        "domain_setting_history",
        "the setting CHANGE record — who changed what, when. The kernel's "
        "`prune_setting_history` is a function an operator schedules; this "
        "deployment schedules none, and a period would be a decision nobody has "
        "taken",
    ),
    _gauge(
        "public",
        "domain_settings",
        "current configuration, replaced in place. The record of change is "
        "`domain_setting_history`, which IS retained; this table holds the "
        "present value and is not kept for its own sake. Kernel "
        "`clear_by_key` can delete a row and no surface here mounts it",
    ),
    _retain(
        "public",
        "external_identity_bindings",
        "which external identity is bound to which local one — an authorisation "
        "provenance record",
    ),
    TablePolicy(
        "public",
        "feature_flag_overrides",
        Disposition.LIFECYCLE_DELETE,
        "the row IS the override. Clearing an override is deleting it, not "
        "disposing of a record, and there is no state that means 'no override' "
        "other than absence. Retain does not fit: it would leave the platform "
        "console's clear action failing against the database",
        deleting_owner="dotmac_kernel.platform_web.set_flag",
        trigger="a platform admin submits action=clear for one declared flag "
        "code on POST /platform/flags/{code}",
    ),
    _retain(
        "public",
        "inbox_records",
        "the tenant idempotency ledger — the record that says an effect already "
        "happened. `dotmac_kernel.idempotency.purge_expired` exists and this "
        "deployment schedules it nowhere; its own docstring puts a fleet-wide "
        "purge on `app_admin`, which is not an online role",
    ),
    _retain(
        "public",
        "machine_credentials",
        "machine credential custody — which credential existed, and when",
    ),
    _retain(
        "public",
        "outbox_events",
        "the tenant outbox. A settled row is the evidence of what was emitted; "
        "the kernel's relay settles by UPDATE and deletes nothing",
    ),
    _retain("public", "parties", "the fleet-wide identity record"),
    _retain("public", "party_organizations", "the organization subtype of an identity"),
    _retain("public", "party_persons", "the person subtype of an identity"),
    _retain("public", "party_roles", "who was granted which role, and by whom"),
    _retain(
        "public",
        "platform_admins",
        "control-plane operator identity — the actor every platform audit event "
        "attributes to",
    ),
    _retain(
        "public",
        "platform_audit_events",
        "the append-only platform audit log. Kernel 0026 already makes the row "
        "immutable; the revoke closes the remaining way to destroy one",
    ),
    _retain(
        "public",
        "platform_inbox_records",
        "the platform idempotency ledger. Same reading as `inbox_records`: a "
        "purge is `app_admin`'s and this deployment schedules none",
    ),
    _retain(
        "public",
        "platform_outbox_events",
        "the platform outbox. Claim and settle are SECURITY DEFINER functions "
        "owned by `app_admin` that UPDATE; the row is the delivery evidence",
    ),
    _retain(
        "public",
        "platform_sessions",
        "operator session provenance. `revoke_platform_session` sets "
        "`revoked_at`; nothing deletes the row, and the row is how a later "
        "review reconstructs who was signed in",
    ),
    _retain("public", "roles", "the role catalogue a grant refers to"),
    _retain(
        "public",
        "tenant_domains",
        "the tenancy catalogue. Kernel 0001 grants `platform_api` DELETE here "
        "and nothing in this assembly uses it; a tenant domain that vanished "
        "would take its grants' meaning with it",
    ),
    _retain(
        "public",
        "tenant_entitlement_grants",
        "grant records. The kernel is explicit that revoking sets "
        "`granted=False` rather than deleting, because 'we took it away' and "
        "'they never had it' are different answers months later",
    ),
    _retain(
        "public",
        "tenants",
        "the tenancy catalogue. Kernel 0001 grants `platform_api` DELETE and "
        "this assembly opens no tenant session at all",
    ),
    _retain(
        "public",
        "user_credentials",
        "credential custody. Deleting a credential row erases the record that "
        "it existed, which is the half an incident review needs",
    ),
    # ── `public`, vendor lineage ─────────────────────────────────────────
    _retain(
        "public",
        "licence_ack_records",
        "a deployment's acknowledgement of a licence — delivery evidence",
    ),
    _retain("public", "licence_deliveries", "what was delivered, to whom, when"),
    _retain(
        "public",
        "licence_delivery_attempts",
        "every attempt, including the failed ones. The failures are the half "
        "worth keeping",
    ),
    _retain(
        "public",
        "licence_delivery_intents",
        "the durable intent a delivery was made against",
    ),
    _retain("public", "licence_delivery_states", "the delivery state history"),
    _retain(
        "public",
        "licence_delivery_targets",
        "the rebuildable delivery-target projection. Vendor `v017` already "
        "withheld the DELETE privilege from `platform_api`, under ADR-0011's "
        "amendment of "
        "2026-08-21 — 'a role holding DELETE on a projection can only destroy "
        "evidence'. This classification is that seal generalised, not a new one",
    ),
    _retain(
        "public",
        "offer_versions",
        "immutable priced offer versions. A contract line points at one, so a "
        "deleted version would leave a priced agreement unable to say what it "
        "was priced at",
    ),
    _gauge(
        "public",
        "relay_heartbeats",
        "the relay's liveness gauge — four columns, superseded by UPDATE. It is "
        "a present-tense reading, not a record, so it is not RETAINED; vendor "
        "`v019` already grants `platform_api` SELECT/INSERT/UPDATE and no DELETE",
    ),
    _retain(
        "public",
        "vendor_accounts",
        "the vendor account registry — the control-plane subject every "
        "agreement, allocation and licence hangs off",
    ),
    # ── `mod_agreements` (dotmac-commercial-agreements) ──────────────────
    _retain("mod_agreements", "agreement_events", "the agreement lifecycle history"),
    _retain("mod_agreements", "agreement_lines", "what was agreed, at what price"),
    _retain("mod_agreements", "agreements", "the commercial agreement record"),
    # ── `mod_approvals` (dotmac-approvals, PLATFORM plane only) ──────────
    _retain(
        "mod_approvals",
        "platform_approval_decisions",
        "who approved what. The decision record is the reason approvals exist",
    ),
    _retain(
        "mod_approvals",
        "platform_approval_policies",
        "the policy version a past decision was taken under. Deleting it makes "
        "the decisions that cite it unreadable",
    ),
    _retain("mod_approvals", "platform_approval_requests", "what was asked for"),
    # ── `mod_deploy` (dotmac-deployment-control) ─────────────────────────
    _retain("mod_deploy", "deployment_plans", "what a deployment was told to do"),
    _retain(
        "mod_deploy",
        "deployment_targets",
        "deployment-target identity — the authority vendor `v017` transferred "
        "this to",
    ),
    _retain("mod_deploy", "observation_attempts", "every attempt to observe a target"),
    _retain(
        "mod_deploy",
        "observation_receipts",
        "the signed observation of what a target actually ran",
    ),
    _retain("mod_deploy", "rollout_attempts", "every attempt, including failures"),
    _retain("mod_deploy", "rollouts", "what was rolled out, where, and when"),
    _retain(
        "mod_deploy",
        "target_credentials",
        "credential custody for a target. Rotation writes a new row; the old "
        "one is how a later review knows what was in use at the time",
    ),
    # ── `mod_ealloc` (dotmac-entitlement-allocation) ─────────────────────
    _retain(
        "mod_ealloc",
        "allocation_entries",
        "what was allocated. Vendor `v014` already leaves `platform_api` with "
        "SELECT/INSERT and a two-column UPDATE, so no DELETE reaches here",
    ),
    _retain("mod_ealloc", "allocations", "the sealed allocation record"),
    # ── `mod_licensing` (dotmac-licensing) ───────────────────────────────
    _retain(
        "mod_licensing",
        "licence_acknowledgements",
        "a deployment's acknowledgement of the licence it received",
    ),
    _retain("mod_licensing", "licence_issuances", "every issuance, immutable"),
    _retain("mod_licensing", "licences", "the licence record"),
    _retain(
        "mod_licensing",
        "revocation_lists",
        "the signed revocation lists that were published",
    ),
    _retain("mod_licensing", "revocations", "what was revoked, and when"),
    _retain(
        "mod_licensing",
        "signing_keys",
        "signing-key custody. A key row deleted is a signature nobody can later "
        "attribute",
    ),
    # ── `mod_rel` (dotmac-release-catalog) ───────────────────────────────
    _retain(
        "mod_rel",
        "artifact_attestations",
        "attestations about a released artifact — evidence by construction",
    ),
    _retain(
        "mod_rel",
        "release_artifacts",
        "immutable artifact identity. Every pin, descriptor and adoption claim "
        "resolves through one of these rows",
    ),
    # ── Alembic's own bookkeeping ────────────────────────────────────────
    TablePolicy(
        "public",
        "alembic_version",
        Disposition.MIGRATION_BOOKKEEPING,
        "Alembic's version table. It is not a record of anything this "
        "deployment governs — the migration runner rewrites it as `app_admin` "
        "on every upgrade, and no online role holds any privilege on it. "
        "Classifying it 'retain' would be retention answering a question nobody "
        "asked, which is the shape requirement 3 refuses",
    ),
)


def _index() -> dict[str, TablePolicy]:
    index: dict[str, TablePolicy] = {}
    for policy in GOVERNED_TABLES:
        if policy.qualified in index:
            raise ValueError(
                f"{policy.qualified} is classified twice. Two dispositions for "
                "one table is two answers, and a lookup would return whichever "
                "was written last"
            )
        index[policy.qualified] = policy
    return index


#: Every classified table, by qualified name. Built once, and construction
#: refuses a duplicate: two policies for one table is two answers, and whichever
#: one a lookup returned would be arbitrary.
POLICY_BY_TABLE: Final[Mapping[str, TablePolicy]] = _index()


class DataGovernanceRefusal(RuntimeError):
    """The database and this classification disagree. Nothing was changed."""


def policy_for(qualified: str) -> TablePolicy | None:
    """The policy for `schema.table`, or None when the table is unclassified."""
    return POLICY_BY_TABLE.get(qualified)


def tables_withholding_online_deletion() -> tuple[str, ...]:
    """Every table no online role may delete from, in catalogue order."""
    return tuple(
        policy.qualified
        for policy in sorted(GOVERNED_TABLES, key=lambda p: p.qualified)
        if policy.withholds_online_deletion
    )


def tables_permitting_online_deletion() -> tuple[str, ...]:
    """Every table an online role MUST still be able to delete from.

    Exported so the enforcement can prove the transient policy in the positive
    direction. A revoke checked only where it should bite is satisfied by
    revoking everything.
    """
    return tuple(
        policy.qualified
        for policy in sorted(GOVERNED_TABLES, key=lambda p: p.qualified)
        if not policy.withholds_online_deletion
    )


def unclassified(observed: Iterable[str]) -> tuple[str, ...]:
    """Tables the database holds that this classification does not name."""
    return tuple(sorted(set(observed) - set(POLICY_BY_TABLE)))


def unobserved(observed: Iterable[str]) -> tuple[str, ...]:
    """Tables this classification names that the database does not hold."""
    return tuple(sorted(set(POLICY_BY_TABLE) - set(observed)))


def admission_refusal(observed: Iterable[str]) -> str:
    """Why this database is not admissible, or `""` when it is.

    Both directions, and the second is the one that is usually left out. A
    classification naming a table that no longer exists keeps describing a
    decision nobody can act on, and it is how a dropped table stops being
    noticed — the exemption shape `dotmac_starter_mt` ADR-0018 refuses.
    """
    catalogue = tuple(observed)
    missing = unclassified(catalogue)
    stale = unobserved(catalogue)
    reasons: list[str] = []
    if missing:
        reasons.append(
            f"{len(missing)} table(s) in this database are not classified: "
            f"{list(missing)}. Add each to GOVERNED_TABLES in "
            "`vendor_cp/data_governance.py` with its disposition and a "
            "rationale. A new table does not inherit a policy: retain is the "
            "ruling's answer for control and evidence records, and a transient "
            "table gets one of its own"
        )
    if stale:
        reasons.append(
            f"{len(stale)} classified table(s) are not in this database: "
            f"{list(stale)}. A policy describing nothing is not harmless — it "
            "is how a table that was dropped stops being noticed. Lower the "
            "classification in the same change that removed the table"
        )
    return "\n".join(reasons)


class GovernanceVerdict(StrEnum):
    """What a production census establishes about this database."""

    GOVERNED = "governed"
    #: The census could not read some tables, so nothing is established about
    #: them. `UNKNOWN` is a member of `ReadOutcome`, never a zero, and it does
    #: not become a clean verdict here either.
    UNESTABLISHED = "unestablished"
    #: The census found a table this classification does not name, or names a
    #: table the census did not find.
    INADMISSIBLE = "inadmissible"


@dataclass(frozen=True, slots=True)
class ObservationReport:
    """A production census judged against the classification."""

    verdict: GovernanceVerdict
    detail: str
    #: `(qualified, disposition, row_count)` for every table the census counted.
    #: A count is a fact about governance; a row is the data being governed.
    counted: tuple[tuple[str, str, int], ...] = ()
    unknown: tuple[str, ...] = ()

    @property
    def governed(self) -> bool:
        return self.verdict is GovernanceVerdict.GOVERNED


def govern_observation(observation: TableInventoryObservation) -> ObservationReport:
    """Judge a production table census against this classification.

    This is the owner `vendor_cp.deployment.table_inventory`'s own docstring says
    it is an INPUT to. The census answers a cardinality and nothing else; the
    judgement about what may be destroyed is taken here.

    An `UNKNOWN` table is not a clean result. A retention verdict that rendered
    "I could not read it" as "nothing to govern" would be the same collapse the
    census type exists to prevent, arriving one layer up.
    """
    observed = tuple(table.qualified for table in observation.tables)
    refusal = admission_refusal(observed)
    if refusal:
        return ObservationReport(GovernanceVerdict.INADMISSIBLE, refusal)
    unknown = tuple(sorted(table.qualified for table in observation.unknown))
    counted = tuple(
        (
            table.qualified,
            str(POLICY_BY_TABLE[table.qualified].disposition),
            int(table.row_count or 0),
        )
        for table in sorted(observation.tables, key=lambda t: t.qualified)
        if table.outcome is ReadOutcome.COUNTED
    )
    if unknown:
        return ObservationReport(
            GovernanceVerdict.UNESTABLISHED,
            f"{len(unknown)} table(s) could not be read, so this census "
            f"establishes nothing about them: {list(unknown)}. A retention "
            "decision may not rest on a partial inventory",
            counted,
            unknown,
        )
    return ObservationReport(
        GovernanceVerdict.GOVERNED,
        f"all {len(counted)} tables are classified and were counted",
        counted,
    )


# ── the code half: every place a row can be deleted, enumerated ─────────────


class Reachability(StrEnum):
    """Whether an online request can reach this deletion in this deployment."""

    #: Mounted here and reachable as an online role. The table it targets MUST
    #: be classified `LIFECYCLE_DELETE`, or the code and the grant disagree and
    #: production is the place that finds out.
    ONLINE_MOUNTED = "online_mounted"
    #: The code exists in a composed distribution and nothing in this assembly
    #: reaches it. The premise is named and is checked, because an exemption
    #: whose premise nobody can test is a waiver.
    NOT_COMPOSED = "not_composed"
    #: Runs against a disposable rehearsal database, never a production one.
    REHEARSAL_ONLY = "rehearsal_only"


@dataclass(frozen=True, slots=True)
class DeletionSite:
    """One place composed code can remove rows, and why that is acceptable."""

    distribution: str
    module: str
    symbol: str
    #: What it deletes from. Only meaningful — and only checked — for
    #: `ONLINE_MOUNTED`, where it must name a `LIFECYCLE_DELETE` table.
    target: str
    reachability: Reachability
    premise: str

    def __post_init__(self) -> None:
        if not self.premise.strip():
            raise ValueError(f"{self.module}.{self.symbol}: a site needs a premise")
        if self.reachability is not Reachability.ONLINE_MOUNTED:
            return
        policy = POLICY_BY_TABLE.get(self.target)
        if policy is None or policy.disposition is not Disposition.LIFECYCLE_DELETE:
            raise ValueError(
                f"{self.module}.{self.symbol} deletes from {self.target!r} on an "
                "online request, and that table is not classified "
                "LIFECYCLE_DELETE. Either the code is removing a record this "
                "deployment retains, or the classification is wrong — and the "
                "grant will make production find out"
            )

    @property
    def identity(self) -> tuple[str, str]:
        return (self.module, self.symbol)


#: EVERY row-deletion site in this repository and in the composed distributions,
#: enumerated and held two-directionally by
#: `tests/architecture/test_data_governance.py`. A kernel repin that adds one
#: fails the build; removing one without lowering this list fails it too.
#:
#: This is the WEAKER of the two enforcements and is second on purpose. It sees
#: only code this scan reaches — not a psql session, not a distribution composed
#: later. The grant is what actually refuses the statement.
DELETION_SITES: Final[tuple[DeletionSite, ...]] = (
    DeletionSite(
        distribution="dotmac-vendor-control-plane",
        module="vendor_cp.commercial_backfill.shadow",
        symbol="repair_statements",
        target="bf_rehearsal.shadow_verdicts",
        reachability=Reachability.REHEARSAL_ONLY,
        premise="the backfill rehearsal's shadow schema is created by "
        "`scripts/reconcile_backfill_shadow.py` in a DISPOSABLE database and is "
        "REVOKEd from `platform_api` by the same statements that create it. No "
        "composed migration builds `bf_rehearsal`, so it is absent from the "
        "production catalogue and from GOVERNED_TABLES — which the admission "
        "check would otherwise refuse it for",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.consent",
        symbol="unsuppress",
        target="public.communication_suppressions",
        reachability=Reachability.NOT_COMPOSED,
        premise="no consent surface is mounted here: the symbol has zero call "
        "sites under `src/vendor_cp` and does not appear in the one kernel "
        "router module this assembly mounts",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.consent",
        symbol="unsuppress_marketing",
        target="public.communication_suppressions",
        reachability=Reachability.NOT_COMPOSED,
        premise="as `unsuppress`: zero call sites here, and absent from the "
        "mounted kernel router module",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.crud",
        symbol="CRUDManager",
        target="whatever model a caller hands it",
        reachability=Reachability.NOT_COMPOSED,
        premise="the kernel's generic CRUD delete. Nothing under `src/vendor_cp` "
        "constructs or calls it, and it appears in no mounted kernel router",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.idempotency",
        symbol="purge_expired",
        target="public.inbox_records and public.platform_inbox_records",
        reachability=Reachability.NOT_COMPOSED,
        premise="a function a product SCHEDULES, and this deployment schedules "
        "it nowhere — zero call sites here. Its own docstring puts a fleet-wide "
        "purge on `app_admin`, which is not an online role, so a retention "
        "policy decided later does not need the grant this withholds",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.platform_web",
        symbol="set_flag",
        target="public.feature_flag_overrides",
        reachability=Reachability.ONLINE_MOUNTED,
        premise="THE transient case. `PLATFORM_WEB_SURFACE` is mounted because "
        "this assembly composes with `web_enabled=True`, and clearing an "
        "override removes the row because absence is what 'no override' means. "
        "`public.feature_flag_overrides` is classified LIFECYCLE_DELETE for "
        "exactly this site, and the enforcement checks the online role can "
        "still act on it",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.settings_resolver",
        symbol="clear_by_key",
        target="public.domain_settings",
        reachability=Reachability.NOT_COMPOSED,
        premise="no settings surface is mounted: the mounted kernel router "
        "publishes login, logout, inventory, flags and entitlements and nothing "
        "else, and there are zero call sites under `src/vendor_cp`",
    ),
    DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.settings_resolver",
        symbol="prune_setting_history",
        target="public.domain_setting_history",
        reachability=Reachability.NOT_COMPOSED,
        premise="a prune an operator schedules; this deployment schedules none, "
        "and the period it would need is a decision nobody has taken",
    ),
)

#: Functions the scan does not walk into, with the premise that makes that
#: enforceable rather than convenient.
#:
#: `downgrade` — the deploy path applies `upgrade heads` and refuses every other
#: target (`vendor_cp.migrations.deploy_target_refusal`), and the installed
#: operator surface exposes no downgrade command at all. A downgrade is an
#: operator running Alembic by hand against a database, which is outside what
#: "no AUTOMATED hard deletion" is a claim about — and the grant still applies
#: to whoever runs it as an online role.
UNSCANNED_FUNCTIONS: Final[tuple[str, ...]] = ("downgrade",)


# ── the live half: what the database is actually made to refuse ─────────────

#: Every table in every non-system schema. `pg_class`/`pg_namespace` rather than
#: `information_schema`, which shows only what the CURRENT ROLE can see and would
#: silently shrink the catalogue for a less privileged observer — turning an
#: unclassified table into an invisible one.
LIVE_TABLES_SQL: Final = """
SELECT n.nspname, c.relname
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
 WHERE c.relkind = 'r'
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg_toast%'
 ORDER BY n.nspname, c.relname
"""

#: EFFECTIVE privileges, in ONE statement, for every table and every online role
#: at once.
#:
#: `has_table_privilege` answers what the role can actually do, including
#: privileges reached through role membership and through `PUBLIC` — which a
#: `pg_class.relacl` or `information_schema` read would miss. That is the same
#: reading vendor `v012`, `v013`, `v014` and `v017` each verify their own grants
#: with, and an isolation gate built on the direct-grant view instead is the
#: mistake those revisions already refused.
#:
#: One statement, not one per table: a failed statement aborts a PostgreSQL
#: transaction until it is rolled back, which is precisely how a per-table census
#: once reported every table after the first denial as UNKNOWN. There are no
#: savepoints here because there is nothing for them to isolate.
EFFECTIVE_PRIVILEGES_SQL_TEMPLATE: Final = """
SELECT n.nspname, c.relname, r.rolname, p.privilege,
       has_table_privilege(r.oid, c.oid, p.privilege) AS holds
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
  CROSS JOIN pg_catalog.pg_roles AS r
  CROSS JOIN (VALUES {privileges}) AS p(privilege)
 WHERE c.relkind = 'r'
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg_toast%'
   AND r.rolname IN ({roles})
 ORDER BY n.nspname, c.relname, r.rolname, p.privilege
"""


def effective_privileges_sql() -> str:
    """The privilege reading, built from this module's own constants.

    Interpolated rather than bound because the role list and the privilege list
    are the CONTRACT — they come from :data:`ONLINE_ROLES`,
    :data:`WITHHELD_PRIVILEGES` and :data:`PRESERVED_PRIVILEGES` in this file and
    from nowhere else, so no external input reaches the statement. Built rather
    than written out so the statement and the constants cannot drift apart.
    """
    privileges = ", ".join(
        f"('{privilege}')"
        for privilege in (*WITHHELD_PRIVILEGES, *PRESERVED_PRIVILEGES)
    )
    roles = ", ".join(f"'{role}'" for role in ONLINE_ROLES)
    return EFFECTIVE_PRIVILEGES_SQL_TEMPLATE.format(privileges=privileges, roles=roles)


#: `ON DELETE CASCADE` edges, child first. A referential action executes with the
#: privileges of the REFERENCING table's owner rather than of the role that
#: issued the parent `DELETE`, so a revoke on the child does not stop a cascade
#: from a parent that role may delete. `confdeltype = 'c'` is CASCADE.
CASCADE_EDGES_SQL: Final = """
SELECT cn.nspname, cc.relname, pn.nspname, pc.relname
  FROM pg_catalog.pg_constraint AS con
  JOIN pg_catalog.pg_class AS cc ON cc.oid = con.conrelid
  JOIN pg_catalog.pg_namespace AS cn ON cn.oid = cc.relnamespace
  JOIN pg_catalog.pg_class AS pc ON pc.oid = con.confrelid
  JOIN pg_catalog.pg_namespace AS pn ON pn.oid = pc.relnamespace
 WHERE con.contype = 'f' AND con.confdeltype = 'c'
 ORDER BY 1, 2, 3, 4
"""

#: Every `SECURITY DEFINER` function body. Such a function runs as its OWNER, so
#: the online role's grant is never consulted for what it does — which is exactly
#: what makes the kernel's outbox claim/settle pair safe to grant `EXECUTE` on,
#: and exactly how a `DELETE` could reach a withheld table without any revoke
#: applying to it.
DEFINER_FUNCTIONS_SQL: Final = """
SELECT n.nspname, p.proname, p.prosrc
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
 WHERE p.prosecdef
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
 ORDER BY 1, 2
"""

#: Identifiers cannot be bound as parameters. Every value interpolated here
#: comes from :data:`GOVERNED_TABLES`, :data:`WITHHELD_PRIVILEGES` and
#: :data:`ONLINE_ROLES` — module constants in this file — so no external input
#: reaches the statement.
#: Which of the online roles the cluster actually has. A role that does not
#: exist produces no privilege rows at all, and every "does this role hold
#: DELETE" question would then answer `False` for the happiest possible reason.
#: That is a gate passing because it examined nothing, so it is refused instead.
ONLINE_ROLES_PRESENT_SQL: Final = """
SELECT rolname FROM pg_catalog.pg_roles ORDER BY rolname
"""

REVOKE_SQL: Final = 'REVOKE {privileges} ON "{schema}"."{table}" FROM {roles}'


class _Result(Protocol):
    """What a driver hands back. Typed narrowly, like the census reader, so this
    cannot quietly start using a richer result than it declares."""

    def __iter__(self) -> Iterator[Sequence[object]]: ...


class _Connection(Protocol):
    """The narrowest shape this needs. It receives a connection inside the
    caller's transaction; it opens none and commits none."""

    def execute(
        self,
        statement: object,
        parameters: Mapping[str, object] | None = None,
    ) -> _Result: ...


@dataclass(frozen=True, slots=True)
class RetentionOutcome:
    """What the enforcement actually did, so a green result is not vacuous.

    A run that examined nothing returns no violations, which is also what a
    conforming database returns. These counts are how the two are told apart —
    the same reason `DriftReport` carries `compared`.
    """

    tables_examined: int
    tables_withheld: int
    tables_permitting_deletion: int
    revocations_issued: int
    cascade_edges_examined: int
    definer_functions_examined: int


def _rows(result: _Result) -> list[Sequence[object]]:
    return [tuple(row) for row in result]


def enforce_retention(connection: _Connection) -> RetentionOutcome:
    """Make this database refuse what the classification says it must refuse.

    RECEIVES a connection inside the caller's transaction and neither opens nor
    commits one, so a refusal rolls the whole composed upgrade back rather than
    leaving a half-governed database committed. `alembic/env.py` calls this on
    the DEPLOY path only — a rehearsal driving an intermediate target has not
    reached composed heads and would refuse for a reason about the rehearsal.

    Runs as `app_admin`, which owns every table here; that is what makes the
    `REVOKE` legal, and it is also why `app_admin` is not an online role.

    Idempotent: a second run revokes what is already revoked and reads back the
    same answer. That is what lets this be a post-condition of every deploy
    rather than a one-shot revision, which in turn is what makes it immune to
    the order the composed lineages happen to run in — a module lineage that
    ran after a revision would have handed its DML grant back.
    """
    from sqlalchemy import text  # noqa: PLC0415 - kept off the import path

    present = {
        str(row[0]) for row in _rows(connection.execute(text(ONLINE_ROLES_PRESENT_SQL)))
    }
    absent = [role for role in ONLINE_ROLES if role not in present]
    if absent:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: the online role(s) {absent} do not exist in this "
            "cluster, so every privilege question about them would answer "
            "'does not hold' for the wrong reason. A gate that passes because "
            "it examined nothing is not a gate"
        )

    observed = tuple(
        f"{row[0]}.{row[1]}" for row in _rows(connection.execute(text(LIVE_TABLES_SQL)))
    )
    refusal = admission_refusal(observed)
    if refusal:
        raise DataGovernanceRefusal(
            f"{CONTRACT} refuses this database and nothing has been "
            f"changed.\n{refusal}"
        )

    before = _privileges(connection)
    withheld = tuple(
        qualified
        for qualified in tables_withholding_online_deletion()
        if qualified in observed
    )
    revocations = 0
    for qualified in withheld:
        schema, _, table = qualified.partition(".")
        connection.execute(
            text(
                REVOKE_SQL.format(
                    privileges=", ".join(WITHHELD_PRIVILEGES),
                    schema=schema,
                    table=table,
                    roles=", ".join(ONLINE_ROLES),
                )
            )
        )
        revocations += 1

    after = _privileges(connection)
    _verify_withheld(withheld, after)
    _verify_still_permitted(observed, after)
    _verify_preserved(before, after, withheld)
    cascades = _verify_no_cascade_into_withheld(connection)
    definers = _verify_no_definer_deletes_withheld(connection)

    return RetentionOutcome(
        tables_examined=len(observed),
        tables_withheld=len(withheld),
        tables_permitting_deletion=len(
            [q for q in tables_permitting_online_deletion() if q in observed]
        ),
        revocations_issued=revocations,
        cascade_edges_examined=cascades,
        definer_functions_examined=definers,
    )


def _privileges(connection: _Connection) -> dict[tuple[str, str, str], bool]:
    """`(qualified, role, privilege) -> effectively holds`, in one statement."""
    from sqlalchemy import text  # noqa: PLC0415 - kept off the import path

    rows = _rows(connection.execute(text(effective_privileges_sql())))
    return {
        (f"{row[0]}.{row[1]}", str(row[2]), str(row[3]).upper()): bool(row[4])
        for row in rows
    }


def _verify_withheld(
    withheld: Sequence[str], holds: Mapping[tuple[str, str, str], bool]
) -> None:
    """Issuing a REVOKE proves a statement ran, not that the privilege is gone.

    A privilege reached through a role grant this function never touched survives
    a table-level revoke, and reporting a seal that did not take is worse than
    reporting no seal at all.
    """
    still: list[str] = []
    for qualified in withheld:
        for role in ONLINE_ROLES:
            for privilege in WITHHELD_PRIVILEGES:
                if holds.get((qualified, role, privilege)):
                    still.append(f"{role} {privilege} on {qualified}")
    if still:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: the revoke did not take — {sorted(still)} survive it. "
            "The privilege is probably held through a role grant this "
            "enforcement does not touch. Refusing to report a seal that did not "
            "take"
        )


def _verify_still_permitted(
    observed: Sequence[str], holds: Mapping[tuple[str, str, str], bool]
) -> None:
    """The transient policy, proved in the direction that can actually fail.

    A `LIFECYCLE_DELETE` classification that no online role can act on is not a
    transient policy; it is a retained table with a misleading label. This is
    also what stops the whole enforcement being satisfied by revoking
    everything.
    """
    broken: list[str] = []
    for qualified in tables_permitting_online_deletion():
        if qualified not in observed:
            continue
        if not any(holds.get((qualified, role, "DELETE")) for role in ONLINE_ROLES):
            broken.append(qualified)
    if broken:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: {sorted(broken)} are classified LIFECYCLE_DELETE and "
            "no online role may remove a row there. A transient policy nothing "
            "can act on is a retained table wearing the wrong label, and the "
            "surface that clears those rows would fail against this database"
        )


def _verify_preserved(
    before: Mapping[tuple[str, str, str], bool],
    after: Mapping[tuple[str, str, str], bool],
    withheld: Sequence[str],
) -> None:
    """Nothing but DELETE and TRUNCATE moved.

    Vendor `v017`'s post-condition made the same check for one table and stated
    why: a projection nothing can rebuild is a broken delivery path, not a sealed
    one. Compared against a reading taken BEFORE the revoke rather than against a
    literal expectation, because the expectation would then be a second, drifting
    copy of what the composed migrations granted.
    """
    lost: list[str] = []
    for qualified in withheld:
        for role in ONLINE_ROLES:
            for privilege in PRESERVED_PRIVILEGES:
                key = (qualified, role, privilege)
                if before.get(key) and not after.get(key):
                    lost.append(f"{role} {privilege} on {qualified}")
    if lost:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: the revoke took more than it was asked for — "
            f"{sorted(lost)} were held before it and are not held after. "
            "Retention withholds DELETE and TRUNCATE; a control plane that "
            "cannot read or write its own tables is a broken deployment"
        )


def _verify_no_cascade_into_withheld(connection: _Connection) -> int:
    """No withheld table is the child of a CASCADE from a deletable parent.

    The grant does not cover this: PostgreSQL runs a referential action with the
    referencing table's owner's privileges, so the online role's revoke is never
    consulted. Returns how many edges were examined, so a clean answer over zero
    edges is distinguishable from a clean answer over all of them.
    """
    from sqlalchemy import text  # noqa: PLC0415 - kept off the import path

    edges = _rows(connection.execute(text(CASCADE_EDGES_SQL)))
    reachable: list[str] = []
    for row in edges:
        child = f"{row[0]}.{row[1]}"
        parent = f"{row[2]}.{row[3]}"
        child_policy = POLICY_BY_TABLE.get(child)
        parent_policy = POLICY_BY_TABLE.get(parent)
        if child_policy is None or parent_policy is None:
            continue
        if child_policy.withholds_online_deletion and not (
            parent_policy.withholds_online_deletion
        ):
            reachable.append(f"{parent} -> {child}")
    if reachable:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: {sorted(reachable)} let a row an online role MAY "
            "delete cascade into a table it may not. A referential action runs "
            "with the referencing table's owner's privileges, so the revoke on "
            "the child is never consulted"
        )
    return len(edges)


def _verify_no_definer_deletes_withheld(connection: _Connection) -> int:
    """No `SECURITY DEFINER` function deletes from a withheld table.

    Same class of escape as the cascade and for the same reason: the function
    runs as its owner, so no online role's grant is consulted for what it does.
    Matched on the function body's text — a coarse reading, deliberately
    over-eager rather than under-eager, because the answer to a false positive is
    to look at the function and the answer to a false negative is a destroyed
    record.
    """
    from sqlalchemy import text  # noqa: PLC0415 - kept off the import path

    functions = _rows(connection.execute(text(DEFINER_FUNCTIONS_SQL)))
    withheld = set(tables_withholding_online_deletion())
    offenders: list[str] = []
    for row in functions:
        body = str(row[2]).lower()
        if "delete" not in body and "truncate" not in body:
            continue
        for qualified in withheld:
            bare = qualified.partition(".")[2]
            if bare in body:
                offenders.append(f"{row[0]}.{row[1]} -> {qualified}")
    if offenders:
        raise DataGovernanceRefusal(
            f"{CONTRACT}: {sorted(offenders)} are SECURITY DEFINER functions "
            "whose bodies mention deleting from a withheld table. Such a "
            "function runs as its owner, so no online role's revoke applies to "
            "what it does"
        )
    return len(functions)
