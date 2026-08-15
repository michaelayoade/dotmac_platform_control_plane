"""Read-only inventory of the LEGACY approvals estate, as deterministic evidence.

Nobody knows whether `public.approval_policies` and `public.approval_records`
hold anything, and that one fact decides between two very different programmes —
a greenfield cutover that makes `dotmac-approvals` authoritative before there is
any production data, or a parity core that translates real legacy facts into the
module's policy engine. Building the wrong one is expensive, so this module
answers the question and nothing else.

Note what it does NOT assume. No checked-in evidence records a Vendor CP database
being provisioned anywhere but disposable CI, and the operations runbook still
states that production deployment is blocked. That is not proof none exists: a
manual dispatch, a hand-provisioned host or a database on unrelated
infrastructure would leave no trace in this repository. So the estate is
MEASURED against a database an operator names, never inferred from the absence of
a record.

## What it will not do

**It does not compare the legacy tables with the module's tables.** Those module
tables are deliberately EMPTY (the shadow phase is read-only), so "legacy has N
rows, module has 0" is a difference guaranteed by construction and informative
about nothing. Worse, it reads like a parity measurement, and a number that looks
like parity gets quoted as parity.

So the two observations are separate types with separate collectors, and no
function anywhere takes both — `tests/architecture/test_inventory_boundaries.py`
fails the build if one appears. The report carries both as sections; it derives
nothing across them.

## Determinism

The document is a pure function of database state: same database, byte-identical
output, twice. There is no run timestamp anywhere in it — not even outside the
digest — because a field that changes per run makes the evidence impossible to
diff, which is most of what evidence is for. Timestamps that DO appear are stored
column values (`created_at`), which are facts about rows rather than readings of
a clock.

Everything is sorted: keys by `sort_keys`, and every list explicitly, so the
output does not inherit PostgreSQL's row order.

## Read-only by the database, not by promise

The caller opens a `READ ONLY` transaction (see
`scripts/approvals_inventory.py`). Every statement here is a `SELECT`, but the
transaction mode is what makes that enforceable rather than merely intended.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import text

#: Document identity. A consumer that reads one of these should be able to tell
#: at a glance what it is looking at and which shape to expect.
DOCUMENT: Final[str] = "dotmac.vendor.approvals.inventory"
DOCUMENT_VERSION: Final[int] = 1

#: Stored timestamps render in one fixed UTC form, so a session timezone cannot
#: change the bytes.
TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"

#: The LEGACY tables. Vendor-owned, in the host namespace, written today by
#: `vendor_cp.approvals.service`.
LEGACY_POLICY_TABLE: Final[str] = "approval_policies"
LEGACY_RECORD_TABLE: Final[str] = "approval_records"
LEGACY_TABLES: Final[tuple[str, ...]] = (LEGACY_POLICY_TABLE, LEGACY_RECORD_TABLE)

#: The composed module's platform plane — observed SEPARATELY, and only to
#: confirm the shadow phase is still what it claims to be.
MODULE_SCHEMA: Final[str] = "mod_approvals"
MODULE_TABLES: Final[tuple[str, ...]] = (
    "platform_approval_policies",
    "platform_approval_requests",
    "platform_approval_decisions",
)

ONLINE_ROLE: Final[str] = "platform_api"
TENANT_ROLE: Final[str] = "app_user"

#: Write and DDL privileges the online role must NOT hold on module tables while
#: the legacy writer is authoritative.
WRITE_PRIVILEGES: Final[tuple[str, ...]] = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

#: PostgreSQL grants only these per column; asking about the others is an error.
_COLUMN_GRANTABLE: Final[frozenset[str]] = frozenset(
    {"SELECT", "INSERT", "UPDATE", "REFERENCES"}
)


# ── Observation types (deliberately NOT combinable) ─────────────────────────


@dataclass(frozen=True, slots=True)
class LegacyEstate:
    """What the legacy approvals tables actually contain.

    This is the answer the programme is waiting on. It knows nothing about the
    module, and there is no method here that accepts a `ModuleReadiness`.
    """

    policies: Mapping[str, Any]
    records: Mapping[str, Any]

    @property
    def is_empty(self) -> bool:
        """True when BOTH legacy tables hold no rows.

        Reported as a fact, never acted on: which programme follows from an
        empty estate is a decision for the owner, not an inference this module
        is entitled to make.
        """
        return (
            int(self.policies["row_count"]) == 0 and int(self.records["row_count"]) == 0
        )


@dataclass(frozen=True, slots=True)
class ModuleReadiness:
    """That the shadow phase is still read-only and unwritten.

    Separate from `LegacyEstate` on purpose. The module's tables are empty by
    construction, so any arithmetic between the two is meaningless — and looks
    exactly like parity to a reader in a hurry.
    """

    tables: Sequence[Mapping[str, Any]]

    @property
    def ok(self) -> bool:
        return all(bool(table["ok"]) for table in self.tables)


# ── Collectors ──────────────────────────────────────────────────────────────


def _scalar(connection: Any, statement: str, **params: object) -> Any:
    return connection.execute(text(statement), params).scalar()


def _column(connection: Any, statement: str, **params: object) -> list[Any]:
    return list(connection.execute(text(statement), params).scalars())


def _render_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        # A naive timestamp has no single instant. Refuse rather than guess a
        # zone and emit evidence that reads as precise.
        raise ValueError("stored timestamp is naive; expected timezone-aware")
    return value.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def collect_legacy_estate(connection: Any) -> LegacyEstate:
    """Count the legacy tables and the facts a cutover would need.

    The record facts are chosen from ADR-0004: the implicit GROUP KEY is the
    composite the legacy quorum was always counted over, so the number of
    distinct groups — not the row count — is the number of approval decisions a
    cutover would have to dispose of.
    """
    policy_count = int(_scalar(connection, "SELECT count(*) FROM approval_policies"))
    policy_codes = sorted(
        _column(connection, "SELECT DISTINCT policy_code FROM approval_policies")
    )
    quorums = sorted(
        int(value)
        for value in _column(
            connection, "SELECT DISTINCT quorum FROM approval_policies"
        )
    )
    self_approval = sorted(
        bool(value)
        for value in _column(
            connection, "SELECT DISTINCT allow_self_approval FROM approval_policies"
        )
    )
    policy_first, policy_last = _extent(connection, LEGACY_POLICY_TABLE)

    record_count = int(_scalar(connection, "SELECT count(*) FROM approval_records"))
    subject_types = sorted(
        _column(connection, "SELECT DISTINCT subject_type FROM approval_records")
    )
    distinct_groups = int(
        _scalar(
            connection,
            "SELECT count(*) FROM (SELECT DISTINCT policy_code, policy_version, "
            "subject_type, subject_id, content_hash FROM approval_records) g",
        )
    )
    distinct_policy_refs = int(
        _scalar(
            connection,
            "SELECT count(*) FROM (SELECT DISTINCT policy_code, policy_version "
            "FROM approval_records) p",
        )
    )
    distinct_approvers = int(
        _scalar(connection, "SELECT count(DISTINCT approver_id) FROM approval_records")
    )
    record_first, record_last = _extent(connection, LEGACY_RECORD_TABLE)

    return LegacyEstate(
        policies={
            "table": LEGACY_POLICY_TABLE,
            "row_count": policy_count,
            "distinct_policy_codes": len(policy_codes),
            "policy_codes": policy_codes,
            "distinct_quorums": quorums,
            "allow_self_approval_values": self_approval,
            "earliest_created_at": policy_first,
            "latest_created_at": policy_last,
        },
        records={
            "table": LEGACY_RECORD_TABLE,
            "row_count": record_count,
            "distinct_subject_types": len(subject_types),
            "subject_types": subject_types,
            "distinct_approval_groups": distinct_groups,
            "distinct_policy_references": distinct_policy_refs,
            "distinct_approvers": distinct_approvers,
            "earliest_created_at": record_first,
            "latest_created_at": record_last,
        },
    )


def _extent(connection: Any, table: str) -> tuple[str | None, str | None]:
    """Earliest and latest STORED `created_at`.

    A durable column recorded at insert time — a fact about the rows. Not
    `now()`, which would be a reading of the inventory's own clock and would
    make two runs over one database differ.
    """
    # The table name is a module constant, never caller input.
    row = connection.execute(
        text(f"SELECT min(created_at), max(created_at) FROM {table}")  # noqa: S608
    ).one()
    return _render_timestamp(row[0]), _render_timestamp(row[1])


def collect_module_readiness(connection: Any) -> ModuleReadiness:
    """The module tables are still empty, and still SELECT-only.

    Deliberately separate from the legacy estate. This is a statement about the
    shadow phase holding, not a measurement of anything.
    """
    tables: list[Mapping[str, Any]] = []
    for table in MODULE_TABLES:
        qualified = f"{MODULE_SCHEMA}.{table}"
        exists = bool(
            _scalar(
                connection,
                "SELECT to_regclass(:q) IS NOT NULL",
                q=qualified,
            )
        )
        # The qualified name is built from module constants, never from input.
        row_count = (
            int(_scalar(connection, f"SELECT count(*) FROM {qualified}"))  # noqa: S608
            if exists
            else None
        )
        online_select = (
            _holds(connection, ONLINE_ROLE, qualified, "SELECT") if exists else None
        )
        online_writes = (
            sorted(
                privilege
                for privilege in WRITE_PRIVILEGES
                if _holds(connection, ONLINE_ROLE, qualified, privilege)
            )
            if exists
            else []
        )
        tenant_any = (
            sorted(
                privilege
                for privilege in ("SELECT", *WRITE_PRIVILEGES)
                if _holds(connection, TENANT_ROLE, qualified, privilege)
            )
            if exists
            else []
        )
        tables.append(
            {
                "table": qualified,
                "exists": exists,
                "row_count": row_count,
                "online_role_can_select": online_select,
                "online_role_write_privileges": online_writes,
                "tenant_role_privileges": tenant_any,
                "ok": bool(
                    exists
                    and row_count == 0
                    and online_select
                    and not online_writes
                    and not tenant_any
                ),
            }
        )
    return ModuleReadiness(tables=tuple(tables))


def _holds(connection: Any, role: str, qualified: str, privilege: str) -> bool:
    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in _COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return bool(
        _scalar(connection, statement, role=role, rel=qualified, priv=privilege)
    )


# ── Evidence rendering ──────────────────────────────────────────────────────


def _canonical(payload: object) -> str:
    """Canonical JSON: sorted keys, no whitespace, ASCII-escaped.

    Sorted keys are what make two runs byte-identical without depending on
    dictionary insertion order surviving a refactor.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def render_evidence(estate: LegacyEstate, readiness: ModuleReadiness) -> str:
    """The inventory document: canonical JSON with a digest over its payload.

    Both observations appear as SECTIONS. Nothing is derived across them — see
    the module docstring for why a legacy-versus-module number would be
    meaningless and misleading at once.

    Takes both objects only to place them side by side; it reads no field of one
    against the other, and returns text rather than a combined value, so there is
    nothing here a caller could mistake for a comparison.
    """
    payload = {
        "legacy_estate": {
            "policies": dict(estate.policies),
            "records": dict(estate.records),
            "is_empty": estate.is_empty,
        },
        "module_readiness": {
            "tables": [dict(table) for table in readiness.tables],
            "ok": readiness.ok,
        },
    }
    body = _canonical(payload)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return _canonical(
        {
            "document": DOCUMENT,
            "version": DOCUMENT_VERSION,
            "payload_digest": f"sha256:{digest}",
            "payload": payload,
        }
    )


__all__ = [
    "DOCUMENT",
    "DOCUMENT_VERSION",
    "LEGACY_RECORD_TABLE",
    "LEGACY_POLICY_TABLE",
    "LEGACY_TABLES",
    "MODULE_SCHEMA",
    "MODULE_TABLES",
    "ONLINE_ROLE",
    "TENANT_ROLE",
    "TIMESTAMP_FORMAT",
    "WRITE_PRIVILEGES",
    "LegacyEstate",
    "ModuleReadiness",
    "collect_legacy_estate",
    "collect_module_readiness",
    "render_evidence",
]
