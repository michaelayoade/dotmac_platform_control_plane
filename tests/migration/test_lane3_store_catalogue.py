"""CP-1 / CP-4 / CP-5: what `v023_lane3_store` builds, proven on the live catalogue.

No Foundation needed: this file runs in the ordinary Postgres step. Three things:

* the CLOCK: the migration's `cp_lane3.store_now()` is exactly `clock_timestamp()`
  (a `pg_get_functiondef` digest the E10a read-back checks again on production);
* the TABLES: grammar CHECKs, trigger-stamped instants, append-only evidence, the
  deliberately absent UNIQUEs, one destruction per receipt;
* the PRIVILEGES (design 3.5): the per-run consumption role created from the exact
  `consumption_role_spec` statements holds NOTHING in `cp_lane3`, nor do PUBLIC,
  `app_user` or `platform_api`; the lease role created from `lease_role_spec` holds
  exactly USAGE plus the eight functions; and both proofs, the revocation and the
  watchdog's lease kind are exercised against real PostgreSQL.

`app_admin` is NOT in the zero-privilege list the design names. It is the migration
owner and so owns every `cp_lane3` object (the function owner is the migration role,
F-G); the test pins that it owns exactly those objects and that no runtime role
inherits anything through it.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    OperationalError,
    ProgrammingError,
)

from vendor_cp.deployment import consumption_role_spec as consumption_spec
from vendor_cp.deployment import consumption_scope as scope
from vendor_cp.deployment import consumption_watchdog as watchdog
from vendor_cp.deployment import lane3_store_integrity as integrity
from vendor_cp.deployment import lease_role_check as role_check
from vendor_cp.deployment import lease_role_spec as lease_spec
from vendor_cp.deployment.target_refusals import FoundationBindingsUnavailable


def _support() -> Any:
    name = "lane3_cp_support"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "unit" / "lane3_cp_support.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: sha256 of `pg_get_functiondef('cp_lane3.store_now()')` as the migration creates it.
STORE_NOW_DEFINITION_SHA256 = (
    "a24607462886a8a2aece5779354304e2f786ae706db0e9c8d1831eb4b82f9cc6"
)
LANE3_TABLES = (
    "e10_destructions",
    "e10_receipts",
    "host_current_lease",
    "host_lease_releases",
    "host_leases",
    "run_bindings",
)
INTERNAL_FUNCTIONS = (
    "forbid_current_lease_removal()",
    "guard_current_lease_update()",
    "guard_lease_update()",
    "require_any_binding()",
    "require_binding(text, text)",
    "require_host_binding(text)",
    "stamp_binding_time()",
    "stamp_destruction_time()",
    "stamp_receipt_time()",
    "stamp_release_time()",
    "store_now()",
)


@pytest.fixture
def case(lane3_cases: Any) -> Any:
    return lane3_cases.new()


def _scalar(db: Any, sql: str, **params: Any) -> Any:
    with db.admin.begin() as conn:
        return conn.execute(text(sql), params).scalar_one()


# ── the clock ───────────────────────────────────────────────────────────────


def test_the_migrations_store_now_is_exactly_clock_timestamp(
    lane3_template: str, case: Any
) -> None:
    """Asserted on a database whose clock the case has NOT replaced: the template."""
    # The per-case database replaces `store_now` with the frozen clock. The
    # template does not, and every case is cloned from it, so read it there.
    from sqlalchemy.engine import make_url

    url = make_url(str(case.admin.url)).set(database=lane3_template)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT pg_get_functiondef(p.oid), p.prosrc, p.provolatile, "
                    "p.prosecdef, l.lanname FROM pg_proc p JOIN pg_language l "
                    "ON l.oid = p.prolang JOIN pg_namespace n ON n.oid = "
                    "p.pronamespace WHERE n.nspname = 'cp_lane3' "
                    "AND p.proname = 'store_now'"
                )
            ).one()
    finally:
        engine.dispose()
    definition, source, volatility, definer, language = row
    assert (
        hashlib.sha256(definition.encode()).hexdigest() == STORE_NOW_DEFINITION_SHA256
    )
    assert source.strip() == "SELECT clock_timestamp()"
    assert volatility == "v"  # VOLATILE: a STABLE one would freeze inside a statement
    assert definer is False
    assert language == "sql"


# ── the schema and its functions ────────────────────────────────────────────


def test_the_schema_holds_exactly_the_six_tables(case: Any) -> None:
    with case.admin.begin() as conn:
        tables = sorted(
            conn.execute(
                text(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON "
                    "n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' "
                    "AND c.relkind = 'r' AND c.relname <> 'clock'"
                )
            ).scalars()
        )
    assert tables == sorted(LANE3_TABLES)


def test_every_function_is_pinned_definer_or_a_plain_clock_and_none_is_public(
    case: Any,
) -> None:
    with case.admin.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT p.proname || '(' || oidvectortypes(p.proargtypes) || ')', "
                "p.prosecdef, p.proconfig, "
                "has_function_privilege('public', p.oid, 'EXECUTE'), "
                "pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_namespace n "
                "ON n.oid = p.pronamespace WHERE n.nspname = 'cp_lane3'"
            )
        ).all()
    by_name = {r[0]: r for r in rows}
    lease = {
        s.replace("timestamptz", "timestamp with time zone")
        for s in lease_spec.LEASE_FUNCTIONS
    }
    assert set(by_name) - lease == {
        s.replace("timestamptz", "timestamp with time zone") for s in INTERNAL_FUNCTIONS
    } | ({"store_now()"} & set(by_name))
    for name, definer, config, public, owner in (
        (r[0], r[1], r[2], r[3], r[4]) for r in rows
    ):
        assert public is False, f"{name} is executable by PUBLIC"
        assert owner == "app_admin" or owner == "postgres", name
        if name in lease:
            assert definer is True, name
            assert config is not None and any(
                "search_path=pg_catalog, cp_lane3, pg_temp" in item for item in config
            ), name


def test_no_function_body_deletes_or_truncates(case: Any) -> None:
    """Rule 25: a SECURITY DEFINER body that deletes from a retained table is an
    escape the revoke cannot see. These bodies never mention it."""
    with case.admin.begin() as conn:
        sources = conn.execute(
            text(
                "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = "
                "p.pronamespace WHERE n.nspname = 'cp_lane3' AND p.prosecdef"
            )
        ).scalars()
        for source in sources:
            assert "delete" not in source.lower()
            assert "truncate" not in source.lower()
            assert "execute" not in source.lower().replace("execute function", "")


def test_the_function_set_the_role_spec_grants_is_the_catalogues_set(case: Any) -> None:
    with case.admin.begin() as conn:
        found = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT p.proname || '(' || oidvectortypes(p.proargtypes) || ')' "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'cp_lane3' AND p.prosecdef "
                    "AND p.proname <> 'store_now' "
                    "AND p.proname NOT LIKE 'require\\_%' ESCAPE '\\' "
                    "AND p.proname NOT LIKE 'guard\\_%' ESCAPE '\\' "
                    "AND p.proname NOT LIKE 'stamp\\_%' ESCAPE '\\' "
                    "AND p.proname NOT LIKE 'forbid\\_%' ESCAPE '\\'"
                )
            )
        }
    assert {role_check._normalise(s) for s in lease_spec.LEASE_FUNCTIONS} == {
        role_check._normalise(s) for s in found
    }


# ── the tables ──────────────────────────────────────────────────────────────

_KEY = bytes(range(32))
_B64 = base64.urlsafe_b64encode(_KEY).decode().rstrip("=")
_FP = "sha256:" + hashlib.sha256(_KEY).hexdigest()


def _receipt_values(**override: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "ref": f"e10-{uuid.uuid4()}",
        "alias": "vm-alpha",
        "host": "host-a",
        "machine": "0" * 32,
        "ssh": "SHA256:" + "A" * 43,
        "slot": None,
        "key": _B64,
        "fp": _FP,
        "enrolment": str(uuid.uuid4()),
        "pointer": "bao://transit-a2-hi-vm-alpha-1/keys/incarnation",
        "by": "test",
    }
    values.update(override)
    return values


_INSERT_RECEIPT = (
    "INSERT INTO cp_lane3.e10_receipts (receipt_ref, vm_alias, host_id, machine_id, "
    "ssh_host_key_fingerprint, vm_slot, incarnation_public_key_b64url, "
    "incarnation_fingerprint, enrolment_uuid, key_custody_pointer, recorded_by) "
    "VALUES (:ref, :alias, :host, :machine, :ssh, :slot, :key, :fp, "
    "CAST(:enrolment AS uuid), :pointer, :by)"
)


def _insert(db: Any, **override: Any) -> str:
    values = _receipt_values(**override)
    with db.admin.begin() as conn:
        conn.execute(text(_INSERT_RECEIPT), values)
    return str(values["ref"])


def test_a_well_formed_receipt_is_accepted_and_its_instant_is_the_database_clock(
    case: Any,
) -> None:
    ref = _insert(case)
    recorded = _scalar(
        case,
        "SELECT recorded_at FROM cp_lane3.e10_receipts WHERE receipt_ref=:r",
        r=ref,
    )
    assert recorded == case.now()


def test_a_client_supplied_instant_is_ignored(case: Any) -> None:
    ref = f"e10-{uuid.uuid4()}"
    values = _receipt_values(ref=ref)
    with case.admin.begin() as conn:
        conn.execute(
            text(
                _INSERT_RECEIPT.replace(
                    "recorded_by)", "recorded_by, recorded_at)"
                ).replace(":by)", ":by, '1999-01-01')")
            ),
            values,
        )
    recorded = _scalar(
        case,
        "SELECT recorded_at FROM cp_lane3.e10_receipts WHERE receipt_ref=:r",
        r=ref,
    )
    assert recorded == case.now()


@pytest.mark.parametrize(
    "override",
    [
        {"ref": "e10-not-a-uuid"},
        {"ref": "receipt-1"},
        {"alias": "VM"},
        {"alias": ""},
        {"host": "Host-A"},
        {"host": "-h"},
        {"machine": "abc"},
        {"machine": "G" * 32},
        {"ssh": "sha256:" + "a" * 64},
        {"ssh": "SHA256:short"},
        {"slot": "proxmox"},
        {"slot": "node/0"},
        {"key": _B64 + "="},
        {"key": _B64[:-1]},
        {
            "key": _B64[:-1] + "B"
        },  # non-canonical trailing bits: same 32 bytes, other spelling
        {"fp": "sha256:" + "0" * 64},  # does not identify the key
        {"fp": _FP.upper()},
        {"pointer": "https://not-a-pointer"},
        {"pointer": "bao://"},
        {"by": ""},
        {"by": "has space"},
    ],
)
def test_a_malformed_receipt_is_refused_by_the_database_itself(
    case: Any, override: dict[str, Any]
) -> None:
    with pytest.raises(DBAPIError):
        _insert(case, **override)


def test_the_enrolment_uuid_is_unique_but_neither_seq_nor_the_fingerprint_is(
    case: Any,
) -> None:
    """Test receipts need DUPLICATES of the key and of `seq`, so neither carries a
    UNIQUE; the enrolment is Control's row and is one per receipt."""
    shared_enrolment = str(uuid.uuid4())
    _insert(case, enrolment=shared_enrolment)
    with pytest.raises(IntegrityError):
        _insert(case, enrolment=shared_enrolment)
    _insert(case)  # the SAME key and fingerprint under a different enrolment
    with case.admin.begin() as conn:
        constraints = (
            conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = "
                    "'cp_lane3.e10_receipts'::regclass AND contype IN ('u', 'p')"
                )
            )
            .scalars()
            .all()
        )
        indexes = (
            conn.execute(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname='cp_lane3' AND tablename='e10_receipts'"
                )
            )
            .scalars()
            .all()
        )
    flat = " ".join([*constraints, *indexes])
    assert "(seq)" not in flat
    assert "incarnation_fingerprint" not in flat.replace(
        "incarnation_fingerprint = ", ""
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE cp_lane3.e10_receipts SET recorded_by = 'x'",
        "DELETE FROM cp_lane3.e10_receipts",
        "TRUNCATE cp_lane3.e10_receipts CASCADE",
    ],
)
def test_receipts_are_append_only_even_for_the_owner(case: Any, statement: str) -> None:
    _insert(case)
    with pytest.raises(DBAPIError, match="append-only"):
        with case.admin.begin() as conn:
            conn.execute(text(statement))


def test_one_destruction_per_receipt_stamped_by_the_database(case: Any) -> None:
    ref = _insert(case)
    with case.admin.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
                "evidence_digest, recorded_by) VALUES (:r, 'transit_mount_disabled', :d, 'test')"
            ),
            {"r": ref, "d": "sha256:" + "1" * 64},
        )
    assert (
        _scalar(
            case,
            "SELECT destroyed_at FROM cp_lane3.e10_destructions WHERE receipt_ref=:r",
            r=ref,
        )
        == case.now()
    )
    with pytest.raises(IntegrityError):
        with case.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
                    "evidence_digest, recorded_by) VALUES (:r, 'transit_mount_disabled', :d, 'test')"
                ),
                {"r": ref, "d": "sha256:" + "2" * 64},
            )


@pytest.mark.parametrize(
    "columns",
    [
        ("'other_route'", "NULL", "NULL"),
        ("'transit_mount_disabled'", "gen_random_uuid()", "NULL"),
        ("'transit_mount_disabled'", "NULL", "'sha256:' || repeat('3', 64)"),
        ("'transit_mount_disabled'", "NULL", "'sha256:short'"),
    ],
)
def test_a_destruction_is_a_transit_mount_disable_with_dispatch_and_digest_together(
    case: Any, columns: tuple[str, str, str]
) -> None:
    ref = _insert(case)
    route, dispatch, digest = columns
    with pytest.raises(DBAPIError):
        with case.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
                    f"dispatch_id, installed_attestation_digest, evidence_digest, "
                    f"recorded_by) VALUES (:r, {route}, {dispatch}, {digest}, :d, 'test')"
                ),
                {"r": ref, "d": "sha256:" + "4" * 64},
            )


def _seed_every_table(db: Any) -> None:
    """One row in every table, written by the owner (the way the functions would)."""
    ref = _insert(db)
    lease = "00000000-0000-4000-8000-000000000001"
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
                "evidence_digest, recorded_by) VALUES "
                "(:r, 'transit_mount_disabled', :d, 't')"
            ),
            {"r": ref, "d": "sha256:" + "5" * 64},
        )
        conn.execute(
            text(
                "INSERT INTO cp_lane3.run_bindings (role_name, host_id, "
                "authorization_run, valid_until, recorded_by) VALUES "
                "('l3_seed_role', 'host-a', 'run-1', :u, 't')"
            ),
            {"u": db.now() + timedelta(hours=1)},
        )
        conn.execute(
            text("INSERT INTO cp_lane3.host_current_lease (host_id) VALUES ('host-a')")
        )
        conn.execute(
            text(
                "INSERT INTO cp_lane3.host_leases (lease_id, host_id, "
                "authorization_run, controller_identity, workload_principal, "
                "e10_receipt_ref, acquired_at, expires_at, ttl_seconds) VALUES "
                "(CAST(:l AS uuid), 'host-a', 'run-1', :c, 'principal', :r, :a, :e, 60)"
            ),
            {
                "l": lease,
                "c": "SHA256:" + "A" * 43,
                "r": ref,
                "a": db.now(),
                "e": db.now() + timedelta(seconds=60),
            },
        )
        conn.execute(
            text(
                "INSERT INTO cp_lane3.host_lease_releases (lease_id, "
                "record_released_at, host_mutated, release_bytes, release_digest) "
                "VALUES (CAST(:l AS uuid), :a, true, CAST('{}' AS bytea), :d)"
            ),
            {"l": lease, "a": db.now(), "d": "sha256:" + "6" * 64},
        )


_MUTATIONS = {
    "e10_receipts": "recorded_by = 'x'",
    "e10_destructions": "recorded_by = 'x'",
    "host_lease_releases": "host_mutated = false",
    "run_bindings": "recorded_by = 'x'",
    "host_leases": "ttl_seconds = 30",
}


@pytest.mark.parametrize("table", sorted(_MUTATIONS))
def test_the_evidence_tables_refuse_update_delete_and_truncate_even_with_rows(
    case: Any, table: str
) -> None:
    _seed_every_table(case)
    for statement in (
        f"UPDATE cp_lane3.{table} SET {_MUTATIONS[table]}",
        f"DELETE FROM cp_lane3.{table}",
        f"TRUNCATE cp_lane3.{table} CASCADE",
    ):
        with pytest.raises(DBAPIError, match="append-only|only the one-time"):
            with case.admin.begin() as conn:
                conn.execute(text(statement))


def _privileges(db: Any, role: str) -> dict[str, list[str]]:
    """Every privilege `role` holds in `cp_lane3`, by kind. All lists must be empty."""
    held: dict[str, list[str]] = {
        "schema": [],
        "table": [],
        "column": [],
        "sequence": [],
        "function": [],
    }
    with db.admin.begin() as conn:
        for kind in ("USAGE", "CREATE"):
            if conn.execute(
                text("SELECT has_schema_privilege(:r, 'cp_lane3', :k)"),
                {"r": role, "k": kind},
            ).scalar_one():
                held["schema"].append(kind)
        for relation, relkind in conn.execute(
            text(
                "SELECT c.oid::regclass::text, c.relkind FROM pg_class c JOIN pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' AND c.relkind IN ('r','S')"
            )
        ).all():
            if relkind == "r":
                for kind in (
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                ):
                    if conn.execute(
                        text(
                            "SELECT has_table_privilege(:r, CAST(:rel AS regclass), :k)"
                        ),
                        {"r": role, "rel": relation, "k": kind},
                    ).scalar_one():
                        held["table"].append(f"{relation}:{kind}")
                if conn.execute(
                    text(
                        "SELECT has_any_column_privilege(:r, CAST(:rel AS regclass), "
                        "'SELECT, INSERT, UPDATE, REFERENCES')"
                    ),
                    {"r": role, "rel": relation},
                ).scalar_one():
                    held["column"].append(relation)
            else:
                for kind in ("USAGE", "SELECT", "UPDATE"):
                    if conn.execute(
                        text(
                            "SELECT has_sequence_privilege(:r, CAST(:rel AS regclass), :k)"
                        ),
                        {"r": role, "rel": relation, "k": kind},
                    ).scalar_one():
                        held["sequence"].append(f"{relation}:{kind}")
        for signature in conn.execute(
            text(
                "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON "
                "n.oid = p.pronamespace WHERE n.nspname = 'cp_lane3'"
            )
        ).scalars():
            if conn.execute(
                text(
                    "SELECT has_function_privilege(:r, CAST(:f AS regprocedure), 'EXECUTE')"
                ),
                {"r": role, "f": signature},
            ).scalar_one():
                held["function"].append(signature)
    return held


def _empty(held: dict[str, list[str]]) -> bool:
    return not any(held.values())


@pytest.mark.parametrize("role", ["public", "app_user", "platform_api"])
def test_no_runtime_role_and_not_public_holds_anything_in_the_lane3_schema(
    case: Any, role: str
) -> None:
    assert _empty(_privileges(case, role)), _privileges(case, role)


def test_app_admin_is_the_migration_owner_and_owns_the_schema_objects_only_as_owner(
    case: Any,
) -> None:
    with case.admin.begin() as conn:
        owners = set(
            conn.execute(
                text(
                    "SELECT pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n "
                    "ON n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' "
                    "AND c.relkind IN ('r', 'S') AND c.relname <> 'clock'"
                )
            ).scalars()
        )
        grantees = set(
            conn.execute(
                text(
                    "SELECT coalesce(pg_get_userbyid(a.grantee), 'PUBLIC') FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace, "
                    "LATERAL aclexplode(c.relacl) a WHERE n.nspname = 'cp_lane3' "
                    "AND c.relkind = 'r'"
                )
            ).scalars()
        )
    assert len(owners) == 1  # one owner: the migration role
    assert grantees <= owners  # and no ACL entry for anybody else
    # A role that merely MEMBERS nothing inherits nothing: platform_api and app_user
    # are not members of the owner.
    for role in ("platform_api", "app_user"):
        assert (
            _scalar(
                case,
                "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = :r",
                r=role,
            )
            == 0
        )


def _create_consumption_role(db: Any) -> tuple[str, str]:
    dispatch = str(uuid.uuid4())
    role = "run_c_" + uuid.uuid4().hex[:12]
    now = datetime.now(UTC)
    verifier = consumption_spec.scram_verifier(
        "c" * 24, salt=bytes(range(16)), iterations=4096
    )
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for statement in consumption_spec.guard_enable_sql():
            if statement not in ("BEGIN", "COMMIT"):
                conn.exec_driver_sql(statement)
        for statement in consumption_spec.executable_creation_sql(
            role,
            dispatch_id=dispatch,
            scram_verifier=verifier,
            valid_until=now + timedelta(hours=3),
            now=now,
        ):
            if statement not in ("BEGIN", "COMMIT"):
                conn.exec_driver_sql(statement)
    db.roles.append(role)
    return role, dispatch


def test_the_consumption_role_from_the_exact_spec_holds_nothing_in_the_lane3_schema(
    case: Any,
) -> None:
    role, _ = _create_consumption_role(case)
    assert _empty(_privileges(case, role)), _privileges(case, role)


def test_as_the_consumption_role_every_lane3_call_is_42501(
    case: Any, lane3_cases: Any
) -> None:
    role, _ = _create_consumption_role(case)
    engine = create_engine(case._url_for_role(role))
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == role
            for statement in (
                "SELECT cp_lane3.store_now()",
                "SELECT * FROM cp_lane3.host_leases",
                "SELECT * FROM cp_lane3.e10_receipts",
                "SELECT cp_lane3.acquire('host-a', 'run-1', 'c', 'p', 60, '{}'::jsonb, NULL, NULL)",
                "SELECT cp_lane3.database_time()",
                "INSERT INTO cp_lane3.run_bindings (role_name, host_id, authorization_run, valid_until, recorded_by) "
                "VALUES ('x', 'host-a', 'r', now(), 'x')",
            ):
                with pytest.raises(ProgrammingError) as caught:
                    conn.exec_driver_sql(statement)
                assert (
                    getattr(caught.value.orig, "sqlstate", None) == "42501"
                ), statement
                conn.rollback()
    finally:
        engine.dispose()


def test_the_real_catalogue_proof_of_the_consumption_role_passes_and_refuses_a_lane3_grant(
    case: Any,
) -> None:
    role, dispatch = _create_consumption_role(case)
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=case.admin)
    scope.prove_scoped_role(factory, dispatch_id=dispatch, role=role)
    for grant in (
        f'GRANT USAGE ON SCHEMA cp_lane3 TO "{role}"',
        f'GRANT SELECT ON cp_lane3.host_leases TO "{role}"',
        f'GRANT SELECT (lease_bytes) ON cp_lane3.host_leases TO "{role}"',
        f'GRANT EXECUTE ON FUNCTION cp_lane3.store_now() TO "{role}"',
        f'GRANT USAGE ON SEQUENCE cp_lane3.e10_receipts_seq_seq TO "{role}"',
    ):
        with case.admin.begin() as conn:
            conn.exec_driver_sql(f'REVOKE ALL ON SCHEMA cp_lane3 FROM "{role}"')
        with case.admin.begin() as conn:
            conn.exec_driver_sql(grant)
            if "SCHEMA" not in grant:
                conn.exec_driver_sql(f'GRANT USAGE ON SCHEMA cp_lane3 TO "{role}"')
        with pytest.raises(FoundationBindingsUnavailable) as caught:
            scope.prove_scoped_role(factory, dispatch_id=dispatch, role=role)
        assert (
            caught.value.code is scope.TargetRefusal.CONSUMPTION_ROLE_OVERBROAD
        ), grant
        with case.admin.begin() as conn:
            conn.exec_driver_sql(f'DROP OWNED BY "{role}"') if False else None
            conn.exec_driver_sql(f'REVOKE ALL ON SCHEMA cp_lane3 FROM "{role}"')
            conn.exec_driver_sql(
                f'REVOKE ALL ON ALL TABLES IN SCHEMA cp_lane3 FROM "{role}"'
            )
            conn.exec_driver_sql(
                f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA cp_lane3 FROM "{role}"'
            )
            conn.exec_driver_sql(
                f'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA cp_lane3 FROM "{role}"'
            )


def _create_lease_role(db: Any, *, host: str = "host-a", run: str = "run-1") -> str:
    role = "l3_chk_" + uuid.uuid4().hex[:12]
    now = datetime.now(UTC)
    verifier = lease_spec.scram_verifier(
        "l" * 24, salt=bytes(range(16)), iterations=4096
    )
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for statement in lease_spec.executable_creation_sql(
            role,
            host_id=host,
            authorization_run=run,
            scram_verifier_value=verifier,
            valid_until=now + timedelta(hours=3),
            now=now,
        ):
            if statement not in ("BEGIN", "COMMIT"):
                conn.exec_driver_sql(statement)
    db.roles.append(role)
    return role


def _prove(db: Any, role: str, host: str = "host-a", run: str = "run-1") -> None:
    from sqlalchemy.orm import sessionmaker

    role_check.prove_lease_role(
        sessionmaker(bind=db.admin), role=role, host_id=host, authorization_run=run
    )


def test_the_lease_role_from_the_exact_spec_is_proven_and_holds_only_the_functions(
    case: Any,
) -> None:
    role = _create_lease_role(case)
    _prove(case, role)
    held = _privileges(case, role)
    assert held["schema"] == ["USAGE"]
    assert not held["table"] and not held["column"] and not held["sequence"]
    assert {
        role_check._normalise(f.removeprefix("cp_lane3.")) for f in held["function"]
    } == {role_check._normalise(f) for f in lease_spec.LEASE_FUNCTIONS}


def test_the_lease_proof_refuses_each_way_the_role_could_be_widened(case: Any) -> None:
    def refused(role: str, code: str, host: str = "host-a", run: str = "run-1") -> None:
        with pytest.raises(role_check.LeaseRoleRefused) as caught:
            _prove(case, role, host, run)
        assert caught.value.code == code

    cases: list[tuple[str, str]] = [
        ("GRANT SELECT ON cp_lane3.host_leases TO {r}", "lease-role-table-privilege"),
        (
            "GRANT SELECT (lease_bytes) ON cp_lane3.host_leases TO {r}",
            "lease-role-column-privilege",
        ),
        (
            "GRANT USAGE ON SEQUENCE cp_lane3.e10_receipts_seq_seq TO {r}",
            "lease-role-sequence-privilege",
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_lane3.store_now() TO {r}",
            "lease-role-function-set",
        ),
        ("GRANT USAGE ON SCHEMA mod_deploy TO {r}", "lease-role-other-schema-usage"),
        ("ALTER ROLE {r} CONNECTION LIMIT 9", "lease-role-connection-limit"),
        ("ALTER ROLE {r} SET log_statement = 'none'", "lease-role-not-logged"),
        ("ALTER ROLE {r} INHERIT", "lease-role-inherit"),
        ("ALTER ROLE {r} CREATEDB", "lease-role-createdb"),
        ("GRANT app_user TO {r}", "lease-role-membership"),
        ("REVOKE USAGE ON SCHEMA cp_lane3 FROM {r}", "lease-role-no-schema-usage"),
        (
            "REVOKE EXECUTE ON FUNCTION cp_lane3.standing(text) FROM {r}",
            "lease-role-function-set",
        ),
    ]
    for statement, code in cases:
        role = _create_lease_role(case)
        with case.admin.begin() as conn:
            conn.exec_driver_sql(statement.format(r=f'"{role}"'))
        refused(role, code)
    # A role bound to another host, or another run, is not THIS run's role.
    role = _create_lease_role(case)
    refused(role, "lease-role-not-bound", host="host-b")
    refused(role, "lease-role-not-bound", run="run-9")
    # A second binding is over-broad.
    with case.admin.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO cp_lane3.run_bindings (role_name, host_id, authorization_run, "
                "valid_until, recorded_by) VALUES (:r, 'host-b', 'run-1', :u, 't')"
            ),
            {"r": role, "u": case.now() + timedelta(hours=1)},
        )
    refused(role, "lease-role-bound-elsewhere")


def test_the_lease_proof_requires_connect_on_the_database_it_is_checked_in(
    case: Any,
) -> None:
    """PUBLIC holds CONNECT by default, so a hardened cluster that revokes it makes
    a role that is otherwise perfect unable to connect: the proof must say so."""
    role = _create_lease_role(case)
    _prove(case, role)
    with case.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        database = conn.exec_driver_sql("SELECT current_database()").scalar_one()
        conn.exec_driver_sql(f'REVOKE CONNECT ON DATABASE "{database}" FROM PUBLIC')
        assert (
            conn.exec_driver_sql(
                f"SELECT has_database_privilege('{role}', '{database}', 'CONNECT')"
            ).scalar_one()
            is False
        )
        with pytest.raises(role_check.LeaseRoleRefused) as caught:
            _prove(case, role)
        assert caught.value.code == "lease-role-cannot-connect"
        conn.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{database}" TO "{role}"')
    _prove(case, role)


def test_revocation_leaves_zero_role_session_and_grant_and_the_watchdog_does_it_too(
    case: Any,
) -> None:
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=case.admin)
    for kind in ("spec", "watchdog"):
        role = _create_lease_role(case)
        engine = create_engine(case._url_for_role(role))
        conn = engine.connect()  # a live session the revocation must kill
        assert conn.execute(text("SELECT 1")).scalar_one() == 1
        if kind == "spec":
            with case.admin.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as admin:
                for statement in lease_spec.revocation_sql(role):
                    admin.exec_driver_sql(statement)
                counts = tuple(
                    admin.exec_driver_sql(lease_spec.verification_sql(role)).one()
                )
        else:
            counts = watchdog.revoke(factory, role, "lease")
        with pytest.raises(OperationalError):
            conn.execute(text("SELECT 1"))
        with contextlib.suppress(Exception):
            conn.close()
        engine.dispose()
        assert counts == (0, 0, 0), kind
        assert (
            _scalar(case, "SELECT count(*) FROM pg_roles WHERE rolname = :r", r=role)
            == 0
        )
    # The binding row is append-only evidence and is inert once the role is gone.
    assert (
        _scalar(
            case,
            "SELECT count(*) FROM cp_lane3.run_bindings WHERE role_name = :r",
            r=role,
        )
        == 1
    )


def test_the_hba_block_is_the_designs_and_only_the_tunnel_source_is_accepted() -> None:
    block = lease_spec.pg_hba_block(
        "l3_x_1", database="vendor_cp", cp_bridge_addr="192.0.2.7"
    )
    assert [line.split()[0] for line in block] == ["hostssl", "host", "local"]
    assert os.linesep not in "".join(block)


# ── LOW: every function pins its search_path; one binding per role ───────────


def test_every_function_pins_search_path_with_pg_catalog_first_and_pg_temp_last(
    lane3_template: str, case: Any
) -> None:
    """Including `store_now` and the SECURITY INVOKER trigger functions, which the
    first cut left to the caller's path. Read on the TEMPLATE (the case replaces
    `store_now`)."""
    engine = _template_engine(case, lane3_template)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT p.proname, p.proconfig FROM pg_proc p JOIN pg_namespace "
                    "n ON n.oid = p.pronamespace WHERE n.nspname = 'cp_lane3'"
                )
            ).all()
    finally:
        engine.dispose()
    assert len(rows) == len(INTERNAL_FUNCTIONS) + len(lease_spec.LEASE_FUNCTIONS)
    for name, config in rows:
        paths = [c for c in (config or []) if c.startswith("search_path=")]
        assert len(paths) == 1, name
        parts = [part.strip() for part in paths[0].split("=", 1)[1].split(",")]
        assert parts[0] == "pg_catalog" and parts[-1] == "pg_temp", name


def test_a_role_can_be_bound_once_and_the_constraint_names_the_role(
    lane3_cases: Any,
) -> None:
    """`single_binding=True` keeps the migration's UNIQUE(role_name); the other
    cases relax it for the multi-run conformance handle (see the harness)."""
    db = lane3_cases.new(single_binding=True)
    with db.admin.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO cp_lane3.run_bindings (role_name, host_id, "
                "authorization_run, valid_until, recorded_by) VALUES "
                "('role_one', 'host-a', 'run-1', now() + interval '1 hour', 'test')"
            )
        )
    for host, run in (("host-a", "run-2"), ("host-b", "run-1"), ("host-a", "run-1")):
        with pytest.raises(IntegrityError) as caught, db.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.run_bindings (role_name, host_id, "
                    "authorization_run, valid_until, recorded_by) VALUES "
                    "('role_one', :h, :r, now() + interval '1 hour', 'test')"
                ),
                {"h": host, "r": run},
            )
        assert getattr(caught.value.orig, "sqlstate", None) == "23505"


# ── M5: the in-migration privilege read-back covers the whole schema ─────────


def _migration() -> Any:
    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / ("v023_lane3_store.py")
    )
    spec = importlib.util.spec_from_file_location("v023_lane3_store_for_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ACL_QUERIES = (
    "SCHEMA_ACL_SQL",
    "RELATION_ACL_SQL",
    "COLUMN_ACL_SQL",
    "FUNCTION_ACL_SQL",
    "DEFAULT_ACL_SQL",
)


def _acl_counts(db: Any) -> dict[str, int]:
    module = _migration()
    with db.admin.begin() as conn:
        return {
            name: int(conn.exec_driver_sql(getattr(module, name)).scalar_one())
            for name in ACL_QUERIES
        }


def test_the_migrations_privilege_read_back_is_zero_on_the_migrated_schema(
    case: Any,
) -> None:
    """The migration already ran these in its own transaction (it would have
    raised); on a clone they are zero too, and name every object kind."""
    assert _acl_counts(case) == dict.fromkeys(ACL_QUERIES, 0)


@pytest.mark.parametrize(
    ("statement", "query"),
    [
        ("GRANT USAGE ON SCHEMA cp_lane3 TO platform_api", "SCHEMA_ACL_SQL"),
        ("GRANT USAGE ON SCHEMA cp_lane3 TO PUBLIC", "SCHEMA_ACL_SQL"),
        (
            "GRANT SELECT ON cp_lane3.e10_receipts TO outbox_dispatcher_probe",
            "RELATION_ACL_SQL",
        ),
        ("GRANT SELECT ON cp_lane3.e10_receipts TO PUBLIC", "RELATION_ACL_SQL"),
        (
            "GRANT USAGE ON SEQUENCE cp_lane3.e10_receipts_seq_seq TO PUBLIC",
            "RELATION_ACL_SQL",
        ),
        (
            "GRANT SELECT (host_id) ON cp_lane3.e10_receipts TO outbox_dispatcher_probe",
            "COLUMN_ACL_SQL",
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_lane3.store_now() TO outbox_dispatcher_probe",
            "FUNCTION_ACL_SQL",
        ),
        (
            "GRANT EXECUTE ON FUNCTION cp_lane3.covers(uuid, text) TO PUBLIC",
            "FUNCTION_ACL_SQL",
        ),
        (
            "ALTER DEFAULT PRIVILEGES IN SCHEMA cp_lane3 GRANT SELECT ON TABLES TO PUBLIC",
            "DEFAULT_ACL_SQL",
        ),
    ],
)
def test_the_privilege_read_back_sees_every_kind_of_leak(
    lane3_cases: Any, statement: str, query: str
) -> None:
    db = lane3_cases.new()
    with db.admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.exec_driver_sql(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
            "'outbox_dispatcher_probe') THEN CREATE ROLE outbox_dispatcher_probe; "
            "END IF; END $$"
        )
        conn.exec_driver_sql(statement)
    counts = _acl_counts(db)
    assert counts[query] >= 1, counts
    for other, count in counts.items():
        if other != query:
            assert count == 0, (other, counts)


def test_a_fresh_function_left_at_the_postgres_default_would_be_counted(
    lane3_cases: Any,
) -> None:
    """The default of a function is PUBLIC EXECUTE (`proacl` NULL): the read-back
    expands NULL through `acldefault`, so an un-revoked function cannot hide."""
    db = lane3_cases.new()
    with db.admin.begin() as conn:
        conn.exec_driver_sql(
            "CREATE FUNCTION cp_lane3.stray() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
    assert _acl_counts(db)["FUNCTION_ACL_SQL"] >= 1


# ── M6: every function body and trigger is pinned, in CI and for E10a ────────


def _template_engine(case: Any, template: str) -> Any:
    from sqlalchemy.engine import make_url

    return create_engine(make_url(str(case.admin.url)).set(database=template))


def _violations(engine: Any) -> tuple[str, ...]:
    with engine.connect() as conn:
        return integrity.check_store_integrity(
            lambda sql: conn.execute(text(sql)).all()
        )


def test_the_migrated_store_is_exactly_as_pinned(
    lane3_template: str, case: Any
) -> None:
    engine = _template_engine(case, lane3_template)
    try:
        assert _violations(engine) == ()
    finally:
        engine.dispose()


def test_the_pins_name_every_function_and_trigger_the_catalogue_holds(
    lane3_template: str, case: Any
) -> None:
    engine = _template_engine(case, lane3_template)
    try:
        with engine.connect() as conn:
            functions = {
                r[0]
                for r in conn.execute(
                    text(
                        "SELECT p.proname || '(' || oidvectortypes(p.proargtypes) "
                        "|| ')' FROM pg_proc p JOIN pg_namespace n ON n.oid = "
                        "p.pronamespace WHERE n.nspname = 'cp_lane3'"
                    )
                )
            }
            triggers = {
                r[0]
                for r in conn.execute(
                    text(
                        "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON "
                        "c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = "
                        "c.relnamespace WHERE n.nspname = 'cp_lane3' "
                        "AND NOT t.tgisinternal"
                    )
                )
            }
    finally:
        engine.dispose()
    assert functions == set(integrity.FUNCTION_DEFINITION_SHA256)
    assert triggers == set(integrity.TRIGGERS)
    assert {state for _, state, _ in integrity.TRIGGERS.values()} == {"O"}
    assert integrity.FUNCTION_DEFINITION_SHA256["store_now()"] == (
        STORE_NOW_DEFINITION_SHA256
    )


def test_the_integrity_check_refuses_a_changed_body_a_disabled_trigger_and_extras(
    lane3_cases: Any,
) -> None:
    db = lane3_cases.new()
    # The case database replaces `store_now` with the frozen clock, so that one
    # violation is the baseline here (the template test above proves it clean).
    base = {"function-changed:store_now()"}
    assert set(_violations(db.admin)) == base
    with db.admin.begin() as conn:
        conn.exec_driver_sql(
            "CREATE OR REPLACE FUNCTION cp_lane3.stamp_receipt_time() RETURNS trigger "
            "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
            "AS $$ BEGIN RETURN NEW; END $$"
        )
    assert set(_violations(db.admin)) == base | {
        "function-changed:stamp_receipt_time()"
    }
    with db.admin.begin() as conn:
        conn.exec_driver_sql(
            "ALTER TABLE cp_lane3.e10_receipts "
            "DISABLE TRIGGER trg_e10_receipts_append_only"
        )
    assert "trigger-not-enabled:trg_e10_receipts_append_only" in _violations(db.admin)
    with db.admin.begin() as conn:
        conn.exec_driver_sql(
            "ALTER TABLE cp_lane3.e10_receipts "
            "ENABLE ALWAYS TRIGGER trg_e10_receipts_append_only"
        )
        conn.exec_driver_sql(
            "CREATE FUNCTION cp_lane3.stray() RETURNS int LANGUAGE sql AS 'SELECT 1'"
        )
        conn.exec_driver_sql(
            "CREATE TRIGGER trg_stray BEFORE INSERT ON cp_lane3.e10_receipts "
            "FOR EACH ROW EXECUTE FUNCTION cp_lane3.stamp_receipt_time()"
        )
    found = set(_violations(db.admin))
    assert {
        "trigger-not-enabled:trg_e10_receipts_append_only",
        "function-unpinned:stray()",
        "trigger-unpinned:trg_stray",
    } <= found
    with db.admin.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER trg_stray ON cp_lane3.e10_receipts")
        conn.exec_driver_sql(
            "DROP TRIGGER trg_e10_receipts_stamp ON cp_lane3.e10_receipts"
        )
    found = set(_violations(db.admin))
    assert "trigger-missing:trg_e10_receipts_stamp" in found


def test_the_integrity_check_is_exposed_for_e10a_and_refuses_without_a_dsn(
    capsys: Any,
) -> None:
    assert integrity.main([], {}) == 2
    assert integrity.ADMIN_DSN_ENV in capsys.readouterr().err
