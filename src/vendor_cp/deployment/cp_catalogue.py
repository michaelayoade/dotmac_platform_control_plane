"""Complete raw catalogues and bounded PostgreSQL CHECK parse equivalence.

Raw observations remain distinct. Only changed ordinary local CHECK expression
representations may compare through PostgreSQL's own parser on the restored
relation. Temporary views are never executed and always rolled back.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Literal, TypedDict, cast

import psycopg
from sqlalchemy import Connection, text

from vendor_cp.deploy_agent.contracts import (
    ContractError,
    Digest,
    Identifier,
    _shape,
    canonical_json,
    read_json,
    require,
    sha,
)

CATALOGUE_QUERIES = {
    "bootstrap": "SELECT rolname,oid::bigint,rolsuper FROM pg_roles WHERE oid=10",
    "schemas": """SELECT nspname, pg_get_userbyid(nspowner), nspacl::text
        FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
        ORDER BY nspname""",
    "relations": """SELECT n.nspname,c.relname,c.relkind,pg_get_userbyid(c.relowner),
        c.relrowsecurity,c.relforcerowsecurity,c.relacl::text,c.reloptions
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
        ORDER BY n.nspname,c.relname""",
    "columns": """SELECT n.nspname,c.relname,a.attname,
        format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,
        pg_get_expr(d.adbin,d.adrelid),a.attacl::text
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped AND n.nspname !~ '^pg_'
        AND n.nspname <> 'information_schema' ORDER BY n.nspname,c.relname,a.attnum""",
    "constraints": """SELECT n.nspname,c.relname,k.conname,
        pg_get_constraintdef(k.oid,true), k.contype::text,k.convalidated,
        k.connoinherit,k.condeferrable,k.condeferred,k.conislocal,k.coninhcount,
        pg_get_expr(k.conbin,k.conrelid,false) FROM pg_constraint k
        JOIN pg_namespace n ON n.oid=k.connamespace
        LEFT JOIN pg_class c ON c.oid=k.conrelid
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
        ORDER BY n.nspname,c.relname,k.conname""",
    "indexes": """SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes
        WHERE schemaname !~ '^pg_' AND schemaname <> 'information_schema'
        ORDER BY schemaname,tablename,indexname""",
    "views": """SELECT schemaname,viewname,definition FROM pg_views
        WHERE schemaname !~ '^pg_' AND schemaname <> 'information_schema'
        ORDER BY schemaname,viewname""",
    "functions": """SELECT n.nspname,p.proname,
        pg_get_function_identity_arguments(p.oid),
        pg_get_userbyid(p.proowner),p.proacl::text,p.prosecdef,p.proconfig,
        pg_get_functiondef(p.oid) FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
        AND p.prokind <> 'a' ORDER BY n.nspname,p.proname,
        pg_get_function_identity_arguments(p.oid)""",
    "policies": """SELECT schemaname,tablename,policyname,permissive,roles,
        cmd,qual,with_check
        FROM pg_policies WHERE schemaname !~ '^pg_'
        ORDER BY schemaname,tablename,policyname""",
    "triggers": """SELECT n.nspname,c.relname,t.tgname,
        pg_get_triggerdef(t.oid,true),t.tgenabled
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE NOT t.tgisinternal AND n.nspname !~ '^pg_'
        ORDER BY n.nspname,c.relname,t.tgname""",
    "default-acls": """SELECT pg_get_userbyid(d.defaclrole),n.nspname,
        d.defaclobjtype,d.defaclacl::text FROM pg_default_acl d
        LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
        ORDER BY 1,2,3""",
    "roles": """SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,
        rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolconfig
        FROM pg_roles WHERE rolname !~ '^pg_'
        ORDER BY rolname""",
    "memberships": """SELECT parent.rolname,member.rolname,grantor.rolname,
        m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m
        JOIN pg_roles parent ON parent.oid=m.roleid
        JOIN pg_roles member ON member.oid=m.member
        JOIN pg_roles grantor ON grantor.oid=m.grantor
        ORDER BY 1,2,3""",
}


class ParserObservation(TypedDict):
    server_version_num: int
    cluster_system_identifier: str
    database: Identifier
    search_path: Literal["pg_catalog"]
    standard_conforming_strings: Literal["on"]


class CheckComparison(TypedDict):
    identity: list[str]
    source_row_digest: Digest
    restored_row_digest: Digest
    source_view_definition: str
    restored_view_definition: str


class RestoreComparison(TypedDict):
    schema: Literal["dotmac.cp_catalogue_restore_comparison/1"]
    request_digest: Digest
    host_nonce: str
    source_cluster_system_identifier: str
    source_database: Identifier
    source_catalogue_digest: Digest
    restored_catalogue_digest: Digest
    method: Literal["postgres16-temp-view-parse/1"]
    parser: ParserObservation
    checks: list[CheckComparison]
    restored_catalogue_after_digest: Digest


Catalogue = dict[str, list[list[object]]]
ConstraintIdentity = tuple[str, str | None, str]
ConstraintRows = dict[ConstraintIdentity, list[object]]


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _driver(connection: Connection) -> psycopg.Connection[tuple[object, ...]]:
    require(connection.dialect.name == "postgresql", "catalogue_postgres_required")
    driver = connection.connection.driver_connection
    require(isinstance(driver, psycopg.Connection), "catalogue_psycopg3_required")
    return cast("psycopg.Connection[tuple[object, ...]]", driver)


@contextmanager
def _fixed_deparse(connection: Connection) -> Iterator[None]:
    # psycopg uses a savepoint inside an existing transaction, and BEGIN on an
    # autocommit observer. Forced rollback restores all caller GUCs in both cases.
    with _driver(connection).transaction(force_rollback=True):
        connection.exec_driver_sql("SET LOCAL search_path = 'pg_catalog'")
        connection.exec_driver_sql("SET LOCAL standard_conforming_strings = 'on'")
        yield


def measure_catalogue(connection: Connection) -> bytes:
    """Read all structural/role fields under one reversible deparse context."""
    with _fixed_deparse(connection):
        value = {
            name: [list(row) for row in connection.execute(text(sql))]
            for name, sql in CATALOGUE_QUERIES.items()
        }
        return canonical_json(value)


def _catalogue(raw: bytes) -> Catalogue:
    value = read_json(raw)
    require(set(value) == set(CATALOGUE_QUERIES), "catalogue_categories_incomplete")
    require(canonical_json(value) == raw, "catalogue_not_canonical")
    for rows in value.values():
        require(isinstance(rows, list), "catalogue_rows_invalid")
        for row in cast(list[object], rows):
            require(isinstance(row, list), "catalogue_row_invalid")
    return cast(Catalogue, value)


def _constraints(catalogue: Catalogue) -> ConstraintRows:
    result: ConstraintRows = {}
    for row in catalogue["constraints"]:
        require(len(row) == 12, "catalogue_constraint_shape")
        require(type(row[0]) is str and type(row[2]) is str)
        require(row[1] is None or type(row[1]) is str)
        require(type(row[3]) is str and bool(row[3]) and type(row[4]) is str)
        require(all(type(row[index]) is bool for index in range(5, 10)))
        require(type(row[10]) is int and row[10] >= 0)
        require(row[11] is None or type(row[11]) is str)
        identity = (cast(str, row[0]), cast(str | None, row[1]), cast(str, row[2]))
        require(identity not in result, "catalogue_constraint_identity_duplicate")
        result[identity] = row
    return result


def _changed_checks(
    source: Catalogue, restored: Catalogue
) -> list[tuple[ConstraintIdentity, list[object], list[object]]]:
    for name in CATALOGUE_QUERIES:
        if name != "constraints":
            require(source[name] == restored[name], "catalogue_noncheck_mismatch")
    original, fresh = _constraints(source), _constraints(restored)
    require(set(original) == set(fresh), "catalogue_constraint_inventory_mismatch")
    relations: dict[tuple[object, object], object] = {}
    for relation in restored["relations"]:
        require(len(relation) == 8, "catalogue_relation_shape")
        require(
            all(type(relation[index]) is str for index in range(3)),
            "catalogue_relation_shape",
        )
        key = relation[0], relation[1]
        require(key not in relations, "catalogue_relation_identity_duplicate")
        relations[key] = relation[2]
    result = []
    # Canonical JSON gives a deterministic ordering even for domain table=None.
    for identity in sorted(original, key=lambda value: canonical_json(value)):
        one, two = original[identity], fresh[identity]
        if one == two:
            continue
        require(
            one[4] == two[4] == "c"
            and one[9] is two[9] is True
            and one[10] == two[10] == 0
            and relations.get((identity[0], identity[1])) == "r"
            and isinstance(identity[1], str),
            "catalogue_changed_constraint_unsupported",
        )
        require(
            all(
                one[index] == two[index] for index in range(12) if index not in {3, 11}
            ),
            "catalogue_constraint_flags_mismatch",
        )
        require(
            isinstance(one[11], str)
            and bool(one[11].strip())
            and isinstance(two[11], str)
            and bool(two[11].strip()),
            "catalogue_check_expression_absent",
        )
        result.append((identity, one, two))
    return result


def _validate_context(
    request_digest: str,
    host_nonce: str,
    expected_source_cluster: str,
    expected_source_database: str,
) -> None:
    sha(request_digest)
    require(re.fullmatch(r"[0-9a-f]{64}", host_nonce) is not None)
    require(
        expected_source_cluster.isascii()
        and expected_source_cluster.isdecimal()
        and int(expected_source_cluster) > 0
    )
    _shape(expected_source_database, Identifier)


def verify_restore_comparison(
    proof: bytes,
    source_catalogue: bytes,
    restored_catalogue: bytes,
    *,
    request_digest: str,
    host_nonce: str,
    expected_source_cluster: str,
    expected_source_database: str,
) -> None:
    """Verify closed retained bindings; root measurement provenance is external."""
    _validate_context(
        request_digest, host_nonce, expected_source_cluster, expected_source_database
    )
    document = read_json(proof)
    _shape(document, RestoreComparison)
    value = cast(RestoreComparison, document)
    require(canonical_json(value) == proof, "catalogue_proof_not_canonical")
    require(
        value["request_digest"] == request_digest
        and value["host_nonce"] == host_nonce
        and value["source_cluster_system_identifier"] == expected_source_cluster
        and value["source_database"] == expected_source_database,
        "catalogue_comparison_binding_mismatch",
    )
    require(
        value["source_catalogue_digest"] == _digest(source_catalogue)
        and value["restored_catalogue_digest"] == _digest(restored_catalogue)
        and value["restored_catalogue_after_digest"] == _digest(restored_catalogue),
        "catalogue_comparison_digest_mismatch",
    )
    parser = value["parser"]
    require(160000 <= parser["server_version_num"] < 170000, "catalogue_parser_version")
    cluster = parser["cluster_system_identifier"]
    require(cluster.isascii() and cluster.isdecimal() and int(cluster) > 0)
    require(
        (cluster, parser["database"])
        != (expected_source_cluster, expected_source_database),
        "catalogue_parser_is_source_database",
    )
    changed = _changed_checks(
        _catalogue(source_catalogue), _catalogue(restored_catalogue)
    )
    entries: dict[ConstraintIdentity, CheckComparison] = {}
    for entry in value["checks"]:
        names = entry["identity"]
        require(len(names) == 3 and all(bool(name) for name in names))
        key = names[0], names[1], names[2]
        require(key not in entries, "catalogue_check_proof_duplicate")
        entries[key] = entry
    require(
        set(entries) == {identity for identity, _, _ in changed},
        "catalogue_check_proof_coverage",
    )
    for identity, original, fresh in changed:
        entry = entries[identity]
        require(
            entry["source_row_digest"] == _digest(canonical_json(original))
            and entry["restored_row_digest"] == _digest(canonical_json(fresh)),
            "catalogue_check_row_binding_mismatch",
        )
        require(
            bool(entry["source_view_definition"].strip())
            and entry["source_view_definition"] == entry["restored_view_definition"],
            "catalogue_check_parse_mismatch",
        )


def _parse_view(
    connection: Connection, schema: str, table: str, expression: str
) -> str:
    quote = connection.dialect.identifier_preparer.quote
    name = "cp_restore_" + secrets.token_hex(16)
    statement = (
        "CREATE TEMP VIEW "  # noqa: S608 -- quoted identifiers; expression parsed once via extended protocol
        + quote(name)
        + " AS SELECT ("
        + expression
        + ") AS constraint_value FROM "
        + quote(schema)
        + "."
        + quote(table)
    )  # noqa: S608 -- identifiers quoted; untrusted expression uses single-statement extended protocol
    # prepare=True forces PostgreSQL extended protocol to reject multiple
    # statements before executing any statement. Views are parsed, never read.
    with _driver(connection).cursor() as cursor:
        cursor.execute(statement, prepare=True)
    definition = connection.execute(
        text(
            "SELECT pg_get_viewdef(c.oid,false) FROM pg_class c "
            "WHERE c.relnamespace=pg_my_temp_schema() "
            "AND c.relname=:name AND c.relkind='v'"
        ),
        {"name": name},
    ).scalar_one()
    require(isinstance(definition, str) and bool(definition.strip()))
    return cast(str, definition)


def capture_restore_comparison(
    connection: Connection,
    source_catalogue: bytes,
    restored_catalogue: bytes,
    *,
    request_digest: str,
    host_nonce: str,
    expected_source_cluster: str,
    expected_source_database: str,
) -> bytes:
    """Parse changed CHECKs on the independently measured restored database."""
    _validate_context(
        request_digest, host_nonce, expected_source_cluster, expected_source_database
    )
    changed = _changed_checks(
        _catalogue(source_catalogue), _catalogue(restored_catalogue)
    )
    require(
        not _driver(connection).autocommit and connection.in_transaction(),
        "catalogue_parser_transaction_required",
    )
    require(
        measure_catalogue(connection) == restored_catalogue,
        "catalogue_live_restore_mismatch",
    )
    checks: list[CheckComparison] = []
    nested = connection.begin_nested()
    try:
        with _fixed_deparse(connection):
            connection.exec_driver_sql("SET LOCAL statement_timeout = '10s'")
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            row = connection.execute(
                text(
                    "SELECT current_setting('server_version_num')::int, "
                    "system_identifier::text,current_database(),current_setting('search_path'),"
                    "current_setting('standard_conforming_strings') "
                    "FROM pg_control_system()"
                )
            ).one()
            parser = ParserObservation(
                server_version_num=row[0],
                cluster_system_identifier=row[1],
                database=row[2],
                search_path=row[3],
                standard_conforming_strings=row[4],
            )
            # Refuse the source context and non-PG16 parser before expression DDL.
            require(
                160000 <= parser["server_version_num"] < 170000,
                "catalogue_parser_version",
            )
            require(
                (parser["cluster_system_identifier"], parser["database"])
                != (expected_source_cluster, expected_source_database),
                "catalogue_parser_is_source_database",
            )
            for identity, original, fresh in changed:
                schema, table, name = identity
                require(isinstance(table, str))
                source_view = _parse_view(
                    connection, schema, cast(str, table), cast(str, original[11])
                )
                restored_view = _parse_view(
                    connection, schema, cast(str, table), cast(str, fresh[11])
                )
                checks.append(
                    CheckComparison(
                        identity=[schema, cast(str, table), name],
                        source_row_digest=_digest(canonical_json(original)),
                        restored_row_digest=_digest(canonical_json(fresh)),
                        source_view_definition=source_view,
                        restored_view_definition=restored_view,
                    )
                )
    except psycopg.Error:
        # Database diagnostics can echo expressions; retain only a fixed reason.
        raise ContractError("catalogue_parser_refused") from None
    finally:
        nested.rollback()
        after = measure_catalogue(connection)
        require(after == restored_catalogue, "catalogue_changed_during_parse")
    value = RestoreComparison(
        schema="dotmac.cp_catalogue_restore_comparison/1",
        request_digest=request_digest,
        host_nonce=host_nonce,
        source_cluster_system_identifier=expected_source_cluster,
        source_database=expected_source_database,
        source_catalogue_digest=_digest(source_catalogue),
        restored_catalogue_digest=_digest(restored_catalogue),
        method="postgres16-temp-view-parse/1",
        parser=parser,
        checks=checks,
        restored_catalogue_after_digest=_digest(after),
    )
    proof = canonical_json(value)
    verify_restore_comparison(
        proof,
        source_catalogue,
        restored_catalogue,
        request_digest=request_digest,
        host_nonce=host_nonce,
        expected_source_cluster=expected_source_cluster,
        expected_source_database=expected_source_database,
    )
    return proof
