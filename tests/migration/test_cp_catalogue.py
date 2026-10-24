"""Real PG16 parser comparison and savepoint cleanup; no local Docker use."""

from __future__ import annotations

import copy
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json, read_json
from vendor_cp.deployment import cp_catalogue as module


@pytest.fixture
def catalogue_pair(postgres_url, scratch_db, url_for):
    source_database = scratch_db.rpartition("/")[2]
    database = "cp_catalogue_restore_" + uuid.uuid4().hex[:12]
    schema = "cp_catalogue_" + uuid.uuid4().hex[:12]
    source_engine = create_engine(url_for(postgres_url, source_database))
    server = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    restored_engine = None
    try:
        with server.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database}"')  # noqa: S608 -- generated identifier
        restored_engine = create_engine(url_for(postgres_url, database))
        with source_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')  # noqa: S608 -- generated identifier
            connection.exec_driver_sql(
                f'CREATE TABLE "{schema}".proof (status varchar(24), '  # noqa: S608 -- generated identifier, fixed CHECK fixture
                "CONSTRAINT ck CHECK (status IN ('accepted','failed')))"
            )
            source = module.measure_catalogue(connection)
            source_row = next(
                row for row in read_json(source)["constraints"] if row[0] == schema
            )
        with restored_engine.begin() as connection:
            connection.exec_driver_sql("ALTER SCHEMA public OWNER TO app_admin")
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')  # noqa: S608 -- generated identifier
            connection.exec_driver_sql(
                f'CREATE TABLE "{schema}".proof (status varchar(24))'
            )  # noqa: S608 -- generated identifier
            connection.exec_driver_sql(
                f'ALTER TABLE "{schema}".proof ADD CONSTRAINT ck ' + source_row[3]  # noqa: S608 -- generated identifier and actual measured fixture CHECK
            )
        with restored_engine.connect() as connection, connection.begin():
            cluster = connection.execute(
                text("SELECT system_identifier::text FROM pg_control_system()")
            ).scalar_one()
            restored = module.measure_catalogue(connection)
            yield SimpleNamespace(
                connection=connection,
                source=source,
                restored=restored,
                schema=schema,
                database=database,
                context=dict(
                    request_digest="sha256:" + "a" * 64,
                    host_nonce="b" * 64,
                    expected_source_cluster=cluster,
                    expected_source_database=source_database,
                ),
            )
    finally:
        if restored_engine:
            restored_engine.dispose()
        source_engine.dispose()
        with server.connect() as connection:
            connection.exec_driver_sql(
                f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'
            )  # noqa: S608 -- exact generated fixture database
        server.dispose()


def temporary_objects(connection):
    return connection.execute(
        text(
            "SELECT n.nspname,c.relname,c.relkind FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.oid=pg_my_temp_schema() AND c.relname LIKE 'cp_restore_%' "
            "ORDER BY n.nspname,c.relname"
        )
    ).all()


def test_real_varchar_array_cast_restore_compares_without_raw_rewrite(catalogue_pair):
    pair = catalogue_pair
    assert (
        pair.source != pair.restored
    ), "fixture did not reproduce observed PG16 cast deparse drift"
    before = temporary_objects(pair.connection)
    settings = pair.connection.execute(text("SHOW search_path")).scalar_one()
    proof = module.capture_restore_comparison(
        pair.connection, pair.source, pair.restored, **pair.context
    )
    value = read_json(proof)
    assert value["source_catalogue_digest"] != value["restored_catalogue_digest"]
    assert len(value["checks"]) == 1
    assert (
        value["checks"][0]["source_view_definition"]
        == value["checks"][0]["restored_view_definition"]
    )
    assert (
        value["parser"]["cluster_system_identifier"]
        == pair.context["expected_source_cluster"]
    )
    assert value["parser"]["database"] != pair.context["expected_source_database"]
    module.verify_restore_comparison(proof, pair.source, pair.restored, **pair.context)
    assert temporary_objects(pair.connection) == before == []
    assert module.measure_catalogue(pair.connection) == pair.restored
    assert pair.connection.execute(text("SHOW search_path")).scalar_one() == settings
    assert pair.connection.in_transaction()


@pytest.mark.parametrize(
    "mutation", ["literal", "operator", "cast", "collation", "validated", "semicolon"]
)
def test_real_parser_refuses_semantic_flags_and_multiquery_drift(
    catalogue_pair, mutation
):
    pair = catalogue_pair
    altered = copy.deepcopy(read_json(pair.source))
    row = next(row for row in altered["constraints"] if row[0] == pair.schema)
    original = row[11]
    if mutation == "literal":
        row[11] = row[11].replace("'accepted'", "'different_literal'")
    elif mutation == "operator":
        row[11] = row[11].replace("= ANY", "<> ALL")
    elif mutation == "cast":
        row[11] = row[11].replace("status", "status::character(1)", 1)
    elif mutation == "collation":
        row[11] = row[11].replace("status", 'status COLLATE "C"', 1)
    elif mutation == "validated":
        row[5] = False
    else:
        quote = pair.connection.dialect.identifier_preparer.quote
        table = quote(pair.schema) + ".proof"
        row[11] = (
            "true) AS constraint_value FROM "
            + table
            + "; CREATE TABLE "
            + quote(pair.schema)
            + ".side_effect(id integer); --"
        )
    assert mutation == "validated" or row[11] != original
    before = temporary_objects(pair.connection)
    pair.connection.exec_driver_sql("SET LOCAL search_path = 'public'")
    pair.connection.exec_driver_sql("SET LOCAL standard_conforming_strings = 'off'")
    with pytest.raises(ContractError) as error:
        module.capture_restore_comparison(
            pair.connection, canonical_json(altered), pair.restored, **pair.context
        )
    assert "different_literal" not in str(error.value) and "CREATE TABLE" not in str(
        error.value
    )
    if mutation == "semicolon":
        assert str(error.value) == "catalogue_parser_refused"
    assert temporary_objects(pair.connection) == before == []
    assert (
        pair.connection.execute(
            text("SELECT to_regclass(:name)"), {"name": pair.schema + ".side_effect"}
        ).scalar_one()
        is None
    )
    assert module.measure_catalogue(pair.connection) == pair.restored
    assert pair.connection.execute(text("SHOW search_path")).scalar_one() == "public"
    assert (
        pair.connection.execute(text("SHOW standard_conforming_strings")).scalar_one()
        == "off"
    )
    assert pair.connection.in_transaction()


def test_real_parser_refuses_original_database_and_preserves_temp_objects(
    catalogue_pair,
):
    pair = catalogue_pair
    context = {**pair.context, "expected_source_database": pair.database}
    before = temporary_objects(pair.connection)
    with pytest.raises(ContractError, match="catalogue_parser_is_source_database"):
        module.capture_restore_comparison(
            pair.connection, pair.restored, pair.restored, **context
        )
    assert temporary_objects(pair.connection) == before == []


def test_measurement_restores_autocommit_observer_deparse_settings(
    catalogue_pair, postgres_url, url_for
):
    pair = catalogue_pair
    observer = create_engine(
        url_for(postgres_url, pair.database), isolation_level="AUTOCOMMIT"
    )
    try:
        with observer.connect() as connection:
            connection.exec_driver_sql("SET search_path = 'public'")
            connection.exec_driver_sql("SET standard_conforming_strings = 'off'")
            assert module.measure_catalogue(connection) == pair.restored
            assert connection.execute(text("SHOW search_path")).scalar_one() == "public"
            assert (
                connection.execute(
                    text("SHOW standard_conforming_strings")
                ).scalar_one()
                == "off"
            )
            with pytest.raises(
                ContractError, match="catalogue_parser_transaction_required"
            ):
                module.capture_restore_comparison(
                    connection, pair.source, pair.restored, **pair.context
                )
            assert temporary_objects(connection) == []
    finally:
        observer.dispose()
