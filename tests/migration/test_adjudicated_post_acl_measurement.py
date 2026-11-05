"""Real hosted PostgreSQL full measurement plus complete heartbeat commitments."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from test_cp_post_acl_measurement import wait_for_exit

from vendor_cp.deploy_agent.contracts import ContractError, digest
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment.cp_transition_host import (
    ExistingCpTransitionHost,
    measure_candidate_quiescence,
    measure_complete_heartbeat_rowset,
)


def measurement(connection):
    observed = dict(measure_candidate_quiescence(connection))
    observed["catalogue_digest"] = cp.raw_digest(observed.pop("catalogue_bytes"))
    return observed


def backend(connection):
    return connection.execute(
        text(
            "SELECT pg_backend_pid(),backend_start::text "
            "FROM pg_stat_activity WHERE pid=pg_backend_pid()"
        )
    ).one()


@pytest.fixture
def present_database(postgres_url, scratch_db, url_for):
    database = scratch_db.rpartition("/")[2]
    url = url_for(postgres_url, database)
    writer = create_engine(url, poolclass=NullPool)
    observed_engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with writer.begin() as connection:
            producer = backend(connection)
            connection.exec_driver_sql(
                "CREATE TABLE public.relay_heartbeats "
                "(worker_id varchar(200) PRIMARY KEY,"
                "started_at timestamptz NOT NULL,last_polled_at timestamptz NOT NULL,"
                "last_claimed_at timestamptz)"
            )
            connection.exec_driver_sql(
                "INSERT INTO public.relay_heartbeats VALUES "
                "('worker','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',NULL)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE public.business_records (id integer PRIMARY KEY)"
            )
        with observed_engine.connect() as observer:
            wait_for_exit(observer, producer)
            historical = measurement(observer)
            old_rowset, count = measure_complete_heartbeat_rowset(observer)
            assert count == 1
            with writer.begin() as connection:
                producer = backend(connection)
                connection.exec_driver_sql(
                    "UPDATE public.relay_heartbeats "
                    "SET last_polled_at='2026-01-02T00:00:00Z'"
                )
            wait_for_exit(observer, producer)
            present = measurement(observer)
            rowset, count = measure_complete_heartbeat_rowset(observer)
            assert count == 1 and rowset != old_rowset
            assert historical != present
            context = cast(
                cp.AdjudicatedPostAclRecoveryContext,
                SimpleNamespace(present_measurement=present),
            )
            request = cast(
                cp.CpAdjudicatedPostAclRequestV1,
                {
                    "basis": {
                        "present_measurement_digest": digest(present),
                        "current_heartbeat_rowset_digest": rowset,
                    }
                },
            )
            # A real acceptance is required before every negative case.
            assert ExistingCpTransitionHost._adjudicated_post_acl_measurement(
                observer, request, context
            ) == (present, rowset, 1)
            yield observer, writer, historical, present, request, context
    finally:
        writer.dispose()
        observed_engine.dispose()


def test_present_boundary_accepts_while_strict_historical_boundary_refuses(
    present_database,
):
    observer, _, historical, present, request, context = present_database
    assert (
        ExistingCpTransitionHost._adjudicated_post_acl_measurement(
            observer, request, context
        )[0]
        == present
    )
    strict = cast(
        cp.CpPostAclRecoveryRequestV1,
        {"basis": {"frontier_measurement_digest": digest(historical)}},
    )
    historical_context = cast(
        cp.PostAclRecoveryContext, SimpleNamespace(measurement=historical)
    )
    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        ExistingCpTransitionHost._post_acl_measurement(
            observer, strict, historical_context
        )


@pytest.mark.parametrize(
    "mutation", ["heartbeat", "business", "extra-row", "catalogue"]
)
def test_further_real_mutation_refuses_after_backend_exit(present_database, mutation):
    observer, writer, _, _, request, context = present_database
    statements = {
        "heartbeat": (
            "UPDATE public.relay_heartbeats "
            "SET last_polled_at='2026-01-03T00:00:00Z'"
        ),
        "business": "INSERT INTO public.business_records VALUES (1)",
        "extra-row": (
            "INSERT INTO public.relay_heartbeats "
            "SELECT 'second',started_at,last_polled_at,NULL "
            "FROM public.relay_heartbeats"
        ),
        "catalogue": (
            "ALTER TABLE public.business_records " "ADD COLUMN unexpected integer"
        ),
    }
    with writer.begin() as connection:
        producer = backend(connection)
        connection.exec_driver_sql(statements[mutation])
    wait_for_exit(observer, producer)
    with pytest.raises(
        ContractError, match="adjudicated_post_acl_measurement_mismatch"
    ):
        ExistingCpTransitionHost._adjudicated_post_acl_measurement(
            observer, request, context
        )


def test_equal_measurement_cannot_waive_wrong_complete_rowset(present_database):
    observer, _, _, _, request, context = present_database
    crossed = deepcopy(request)
    crossed["basis"]["current_heartbeat_rowset_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ContractError, match="adjudicated_post_acl_rowset_mismatch"):
        ExistingCpTransitionHost._adjudicated_post_acl_measurement(
            observer, crossed, context
        )
