"""Hosted PostgreSQL proves the finite recovery comparison sees real mutations.

The existing scratch database and measurement owner supply every observation.
No Docker or global PostgreSQL settings are changed by these cases.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from vendor_cp.deploy_agent.contracts import ContractError, digest
from vendor_cp.deployment.cp_transition import (
    CandidateMeasurementV1,
    CpPostAclRecoveryRequestV1,
    PostAclRecoveryContext,
    raw_digest,
)
from vendor_cp.deployment.cp_transition_host import (
    ExistingCpTransitionHost,
    measure_candidate_quiescence,
)


def wait_for_exit(observer, backend):
    """Use the existing owner prerequisite: the producer backend must exit."""
    deadline = time.monotonic() + 3
    while observer.execute(
        text(
            "SELECT count(*) FROM pg_stat_activity WHERE pid=:pid "
            "AND backend_start::text=:started"
        ),
        {"pid": backend[0], "started": backend[1]},
    ).scalar_one():
        assert time.monotonic() < deadline, "measurement producer backend did not exit"
        time.sleep(0.01)


def bound_baseline(measurement):
    """Map an actual retained snapshot to the new owner's request/context input."""
    baseline = dict(measurement)
    baseline["catalogue_digest"] = raw_digest(baseline.pop("catalogue_bytes"))
    return (
        cast(
            CpPostAclRecoveryRequestV1,
            {"basis": {"frontier_measurement_digest": digest(baseline)}},
        ),
        cast(
            PostAclRecoveryContext,
            SimpleNamespace(measurement=cast(CandidateMeasurementV1, baseline)),
        ),
    )


@pytest.fixture
def measured_database(postgres_url, scratch_db, url_for):
    database = scratch_db.rpartition("/")[2]
    url = url_for(postgres_url, database)
    # NullPool closes the real producer backend at context exit, flushing its
    # tuple statistics before the separately connected observer takes a reading.
    writer = create_engine(url, poolclass=NullPool)
    observer_engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with writer.begin() as connection:
            backend = connection.execute(
                text(
                    "SELECT pg_backend_pid(),backend_start::text "
                    "FROM pg_stat_activity WHERE pid=pg_backend_pid()"
                )
            ).one()
            for table in (
                "business_records",
                "relay_heartbeats",
                "platform_outbox_events",
            ):
                connection.exec_driver_sql(
                    f'CREATE TABLE public."{table}" (id integer,value text)'
                )
                connection.exec_driver_sql(
                    f"INSERT INTO public.\"{table}\" VALUES (1,'baseline')"  # noqa: S608
                )
            connection.exec_driver_sql("CREATE SEQUENCE public.post_acl_counter")
        with observer_engine.connect() as observer:
            wait_for_exit(observer, backend)
            request, context = bound_baseline(measure_candidate_quiescence(observer))
            # Establish acceptance through the real new host owner before any
            # negative case; an always-refusing implementation cannot pass.
            accepted = ExistingCpTransitionHost._post_acl_measurement(
                observer, request, context
            )
            assert accepted == context.measurement
            assert {row[1] for row in accepted["relations"]} >= {
                "business_records",
                "relay_heartbeats",
                "platform_outbox_events",
            }
            yield observer, writer, request, context
    finally:
        writer.dispose()
        observer_engine.dispose()


def test_equal_complete_post_acl_measurement_is_accepted(measured_database):
    observer, _, request, context = measured_database
    assert (
        ExistingCpTransitionHost._post_acl_measurement(observer, request, context)
        == context.measurement
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "business-insert",
        "business-update",
        "business-delete",
        "heartbeat-update",
        "outbox-delete",
        "sequence",
        "catalogue",
    ],
)
def test_real_post_acl_mutations_refuse_after_backend_exit(measured_database, mutation):
    observer, writer, request, context = measured_database
    statements = {
        "business-insert": "INSERT INTO public.business_records VALUES (2,'changed')",
        "business-update": (
            "UPDATE public.business_records SET value='changed' WHERE id=1"
        ),
        "business-delete": "DELETE FROM public.business_records WHERE id=1",
        "heartbeat-update": (
            "UPDATE public.relay_heartbeats SET value='fresh heartbeat' WHERE id=1"
        ),
        "outbox-delete": "DELETE FROM public.platform_outbox_events WHERE id=1",
        "sequence": "SELECT nextval('public.post_acl_counter')",
        "catalogue": (
            "ALTER TABLE public.business_records ADD COLUMN unexpected integer"
        ),
    }
    with writer.begin() as connection:
        backend = connection.execute(
            text(
                "SELECT pg_backend_pid(),backend_start::text "
                "FROM pg_stat_activity WHERE pid=pg_backend_pid()"
            )
        ).one()
        connection.exec_driver_sql(statements[mutation])
    wait_for_exit(observer, backend)
    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        ExistingCpTransitionHost._post_acl_measurement(observer, request, context)


def test_unavailable_statistics_refuses_in_real_measurement_owner(measured_database):
    observer, _, request, context = measured_database
    observer.exec_driver_sql("SET track_counts=off")
    with pytest.raises(ContractError, match="quiescence_statistics_disabled"):
        ExistingCpTransitionHost._post_acl_measurement(observer, request, context)


@pytest.mark.parametrize("identity", ["stats_reset", "server_start"])
def test_retained_reset_or_restart_identity_must_match_live_server(
    measured_database, identity
):
    observer, _, _, context = measured_database
    # Change the retained identity, never server-global statistics or lifecycle.
    # The new owner still obtains its comparison from a real PostgreSQL query.
    prior = dict(context.measurement)
    prior[identity] = "1900-01-01 00:00:00+00"
    request = cast(
        CpPostAclRecoveryRequestV1,
        {"basis": {"frontier_measurement_digest": digest(prior)}},
    )
    retained = cast(PostAclRecoveryContext, SimpleNamespace(measurement=prior))
    with pytest.raises(ContractError, match="post_acl_measurement_mismatch"):
        ExistingCpTransitionHost._post_acl_measurement(observer, request, retained)
