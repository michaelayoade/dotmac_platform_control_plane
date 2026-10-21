"""Hosted PostgreSQL proof; full composed Alembic heads are the schema authority."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent.ledger import GitLedger
from vendor_cp.deploy_agent.models import KeyRecord
from vendor_cp.deploy_agent.projection import rebuild
from vendor_cp.platform_admin import upsert_platform_admin


@dataclass(frozen=True)
class Databases:
    owner: Engine
    runtime: Engine
    actor_id: UUID


@pytest.fixture
def databases(scratch_db: str, url_for: Callable[..., str]) -> Iterator[Databases]:
    from vendor_cp.migrations import make_alembic_config

    command.upgrade(make_alembic_config(scratch_db), "heads")
    owner = create_engine(scratch_db)
    with owner.connect() as connection:
        assert connection.scalar(text("SELECT current_user")) == "app_admin"
        name = connection.scalar(text("SELECT current_database()"))
        assert (
            connection.scalar(
                text(
                    "SELECT tableowner FROM pg_tables WHERE "
                    "schemaname='public' AND tablename='deploy_agent_receipts'"
                )
            )
            == "app_admin"
        )
    runtime = create_engine(url_for(scratch_db, name, user="platform_api"))
    with Session(owner) as db:
        actor_id = upsert_platform_admin(
            db, email="deploy-fixture@example.invalid", password="offline-only-fixture"
        ).admin.id
        db.commit()
    try:
        yield Databases(owner, runtime, actor_id)
    finally:
        runtime.dispose()
        owner.dispose()


@dataclass(frozen=True)
class Evidence:
    ledger: GitLedger
    pending: KeyRecord
    active: KeyRecord
    desired: c.Envelope
    applied: c.Envelope


def evidence(root: Path, actor_id: UUID) -> Evidence:
    root.mkdir()
    subprocess.run(  # noqa: S603 - fixed local fixture Git
        ["/usr/bin/git", "-C", str(root), "init", "-b", "main"],
        check=True,
        capture_output=True,
    )
    ledger = GitLedger(root, remote=None)
    for key, value in (
        ("user.name", "PostgreSQL fixture"),
        ("user.email", "fixture@example.invalid"),
        ("commit.gpgsign", "false"),
    ):
        ledger.git("config", key, value)
    hooks = root / ".git" / "fixture-hooks"
    hooks.mkdir()
    ledger.git("config", "core.hooksPath", str(hooks))
    ledger.git("commit", "--allow-empty", "-m", "fixture root")
    vectors = c.read_json(
        (
            Path(__file__).parents[1] / "deploy_agent/vectors/conformance.json"
        ).read_bytes()
    )
    envelopes: dict[str, c.Envelope] = {}
    for kind in (c.DESIRED, c.APPLIED, c.POSSESSION):
        vector = cast(c.Json, vectors[kind])
        envelopes[kind] = cast(c.Envelope, vector["envelope"])
        c.verify(kind, envelopes[kind], cast(str, vector["public_key_b64"]))
    proof = c.validate_possession(
        c.read_json(c.unb64(envelopes[c.POSSESSION]["payload_b64"]))
    )
    challenge = c.validate_challenge(
        {key: value for key, value in proof.items() if key != "observed_image_digest"}
        | {"schema": c.CHALLENGE}
    )
    pending: KeyRecord = {
        "key_id": proof["key_id"],
        "deployment_ref": proof["deployment_ref"],
        "public_key_b64": cast(str, cast(c.Json, vectors[c.APPLIED])["public_key_b64"]),
        "actor_admin_id": str(actor_id),
        "state": "pending",
        "challenge": challenge,
    }
    active = cast(
        KeyRecord,
        {
            **pending,
            "state": "active",
            "possession": envelopes[c.POSSESSION],
            "baseline_digest": proof["observed_image_digest"],
            "received_at": "2026-10-21T10:00:00Z",
        },
    )
    with ledger.transaction():
        ledger.append("keys/test-host/001-pending.json", pending)
    return Evidence(ledger, pending, active, envelopes[c.DESIRED], envelopes[c.APPLIED])


def receipts(engine: Engine) -> tuple[tuple[object, ...], ...]:
    with engine.connect() as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT path,kind,"
                    "deployment_ref,report_id,nonce,fingerprint,envelope::text,"
                    "recorded_at::text "
                    "FROM public.deploy_agent_receipts ORDER BY path"
                )
            )
        )


def plant(
    connection: Connection, path: str, envelope: c.Envelope, *, corrupt: bool = False
) -> None:
    payload = c.validate_desired(c.read_json(c.unb64(envelope["payload_b64"])))
    stored = {**envelope, "signature_b64": "corrupted"} if corrupt else envelope
    connection.execute(
        text(
            "INSERT INTO public.deploy_agent_receipts "
            "(path,kind,deployment_ref,fingerprint,envelope) VALUES "
            "(:path,'desired',:ref,:fingerprint,CAST(:envelope AS jsonb))"
        ),
        {
            "path": path,
            "ref": payload["deployment_ref"],
            "fingerprint": c.digest(envelope),
            "envelope": c.canonical_json(stored).decode(),
        },
    )


def test_owning_migrator_cannot_update_delete_or_truncate_receipts(
    databases: Databases,
) -> None:
    vector = c.read_json(
        (
            Path(__file__).parents[1] / "deploy_agent/vectors/conformance.json"
        ).read_bytes()
    )
    envelope = cast(c.Envelope, cast(c.Json, vector[c.DESIRED])["envelope"])
    with databases.owner.begin() as connection:
        plant(connection, "desired/guard.json", envelope)
    original = receipts(databases.owner)
    for statement in (
        "UPDATE public.deploy_agent_receipts SET kind='changed'",
        "DELETE FROM public.deploy_agent_receipts",
        "TRUNCATE public.deploy_agent_receipts",
    ):
        with databases.owner.connect() as connection:
            with pytest.raises(ProgrammingError, match="append-only"):
                connection.execute(text(statement))
            connection.rollback()
        assert receipts(databases.owner) == original


def test_runtime_has_no_destructive_privileges(databases: Databases) -> None:
    statements = (
        "UPDATE public.deploy_agent_receipts SET kind='changed'",
        "DELETE FROM public.deploy_agent_receipts",
        "TRUNCATE public.deploy_agent_receipts",
        "DELETE FROM public.deploy_host_keys",
        "TRUNCATE public.deploy_host_keys",
    )
    with databases.runtime.connect() as connection:
        assert connection.scalar(text("SELECT current_user")) == "platform_api"
        for statement in statements:
            with pytest.raises(ProgrammingError, match="permission denied"):
                connection.execute(text(statement))
            connection.rollback()


def test_rebuild_is_idempotent_and_advances_key_projection(
    databases: Databases, tmp_path: Path
) -> None:
    fixture = evidence(tmp_path / "ledger", databases.actor_id)
    with Session(databases.runtime) as db:
        assert rebuild(db, fixture.ledger) == {
            "events": 1,
            "repaired": 1,
            "matches": True,
        }
        first = receipts(databases.owner)
        key = db.execute(
            text(
                "SELECT state,event_path FROM public.deploy_host_keys "
                "WHERE key_id='test-host'"
            )
        ).one()
        assert tuple(key) == ("pending", "keys/test-host/001-pending.json")
        assert rebuild(db, fixture.ledger) == {
            "events": 1,
            "repaired": 0,
            "matches": True,
        }
        assert receipts(databases.owner) == first
        with fixture.ledger.transaction():
            fixture.ledger.append("keys/test-host/002-active.json", fixture.active)
            fixture.ledger.append("desired/fixture.json", fixture.desired)
            fixture.ledger.append("applied/fixture.json", fixture.applied)
        assert rebuild(db, fixture.ledger) == {
            "events": 4,
            "repaired": 3,
            "matches": True,
        }
        advanced = receipts(databases.owner)
        assert len(advanced) == 4 and all(row in advanced for row in first)
        key = db.execute(
            text(
                "SELECT state,event_path FROM public.deploy_host_keys "
                "WHERE key_id='test-host'"
            )
        ).one()
        assert tuple(key) == ("active", "keys/test-host/002-active.json")
        db.rollback()
        assert rebuild(db, fixture.ledger) == {
            "events": 4,
            "repaired": 0,
            "matches": True,
        }
        assert receipts(databases.owner) == advanced
        assert (
            db.scalar(
                text(
                    "SELECT count(*) FROM public.platform_audit_events "
                    "WHERE action='vendor.deploy_agent.recorded'"
                )
            )
            == 4
        )


def test_corrupted_retained_row_refuses_rebuild_without_disabling_guard(
    databases: Databases, tmp_path: Path
) -> None:
    fixture = evidence(tmp_path / "ledger", databases.actor_id)
    with fixture.ledger.transaction():
        fixture.ledger.append("desired/fixture.json", fixture.desired)
    with databases.owner.begin() as connection:
        plant(connection, "desired/fixture.json", fixture.desired, corrupt=True)
    original = receipts(databases.owner)
    with Session(databases.runtime) as db:
        with pytest.raises(c.ContractError, match="projection_conflict"):
            rebuild(db, fixture.ledger)
        db.rollback()
        assert db.scalar(text("SELECT count(*) FROM public.deploy_host_keys")) == 0
    assert receipts(databases.owner) == original
