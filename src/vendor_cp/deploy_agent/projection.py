"""PostgreSQL projection of immutable git events; kernel owns the session."""

from typing import cast
from uuid import UUID

from dotmac_kernel import write_platform_audit_event
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import contracts as c
from .ledger import GitLedger
from .models import Receipt


def receipt(db: Session, deployment_ref: str, report_id: UUID) -> Receipt | None:
    """Read stored projection evidence for comparison with sealed bytes and Git."""
    row = (
        db.execute(
            text(
                "SELECT deployment_ref,report_id,path,fingerprint "
                "FROM public.deploy_agent_receipts "
                "WHERE kind='applied' AND deployment_ref=:ref AND report_id=:report"
            ),
            {"ref": deployment_ref, "report": str(report_id)},
        )
        .mappings()
        .one_or_none()
    )
    return cast(Receipt, dict(row)) if row is not None else None


def project(db: Session, path: str, event: c.Json) -> None:
    fingerprint = c.digest(event)
    existing = db.execute(
        text("SELECT fingerprint FROM public.deploy_agent_receipts WHERE path=:path"),
        {"path": path},
    ).scalar_one_or_none()
    if existing:
        c.require(existing == fingerprint, "projection_conflict")
        return
    kind = path.split("/", 1)[0]
    deployment_ref = event.get("deployment_ref")
    report_id = nonce = None
    if kind in {"desired", "applied"}:
        payload = c.read_json(c.unb64(cast(str, event["payload_b64"])))
        deployment_ref = payload["deployment_ref"]
        if kind == "applied":
            report = c.validate_applied(payload)
            report_id, nonce = report["report_id"], report["desired"]["nonce"]
    actor = event.get("actor_admin_id")
    write_platform_audit_event(
        db,
        actor_admin_id=UUID(cast(str, actor)) if actor else None,
        action="vendor.deploy_agent.recorded",
        entity_type="deploy_agent_ledger",
        entity_id=path,
        details={"fingerprint": fingerprint, "kind": kind},
    )
    db.execute(
        text("""INSERT INTO public.deploy_agent_receipts
        (path,kind,deployment_ref,report_id,nonce,fingerprint,envelope)
        VALUES (:path,:kind,:ref,:report,:nonce,:fingerprint,
                CAST(:envelope AS jsonb))"""),
        {
            "path": path,
            "kind": kind,
            "ref": deployment_ref,
            "report": report_id,
            "nonce": nonce,
            "fingerprint": fingerprint,
            "envelope": c.canonical_json(event).decode(),
        },
    )


def rebuild(db: Session, ledger: GitLedger) -> dict[str, int | bool]:
    """Repair missing receipts and current registry; refuse divergent retained rows."""
    events = ledger.events()
    expected = {path: c.digest(event) for path, event in events}
    actual: dict[str, str] = {}
    for row in db.execute(
        text(
            "SELECT path,kind,deployment_ref,report_id,nonce,fingerprint,envelope "
            "FROM public.deploy_agent_receipts"
        )
    ):
        path, kind, ref, report_id, nonce, fingerprint, envelope = row
        c.require(
            path in expected
            and isinstance(envelope, dict)
            and c.digest(envelope) == fingerprint == expected[path],
            "projection_conflict",
        )
        c.require(kind == path.split("/", 1)[0], "projection_conflict")
        event = cast(c.Json, envelope)
        expected_ref, expected_report, expected_nonce = (
            event.get("deployment_ref"),
            None,
            None,
        )
        if kind in {"desired", "applied"}:
            payload = c.read_json(c.unb64(cast(str, event["payload_b64"])))
            expected_ref = payload["deployment_ref"]
            if kind == "applied":
                report = c.validate_applied(payload)
                expected_report, expected_nonce = (
                    report["report_id"],
                    report["desired"]["nonce"],
                )
        c.require(
            (kind, ref, report_id, nonce)
            == (path.split("/", 1)[0], expected_ref, expected_report, expected_nonce),
            "projection_conflict",
        )
        actual[path] = fingerprint
    keys = {
        cast(str, event["key_id"]): (path, event)
        for path, event in events
        if path.startswith("keys/")
    }
    actual_keys = db.execute(
        text("SELECT key_id,deployment_ref,public_key_b64 FROM public.deploy_host_keys")
    )
    for key_id, ref, public in actual_keys:
        c.require(
            key_id in keys
            and keys[key_id][1]["deployment_ref"] == ref
            and keys[key_id][1]["public_key_b64"] == public,
            "projection_conflict",
        )
    for path, event in events:
        project(db, path, event)
    for key_id, (path, event) in keys.items():
        db.execute(
            text("""INSERT INTO public.deploy_host_keys
            (key_id,deployment_ref,public_key_b64,state,event_path)
            VALUES (:key,:ref,:public,:state,:path) ON CONFLICT(key_id)
            DO UPDATE SET state=excluded.state,event_path=excluded.event_path"""),
            {
                "key": key_id,
                "ref": event["deployment_ref"],
                "public": event["public_key_b64"],
                "state": event["state"],
                "path": path,
            },
        )
    db.commit()
    return {
        "events": len(events),
        "repaired": len(expected) - len(actual),
        "matches": True,
    }
