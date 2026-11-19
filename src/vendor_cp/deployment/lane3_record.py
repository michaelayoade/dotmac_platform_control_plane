"""The E9 export: one dispatch's Control and Lane 3 records as canonical JSON (CP-6).

Pre-E11 design section 5 (CP-6, MUST: E9 is projects-ff's). A READ-ONLY command run
by the ceremony owner session on the CP host, so the E9 offline orchestrator's joins
rest on this code and not on hand-written SQL:

    LANE3_E10_DATABASE_URL=... python -m vendor_cp.deployment.lane3_record export \\
        --dispatch-id UUID --host-id HOST [--out PATH]

It reads, in ONE `REPEATABLE READ, READ ONLY` transaction:

* the Control half: the signed dispatch envelope Control stored (its canonical bytes
  and digest are Control's own `DispatchEnvelopeV1` / `DispatchEnvelopeDigestV1`,
  over `canonical_json({statement, signature})`) and the replay-ledger row the
  consumption wrote (`scope = deployment.consume_dispatch_challenge.v1`, key = the
  bare dispatch id, status `executed`, Control's consumption fingerprint stored as
  bare hex);
* the `cp_lane3` half: the E10 receipt and its digest (THE `receipt_digest` of
  `lane3_e10`), its destruction stamp, the lease row the consumption fell under, the
  lease's release (or `null`), and both roots' standings (candidate and installed) as
  Control's enrolment rows.

The shape is the one Starter's `lane3_cp6_export.parse_cp6_export` parses (schema
`lane3.cp6-export.v1`); a test parses this command's output with that exact file,
vendored by digest. The document is canonical JSON (`lane3_e10.canonical`) and its
sha256 is printed to stderr as `export_digest=`.

It judges nothing. The orchestrator verifies the dispatch signature against the
independently pinned CP identities, recomputes the ledger fingerprint and the
receipt digest, and does every time join. What this command refuses is an export it
cannot make faithfully: an unknown dispatch, a ledger row that is not an executed
consumption, no destruction citing the dispatch, a destruction for another host, a
receipt that is not the host's.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text

from vendor_cp.deployment.lane3_e10 import (
    DSN_ENV,
    E10Refused,
    canonical,
    exported_receipt,
    format_time,
    receipt_digest,
)

__all__ = [
    "CONSUME_SCOPE",
    "CONSUME_STATUS",
    "EXPORT_SCHEMA",
    "MAX_EXPORT_BYTES",
    "build_export",
    "main",
]

#: The schema identifier and size bound Starter's parser pins (`# CP-6 PIN`).
EXPORT_SCHEMA: Final = "lane3.cp6-export.v1"
MAX_EXPORT_BYTES: Final = 262144
#: Control's consumption scope and the status of a consumed dispatch.
CONSUME_SCOPE: Final = "deployment.consume_dispatch_challenge.v1"
CONSUME_STATUS: Final = "executed"

_HOST: Final = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_BARE_HEX: Final = re.compile(r"[0-9a-f]{64}")


def _dispatch_id(value: str) -> str:
    try:
        canonical_id = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise E10Refused("dispatch-id-invalid") from None
    if canonical_id != value:
        raise E10Refused("dispatch-id-invalid")
    return canonical_id


def _b64url_key(value: str) -> str:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise E10Refused("root-key-invalid")
    return value


def _root_block(row: Mapping[str, Any]) -> dict[str, Any]:
    """An enrolment as the export's root block. `revoked_at` is the closure instant
    (revoked OR superseded: either way the root no longer verifies new evidence)."""
    return {
        "enrolment_uuid": row["enrolment_uuid"],
        "custody_domain": row["custody_domain"],
        "issuer": row["issuer"],
        "key_id": row["attestation_key_id"],
        "purpose": row["evidence_purpose"],
        "algorithm": row["algorithm"],
        "public_key_b64url": _b64url_key(row["public_key_b64"]),
        "not_before": format_time(row["enrolled_at"]),
        "not_after": format_time(row["not_after"]),
        "enrolled_at": format_time(row["enrolled_at"]),
        "revoked_at": None
        if row["closed_at"] is None
        else format_time(row["closed_at"]),
    }


_ROOT_SQL: Final = (
    "SELECT e.id::text AS enrolment_uuid, e.custody_domain, e.public_key_b64, "
    "e.algorithm, e.enrolled_at, d.issuer, d.attestation_key_id, "
    "d.evidence_purpose, d.not_after, f.closed_at "
    "FROM mod_deploy.attestation_enrolments e "
    "JOIN mod_deploy.attestation_root_descriptors d ON d.enrolment_id = e.id "
    "LEFT JOIN mod_deploy.attestation_fingerprint_closures f "
    "ON f.fingerprint = e.public_key_fingerprint "
)


def _dispatch_block(db: Any, dispatch_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """`(the dispatch block, its statement)`, through Control's own envelope type."""
    from dotmac_deployment_control import (
        DispatchEnvelopeDigestV1,
        DispatchEnvelopeRefusedError,
        DispatchEnvelopeV1,
    )

    stored = db.execute(
        text(
            "SELECT dispatch_envelope FROM mod_deploy.rollout_attempts "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": dispatch_id},
    ).scalar_one_or_none()
    if not isinstance(stored, dict):
        raise E10Refused("dispatch-unknown")
    try:
        envelope = DispatchEnvelopeV1.parse(stored)
    except DispatchEnvelopeRefusedError:
        raise E10Refused("dispatch-envelope-malformed") from None
    statement = envelope.statement.as_mapping()
    if statement["dispatch_id"] != dispatch_id:
        raise E10Refused("dispatch-envelope-names-another-dispatch")
    digest = DispatchEnvelopeDigestV1.over_bytes(envelope.canonical_bytes).canonical
    block = {
        "statement": json.loads(json.dumps(statement)),
        "signature": envelope.signature,
        "envelope_digest": digest,
    }
    return block, statement


def _ledger_block(
    db: Any, dispatch_id: str, statement: Mapping[str, Any]
) -> dict[str, Any]:
    row = (
        db.execute(
            text(
                'SELECT scope, "key" AS ledger_key, status, fingerprint, created_at '
                "FROM public.platform_idempotency_records "
                'WHERE scope = :scope AND "key" = :key'
            ),
            {"scope": CONSUME_SCOPE, "key": dispatch_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise E10Refused("ledger-row-absent")
    if (
        row["status"] != CONSUME_STATUS
        or not isinstance(row["fingerprint"], str)
        or not _BARE_HEX.fullmatch(row["fingerprint"])
    ):
        raise E10Refused("ledger-row-not-consumed")
    return {
        "key": row["ledger_key"],
        "scope": row["scope"],
        "status": row["status"],
        "fingerprint": row["fingerprint"],
        "created_at": format_time(row["created_at"]),
        "execution_sequence": int(statement["execution_sequence"]),
        "attempt_no": int(statement["attempt_no"]),
    }


def build_export(db: Any, *, dispatch_id: str, host_id: str) -> dict[str, Any]:
    """The export document for one dispatch on one host, or a refusal."""
    dispatch_id = _dispatch_id(dispatch_id)
    if not _HOST.fullmatch(host_id):
        raise E10Refused("host-id-invalid")
    dispatch, statement = _dispatch_block(db, dispatch_id)
    ledger = _ledger_block(db, dispatch_id, statement)
    created = db.execute(
        text(
            "SELECT created_at FROM public.platform_idempotency_records "
            'WHERE scope = :scope AND "key" = :key'
        ),
        {"scope": CONSUME_SCOPE, "key": dispatch_id},
    ).scalar_one()
    if not isinstance(created, datetime):
        raise E10Refused("ledger-row-not-consumed")

    destructions = (
        db.execute(
            text(
                "SELECT receipt_ref, destroyed_at, route, dispatch_id::text AS "
                "dispatch_id, installed_attestation_digest, evidence_digest, "
                "recorded_by FROM cp_lane3.e10_destructions "
                "WHERE dispatch_id = CAST(:id AS uuid)"
            ),
            {"id": dispatch_id},
        )
        .mappings()
        .all()
    )
    if len(destructions) != 1:
        raise E10Refused("destruction-not-exactly-one")
    destruction = destructions[0]
    receipt_row = (
        db.execute(
            text(
                "SELECT receipt_ref, vm_alias, host_id, machine_id, "
                "ssh_host_key_fingerprint, vm_slot, incarnation_public_key_b64url, "
                "incarnation_fingerprint, enrolment_uuid::text AS enrolment_uuid, "
                "key_custody_pointer, recorded_by, recorded_at, seq "
                "FROM cp_lane3.e10_receipts WHERE receipt_ref = :ref"
            ),
            {"ref": destruction["receipt_ref"]},
        )
        .mappings()
        .one()
    )
    receipt = exported_receipt(dict(receipt_row))
    if receipt["host_id"] != host_id:
        raise E10Refused("receipt-is-for-another-host")

    lease = (
        db.execute(
            text(
                "SELECT lease_id::text AS lease_id, host_id, authorization_run, "
                "e10_receipt_ref, acquired_at, expires_at FROM cp_lane3.host_leases "
                "WHERE host_id = :host AND acquired_at <= :created "
                "ORDER BY acquired_at DESC, lease_id LIMIT 1"
            ),
            {"host": host_id, "created": created},
        )
        .mappings()
        .one_or_none()
    )
    if lease is None:
        raise E10Refused("lease-absent")
    release_row = (
        db.execute(
            text(
                "SELECT lease_id::text AS lease_id, released_at, host_mutated "
                "FROM cp_lane3.host_lease_releases WHERE lease_id = "
                "CAST(:id AS uuid)"
            ),
            {"id": lease["lease_id"]},
        )
        .mappings()
        .one_or_none()
    )

    installed = (
        db.execute(
            text(_ROOT_SQL + "WHERE e.id = CAST(:id AS uuid)"),
            {"id": receipt["enrolment_uuid"]},
        )
        .mappings()
        .one_or_none()
    )
    if installed is None:
        raise E10Refused("installed-root-unknown")
    subject = db.execute(
        text(
            "SELECT p.candidate_root_subject FROM "
            "mod_deploy.target_current_admission_policies c "
            "JOIN mod_deploy.target_admission_policies p ON p.id = c.policy_id "
            "WHERE c.target_id = CAST(:target AS uuid)"
        ),
        {"target": statement["target_id"]},
    ).scalar_one_or_none()
    if subject is None:
        raise E10Refused("admission-policy-absent")
    # The candidate root is the one that was CURRENT when the ledger row was
    # written (`created`): enrolled by then and not closed by then. Exactly one;
    # none or several is a refusal, never a pick (a later rotation must not
    # change what an earlier dispatch exported).
    candidates = (
        db.execute(
            text(
                _ROOT_SQL + "WHERE e.custody_domain = 'candidate_release_signer' "
                "AND e.subject = :subject AND e.enrolled_at <= :created "
                "AND (f.closed_at IS NULL OR f.closed_at > :created) "
                "ORDER BY e.enrolled_at, e.id"
            ),
            {"subject": subject, "created": created},
        )
        .mappings()
        .all()
    )
    if not candidates:
        raise E10Refused("candidate-root-absent")
    if len(candidates) != 1:
        raise E10Refused("candidate-root-ambiguous")
    candidate = candidates[0]

    return {
        "schema": EXPORT_SCHEMA,
        "dispatch_id": dispatch_id,
        "host_id": host_id,
        "control": {"dispatch": dispatch, "ledger": ledger},
        "cp_lane3": {
            "e10_receipt": receipt,
            "e10_receipt_digest": receipt_digest(receipt),
            "destruction": {
                "receipt_ref": destruction["receipt_ref"],
                "destroyed_at": format_time(destruction["destroyed_at"]),
                "route": destruction["route"],
                "dispatch_id": destruction["dispatch_id"],
                "installed_attestation_digest": destruction[
                    "installed_attestation_digest"
                ],
                "evidence_digest": destruction["evidence_digest"],
                "recorded_by": destruction["recorded_by"],
            },
            "lease": {
                "lease_id": lease["lease_id"],
                "host_id": lease["host_id"],
                "authorization_run": lease["authorization_run"],
                "e10_receipt_ref": lease["e10_receipt_ref"],
                "acquired_at": format_time(lease["acquired_at"]),
                "expires_at": format_time(lease["expires_at"]),
            },
            "release": None
            if release_row is None
            else {
                "lease_id": release_row["lease_id"],
                "released_at": format_time(release_row["released_at"]),
                "host_mutated": bool(release_row["host_mutated"]),
            },
            "candidate_root": _root_block(candidate),
            "installed_root": _root_block(installed),
        },
    }


def render(document: Mapping[str, Any]) -> bytes:
    payload = canonical(dict(document))
    if len(payload) > MAX_EXPORT_BYTES:
        raise E10Refused("export-too-large")
    return payload


def _write_create_only(path: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise E10Refused("out-path-unwritable") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    if stat.S_IMODE(os.stat(path).st_mode) != 0o600:
        raise E10Refused("out-path-unwritable")


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    session: Any = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)
    export = sub.add_parser("export")
    export.add_argument("--dispatch-id", required=True)
    export.add_argument("--host-id", required=True)
    export.add_argument("--out")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        if session is None:
            dsn = env.get(DSN_ENV, "").strip()
            if not dsn:
                raise E10Refused("dsn-missing")
            if any(name.startswith("PG") for name in env):
                raise E10Refused("libpq-environment")
            from dotmac_kernel.session_runtime import DatabaseRuntime

            session = DatabaseRuntime.from_urls(
                database_url=dsn, platform_database_url=dsn
            ).platform_session_factory()
        try:
            # One consistent snapshot, and the server refuses a write.
            session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            session.execute(text("SET TRANSACTION READ ONLY"))
            payload = render(
                build_export(
                    session, dispatch_id=args.dispatch_id, host_id=args.host_id
                )
            )
        finally:
            session.rollback()
            session.close()
        if args.out:
            _write_create_only(args.out, payload)
        else:
            sys.stdout.buffer.write(payload)
        print(
            "export_digest=sha256:" + hashlib.sha256(payload).hexdigest(),
            file=sys.stderr,
        )
    except E10Refused as refusal:
        print(f"export refused: {refusal.code}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        # A database or owner error can carry statement text and parameters.
        print(f"export failed: {type(error).__name__}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
