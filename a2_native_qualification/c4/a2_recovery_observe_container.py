# Runs INSIDE the pinned CP image (python -, script on stdin). Read-only: the oracle's three fixed SELECTs
# (kit params/recovery-fixed-queries.json, sha256 afc3d7b7...) plus ONE fixed SELECT of the stored
# authorization envelope, which is read through Control's own parser. No caller SQL, no DSN on argv.
# argv: rollout_ref plan_id rollout_command_id dispatch_command_id. DSN: env A2_OBSERVE_DSN (a read-only role).
import json
import os
import sys

PROPOSAL_SHA256 = "b0957a8d0ad26cb4dd02bd3bf3933ee7fbc05d8507631a37adf3c3415f6dc926"
BOUNDARY = "authorization_committed_dispatch_signing_failed_before_attempt"
Q_COMMAND_LEDGER = "SELECT scope, key, operation, status, result ->> 'id' AS rollout_id\nFROM public.platform_idempotency_records\nWHERE scope = 'inbox' AND key IN (:rollout_command_id, :dispatch_command_id)\nORDER BY key;"
Q_ROLLOUT = 'SELECT id::text AS id, rollout_ref, plan_id::text AS plan_id, status, execution_sequence, record_version,\n       authorization_envelope IS NOT NULL AS has_authorization\nFROM mod_deploy.rollouts\nWHERE rollout_ref = :rollout_ref AND plan_id = CAST(:plan_id AS uuid);'
Q_ATTEMPTS = 'SELECT a.id::text AS attempt_id, a.attempt_no, a.outcome, a.dispatched_at,\n       a.dispatch_envelope IS NOT NULL AS has_dispatch_envelope,\n       s.attempt_id::text AS settlement_attempt_id, s.outcome AS settlement_outcome\nFROM mod_deploy.rollout_attempts AS a\nLEFT JOIN mod_deploy.rollout_attempt_settlements AS s ON s.attempt_id = a.id\nWHERE a.rollout_id = CAST(:rollout_id AS uuid)\nORDER BY a.attempt_no;'
Q_AUTHORIZATION = (
    "SELECT authorization_envelope\n"
    "FROM mod_deploy.rollouts\n"
    "WHERE id = CAST(:rollout_id AS uuid) AND rollout_ref = :rollout_ref AND plan_id = CAST(:plan_id AS uuid);"
)


def stop(name):
    print("recovery-observe STOP: " + name, file=sys.stderr)
    raise SystemExit(2)


def main():
    if len(sys.argv) != 5:
        stop("arguments")
    rollout_ref, plan_id, rollout_command_id, dispatch_command_id = sys.argv[1:5]
    dsn = os.environ.get("A2_OBSERVE_DSN", "")
    if not dsn:
        stop("dsn_missing")
    from sqlalchemy import create_engine, text
    from dotmac_deployment_control.authorization import AuthorizationEnvelopeV2
    engine = create_engine(dsn)
    with engine.connect() as connection:
        connection.execute(text("SET TRANSACTION READ ONLY"))

        def rows(sql, **params):
            return [dict(row._mapping) for row in connection.execute(text(sql), params)]
        ledger = rows(Q_COMMAND_LEDGER, rollout_command_id=rollout_command_id, dispatch_command_id=dispatch_command_id)
        if len(ledger) != 1:
            stop("ledger_cardinality")
        rollout_id = ledger[0]["rollout_id"]
        rollout = rows(Q_ROLLOUT, rollout_ref=rollout_ref, plan_id=plan_id)
        if len(rollout) != 1 or rollout[0]["id"] != rollout_id:
            stop("rollout_cardinality")
        attempts = rows(Q_ATTEMPTS, rollout_id=rollout_id)
        stored = rows(Q_AUTHORIZATION, rollout_id=rollout_id, rollout_ref=rollout_ref, plan_id=plan_id)
        connection.rollback()
    if len(stored) != 1:
        stop("authorization_cardinality")
    value = stored[0]["authorization_envelope"]
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    try:
        envelope = AuthorizationEnvelopeV2.parse(value).as_mapping()
    except Exception:
        stop("authorization_parse")
    observation = {
        "schema": "a2_recovery_oracle_observation.v1", "boundary": BOUNDARY, "proposal_sha256": PROPOSAL_SHA256,
        "coordinates": {"rollout_command_id": rollout_command_id, "dispatch_command_id": dispatch_command_id, "plan_id": plan_id,
                        "rollout_id": rollout_id, "rollout_ref": rollout_ref, "execution_sequence": rollout[0]["execution_sequence"]},
        "rows": {"command_ledger": ledger, "rollout": rollout, "attempts_and_settlements": attempts}}
    print(json.dumps({"observation": observation, "original_authorization": envelope}, sort_keys=True, default=str))


main()
