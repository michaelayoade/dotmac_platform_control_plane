"""C4 harness helpers (stdlib only): SCRAM verifier, SQL rendering, role
read-back, and the values-free result. No secret is printed or stored in the
result; the password lives only in the runner-temp env file the container reads.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent


def scram_verifier(password: str) -> str:
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    client = hmac.new(salted, b"Client Key", "sha256").digest()
    server = hmac.new(salted, b"Server Key", "sha256").digest()
    b64 = base64.b64encode
    stored = hashlib.sha256(client).digest()
    return (
        f"SCRAM-SHA-256$4096:{b64(salt).decode()}$"
        f"{b64(stored).decode()}:{b64(server).decode()}"
    )


def render_create(role_suffix: str, dbname: str) -> str:
    text = (HERE / "a2-observer-create.sql").read_text(encoding="utf-8")
    until = (datetime.now(UTC) + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S+00")
    return (
        text.replace("a2_recovery_observer_rN", f"a2_recovery_observer_{role_suffix}")
        .replace("<cp_db_name>", dbname)
        .replace("<UTC now + 3 hours>", until)
    )


def readback_sql(role: str, dbname: str) -> str:
    # role/dbname are harness-generated, never user input.
    return f"""SELECT json_build_object(
 'canlogin', (SELECT rolcanlogin FROM pg_roles WHERE rolname='{role}'),
 'privileged_flags', (SELECT rolsuper OR rolcreatedb OR rolcreaterole
     OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname='{role}'),
 'connlimit', (SELECT rolconnlimit FROM pg_roles WHERE rolname='{role}'),
 'valid_until_set', (SELECT rolvaliduntil IS NOT NULL FROM pg_roles
     WHERE rolname='{role}'),
 'config', (SELECT to_json(rolconfig) FROM pg_roles WHERE rolname='{role}'),
 'table_grants', (SELECT json_agg(privilege_type) FROM
     information_schema.role_table_grants WHERE grantee='{role}'),
 'column_privileges', (SELECT count(*) FROM information_schema.column_privileges
     WHERE grantee='{role}'),
 'memberships', (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r
     ON r.oid=m.member WHERE r.rolname='{role}'),
 'db_create', has_database_privilege('{role}', '{dbname}', 'CREATE'),
 'schema_create', has_schema_privilege('{role}', 'mod_deploy', 'CREATE'),
 'other_tables_select', json_build_array(
   has_table_privilege('{role}', 'mod_deploy.deployment_plans', 'SELECT'),
   has_table_privilege('{role}', 'mod_deploy.deployment_targets', 'SELECT'))
); """  # noqa: S608


EXPECTED_CONFIG = {
    "default_transaction_read_only=on",
    "statement_timeout=5s",
    "lock_timeout=2s",
    "idle_in_transaction_session_timeout=10s",
}


def judge_readback(doc: dict) -> dict[str, bool]:
    grants = doc.get("table_grants") or []
    return {
        "login_role_unprivileged": doc.get("canlogin") is True
        and doc.get("privileged_flags") is False,
        "connection_limit_2": doc.get("connlimit") == 2,
        "valid_until_set": doc.get("valid_until_set") is True,
        "config_exactly_four": set(doc.get("config") or []) == EXPECTED_CONFIG
        and len(doc.get("config") or []) == 4,
        "exactly_4_select_grants": len(grants) == 4 and set(grants) == {"SELECT"},
        "no_column_privileges": doc.get("column_privileges") == 0,
        "no_memberships": doc.get("memberships") == 0,
        "no_create": doc.get("db_create") is False
        and doc.get("schema_create") is False,
        "other_tables_denied": doc.get("other_tables_select") == [False, False],
    }


def judge_observation(stdout: str) -> dict[str, bool]:
    try:
        doc = json.loads(stdout)
        obs = doc["observation"]
        rows = obs["rows"]
        return {
            "observation_schema": obs.get("schema")
            == "a2_recovery_oracle_observation.v1",
            "ledger_one_row": len(rows["command_ledger"]) == 1,
            "rollout_one_row": len(rows["rollout"]) == 1
            and rows["rollout"][0]["has_authorization"] is True,
            "no_attempts_yet": rows["attempts_and_settlements"] == [],
            "authorization_parsed": isinstance(doc["original_authorization"], dict)
            and bool(doc["original_authorization"]),
        }
    except (ValueError, KeyError, TypeError, IndexError):
        return {"observation_decodes": False}


def main(argv: list[str]) -> int:
    cmd = argv[1]
    if cmd == "scram":  # scram <password-file> -> verifier on stdout
        print(scram_verifier(Path(argv[2]).read_text().strip()))
    elif cmd == "render":  # render <role_suffix> <dbname>
        sys.stdout.write(render_create(argv[2], argv[3]))
    elif cmd == "readback-sql":  # readback-sql <role> <dbname>
        sys.stdout.write(readback_sql(argv[2], argv[3]))
    elif cmd == "result":
        # result <readback.json> <stdout-file> <stderr-file> <rc> <writeprobe_rc> \
        #        <script_sha> <image_id> <out.json>
        rb, out, err, rc, wrc, script_sha, image_id, dest = argv[2:10]
        readback = judge_readback(json.loads(Path(rb).read_text()))
        stdout = Path(out).read_text()
        observation = judge_observation(stdout) if rc == "0" else {}
        stderr = Path(err).read_text()
        stop = stderr.strip().rsplit("STOP: ", 1)[-1][:60] if "STOP:" in stderr else ""
        checks = {
            "container_exit_zero": rc == "0",
            "observer_cannot_write": wrc != "0",
            **{f"role_{k}": v for k, v in readback.items()},
            **{f"obs_{k}": v for k, v in observation.items()},
        }
        result = {
            "status": "PASS" if all(checks.values()) and observation else "FAIL",
            "script": "a2_recovery_observe_container.py",
            "script_sha256": script_sha,
            "kit": "kit-v5",
            "image_id": image_id,
            "dsn_scheme": "postgresql",
            "stop_name": stop,
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "checks": checks,
        }
        Path(dest).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"recovery_observe_native: {result['status']}")
    else:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
