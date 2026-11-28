"""Log in with the snippet-written DSN and prove the observer's limits.

DSN only from env OBS_DSN (never argv, never printed). Output: names and booleans
and SQLSTATE codes only, to the file named by OUT.
"""

from __future__ import annotations

import json
import os
import sys

import psycopg

FOUR = (
    "mod_deploy.rollouts",
    "mod_deploy.rollout_attempts",
    "mod_deploy.rollout_attempt_settlements",
    "public.platform_idempotency_records",
)
INSERT = "INSERT INTO mod_deploy.rollouts DEFAULT VALUES"


def sqlstate_of(conn: psycopg.Connection, sql: str) -> str:
    try:
        conn.execute(sql)  # type: ignore[arg-type]
    except psycopg.Error as exc:
        return exc.sqlstate or "unknown"
    return "no_error"


def run(dsn: str) -> dict[str, object]:
    with psycopg.connect(dsn, autocommit=True, connect_timeout=10) as conn:
        selects = {}
        for table in FOUR:
            selects[table] = sqlstate_of(conn, f"SELECT count(*) FROM {table}")  # noqa: S608
        plans = sqlstate_of(conn, "SELECT count(*) FROM mod_deploy.deployment_plans")
        first = sqlstate_of(conn, INSERT)
        conn.execute("SET default_transaction_read_only = off")
        shown = conn.execute("SHOW default_transaction_read_only").fetchone()
        second = sqlstate_of(conn, INSERT)
        ssl_row = conn.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        ).fetchone()
    return {
        "driver": "psycopg" + psycopg.__version__.split(".")[0],
        "tls_session": bool(ssl_row and ssl_row[0]),
        "select_four_tables_ok": all(v == "no_error" for v in selects.values()),
        "select_deployment_plans_refused": plans == "42501",
        "insert_rollouts_refused": first in ("25006", "42501"),
        "insert_first_sqlstate": first,
        "read_only_switched_off": bool(shown and shown[0] == "off"),
        "insert_still_refused_after_read_only_off": second == "42501",
        "insert_second_sqlstate": second,
    }


if __name__ == "__main__":
    try:
        result = run(os.environ["OBS_DSN"])
    except Exception as exc:  # noqa: BLE001 - record the class only, never the DSN
        result = {"login_error": type(exc).__name__}
    with open(os.environ["OUT"], "w", encoding="utf-8") as handle:
        json.dump(result, handle, sort_keys=True)
    sys.exit(0)
