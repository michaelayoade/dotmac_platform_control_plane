"""Exact UID10 reader token revocation SQL preparation; no execution authority.

Cleanup checks only stable owner identity and the exact new token row. It does
not depend on grants/flags that could drift after mint. Require ON_ERROR_STOP,
committed metadata reconciliation, and same-token HTTP401; never retry an
uncertain transaction. No connection or credential material is accepted here.
"""
_KEYS = frozenset({"kind", "token_id", "user_id", "username", "token_name",
                   "scope", "created_unix"})
_INT64_MAX = 9223372036854775807


def _positive_int(value):
    if type(value) is not int or not 1 <= value <= _INT64_MAX:
        raise ValueError("reader_binding_integer")
    return value


def _literal(value):
    return "'" + value.replace("'", "''") + "'"


def build_revocation_sql(binding):
    """Accept only seven exact metadata fields; return one guarded transaction."""
    if type(binding) is not dict or set(binding) != _KEYS:
        raise ValueError("reader_binding_keys")
    fixed = {"kind": "reader", "user_id": 10, "username": "cp-bundle-reader",
             "token_name": "cp-artifact-bootstrap-20261127-r2", "scope": "read:package"}
    if any(type(binding[k]) is not type(v) or binding[k] != v
           for k, v in fixed.items()):
        raise ValueError("reader_binding_identity")
    token_id = _positive_int(binding["token_id"])
    user_id = _positive_int(binding["user_id"])
    created = _positive_int(binding["created_unix"])
    if token_id <= 30:
        raise ValueError("reader_reserved_token_id")
    username = fixed["username"]
    token_name = fixed["token_name"]
    expected_scope = fixed["scope"]

    owner = f'''u.id = {user_id}
       AND u.name = {_literal(username)}
       AND u.lower_name = {_literal(username)}
       AND u.type = 0'''

    return f'''-- SOURCE PREPARATION ONLY: execution needs separate exact write authority.
-- Require psql ON_ERROR_STOP=1; never retry an ambiguous commit automatically.
BEGIN;
SET LOCAL search_path = public, pg_catalog;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '5s';
DO $cp_exact_revoke$
DECLARE
    affected bigint;
BEGIN
    -- Lock the exact owner identity before the sole data mutation.
    PERFORM u.id FROM "user" u
     WHERE {owner}
     FOR UPDATE;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION 'revocation refused: owner identity mismatch';
    END IF;
    DELETE FROM access_token a
     WHERE a.id = {token_id}
       AND a.uid = {user_id}
       AND a.name = {_literal(token_name)}
       AND a.scope = {_literal(expected_scope)}
       AND a.created_unix = {created}
       AND EXISTS (SELECT 1 FROM "user" u WHERE {owner});
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION 'revocation refused: exact token row/owner guard mismatch';
    END IF;
END;
$cp_exact_revoke$;
COMMIT;
-- A pre-COMMIT marker is not commit proof; reconcile committed absence separately.
SELECT '{{"status":"EXACT_TOKEN_ROW_TRANSACTION_COMMITTED","deleted_rows":1}}'::json;
'''
