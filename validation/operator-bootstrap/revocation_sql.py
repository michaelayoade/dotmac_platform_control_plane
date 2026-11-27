"""Prepare exact-row revocation SQL; never connect to or execute against a database.

This is source preparation, not live-write authority. Callers must independently
bind freshly minted metadata, protect the privileged mutation window, and use a
pinned psql invocation with ON_ERROR_STOP=1. Row locks do not freeze privileged
administrators. No advisory lock is such a freeze. Strict capability and isolation
checks belong before minting; cleanup deliberately depends only on stable owner
and exact new token identity, so later grant/permission drift cannot block it.
Owner rename still refuses cleanup and needs reconciliation in the exclusive window.

The fixed JSON result is emitted AFTER COMMIT. Even that output is not sufficient
native revocation proof: require successful psql completion, committed read-only
absence/no-collateral reconciliation, and the same token's HTTP 401. A disconnect
can leave commit outcome unknown; reconcile without blindly retrying DELETE.
Any output marker before COMMIT would not prove commit.
"""

import re


_KEYS = frozenset({
    "kind", "token_id", "user_id", "username", "token_name", "scope", "created_unix",
})
_INT64_MAX = 9223372036854775807
_PROTECTED_TOKEN_IDS = frozenset({2, 16, 26, 28})
_PROTECTED_USER_IDS = frozenset({1, 2, 3, 4, 5})
_NAME = re.compile(r"[a-z0-9-]{1,64}", re.ASCII)
_SUFFIX = re.compile(r"[a-z0-9][a-z0-9-]{6,30}[a-z0-9]", re.ASCII)


def _positive_int(value, field):
    if type(value) is not int or not 1 <= value <= _INT64_MAX:
        raise ValueError(field + " must be a positive signed-64-bit integer")
    return value


def _name(value, field, prefix=None):
    if type(value) is not str or not _NAME.fullmatch(value):
        raise ValueError(field + " must be a lowercase simple name of at most 64 characters")
    if prefix is not None:
        if not value.startswith(prefix) or not _SUFFIX.fullmatch(value[len(prefix):]):
            raise ValueError(field + " must have its fixed prefix and an 8..32 character suffix")
    return value


def _literal(value):
    """Only prevalidated ASCII metadata reaches SQL literals; escape defensively."""
    return "'" + value.replace("'", "''") + "'"


def build_revocation_sql(binding: dict) -> str:
    """Return one guarded transaction plus a fixed, nonsecret post-commit result.

    Accept exactly the seven metadata keys in _KEYS. No token material, owner
    flags, arbitrary predicates, SQL fragments, scope lists, or configuration.
    Prefixes prevent adopting an existing general-purpose token; the execution
    owner must still establish that this is the newly minted row.
    """
    if type(binding) is not dict or set(binding) != _KEYS:
        raise ValueError("binding must contain exactly the seven documented metadata keys")
    kind = binding["kind"]
    if type(kind) is not str or kind not in ("canary", "bootstrap"):
        raise ValueError("kind must be canary or bootstrap")
    token_id = _positive_int(binding["token_id"], "token_id")
    user_id = _positive_int(binding["user_id"], "user_id")
    created = _positive_int(binding["created_unix"], "created_unix")
    if token_id in _PROTECTED_TOKEN_IDS:
        raise ValueError("protected existing token ID")

    if kind == "canary":
        if user_id in _PROTECTED_USER_IDS:
            raise ValueError("canary must use a fresh, separate principal")
        username = _name(binding["username"], "username", "cp-revoke-proof-")
        token_name = _name(binding["token_name"], "token_name", "cp-canary-read-")
        expected_scope = "read:user"
    else:
        username = _name(binding["username"], "username")
        if user_id != 1 or username != "dotmac-admin":
            raise ValueError("bootstrap requires exact dotmac-admin UID 1")
        token_name = _name(binding["token_name"], "token_name", "cp-org-bootstrap-")
        expected_scope = "write:organization"
    if type(binding["scope"]) is not str or binding["scope"] != expected_scope:
        raise ValueError("scope differs from the fixed scope for this kind")

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
