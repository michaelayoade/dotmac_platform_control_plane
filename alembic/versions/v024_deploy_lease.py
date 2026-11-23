"""The production (deploy) lease class, expand-only (P-CP1 WP5c, DESIGN-rev3 2.6.2).

A persistent app host is leased by the Control plane for the length of one
deploy or one role job. This is the *production class* beside the rehearsal class
`v023_lane3_store` created. It adds objects only.

## Shape

* **A new schema, `cp_deploy_lease`, not new objects in `cp_lane3`.** The
  rehearsal store's integrity pins (`lane3_store_integrity`) are an EXACT set of
  `cp_lane3` functions, triggers, constraints and indexes, and the standing rule
  is that no runtime role holds anything in `cp_lane3`. A deploy class inside
  `cp_lane3` would either break both or need the runtime role granted into it.
  Here the CP runtime role holds `USAGE` on `cp_deploy_lease` and `EXECUTE` on
  five functions of it, and NOTHING in `cp_lane3` (not `store_now()`, not
  `USAGE`): the functions are `SECURITY DEFINER`, owned by the migrator, and
  reach `cp_lane3` themselves.
* **One writer per host across both classes (M10).** Both classes take the SAME
  row lock: `cp_lane3.host_current_lease`, `FOR UPDATE`, keyed by host. The
  deploy functions read and move that row's `lease_id` pointer, so a host held
  by a rehearsal lease refuses a deploy acquire (`lease-held-by-another-run`,
  or `lease-host-mutated` once it expired or was released), and a host held by a
  deploy lease refuses a rehearsal acquire: the rehearsal function finds a
  pointer with no `host_leases` row, which it reads as a mutated host
  (`lease-host-mutated`) and which only a newer, destroyed E10 receipt for a
  reprovisioned machine can reopen. No `cp_lane3` object is created, altered or
  granted by this migration.
* **Retries are idempotent (the wire contract).** A second acquire by the SAME
  run, principal and target while its lease is live returns that lease; a second
  release by the same target and principal with the same `host_mutated` is a
  replay (`o_replay`). Any other repeat is refused.
* **Lease class.** `lease_class` is stored on the row: `serving` (ttl 1..900, total up
  to 10800, renewable) or `run_job` (ttl = total, at most 3600, never renewed:
  `lease-not-renewable`). The tables enforce it as well as the function.
* **Renewal (architect ruling Q-c/4).** A lease has a per-grant TTL
  (`ttl_seconds`, the plan's `lease_ttl_seconds`) and a total (`max_seconds`, the
  plan's `lease_max_seconds`, at most 10800). `deploy_renew` grants
  `min(ttl, max - time held)` as an append-only renewal row; the effective expiry
  is the later of the lease's and its renewals'. It refuses (never resurrects) a
  released, foreign or expired lease, and a lease already at its total.
* **Persistent-host rule.** A RELEASED lease is the clean state, whatever
  `host_mutated` says (a clean deploy necessarily releases a mutated host). A
  lease that EXPIRED UNRELEASED is standing `expired_unreleased`; the next
  acquire needs a reconcile marker (`p_marker`, the digest of Control's reconcile
  decision, spent once). The database does not judge the observation behind the
  marker: that is Control's `reconcile_marker_requires_match`, and the marker is
  asserted by the CP application after it verified a signed observation, in the
  same way as `principal_ref`.
* **Identity shift (W-i).** These functions do not use `session_user`: the CP
  application asserts `principal_ref` after verifying the target's PoP
  signature. The grant is therefore the whole authorization of the database
  side, and this migration reads it back before it commits.
* **Every function judges time on `cp_lane3.store_now()`**; no function reads the
  caller's clock. Writes go through functions only: the runtime role holds no
  table privilege. The migration does not `CREATE ROLE`.
* **Append-only evidence.** Leases and releases are refused UPDATE, DELETE and
  TRUNCATE by the existing `public.forbid_mutation_of_append_only_table()`.

## Refusal codes

The CLOSED code set of `lease_store.REFUSAL_CODES`, plus two added for this class
(`reconcile-marker-required`, `lease-max-reached`, `lease-not-renewable`). Mapping
used by the deploy class: an unknown lease or a malformed identity is
`lease-role-unbound`; a lease held by another run, `lease-held-by-another-run`;
an expired-unreleased host without a marker, `reconcile-marker-required`; a host
last held by the rehearsal class, `lease-host-mutated`; a lease already at its
total, `lease-max-reached`; a malformed marker,
`reprovision-receipt-mismatch`; a reused marker, `reprovision-receipt-spent`.

## Not for prod before the fence line closes

`held_fence_acl_drift` (the CP149 fence ACL line) must be closed before this
migration reaches production (DESIGN-rev3 6.3 floor). Main must stay deployable.

Revision ID: v024_deploy_lease
Revises: v023_lane3_store
Create Date: 2026-11-23
"""

# ruff: noqa: E501, S608
# Every statement below is a CONSTANT; no external value ever reaches it, and a
# PL/pgSQL body is one string by nature.
from __future__ import annotations

import contextlib
import hashlib

from alembic import op

revision = "v024_deploy_lease"
down_revision = "v023_lane3_store"
branch_labels = None
depends_on = None

#: SQLSTATE of every typed refusal (same as the rehearsal class).
REFUSAL_SQLSTATE = "L3001"

SCHEMA = "cp_deploy_lease"
#: The CP runtime role that serves the target API. Granted, never created, here.
RUNTIME_ROLE = "platform_api"

_GUARD = "public.forbid_mutation_of_append_only_table()"
#: sha256 of `pg_get_functiondef` for the append-only guard, as v023 pins it.
PUBLIC_GUARD_SHA256 = "a84c545276143a3dc138a57375459fb42daf23924c7030a0a9cdd1e42e87a74f"
PREFLIGHT_MAJOR = 16
PINNED_SEARCH_PATH = "pg_catalog, pg_temp"

_PRINTABLE = "'^[\\x21-\\x7e]{1,255}$'"
#: The run is `<target_ref>#<dispatch_id>` (up to 194 + 1 + 128 characters). PostgreSQL
#: regular expressions refuse a repetition bound above 255, so the length is its
#: own test.
_RUN = "'^[\\x21-\\x7e]+$'"
_RUN_MAX = 512
_HOST = "'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'"
_MARKER = "'^sha256:[0-9a-f]{64}$'"


def _refuse(code: str) -> str:
    return f"RAISE EXCEPTION '{code}' USING ERRCODE = 'L3001';"


def _append_only(table: str) -> tuple[str, ...]:
    return (
        f"CREATE TRIGGER trg_{table}_append_only BEFORE UPDATE OR DELETE "
        f"ON {SCHEMA}.{table} FOR EACH ROW EXECUTE FUNCTION {_GUARD}",
        f"CREATE TRIGGER trg_{table}_append_only_truncate BEFORE TRUNCATE "
        f"ON {SCHEMA}.{table} FOR EACH STATEMENT EXECUTE FUNCTION {_GUARD}",
    )


# ── tables ───────────────────────────────────────────────────────────────────

TABLES_SQL = (
    f"CREATE TABLE {SCHEMA}.deploy_host_leases ("
    " lease_id uuid PRIMARY KEY,"
    f" host_id text NOT NULL CHECK (host_id ~ {_HOST}),"
    f" target_ref text NOT NULL CHECK (target_ref ~ {_PRINTABLE}),"
    f" dispatch_run text NOT NULL CHECK (dispatch_run ~ {_RUN}"
    f" AND char_length(dispatch_run) <= {_RUN_MAX}),"
    f" principal_ref text NOT NULL CHECK (principal_ref ~ {_PRINTABLE}),"
    f" reconcile_marker_ref text UNIQUE CHECK (reconcile_marker_ref ~ {_MARKER}),"
    " acquired_at timestamptz NOT NULL,"
    " expires_at timestamptz NOT NULL,"
    # per-grant TTL (the plan's lease_ttl_seconds) and the total the plan sizes
    # the class is stored: a run_job lease is granted once (ttl = max, never
    # renewed); a serving lease is granted 1..900 s at a time up to its total
    " lease_class text NOT NULL CHECK (lease_class IN ('serving', 'run_job')),"
    " ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 3600),"
    " max_seconds integer NOT NULL CHECK (max_seconds BETWEEN 1 AND 10800),"
    " CHECK ((lease_class = 'serving' AND ttl_seconds <= 900"
    "  AND max_seconds >= ttl_seconds)"
    "  OR (lease_class = 'run_job' AND ttl_seconds = max_seconds)),"
    " seq bigserial NOT NULL,"
    " CHECK (expires_at = acquired_at + ttl_seconds * interval '1 second'))",
    f"CREATE TABLE {SCHEMA}.deploy_host_lease_renewals ("
    f" lease_id uuid NOT NULL REFERENCES {SCHEMA}.deploy_host_leases (lease_id),"
    " seq bigserial NOT NULL,"
    " renewed_at timestamptz NOT NULL,"
    " new_expires_at timestamptz NOT NULL,"
    " granted_seconds integer NOT NULL CHECK (granted_seconds BETWEEN 1 AND 900),"
    " PRIMARY KEY (lease_id, seq))",
    f"CREATE TABLE {SCHEMA}.deploy_host_lease_releases ("
    f" lease_id uuid PRIMARY KEY REFERENCES {SCHEMA}.deploy_host_leases (lease_id),"
    " released_at timestamptz NOT NULL,"
    " host_mutated boolean NOT NULL,"
    f" released_by text NOT NULL CHECK (released_by ~ {_PRINTABLE}))",
)

# The release instant is the database's, never the caller's.
TRIGGER_FUNCTIONS_SQL = (
    f"CREATE FUNCTION {SCHEMA}.stamp_deploy_release_time() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp "
    "AS $$ BEGIN "
    "NEW.released_at := cp_lane3.store_now(); RETURN NEW; END $$",
    # The lease's effective expiry: its own, or the latest renewal's if later.
    f"CREATE FUNCTION {SCHEMA}.effective_expiry(p_lease uuid) RETURNS timestamptz "
    "LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp "
    "AS $$ SELECT greatest(l.expires_at, coalesce((SELECT max(r.new_expires_at) "
    f"FROM {SCHEMA}.deploy_host_lease_renewals r WHERE r.lease_id = l.lease_id), "
    f"l.expires_at)) FROM {SCHEMA}.deploy_host_leases l "
    "WHERE l.lease_id = p_lease $$",
)

TRIGGERS_SQL = (
    f"CREATE TRIGGER trg_deploy_host_lease_releases_stamp BEFORE INSERT "
    f"ON {SCHEMA}.deploy_host_lease_releases "
    f"FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.stamp_deploy_release_time()",
    *_append_only("deploy_host_leases"),
    *_append_only("deploy_host_lease_renewals"),
    *_append_only("deploy_host_lease_releases"),
)

# ── the deploy functions ─────────────────────────────────────────────────────

_DEFINER = "LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp"
_EFF = f"{SCHEMA}.effective_expiry"

FUNCTIONS_SQL = (
    # deploy_acquire: the shared host row lock, then the persistent-host rule.
    f"CREATE FUNCTION {SCHEMA}.deploy_acquire(p_target_ref text, p_host text, "
    "p_run text, p_ttl integer, p_max integer, p_class text, p_principal text, "
    "p_marker text DEFAULT NULL) "
    "RETURNS TABLE (o_lease_id uuid, o_ttl integer, o_acquired_at timestamptz, "
    "o_expires_at timestamptz, o_store_now timestamptz) " + _DEFINER + " AS $$ "
    "DECLARE v_now timestamptz; v_acq timestamptz; v_prev uuid; v_exp timestamptz; "
    "v_dl record; v_rl record; v_new uuid; v_needs_marker boolean := false; "
    "BEGIN "
    "IF p_class IS NULL OR p_class NOT IN ('serving', 'run_job') "
    "OR p_ttl IS NULL OR p_ttl < 1 OR p_max IS NULL OR p_max < p_ttl "
    "OR p_max > 10800 OR (p_class = 'serving' AND p_ttl > 900) "
    "OR (p_class = 'run_job' AND (p_ttl <> p_max OR p_ttl > 3600)) THEN "
    + _refuse("lease-ttl-invalid")
    + " END IF; "
    f"IF p_host IS NULL OR p_host !~ {_HOST} "
    f"OR p_target_ref IS NULL OR p_target_ref !~ {_PRINTABLE} "
    f"OR p_run IS NULL OR p_run !~ {_RUN} OR char_length(p_run) > {_RUN_MAX} "
    f"OR p_principal IS NULL OR p_principal !~ {_PRINTABLE} THEN "
    + _refuse("lease-role-unbound")
    + " END IF; "
    f"IF p_marker IS NOT NULL AND p_marker !~ {_MARKER} THEN "
    + _refuse("reprovision-receipt-mismatch")
    + " END IF; "
    "INSERT INTO cp_lane3.host_current_lease (host_id) VALUES (p_host) "
    "ON CONFLICT DO NOTHING; "
    "SELECT hc.lease_id INTO v_prev FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = p_host FOR UPDATE; "
    "v_now := cp_lane3.store_now(); "
    "v_acq := date_trunc('second', v_now); "
    "IF v_prev IS NOT NULL THEN "
    f"SELECT * INTO v_dl FROM {SCHEMA}.deploy_host_leases l "
    "WHERE l.lease_id = v_prev; "
    "IF NOT FOUND THEN "
    # the pointer names a rehearsal-class lease: one writer across both classes
    "SELECT * INTO v_rl FROM cp_lane3.host_leases l WHERE l.lease_id = v_prev; "
    "IF FOUND AND NOT EXISTS (SELECT 1 FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = v_prev) AND v_now < v_rl.expires_at THEN "
    + _refuse("lease-held-by-another-run")
    + " END IF; "
    + _refuse("lease-host-mutated")
    + " END IF; "
    f"IF NOT EXISTS (SELECT 1 FROM {SCHEMA}.deploy_host_lease_releases x "
    "WHERE x.lease_id = v_prev) THEN "
    f"v_exp := {_EFF}(v_prev); "
    "IF v_now < v_exp THEN "
    # a retry by the SAME run, principal and target is the same request: it gets
    # its own live lease back, never a second one
    "IF v_dl.dispatch_run = p_run AND v_dl.principal_ref = p_principal "
    "AND v_dl.target_ref = p_target_ref THEN "
    "RETURN QUERY SELECT l.lease_id, "
    "ceil(extract(epoch FROM (v_exp - v_now)))::integer, l.acquired_at, v_exp, v_now "
    f"FROM {SCHEMA}.deploy_host_leases l WHERE l.lease_id = v_prev; "
    "RETURN; END IF; " + _refuse("lease-held-by-another-run") + " END IF; "
    # expired unreleased: only a reconcile marker reopens the host
    "IF p_marker IS NULL THEN " + _refuse("reconcile-marker-required") + " END IF; "
    "v_needs_marker := true; "
    "END IF; END IF; "
    "IF v_needs_marker AND EXISTS (SELECT 1 "
    f"FROM {SCHEMA}.deploy_host_leases l2 "
    "WHERE l2.reconcile_marker_ref = p_marker) THEN "
    + _refuse("reprovision-receipt-spent")
    + " END IF; "
    "v_new := gen_random_uuid(); "
    f"INSERT INTO {SCHEMA}.deploy_host_leases (lease_id, host_id, target_ref, "
    "dispatch_run, principal_ref, reconcile_marker_ref, acquired_at, expires_at, "
    "lease_class, ttl_seconds, max_seconds) VALUES (v_new, p_host, p_target_ref, "
    "p_run, p_principal, CASE WHEN v_needs_marker THEN p_marker END, v_acq, "
    "v_acq + p_ttl * interval '1 second', p_class, p_ttl, p_max); "
    "UPDATE cp_lane3.host_current_lease SET lease_id = v_new WHERE host_id = p_host; "
    "RETURN QUERY SELECT l.lease_id, l.ttl_seconds, l.acquired_at, l.expires_at, "
    f"v_now FROM {SCHEMA}.deploy_host_leases l WHERE l.lease_id = v_new; END $$",
    # deploy_covers: live, unreleased, held by THIS dispatch run, on store time.
    f"CREATE FUNCTION {SCHEMA}.deploy_covers(p_lease uuid, p_run text) "
    "RETURNS timestamptz " + _DEFINER + " AS $$ "
    "DECLARE v_l record; v_now timestamptz; "
    "BEGIN "
    f"SELECT * INTO v_l FROM {SCHEMA}.deploy_host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "v_now := cp_lane3.store_now(); "
    f"IF EXISTS (SELECT 1 FROM {SCHEMA}.deploy_host_lease_releases x "
    f"WHERE x.lease_id = p_lease) OR v_now >= {_EFF}(p_lease) THEN "
    + _refuse("lease-expired")
    + " END IF; "
    "IF p_run IS NULL OR v_l.dispatch_run <> p_run THEN "
    + _refuse("lease-foreign-run")
    + " END IF; "
    "RETURN v_now; END $$",
    # deploy_renew: min(per-grant ttl, max - time held); never past the total.
    f"CREATE FUNCTION {SCHEMA}.deploy_renew(p_lease uuid, p_run text) "
    "RETURNS TABLE (o_lease_id uuid, o_granted integer, "
    "o_expires_at timestamptz, o_store_now timestamptz) " + _DEFINER + " AS $$ "
    "DECLARE v_l record; v_now timestamptz; v_t timestamptz; v_cur timestamptz; "
    "v_cap timestamptz; v_new timestamptz; v_g integer; "
    "BEGIN "
    f"SELECT * INTO v_l FROM {SCHEMA}.deploy_host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "PERFORM 1 FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = v_l.host_id FOR UPDATE; "
    "v_now := cp_lane3.store_now(); v_t := date_trunc('second', v_now); "
    f"IF EXISTS (SELECT 1 FROM {SCHEMA}.deploy_host_lease_releases x "
    "WHERE x.lease_id = p_lease) THEN "
    + _refuse("lease-already-released")
    + " END IF; "
    "IF p_run IS NULL OR v_l.dispatch_run <> p_run THEN "
    + _refuse("lease-foreign-run")
    + " END IF; "
    f"v_cur := {_EFF}(p_lease); "
    "IF v_now >= v_cur THEN " + _refuse("lease-expired") + " END IF; "
    "IF v_l.lease_class = 'run_job' THEN "
    + _refuse("lease-not-renewable")
    + " END IF; "
    "v_cap := v_l.acquired_at + v_l.max_seconds * interval '1 second'; "
    "IF v_t >= v_cap THEN " + _refuse("lease-max-reached") + " END IF; "
    # min(ttl, max - held), as the contract's reference ledger grants it
    "v_g := least(v_l.ttl_seconds, extract(epoch FROM (v_cap - v_t))::integer); "
    "v_new := v_t + v_g * interval '1 second'; "
    "IF v_new < v_cur THEN v_new := v_cur; v_g := extract(epoch FROM (v_new - v_t))::integer; END IF; "
    f"INSERT INTO {SCHEMA}.deploy_host_lease_renewals (lease_id, renewed_at, "
    "new_expires_at, granted_seconds) VALUES (p_lease, v_t, v_new, v_g); "
    "RETURN QUERY SELECT p_lease, v_g, v_new, v_now; END $$",
    # deploy_release: under the shared host row lock; one release; never late.
    f"CREATE FUNCTION {SCHEMA}.deploy_release(p_lease uuid, p_target_ref text, "
    "p_principal text, p_host_mutated boolean) "
    "RETURNS TABLE (o_released_at timestamptz, o_replay boolean) "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_l record; v_rel record; v_now timestamptz; v_at timestamptz; "
    "BEGIN "
    f"SELECT * INTO v_l FROM {SCHEMA}.deploy_host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "IF p_host_mutated IS NULL THEN " + _refuse("host-mutated-required") + " END IF; "
    "PERFORM 1 FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = v_l.host_id FOR UPDATE; "
    "v_now := cp_lane3.store_now(); "
    # the holder: the authenticated target and its credential principal
    "IF p_target_ref IS DISTINCT FROM v_l.target_ref "
    "OR p_principal IS DISTINCT FROM v_l.principal_ref THEN "
    + _refuse("release-not-this-lease")
    + " END IF; "
    f"SELECT * INTO v_rel FROM {SCHEMA}.deploy_host_lease_releases x "
    "WHERE x.lease_id = p_lease; "
    "IF FOUND THEN "
    # a second release saying the same thing is a replay (wire contract)
    "IF v_rel.host_mutated = p_host_mutated THEN "
    "RETURN QUERY SELECT v_rel.released_at, true; RETURN; END IF; "
    + _refuse("lease-already-released")
    + " END IF; "
    f"IF v_now >= {_EFF}(p_lease) THEN " + _refuse("lease-expired") + " END IF; "
    f"INSERT INTO {SCHEMA}.deploy_host_lease_releases (lease_id, released_at, "
    "host_mutated, released_by) VALUES (p_lease, v_now, p_host_mutated, "
    "p_principal) RETURNING released_at INTO v_at; "
    "RETURN QUERY SELECT v_at, false; END $$",
    # deploy_standing: the host's standing on store time, for GET lease/standing.
    f"CREATE FUNCTION {SCHEMA}.deploy_standing(p_host text) "
    "RETURNS TABLE (o_standing text, o_lease_id uuid, o_expires_at timestamptz, "
    "o_store_now timestamptz, o_dispatch_run text) " + _DEFINER + " AS $$ "
    "DECLARE v_id uuid; v_l record; v_now timestamptz; v_s text; v_e timestamptz; "
    "BEGIN "
    "SELECT hc.lease_id INTO v_id FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = p_host; "
    "IF v_id IS NULL THEN " + _refuse("lease-host-unknown") + " END IF; "
    f"SELECT * INTO v_l FROM {SCHEMA}.deploy_host_leases l WHERE l.lease_id = v_id; "
    "IF NOT FOUND THEN " + _refuse("lease-host-mutated") + " END IF; "
    "v_now := cp_lane3.store_now(); "
    f"v_e := {_EFF}(v_id); "
    f"IF EXISTS (SELECT 1 FROM {SCHEMA}.deploy_host_lease_releases x "
    "WHERE x.lease_id = v_id) THEN v_s := 'released'; "
    "ELSIF v_now >= v_e THEN v_s := 'expired_unreleased'; "
    "ELSE v_s := 'held'; END IF; "
    "RETURN QUERY SELECT v_s, v_l.lease_id, v_e, v_now, v_l.dispatch_run; END $$",
)

#: Every function the runtime role is granted. Written down because the grant,
#: the read-back and the privilege proof must name the same set.
RUNTIME_ROLE_FUNCTIONS = (
    "deploy_acquire(text, text, text, integer, integer, text, text, text)",
    "deploy_covers(uuid, text)",
    "deploy_release(uuid, text, text, boolean)",
    "deploy_renew(uuid, text)",
    "deploy_standing(text)",
)
#: The internal functions: owned and executed by the definer, never granted.
INTERNAL_FUNCTIONS = ("stamp_deploy_release_time()", "effective_expiry(uuid)")

# ── the privilege read-back ──────────────────────────────────────────────────
#
# Counts ACL entries whose grantee is neither the object's owner nor the one
# intended grant. A NULL ACL is the type's DEFAULT, which `acldefault` expands.
_RT = f"(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = '{RUNTIME_ROLE}')"

SCHEMA_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_namespace n, "
    "LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, "
    "pg_catalog.acldefault('n'::\"char\", n.nspowner))) a "
    f"WHERE n.nspname = '{SCHEMA}' AND a.grantee <> n.nspowner "
    f"AND NOT (a.grantee = {_RT} AND a.privilege_type = 'USAGE' "
    "AND NOT a.is_grantable)"
)
SCHEMA_GRANT_PRESENT_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_namespace n, "
    "LATERAL pg_catalog.aclexplode(n.nspacl) a "
    f"WHERE n.nspname = '{SCHEMA}' AND a.grantee = {_RT} "
    "AND a.privilege_type = 'USAGE'"
)
RELATION_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, "
    "LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault("
    "CASE WHEN c.relkind = 'S' THEN 's'::\"char\" ELSE 'r'::\"char\" END, "
    "c.relowner))) a "
    f"WHERE n.nspname = '{SCHEMA}' AND a.grantee <> c.relowner"
)
COLUMN_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_attribute t "
    "JOIN pg_catalog.pg_class c ON c.oid = t.attrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, "
    "LATERAL pg_catalog.aclexplode(t.attacl) a "
    f"WHERE n.nspname = '{SCHEMA}' AND t.attacl IS NOT NULL "
    "AND a.grantee <> c.relowner"
)
FUNCTION_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace, "
    "LATERAL pg_catalog.aclexplode(COALESCE(p.proacl, "
    "pg_catalog.acldefault('f'::\"char\", p.proowner))) a "
    f"WHERE n.nspname = '{SCHEMA}' AND a.grantee <> p.proowner "
    f"AND NOT (a.grantee = {_RT} AND a.privilege_type = 'EXECUTE' "
    "AND NOT a.is_grantable AND left(p.proname, 7) = 'deploy_')"
)
FUNCTION_GRANT_COUNT_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace, "
    "LATERAL pg_catalog.aclexplode(p.proacl) a "
    f"WHERE n.nspname = '{SCHEMA}' AND a.grantee = {_RT} "
    "AND a.privilege_type = 'EXECUTE' AND left(p.proname, 7) = 'deploy_'"
)
DEFAULT_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_default_acl d "
    "JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace "
    f"WHERE n.nspname = '{SCHEMA}'"
)
#: The runtime role still holds nothing in the rehearsal schema.
LANE3_REACH_SQL = (
    f"SELECT pg_catalog.has_schema_privilege('{RUNTIME_ROLE}', 'cp_lane3', 'USAGE')"
)
OWNER_NOT_MIGRATOR_SQL = (
    "SELECT count(*) FROM ("
    f"SELECT nspowner AS o FROM pg_catalog.pg_namespace WHERE nspname = '{SCHEMA}' "
    "UNION ALL SELECT c.relowner FROM pg_catalog.pg_class c JOIN "
    f"pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{SCHEMA}' "
    "UNION ALL SELECT p.proowner FROM pg_catalog.pg_proc p JOIN "
    f"pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '{SCHEMA}' "
    "UNION ALL SELECT t.typowner FROM pg_catalog.pg_type t JOIN "
    f"pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = '{SCHEMA}'"
    ") owners WHERE o <> (SELECT r.oid FROM pg_catalog.pg_roles r "
    "WHERE r.rolname = current_user)"
)

# ── the preflight: refuse BEFORE any DDL ─────────────────────────────────────

PREFLIGHT_VERSION_SQL = "SHOW server_version_num"
PREFLIGHT_ROLE_SQL = (
    "SELECT rolsuper, rolcreaterole FROM pg_catalog.pg_roles "
    "WHERE rolname = current_user"
)
PREFLIGHT_RUNTIME_ROLE_SQL = (
    f"SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = '{RUNTIME_ROLE}'"
)
PREFLIGHT_EVENT_TRIGGERS_SQL = "SELECT count(*) FROM pg_catalog.pg_event_trigger"
PREFLIGHT_DEFAULT_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_default_acl d WHERE (d.defaclnamespace = 0 "
    "AND d.defaclrole = (SELECT r.oid FROM pg_catalog.pg_roles r "
    "WHERE r.rolname = current_user)) OR d.defaclnamespace IN "
    f"(SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = '{SCHEMA}')"
)
PREFLIGHT_SCHEMA_SQL = (
    f"SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = '{SCHEMA}'"
)
#: v023's shared row-lock point and clock must exist.
PREFLIGHT_V023_SQL = (
    "SELECT (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
    "ON n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' "
    "AND c.relname = 'host_current_lease') "
    "+ (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
    "ON n.oid = p.pronamespace WHERE n.nspname = 'cp_lane3' AND p.proname = 'store_now')"
)
PREFLIGHT_GUARD_SQL = (
    "SELECT pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'public' "
    "AND p.proname = 'forbid_mutation_of_append_only_table'"
)


@contextlib.contextmanager
def _pinned_search_path(connection):  # type: ignore[no-untyped-def]
    """Resolve every name in a read-back from `pg_catalog` only, then restore."""
    saved = connection.exec_driver_sql(
        "SELECT pg_catalog.current_setting('search_path')"
    ).scalar_one()
    connection.exec_driver_sql(
        "SELECT pg_catalog.set_config('search_path', %s, true)",
        (PINNED_SEARCH_PATH,),
    )
    try:
        yield
    finally:
        connection.exec_driver_sql(
            "SELECT pg_catalog.set_config('search_path', %s, true)", (saved,)
        )


def _preflight(connection) -> None:  # type: ignore[no-untyped-def]
    """Refuse, by NAME and before any DDL, unless the preconditions hold."""

    def refuse(name: str) -> None:
        raise RuntimeError(f"v024_deploy_lease preflight refused: {name}")

    with _pinned_search_path(connection):
        major = (
            int(connection.exec_driver_sql(PREFLIGHT_VERSION_SQL).scalar_one()) // 10000
        )
        if major != PREFLIGHT_MAJOR:
            refuse("server-major-not-16")
        row = connection.exec_driver_sql(PREFLIGHT_ROLE_SQL).one_or_none()
        if row is None:
            refuse("migration-role-unreadable")
        if row[0] is not False:
            refuse("migration-role-is-superuser")
        if row[1] is not False:
            refuse("migration-role-has-createrole")
        runtime = connection.exec_driver_sql(PREFLIGHT_RUNTIME_ROLE_SQL).one_or_none()
        if runtime is None:
            refuse("runtime-role-absent")
        # Only the attribute that makes a grant meaningless is refused here. The
        # rest of the attribute set is U16's names-only read-back, not a guess.
        if runtime[0] is not False:
            refuse("runtime-role-is-superuser")
        if connection.exec_driver_sql(PREFLIGHT_EVENT_TRIGGERS_SQL).scalar_one():
            refuse("event-triggers-exist")
        if connection.exec_driver_sql(PREFLIGHT_DEFAULT_ACL_SQL).scalar_one():
            refuse("default-privileges-would-apply")
        if connection.exec_driver_sql(PREFLIGHT_SCHEMA_SQL).scalar_one():
            refuse("schema-already-exists")
        if connection.exec_driver_sql(PREFLIGHT_V023_SQL).scalar_one() != 2:
            refuse("lane3-store-absent")
        guards = connection.exec_driver_sql(PREFLIGHT_GUARD_SQL).all()
        if len(guards) != 1:
            refuse("append-only-guard-absent-or-ambiguous")
        if (
            hashlib.sha256(str(guards[0][0]).encode()).hexdigest()
            != PUBLIC_GUARD_SHA256
        ):
            refuse("append-only-guard-changed")


def upgrade() -> None:
    connection = op.get_bind()
    _preflight(connection)

    def run(statements: tuple[str, ...]) -> None:
        for statement in statements:
            connection.exec_driver_sql(statement)

    connection.exec_driver_sql("CREATE SCHEMA cp_deploy_lease")
    connection.exec_driver_sql(f"REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC")
    run(TABLES_SQL)
    run(TRIGGER_FUNCTIONS_SQL)
    run(TRIGGERS_SQL)
    run(FUNCTIONS_SQL)
    for signature in (*RUNTIME_ROLE_FUNCTIONS, *INTERNAL_FUNCTIONS):
        connection.exec_driver_sql(
            f"REVOKE ALL ON FUNCTION {SCHEMA}.{signature} FROM PUBLIC"
        )
    # The one grant of this migration (W-i): the runtime role may call the five
    # functions and nothing else. No table, no sequence, nothing in cp_lane3.
    connection.exec_driver_sql(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {RUNTIME_ROLE}")
    for signature in RUNTIME_ROLE_FUNCTIONS:
        connection.exec_driver_sql(
            f"GRANT EXECUTE ON FUNCTION {SCHEMA}.{signature} TO {RUNTIME_ROLE}"
        )
    with _pinned_search_path(connection):
        for sql, message in (
            (SCHEMA_ACL_SQL, "an ACL entry on the schema beyond the one grant"),
            (RELATION_ACL_SQL, "an ACL entry on a table or sequence"),
            (COLUMN_ACL_SQL, "a column ACL entry"),
            (FUNCTION_ACL_SQL, "an ACL entry on a function beyond the five grants"),
            (DEFAULT_ACL_SQL, "a default-privilege rule names the schema"),
            (OWNER_NOT_MIGRATOR_SQL, "an object not owned by the migrating role"),
        ):
            if connection.exec_driver_sql(sql).scalar_one():
                raise RuntimeError(f"v024_deploy_lease: {message}")
        if connection.exec_driver_sql(SCHEMA_GRANT_PRESENT_SQL).scalar_one() != 1:
            raise RuntimeError("v024_deploy_lease: the schema grant is not in place")
        if connection.exec_driver_sql(FUNCTION_GRANT_COUNT_SQL).scalar_one() != len(
            RUNTIME_ROLE_FUNCTIONS
        ):
            raise RuntimeError("v024_deploy_lease: the function grants are not exact")
        if connection.exec_driver_sql(LANE3_REACH_SQL).scalar_one():
            raise RuntimeError(
                "v024_deploy_lease: the runtime role reaches the rehearsal schema"
            )


def downgrade() -> None:
    raise RuntimeError(
        "the deploy lease class cannot be downgraded; it is retained evidence, "
        "forward repair required"
    )
