"""The Lane 3 lease store and E10 receipt tables (`cp_lane3`), expand-only.

Pre-E11 design sections 1.2, 1.3, 3.1-3.3. CP is the lease store (U5, Michael's
ruling) and the home of the per-VM E10 receipt (Q2-A). Nothing here is read by
any existing code path; the migration only adds objects.

## Shape

* **A new schema, `cp_lane3`.** `REVOKE ALL ... FROM PUBLIC`, and no runtime
  role is ever granted `USAGE`: `platform_api`, `app_user`, the per-run
  consumption role and PUBLIC all hold nothing here, so a stray table grant
  stays unreachable. Only the per-run LEASE role (created by the E6 ceremony,
  never by this migration) receives `USAGE` plus `EXECUTE` on the functions.
* **Writes through functions only.** The lease role holds no table privilege at
  all. Every function is `SECURITY DEFINER`, pins
  `search_path = pg_catalog, cp_lane3, pg_temp`, uses no dynamic SQL, and has
  `EXECUTE` revoked from PUBLIC explicitly. (`ALTER DEFAULT PRIVILEGES` would
  change the migration role's defaults for every schema, which is a wider act
  than this migration owns; a catalogue test asserts no `cp_lane3` function is
  PUBLIC-executable instead.) The migration does not `CREATE ROLE`.
* **Every function judges time on `cp_lane3.store_now()`**, which is
  `clock_timestamp()`; no function reads the caller's clock.
* **Append-only evidence.** Receipts, destructions, bindings, releases and the
  lease rows are refused UPDATE, DELETE and TRUNCATE by the existing
  `public.forbid_mutation_of_append_only_table()` guard, except two narrow
  exceptions guarded by their own triggers: the one-time NULL -> value bind of a
  lease's document, and the `host_current_lease` row-lock row.

* **The migration proves its own privileges.** Before it commits it reads the
  catalogue back: the schema, every table and sequence, every column and every
  function must carry NO ACL entry other than their owner's (the migration grants
  nothing: the lease role is granted by the ceremony), and no `pg_default_acl`
  rule may name the schema. `lane3_store_integrity` pins every function body and
  trigger afterwards, in CI and for the E10a read-back.

## Refusal codes

A function refuses with `RAISE EXCEPTION '<code>' USING ERRCODE = 'L3001'`.
The code set is closed and mapped one to one by `vendor_cp.deployment.lease_store`;
anything else becomes `store-error`.

Revision ID: v023_lane3_store
Revises: v022_deploy_agent
Create Date: 2026-11-19
"""

# ruff: noqa: E501, S608
# Every statement below is a CONSTANT assembled from module constants (regex
# fragments, refusal codes); no external value ever reaches it, and a PL/pgSQL
# body is one string by nature.
from __future__ import annotations

from alembic import op

revision = "v023_lane3_store"
down_revision = "v022_deploy_agent"
branch_labels = None
depends_on = None

#: SQLSTATE of every typed refusal this schema raises.
REFUSAL_SQLSTATE = "L3001"

_GUARD = "public.forbid_mutation_of_append_only_table()"

_HEX64 = "[0-9a-f]{64}"
_B64_RAW = "decode(translate({col}, '-_', '+/') || '=', 'base64')"


def _append_only(table: str) -> tuple[str, ...]:
    return (
        f"CREATE TRIGGER trg_{table}_append_only BEFORE UPDATE OR DELETE "
        f"ON cp_lane3.{table} FOR EACH ROW EXECUTE FUNCTION {_GUARD}",
        f"CREATE TRIGGER trg_{table}_append_only_truncate BEFORE TRUNCATE "
        f"ON cp_lane3.{table} FOR EACH STATEMENT EXECUTE FUNCTION {_GUARD}",
    )


# ── the clock ────────────────────────────────────────────────────────────────

CLOCK_SQL = (
    "CREATE FUNCTION cp_lane3.store_now() RETURNS timestamptz "
    "LANGUAGE sql VOLATILE SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ SELECT clock_timestamp() $$",
)

# ── tables ───────────────────────────────────────────────────────────────────

_PUBKEY = _B64_RAW.format(col="incarnation_public_key_b64url")

TABLES_SQL = (
    "CREATE TABLE cp_lane3.e10_receipts ("
    " receipt_ref text PRIMARY KEY"
    "  CHECK (receipt_ref ~ '^e10-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    "[0-9a-f]{4}-[0-9a-f]{12}$'),"
    " vm_alias text NOT NULL CHECK (vm_alias ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),"
    " host_id text NOT NULL"
    "  CHECK (host_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),"
    " machine_id text NOT NULL CHECK (machine_id ~ '^[0-9a-f]{32}$'),"
    " ssh_host_key_fingerprint text NOT NULL"
    "  CHECK (ssh_host_key_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'),"
    " vm_slot text"
    "  CHECK (vm_slot IS NULL OR vm_slot ~ "
    "'^[a-z0-9][a-z0-9._-]{0,62}/[1-9][0-9]{0,8}$'),"
    " incarnation_public_key_b64url text NOT NULL"
    "  CHECK (incarnation_public_key_b64url ~ '^[A-Za-z0-9_-]{43}$'"
    f"   AND octet_length({_PUBKEY}) = 32"
    f"   AND translate(encode({_PUBKEY}, 'base64'), '+/=', '-_') "
    "     = incarnation_public_key_b64url),"
    " incarnation_fingerprint text NOT NULL"
    f"  CHECK (incarnation_fingerprint ~ '^sha256:{_HEX64}$'"
    "   AND incarnation_fingerprint = 'sha256:' || "
    f"    encode(sha256({_PUBKEY}), 'hex')),"
    " enrolment_uuid uuid NOT NULL UNIQUE,"
    " key_custody_pointer text NOT NULL CHECK (key_custody_pointer ~ '^bao://.+'),"
    " recorded_by text NOT NULL CHECK (recorded_by ~ '^[\\x21-\\x7e]{1,120}$'),"
    " recorded_at timestamptz NOT NULL,"
    " seq bigserial NOT NULL)",
    "CREATE TABLE cp_lane3.e10_destructions ("
    " receipt_ref text PRIMARY KEY REFERENCES cp_lane3.e10_receipts (receipt_ref),"
    " destroyed_at timestamptz NOT NULL,"
    " route text NOT NULL CHECK (route = 'transit_mount_disabled'),"
    " dispatch_id uuid,"
    " installed_attestation_digest text"
    f"  CHECK (installed_attestation_digest ~ '^sha256:{_HEX64}$'),"
    " evidence_digest text NOT NULL"
    f"  CHECK (evidence_digest ~ '^sha256:{_HEX64}$'),"
    " recorded_by text NOT NULL CHECK (recorded_by ~ '^[\\x21-\\x7e]{1,120}$'),"
    " CHECK ((dispatch_id IS NULL) = (installed_attestation_digest IS NULL)))",
    "CREATE TABLE cp_lane3.run_bindings ("
    " role_name text NOT NULL UNIQUE CHECK (role_name ~ '^[a-z][a-z0-9_]{2,53}$'),"
    " host_id text NOT NULL"
    "  CHECK (host_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),"
    " authorization_run text NOT NULL CHECK (authorization_run ~ '^[\\x21-\\x7e]{1,255}$'),"
    " valid_until timestamptz NOT NULL,"
    " created_at timestamptz NOT NULL,"
    " recorded_by text NOT NULL CHECK (recorded_by ~ '^[\\x21-\\x7e]{1,120}$'),"
    " PRIMARY KEY (role_name, host_id, authorization_run),"
    " CHECK (valid_until > created_at AND valid_until <= created_at + interval '4 hours'))",
    "CREATE TABLE cp_lane3.host_current_lease ("
    " host_id text PRIMARY KEY"
    "  CHECK (host_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),"
    " lease_id uuid)",
    "CREATE TABLE cp_lane3.host_leases ("
    " lease_id uuid PRIMARY KEY,"
    " host_id text NOT NULL REFERENCES cp_lane3.host_current_lease (host_id),"
    " authorization_run text NOT NULL CHECK (authorization_run ~ '^[\\x21-\\x7e]{1,255}$'),"
    " controller_identity text NOT NULL CHECK (controller_identity ~ '^SHA256:[A-Za-z0-9+/]{43}$'),"
    " workload_principal text NOT NULL CHECK (workload_principal ~ '^[\\x21-\\x7e]{1,255}$'),"
    " e10_receipt_ref text NOT NULL REFERENCES cp_lane3.e10_receipts (receipt_ref),"
    " reprovision_receipt_ref text UNIQUE REFERENCES cp_lane3.e10_receipts (receipt_ref),"
    " acquired_at timestamptz NOT NULL,"
    " expires_at timestamptz NOT NULL,"
    " ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 3600),"
    " lease_bytes bytea,"
    " lease_digest text"
    f"  CHECK (lease_digest ~ '^sha256:{_HEX64}$'),"
    " CHECK (expires_at = acquired_at + ttl_seconds * interval '1 second'),"
    " CHECK ((lease_bytes IS NULL) = (lease_digest IS NULL)))",
    "CREATE TABLE cp_lane3.host_lease_releases ("
    " lease_id uuid PRIMARY KEY REFERENCES cp_lane3.host_leases (lease_id),"
    " released_at timestamptz NOT NULL,"
    " record_released_at timestamptz NOT NULL,"
    " host_mutated boolean NOT NULL,"
    " release_bytes bytea NOT NULL,"
    " release_digest text NOT NULL"
    f"  CHECK (release_digest ~ '^sha256:{_HEX64}$'))",
)

# ── trigger functions (SECURITY INVOKER: they run as the inserting owner) ────

TRIGGER_FUNCTIONS_SQL = (
    "CREATE FUNCTION cp_lane3.stamp_receipt_time() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "NEW.recorded_at := cp_lane3.store_now(); RETURN NEW; END $$",
    "CREATE FUNCTION cp_lane3.stamp_destruction_time() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "NEW.destroyed_at := cp_lane3.store_now(); RETURN NEW; END $$",
    "CREATE FUNCTION cp_lane3.stamp_binding_time() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "NEW.created_at := cp_lane3.store_now(); RETURN NEW; END $$",
    "CREATE FUNCTION cp_lane3.stamp_release_time() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "NEW.released_at := cp_lane3.store_now(); RETURN NEW; END $$",
    # The one lease update: NULL -> value for the document and its digest, and
    # nothing else. A second bind, or any other column, is refused.
    "CREATE FUNCTION cp_lane3.guard_lease_update() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "IF OLD.lease_bytes IS NULL AND OLD.lease_digest IS NULL "
    "AND NEW.lease_bytes IS NOT NULL AND NEW.lease_digest IS NOT NULL "
    "AND NEW.lease_id = OLD.lease_id AND NEW.host_id = OLD.host_id "
    "AND NEW.authorization_run = OLD.authorization_run "
    "AND NEW.controller_identity = OLD.controller_identity "
    "AND NEW.workload_principal = OLD.workload_principal "
    "AND NEW.e10_receipt_ref = OLD.e10_receipt_ref "
    "AND NEW.reprovision_receipt_ref IS NOT DISTINCT FROM OLD.reprovision_receipt_ref "
    "AND NEW.acquired_at = OLD.acquired_at AND NEW.expires_at = OLD.expires_at "
    "AND NEW.ttl_seconds = OLD.ttl_seconds THEN RETURN NEW; END IF; "
    "RAISE EXCEPTION 'host_leases is append-only: only the one-time document "
    "bind is permitted' USING ERRCODE = 'L3002'; END $$",
    # The row-lock row: only its pointer moves, and it is never removed.
    "CREATE FUNCTION cp_lane3.guard_current_lease_update() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "IF NEW.host_id = OLD.host_id THEN RETURN NEW; END IF; "
    "RAISE EXCEPTION 'host_current_lease: the host key is immutable' "
    "USING ERRCODE = 'L3002'; END $$",
    "CREATE FUNCTION cp_lane3.forbid_current_lease_removal() RETURNS trigger "
    "LANGUAGE plpgsql SET search_path = pg_catalog, cp_lane3, pg_temp "
    "AS $$ BEGIN "
    "RAISE EXCEPTION 'host_current_lease rows are never removed' "
    "USING ERRCODE = 'L3002'; END $$",
)

TRIGGERS_SQL = (
    "CREATE TRIGGER trg_e10_receipts_stamp BEFORE INSERT ON cp_lane3.e10_receipts "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.stamp_receipt_time()",
    "CREATE TRIGGER trg_e10_destructions_stamp BEFORE INSERT "
    "ON cp_lane3.e10_destructions "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.stamp_destruction_time()",
    "CREATE TRIGGER trg_run_bindings_stamp BEFORE INSERT ON cp_lane3.run_bindings "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.stamp_binding_time()",
    "CREATE TRIGGER trg_host_lease_releases_stamp BEFORE INSERT "
    "ON cp_lane3.host_lease_releases "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.stamp_release_time()",
    *_append_only("e10_receipts"),
    *_append_only("e10_destructions"),
    *_append_only("run_bindings"),
    *_append_only("host_lease_releases"),
    "CREATE TRIGGER trg_host_leases_update BEFORE UPDATE ON cp_lane3.host_leases "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.guard_lease_update()",
    "CREATE TRIGGER trg_host_leases_delete BEFORE DELETE ON cp_lane3.host_leases "
    f"FOR EACH ROW EXECUTE FUNCTION {_GUARD}",
    "CREATE TRIGGER trg_host_leases_truncate BEFORE TRUNCATE ON cp_lane3.host_leases "
    f"FOR EACH STATEMENT EXECUTE FUNCTION {_GUARD}",
    "CREATE TRIGGER trg_host_current_lease_update BEFORE UPDATE "
    "ON cp_lane3.host_current_lease "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.guard_current_lease_update()",
    "CREATE TRIGGER trg_host_current_lease_delete BEFORE DELETE "
    "ON cp_lane3.host_current_lease "
    "FOR EACH ROW EXECUTE FUNCTION cp_lane3.forbid_current_lease_removal()",
    "CREATE TRIGGER trg_host_current_lease_truncate BEFORE TRUNCATE "
    "ON cp_lane3.host_current_lease "
    "FOR EACH STATEMENT EXECUTE FUNCTION cp_lane3.forbid_current_lease_removal()",
)

# ── the lease-store functions ────────────────────────────────────────────────

_DEFINER = (
    "LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, cp_lane3, pg_temp"
)


def _refuse(code: str) -> str:
    return f"RAISE EXCEPTION '{code}' USING ERRCODE = 'L3001';"


# A binding is the ceremony's statement that THIS role may act for THIS host and
# run, until a deadline on store time. `session_user` is the connecting role, not
# the definer. Every function calls one of these two first.
BINDING_FUNCTIONS_SQL = (
    "CREATE FUNCTION cp_lane3.require_binding(p_host text, p_run text) "
    "RETURNS void " + _DEFINER + " AS $$ BEGIN "
    "IF NOT EXISTS (SELECT 1 FROM cp_lane3.run_bindings b "
    "WHERE b.role_name = session_user AND b.host_id = p_host "
    "AND b.authorization_run = p_run "
    "AND b.valid_until > cp_lane3.store_now()) THEN "
    + _refuse("lease-role-unbound")
    + " END IF; END $$",
    "CREATE FUNCTION cp_lane3.require_any_binding() RETURNS void "
    + _DEFINER
    + " AS $$ BEGIN "
    "IF NOT EXISTS (SELECT 1 FROM cp_lane3.run_bindings b "
    "WHERE b.role_name = session_user "
    "AND b.valid_until > cp_lane3.store_now()) THEN "
    + _refuse("lease-role-unbound")
    + " END IF; END $$",
    "CREATE FUNCTION cp_lane3.require_host_binding(p_host text) RETURNS void "
    + _DEFINER
    + " AS $$ BEGIN "
    "IF NOT EXISTS (SELECT 1 FROM cp_lane3.run_bindings b "
    "WHERE b.role_name = session_user AND b.host_id = p_host "
    "AND b.valid_until > cp_lane3.store_now()) THEN "
    + _refuse("lease-role-unbound")
    + " END IF; END $$",
)

# The cross-binding every verification re-joins (design 1.3, RULED Q2-A): the
# receipt's enrolment is Control's own row, in the host-attester domain, for this
# host, naming this key and this custody pointer. Returns `ok` and `current`.
_ENROLMENT_ROW = (
    "SELECT e.id FROM mod_deploy.attestation_enrolments e "
    "WHERE e.id = v_r.enrolment_uuid AND e.custody_domain = 'host_attester' "
    "AND e.subject = v_r.host_id "
    "AND e.public_key_fingerprint = v_r.incarnation_fingerprint "
    "AND e.key_custody_pointer = v_r.key_custody_pointer"
)

_IS_CURRENT_ROOT = (
    "SELECT 1 FROM mod_deploy.attestation_current_roots c "
    "WHERE c.custody_domain = 'host_attester' AND c.subject = v_r.host_id "
    "AND c.current_fingerprint = v_r.incarnation_fingerprint "
    # a view row is not enough: a fingerprint any closure names is closed
    # (revoked or superseded), whatever the view says
    "AND NOT EXISTS (SELECT 1 FROM mod_deploy.attestation_fingerprint_closures f "
    "WHERE f.fingerprint = v_r.incarnation_fingerprint)"
)

LEASE_FUNCTIONS_SQL = (
    # e10_receipt: the launcher reads its E10ReceiptRef from HERE. Refuses unless
    # the receipt and its destruction exist (destroyed no later than store time)
    # and Control's registry agrees, and the enrolment is the host's current root.
    "CREATE FUNCTION cp_lane3.e10_receipt(p_host text, p_run text, p_ref text) "
    "RETURNS jsonb " + _DEFINER + " AS $$ "
    "DECLARE v_r record; "
    "v_d record; v_out jsonb; "
    "BEGIN PERFORM cp_lane3.require_binding(p_host, p_run); "
    "SELECT * INTO v_r FROM cp_lane3.e10_receipts WHERE receipt_ref = p_ref; "
    "IF NOT FOUND THEN " + _refuse("e10-receipt-unknown") + " END IF; "
    "IF v_r.host_id <> p_host THEN "
    + _refuse("e10-receipt-for-another-host")
    + " END IF; "
    "SELECT * INTO v_d FROM cp_lane3.e10_destructions WHERE receipt_ref = p_ref; "
    "IF NOT FOUND OR v_d.destroyed_at > cp_lane3.store_now() THEN "
    + _refuse("e10-receipt-not-destroyed")
    + " END IF; "
    f"IF NOT EXISTS ({_ENROLMENT_ROW}) THEN "
    + _refuse("e10-receipt-mismatch")
    + " END IF; "
    f"IF NOT EXISTS ({_IS_CURRENT_ROOT}) THEN "
    + _refuse("e10-receipt-not-current-root")
    + " END IF; "
    "SELECT jsonb_build_object("
    "'vm_alias', v_r.vm_alias, 'host_id', v_r.host_id, "
    "'machine_id', v_r.machine_id, "
    "'ssh_host_key_fingerprint', v_r.ssh_host_key_fingerprint, "
    "'incarnation_public_key_b64url', v_r.incarnation_public_key_b64url, "
    "'incarnation_fingerprint', v_r.incarnation_fingerprint, "
    "'enrolment_uuid', v_r.enrolment_uuid::text, "
    "'incarnation_key_destroyed_at', "
    "to_char(v_d.destroyed_at AT TIME ZONE 'UTC', "
    "'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '+00:00', "
    "'receipt_ref', v_r.receipt_ref, 'vm_slot', v_r.vm_slot) INTO v_out; "
    "RETURN v_out; END $$",
    # acquire: one transaction. The row lock on `host_current_lease` is the only
    # serialisation point; a waiter re-reads the winner's pointer (READ COMMITTED).
    "CREATE FUNCTION cp_lane3.acquire(p_host text, p_run text, p_controller text, "
    "p_principal text, p_ttl integer, p_receipt jsonb, p_marker_host text, "
    "p_marker_receipt jsonb) "
    "RETURNS TABLE (o_lease_id uuid, o_acquired_at timestamptz, o_expires_at timestamptz) "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_now timestamptz; v_prev uuid; v_pl record; "
    "v_rel record; v_mutated boolean := false; "
    "v_marker boolean := p_marker_receipt IS NOT NULL; "
    "v_pre text := CASE WHEN p_marker_receipt IS NOT NULL "
    "THEN 'reprovision-receipt-' ELSE 'e10-receipt-' END; "
    "v_r record; v_d record; "
    "v_pr record; v_ref text; v_new uuid; "
    "v_at timestamptz; v_acq timestamptz; "
    "BEGIN "
    "IF p_ttl IS NULL OR p_ttl < 1 OR p_ttl > 3600 THEN "
    + _refuse("lease-ttl-invalid")
    + " END IF; "
    "PERFORM cp_lane3.require_binding(p_host, p_run); "
    "v_ref := p_receipt ->> 'receipt_ref'; "
    "IF p_receipt ->> 'host_id' IS DISTINCT FROM p_host THEN "
    + _refuse("e10-receipt-for-another-host")
    + " END IF; "
    "INSERT INTO cp_lane3.host_current_lease (host_id) VALUES (p_host) "
    "ON CONFLICT DO NOTHING; "
    "SELECT hc.lease_id INTO v_prev FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = p_host FOR UPDATE; "
    "v_now := cp_lane3.store_now(); "
    # the lease stores whole seconds, and E9 requires destroyed <= acquired: judge
    # the destruction against the SAME truncated instant that is stored
    "v_acq := date_trunc('second', v_now); "
    "IF v_prev IS NOT NULL THEN "
    "SELECT * INTO v_pl FROM cp_lane3.host_leases l WHERE l.lease_id = v_prev; "
    "SELECT * INTO v_rel FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = v_prev; "
    "IF NOT FOUND AND v_now < v_pl.expires_at THEN "
    + _refuse("lease-held-by-another-run")
    + " END IF; "
    "v_mutated := CASE WHEN v_rel.lease_id IS NULL THEN true "
    "ELSE v_rel.host_mutated END; "
    "END IF; "
    # the marker names this host and cites the receipt the new lease is under
    "IF v_marker AND (p_marker_host IS DISTINCT FROM p_host "
    "OR p_marker_receipt IS DISTINCT FROM p_receipt) THEN "
    + _refuse("reprovision-receipt-mismatch")
    + " END IF; "
    "SELECT * INTO v_r FROM cp_lane3.e10_receipts WHERE receipt_ref = v_ref; "
    "IF NOT FOUND THEN "
    "RAISE EXCEPTION USING MESSAGE = v_pre || 'unknown', ERRCODE = 'L3001'; "
    "END IF; "
    "SELECT * INTO v_d FROM cp_lane3.e10_destructions WHERE receipt_ref = v_ref; "
    "v_at := v_d.destroyed_at; "
    "IF v_r.host_id <> p_host OR v_r.vm_alias IS DISTINCT FROM "
    "(p_receipt ->> 'vm_alias') OR v_r.machine_id IS DISTINCT FROM "
    "(p_receipt ->> 'machine_id') OR v_r.ssh_host_key_fingerprint IS DISTINCT FROM "
    "(p_receipt ->> 'ssh_host_key_fingerprint') OR v_r.vm_slot IS DISTINCT FROM "
    "(p_receipt ->> 'vm_slot') OR v_r.incarnation_public_key_b64url IS DISTINCT FROM "
    "(p_receipt ->> 'incarnation_public_key_b64url') OR "
    "v_r.incarnation_fingerprint IS DISTINCT FROM "
    "(p_receipt ->> 'incarnation_fingerprint') OR "
    "v_r.enrolment_uuid::text IS DISTINCT FROM (p_receipt ->> 'enrolment_uuid') OR "
    "(v_at IS NOT NULL AND v_at IS DISTINCT FROM "
    "((p_receipt ->> 'incarnation_key_destroyed_at')::timestamptz)) THEN "
    "RAISE EXCEPTION USING MESSAGE = v_pre || 'mismatch', ERRCODE = 'L3001'; "
    "END IF; "
    "IF v_prev IS NOT NULL AND v_mutated AND NOT v_marker THEN "
    + _refuse("lease-host-mutated")
    + " END IF; "
    "IF v_at IS NULL OR v_at > v_acq THEN "
    "RAISE EXCEPTION USING MESSAGE = v_pre || 'not-destroyed', ERRCODE = 'L3001'; "
    "END IF; "
    # a marker reopens a host only for a DIFFERENT, NEWER incarnation than the
    # lease's own: the same ref, key or enrolment is the same incarnation, and
    # newer is strictly greater `seq`
    "IF v_marker AND v_prev IS NOT NULL THEN "
    "SELECT * INTO v_pr FROM cp_lane3.e10_receipts "
    "WHERE receipt_ref = v_pl.e10_receipt_ref; "
    "IF v_r.receipt_ref = v_pr.receipt_ref "
    "OR v_r.incarnation_fingerprint = v_pr.incarnation_fingerprint "
    "OR v_r.enrolment_uuid = v_pr.enrolment_uuid THEN "
    + _refuse("reprovision-receipt-same-incarnation")
    + " END IF; "
    "IF v_r.seq <= v_pr.seq THEN "
    + _refuse("reprovision-receipt-not-newer")
    + " END IF; END IF; "
    # the enrolment is Control's own row for this host, and is its CURRENT root
    f"IF NOT EXISTS ({_ENROLMENT_ROW}) THEN "
    "RAISE EXCEPTION USING MESSAGE = v_pre || 'mismatch', ERRCODE = 'L3001'; "
    "END IF; "
    f"IF NOT EXISTS ({_IS_CURRENT_ROOT}) THEN "
    "RAISE EXCEPTION USING MESSAGE = v_pre || 'not-current-root', "
    "ERRCODE = 'L3001'; END IF; "
    "IF v_marker AND EXISTS (SELECT 1 FROM cp_lane3.host_leases l2 "
    "WHERE l2.reprovision_receipt_ref = v_ref) THEN "
    + _refuse("reprovision-receipt-spent")
    + " END IF; "
    "v_new := gen_random_uuid(); "
    "INSERT INTO cp_lane3.host_leases (lease_id, host_id, authorization_run, "
    "controller_identity, workload_principal, e10_receipt_ref, "
    "reprovision_receipt_ref, acquired_at, expires_at, ttl_seconds) "
    "VALUES (v_new, p_host, p_run, p_controller, p_principal, v_ref, "
    "CASE WHEN v_marker THEN v_ref END, v_acq, "
    "v_acq + p_ttl * interval '1 second', p_ttl); "
    "UPDATE cp_lane3.host_current_lease SET lease_id = v_new WHERE host_id = p_host; "
    "RETURN QUERY SELECT l.lease_id, l.acquired_at, l.expires_at "
    "FROM cp_lane3.host_leases l WHERE l.lease_id = v_new; END $$",
    # bind_document: the lease document IS the row (rule 9). Same transaction as
    # acquire. Refuses unless the digest is the sha256 of the bytes and the
    # document's own fields equal the row's.
    "CREATE FUNCTION cp_lane3.bind_document(p_lease uuid, p_bytes bytea, "
    "p_digest text) RETURNS void " + _DEFINER + " AS $$ "
    "DECLARE v_l record; v_doc jsonb; "
    "BEGIN "
    "SELECT * INTO v_l FROM cp_lane3.host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "PERFORM cp_lane3.require_binding(v_l.host_id, v_l.authorization_run); "
    "IF v_l.lease_bytes IS NOT NULL THEN "
    + _refuse("lease-document-already-bound")
    + " END IF; "
    "IF p_digest IS DISTINCT FROM 'sha256:' || encode(sha256(p_bytes), 'hex') THEN "
    + _refuse("lease-document-digest-mismatch")
    + " END IF; "
    "v_doc := convert_from(p_bytes, 'UTF8')::jsonb; "
    "IF v_doc ->> 'target' IS DISTINCT FROM v_l.host_id "
    "OR v_doc ->> 'authorization_run_id' IS DISTINCT FROM v_l.authorization_run "
    "OR v_doc ->> 'workload_principal' IS DISTINCT FROM v_l.workload_principal "
    "OR v_doc ->> 'controller_identity_fingerprint' "
    "IS DISTINCT FROM v_l.controller_identity "
    "OR (v_doc ->> 'starts_at')::timestamptz IS DISTINCT FROM v_l.acquired_at "
    "OR (v_doc ->> 'expires_at')::timestamptz IS DISTINCT FROM v_l.expires_at THEN "
    + _refuse("lease-document-mismatch")
    + " END IF; "
    "UPDATE cp_lane3.host_leases SET lease_bytes = p_bytes, lease_digest = p_digest "
    "WHERE lease_id = p_lease; END $$",
    # covers: judged on store time; returns the instant judged.
    "CREATE FUNCTION cp_lane3.covers(p_lease uuid, p_run text) RETURNS timestamptz "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_l record; v_now timestamptz; "
    "BEGIN "
    "SELECT * INTO v_l FROM cp_lane3.host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "PERFORM cp_lane3.require_binding(v_l.host_id, v_l.authorization_run); "
    "v_now := cp_lane3.store_now(); "
    "IF EXISTS (SELECT 1 FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = p_lease) OR v_now >= v_l.expires_at THEN "
    + _refuse("lease-expired")
    + " END IF; "
    "IF v_l.authorization_run <> p_run THEN "
    + _refuse("lease-foreign-run")
    + " END IF; "
    "RETURN v_now; END $$",
    # release: FOR UPDATE on the host row; stamps `released_at` = store time.
    "CREATE FUNCTION cp_lane3.release(p_lease uuid, p_bytes bytea, p_digest text, "
    "p_lease_digest text, p_released_by text, p_controller text, "
    "p_record_released_at timestamptz, p_host_mutated boolean) RETURNS text "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_l record; v_now timestamptz; v_doc jsonb; v_ok boolean; "
    "BEGIN "
    "SELECT * INTO v_l FROM cp_lane3.host_leases WHERE lease_id = p_lease; "
    "IF NOT FOUND THEN " + _refuse("lease-role-unbound") + " END IF; "
    "PERFORM cp_lane3.require_binding(v_l.host_id, v_l.authorization_run); "
    "IF p_host_mutated IS NULL THEN " + _refuse("host-mutated-required") + " END IF; "
    "PERFORM 1 FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = v_l.host_id FOR UPDATE; "
    "v_now := cp_lane3.store_now(); "
    "IF EXISTS (SELECT 1 FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = p_lease) THEN "
    + _refuse("lease-already-released")
    + " END IF; "
    "IF v_now >= v_l.expires_at THEN " + _refuse("lease-expired") + " END IF; "
    "IF v_l.lease_digest IS NULL OR p_lease_digest IS DISTINCT FROM v_l.lease_digest "
    "OR p_released_by IS DISTINCT FROM v_l.workload_principal "
    "OR p_controller IS DISTINCT FROM v_l.controller_identity THEN "
    + _refuse("release-not-this-lease")
    + " END IF; "
    "IF p_digest IS DISTINCT FROM 'sha256:' || encode(sha256(p_bytes), 'hex') THEN "
    + _refuse("release-not-this-lease")
    + " END IF; "
    # The stored document is what Control keeps as evidence, so it is parsed here
    # as `bind_document` parses the lease's, and must agree with the parameters
    # the row records. An unparseable document is not this lease's release.
    "BEGIN v_doc := convert_from(p_bytes, 'UTF8')::jsonb; "
    "v_ok := v_doc ->> 'lease_digest' IS NOT DISTINCT FROM v_l.lease_digest "
    "AND v_doc ->> 'authorization_run_id' IS NOT DISTINCT FROM v_l.authorization_run "
    "AND v_doc ->> 'controller_identity_fingerprint' IS NOT DISTINCT FROM p_controller "
    "AND v_doc -> 'released_by' ->> 'subject' IS NOT DISTINCT FROM p_released_by "
    "AND (v_doc ->> 'released_at')::timestamptz IS NOT DISTINCT FROM p_record_released_at; "
    "EXCEPTION WHEN others THEN v_ok := false; END; "
    "IF v_ok IS NOT TRUE THEN " + _refuse("release-not-this-lease") + " END IF; "
    # a release that says the host was NOT mutated must also say it is reusable
    "IF NOT p_host_mutated AND v_doc ->> 'closure' IS DISTINCT FROM 'reusable' THEN "
    + _refuse("release-not-this-lease")
    + " END IF; "
    "IF abs(extract(epoch FROM (p_record_released_at - v_now))) > 60 THEN "
    + _refuse("release-clock-skew")
    + " END IF; "
    "INSERT INTO cp_lane3.host_lease_releases (lease_id, released_at, "
    "record_released_at, host_mutated, release_bytes, release_digest) "
    "VALUES (p_lease, v_now, p_record_released_at, p_host_mutated, p_bytes, "
    "p_digest); RETURN p_digest; END $$",
    # standing / released_at: reads, judged on store time. HELD / RELEASED /
    # EXPIRED_MUTATED. A host that was never leased has no standing to report.
    "CREATE FUNCTION cp_lane3.standing(p_host text) RETURNS text "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_id uuid; v_l record; "
    "BEGIN PERFORM cp_lane3.require_host_binding(p_host); "
    "SELECT hc.lease_id INTO v_id FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = p_host; "
    "IF v_id IS NULL THEN " + _refuse("lease-host-unknown") + " END IF; "
    "SELECT * INTO v_l FROM cp_lane3.host_leases WHERE lease_id = v_id; "
    "IF EXISTS (SELECT 1 FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = v_id) THEN RETURN 'released'; END IF; "
    "IF cp_lane3.store_now() >= v_l.expires_at THEN RETURN 'expired_mutated'; END IF; "
    "RETURN 'held'; END $$",
    "CREATE FUNCTION cp_lane3.released_at(p_host text) RETURNS timestamptz "
    + _DEFINER
    + " AS $$ "
    "DECLARE v_id uuid; v_at timestamptz; "
    "BEGIN PERFORM cp_lane3.require_host_binding(p_host); "
    "SELECT hc.lease_id INTO v_id FROM cp_lane3.host_current_lease hc "
    "WHERE hc.host_id = p_host; "
    "IF v_id IS NULL THEN " + _refuse("lease-host-unknown") + " END IF; "
    "SELECT x.released_at INTO v_at FROM cp_lane3.host_lease_releases x "
    "WHERE x.lease_id = v_id; RETURN v_at; END $$",
    # database_time: the store's own clock, for a bound role only.
    "CREATE FUNCTION cp_lane3.database_time() RETURNS timestamptz "
    + _DEFINER
    + " AS $$ BEGIN PERFORM cp_lane3.require_any_binding(); "
    "RETURN cp_lane3.store_now(); END $$",
)

#: Every function a lease role may be granted. Written down because the role spec
#: and its read-back must name the same set the migration creates.
LEASE_ROLE_FUNCTIONS = (
    "acquire(text, text, text, text, integer, jsonb, text, jsonb)",
    "bind_document(uuid, bytea, text)",
    "covers(uuid, text)",
    "database_time()",
    "e10_receipt(text, text, text)",
    "release(uuid, bytea, text, text, text, text, timestamptz, boolean)",
    "released_at(text)",
    "standing(text)",
)

#: The internal helpers: owned and executed by the definer, never granted.
INTERNAL_FUNCTIONS = (
    "forbid_current_lease_removal()",
    "guard_current_lease_update()",
    "guard_lease_update()",
    "require_any_binding()",
    "require_binding(text, text)",
    "require_host_binding(text)",
    "stamp_binding_time()",
    "stamp_destruction_time()",
    "stamp_receipt_time()",
    "stamp_release_time()",
    "store_now()",
)

# ── the privilege read-back ──────────────────────────────────────────────────
#
# Every query counts ACL entries whose grantee is anybody but the object's owner
# (PUBLIC is grantee 0, so it is counted). A NULL ACL is the type's DEFAULT, which
# `acldefault` expands, so an object that was never touched is judged as its
# default is: functions default to PUBLIC EXECUTE, which is why the migration
# revokes it. The intended grants are none.
SCHEMA_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_namespace n, "
    "LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, "
    "pg_catalog.acldefault('n'::\"char\", n.nspowner))) a "
    "WHERE n.nspname = 'cp_lane3' AND a.grantee <> n.nspowner"
)
RELATION_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, "
    "LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault("
    "CASE WHEN c.relkind = 'S' THEN 's'::\"char\" ELSE 'r'::\"char\" END, "
    "c.relowner))) a "
    "WHERE n.nspname = 'cp_lane3' AND a.grantee <> c.relowner"
)
COLUMN_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_attribute t "
    "JOIN pg_catalog.pg_class c ON c.oid = t.attrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, "
    "LATERAL pg_catalog.aclexplode(t.attacl) a "
    "WHERE n.nspname = 'cp_lane3' AND t.attacl IS NOT NULL "
    "AND a.grantee <> c.relowner"
)
FUNCTION_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace, "
    "LATERAL pg_catalog.aclexplode(COALESCE(p.proacl, "
    "pg_catalog.acldefault('f'::\"char\", p.proowner))) a "
    "WHERE n.nspname = 'cp_lane3' AND a.grantee <> p.proowner"
)
DEFAULT_ACL_SQL = (
    "SELECT count(*) FROM pg_catalog.pg_default_acl d "
    "JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace "
    "WHERE n.nspname = 'cp_lane3'"
)


def upgrade() -> None:
    connection = op.get_bind()

    def run(statements: tuple[str, ...]) -> None:
        for statement in statements:
            connection.exec_driver_sql(statement)

    connection.exec_driver_sql("CREATE SCHEMA cp_lane3")
    connection.exec_driver_sql("REVOKE ALL ON SCHEMA cp_lane3 FROM PUBLIC")
    run(CLOCK_SQL)
    run(TABLES_SQL)
    run(TRIGGER_FUNCTIONS_SQL)
    run(TRIGGERS_SQL)
    run(BINDING_FUNCTIONS_SQL)
    run(LEASE_FUNCTIONS_SQL)
    for signature in (*LEASE_ROLE_FUNCTIONS, *INTERNAL_FUNCTIONS):
        connection.exec_driver_sql(
            f"REVOKE ALL ON FUNCTION cp_lane3.{signature} FROM PUBLIC"
        )
    # Retained evidence: nothing in this schema is reachable by anybody but its
    # owner, and the read-back is in the same transaction (issuing a REVOKE proves
    # a statement ran, not that a privilege is gone). The migration grants NOTHING:
    # the per-run lease role is granted by the E6 ceremony, never here, so the list
    # of intended grants is empty.
    for sql, message in (
        (SCHEMA_ACL_SQL, "an ACL entry other than the owner's on the schema"),
        (
            RELATION_ACL_SQL,
            "an ACL entry other than the owner's on a table or sequence",
        ),
        (COLUMN_ACL_SQL, "a column ACL entry other than the owner's"),
        (FUNCTION_ACL_SQL, "an ACL entry other than the owner's on a function"),
        (DEFAULT_ACL_SQL, "a default-privilege rule names the schema"),
    ):
        if connection.exec_driver_sql(sql).scalar_one():
            raise RuntimeError(f"v023_lane3_store: {message}")


def downgrade() -> None:
    raise RuntimeError(
        "the Lane 3 lease store and E10 receipts cannot be downgraded; they are "
        "retained evidence, forward repair required"
    )
