-- Terminate every open backend on the fenced database whose usename is one
-- of D16's writer roles, or a transitive member of one. This is the ONE
-- statement `scripts/lib/fence_broker.sh` ever runs in response to a
-- `DOTMAC-FENCE-TERMINATE` request; PR 2's `StdioBrokerTerminator` never
-- terminates anything itself (see `vendor_cp.deployment.transition_fence`'s
-- module docstring, "D1: the owner topology", for why termination stays off
-- the owner connection the fence itself uses).
--
-- Fed on stdin, by the `postgres` superuser, scoped by ONE bound variable:
--
--     psql -X -v ON_ERROR_STOP=1 --username postgres -q -t -A \
--         -v "db=<name>" < terminate_writers.sql
--
-- `:'db'` is the only substitution this file ever makes. It is never
-- interpolated with anything else the container supplies — no role name, no
-- fence_id, nothing from the request line `fence_broker_serve` read crosses
-- into this statement.
--
-- ── Server-side bound: `statement_timeout` ──────────────────────────────────
--
-- The broker's own `timeout` wraps the WHOLE `compose exec` invocation from
-- the outside; this `SET` bounds the STATEMENT itself, from the server's
-- side, independently of whatever the client-side wrapper does — belt and
-- braces against a slow catalogue read or lock wait inside this one
-- connection, never a substitute for the broker's own timeout.
SET statement_timeout = '20s';
--
-- The writer role list below is the literal, exact set
-- `vendor_cp.deployment.transition_fence.WRITER_ROLES` names today
-- (app_user, platform_api, platform_outbox_dispatcher, outbox_dispatcher).
-- If that tuple ever changes, this list changes with it in the same
-- migration — `tests/architecture/test_fence_broker_sql.py` fails the build
-- otherwise.
--
-- The recursive walk below is the identical shape to that module's
-- `_MEMBER_ROLES_QUERY`: a role that is a (transitive) member of a named
-- writer can `SET ROLE` to it and keep writing, so it must be terminated
-- too. Unlike that Python query, the base case here seeds the recursion with
-- the writer roles' own oids, so the final set already contains the writers
-- themselves as well as their members — no separate second list is needed.
--
-- ── Self-bounding: every exclusion below can only SHRINK the kill set ──────
--
-- Removing a role from `effective_roles` can only leave a survivor that a
-- correctly-scoped statement would have killed — it can never widen who gets
-- terminated. That is why each of these is safe to add unconditionally,
-- never gated on the writer-role walk having already excluded it:
--
--   * `rolname <> 'app_admin'` — the migrator (`MIGRATION_ROLE`) is never
--     terminated, even though `fence_writers` already refuses
--     `SHARED_WRITER_ROLE` before this statement could ever be asked to act
--     on a set containing it — belt and braces against this file ever being
--     run standalone, outside a fence this module already validated.
--   * `NOT r.rolsuper` — a superuser reached via the membership walk (an
--     operational role someone granted a writer role to, for instance) is
--     never terminated: a broker statement that can kill a superuser's
--     session can kill the very session doing the terminating, or an
--     unrelated administrative connection sharing that identity.
--   * `NOT pg_has_role(r.oid, 'app_admin', 'member')` — a role that is a
--     MEMBER of `app_admin` (not `app_admin` itself, which the first bullet
--     already excludes) inherits `app_admin`'s privilege via `SET ROLE` and
--     must never be killed by the same statement that protects `app_admin`
--     directly.
--   * `NOT pg_has_role(r.oid, (SELECT datdba FROM pg_database WHERE
--     datname = :'db'), 'member')` — a member of the database's OWNER can
--     `SET ROLE` to the owner and reconnect under the owner's own implicit
--     CONNECT (see `transition_fence`'s "Inherited CONNECT cannot be
--     revoked away" section for the identical reasoning on the Python
--     side); terminating that role's open session here, while the owner
--     itself can simply reconnect, would not close anything the fence
--     actually depends on and risks an operational identity that happens to
--     share membership with the owner.
--
-- `pg_has_role` is used rather than a second recursive walk for both of
-- these: `NOT r.rolsuper` has already excluded every superuser from
-- `effective_roles` by this point, which is exactly the case where
-- `pg_has_role` would otherwise answer true for every role against every
-- other role — the same reason `transition_fence._member_roles` avoids
-- `pg_has_role` for the ORIGINAL writer walk, but that reason does not
-- apply here once superusers are already gone from consideration.
WITH RECURSIVE members(oid) AS (
    SELECT r.oid
      FROM pg_roles r
     WHERE r.rolname = ANY(ARRAY[
        'app_user',
        'platform_api',
        'platform_outbox_dispatcher',
        'outbox_dispatcher'
     ])
    UNION
    SELECT am.member
      FROM pg_auth_members am
      JOIN members m ON am.roleid = m.oid
),
effective_roles AS (
    SELECT DISTINCT r.oid, r.rolname
      FROM members m
      JOIN pg_roles r ON r.oid = m.oid
     WHERE r.rolname <> 'app_admin'
       AND NOT r.rolsuper
       AND NOT pg_has_role(r.oid, 'app_admin', 'member')
       AND NOT pg_has_role(
             r.oid,
             (SELECT datdba FROM pg_database WHERE datname = :'db'),
             'member'
           )
)
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = :'db'
   AND pid <> pg_backend_pid()
   AND usename IN (SELECT rolname FROM effective_roles);
