-- Terminate every open backend on the fenced database whose usename is one
-- of D16's writer roles, or a transitive member of one. This is the ONE
-- statement `scripts/lib/fence_broker.sh` ever runs in response to a
-- `DOTMAC-FENCE-TERMINATE` request; PR 2's `StdioBrokerTerminator` never
-- terminates anything itself (see `vendor_cp.deployment.transition_fence`'s
-- module docstring, "D1: the owner topology", for why termination stays off
-- the owner connection the fence itself uses).
--
-- Fed on stdin, by a superuser, scoped by ONE bound variable:
--
--     psql -X -v ON_ERROR_STOP=1 -v "db=<name>" < terminate_writers.sql
--
-- `:'db'` is the only substitution this file ever makes. It is never
-- interpolated with anything else the container supplies — no role name, no
-- fence_id, nothing from the request line `fence_broker_serve` read crosses
-- into this statement.
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
-- `app_admin` (`vendor_cp.deployment.transition_fence.MIGRATION_ROLE`) is
-- explicitly excluded, even though it can never legitimately appear in the
-- walk above (fence_writers refuses SHARED_WRITER_ROLE first) — belt and
-- braces against this file ever being run standalone, outside a fence this
-- module already validated. `pg_backend_pid()` excludes this statement's own
-- backend, which is never a writer role's backend but is excluded on
-- principle: a broker statement must never be able to terminate its own
-- connection.
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
    SELECT DISTINCT r.rolname
      FROM members m
      JOIN pg_roles r ON r.oid = m.oid
     WHERE r.rolname <> 'app_admin'
)
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = :'db'
   AND pid <> pg_backend_pid()
   AND usename IN (SELECT rolname FROM effective_roles);
