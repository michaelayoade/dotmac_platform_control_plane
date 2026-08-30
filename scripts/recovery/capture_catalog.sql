-- Read one database's catalogue into the evidence a recovery is checked against.
--
-- Product-owned on purpose. `dotmac-deployment-foundation` defines the fact
-- types and the comparison and deliberately CONNECTS TO NOTHING, so the SQL
-- that fills them belongs here. A facility that could read the database it
-- validates could also make its own check pass.
--
-- Emits ONE json document on stdout. Run with `psql -tA -f`.
--
-- Two rules this file exists to hold:
--
--   * Privileges are read TWICE and the two readings are not the same claim.
--     `privileges` is the direct grant list, which is what a dump carries.
--     `effective_privileges` is `has_*_privilege`, which is what a role can
--     actually do. A role reaching a table through a group membership appears
--     in the second and not the first, and an isolation check built on the
--     first passes over a real privilege.
--   * PUBLIC is a PSEUDO-ROLE and is spelled `PUBLIC` everywhere. Grantee OID
--     0 means PUBLIC, and `pg_get_userbyid(0)` returns the string
--     'unknown (OID=0)' rather than NULL — so a COALESCE never fires and a
--     fabricated role name reaches the closure, where the bundle correctly
--     refuses it as an undefined role. `pg_policies` renders it lowercase.
--   * NOTHING here reads a password, a verifier or row data. `rolpassword` is
--     never selected. The bundle proves a database's SHAPE and its
--     authorisation, and credentials are re-supplied after a restore.

\set ON_ERROR_STOP on

WITH
roles AS (
  SELECT json_agg(json_build_object(
    'name', r.rolname,
    'can_login', r.rolcanlogin,
    'inherit', r.rolinherit,
    'superuser', r.rolsuper,
    'createrole', r.rolcreaterole,
    'createdb', r.rolcreatedb,
    'replication', r.rolreplication,
    'bypassrls', r.rolbypassrls,
    'connection_limit', r.rolconnlimit
  ) ORDER BY r.rolname) AS v
  FROM pg_roles r
  WHERE r.rolname NOT LIKE 'pg\_%'
),
memberships AS (
  -- PostgreSQL 16 keeps INHERIT and SET per MEMBERSHIP, not per role, so they
  -- cannot be derived from the member's own rolinherit.
  SELECT COALESCE(json_agg(json_build_object(
    'member', m.rolname,
    'role', g.rolname,
    'admin_option', a.admin_option,
    'inherit_option', a.inherit_option,
    'set_option', a.set_option
  ) ORDER BY m.rolname, g.rolname), '[]'::json) AS v
  FROM pg_auth_members a
  JOIN pg_roles m ON m.oid = a.member
  JOIN pg_roles g ON g.oid = a.roleid
  WHERE m.rolname NOT LIKE 'pg\_%'
),
ownership AS (
  SELECT json_agg(x ORDER BY x->>'kind', x->>'identity') AS v FROM (
    SELECT json_build_object('kind','schema','identity',n.nspname,
                             'owner',pg_get_userbyid(n.nspowner)) AS x
      FROM pg_namespace n
     WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
    UNION ALL
    SELECT json_build_object('kind','table','identity',n.nspname||'.'||c.relname,
                             'owner',pg_get_userbyid(c.relowner))
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg\_%'
       AND n.nspname <> 'information_schema'
    UNION ALL
    SELECT json_build_object('kind','sequence','identity',n.nspname||'.'||c.relname,
                             'owner',pg_get_userbyid(c.relowner))
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg\_%'
       AND n.nspname <> 'information_schema'
  ) s
),
-- Direct grants, expanded from the ACL arrays. This is the half a dump carries.
privileges AS (
  SELECT COALESCE(json_agg(x ORDER BY x->>'scope', x->>'identity',
                           x->>'grantee', x->>'privilege'), '[]'::json) AS v
  FROM (
    SELECT json_build_object(
      'scope','table','identity',n.nspname||'.'||c.relname,
      'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                      ELSE pg_get_userbyid(acl.grantee) END,
      'privilege', acl.privilege_type,
      'grantor', pg_get_userbyid(acl.grantor),
      'grantable', acl.is_grantable) AS x
      FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace,
           aclexplode(c.relacl) AS acl
     WHERE c.relkind IN ('r','p','S') AND n.nspname NOT LIKE 'pg\_%'
       AND n.nspname <> 'information_schema'
    UNION ALL
    SELECT json_build_object(
      'scope','schema','identity',n.nspname,
      'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                      ELSE pg_get_userbyid(acl.grantee) END,
      'privilege', acl.privilege_type,
      'grantor', pg_get_userbyid(acl.grantor),
      'grantable', acl.is_grantable)
      FROM pg_namespace n, aclexplode(n.nspacl) AS acl
     WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
  ) s
),
-- What each role can ACTUALLY do. The half a dump does not carry and the half
-- an isolation claim has to rest on.
eff_tables AS (
  SELECT COALESCE(json_agg(json_build_object(
    'role', r.rolname, 'scope','table',
    'identity', n.nspname||'.'||c.relname,
    'privilege', p.priv,
    'holds', has_table_privilege(r.rolname, c.oid, p.priv)
  ) ORDER BY r.rolname, n.nspname, c.relname, p.priv), '[]'::json) AS v
  FROM pg_roles r
  CROSS JOIN LATERAL (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
                             ('TRUNCATE'),('REFERENCES'),('TRIGGER')) AS p(priv)
  JOIN pg_class c ON c.relkind IN ('r','p')
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE r.rolname NOT LIKE 'pg\_%' AND NOT r.rolsuper
    AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
),
eff_schemas AS (
  SELECT COALESCE(json_agg(json_build_object(
    'role', r.rolname, 'scope','schema', 'identity', n.nspname,
    'privilege', p.priv,
    'holds', has_schema_privilege(r.rolname, n.nspname, p.priv)
  ) ORDER BY r.rolname, n.nspname, p.priv), '[]'::json) AS v
  FROM pg_roles r
  CROSS JOIN LATERAL (VALUES ('USAGE'),('CREATE')) AS p(priv)
  JOIN pg_namespace n ON n.nspname NOT LIKE 'pg\_%'
                     AND n.nspname <> 'information_schema'
  WHERE r.rolname NOT LIKE 'pg\_%' AND NOT r.rolsuper
),
functions AS (
  SELECT COALESCE(json_agg(json_build_object(
    'signature', n.nspname||'.'||p.proname||'('||
                 pg_get_function_identity_arguments(p.oid)||')',
    'owner', pg_get_userbyid(p.proowner),
    'security_definer', p.prosecdef,
    'public_may_execute', has_function_privilege('public', p.oid, 'EXECUTE'),
    'executors', COALESCE((
      SELECT json_agg(DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                      ELSE pg_get_userbyid(a.grantee) END)
        FROM aclexplode(p.proacl) a WHERE a.privilege_type='EXECUTE'
    ), '[]'::json)
  ) ORDER BY n.nspname, p.proname), '[]'::json) AS v
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
),
default_privileges AS (
  SELECT COALESCE(json_agg(json_build_object(
    'owner', pg_get_userbyid(d.defaclrole),
    'schema', COALESCE(n.nspname,''),
    'object_kind', d.defaclobjtype,
    'grantee', CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                      ELSE pg_get_userbyid(acl.grantee) END,
    'privilege', acl.privilege_type
  ) ORDER BY 1), '[]'::json) AS v
  FROM pg_default_acl d
  LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace,
       aclexplode(d.defaclacl) AS acl
),
policies AS (
  SELECT COALESCE(json_agg(json_build_object(
    'table', schemaname||'.'||tablename,
    'name', policyname,
    'command', cmd,
    -- pg_policies renders the PUBLIC pseudo-role lowercase; the bundle spells
    -- it PUBLIC, and a policy naming no role is a policy naming PUBLIC.
    'roles', COALESCE((SELECT json_agg(CASE WHEN x = 'public' THEN 'PUBLIC'
                                            ELSE x END)
                         FROM unnest(roles) AS x), '[]'::json),
    'permissive', permissive = 'PERMISSIVE'
  ) ORDER BY schemaname, tablename, policyname), '[]'::json) AS v
  FROM pg_policies
),
row_security AS (
  SELECT COALESCE(json_agg(json_build_object(
    'table', n.nspname||'.'||c.relname,
    'enabled', c.relrowsecurity,
    'forced', c.relforcerowsecurity
  ) ORDER BY n.nspname, c.relname), '[]'::json) AS v
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg\_%'
    AND n.nspname <> 'information_schema'
),
extensions AS (
  SELECT COALESCE(json_agg(json_build_object(
    'name', e.extname, 'version', e.extversion,
    'schema', n.nspname) ORDER BY e.extname), '[]'::json) AS v
  FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
),
schemas AS (
  SELECT json_agg(n.nspname ORDER BY n.nspname) AS v
  FROM pg_namespace n
  WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
),
heads AS (
  SELECT COALESCE(json_agg(version_num ORDER BY version_num), '[]'::json) AS v
  FROM alembic_version
)
SELECT json_build_object(
  'roles', (SELECT v FROM roles),
  'memberships', (SELECT v FROM memberships),
  'ownership', (SELECT v FROM ownership),
  'privileges', (SELECT v FROM privileges),
  'effective_privileges', (SELECT v FROM eff_tables),
  'effective_schema_privileges', (SELECT v FROM eff_schemas),
  'functions', (SELECT v FROM functions),
  'default_privileges', (SELECT v FROM default_privileges),
  'policies', (SELECT v FROM policies),
  'row_security', (SELECT v FROM row_security),
  'extensions', (SELECT v FROM extensions),
  'schemas', (SELECT v FROM schemas),
  'migration_heads', (SELECT v FROM heads)
);
