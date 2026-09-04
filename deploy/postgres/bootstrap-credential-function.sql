-- The executor-only credential bootstrap, as ONE named operation.
--
-- `app_admin` stays NOSUPERUSER NOCREATEROLE. The capability to install the
-- relay dispatcher's credential arrives as a specific operation rather than as
-- a role grant, so nothing in this deployment gains the ability to rewrite
-- roles in general.
--
-- ── Why this is not in the Alembic lineage ──────────────────────────────────
--
-- The kernel's `0012_platform_outbox` is the precedent for the SHAPE — a
-- SECURITY DEFINER function, EXECUTE granted to one role, that role holding no
-- direct privilege — and it is explicit about the part that does not carry
-- over: *"SECURITY DEFINER functions run as their owner (app_admin), so
-- app_admin needs privilege on the table"*. That works because app_admin HAS
-- table privileges. It does not have CREATEROLE, so a function it owns cannot
-- `ALTER ROLE` whatever its body says.
--
-- Migrations run as app_admin, and a role cannot create an object owned by a
-- superuser. So this file is applied BY a superuser, once, and is deliberately
-- not a revision. `tests/migration/test_credential_bootstrap_atomicity.py`
-- measures the app_admin-owned case rather than asserting it from this comment.
--
-- ── What it can and cannot do ───────────────────────────────────────────────
--
-- It alters exactly one role, named here as a constant. A security-definer
-- function that altered whatever principal it was handed would be a CREATEROLE
-- grant with extra steps, reachable by anything holding EXECUTE.
--
-- It keeps the one-time property: advisory lock, presence re-read UNDER that
-- lock, and a refusal if a credential is already present. Moving the act inside
-- a function must not lose the ordering that makes it install-once.
--
-- The material arrives as a BIND PARAMETER rather than inside DDL text, so it
-- does not reach `log_statement`. The `ALTER ROLE` built below is executed
-- inside plpgsql, which `log_statement` does not log.

CREATE OR REPLACE FUNCTION public.bootstrap_dispatcher_credential(
    p_principal text, p_material text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
DECLARE
    -- The ONE role this operation may touch. A constant rather than an
    -- argument: the argument exists so a caller must state its intent and be
    -- refused when it is wrong, never so the target can be chosen.
    allowed constant text := 'platform_outbox_dispatcher';
    can_login boolean;
    is_super boolean;
    has_password boolean;
BEGIN
    IF p_principal IS DISTINCT FROM allowed THEN
        RAISE EXCEPTION
            'principal % is not bootstrappable by this operation', p_principal
            USING ERRCODE = 'DM101';
    END IF;
    IF p_material IS NULL OR length(p_material) = 0 THEN
        RAISE EXCEPTION 'refusing to install an empty credential'
            USING ERRCODE = 'DM106';
    END IF;

    SELECT r.rolcanlogin, r.rolsuper INTO can_login, is_super
      FROM pg_catalog.pg_roles AS r
     WHERE r.rolname = allowed;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'role % does not exist', allowed
            USING ERRCODE = 'DM102';
    END IF;
    IF NOT can_login THEN
        RAISE EXCEPTION 'role % cannot log in', allowed
            USING ERRCODE = 'DM103';
    END IF;
    IF is_super THEN
        RAISE EXCEPTION 'role % is a superuser', allowed
            USING ERRCODE = 'DM104';
    END IF;

    -- Transaction-scoped, so it is released by the caller's commit or rollback
    -- and a refusing executor cannot hold it against the next one.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtext(allowed)::bigint
    );

    -- Re-read UNDER the lock. A presence check taken before it is a check of a
    -- state that can change before the write. `pg_authid` is readable here
    -- because this function runs as its owner; the caller could not read it.
    SELECT a.rolpassword IS NOT NULL INTO has_password
      FROM pg_catalog.pg_authid AS a
     WHERE a.rolname = allowed;
    IF has_password THEN
        RAISE EXCEPTION
            'role % already holds a credential; this operation installs once',
            allowed
            USING ERRCODE = 'DM105';
    END IF;

    EXECUTE pg_catalog.format('ALTER ROLE %I PASSWORD %L', allowed, p_material);
    RETURN 'installed';
END
$fn$;

-- Executor-only. PUBLIC gets nothing, and the application's own roles are
-- revoked by name so the absence is stated rather than inherited.
REVOKE ALL ON FUNCTION public.bootstrap_dispatcher_credential(text, text)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION public.bootstrap_dispatcher_credential(text, text)
    FROM app_user;
REVOKE ALL ON FUNCTION public.bootstrap_dispatcher_credential(text, text)
    FROM platform_api;
