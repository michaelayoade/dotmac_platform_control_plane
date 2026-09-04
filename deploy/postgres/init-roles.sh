#!/usr/bin/env bash
# First-cluster initialization only. PostgreSQL's entrypoint runs this file as
# its separate `postgres` bootstrap superuser. It creates the permanent
# app_admin migrator with the final NOSUPERUSER/BYPASSRLS contract before any
# module DDL. Passwords enter psql through \getenv, never argv, SQL, or logs.
set -euo pipefail

: "${VENDOR_DB_ADMIN_PASSWORD:?VENDOR_DB_ADMIN_PASSWORD is required}"
: "${VENDOR_DB_APP_USER_PASSWORD:?VENDOR_DB_APP_USER_PASSWORD is required}"
: "${VENDOR_DB_PLATFORM_API_PASSWORD:?VENDOR_DB_PLATFORM_API_PASSWORD is required}"
: "${VENDOR_DB_DISPATCHER_PASSWORD:?VENDOR_DB_DISPATCHER_PASSWORD is required}"

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv admin_password VENDOR_DB_ADMIN_PASSWORD
\getenv app_user_password VENDOR_DB_APP_USER_PASSWORD
\getenv platform_api_password VENDOR_DB_PLATFORM_API_PASSWORD
\getenv dispatcher_password VENDOR_DB_DISPATCHER_PASSWORD
\getenv database_name POSTGRES_DB

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_admin') THEN
        CREATE ROLE app_admin LOGIN NOSUPERUSER BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_api') THEN
        CREATE ROLE platform_api LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'outbox_dispatcher') THEN
        CREATE ROLE outbox_dispatcher LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'platform_outbox_dispatcher'
    ) THEN
        CREATE ROLE platform_outbox_dispatcher LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$roles$;

ALTER ROLE app_admin NOSUPERUSER NOCREATEROLE BYPASSRLS LOGIN;
ALTER ROLE app_admin PASSWORD :'admin_password';
ALTER ROLE app_user PASSWORD :'app_user_password';
ALTER ROLE platform_api PASSWORD :'platform_api_password';
-- The platform outbox relay's dispatcher. It holds EXECUTE on the kernel's
-- two leasing functions and no table privilege of any kind; the password is
-- what lets the relay CONNECT as it, and nothing more.
--
-- FIRST CLUSTER INITIALISATION ONLY. PostgreSQL runs this file once, when the
-- data directory is created. On a cluster that already exists this line has
-- never run and never will, so the password must be set by an operator
-- instead — see docs/operations/production-deployment.md.
ALTER ROLE platform_outbox_dispatcher PASSWORD :'dispatcher_password';
ALTER DATABASE :"database_name" OWNER TO app_admin;
ALTER SCHEMA public OWNER TO app_admin;

-- The bootstrap password exists only long enough for the official image to
-- initialize the cluster. Remove it before the temporary server stops; host
-- recovery remains possible through the container's local postgres identity.
ALTER ROLE postgres PASSWORD NULL;
SQL
