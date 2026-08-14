#!/usr/bin/env bash
# First-cluster initialization only. PostgreSQL's entrypoint runs this file as
# the configured app_admin superuser before the kernel migrations. Passwords
# enter psql through \getenv, never argv, SQL text, or logs.
set -euo pipefail

: "${VENDOR_DB_APP_USER_PASSWORD:?VENDOR_DB_APP_USER_PASSWORD is required}"
: "${VENDOR_DB_PLATFORM_API_PASSWORD:?VENDOR_DB_PLATFORM_API_PASSWORD is required}"

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_user_password VENDOR_DB_APP_USER_PASSWORD
\getenv platform_api_password VENDOR_DB_PLATFORM_API_PASSWORD

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_api') THEN
        CREATE ROLE platform_api LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$roles$;

ALTER ROLE app_user PASSWORD :'app_user_password';
ALTER ROLE platform_api PASSWORD :'platform_api_password';
SQL
