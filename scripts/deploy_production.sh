#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_HOST_ID="vendor-cp-prod"
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
readonly ENV_FILE="${ENV_FILE:-.env}"
readonly HOST_ID_FILE="${HOST_ID_FILE:-/etc/dotmac-host-id}"
readonly BACKUP_DIR="${BACKUP_DIR:-/opt/backups/dotmac-vendor-control-plane}"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# -eq 1 ]] || die "usage: scripts/deploy_production.sh sha256:<digest>"
readonly DIGEST="$1"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image digest is not sha256"

[[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing"
grep -Fqx 'APP_ENV=production' "$ENV_FILE" || die "APP_ENV marker mismatch"
grep -Fqx 'SERVER_NAME=vendor-cp-prod' "$ENV_FILE" || die "server marker mismatch"
grep -Fqx 'ENVIRONMENT=production' "$ENV_FILE" || die "runtime is not production"
grep -Fqx 'PLATFORM_ROOT_DOMAIN=vendor.dotmac.io' "$ENV_FILE" \
    || die "platform domain mismatch"
# The deployment profile is REQUIRED here rather than defaulted in the image.
# `load_deployment_profile` falls back to `full` so a developer sees the whole
# assembly; a production host that omitted the line would inherit that fallback
# and publish the licensing and offers routes the bootstrap profile exists to
# withhold. Failing before the image starts is the only place that is cheap.
grep -Fqx 'VENDOR_DEPLOYMENT_PROFILE=production-bootstrap' "$ENV_FILE" \
    || die "deployment profile is not production-bootstrap"
[[ -f "$HOST_ID_FILE" ]] || die "$HOST_ID_FILE is missing"
[[ "$(tr -d '\r\n' < "$HOST_ID_FILE")" == "$EXPECTED_HOST_ID" ]] \
    || die "host identity mismatch"

# The official image requires a bootstrap password even though that role is
# not the application migrator. Generate it per deploy, pass it only to the DB
# service, and let first-cluster initialization remove the stored verifier.
readonly VENDOR_DB_BOOTSTRAP_PASSWORD="$(
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
)"
[[ "$VENDOR_DB_BOOTSTRAP_PASSWORD" =~ ^[A-Za-z0-9_-]{64}$ ]] \
    || die "could not generate the database bootstrap credential"
export VENDOR_DB_BOOTSTRAP_PASSWORD

readonly VENDOR_APP_IMAGE="ghcr.io/michaelayoade/dotmac_vendor_control_plane@${DIGEST}"
export VENDOR_APP_IMAGE

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

docker pull "$VENDOR_APP_IMAGE"
compose up -d --wait db

readonly ROLE_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT rolsuper::text || '\''|'\'' || rolbypassrls::text || '\''|'\'' || rolcanlogin::text FROM pg_roles WHERE rolname = current_user"')"
[[ "$ROLE_CONTRACT" == "false|true|true" ]] \
    || die "module database role contract is not satisfied"
readonly OWNER_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT pg_get_userbyid(datdba) || '\''|'\'' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='\''public'\'') FROM pg_database WHERE datname = current_database()"')"
[[ "$OWNER_CONTRACT" == "app_admin|app_admin" ]] \
    || die "module database ownership contract is not satisfied"

mkdir -p "$BACKUP_DIR"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly BACKUP_PATH="${BACKUP_DIR}/vendor-control-plane-${TIMESTAMP}.dump"
readonly BACKUP_TMP="${BACKUP_PATH}.tmp"
compose exec -T db sh -c \
    'exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom' \
    > "$BACKUP_TMP"
mv "$BACKUP_TMP" "$BACKUP_PATH"

# This is the one composed migration owner: kernel, Vendor, Release Catalog,
# Entitlement Allocation, and Approvals advance before the app is replaced.
compose --profile ops run --rm --no-deps ops scripts/migrate.py

compose up -d app --wait
curl --fail --silent --show-error --max-time 10 \
    "http://127.0.0.1:${VENDOR_APP_PORT:-8100}/health" >/dev/null

printf 'Deployed %s; pre-migration backup: %s\n' \
    "$VENDOR_APP_IMAGE" "$BACKUP_PATH"
