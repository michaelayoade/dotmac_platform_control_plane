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
# `load_deployment_profile` falls back to `full` OUTSIDE production only, so a
# developer sees the whole assembly; since ADR-0015 an absent profile in a
# production environment fails the boot instead. This grep is therefore no
# longer the only thing standing between the host and the `full` composition —
# it is the cheap check that runs before the image starts, and the loader is
# the one that runs on every restart this script does not perform.
grep -Fqx 'VENDOR_DEPLOYMENT_PROFILE=production-bootstrap' "$ENV_FILE" \
    || die "deployment profile is not production-bootstrap"
# ── The kernel's production-fatal settings, checked BEFORE anything is touched ─
#
# Look at the order of this script. `compose up -d app` is the SEVENTH action:
# the image is pulled, the database is started, the manifest volume is
# initialised, the role and ownership contracts are read, a backup is taken and
# THE MIGRATIONS ARE APPLIED before the application is ever started. A
# configuration error left to the application's lifespan therefore arrives with
# the schema already advanced and the service down — the most expensive possible
# moment to learn it, and entirely avoidable, because every input it depends on
# is readable here.
#
# `CSRF_SECRET` is the live instance. Kernel a98 `validate_settings` refuses it
# three ways: still the dev default, fewer than 32 bytes, or equal to
# `JWT_SECRET`/`SESSION_HASH_SECRET`. The host that runs this script was
# materialized from a template that never declared it at all.
#
# Nothing below prints a value. Lengths and equality only.
readonly CSRF_REMEDY="Remediation: patch the OpenBao record \
secret/dotmac/vendor-control-plane/production/runtime to add a csrf_secret \
field of at least 32 bytes, distinct from jwt_secret and session_hash_secret, \
then re-run 'materialize_production_secrets.py push'. Note that 'seed' only \
CREATES absent records and will not repair one that already exists."

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | head -1; }

grep -Fqx 'CSRF_ENABLED=true' "$ENV_FILE" || die "CSRF_ENABLED is not true"
csrf_secret="$(env_value CSRF_SECRET)"
[[ -n "$csrf_secret" ]] \
    || die "CSRF_SECRET is absent or empty in $ENV_FILE. $CSRF_REMEDY"
(( ${#csrf_secret} >= 32 )) \
    || die "CSRF_SECRET is shorter than 32 bytes. $CSRF_REMEDY"
[[ "$csrf_secret" != "$(env_value JWT_SECRET)" \
    && "$csrf_secret" != "$(env_value SESSION_HASH_SECRET)" ]] \
    || die "CSRF_SECRET must differ from JWT_SECRET and SESSION_HASH_SECRET. $CSRF_REMEDY"
unset csrf_secret

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

# The ARTIFACT's own verdict on this host's environment, still before the host
# is touched. The greps above are a fast, dependency-free floor that restates
# three of the kernel's rules and will drift from them; this asks the image that
# is about to run, using the very function its lifespan calls. A clean answer
# here is the answer the boot will give — except that it arrives before the
# database has been started, the manifest volume initialised, a backup taken or
# a single migration applied.
#
# The two DSNs are placeholders. Compose supplies the real ones from its own
# `environment:` block, so they are absent from the env file and would be
# reported as missing; `--network none` guarantees neither is dialled.
#
# `validate_settings` returns error strings that name SETTINGS and never values,
# which is what makes it safe to print this verdict.
readonly ENVIRONMENT_VERDICT="$(docker run --rm --network none \
    --env-file "$ENV_FILE" \
    --env DATABASE_URL=postgresql+psycopg://placeholder@127.0.0.1:5432/none \
    --env PLATFORM_DATABASE_URL=postgresql+psycopg://placeholder@127.0.0.1:5432/none \
    --entrypoint python "$VENDOR_APP_IMAGE" -c \
    'from dotmac_kernel.config import settings, validate_settings
for error in validate_settings(settings):
    print(error)')"
[[ -z "$ENVIRONMENT_VERDICT" ]] || die "the image refuses this host environment:
${ENVIRONMENT_VERDICT}
Nothing has been changed — no container started, no migration applied.
${CSRF_REMEDY}"

compose up -d --wait db
compose --profile ops run --rm --no-deps manifest-init

readonly ROLE_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT rolsuper::text || '\''|'\'' || rolcreaterole::text || '\''|'\'' || rolbypassrls::text || '\''|'\'' || rolcanlogin::text FROM pg_roles WHERE rolname = current_user"')"
[[ "$ROLE_CONTRACT" == "false|false|true|true" ]] \
    || die "module database role contract is not satisfied"
readonly OWNER_CONTRACT="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT pg_get_userbyid(datdba) || '\''|'\'' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='\''public'\'') FROM pg_database WHERE datname = current_database()"')"
[[ "$OWNER_CONTRACT" == "app_admin|app_admin" ]] \
    || die "module database ownership contract is not satisfied"

# ── The backup is a PAIR, because a dump on its own is not a rollback ────────
#
# Rehearsed 2026-08-30 against this host's own newest backup: a plain
# `pg_restore` of the dump alone exited 1 with 114 missing-role errors across
# five roles, and left a database that LOOKED recovered — 45 tables, 23 of 26
# policies, 16 RLS-enabled tables — with no roles, no grants, and every object
# owned by whoever ran the restore. `pg_dump` of one database carries object
# ACLs and RLS policies but never role definitions: those live in the cluster.
#
# That is worse than a backup that fails outright. This assembly's plane
# separation IS the grant/revoke matrix rather than the policies alone
# (`dotmac_starter_mt` ADR-0023), so a restore that silently drops the role
# layer produces a control-plane database with no plane separation, and an
# operator reading `pg_policies` afterwards concludes the isolation model came
# back. It did not.
#
# `--no-role-passwords` is the PROVED configuration, not a precaution. The same
# artefact, restored with globals captured that way, exited 0 with zero errors
# and the facility's `verify_recovery` reported zero findings across roles,
# memberships, ownership, effective privileges, RLS force and the descriptor's
# own isolation invariants — `docs/operations/recovery-proved-2026-08-30.md`.
# It also needs no superuser, which this cluster deliberately has no password
# for (`deploy/postgres/init-roles.sh` ends with `ALTER ROLE postgres PASSWORD
# NULL`), and it keeps every SCRAM verifier out of a file sitting on the host.
#
# Both halves are written to `.tmp` and PUBLISHED only once both are complete
# and the globals have been checked. A dump appearing beside a missing or empty
# globals file would be the same half-artifact under a new name.
#
# RESTORE ORDER IS GLOBALS FIRST. Restoring the dump first recreates the 114
# errors, because the grants it carries name principals that do not exist yet.
mkdir -p "$BACKUP_DIR"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly BACKUP_PATH="${BACKUP_DIR}/vendor-control-plane-${TIMESTAMP}.dump"
readonly BACKUP_TMP="${BACKUP_PATH}.tmp"
readonly GLOBALS_PATH="${BACKUP_DIR}/vendor-control-plane-${TIMESTAMP}.globals.sql"
readonly GLOBALS_TMP="${GLOBALS_PATH}.tmp"

compose exec -T db sh -c \
    'exec pg_dumpall --username app_admin --database "$POSTGRES_DB" \
        --globals-only --no-role-passwords' \
    > "$GLOBALS_TMP"

# Checked by NAME, against the five roles `deploy/postgres/init-roles.sh`
# creates and `deploy/product.toml` declares as `[[database.roles]]`. A
# non-empty or size check would pass on a globals file carrying only
# tablespaces — which is exactly the shape that produces 114 errors while
# looking like a capture. The failure arrives here, before the migration and
# before the application is replaced, so nothing has been changed yet.
for role in app_admin app_user platform_api outbox_dispatcher \
            platform_outbox_dispatcher; do
    grep -Eq "^CREATE ROLE \"?${role}\"?;\$" "$GLOBALS_TMP" || die \
"cluster globals capture does not create role ${role}. The pair would restore \
without the grant/revoke matrix that IS this database's plane separation, and \
the restore would look successful. Nothing has been changed."
done

compose exec -T db sh -c \
    'exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom' \
    > "$BACKUP_TMP"

mv "$GLOBALS_TMP" "$GLOBALS_PATH"
mv "$BACKUP_TMP" "$BACKUP_PATH"

# This is the one composed migration owner: kernel, Vendor, Release Catalog,
# Entitlement Allocation, and Approvals advance before the app is replaced.
#
# The INSTALLED console script, not a path into the image. `scripts/` is no
# longer copied into the runtime stage at all, so this cannot silently become a
# stale file somebody rsynced; and the command's exit status is the CLI's own —
# 3 if the migration owner refused the target, 4 if the evidence it needed was
# absent — which `set -e` propagates to the deploy as a whole.
compose --profile ops run --rm --no-deps ops dotmac-platform admin migrate

compose up -d app --wait
# Both probes, and they answer different questions. `/health` is the kernel's
# liveness route and does not touch the database; `/health/ready` asks the one
# dependency this assembly has. Checking only the first is how a deploy could
# report success while the application could not serve — so the readiness check
# is the one that gates the printed result, and liveness is kept as the
# positive control that distinguishes "not ready" from "not answering at all".
curl --fail --silent --show-error --max-time 10 \
    --header "Host: vendor.dotmac.io" \
    "http://127.0.0.1:${VENDOR_APP_PORT:-8100}/health" >/dev/null
curl --fail --silent --show-error --max-time 10 \
    --header "Host: vendor.dotmac.io" \
    "http://127.0.0.1:${VENDOR_APP_PORT:-8100}/health/ready" >/dev/null

printf 'Deployed %s\npre-migration backup (restore globals FIRST): %s then %s\n' \
    "$VENDOR_APP_IMAGE" "$GLOBALS_PATH" "$BACKUP_PATH"
