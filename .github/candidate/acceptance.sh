#!/usr/bin/env bash
# Accept, or refuse, one locally built candidate image.
#
# Invoked as `.github/candidate/acceptance.sh <image-reference>` by
# `.github/workflows/production-image.yml`, BEFORE anything is pushed. That
# ordering is the whole point of this file: the previous pipeline pushed and
# then smoked, so a failing smoke left published bytes nobody had accepted and
# the registry became the record of what was built rather than of what passed.
#
# It lives under `.github/` and not under `scripts/` deliberately. `scripts/` is
# where production instructions live, and those are being retired into the
# installed console script; this is a CI-only harness that must never become a
# production entry point. `vendor_cp.installed_surface` refuses new
# `scripts/`-shaped production invocations, and putting this there would have
# been the first one.
#
# Every check runs against the EXACT bytes that will be published. Where a check
# needs the application's own code it runs INSIDE the candidate container, not
# against the checkout — a test of a checkout proves what the source says, and
# the whole class of defect this pipeline exists to catch is an artifact that
# disagrees with its source.
set -euo pipefail

IMAGE="${1:?usage: acceptance.sh <image-reference>}"
WORKDIR="$(mktemp -d)"
DB_PORT="${CANDIDATE_DB_PORT:-5449}"
DB_CONTAINER="candidate-postgres"
APP_CONTAINER="candidate-app"
PG_IMAGE="${CANDIDATE_POSTGRES_IMAGE:-postgres:16}"
HOSTNAME_HEADER="candidate.dotmac.invalid"

pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

cleanup() {
    docker rm -f "$APP_CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── The production-shaped environment ───────────────────────────────────────
# Taken from `.env.production.example` rather than invented, so the candidate is
# exercised in the composition it will actually run in. The two differences are
# named: the database points at a disposable container, and the signing key is
# generated per run by the image itself and never leaves this runner.
psql_admin() { docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres "$@"; }

dsn() { printf 'postgresql+psycopg://%s@127.0.0.1:%s/%s' "$1" "$DB_PORT" "$2"; }

# Runs python inside the candidate image with a production-shaped environment.
in_image() {
    local db="${CANDIDATE_DB:-candidate}"
    docker run --rm --network host \
        --env "DATABASE_URL=$(dsn app_user "$db")" \
        --env "PLATFORM_DATABASE_URL=$(dsn platform_api "$db")" \
        --env "MIGRATION_DATABASE_URL=$(dsn app_admin "$db")" \
        --entrypoint python "$IMAGE" -c "$SCRIPT"
}

step "0  disposable database, initialised by the production role script"
docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$DB_CONTAINER" \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    --env POSTGRES_DB=candidate \
    --env VENDOR_DB_ADMIN_PASSWORD=admin \
    --env VENDOR_DB_APP_USER_PASSWORD=app \
    --env VENDOR_DB_PLATFORM_API_PASSWORD=platform \
    --volume "$PWD/deploy/postgres/init-roles.sh:/docker-entrypoint-initdb.d/001-vendor-roles.sh:ro" \
    --publish "127.0.0.1:${DB_PORT}:5432" \
    "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$DB_CONTAINER" pg_isready -U postgres -d candidate >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$DB_CONTAINER" pg_isready -U postgres -d candidate >/dev/null \
    || fail "the disposable database never became ready"
pass "database up, roles created by deploy/postgres/init-roles.sh"

# ═══════════════════════════════════════════════════════════════════════════
step "1  the installed CLI, and that it is installed"
docker run --rm --entrypoint dotmac-platform "$IMAGE" --version >/dev/null \
    || fail "the console script is not installed in the candidate"
docker run --rm --network none \
    --env DATABASE_URL=postgresql+psycopg://x@127.0.0.1:5432/none \
    --env PLATFORM_DATABASE_URL=postgresql+psycopg://x@127.0.0.1:5432/none \
    --entrypoint dotmac-platform "$IMAGE" \
    --format json diagnose self --strict >/dev/null \
    || fail "diagnose self --strict found the candidate is not running installed"
pass "dotmac-platform resolves, reports a metadata version, and is installed"

step "12 no checkout dependency — the counter-proof, run inside the candidate"
# The positive case above passes from `site-packages`. It would ALSO pass from a
# source tree if the check were weak, which is exactly how a package can report
# one identity while being another. So the same binary is pointed at a checkout
# and must REFUSE with 6 (integrity/identity), not 0.
#
# Mounted at `/checkout/tree` rather than `/checkout/src` deliberately. What the
# counter-proof needs is that `vendor_cp` resolves outside the installed tree,
# which any directory provides. Naming it `src` would plant a production-shaped
# import-root assignment in a file the installed-surface ratchet scans, and it
# would then have to be declared as debt it is not — the ratchet caught exactly
# that when this check was first written.
set +e
docker run --rm --network none \
    --env DATABASE_URL=postgresql+psycopg://x@127.0.0.1:5432/none \
    --env PLATFORM_DATABASE_URL=postgresql+psycopg://x@127.0.0.1:5432/none \
    --env PYTHONPATH=/checkout/tree \
    --volume "$PWD/src:/checkout/tree:ro" \
    --entrypoint dotmac-platform "$IMAGE" \
    diagnose self --strict >/dev/null 2>&1
counter=$?
set -e
test "$counter" -eq 6 \
    || fail "pointed at a checkout the candidate exited $counter, expected 6"
pass "the same command refuses a checkout with 6 — the check cannot pass both ways"

step "2  the application imports, and publishes the production documentation surface"
# No ENVIRONMENT is set on purpose: `classify_environment` fails closed, so an
# image with nothing declared must already serve the production inventory.
SCRIPT="
from vendor_cp.main import app; import vendor_cp.api_documentation as policy; assert app is not None; assert policy.classify_environment(None) == policy.PRODUCTION; paths = {getattr(route, 'path', '') for route in app.routes}; assert not paths & {'/docs', '/docs/oauth2-redirect', '/redoc'}, paths; assert not policy.audit_api_documentation( app, policy.api_documentation_policy(policy.PRODUCTION)); assert '/openapi.json' in paths, 'the document plane must be served, not merely declared'
"
in_image || fail "the built bytes do not serve the production documentation policy"
pass "app imports; /docs, /docs/oauth2-redirect and /redoc are ABSENT from the live inventory"

step "10 the documentation gate refuses an omission too, in the artifact"
# ADR-0016's gate is bidirectional. Asserting only that the interactive routes
# are gone would pass on an application that serves nothing at all, so the
# DOCUMENT plane's presence is asserted in the same breath above, and here the
# development policy is applied to the same app to prove the gate can still
# object in the other direction.
SCRIPT="
import vendor_cp.api_documentation as policy
from vendor_cp.main import app
findings = policy.audit_api_documentation(app, policy.api_documentation_policy(policy.DEVELOPMENT))
assert findings, 'the production artifact satisfied the DEVELOPMENT policy, so the gate is not discriminating'
assert any('no route is mounted' in f for f in findings), findings
"
in_image || fail "the documentation gate did not object to an under-published plane"
pass "the gate objects to omission as well as over-publication"

step "11 the provisioning laboratory is absent, and the refusals are live in the artifact"
SCRIPT="
from vendor_cp.deployment_profile import ProductionProfileRefusedError, deployment_profile, validate_profile_for_environment
import vendor_cp.assembly as assembly
from dotmac_kernel import create_app

def refuses(code):
    try:
        validate_profile_for_environment(deployment_profile(code), environment='production', provider_mode='fake')
    except ProductionProfileRefusedError:
        return True
    return False

assert refuses('full'), 'a production environment accepted the laboratory profile'
paths = {getattr(r, 'path', '') for r in create_app(assembly.build_spec(deployment_profile('production-bootstrap'))).routes}
withheld = [p for p in paths if p.startswith('/platform/vendor/provisioning')]
assert not withheld, withheld
assert not [p for p in paths if p.startswith('/platform/vendor/licences')]
assert not [p for p in paths if p.startswith('/platform/vendor/offer-versions')]
# NON-VACUITY: the same artifact must still be able to mount them, or the
# absence above is a statement about a build that has no such routes at all.
lab = {getattr(r, 'path', '') for r in create_app(assembly.build_spec(deployment_profile('full'))).routes}
assert [p for p in lab if p.startswith('/platform/vendor/provisioning')], 'the laboratory routes do not exist in this artifact at all'
"
in_image || fail "the production surface policy is not live in the built bytes"
pass "provisioning/licences/offers withheld under production-bootstrap; present under full"

step "3  fresh zero-to-head migration"
docker run --rm --network host \
    --env "MIGRATION_DATABASE_URL=$(dsn app_admin candidate)" \
    --env "DATABASE_URL=$(dsn app_admin candidate)" \
    --entrypoint dotmac-platform "$IMAGE" admin migrate >/dev/null \
    || fail "the candidate could not migrate an empty database to heads"
pass "empty database reaches composed heads"

step "4  restored-production migration — the path that can actually fail"
# CI's empty database is the path that cannot fail. A RESTORED copy is the one
# that can, and the rehearsal on 2026-08-31 proved how: production is owned by
# `app_admin`, while a copy created by initdb through POSTGRES_DB is owned by
# `postgres`, so `CREATE SCHEMA` is refused. A recovery bundle can be PROVED and
# still restore into a differently-owned database, because CatalogEvidence
# covers schema, table and sequence ownership but not DATABASE ownership.
#
# So both lanes run. Lane A is the conforming restore; lane B plants the exact
# defect and REQUIRES the failure. Without lane B, lane A passing would say
# nothing about whether the trap is still detectable.
psql_admin -c "CREATE DATABASE prodshape OWNER app_admin;" >/dev/null
SCRIPT="
from alembic import command
from vendor_cp.migrations import make_alembic_config
command.upgrade(make_alembic_config('$(dsn app_admin prodshape)'), 'v016_licensing_authority')
"
CANDIDATE_DB=prodshape in_image \
    || fail "could not build the pre-upgrade production-shaped state"
docker exec "$DB_CONTAINER" pg_dump -U postgres --format custom --dbname prodshape \
    > "$WORKDIR/prodshape.dump"
test -s "$WORKDIR/prodshape.dump" || fail "the production-shaped dump is empty"

psql_admin -c "CREATE DATABASE restored_ok OWNER app_admin;" >/dev/null
psql_admin -c "CREATE DATABASE restored_wrong_owner OWNER postgres;" >/dev/null
# `|| true` because pg_restore reports ACL warnings on a cluster whose roles
# were created by the init script rather than by the dump — the RESULT is
# asserted below instead of the exit code, which is the honest way round.
for target in restored_ok restored_wrong_owner; do
    docker exec -i "$DB_CONTAINER" pg_restore -U postgres --no-owner --role=app_admin \
        --dbname "$target" < "$WORKDIR/prodshape.dump" >/dev/null 2>&1 || true
done
for target in restored_ok restored_wrong_owner; do
    restored_tables="$(psql_admin --tuples-only --no-align --dbname "$target" -c \
      "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema');" | tr -d ' ')"
    test "$restored_tables" -gt 0 \
        || fail "$target restored zero tables, so the upgrade below would be a fresh install"
done
pass "restored two copies of the same production-shaped state, both non-empty"

docker run --rm --network host \
    --env "MIGRATION_DATABASE_URL=$(dsn app_admin restored_ok)" \
    --env "DATABASE_URL=$(dsn app_admin restored_ok)" \
    --entrypoint dotmac-platform "$IMAGE" admin migrate >/dev/null \
    || fail "the candidate could not upgrade a correctly-owned restored copy"
pass "lane A: a correctly-owned restored copy upgrades to heads"

set +e
docker run --rm --network host \
    --env "MIGRATION_DATABASE_URL=$(dsn app_admin restored_wrong_owner)" \
    --env "DATABASE_URL=$(dsn app_admin restored_wrong_owner)" \
    --entrypoint dotmac-platform "$IMAGE" admin migrate \
    > "$WORKDIR/wrong-owner.log" 2>&1
wrong_owner_status=$?
set -e
test "$wrong_owner_status" -ne 0 \
    || fail "a restored copy owned by postgres migrated successfully — the trap is undetectable"
grep -qi "permission denied for database" "$WORKDIR/wrong-owner.log" \
    || fail "the wrong-owner restore failed for some OTHER reason: $(tail -5 "$WORKDIR/wrong-owner.log")"
pass "lane B: a wrongly-owned restored copy is refused, and for the right reason"

step "5  database ownership, roles, grants and isolation"
SQL="
SELECT format('%s|%s|%s|%s',
  (SELECT rolsuper FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolcreaterole FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolbypassrls FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolcanlogin FROM pg_roles WHERE rolname='app_admin'));
"
role_contract="$(psql_admin --tuples-only --no-align --dbname restored_ok -c "$SQL" | tr -d ' ')"
test "$role_contract" = "false|false|true|true" \
    || fail "app_admin role contract is $role_contract, expected false|false|true|true"
owner_contract="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT pg_get_userbyid(datdba) || '|' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public') FROM pg_database WHERE datname=current_database();")"
test "$owner_contract" = "app_admin|app_admin" \
    || fail "database/schema ownership is $owner_contract, expected app_admin|app_admin"
pass "app_admin is a non-superuser BYPASSRLS owner of the database and public schema"

module_schemas="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT count(*) FROM information_schema.schemata WHERE schema_name LIKE 'mod\\_%';" | tr -d ' ')"
test "$module_schemas" -ge 1 \
    || fail "no module schema exists, so the isolation assertion below would be vacuous"
leaked="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT count(*) FROM information_schema.schemata WHERE schema_name LIKE 'mod\\_%' AND has_schema_privilege('app_user', schema_name, 'USAGE');" | tr -d ' ')"
test "$leaked" = "0" \
    || fail "app_user holds USAGE on $leaked module schema(s); the plane boundary is open"
reachable="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT count(*) FROM information_schema.schemata WHERE schema_name LIKE 'mod\\_%' AND has_schema_privilege('platform_api', schema_name, 'USAGE');" | tr -d ' ')"
test "$reachable" = "$module_schemas" \
    || fail "platform_api reaches $reachable of $module_schemas module schemas; the online role cannot work"
pass "$module_schemas module schemas: app_user reaches none, platform_api reaches all"

forced="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN information_schema.columns col ON col.table_schema=n.nspname AND col.table_name=c.relname AND col.column_name='tenant_id' WHERE c.relkind='r' AND NOT (c.relrowsecurity AND c.relforcerowsecurity);" | tr -d ' ')"
test "$forced" = "0" \
    || fail "$forced tenant-scoped table(s) do not have RLS enabled AND forced"
pass "every table carrying tenant_id has row security enabled and forced"

step "9  the exact UI assets this artifact serves"
SCRIPT="
import hashlib, pathlib
from dotmac_kernel.templating import static_dir
root = pathlib.Path(static_dir())
entries = sorted(
    (p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
    for p in root.rglob('*') if p.is_file()
)
manifest = '\n'.join(f'{name}  {digest}' for name, digest in entries)
print(len(entries))
print(hashlib.sha256(manifest.encode()).hexdigest())
"
asset_report="$(in_image)"
asset_count="$(printf '%s\n' "$asset_report" | sed -n '1p')"
asset_digest="$(printf '%s\n' "$asset_report" | sed -n '2p')"
expected_count="$(sed -n '1p' .github/candidate/ui-assets.expected)"
expected_digest="$(sed -n '2p' .github/candidate/ui-assets.expected)"
test "$asset_count" = "$expected_count" \
    || fail "the artifact serves $asset_count UI assets, declared $expected_count"
test "$asset_digest" = "$expected_digest" \
    || fail "UI asset manifest digest $asset_digest does not match the declared $expected_digest"
pass "$asset_count UI assets, manifest digest matches .github/candidate/ui-assets.expected"

# ── The running application ─────────────────────────────────────────────────
step "6  dependency-aware readiness, against liveness as the control"
signing_key="$(docker run --rm --network none --entrypoint python "$IMAGE" -c "
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
raw = Ed25519PrivateKey.generate().private_bytes(
    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
print(base64.urlsafe_b64encode(raw).rstrip(b'=').decode())
")"
printf '%s' "$signing_key" > "$WORKDIR/primary.key"
unset signing_key

start_app() {
    local database_url="$1"
    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$APP_CONTAINER" --network host \
        --env "DATABASE_URL=$database_url" \
        --env "PLATFORM_DATABASE_URL=$database_url" \
        --env APP_ENV=production \
        --env ENVIRONMENT=production \
        --env VENDOR_DEPLOYMENT_PROFILE=production-bootstrap \
        --env "PLATFORM_ROOT_DOMAIN=${HOSTNAME_HEADER}" \
        --env "TRUSTED_HOSTS=${HOSTNAME_HEADER}" \
        --env TENANCY=multi \
        --env JWT_SECRET=candidate-jwt-secret-not-a-real-one \
        --env SESSION_HASH_SECRET=candidate-session-secret-not-a-real-one \
        --env CSRF_ENABLED=true \
        --env RATE_LIMIT_ENABLED=false \
        --env VENDOR_PROVIDER_MODE=fake \
        --env 'VENDOR_PRODUCT_RELEASE_PINS_JSON={}' \
        --env VENDOR_PRODUCT_MANIFEST_DIRECTORY=/tmp/manifests \
        --env VENDOR_LICENCE_SIGNING_MODE=configured \
        --env VENDOR_LICENCE_SIGNING_KEY_FILE=/run/candidate/primary.key \
        --env VENDOR_LICENCE_SIGNING_KEY_ID=candidate-1 \
        --env VENDOR_LICENCE_DELIVERY_MODE=logging \
        --volume "$WORKDIR/primary.key:/run/candidate/primary.key:ro" \
        "$IMAGE" >/dev/null
}

probe() { curl --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 5 --header "Host: ${HOSTNAME_HEADER}" "http://127.0.0.1:8000$1"; }

await_liveness() {
    for _ in $(seq 1 60); do
        test "$(probe /health)" = "200" && return 0
        sleep 1
    done
    docker logs "$APP_CONTAINER" 2>&1 | tail -30 >&2
    return 1
}

# The negative case FIRST, so a passing readiness check later cannot be the
# result of a probe that returns 200 unconditionally.
start_app "postgresql+psycopg://app_admin@127.0.0.1:1/nothing-listens-here"
await_liveness || fail "the candidate did not come up with an unreachable database"
test "$(probe /health)" = "200" \
    || fail "liveness should answer 200 even with no database — it does not touch one"
ready_code="$(probe /health/ready)"
test "$ready_code" = "503" \
    || fail "readiness returned $ready_code with an unreachable database, expected 503"
pass "database unreachable: /health 200 (alive) and /health/ready 503 (not ready) — they differ"

start_app "$(dsn app_admin restored_ok)"
await_liveness || fail "the candidate did not come up against a migrated database"
for _ in $(seq 1 30); do test "$(probe /health/ready)" = "200" && break; sleep 1; done
test "$(probe /health/ready)" = "200" \
    || fail "readiness never became 200 against a reachable, migrated database"
pass "database reachable: /health/ready 200 — the probe tracks the dependency, not the process"

step "7  one journey across browser, API and CLI"
admin_email="candidate@${HOSTNAME_HEADER}"
admin_password="candidate-password-$RANDOM$RANDOM"
printf '%s' "$admin_password" | docker run --rm --interactive --network host \
    --env "DATABASE_URL=$(dsn app_admin restored_ok)" \
    --env "PLATFORM_DATABASE_URL=$(dsn app_admin restored_ok)" \
    --entrypoint dotmac-platform "$IMAGE" \
    admin create "$admin_email" --password-stdin >/dev/null \
    || fail "the CLI could not create a platform administrator"
pass "CLI: platform administrator created, password read from stdin and never on argv"

token="$(curl --silent --max-time 10 --header "Host: ${HOSTNAME_HEADER}" \
    --header 'Content-Type: application/json' \
    --data "{\"email\":\"${admin_email}\",\"password\":\"${admin_password}\"}" \
    "http://127.0.0.1:8000/platform/auth/login" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))')"
test -n "$token" || fail "the API did not issue a bearer token to the CLI-created identity"
pass "API: the identity the CLI created authenticates over the bearer plane"

doc_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Host: ${HOSTNAME_HEADER}" --header "Authorization: Bearer ${token}" \
    "http://127.0.0.1:8000/openapi.json")"
test "$doc_code" = "200" \
    || fail "the bearer-protected document plane returned $doc_code to a platform admin"
pass "API: /openapi.json answers 200 to a platform-admin bearer token"

cookie_jar="$WORKDIR/cookies"
login_page="$(curl --silent --max-time 10 --cookie-jar "$cookie_jar" \
    --header "Host: ${HOSTNAME_HEADER}" "http://127.0.0.1:8000/platform/login")"
csrf="$(printf '%s' "$login_page" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')"
login_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --cookie "$cookie_jar" --cookie-jar "$cookie_jar" \
    --header "Host: ${HOSTNAME_HEADER}" \
    --data-urlencode "email=${admin_email}" \
    --data-urlencode "password=${admin_password}" \
    --data-urlencode "csrf_token=${csrf}" \
    "http://127.0.0.1:8000/platform/login")"
case "$login_code" in
    200|302|303) ;;
    *) fail "the browser login returned $login_code — no session can be obtained" ;;
esac
console_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --cookie "$cookie_jar" --header "Host: ${HOSTNAME_HEADER}" \
    "http://127.0.0.1:8000/platform/console")"
test "$console_code" = "200" \
    || fail "the console returned $console_code to a freshly logged-in admin"
pass "browser: form login yields a session that reaches the console"

docker run --rm --network host \
    --env "DATABASE_URL=$(dsn app_admin restored_ok)" \
    --env "PLATFORM_DATABASE_URL=$(dsn app_admin restored_ok)" \
    --entrypoint dotmac-platform "$IMAGE" \
    --format json admin accounts >/dev/null \
    || fail "the CLI could not read through the same owner the surfaces use"
pass "CLI: a read reaches the same owner the browser and API just used"

step "8  wrong credential and wrong standing are refused"
bad_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Host: ${HOSTNAME_HEADER}" --header 'Content-Type: application/json' \
    --data "{\"email\":\"${admin_email}\",\"password\":\"not-the-password\"}" \
    "http://127.0.0.1:8000/platform/auth/login")"
test "$bad_code" = "401" \
    || fail "a wrong password returned $bad_code, expected 401"
pass "wrong credential: 401"

inactive_email="inactive@${HOSTNAME_HEADER}"
printf '%s' "$admin_password" | docker run --rm --interactive --network host \
    --env "DATABASE_URL=$(dsn app_admin restored_ok)" \
    --env "PLATFORM_DATABASE_URL=$(dsn app_admin restored_ok)" \
    --entrypoint dotmac-platform "$IMAGE" \
    admin create "$inactive_email" --password-stdin --inactive >/dev/null \
    || fail "could not create the inactive identity the refusal case needs"
inactive_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Host: ${HOSTNAME_HEADER}" --header 'Content-Type: application/json' \
    --data "{\"email\":\"${inactive_email}\",\"password\":\"${admin_password}\"}" \
    "http://127.0.0.1:8000/platform/auth/login")"
test "$inactive_code" = "401" \
    || fail "an inactive administrator with the CORRECT password returned $inactive_code, expected 401"
pass "wrong standing: a correct password on an inactive identity is still 401"

unauth_code="$(probe /openapi.json)"
test "$unauth_code" = "401" \
    || fail "the document plane returned $unauth_code without a token, expected 401"
pass "no credential: the bearer-protected document plane is 401, not 200"

printf '\nCANDIDATE ACCEPTED\n'
