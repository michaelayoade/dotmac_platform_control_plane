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
CANDIDATE_NETWORK="candidate-vendor-backend"
PG_IMAGE="${CANDIDATE_POSTGRES_IMAGE:-postgres:16}"
# The platform host this run addresses. It is a Host HEADER only — every request
# below dials 127.0.0.1 explicitly — so this name is never resolved and no such
# host need exist.
#
# It was `candidate.dotmac.invalid`, chosen so it could not possibly resolve, and
# that choice broke the API journey in a way worth recording. `.invalid` is an
# IANA SPECIAL-USE domain, and `email-validator` (behind pydantic's `EmailStr`)
# refuses one in the domain part regardless of deliverability checking. The
# platform login body is an `EmailStr`, so an administrator the CLI had just
# created successfully — the CLI does not validate as an `EmailStr` — was
# rejected with 422 before any credential was checked. The battery reported
# "the API did not issue a bearer token", which was true and named nothing.
HOSTNAME_HEADER="candidate.dotmac.io"

pass() { printf '  ok    %s\n' "$*"; }
# A refusal that names nothing costs a whole run to diagnose. This renders the
# reason and the response SHAPE, and never a value: a successful body carries a
# bearer token, and a failing one is only a step away from carrying an echoed
# credential.
refusal_reason() {
    python3 - "$1" <<'REASON'
import json
import sys

raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
try:
    body = json.loads(raw)
except Exception:
    print(raw[:200].replace("\n", " "))
    raise SystemExit(0)
if isinstance(body, dict):
    print(f"detail={body.get('detail')!r} keys={sorted(body)}")
else:
    print(str(body)[:200])
REASON
}
fail() { printf '  FAIL  %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

cleanup() {
    docker rm -f "$APP_CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$CANDIDATE_NETWORK" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── The production-shaped environment ───────────────────────────────────────
# Taken from `.env.production.example` rather than invented, so the candidate is
# exercised in the composition it will actually run in. The three differences are
# named: the database points at a disposable container, the signing key is
# generated per run by the image itself and never leaves this runner, and
# `CSRF_SECRET` is a throwaway literal.
#
# That third one is not a convenience — it is a FINDING. `dotmac_kernel`
# `validate_settings` treats `CSRF_SECRET` as production-fatal in three separate
# ways: unset (still the dev default), shorter than 32 bytes, or equal to
# `JWT_SECRET`/`SESSION_HASH_SECRET`. Any of them raises in the application
# lifespan when `ENVIRONMENT=production`. `.env.production.example` declares
# `CSRF_ENABLED=true` and does NOT declare `CSRF_SECRET` at all, and
# `vendor_cp.production_secrets` does not materialize one: `SECRET_FIELDS`
# carries `jwt_secret` and `session_hash_secret` on the runtime record and no
# CSRF field. A host whose `.env` was built from that template therefore cannot
# boot this artifact.
#
# The battery supplies its own so the remaining checks can run at all. It does
# NOT repair the production secret contract — that changes what
# `materialize_production_secrets.py` requires of an OpenBao record that already
# exists, which is a deployment-window decision and not this file's to make.
psql_admin() { docker exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres "$@"; }

dsn() {
    local role="$1" database="$2" password
    case "$role" in
        app_admin) password=admin ;;
        app_user) password=app ;;
        platform_api) password=platform ;;
        *) fail "no candidate password is declared for database role $role" ;;
    esac
    printf 'postgresql+psycopg://%s:%s@127.0.0.1:%s/%s' \
        "$role" "$password" "$DB_PORT" "$database"
}

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
docker network rm "$CANDIDATE_NETWORK" >/dev/null 2>&1 || true
docker network create "$CANDIDATE_NETWORK" >/dev/null
docker run -d --name "$DB_CONTAINER" \
    --network "$CANDIDATE_NETWORK" \
    --network-alias db \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_PASSWORD=postgres \
    --env 'POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=scram-sha-256' \
    --env POSTGRES_DB=candidate \
    --env VENDOR_DB_ADMIN_PASSWORD=admin \
    --env VENDOR_DB_APP_USER_PASSWORD=app \
    --env VENDOR_DB_PLATFORM_API_PASSWORD=platform \
    --volume "$PWD/deploy/postgres/init-roles.sh:/docker-entrypoint-initdb.d/001-vendor-roles.sh:ro" \
    --volume "$PWD/.github/candidate/postgres-hba.sh:/docker-entrypoint-initdb.d/002-candidate-hba.sh:ro" \
    --publish "127.0.0.1:${DB_PORT}:5432" \
    "$PG_IMAGE" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$DB_CONTAINER" pg_isready -U postgres -d candidate >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$DB_CONTAINER" pg_isready -U postgres -d candidate >/dev/null \
    || fail "the disposable database never became ready"
pass "database up, roles created by deploy/postgres/init-roles.sh"

step "0a loopback trust is blind; the application bridge oracle discriminates"
# Reproduce the retired probe first. A deliberately invalid password succeeds
# from inside PostgreSQL because 127.0.0.1 selects the earlier trust rule.
docker exec --env PGPASSWORD=deliberately-invalid-candidate-proof \
    "$DB_CONTAINER" psql -X --no-password --host 127.0.0.1 --port 5432 \
    --username app_user --dbname candidate --command 'SELECT 1' >/dev/null \
    || fail "the loopback control did not reproduce the trusted path"
pass "control: container-local 127.0.0.1 accepts deliberately invalid material"

# Read the payload from the INSTALLED wheel inside the exact image under test.
# The source checkout is not mounted, and the image's own app runtime supplies
# the db:5432 coordinate the production adapter uses.
docker run --rm --network none --entrypoint python "$IMAGE" -c \
    'from vendor_cp.production_secrets import rotation_database_auth_oracle_program as p; print(p(), end="")' \
    >"$WORKDIR/database-auth-oracle.pyprogram" \
    || fail "the installed image cannot produce the database auth oracle"

run_database_auth_oracle() {
    docker run --rm --interactive --network "$CANDIDATE_NETWORK" \
        --env DATABASE_URL=postgresql+psycopg://app_user:app@db:5432/candidate \
        --env PLATFORM_DATABASE_URL=postgresql+psycopg://platform_api:platform@db:5432/candidate \
        --entrypoint python "$IMAGE" -c "$(cat "$WORKDIR/database-auth-oracle.pyprogram")"
}

printf '%s' '{"schema":"platform-database-authentication-oracle.v1","role":"app_user","password":"deliberately-invalid-candidate-proof"}' \
    | run_database_auth_oracle >"$WORKDIR/invalid-auth.json" \
    || fail "the bridge oracle could not classify deliberately invalid material"
python3 - "$WORKDIR/invalid-auth.json" <<'PY' \
    || fail "the db:5432 bridge accepted deliberately invalid material"
import json
import sys

assert json.load(open(sys.argv[1], encoding="utf-8")) == {
    "schema": "platform-database-authentication-oracle.v1",
    "role": "app_user",
    "accepted": False,
}
PY

printf '%s' '{"schema":"platform-database-authentication-oracle.v1","role":"app_user","password":"app"}' \
    | run_database_auth_oracle >"$WORKDIR/valid-auth.json" \
    || fail "the bridge oracle could not classify valid material"
python3 - "$WORKDIR/valid-auth.json" <<'PY' \
    || fail "the db:5432 bridge refused the active app_user material"
import json
import sys

assert json.load(open(sys.argv[1], encoding="utf-8")) == {
    "schema": "platform-database-authentication-oracle.v1",
    "role": "app_user",
    "accepted": True,
}
PY
pass "subject: db:5432 SCRAM refuses invalid and admits active material"

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

step "13 the distribution manifest the release receipt will carry"
# The receipt records a per-file digest for the wheel and the sdist, READ out of
# this document rather than re-measured: a second `poetry build` produces a
# different archive for identical source, because a zip carries timestamps.
#
# That makes the document one of the things a candidate must demonstrate. The
# pipeline step that reads it runs on the publication path ONLY, so without this
# a malformed or silently narrowed manifest would first be discovered after the
# push — the precise failure shape this whole ordering exists to prevent.
SCRIPT="
import json, re
from importlib.metadata import version

document = json.load(open('/app/distributions.json'))
assert document['contract'] == 'dotmac-distribution-digests/1', document.get('contract')
files = document['files']
wheels = [f for f in files if f['filename'].endswith('.whl')]
sdists = [f for f in files if f['filename'].endswith('.tar.gz')]
assert len(wheels) == 1, wheels
assert len(sdists) == 1, sdists
for entry in files:
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', entry['sha256']), entry
    assert entry['size_bytes'] > 0, entry
# Tied to the INSTALLED distribution rather than free-floating. A manifest that
# described some other build would satisfy every check above.
installed = version('dotmac-vendor-control-plane')
assert wheels[0]['filename'].split('-')[1] == installed, (wheels[0]['filename'], installed)
assert sdists[0]['filename'].endswith(installed + '.tar.gz'), (sdists[0]['filename'], installed)
print(wheels[0]['filename'], '+', sdists[0]['filename'], 'at', installed)
"
distribution_report="$(in_image)" \
    || fail "the candidate's distribution manifest is absent, malformed, or describes another build"
pass "distribution manifest: $distribution_report"

step "14 the artifact refuses a production environment the deploy would reject"
# `scripts/deploy_production.sh` asks the IMAGE whether this host environment is
# bootable — running the kernel's own `validate_settings` after the pull and
# before the database is started, so a fatal setting cannot be discovered at
# lifespan with the migrations already applied.
#
# That check runs only at deploy time, which is exactly the unmonitored-region
# shape this battery exists to close. So the PROPERTY it depends on is proved
# here, against the same bytes: the artifact must refuse a production
# environment whose CSRF_SECRET is absent, short, or reused, and its refusals
# must name no value — the deploy PRINTS that verdict.
SCRIPT="
from dotmac_kernel.config import Settings, validate_settings

base = dict(
    environment='production',
    database_url='postgresql+psycopg://x@127.0.0.1:5432/none',
    platform_database_url='postgresql+psycopg://x@127.0.0.1:5432/none',
    platform_root_domain='candidate.dotmac.io',
    trusted_hosts='candidate.dotmac.io',
    jwt_secret='jwt-' + 'j' * 40,
    session_hash_secret='session-' + 's' * 40,
    csrf_enabled=True,
)
conforming = 'csrf-' + 'c' * 40

absent = validate_settings(Settings(**base))
assert any('CSRF_SECRET' in error for error in absent), absent

for rejected, why in ((conforming[:20], 'shorter than 32 bytes'), (base['jwt_secret'], 'reused')):
    errors = validate_settings(Settings(csrf_secret=rejected, **base))
    assert any('CSRF_SECRET' in error for error in errors), (why, errors)

clean = validate_settings(Settings(csrf_secret=conforming, **base))
assert not [error for error in clean if 'CSRF_SECRET' in error], clean

# The deploy prints this verdict into an operator's terminal and its logs, so a
# refusal that interpolated a value would put a production credential there.
for message in absent:
    for value in (base['jwt_secret'], base['session_hash_secret'], conforming):
        assert value not in message, message
print(len(absent), 'refusal(s) with CSRF_SECRET absent;', len(clean), 'remaining with it set')
"
verdict_report="$(in_image)" \
    || fail "the artifact does not refuse a production environment the deploy preflight would reject"
pass "validate_settings refuses an absent/short/reused CSRF_SECRET and names no value: $verdict_report"

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

# The two lanes must differ in EXACTLY ONE thing: who owns the DATABASE. An
# earlier construction also left the `public` schema owned by `postgres` in lane
# B, so `app_admin` could not create anything and the restore landed zero tables
# — the guard below caught it, and it would have "failed for the right message"
# for entirely the wrong reason. A two-variable experiment cannot attribute its
# own result.
#
# So both copies get `public` owned by `app_admin` and their objects restored as
# `app_admin`, exactly as production has them. Only `datdba` differs.
psql_admin -c "CREATE DATABASE restored_ok OWNER app_admin;" >/dev/null
psql_admin -c "CREATE DATABASE restored_wrong_owner OWNER postgres;" >/dev/null
for target in restored_ok restored_wrong_owner; do
    psql_admin --dbname "$target" -c "ALTER SCHEMA public OWNER TO app_admin;" >/dev/null
done
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

# The single-variable proof, asserted rather than assumed. Both copies must
# agree on schema ownership and disagree on database ownership; if they ever
# agree on both, lane B stops being a trap and starts being a duplicate of
# lane A that happens to pass.
ok_owners="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT pg_get_userbyid(datdba) || '|' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public') FROM pg_database WHERE datname=current_database();")"
bad_owners="$(psql_admin --tuples-only --no-align --dbname restored_wrong_owner -c \
  "SELECT pg_get_userbyid(datdba) || '|' || (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public') FROM pg_database WHERE datname=current_database();")"
test "$ok_owners" = "app_admin|app_admin" \
    || fail "lane A ownership is $ok_owners, expected app_admin|app_admin"
test "$bad_owners" = "postgres|app_admin" \
    || fail "lane B ownership is $bad_owners, expected postgres|app_admin — the lanes must differ only in DATABASE ownership"
pass "two copies of one production-shaped state, differing only in database ownership"

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
# And the refusal must be about the DATABASE, not about a table the restore
# happened to leave unreachable — the failure mode the single-variable setup
# above exists to exclude.
grep -qi "permission denied for table\|permission denied for relation" "$WORKDIR/wrong-owner.log" \
    && fail "lane B failed on TABLE privileges, so it was not testing database ownership"
pass "lane B failed on database ownership specifically, not on object privileges"

step "5  database ownership, roles, grants and isolation"
# `::text` on every flag, and it is load-bearing rather than tidy. PostgreSQL
# has TWO renderings of a boolean and they do not agree: the type's own output
# function — which is what `format('%s', ...)` calls — emits `t`/`f`, while the
# boolean-to-text CAST emits `true`/`false`. Written without the casts this
# assertion compared `f|f|t|t` against a declared `false|false|true|true` and
# could never hold, on any correct database. It was measured failing in run
# 33407635872 on protected main, at the FIRST assertion of step 5, which is why
# nothing after it in this battery had ever executed.
#
# The declared form is kept in the readable spelling and the QUERY is corrected,
# rather than the other way round: `false|false|true|true` says what the role
# contract IS to someone reading the failure message, and `f|f|t|t` does not.
SQL="
SELECT format('%s|%s|%s|%s',
  (SELECT rolsuper::text FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolcreaterole::text FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolbypassrls::text FROM pg_roles WHERE rolname='app_admin'),
  (SELECT rolcanlogin::text FROM pg_roles WHERE rolname='app_admin'));
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

# NAMED, not counted, and declared as an EQUALITY rather than an emptiness.
#
# Two corrections live here, both measured. The first version reported a number:
# "1 tenant-scoped table does not have RLS forced" does not say which table, in
# which schema, or whether the gap is enabled-but-not-forced or no row security
# at all, so an operator reading the failure has to reproduce the whole battery
# to learn what it found.
#
# The second is the predicate itself. Carrying a column NAMED `tenant_id` is not
# the same as being tenant-SCOPED. `public.tenant_domains` maps a hostname to a
# tenant and is precisely what `dotmac_kernel.middleware.tenant` reads IN ORDER
# TO DISCOVER which tenant a request belongs to — necessarily before any tenant
# context exists. Row security there would make every request fail to resolve,
# so the kernel declares it platform-level and grants `app_user` SELECT on it
# explicitly (kernel migration `0001_initial_tenant_schema`: "`tenants` and
# `tenant_domains` (NOT under RLS — platform-level)").
#
# So it is DECLARED, not exempted-by-silence, and declared as an equality so the
# ratchet bites in both directions: a newly unprotected tenant-scoped table makes
# the observed set grow and fails, and `tenant_domains` acquiring row security
# makes it shrink and also fails — either way the declaration is revisited
# rather than quietly satisfied.
RESOLVER_INPUT_TABLES="public.tenant_domains"
unforced="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT COALESCE(string_agg(DISTINCT n.nspname||'.'||c.relname, ', ' ORDER BY n.nspname||'.'||c.relname), '') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN information_schema.columns col ON col.table_schema=n.nspname AND col.table_name=c.relname AND col.column_name='tenant_id' WHERE c.relkind='r' AND NOT (c.relrowsecurity AND c.relforcerowsecurity);")"
test "$unforced" = "$RESOLVER_INPUT_TABLES" \
    || fail "tables carrying tenant_id without RLS enabled AND forced are [$unforced]; the declared resolver-input set is [$RESOLVER_INPUT_TABLES]"
# NON-VACUITY: the assertion above is satisfied by a database with no
# tenant-scoped table at all, which is exactly what a wrong schema name or a
# mis-joined catalogue query would produce.
tenant_scoped="$(psql_admin --tuples-only --no-align --dbname restored_ok -c \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN information_schema.columns col ON col.table_schema=n.nspname AND col.table_name=c.relname AND col.column_name='tenant_id' WHERE c.relkind='r';" | tr -d ' ')"
test "$tenant_scoped" -gt 1 \
    || fail "only $tenant_scoped table carries tenant_id, so the equality above is satisfied by the declaration alone"
pass "$tenant_scoped tables carry tenant_id; all but the declared resolver input force row security"

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
        --env CSRF_SECRET=candidate-csrf-secret-not-a-real-one-0123456789 \
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

login_status="$(curl --silent --output "$WORKDIR/login.json" --write-out '%{http_code}' \
    --max-time 10 --header "Host: ${HOSTNAME_HEADER}" \
    --header 'Content-Type: application/json' \
    --data "{\"email\":\"${admin_email}\",\"password\":\"${admin_password}\"}" \
    "http://127.0.0.1:8000/platform/auth/login")"
token="$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("access_token", ""))
except Exception:
    print("")' "$WORKDIR/login.json")"
test -n "$token" \
    || fail "the API did not issue a bearer token to the CLI-created identity (HTTP $login_status): $(refusal_reason "$WORKDIR/login.json")"
pass "API: the identity the CLI created authenticates over the bearer plane"

doc_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Host: ${HOSTNAME_HEADER}" --header "Authorization: Bearer ${token}" \
    "http://127.0.0.1:8000/openapi.json")"
test "$doc_code" = "200" \
    || fail "the bearer-protected document plane returned $doc_code to a platform admin"
pass "API: /openapi.json answers 200 to a platform-admin bearer token"

# Cookies are REPLAYED from the response headers rather than kept in curl's
# cookie jar, and that is forced by a real property of the artifact rather than
# by convenience. `CSRFMiddleware` names its cookie `__Host-csrf_token` when
# `production` is set, and the `__Host-` prefix requires `Secure` — so curl,
# which correctly refuses to return a Secure cookie over plain `http://`, sent
# nothing back and the login was 403. Production terminates TLS at nginx; this
# battery drives the container directly, so the transport differs and only the
# transport does. Replaying `Set-Cookie` verbatim is what a browser over TLS
# would do.
#
# It does not weaken the check: the token is still signed, still expiring, and
# still bound to the very cookie set being replayed, and the non-vacuity case
# below proves the refusal still fires.
replay_cookies() {
    tr -d '\r' < "$1" \
        | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' \
        | paste -sd ';' - \
        | sed 's/;/; /g'
}

login_page="$(curl --silent --max-time 10 --dump-header "$WORKDIR/login.head" \
    --header "Host: ${HOSTNAME_HEADER}" "http://127.0.0.1:8000/platform/login")"
issued_cookies="$(replay_cookies "$WORKDIR/login.head")"
test -n "$issued_cookies" \
    || fail "the login page issued no cookie at all, so the CSRF proof cannot be bound to one"
csrf="$(printf '%s' "$login_page" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')"
test -n "$csrf" || fail "the login page carries no hidden csrf_token field"

# NON-VACUITY, first: replaying cookies must not have turned the protection off.
# The same request without the proof has to be refused, or "the login succeeded"
# says nothing about whether anything was checked.
unproven_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Host: ${HOSTNAME_HEADER}" --header "Cookie: ${issued_cookies}" \
    --data-urlencode "email=${admin_email}" \
    --data-urlencode "password=${admin_password}" \
    "http://127.0.0.1:8000/platform/login")"
test "$unproven_code" = "403" \
    || fail "a form POST with no CSRF proof returned $unproven_code, expected 403 — the check is not live"
pass "browser: a form POST carrying no CSRF proof is refused 403"

login_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --dump-header "$WORKDIR/session.head" \
    --header "Host: ${HOSTNAME_HEADER}" --header "Cookie: ${issued_cookies}" \
    --data-urlencode "email=${admin_email}" \
    --data-urlencode "password=${admin_password}" \
    --data-urlencode "csrf_token=${csrf}" \
    "http://127.0.0.1:8000/platform/login")"
case "$login_code" in
    200|302|303) ;;
    *) fail "the browser login returned $login_code — no session can be obtained" ;;
esac
# Anything the login response set (the platform session, a rotated CSRF token)
# comes LAST so it overrides the value issued by the page.
session_cookies="$(replay_cookies "$WORKDIR/session.head")"
test -n "$session_cookies" \
    || fail "the browser login set no cookie, so it granted no session"
console_code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    --header "Cookie: ${issued_cookies}; ${session_cookies}" \
    --header "Host: ${HOSTNAME_HEADER}" \
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

step "17  separation: the deployment tool is not in the application image"
# An OBSERVATION about this candidate, not a rule about future ones.
#
# `dotmac-deployment-foundation` is the deployment TOOL. It renders the
# execution plan and computes the digest an authorization binds; it has no
# business inside the application. Today it stays out because it is in no
# dependency group and the Dockerfile installs `--only main` — a mechanism,
# with nothing asserting the result. This reads the RESULT, off the exact bytes
# about to be published, because the recipe and the artifact are different
# claims and this pipeline exists for the cases where they disagree.
#
# `--network none`: the answer must come from the image, not from an index.
separation="$(docker run --rm --network none --entrypoint python "$IMAGE" -c '
import importlib.metadata as md, importlib.util as iu, json
names = sorted((d.metadata["Name"] or "").lower() for d in md.distributions())
try:
    importable = iu.find_spec("dotmac_deployment_foundation") is not None
except ModuleNotFoundError:
    importable = False
print(json.dumps({
    "present": [n for n in names if n == "dotmac-deployment-foundation"],
    "importable": importable,
    "distributions_seen": len(names),
}))')"
printf '  image reports %s\n' "$separation"

python3 - "$separation" <<'SEPARATION' || fail "the deployment tool must not be inside the application image"
import json, sys

observed = json.loads(sys.argv[1])
problems = []
if observed["present"]:
    problems.append(f"the image carries {observed['present']}")
if observed["importable"]:
    problems.append("dotmac_deployment_foundation is importable inside the image")
# NON-VACUITY. An empty `present` list is also what a broken enumeration
# returns, and "we found nothing" would then be indistinguishable from "we
# looked at nothing" — the same shape as a validator only ever seen refusing.
if observed["distributions_seen"] < 2:
    problems.append(
        f"only {observed['distributions_seen']} distribution(s) were enumerated, "
        "so the absence above is not evidence of anything"
    )
if problems:
    print("; ".join(problems), file=sys.stderr)
    raise SystemExit(1)
SEPARATION
pass "the deployment tool must not be inside the application image, and is not"
pass "and the enumeration saw the image's other distributions, so the absence means something"

printf '\nCANDIDATE ACCEPTED\n'
