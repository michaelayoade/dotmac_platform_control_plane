#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_HOST_ID="vendor-cp-prod"
readonly COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
readonly ENV_FILE="${ENV_FILE:-.env}"
readonly HOST_ID_FILE="${HOST_ID_FILE:-/etc/dotmac-host-id}"
readonly BACKUP_DIR="${BACKUP_DIR:-/opt/backups/dotmac-vendor-control-plane}"
readonly DESCRIPTOR_FILE="${DESCRIPTOR_FILE:-deploy/product.toml}"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || die "usage: scripts/deploy_production.sh sha256:<digest> <authorization-ref>"
readonly DIGEST="$1"
readonly AUTHORIZATION_REF="$2"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image digest is not sha256"
[[ -n "${AUTHORIZATION_REF// }" ]] || die "an authorization reference is required"

# ── This script is an EFFECT ADAPTER, not an effector anyone may call ────────
#
# It used to take one argument and a `sha256:` regex, and that was its entire
# contract. Every check that made a deploy legitimate — the CI run, the release
# receipt, the ancestry, the target name — lived in the WORKFLOW, so anyone
# holding the deploy SSH key skipped all of them by running one command here.
#
# A check beside the effect is not a control; it is a convention one caller
# happens to follow. The authority question now runs HERE, before anything is
# touched, and is asked of Control rather than of whoever invoked this.
#
# Cleanup is this script's own. The wrapper that hands it a registry token has a
# trap; this one had none, and it is the process holding the compose operation
# when an SSH connection drops.
cleanup_effector() {
    local status=$?
    [[ -n "${BUNDLE_TMP:-}" && -d "${BUNDLE_TMP:-/nonexistent}" ]] \
        && rm -rf -- "$BUNDLE_TMP"
    return "$status"
}
trap cleanup_effector EXIT HUP INT TERM

# ── One deployment at a time, enforced where the deployment happens ──────────
#
# `concurrency:` in the workflow is GitHub-side, so it does not exist for a
# direct invocation on this host — the identical hole as the authority check.
# `flock` is held for the whole run and released when this process exits,
# including when its SSH connection drops.
readonly LOCK_FILE="${LOCK_FILE:-/var/lock/dotmac-vendor-control-plane-deploy.lock}"
exec {LOCK_FD}>"$LOCK_FILE" || die "cannot open the deployment lock $LOCK_FILE"
flock --nonblock "$LOCK_FD" \
    || die "another deployment holds $LOCK_FILE. Deployments are serialized here \
rather than in the workflow, because a workflow-side group does not exist for a \
direct invocation on this host."

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

# ── Authorized, or nothing happens ──────────────────────────────────────────
#
# Asked of Control through the installed console script in a one-shot ops
# container, on the exact image about to be deployed. `--no-deps` starts
# nothing: this question opens no session and reaches no database, so it can be
# answered before the first mutation rather than after it.
#
# The refusal is fail-closed BY DESIGN while Platform CP pins a Control without
# the read API. A deployment that cannot be shown to be authorized does not
# proceed, and leaving the effector ungated until the lookup exists would keep
# the SSH-key bypass open for exactly as long as it takes someone to forget.
#
# Exit 4 is "nothing looked" and exit 3 is "an owner said no". They are
# different findings for different people and this path keeps them apart.
compose --profile ops run --rm --no-deps ops \
    dotmac-platform deployment require-authorization \
        --authorization-ref "$AUTHORIZATION_REF" \
        --image-digest "$DIGEST" \
    || die "refusing to deploy ${DIGEST}: Control did not authorize it under \
${AUTHORIZATION_REF}. Nothing has been changed — no container started, no \
migration applied, no bundle written."

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

# ── The recovery bundle: one atomic artifact, or no deployment ───────────────
#
# Rehearsed 2026-08-30 against this host's own newest backup: a plain
# `pg_restore` of a custom dump exited 1 with 114 missing-role errors across
# five roles, and left a database that LOOKED recovered — 45 tables, 23 of 26
# policies, 16 RLS-enabled tables — with no roles, no grants, and every object
# owned by whoever ran the restore. `pg_dump` of one database carries object
# ACLs and RLS policies but never role definitions, memberships or tablespaces:
# those are CLUSTER objects and only `pg_dumpall --globals-only` emits them.
#
# That is worse than a backup that fails outright. This assembly's plane
# separation IS the grant/revoke matrix rather than the policies alone
# (`dotmac_starter_mt` ADR-0023), so a restore that silently drops the role
# layer produces a control-plane database with no plane separation, and an
# operator reading `pg_policies` afterwards concludes the isolation model came
# back. It did not.
#
# So a backup is no longer a file. It is a BUNDLE — dump, globals, manifest and
# checksums — assembled in a hidden temporary directory, validated in full, and
# moved into place with a single `mv`, which is `rename(2)` within one
# filesystem and therefore atomic. A reader either sees a complete bundle or
# sees nothing. And the deploy REFUSES to migrate unless one exists: a rollback
# that is discovered to be absent after the schema has advanced is not a
# rollback.
#
# This runs before the migration and before the application is replaced, under
# the workflow's `vendor-control-plane-production` concurrency group, which is
# the only deployment lock this path has.
mkdir -p "$BACKUP_DIR"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly BUNDLE_PATH="${BACKUP_DIR}/bundle-${TIMESTAMP}"
[[ ! -e "$BUNDLE_PATH" ]] || die "recovery bundle $BUNDLE_PATH already exists"
BUNDLE_TMP="$(mktemp -d "${BACKUP_DIR}/.bundle-${TIMESTAMP}.XXXXXX")"
readonly BUNDLE_TMP
chmod 700 "$BUNDLE_TMP"

# 1. Cluster globals, through the container-local PostgreSQL superuser over the
#    unix socket. `app_admin` is NOSUPERUSER by contract (checked above) and is
#    not the right authority for a CLUSTER dump — it owns one database. The
#    socket is why no password is needed and none is retained: this cluster
#    deliberately has none for `postgres` (`deploy/postgres/init-roles.sh` ends
#    with `ALTER ROLE postgres PASSWORD NULL`).
#
#    `--no-role-passwords` is the configuration that was PROVED, not a
#    precaution: the same artefact restored with globals captured this way
#    exited 0 with zero errors and `verify_recovery` reported zero findings
#    across roles, memberships, ownership, effective privileges and RLS force
#    (`docs/operations/recovery-proved-2026-08-30.md`). It reads `pg_roles`
#    rather than `pg_authid`, so no SCRAM verifier is written to a file at rest.
#    A restored cluster therefore has the five roles with NULL passwords, and
#    the operator resupplies them from OpenBao before the application connects.
compose exec -T --user postgres db \
    pg_dumpall --username postgres --globals-only --no-role-passwords \
    > "${BUNDLE_TMP}/globals.sql"

# 2. The database, with ownership and privileges INTACT. No `--no-owner` and no
#    `--no-privileges`: stripping either would reproduce, by flag, exactly the
#    state the rehearsal found by accident.
#
#    `sh -c 'exec pg_dump …'` is one idiom, not two coincidences. `sh -c` is
#    needed because `$POSTGRES_DB` must expand inside the container; `exec`
#    replaces that shell so the container's process IS pg_dump. Drop the `exec`
#    and a dropped SSH connection leaves an orphaned shell holding the pipe
#    while pg_dump keeps writing into it. A rewrite that keeps the command and
#    loses the `exec` reads identically in review and reintroduces the bug.
compose exec -T db sh -c \
    'exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom' \
    > "${BUNDLE_TMP}/database.dump"

# 3. Validate BEFORE accepting. Every check below is a way the pair can be
#    present and useless.
[[ -s "${BUNDLE_TMP}/globals.sql" ]] || die "cluster globals capture is empty"
[[ -s "${BUNDLE_TMP}/database.dump" ]] || die "database dump is empty"

#    The dump's own table of contents must parse. A truncated custom-format
#    dump is a well-formed FILE and `pg_restore --list` is what distinguishes
#    it from an archive. Piped back into the container because the host holds
#    no PostgreSQL client tools.
compose exec -T db pg_restore --list < "${BUNDLE_TMP}/database.dump" > /dev/null \
    || die "the database dump is not a readable pg_restore archive"

#    Checked by NAME, against the five roles `deploy/postgres/init-roles.sh`
#    creates and `deploy/product.toml` declares as `[[database.roles]]`. A
#    non-empty check would pass on a globals file carrying only tablespaces —
#    which is exactly the shape that produces 114 errors while looking like a
#    capture.
for role in app_admin app_user platform_api outbox_dispatcher \
            platform_outbox_dispatcher; do
    grep -Eq "^CREATE ROLE \"?${role}\"?;\$" "${BUNDLE_TMP}/globals.sql" || die \
"cluster globals capture does not create role ${role}. The pair would restore \
without the grant/revoke matrix that IS this database's plane separation, and \
the restore would look successful. Nothing has been changed."
done

#    And the other direction, because `--no-role-passwords` is a flag and a flag
#    can be dropped. A verifier in this file would be a production credential at
#    rest in a backup directory. Matched on the SHAPE of a verifier, never
#    printed.
! grep -Eq "SCRAM-SHA-256\\\$|PASSWORD '(md5|SCRAM)" "${BUNDLE_TMP}/globals.sql" \
    || die "the cluster globals capture contains a password verifier; \
--no-role-passwords did not hold and this bundle must not be kept"

# 4. The facts a restore has to be checked against, measured from the cluster
#    being captured rather than assumed from a declaration.
PG_VERSION_NUM="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" -tAc "SHOW server_version_num"' \
    | tr -d '\r\n')"
readonly PG_VERSION_NUM
[[ "$PG_VERSION_NUM" =~ ^[0-9]+$ ]] || die "could not read server_version_num"
readonly PG_MAJOR="$(( PG_VERSION_NUM / 10000 ))"

CLUSTER_SYSTEM_IDENTIFIER="$(compose exec -T --user postgres db \
    psql --username postgres -tAc \
    'SELECT system_identifier FROM pg_control_system()' | tr -d '\r\n')"
readonly CLUSTER_SYSTEM_IDENTIFIER
[[ "$CLUSTER_SYSTEM_IDENTIFIER" =~ ^[0-9]+$ ]] \
    || die "could not read the cluster system identifier"

DATABASE_NAME="$(compose exec -T db sh -c 'printf %s "$POSTGRES_DB"' | tr -d '\r\n')"
readonly DATABASE_NAME
[[ -n "$DATABASE_NAME" ]] || die "could not read the database name"

# READ OFF THE ARTIFACT, not accepted as an argument. The revision this image
# was built from is inside its own config as an OCI label, so the manifest
# records what the bytes say rather than what the caller asserted.
SOURCE_REVISION="$(docker inspect \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    "$VENDOR_APP_IMAGE" | tr -d '\r\n')"
readonly SOURCE_REVISION
[[ "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] \
    || die "the image carries no 40-character OCI revision label"

# The ACCEPTED descriptor, as the deployment adapter delivered it. A bundle that
# cannot say which contract it is meant to satisfy cannot be checked against one.
[[ -f "$DESCRIPTOR_FILE" ]] || die "$DESCRIPTOR_FILE is missing; the deployment \
adapter did not deliver the accepted descriptor, so this bundle could not name \
the contract a recovery must satisfy"
DESCRIPTOR_SHA256="sha256:$(sha256sum "$DESCRIPTOR_FILE" | cut -d' ' -f1)"
readonly DESCRIPTOR_SHA256

MIGRATION_HEADS="$(compose exec -T db sh -c \
    'psql --username app_admin --dbname "$POSTGRES_DB" -tAc \
        "SELECT version_num FROM alembic_version ORDER BY version_num"' \
    | tr -d '\r')"
readonly MIGRATION_HEADS
[[ -n "$MIGRATION_HEADS" ]] || die "the database reports no migration heads"

# 5. Hash both components, in the format `sha256sum -c` reads back.
( cd "$BUNDLE_TMP" && sha256sum database.dump globals.sql > SHA256SUMS )

# 6. The manifest. Canonical JSON, so the bundle digest over it is re-derivable
#    by anyone holding the bundle.
env \
    BUNDLE_TMP="$BUNDLE_TMP" \
    TARGET_HOST_ID="$EXPECTED_HOST_ID" \
    PG_MAJOR="$PG_MAJOR" \
    CLUSTER_SYSTEM_IDENTIFIER="$CLUSTER_SYSTEM_IDENTIFIER" \
    DATABASE_NAME="$DATABASE_NAME" \
    IMAGE_DIGEST="$DIGEST" \
    SOURCE_REVISION="$SOURCE_REVISION" \
    DESCRIPTOR_SHA256="$DESCRIPTOR_SHA256" \
    MIGRATION_HEADS="$MIGRATION_HEADS" \
    CREATED_AT="$TIMESTAMP" \
    python3 - <<'MANIFEST'
import hashlib, json, os
from pathlib import Path

bundle = Path(os.environ["BUNDLE_TMP"])
digests = {}
for name in ("database.dump", "globals.sql"):
    digests[name] = "sha256:" + hashlib.sha256((bundle / name).read_bytes()).hexdigest()

manifest = {
    "schema": "PlatformCpRecoveryBundle.v1",
    "product": "dotmac_vendor_control_plane",
    "environment": "production",
    "target": os.environ["TARGET_HOST_ID"],
    "postgres_major": int(os.environ["PG_MAJOR"]),
    "cluster_system_identifier": os.environ["CLUSTER_SYSTEM_IDENTIFIER"],
    "database_name": os.environ["DATABASE_NAME"],
    "image_digest": os.environ["IMAGE_DIGEST"],
    "image_source_revision": os.environ["SOURCE_REVISION"],
    "descriptor_sha256": os.environ["DESCRIPTOR_SHA256"],
    "migration_heads": sorted(
        line for line in os.environ["MIGRATION_HEADS"].splitlines() if line.strip()
    ),
    "files": digests,
    "created_at": os.environ["CREATED_AT"],
    "restore_order": ["globals.sql", "database.dump"],
}
payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
# Written, not printed. The bundle digest has ONE producer, immediately below;
# a second `print` here would be a second answer to the same question.
(bundle / "manifest.json").write_text(payload + "\n", encoding="utf-8")
MANIFEST

# 7. The bundle digest is over the canonical manifest, which names both file
#    digests — so one value identifies the whole artifact.
BUNDLE_DIGEST="$(BUNDLE_TMP="$BUNDLE_TMP" python3 - <<'DIGEST'
import hashlib, json, os
from pathlib import Path
payload = json.loads(
    (Path(os.environ["BUNDLE_TMP"]) / "manifest.json").read_text(encoding="utf-8")
)
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
print("sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest())
DIGEST
)"
readonly BUNDLE_DIGEST
[[ "$BUNDLE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not digest the bundle"

# 8. Publish atomically. Until this line there is no bundle, only a dot-prefixed
#    temporary directory that no reader will mistake for one.
mv "$BUNDLE_TMP" "$BUNDLE_PATH"

# 9. REFUSE to go further without it — re-read from its published location
#    rather than trusting the variables that built it. `sha256sum -c` is the
#    check that the bytes on disk are the bytes that were hashed.
for component in database.dump globals.sql manifest.json SHA256SUMS; do
    [[ -f "${BUNDLE_PATH}/${component}" ]] \
        || die "recovery bundle is incomplete: ${component} is missing"
done
( cd "$BUNDLE_PATH" && sha256sum --quiet --check SHA256SUMS ) \
    || die "recovery bundle checksums do not verify; refusing to migrate"

printf 'recovery bundle %s\n  digest %s\n  restore order: globals.sql then database.dump\n' \
    "$BUNDLE_PATH" "$BUNDLE_DIGEST"

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

printf 'Deployed %s\nrecovery bundle: %s\nrecovery bundle digest: %s\n' \
    "$VENDOR_APP_IMAGE" "$BUNDLE_PATH" "$BUNDLE_DIGEST"
