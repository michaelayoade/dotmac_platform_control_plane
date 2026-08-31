#!/bin/bash
# ADR-0013 (as amended 2026-08-31) — the single-use, CREATE-ONLY issuer bootstrap.
#
# The thing that authorizes deployments cannot authorize its own first
# deployment. This discharges that circularity ONCE.
#
# WHAT CREATE-ONLY MEANS HERE, because the first version of this file got it
# wrong: this creates the issuer's AUTHORITY inside the existing deployment and
# nothing else. It does not replace, restart, update or reconfigure the running
# application, it does not rewrite VENDOR_APP_IMAGE, and it exposes no interface
# that could. The earlier version ran `docker compose up -d app` — a general
# deployment capability, which is exactly what the issuer is supposed to become
# the sole owner of. Written to bootstrap an authority, it was a second
# executor.
#
# The running application is replaced for the first time by a deployment
# Platform CP ITSELF authorizes, and that self-authorized deployment is the
# proof the issuer works. A bootstrap that had already replaced the application
# would have destroyed the thing that proof depends on.
#
# Reuse is prevented STRUCTURALLY: the receipt path is claimed with `set -C`
# (O_EXCL) as the FIRST action, before any work. A second invocation dies on
# that create. A crashed first run leaves the claim standing, deliberately — a
# partial bootstrap is investigated, never silently retried.
#
# It calls no secret store. Credentials are already installed in the host `.env`,
# the same held-secret seam the application reads (ADR-0009).
#
# RETIREMENT: this file, and the classifier rule that permits it, are removed
# once Platform CP authorizes its own second deployment.
#
# Usage:
#   bootstrap_once.sh <transferred-image-id> <source-revision> <layer-chain>
set -Cueo pipefail

DEPLOY_DIR=/opt/dotmac/vendor-control-plane
COMPOSE=docker-compose.production.yml
RECEIPT="${DEPLOY_DIR}/BOOTSTRAP_RECEIPT.json"

IMAGE_ID="${1:?transferred image id required}"
EXPECT_REVISION="${2:?expected source revision required}"
EXPECT_LAYER_CHAIN="${3:?expected rootfs layer chain required}"

# Coordinates fixed at authorship. They are literals rather than arguments so
# that the argv vector a permission rule pins cannot vary them.
REGISTRY_DIGEST="sha256:3e35aeb837ed6c109b4fab44171de7490c402d6dce2e6eccaa316e192ca48efc"
CONTROL_WHEEL_SHA256="sha256:9b02cf33f954b6562858af320b518c10f9e93aa92fbc3873e4a83fdf117b8fc0"
DESCRIPTOR_SHA256="sha256:99eef0cc82bc73065c17c543e7a3d8824e825d3c97da22bd4e73f648e0b2daeb"
AUTHORIZER="Michael Ayoade"
TARGET_MARKER="vendor-cp-prod"

die() { echo "BOOTSTRAP REFUSED: $*" >&2; exit 1; }

# 1. The target identifies itself by MARKER. An address can be reassigned.
[ "$(cat /etc/dotmac-host-id 2>/dev/null)" = "$TARGET_MARKER" ] \
  || die "host marker is not ${TARGET_MARKER}"

# 2. The receipt CONDITION is the ADR's, not this file's own bookkeeping. Any
#    receipt asserting the bootstrap has occurred stops this, and one that
#    cannot be parsed or does not match this contract is a refusal rather than
#    an invitation to proceed.
for candidate in "$RECEIPT" "${DEPLOY_DIR}"/*BOOTSTRAP*RECEIPT*.json; do
  [ -e "$candidate" ] || continue
  die "a bootstrap receipt already exists at ${candidate} - the issuer authority is created once"
done

# 3. Claim the receipt path ATOMICALLY, before any work. This is the single-use
#    gate; everything below it is unreachable on a second invocation.
{ printf '{"state":"claimed","claimed_at":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RECEIPT"; } 2>/dev/null \
  || die "could not claim ${RECEIPT} - it already exists and this bootstrap is single-use"

# 3a. Compose interpolation, before the FIRST `docker compose` call.
#
#     Every compose invocation below — including the read-only ownership check —
#     parses the whole file, and the `db` service interpolates a bootstrap
#     password at parse time even though the already-running database never
#     consumes it. Exporting this later than the first compose call is exactly
#     the bug that aborted the first authorized attempt: the launcher died on
#     the ownership gate having mutated nothing, but having already taken its
#     single-use claim.
#
#     The value is ephemeral, generated per run, never stored and never read by
#     anything: the database it nominally belongs to was initialised long ago.
VENDOR_DB_BOOTSTRAP_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export VENDOR_DB_BOOTSTRAP_PASSWORD
#
#     VENDOR_APP_IMAGE is the SECOND parse-time variable and belongs here for
#     the identical reason. Exporting it beside the ops container it feeds read
#     naturally and was wrong: `services.app.image` interpolates whenever the
#     file is parsed, so the ownership gate needed it too. Setting it here does
#     NOT deploy anything — it only lets compose parse, and the `app` service is
#     never named in a command below.
export VENDOR_APP_IMAGE="$IMAGE_ID"

# 4. Image identity: BOTH the transferred id and the layer chain, plus the
#    revision label. `docker save`/`load` does not preserve the manifest digest,
#    so the chain is what survives the transfer and the registry digest is what
#    ties it back to what was verified off-host. Neither substitutes.
ACTUAL_REVISION="$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_ID")"
[ "$ACTUAL_REVISION" = "$EXPECT_REVISION" ] \
  || die "image revision ${ACTUAL_REVISION} != expected ${EXPECT_REVISION}"
ACTUAL_CHAIN="$(docker image inspect "$IMAGE_ID" \
  --format '{{range .RootFS.Layers}}{{println .}}{{end}}' \
  | sed '/^$/d' | sha256sum | cut -d' ' -f1)"
[ "$ACTUAL_CHAIN" = "$EXPECT_LAYER_CHAIN" ] \
  || die "image layer chain ${ACTUAL_CHAIN} != verified ${EXPECT_LAYER_CHAIN}"

cd "$DEPLOY_DIR"

# 5. Ownership gate BEFORE migrations. A database whose owner differs fails
#    partway through at CREATE SCHEMA, and the recovery bundle does not carry
#    database ownership, so nothing upstream catches it.
OWNER="$(docker compose -f "$COMPOSE" exec -T db \
  psql -U app_admin -d vendor_control_plane -tAc \
  'select pg_get_userbyid(datdba)' | tr -d '[:space:]')"
[ "$OWNER" = "app_admin" ] || die "database owner is ${OWNER}, expected app_admin"

# 6. Backup WITH cluster globals. A database-only dump restores into something
#    that looks recovered and has no roles, no grants and no isolation.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR=/opt/backups/dotmac-vendor-control-plane
mkdir -p "$BACKUP_DIR"
umask 077
docker compose -f "$COMPOSE" exec -T db \
  sh -c 'exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom' \
  > "${BACKUP_DIR}/bootstrap-${STAMP}.dump"
docker compose -f "$COMPOSE" exec -T db \
  sh -c 'exec pg_dumpall --username app_admin --globals-only --no-role-passwords' \
  > "${BACKUP_DIR}/bootstrap-${STAMP}.globals.sql"
DUMP_SHA="sha256:$(sha256sum "${BACKUP_DIR}/bootstrap-${STAMP}.dump" | cut -d' ' -f1)"

# 7. CREATE the issuer authority. One short-lived `ops` container on the new
#    image runs the composed migrations; `--no-deps` keeps it from touching any
#    other service, and `--rm` leaves nothing behind. The running `app` service
#    is NOT named here, NOT restarted, and NOT repinned. That absence is the
#    create-only property.
#
docker compose -f "$COMPOSE" --profile ops run --rm --no-deps ops scripts/migrate.py

# 8. Prove the authority now exists and the application was left alone.
HEADS="$(docker compose -f "$COMPOSE" exec -T db \
  psql -U app_admin -d vendor_control_plane -tAc \
  'select version_num from alembic_version order by 1' | tr -d '\r' | paste -sd, -)"
MOD_DEPLOY="$(docker compose -f "$COMPOSE" exec -T db \
  psql -U app_admin -d vendor_control_plane -tAc \
  "select count(*) from pg_namespace where nspname = 'mod_deploy'" | tr -d '[:space:]')"
[ "$MOD_DEPLOY" = "1" ] || die "mod_deploy was not created; the issuer has no authority"

RUNNING_REVISION="$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  dotmac_vendor_control_plane-app-1)"
[ "$RUNNING_REVISION" != "$EXPECT_REVISION" ] \
  || die "the running application was replaced; this bootstrap is create-only"

curl --fail --silent --show-error --max-time 10 \
  --header 'Host: vendor.dotmac.io' \
  'http://127.0.0.1:8100/health' >/dev/null || die "health check failed after bootstrap"

LAUNCHER_SHA="sha256:$(sha256sum "$0" | cut -d' ' -f1)"

# 9. Finalise, binding all nine coordinates. The claim in step 3 already
#    prevents reuse; this records what the single use bound.
cat > "${RECEIPT}.tmp" <<RECEIPT_JSON
{
  "schema": "PlatformCpBootstrapReceipt.v1",
  "state": "completed",
  "single_use": "the receipt path is claimed with O_EXCL before any work; a second run cannot start",
  "create_only": "created the issuer authority (mod_deploy) inside the existing deployment; the running application was not replaced, restarted or repinned",
  "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_revision": "${EXPECT_REVISION}",
  "registry_image_digest": "${REGISTRY_DIGEST}",
  "transferred_image_id": "${IMAGE_ID}",
  "rootfs_layer_chain_sha256": "${EXPECT_LAYER_CHAIN}",
  "control_wheel_sha256": "${CONTROL_WHEEL_SHA256}",
  "product_descriptor_sha256": "${DESCRIPTOR_SHA256}",
  "migration_heads": "${HEADS}",
  "launcher_sha256": "${LAUNCHER_SHA}",
  "authorizer": "${AUTHORIZER}",
  "target": "${TARGET_MARKER}",
  "workflow_revision": "hand-run by the authorizer; no workflow performed this bootstrap",
  "pre_bootstrap_revision": "${RUNNING_REVISION}",
  "backup_dump_sha256": "${DUMP_SHA}",
  "retires_when": "Platform CP authorizes its own second deployment; this receipt becomes history, this launcher is deleted, and the classifier rule permitting it is removed"
}
RECEIPT_JSON
mv "${RECEIPT}.tmp" "$RECEIPT"
echo "BOOTSTRAP COMPLETE - issuer authority created, application untouched"
echo "heads: ${HEADS}"
