#!/bin/bash
# ADR-0013 single-use bootstrap launcher — Platform Control Plane.
#
# The thing that authorizes deployments cannot authorize its own first
# deployment. This discharges that circularity ONCE, and is built so that it
# cannot discharge it twice.
#
# Reuse is prevented STRUCTURALLY rather than by a check somebody could skip:
# the receipt path is claimed with `set -C` (O_EXCL) as the FIRST action, before
# any work happens. A second invocation fails on that create and never reaches
# the deployment. A crashed first invocation also leaves the claim behind, and
# that is deliberate — a partial bootstrap must be investigated, never silently
# retried. A receipt written at the end records that a bootstrap happened; a
# claim taken at the start is what makes a second one impossible.
#
# It calls no secret store. Every credential is already installed in the host's
# `.env`, which is the same held-secret seam the application itself reads. There
# is no OpenBao call on this path at any point.
#
# RETIREMENT: this file is deleted once Platform CP has authorized its own
# second deployment. Until then it is the only bootstrap path and its call
# sites must stay at exactly one.
#
# Usage: bootstrap_once.sh <image-id> <expected-revision> <expected-layer-chain>
set -Cueo pipefail

RECEIPT=/opt/dotmac/vendor-control-plane/BOOTSTRAP_RECEIPT.json
DEPLOY_DIR=/opt/dotmac/vendor-control-plane
COMPOSE=docker-compose.production.yml
IMAGE_ID="${1:?image id required}"
EXPECT_REVISION="${2:?expected source revision required}"
EXPECT_LAYER_CHAIN="${3:?expected rootfs layer chain required}"

die() { echo "BOOTSTRAP REFUSED: $*" >&2; exit 1; }

# 1. The target must identify itself. An address can be reassigned; a marker
#    cannot be arrived at by accident.
[ "$(cat /etc/dotmac-host-id 2>/dev/null)" = "vendor-cp-prod" ] \
  || die "host marker is not vendor-cp-prod"

# 2. Claim the receipt path ATOMICALLY. This is the single-use gate and it is
#    first on purpose: nothing below it can ever run a second time.
{ printf '{"state":"claimed","claimed_at":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RECEIPT"; } 2>/dev/null \
  || die "receipt already exists at $RECEIPT - this bootstrap is single-use and has already run"

# 3. The image must be the bytes verified off-host. A manifest digest does not
#    survive docker save/load, so identity is proven by the RootFS layer chain,
#    which does, together with the source revision label.
ACTUAL_REVISION="$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_ID")"
[ "$ACTUAL_REVISION" = "$EXPECT_REVISION" ] \
  || die "image revision $ACTUAL_REVISION != expected $EXPECT_REVISION"
ACTUAL_CHAIN="$(docker image inspect "$IMAGE_ID" \
  --format '{{range .RootFS.Layers}}{{println .}}{{end}}' \
  | sed '/^$/d' | sha256sum | cut -d' ' -f1)"
[ "$ACTUAL_CHAIN" = "$EXPECT_LAYER_CHAIN" ] \
  || die "image layer chain $ACTUAL_CHAIN != verified $EXPECT_LAYER_CHAIN"

cd "$DEPLOY_DIR"

# 4. Ownership gate, BEFORE the migrations run. A database whose owner differs
#    fails partway through at CREATE SCHEMA, and the recovery bundle does not
#    carry database ownership, so nothing upstream catches it first.
OWNER="$(docker compose -f "$COMPOSE" exec -T db \
  psql -U app_admin -d vendor_control_plane -tAc \
  'select pg_get_userbyid(datdba)' | tr -d '[:space:]')"
[ "$OWNER" = "app_admin" ] || die "database owner is $OWNER, expected app_admin"

# 5. Backup, WITH cluster globals. A database-only dump restores into something
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
DUMP_SHA="$(sha256sum "${BACKUP_DIR}/bootstrap-${STAMP}.dump" | cut -d' ' -f1)"

# 6. Pin the image, migrate, start. One composed migration owner - every
#    lineage advances before the application is replaced.
sed -i "s|^VENDOR_APP_IMAGE=.*|VENDOR_APP_IMAGE=${IMAGE_ID}|" .env
export VENDOR_APP_IMAGE="$IMAGE_ID"

docker compose -f "$COMPOSE" --profile ops run --rm --no-deps ops scripts/migrate.py
docker compose -f "$COMPOSE" up -d app --wait

HEADS="$(docker compose -f "$COMPOSE" exec -T db \
  psql -U app_admin -d vendor_control_plane -tAc \
  'select version_num from alembic_version order by 1' | tr -d '\r' | paste -sd, -)"

curl --fail --silent --show-error --max-time 10 \
  --header 'Host: vendor.dotmac.io' \
  "http://127.0.0.1:8100/health" >/dev/null || die "health check failed"

# 7. Finalise. The claim in step 2 already prevents reuse; this records what the
#    single use actually bound.
cat > "${RECEIPT}.tmp" <<RECEIPT_JSON
{
  "schema": "PlatformCpBootstrapReceipt.v1",
  "state": "completed",
  "single_use": "the receipt path is claimed with O_EXCL before any work; a second run cannot start",
  "target": "vendor-cp-prod",
  "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image_id": "${IMAGE_ID}",
  "source_revision": "${EXPECT_REVISION}",
  "image_layer_chain_sha256": "${EXPECT_LAYER_CHAIN}",
  "pre_bootstrap_image_digest": "sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d",
  "pre_bootstrap_revision": "af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e",
  "backup_dump_sha256": "${DUMP_SHA}",
  "backup_stamp": "${STAMP}",
  "migration_heads_after": "${HEADS}",
  "database_owner_verified": "app_admin",
  "retires_when": "Platform CP authorizes its own second deployment; this receipt is then history and this launcher is deleted"
}
RECEIPT_JSON
mv "${RECEIPT}.tmp" "$RECEIPT"
echo "BOOTSTRAP COMPLETE"
echo "heads: ${HEADS}"
