#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_HOST_ID="vendor-cp-prod"
readonly DEPLOY_DIR="${DEPLOY_DIR:-/opt/dotmac/vendor-control-plane}"
readonly BACKUP_DIR="${BACKUP_DIR:-/opt/backups/dotmac-vendor-control-plane}"
readonly KEY_DIR="/run/secrets/dotmac/vendor-control-plane/licence-signing"
readonly KEY_FILE="${KEY_DIR}/primary.key"
readonly NGINX_AVAILABLE="/etc/nginx/sites-available/vendor.dotmac.io"
readonly NGINX_ENABLED="/etc/nginx/sites-enabled/vendor.dotmac.io"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || die "run as root on the explicitly named host"
: "${CERTBOT_EMAIL:?Set CERTBOT_EMAIL explicitly}"

for command in docker nginx certbot rsync; do
    command -v "$command" >/dev/null || die "$command is not installed"
done
docker compose version >/dev/null

install -d -m 0750 "$DEPLOY_DIR" "$BACKUP_DIR"
install -d -m 0700 -o 10001 -g 10001 "$KEY_DIR"
if [[ -f /etc/dotmac-host-id ]]; then
    [[ "$(tr -d '\r\n' < /etc/dotmac-host-id)" == "$EXPECTED_HOST_ID" ]] \
        || die "existing host identity is not $EXPECTED_HOST_ID"
fi
printf '%s\n' "$EXPECTED_HOST_ID" > /etc/dotmac-host-id
chmod 0644 /etc/dotmac-host-id

[[ -s "$KEY_FILE" ]] || die "$KEY_FILE must be materialised from OpenBao path secret/dotmac/licensing/signing-key before bootstrap"
chown 10001:10001 "$KEY_FILE"
chmod 0600 "$KEY_FILE"

install -d -m 0755 /var/www/certbot
install -m 0644 deploy/nginx/vendor.dotmac.io.bootstrap.conf "$NGINX_AVAILABLE"
ln -sfn "$NGINX_AVAILABLE" "$NGINX_ENABLED"
nginx -t
systemctl reload nginx

certbot certonly \
    --non-interactive \
    --agree-tos \
    --email "$CERTBOT_EMAIL" \
    --webroot \
    --webroot-path /var/www/certbot \
    --domain vendor.dotmac.io

install -m 0644 deploy/nginx/vendor.dotmac.io.conf "$NGINX_AVAILABLE"
nginx -t
systemctl reload nginx

if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
    install -m 0600 .env.production.example "$DEPLOY_DIR/.env"
    die "$DEPLOY_DIR/.env was created with empty secrets; materialise it before deploy"
fi
chmod 0600 "$DEPLOY_DIR/.env"

printf 'Production host contract prepared at %s.\n' "$DEPLOY_DIR"
