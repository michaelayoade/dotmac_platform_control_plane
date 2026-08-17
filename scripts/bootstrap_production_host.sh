#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_HOST_ID="vendor-cp-prod"
readonly PRODUCTION_DOMAIN="vendor.dotmac.io"
readonly DEPLOY_DIR="${DEPLOY_DIR:-/opt/dotmac/vendor-control-plane}"
readonly BACKUP_DIR="${BACKUP_DIR:-/opt/backups/dotmac-vendor-control-plane}"
readonly KEY_FILE="/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
readonly KEY_DIR="${KEY_FILE%/*}"
readonly NGINX_AVAILABLE="/etc/nginx/sites-available/vendor.dotmac.io"
readonly NGINX_ENABLED="/etc/nginx/sites-enabled/vendor.dotmac.io"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

CERTBOT_ACCOUNT_MODE=""
readonly REQUIRED_ENV_KEYS=(
    VENDOR_DB_ADMIN_PASSWORD
    VENDOR_DB_APP_USER_PASSWORD
    VENDOR_DB_PLATFORM_API_PASSWORD
    JWT_SECRET
    SESSION_HASH_SECRET
    VENDOR_LICENCE_SIGNING_KEY_ID
)

resolve_certbot_registration() {
    if [[ -n "${CERTBOT_EMAIL:-}" ]]; then
        CERTBOT_ACCOUNT_MODE="explicit-email"
        return
    fi
    certbot show_account --non-interactive >/dev/null 2>&1 \
        || die "CERTBOT_EMAIL is required when no Certbot account exists"
    CERTBOT_ACCOUNT_MODE="existing-account"
}

certbot_certonly() {
    certbot certonly \
        --non-interactive \
        --agree-tos \
        "$@" \
        --webroot \
        --webroot-path /var/www/certbot \
        --domain "$PRODUCTION_DOMAIN"
}

issue_production_certificate() {
    case "$CERTBOT_ACCOUNT_MODE" in
        existing-account)
            certbot_certonly
            ;;
        explicit-email)
            certbot_certonly --email "$CERTBOT_EMAIL"
            ;;
        *)
            die "Certbot registration mode was not resolved"
            ;;
    esac
}

validate_materialized_env() {
    [[ $# -eq 1 ]] || die "validate_materialized_env requires one path"
    local env_file="$1"
    local key
    local count
    local declaration
    [[ -f "$env_file" && ! -L "$env_file" ]] \
        || die "host environment is not a regular file"
    for key in "${REQUIRED_ENV_KEYS[@]}"; do
        count="$(grep -Ec "^${key}=" "$env_file" || true)"
        declaration="$(grep -E "^${key}=" "$env_file" || true)"
        [[ "$count" -eq 1 && "$declaration" != "${key}=" ]] \
            || die "host environment declaration is missing, empty, or duplicated"
    done
}

main() {
    [[ "${EUID}" -eq 0 ]] || die "run as root on the explicitly named host"

    for command in docker nginx certbot openssl rsync; do
        command -v "$command" >/dev/null || die "$command is not installed"
    done
    docker compose version >/dev/null
    resolve_certbot_registration

    if [[ -e /etc/dotmac-host-id || -L /etc/dotmac-host-id ]]; then
        [[ -f /etc/dotmac-host-id && ! -L /etc/dotmac-host-id ]] \
            || die "existing host identity is not a regular file"
        [[ "$(tr -d '\r\n' < /etc/dotmac-host-id)" == "$EXPECTED_HOST_ID" ]] \
            || die "existing host identity is not $EXPECTED_HOST_ID"
    fi

    install -d -m 0750 "$DEPLOY_DIR" "$BACKUP_DIR"
    install -d -m 0700 -o 10001 -g 10001 "$KEY_DIR"
    [[ -s "$KEY_FILE" ]] \
        || die "$KEY_FILE must be materialised from OpenBao path secret/dotmac/licensing/signing-key before bootstrap"
    chown 10001:10001 "$KEY_FILE"
    chmod 0600 "$KEY_FILE"

    install -d -m 0755 /var/www/certbot
    install -m 0644 deploy/nginx/vendor.dotmac.io.bootstrap.conf "$NGINX_AVAILABLE"
    ln -sfn "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    nginx -t
    systemctl reload nginx

    issue_production_certificate

    readonly CERTIFICATE="/etc/letsencrypt/live/$PRODUCTION_DOMAIN/fullchain.pem"
    readonly PRIVATE_KEY="/etc/letsencrypt/live/$PRODUCTION_DOMAIN/privkey.pem"
    [[ -s "$CERTIFICATE" && -s "$PRIVATE_KEY" ]] \
        || die "Certbot did not materialise the production certificate"
    openssl x509 -checkhost "$PRODUCTION_DOMAIN" -noout -in "$CERTIFICATE" \
        >/dev/null || die "production certificate does not cover $PRODUCTION_DOMAIN"
    openssl x509 -checkend 2592000 -noout -in "$CERTIFICATE" >/dev/null \
        || die "production certificate expires within 30 days"

    install -m 0644 deploy/nginx/vendor.dotmac.io.conf "$NGINX_AVAILABLE"
    nginx -t
    systemctl reload nginx

    if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
        install -m 0600 .env.production.example "$DEPLOY_DIR/.env"
        die "$DEPLOY_DIR/.env was created with empty secrets; materialise it before deploy"
    fi
    chmod 0600 "$DEPLOY_DIR/.env"
    validate_materialized_env "$DEPLOY_DIR/.env"

    # This marker attests the complete one-time host contract, so it is the
    # last mutation. A failed Certbot, nginx, key, or env step must never leave
    # a deployable-looking host behind.
    HOST_ID_TMP="$(mktemp /etc/.dotmac-host-id.XXXXXX)"
    readonly HOST_ID_TMP
    trap 'rm -f -- "$HOST_ID_TMP"' EXIT HUP INT TERM
    printf '%s\n' "$EXPECTED_HOST_ID" > "$HOST_ID_TMP"
    chmod 0644 "$HOST_ID_TMP"
    mv "$HOST_ID_TMP" /etc/dotmac-host-id
    trap - EXIT HUP INT TERM

    printf 'Production host contract prepared at %s.\n' "$DEPLOY_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
