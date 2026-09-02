#!/usr/bin/env bash
# Candidate-only reproduction of the production HBA ordering: container-local
# TCP is trusted first, while every non-loopback host path requires SCRAM.
set -euo pipefail

: "${PGDATA:?PGDATA is required}"
temporary="$(mktemp "${PGDATA}/pg_hba.conf.candidate.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
{
    printf '%s\n' \
        'host all all 127.0.0.1/32 trust' \
        'host all all ::1/128 trust'
    cat "${PGDATA}/pg_hba.conf"
} >"$temporary"
chmod --reference="${PGDATA}/pg_hba.conf" "$temporary"
mv -f -- "$temporary" "${PGDATA}/pg_hba.conf"
psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" --command 'SELECT pg_reload_conf();' >/dev/null
