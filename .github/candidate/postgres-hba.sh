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
# The official entrypoint stops its temporary initialization server after this
# script and starts the final server against these bytes. Reloading here is both
# unnecessary and misleading: the temporary server has command-line-only
# listen settings that correctly refuse a SIGHUP change during initialization.
