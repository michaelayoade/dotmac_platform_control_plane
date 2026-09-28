#!/usr/bin/env bash
# scripts/lib/fence_broker.sh — the host side of the D16 fence's termination
# protocol. A SOURCED library, not a script: `source scripts/lib/fence_broker.sh`,
# never `scripts/lib/fence_broker.sh` directly. PR 4 wires it into the
# maintenance-window deploy; this file is checked in and tested statically
# only (`bash -n`, `tests/architecture/test_fence_broker_sql.py`).
#
# ── The seam this crosses ────────────────────────────────────────────────────
#
# `vendor_cp.deployment.fence_commands.StdioBrokerTerminator` (PR 2) writes
# `DOTMAC-FENCE-TERMINATE v1 <fence_id>` to ITS OWN stdout and reads a reply
# from ITS OWN stdin. `fence_broker_serve` is the OTHER end of that exact
# pipe: it reads request lines from ITS OWN stdin (which the caller wires,
# via a bash coproc, to the spawned `dotmac-platform admin transition-fence
# ...` process's stdout) and writes replies to ITS OWN stdout (wired, the
# same way, to that process's stdin). This file never spawns that process
# itself and never decides which command runs — that stays PR 4's, in
# `scripts/deploy_production.sh`, over the SAME `compose()` function already
# defined there.
#
# ── The database work is ONE fixed, checked-in statement ────────────────────
#
# On every exact `DOTMAC-FENCE-TERMINATE v1 <fence_id>` request line whose
# fence_id matches the one THIS invocation of `fence_broker_serve` was given,
# the broker runs `deploy/postgres/terminate_writers.sql` as the `postgres`
# superuser, parameterised ONLY by `$database` (never by anything read off
# the request line itself — the fence_id is checked, never interpolated into
# SQL). A request line whose fence_id does not match is refused outright
# (non-zero return), because a fence_id mismatch here is exactly the "digest
# channel" failure mode `fence_commands`'s module docstring describes: this
# broker is not the place that decides whether to trust a mismatched run.
#
# ── Everything else passes through fd 3, never fd 1 ──────────────────────────
#
# fd 1 here is wired to the spawned process's stdin — writing anything but a
# protocol reply there would feed garbage into that process's next read. Any
# line that is not a `DOTMAC-FENCE-TERMINATE` request (in particular, the
# final JSON envelope `dotmac-platform` prints once it exits) is written to
# fd 3 instead, which the caller redirects to a file or captures directly.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "fence_broker.sh must be sourced, not executed directly" >&2
    exit 1
fi

# The fixed, checked-in SQL this broker ever runs. Overridable only so a test
# can point it at a fixture without needing a real Postgres — production
# never sets this.
: "${FENCE_TERMINATE_SQL:=deploy/postgres/terminate_writers.sql}"

#: `fence_broker_serve <database> <fence_id>`
#:
#: Reads request lines from stdin until stdin closes. On an exact
#: `DOTMAC-FENCE-TERMINATE v1 <fence_id>` line matching the second argument,
#: runs the fixed termination SQL against `<database>` and writes
#: `DOTMAC-FENCE-TERMINATED v1 <fence_id>` to stdout. Any other line is
#: written to fd 3 unchanged. A request line naming a DIFFERENT fence_id is
#: refused: the function returns non-zero immediately, without running any
#: SQL and without replying, rather than silently ignoring a request it
#: cannot trust the origin of.
fence_broker_serve() {
    local database="$1"
    local fence_id="$2"
    local line request_fence_id

    if [[ -z "$database" || -z "$fence_id" ]]; then
        echo "fence_broker_serve: both <database> and <fence_id> are required" >&2
        return 1
    fi

    while IFS= read -r line; do
        if [[ "$line" == "DOTMAC-FENCE-TERMINATE v1 "* ]]; then
            request_fence_id="${line#DOTMAC-FENCE-TERMINATE v1 }"
            if [[ "$request_fence_id" != "$fence_id" ]]; then
                echo "fence_broker_serve: refusing termination request for" \
                    "fence_id '$request_fence_id'; this broker is serving" \
                    "'$fence_id'" >&2
                return 1
            fi
            compose exec -T --user postgres db \
                psql -X -v ON_ERROR_STOP=1 -v "db=$database" \
                < "$FENCE_TERMINATE_SQL"
            printf 'DOTMAC-FENCE-TERMINATED v1 %s\n' "$fence_id"
        else
            printf '%s\n' "$line" >&3
        fi
    done
}
