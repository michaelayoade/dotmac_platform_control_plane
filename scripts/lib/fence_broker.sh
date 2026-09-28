#!/usr/bin/env bash
# scripts/lib/fence_broker.sh — the host side of the D16 fence's termination
# protocol. A SOURCED library, not a script: `source scripts/lib/fence_broker.sh`,
# never `scripts/lib/fence_broker.sh` directly. PR 4 wires it into the
# maintenance-window deploy; this file is checked in and tested statically
# (`bash -n`, `tests/architecture/test_fence_broker_sql.py`) plus, against a
# real cluster, `tests/migration/test_fence_broker_script.py`.
#
# ── The seam this crosses ────────────────────────────────────────────────────
#
# `vendor_cp.deployment.fence_commands.StdioBrokerTerminator` (PR 2) writes
# `DOTMAC-FENCE-TERMINATE v1 <fence_id>` to ITS OWN stdout and reads a reply
# from ITS OWN stdin. `fence_broker_serve` is the OTHER end of that exact
# pipe: it reads request lines from ITS OWN stdin (which the caller wires,
# via a bash coproc, to the spawned `dotmac-platform admin transition-fence-*`
# process's stdout) and writes replies to ITS OWN stdout (wired, the same
# way, to that process's stdin). This file never spawns that process itself
# and never decides which command runs — that stays PR 4's, in
# `scripts/deploy_production.sh`, over the SAME `compose()` function already
# defined there.
#
# **The caller MUST wire fd 3 before calling `fence_broker_serve`** — see
# "Everything else passes through fd 3" below — and, if this function
# `return`s 1, MUST assume the ops process may still be blocked inside its
# own `readline()` waiting for a reply that will never come (a refused
# fence_id, a missing SQL file, or a failed/timed-out termination all return
# without replying) and kill that coprocess rather than leaving it hung.
#
# ── The database work is ONE fixed, checked-in statement ────────────────────
#
# On every exact `DOTMAC-FENCE-TERMINATE v1 <fence_id>` request line whose
# fence_id matches the one THIS invocation of `fence_broker_serve` was given
# (validated first against `^[A-Za-z0-9._-]{1,128}$`, the identical pattern
# `fence_commands` enforces on the Python side), the broker runs
# `deploy/postgres/terminate_writers.sql` — resolved ONLY relative to this
# file's own location (`${BASH_SOURCE[0]}`), canonicalised, never from an
# environment override — as the `postgres` superuser, parameterised ONLY by
# `$database` (never by anything read off the request line itself — the
# fence_id is checked, never interpolated into SQL).
#
# ── Bounded, checked, and silent-by-default on success ─────────────────────
#
# The `compose exec` that runs `psql` is wrapped in `timeout
# FENCE_BROKER_TIMEOUT_SECONDS`: a termination attempt that never returns
# must not hang this broker (and, transitively, the maintenance window)
# forever. `psql` itself runs `-q -t -A` and its stdout is discarded
# (`> /dev/null`) — NEVER left attached to fd 1, which here is the ops
# process's stdin: a `psql` NOTICE, a column header, or a query result row
# reaching fd 1 would be fed into that process's next `readline()` as if it
# were this protocol's reply, corrupting the channel. `$?` is captured and
# checked explicitly, right after the command, rather than relied on via
# `set -e` — this function can be invoked from an `a || b` construct, where
# errexit is off for the duration of `a`, so an inherited `set -e` cannot be
# assumed to catch a failure here. A non-zero status (an ordinary `psql`
# failure, or a `timeout`-induced 124) means NO reply is ever sent, and the
# function returns 1 without touching the ops process's stdin at all.
#
# ── Everything else passes through fd 3, never fd 1 ──────────────────────────
#
# fd 1 here is wired to the spawned process's stdin — writing anything but a
# protocol reply there would feed garbage into that process's next read. Any
# line that is not a `DOTMAC-FENCE-TERMINATE` request (in particular, the
# final JSON envelope `dotmac-platform` prints once it exits) is written to
# fd 3 instead, which the caller redirects to a file or captures directly.
# `fence_broker_serve` checks fd 3 is actually open BEFORE reading any
# request line, and refuses loudly (`return 1`) rather than silently
# dropping every non-protocol line it would otherwise have written there.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "fence_broker.sh must be sourced, not executed directly" >&2
    exit 1
fi

# A fixed constant, not an environment override: the whole point of bounding
# a single termination attempt is that nothing at runtime can widen it.
FENCE_BROKER_TIMEOUT_SECONDS=30

#: `^[A-Za-z0-9._-]{1,128}$` — identical to
#: `vendor_cp.deployment.fence_commands._FENCE_ID_PATTERN` on the Python
#: side. A broker that skipped this check would trust an unvalidated string
#: straight into a shell comparison and a SQL bind parameter's context.
_fence_broker_valid_fence_id() {
    [[ "$1" =~ ^[A-Za-z0-9._-]{1,128}$ ]]
}

# The checked-in SQL file, resolved ONLY relative to this file's own
# location and canonicalised (`cd ... && pwd`, never a string concatenation
# that could carry a `..` or a symlink unresolved) — never an environment
# override, which would let something other than this checked-in path decide
# what gets executed as the `postgres` superuser.
_fence_broker_sql_path() {
    local script_dir sql_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || return 1
    sql_dir="$(cd "$script_dir/../../deploy/postgres" && pwd)" || return 1
    printf '%s/terminate_writers.sql' "$sql_dir"
}

#: `fence_broker_serve <database> <fence_id>`
#:
#: Reads request lines from stdin until stdin closes. On an exact
#: `DOTMAC-FENCE-TERMINATE v1 <fence_id>` line matching the second argument,
#: runs the fixed termination SQL against `<database>`, bounded by
#: `FENCE_BROKER_TIMEOUT_SECONDS`, and writes `DOTMAC-FENCE-TERMINATED v1
#: <fence_id>` to stdout ONLY on success. Any other line is written to fd 3
#: unchanged. A request line naming a DIFFERENT fence_id, an invalid
#: fence_id, a missing SQL file, or a failed/timed-out termination all
#: `return 1` WITHOUT replying — the caller must not treat silence as
#: success and must be prepared to kill the coprocess it spawned.
fence_broker_serve() {
    local database="$1"
    local fence_id="$2"
    local line request_fence_id sql_path status

    if [[ -z "$database" || -z "$fence_id" ]]; then
        echo "fence_broker_serve: both <database> and <fence_id> are required" >&2
        return 1
    fi
    if ! _fence_broker_valid_fence_id "$fence_id"; then
        echo "fence_broker_serve: fence_id '$fence_id' does not match" \
            "^[A-Za-z0-9._-]{1,128}\$" >&2
        return 1
    fi
    if ! { : >&3; } 2>/dev/null; then
        echo "fence_broker_serve: fd 3 is not open; the caller must redirect" \
            "it (e.g. \`fence_broker_serve ... 3>envelope.txt\`) before any" \
            "non-protocol line can be captured" >&2
        return 1
    fi
    sql_path="$(_fence_broker_sql_path)" || {
        echo "fence_broker_serve: cannot resolve deploy/postgres/terminate_writers.sql" >&2
        return 1
    }
    if [[ ! -f "$sql_path" ]]; then
        echo "fence_broker_serve: $sql_path does not exist" >&2
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
            timeout "$FENCE_BROKER_TIMEOUT_SECONDS" \
                compose exec -T --user postgres db \
                psql -X -v ON_ERROR_STOP=1 --username postgres -q -t -A \
                -v "db=$database" \
                < "$sql_path" \
                > /dev/null
            status=$?
            if [[ $status -ne 0 ]]; then
                echo "fence_broker_serve: termination command for fence_id" \
                    "'$fence_id' failed or timed out (exit $status); not" \
                    "replying" >&2
                return 1
            fi
            printf 'DOTMAC-FENCE-TERMINATED v1 %s\n' "$fence_id"
        else
            printf '%s\n' "$line" >&3
        fi
    done
}
