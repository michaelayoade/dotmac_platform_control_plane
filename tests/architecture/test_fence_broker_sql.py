"""Static proofs about the D16 fence's host-side termination path — no
database, no subprocess, no real coproc.

`deploy/postgres/terminate_writers.sql` and `scripts/lib/fence_broker.sh` are
CHECKED-IN artifacts, not something a deploy renders from configuration, so
every check here reads the same two files CI and an operator would and
compares them by text against `transition_fence`'s own vocabulary — never the
other way around, since that module is the one thing both files must agree
with. `tests/migration/test_fence_broker_script.py` proves the broker's
actual behaviour against a real cluster; this file proves its checked-in
SHAPE without one.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

from vendor_cp.cli.owners import by_command
from vendor_cp.deployment.transition_fence import MIGRATION_ROLE, WRITER_ROLES

ROOT = Path(__file__).resolve().parents[2]
SQL_PATH = ROOT / "deploy" / "postgres" / "terminate_writers.sql"
BROKER_PATH = ROOT / "scripts" / "lib" / "fence_broker.sh"


def _sql_text() -> str:
    return SQL_PATH.read_text(encoding="utf-8")


def _broker_text() -> str:
    return BROKER_PATH.read_text(encoding="utf-8")


def _broker_function_body() -> str:
    """Just `fence_broker_serve`'s own body — isolates checks that must be
    anchored on CODE from the header comment, which uses the same words."""
    text = _broker_text()
    start = text.index("fence_broker_serve() {")
    return text[start:]


# ── the SQL ───────────────────────────────────────────────────────────────


def test_the_writer_list_is_exactly_writer_roles() -> None:
    """A literal role array, compared as a set against the live tuple — a
    future addition/removal from `WRITER_ROLES` must edit this file in the
    same change, never drift from it silently."""
    text = _sql_text()
    match = re.search(r"ANY\(ARRAY\[(.*?)\]\)", text, re.DOTALL)
    assert match is not None, "no literal writer-role array found in the SQL"
    listed = {
        entry.strip().strip("'") for entry in match.group(1).split(",") if entry.strip()
    }
    assert listed == set(WRITER_ROLES)


def test_the_sql_scopes_by_db_and_never_its_own_backend() -> None:
    text = _sql_text()
    assert ":'db'" in text
    assert "pg_backend_pid()" in text


def test_the_sql_excludes_the_migration_role() -> None:
    text = _sql_text()
    assert f"<> '{MIGRATION_ROLE}'" in text


def test_the_sql_uses_the_same_recursive_membership_walk_shape() -> None:
    """The identical CTE shape `transition_fence._MEMBER_ROLES_QUERY` uses:
    a recursive walk over `pg_auth_members` joined on `roleid = m.oid`."""
    text = _sql_text()
    assert "WITH RECURSIVE" in text
    assert "pg_auth_members" in text
    assert "am.roleid = m.oid" in text


def test_the_sql_excludes_superusers() -> None:
    text = _sql_text()
    assert "NOT r.rolsuper" in text


def test_the_sql_excludes_members_of_app_admin() -> None:
    text = _sql_text()
    assert "pg_has_role(r.oid, 'app_admin', 'member')" in text


def test_the_sql_excludes_members_of_the_database_owner() -> None:
    text = _sql_text()
    assert "SELECT datdba FROM pg_database WHERE datname = :'db'" in text
    # The owner subquery must feed a `pg_has_role(..., 'member')` check, not
    # merely appear somewhere unrelated in the file.
    owner_check = re.search(
        r"pg_has_role\(\s*r\.oid,\s*\(SELECT datdba FROM pg_database WHERE"
        r" datname = :'db'\),\s*'member'\s*\)",
        text,
    )
    assert owner_check is not None


def test_the_sql_has_a_server_side_statement_timeout() -> None:
    text = _sql_text()
    assert "SET statement_timeout = '20s';" in text


def test_the_sql_is_exactly_two_statements() -> None:
    """`psql` runs every statement in the file in sequence; a SQLAlchemy
    caller driving the checked-in text through a single parameterised
    `execute` cannot (`psycopg.errors.SyntaxError: cannot insert multiple
    commands into a prepared statement`), so both
    `tests/migration/test_fence_commands.py`'s `_InProcessHostBroker` and its
    standalone SQL test split the file into statements and run each
    separately. That split assumes exactly two: the `SET statement_timeout`,
    then the terminate query — asserted here, independently, so the helper's
    assumption cannot drift from the checked-in file silently."""
    without_comments = "\n".join(
        line for line in _sql_text().splitlines() if not line.strip().startswith("--")
    )
    statements = [s.strip() for s in without_comments.split(";") if s.strip()]
    assert len(statements) == 2, statements
    assert statements[0].startswith("SET statement_timeout")
    assert statements[1].startswith("WITH RECURSIVE")


def test_the_sql_names_no_psql_variable_other_than_db() -> None:
    """A psql bind is `:name` or `:'name'`. `::` type casts are not a bind and
    must not be mistaken for one — this SQL has none, so the check stays
    simple, but it is written to survive one being added."""
    text = _sql_text()
    quoted = set(re.findall(r":'([A-Za-z_][A-Za-z0-9_]*)'", text))
    bare = set(re.findall(r"(?<!:):(?!')([A-Za-z_][A-Za-z0-9_]*)", text))
    assert quoted | bare == {"db"}


# ── the broker script ────────────────────────────────────────────────────


def test_the_broker_is_a_sourced_library_not_an_executable() -> None:
    text = _broker_text()
    assert "must be sourced" in text
    mode = BROKER_PATH.stat().st_mode
    assert not (mode & stat.S_IXUSR), "fence_broker.sh must not be executable"


def test_the_broker_has_no_environment_sql_override() -> None:
    """The SQL path is resolved ONLY from this file's own location —
    `FENCE_TERMINATE_SQL` (a prior, since-removed environment override) must
    never reappear."""
    text = _broker_text()
    assert "FENCE_TERMINATE_SQL" not in text


def test_the_broker_resolves_the_sql_path_only_from_its_own_location() -> None:
    body = _broker_function_body()
    assert "BASH_SOURCE[0]" in _broker_text()
    assert "_fence_broker_sql_path" in body
    # `fence_broker_serve` itself never spells the path as a literal — it
    # calls `_fence_broker_sql_path`, which builds it from `${BASH_SOURCE[0]}`.
    assert "cd " not in body, "path resolution belongs in _fence_broker_sql_path"


def test_the_broker_only_ever_names_the_one_sql_file() -> None:
    """A basename-only scan: the file legitimately builds the full path from
    shell variables (`$sql_dir/terminate_writers.sql`), which a regex over
    the whole path would mis-tokenise at the `$` — the basename is the part
    that must never vary."""
    names = set(re.findall(r"([A-Za-z0-9_-]+\.sql)", _broker_text()))
    assert names == {"terminate_writers.sql"}


def test_the_broker_refuses_a_missing_sql_file() -> None:
    body = _broker_function_body()
    assert '[[ ! -f "$sql_path" ]]' in body
    return_index = body.index('[[ ! -f "$sql_path" ]]')
    following = body[return_index : return_index + 200]
    assert "return 1" in following


def test_the_broker_redirects_psqls_own_stdout_away_from_fd_1() -> None:
    """`psql` runs quiet/tuples-only/unaligned and its stdout is discarded —
    fd 1 here is the ops process's stdin, and a NOTICE or a result row
    reaching it would corrupt the next protocol reply it reads."""
    body = _broker_function_body()
    assert "-q -t -A" in body
    assert "> /dev/null" in body
    # The redirect must apply to the SAME psql invocation, not merely be
    # present somewhere else in the function.
    psql_index = body.index("psql -X")
    devnull_index = body.index("> /dev/null")
    assert psql_index < devnull_index < psql_index + 400


def test_the_broker_checks_the_exit_status_before_replying() -> None:
    """`$?` captured explicitly (never relied on via `set -e`, since the
    function may be called from a `||` where errexit is off), checked, and
    ONLY on success does the reply `printf` run."""
    body = _broker_function_body()
    status_capture_index = body.index("status=$?")
    status_check_index = body.index("$status -ne 0")
    reply_index = body.index("printf 'DOTMAC-FENCE-TERMINATED")
    assert status_capture_index < status_check_index < reply_index
    # The failure branch must return before the reply, without falling
    # through to it.
    failure_branch = body[status_check_index:reply_index]
    assert "return 1" in failure_branch


def test_the_broker_never_runs_timeout_directly_against_compose() -> None:
    """`timeout` execs a named program; `compose` is a bash FUNCTION in both
    production and the test shim, so `timeout N compose ...` exits 127 on
    every call without terminating anything — this file shipped exactly that
    defect once. `compose` must always be the FIRST word of the pipeline."""
    body = _broker_function_body()
    broken_form = re.search(
        r'timeout\s+"\$FENCE_BROKER_TIMEOUT_SECONDS"\s+compose', body
    )
    assert broken_form is None
    assert re.search(r"^\s*compose exec", body, re.MULTILINE) is not None


def test_the_broker_bounds_psql_inside_the_container_as_defence_in_depth() -> None:
    """`compose exec ... timeout N psql ...` — `timeout` there execs a real
    program (`psql`), which DOES work, unlike wrapping the outer `compose`
    call. This runs INSIDE the watchdog-backgrounded job, not instead of it."""
    body = _broker_function_body()
    compose_index = body.index("compose exec")
    timeout_index = body.index('timeout "$FENCE_BROKER_PSQL_TIMEOUT_SECONDS"')
    psql_index = body.index("psql -X")
    assert compose_index < timeout_index < psql_index < compose_index + 300


def test_the_broker_runs_the_termination_command_under_a_watchdog() -> None:
    """A backgrounded job, a backgrounded sleep-then-`kill -TERM` watchdog,
    and `wait` used as an `if` CONDITION — which never triggers an inherited
    `set -e`, unlike a bare `wait` whose own non-zero status would."""
    body = _broker_function_body()
    assert "FENCE_BROKER_TIMEOUT_SECONDS" in _broker_text()
    # A fixed constant, not an environment-overridable default (no `:-`/`:=`
    # against it).
    assert re.search(
        r"^FENCE_BROKER_TIMEOUT_SECONDS=\d+\s*$", _broker_text(), re.MULTILINE
    )
    job_index = body.index("job=$!")
    watchdog_spawn_index = body.index("kill -TERM")
    watchdog_pid_index = body.index("watchdog=$!")
    wait_if_index = body.index('if wait "$job"')
    status_check_index = body.index("$status -ne 0")
    assert (
        job_index
        < watchdog_spawn_index
        < watchdog_pid_index
        < wait_if_index
        < status_check_index
    )
    # The status check follows the `if wait ...` block closely — no second
    # command invocation (another `compose`/`psql` call) sits between the
    # `wait` and the check that could itself fail and abort under `set -e`
    # before `status` is ever read.
    between = body[wait_if_index:status_check_index]
    assert "compose exec" not in between
    assert "psql -X" not in between


def test_the_broker_checks_the_fence_id_pattern_before_serving() -> None:
    text = _broker_text()
    assert "_fence_broker_valid_fence_id" in text
    assert "^[A-Za-z0-9._-]{1,128}$" in text
    body = _broker_function_body()
    validate_index = body.index("_fence_broker_valid_fence_id")
    loop_index = body.index("while IFS=")
    assert validate_index < loop_index


def test_the_broker_checks_the_request_fence_id_before_running_any_sql() -> None:
    body = _broker_function_body()
    terminate_request_index = body.index("DOTMAC-FENCE-TERMINATE v1")
    fence_id_check_index = body.index('"$request_fence_id" != "$fence_id"')
    psql_invocation_index = body.index("psql -X")
    assert terminate_request_index < fence_id_check_index < psql_invocation_index


def test_the_broker_refuses_a_mismatched_fence_id_with_a_non_zero_return() -> None:
    body = _broker_function_body()
    refusal_block = body[
        body.index('"$request_fence_id" != "$fence_id"') : body.index("psql -X")
    ]
    assert "return 1" in refusal_block


def test_the_broker_checks_fd_3_is_open_before_serving() -> None:
    body = _broker_function_body()
    assert ": >&3" in body
    fd3_check_index = body.index(": >&3")
    loop_index = body.index("while IFS=")
    assert fd3_check_index < loop_index


def test_the_broker_passes_non_protocol_lines_to_fd_3_not_stdout() -> None:
    text = _broker_text()
    assert ">&3" in text


# ── the three commands are registered with owners ───────────────────────────


def test_the_three_fence_commands_are_registered_with_owners() -> None:
    owners = by_command()
    close = owners["admin transition-fence-close"]
    holding = owners["admin transition-fence-holding"]
    restore = owners["admin transition-fence-restore"]

    for owner in (close, holding, restore):
        assert owner.module == "vendor_cp.deployment.fence_commands"

    assert close.symbol == "close_fence"
    assert close.mutates is True
    assert holding.symbol == "fence_holding"
    assert holding.mutates is False
    assert restore.symbol == "restore_fence"
    assert restore.mutates is True


def test_the_watchdog_holds_none_of_the_callers_descriptors() -> None:
    """A surviving watchdog `sleep` must not keep the reply pipe (fd 1), stderr
    or the envelope descriptor (fd 3) open after the broker has answered, or
    anything waiting for end-of-file on them stalls. Sensitivity: dropping the
    subshell's redirections fails this test."""
    body = _broker_function_body()
    assert ") </dev/null >/dev/null 2>/dev/null 3>&- &" in body


def test_the_in_container_timeout_is_shorter_than_the_watchdog() -> None:
    """The in-container bound fires first; the watchdog is only a backstop.
    Sensitivity: equal or inverted constants fail this test."""
    text = _broker_text()
    outer = int(
        re.search(r"^FENCE_BROKER_TIMEOUT_SECONDS=(\d+)\s*$", text, re.MULTILINE).group(
            1
        )
    )
    inner = int(
        re.search(
            r"^FENCE_BROKER_PSQL_TIMEOUT_SECONDS=(\d+)\s*$", text, re.MULTILINE
        ).group(1)
    )
    assert inner < outer
