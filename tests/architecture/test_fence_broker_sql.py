"""Static proofs about the D16 fence's host-side termination path — no
database, no subprocess, no real coproc.

`deploy/postgres/terminate_writers.sql` and `scripts/lib/fence_broker.sh` are
CHECKED-IN artifacts, not something a deploy renders from configuration, so
every check here reads the same two files CI and an operator would and
compares them by text against `transition_fence`'s own vocabulary — never the
other way around, since that module is the one thing both files must agree
with.
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


def test_the_broker_only_ever_runs_the_one_checked_in_sql_file() -> None:
    text = _broker_text()
    assert "psql" in text
    assert '"$FENCE_TERMINATE_SQL"' in text
    assert "FENCE_TERMINATE_SQL:=deploy/postgres/terminate_writers.sql" in text
    referenced = set(re.findall(r"[\w./-]+\.sql", text))
    assert referenced <= {"deploy/postgres/terminate_writers.sql"}


def test_the_broker_checks_the_fence_id_before_running_any_sql() -> None:
    text = _broker_text()
    terminate_request_index = text.index("DOTMAC-FENCE-TERMINATE v1")
    fence_id_check_index = text.index('"$request_fence_id" != "$fence_id"')
    psql_invocation_index = text.index("psql -X")
    assert terminate_request_index < fence_id_check_index < psql_invocation_index


def test_the_broker_refuses_a_mismatched_fence_id_with_a_non_zero_return() -> None:
    text = _broker_text()
    refusal_block = text[
        text.index('"$request_fence_id" != "$fence_id"') : text.index("psql -X")
    ]
    assert "return 1" in refusal_block


def test_the_broker_passes_non_protocol_lines_to_fd_3_not_stdout() -> None:
    text = _broker_text()
    assert ">&3" in text


# ── the three commands are registered with owners ───────────────────────────


def test_the_three_fence_commands_are_registered_with_owners() -> None:
    owners = by_command()
    close = owners["admin transition-fence close"]
    holding = owners["admin transition-fence holding"]
    restore = owners["admin transition-fence restore"]

    for owner in (close, holding, restore):
        assert owner.module == "vendor_cp.deployment.fence_commands"

    assert close.symbol == "close_fence"
    assert close.mutates is True
    assert holding.symbol == "fence_holding"
    assert holding.mutates is False
    assert restore.symbol == "restore_fence"
    assert restore.mutates is True
