"""Read-only integrity check of the Lane 3 store's code and triggers (CP-5, E10a).

The store's safety lives in its function bodies and in six tables' triggers: a
`SECURITY DEFINER` function whose body was edited, or an append-only trigger that
was disabled, defeats every guarantee while every privilege check still passes.
So this pins, from the migration as written:

* the sha256 of `pg_get_functiondef` for EVERY function in `cp_lane3` (the
  definition covers the argument list, language, `SECURITY DEFINER`, the pinned
  `search_path`, volatility and the body), including `store_now()`, which must be
  exactly `clock_timestamp()`;
* every non-internal trigger: its table, its enable state (`O`, enabled), and the
  sha256 of `pg_get_triggerdef`.

The set must match exactly: a function or trigger that is extra, missing, changed
or not enabled is a violation. CI runs it on the migrated schema, and the E10a
read-back runs it on production:

    LANE3_STORE_CHECK_DATABASE_URL=... \\
        python -m vendor_cp.deployment.lane3_store_integrity

Exit 0 only when there is no violation; 2 on any violation; it prints names only.
Re-pin by running the migration on a scratch database and reading the catalogue:
a change to a pinned digest is a reviewed diff, never an incidental one.
"""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from sqlalchemy import text

__all__ = [
    "ADMIN_DSN_ENV",
    "FUNCTION_DEFINITION_SHA256",
    "TRIGGERS",
    "check_store_integrity",
    "main",
]

ADMIN_DSN_ENV: Final = "LANE3_STORE_CHECK_DATABASE_URL"

# BEGIN PINS (generated from v023_lane3_store; see the module docstring)
FUNCTION_DEFINITION_SHA256: Final[Mapping[str, str]] = {
    "acquire(text, text, text, text, integer, jsonb, text, jsonb)": (
        "757adc53fd1b8bce11344bf3785ec088ca135923bcefa4d229f6fadee5a14897"
    ),
    "bind_document(uuid, bytea, text)": (
        "2065883d75011a25eb3f3d52ccd833019904fefd8998daac0c3c0d2a8d7c8ec0"
    ),
    "covers(uuid, text)": (
        "3fed9fe44a9e213daae67f0386fb43f76d225de5cd8cac6ef58c9ee2db228816"
    ),
    "database_time()": (
        "b8d0ac406814b6fb6abcb00735df53053410039427b58762888d0a339b57e890"
    ),
    "e10_receipt(text, text, text)": (
        "5cf773980593744b129aaf12342b2fd3cb4ee5562cc82ff5c9d8caab00f6c48b"
    ),
    "forbid_current_lease_removal()": (
        "73eccfc8e980c2c637797a3e9f0c2c7a75373210eae64ee7b3deff11d63ce86c"
    ),
    "guard_current_lease_update()": (
        "c8a53ab366b5558c1d370d91d45479eea8008bde9628b10a50da5856469db18a"
    ),
    "guard_lease_update()": (
        "21e76d5bab6d702c5ff23cb5703f7b9e0d4a257f4d035f1ac7388c00e8cc6eda"
    ),
    "release(uuid, bytea, text, text, text, text, timestamp with time zone, boolean)": (
        "f0ddab36995fe7cd328a150ce853cb4160604e663c5c8039cc373a8b76a25f84"
    ),
    "released_at(text)": (
        "ac1f2cfe4452ee9a91290ee0780711b6bddbc513c61570f8cde00ccb883faa35"
    ),
    "require_any_binding()": (
        "4f051b19227aef1c8dea51411271525820aa69809b547400beda4e5f47374539"
    ),
    "require_binding(text, text)": (
        "316870b91a38545d045ccff119042c3514eb5e0116b1817371689b716ec34587"
    ),
    "require_host_binding(text)": (
        "cd93c872e1796edc02c92609c6ebb4b6b68ebae148d23fc73b6f6cc31cd076c2"
    ),
    "stamp_binding_time()": (
        "588b6e5c6d521660fa8cb30359d2a46464af9820f9ec73f5a186babffd948da5"
    ),
    "stamp_destruction_time()": (
        "23d2bf6962ff96dee14360819b7bb59538acaff0efc43fddac8f2b95fb91e6b8"
    ),
    "stamp_receipt_time()": (
        "f357638e31a1601389dae18c1853e985778a5e539e28aed49fe4583cf828ba55"
    ),
    "stamp_release_time()": (
        "83a1450d104a389e72ad57d815b6bca7bc7278795c9f50ab8c5bf0cdfe9a5af0"
    ),
    "standing(text)": (
        "ea6bbe5145d12fb4aa78dc41fad93696934b189b25a483ea5d6c4f0b7e0fe302"
    ),
    "store_now()": ("a24607462886a8a2aece5779354304e2f786ae706db0e9c8d1831eb4b82f9cc6"),
}

#: `trigger name -> (table, enable state, sha256 of pg_get_triggerdef)`.
TRIGGERS: Final[Mapping[str, tuple[str, str, str]]] = {
    "trg_e10_destructions_append_only": (
        "e10_destructions",
        "O",
        "417536e63a7c8f5905950c3d1f8dd9835fda8006c648474ea35e592542c5d43e",
    ),
    "trg_e10_destructions_append_only_truncate": (
        "e10_destructions",
        "O",
        "03613ac0b6292b16f7c26ef893c5d725ecdbb3919f0ffb59e3909cec55e0ec7c",
    ),
    "trg_e10_destructions_stamp": (
        "e10_destructions",
        "O",
        "eca80d78f3da763f5615b2f2add571e018f1d22e518e6ea830c500791810d0b5",
    ),
    "trg_e10_receipts_append_only": (
        "e10_receipts",
        "O",
        "3935cec713d58b8852823a054046f69397fb92d6573eb0dc43ce49f5f3fb68b7",
    ),
    "trg_e10_receipts_append_only_truncate": (
        "e10_receipts",
        "O",
        "e13c557e942b3e247b2dabe9d8b5916cb4fd3c2d0b43f9ff0b499988f15ed7a5",
    ),
    "trg_e10_receipts_stamp": (
        "e10_receipts",
        "O",
        "f9dfa8b72ccf4c0c47fcb4e6c1539338e7beefd0cce13caddc3ef6041464f4ea",
    ),
    "trg_host_current_lease_delete": (
        "host_current_lease",
        "O",
        "042125c16bfe0e10ef4f3787c3bafac28db24ac5d04ed0bc7b0d4f6c3e0eab44",
    ),
    "trg_host_current_lease_truncate": (
        "host_current_lease",
        "O",
        "bebc9bc0cd6be74e1888433b3e08b9b994369521e198785b3a3924d14255f067",
    ),
    "trg_host_current_lease_update": (
        "host_current_lease",
        "O",
        "40118efd6b7ef1852dff944f0d43a2954b6a60248b74406cc5bf803a44b9d466",
    ),
    "trg_host_lease_releases_append_only": (
        "host_lease_releases",
        "O",
        "a07205bf1aecde719dd3fca842e014167f51a703047dc91e35afca7ea62d304e",
    ),
    "trg_host_lease_releases_append_only_truncate": (
        "host_lease_releases",
        "O",
        "cdfdeec99f5affe8dcb41beaaa8f96e2d3bbc850ee7e91caa8377c7985b59289",
    ),
    "trg_host_lease_releases_stamp": (
        "host_lease_releases",
        "O",
        "021d7d797bf4e03e77d669e7e542fb8498f36c0879afc5e9f25a5427a05c5624",
    ),
    "trg_host_leases_delete": (
        "host_leases",
        "O",
        "c113b7967d262e01dcd6ab4c9d45301e440d5e47f3634d1eb1ba5e147fdd2da5",
    ),
    "trg_host_leases_truncate": (
        "host_leases",
        "O",
        "47e7e2bf909d080fc1d2a737e59fa4fa48a9429bd7512cc21a235e43f6e684b6",
    ),
    "trg_host_leases_update": (
        "host_leases",
        "O",
        "3d221c48658071db26d86b0043df23defe9c0ad98c03a73db5c6c7b4a285d06c",
    ),
    "trg_run_bindings_append_only": (
        "run_bindings",
        "O",
        "7d1a24660b8501affc414ce94908bee81df0ff45da498d4176d17d1aa0741ba2",
    ),
    "trg_run_bindings_append_only_truncate": (
        "run_bindings",
        "O",
        "fcca070a1c71bfaf8b8d704f79b97b00e0dacb733a1c69d377c67b335ea032c1",
    ),
    "trg_run_bindings_stamp": (
        "run_bindings",
        "O",
        "443acd3c64ba55898921dce4266c179b657b49c89732ea8f464cdba63df56589",
    ),
}
# END PINS

_FUNCTIONS_SQL: Final = (
    "SELECT p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')', "
    "pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_TRIGGERS_SQL: Final = (
    "SELECT t.tgname, c.relname, t.tgenabled::text, "
    "pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t "
    "JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3' AND NOT t.tgisinternal"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def check_store_integrity(
    execute: Callable[[str], Any],
    *,
    functions: Mapping[str, str] | None = None,
    triggers: Mapping[str, tuple[str, str, str]] | None = None,
) -> tuple[str, ...]:
    """The violations, sorted; empty means the store is exactly as pinned.

    `execute(sql)` returns the rows of a read-only query. The pins default to this
    module's, and are parameters so a test can show the check refuses.
    """
    expected_functions = FUNCTION_DEFINITION_SHA256 if functions is None else functions
    expected_triggers = TRIGGERS if triggers is None else triggers
    violations: list[str] = []

    found_functions = {
        str(row[0]): _digest(str(row[1])) for row in execute(_FUNCTIONS_SQL)
    }
    for signature in sorted(set(found_functions) | set(expected_functions)):
        if signature not in found_functions:
            violations.append(f"function-missing:{signature}")
        elif signature not in expected_functions:
            violations.append(f"function-unpinned:{signature}")
        elif found_functions[signature] != expected_functions[signature]:
            violations.append(f"function-changed:{signature}")

    found_triggers = {
        str(row[0]): (str(row[1]), str(row[2]), _digest(str(row[3])))
        for row in execute(_TRIGGERS_SQL)
    }
    for name in sorted(set(found_triggers) | set(expected_triggers)):
        if name not in found_triggers:
            violations.append(f"trigger-missing:{name}")
        elif name not in expected_triggers:
            violations.append(f"trigger-unpinned:{name}")
        else:
            table, state, definition = found_triggers[name]
            want_table, want_state, want_definition = expected_triggers[name]
            if state != want_state:
                violations.append(f"trigger-not-enabled:{name}")
            if table != want_table or definition != want_definition:
                violations.append(f"trigger-changed:{name}")
    return tuple(violations)


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    del argv
    env = os.environ if environ is None else environ
    dsn = env.get(ADMIN_DSN_ENV, "").strip()
    if not dsn:
        print(
            f"store integrity refused: {ADMIN_DSN_ENV} is not supplied", file=sys.stderr
        )
        return 2
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        session = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory()
        try:
            session.execute(text("SET TRANSACTION READ ONLY"))
            violations = check_store_integrity(
                lambda sql: session.execute(text(sql)).all()
            )
        finally:
            session.rollback()
            session.close()
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        print(f"store integrity unverifiable: {type(error).__name__}", file=sys.stderr)
        return 2
    if violations:
        print("store integrity violated: " + ", ".join(violations), file=sys.stderr)
        return 2
    print("store integrity passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
