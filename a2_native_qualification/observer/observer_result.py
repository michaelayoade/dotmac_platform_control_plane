"""Assemble the values-free observer_sql_native result (stdlib only).

Every sensitivity proof compares the EXACT set of false readback rows, not mere
membership: a grant that flips an extra row, or fails to flip the expected one,
is a FAIL.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

STAGES = (
    "pins",
    "materialize",
    "tls_setup",
    "create",
    "readback",
    "secdef_names",
    "probe_create",
    "probe_drop",
    "sens_a",
    "sens_b",
    "sens_c",
    "final_readback",
    "login",
    "drop",
    "absence",
)
SECDEF_ROW = "no_reachable_security_definer_functions_outside_allowlist"
PROBE = "public.a2_ci_sensitivity_probe()"
ROLE_ROW = "no_column_level_grants_to_role"
PUBLIC_ROW = "no_column_level_grants_to_public_outside_catalogs"
# Sensitivity name -> the EXACT set of readback rows that must read false.
EXPECTED_FALSE = {
    "probe": {SECDEF_ROW},
    "a": {ROLE_ROW},  # column SELECT on deployment_plans (the has_table_* gap)
    "b": {ROLE_ROW},  # column UPDATE on rollouts
    "c": {PUBLIC_ROW},  # column SELECT granted to PUBLIC
    "final": set(),  # after every revoke: all rows true
}
NEW_ROWS = (ROLE_ROW, PUBLIC_ROW)
PIN = {
    "readback_sha256": (
        "94fb64b6b9825b7ba628d43ac4e0fbc49d911f5a20ebbe95a07b59d4dfa79e68"
    ),
    "replaces": "70804d18d6af1e472ceefbd3a8b114004e0d284a741612707391d10b2c571ce8",
    "status": "APPROVED",
    "note": "architect r8 D1; approved (register v2155+; Michael, 2026-11-24)",
}
LOGIN_KEYS = (
    "select_four_tables_ok",
    "select_deployment_plans_refused",
    "insert_rollouts_refused",
    "read_only_switched_off",
    "insert_still_refused_after_read_only_off",
    "tls_session",
)


def rows_of(lines: list[str]) -> dict[str, bool]:
    rows = {}
    for line in lines:
        name, _, value = line.partition("|")
        rows[name] = value == "true"
    return rows


def false_set(lines: list[str]) -> set[str]:
    return {k for k, v in rows_of(lines).items() if not v}


def judge(
    stages: dict[str, str],
    readback: list[str],
    login: dict,
    absence: list[str],
    names: list[str] | None = None,
    sens: dict[str, list[str]] | None = None,
    sens_names: list[str] | None = None,
):
    rows = rows_of(readback)
    sens = sens or {}
    checks = {
        **{f"stage_{s}": stages.get(s) == "0" for s in STAGES},
        "readback_has_rows": bool(rows),
        "readback_has_the_two_column_acl_rows": all(r in rows for r in NEW_ROWS),
        **{f"readback_{k}": v for k, v in rows.items()},
        **{f"login_{k}": login.get(k) is True for k in LOGIN_KEYS},
        "absence_role_absent": absence == ["role_absent|true"],
        "probe_listed_in_secdef_names": any(PROBE in n for n in (sens_names or [])),
        "secdef_names_recorded": bool(names),
    }
    for key, expected in EXPECTED_FALSE.items():
        got = sens.get(key) or []
        checks[f"sensitivity_{key}_exact_false_set"] = (
            bool(got) and false_set(got) == expected
        )
    failed = sorted(k for k, v in checks.items() if not v)
    return {
        "status": "PASS" if not failed else "FAIL",
        "n": 999,
        "pin": PIN,
        "failed_checks": failed,
        "readback_rows": rows,
        "sensitivity_false_sets": {
            k: sorted(false_set(v)) for k, v in sens.items() if v
        },
        "secdef_reachable_names": sorted(
            n.partition("|")[2] for n in (names or []) if "|" in n
        ),
        "login": login,
        "stages": stages,
        "checks": checks,
    }


def main(argv: list[str]) -> int:
    d = Path(argv[1])
    stages = {}
    for line in (d / "stages.txt").read_text().splitlines():
        name, _, rc = line.partition(" ")
        stages[name] = rc

    def lines(name: str) -> list[str]:
        p = d / name
        if not p.is_file():
            return []
        return [x for x in p.read_text().splitlines() if "|" in x]

    login_p = d / "login.json"
    login = json.loads(login_p.read_text()) if login_p.is_file() else {}
    sens = {
        "probe": lines("sens-readback.txt"),
        "a": lines("sens-a.txt"),
        "b": lines("sens-b.txt"),
        "c": lines("sens-c.txt"),
        "final": lines("final-readback.txt"),
    }
    result = judge(
        stages,
        lines("readback.txt"),
        login,
        lines("absence.txt"),
        lines("secdef-names.txt"),
        sens,
        lines("sens-names.txt"),
    )
    Path(argv[2]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"observer_sql_native: {result['status']} failed={result['failed_checks']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
