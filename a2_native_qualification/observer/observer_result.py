"""Assemble the values-free observer_sql_native result (stdlib only)."""

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
    "login",
    "drop",
    "absence",
)
SECDEF_ROW = "no_reachable_security_definer_functions_outside_allowlist"
PROBE = "public.a2_ci_sensitivity_probe()"


def judge(
    stages: dict[str, str],
    readback: list[str],
    login: dict,
    absence: list[str],
    names: list[str] | None = None,
    sens_readback: list[str] | None = None,
    sens_names: list[str] | None = None,
):
    rows = {}
    for line in readback:
        name, _, value = line.partition("|")
        rows[name] = value == "true"
    login_keys = (
        "select_four_tables_ok",
        "select_deployment_plans_refused",
        "insert_rollouts_refused",
        "read_only_switched_off",
        "insert_still_refused_after_read_only_off",
        "tls_session",
    )
    checks = {
        **{f"stage_{s}": stages.get(s) == "0" for s in STAGES},
        "readback_has_rows": bool(rows),
        **{f"readback_{k}": v for k, v in rows.items()},
        **{f"login_{k}": login.get(k) is True for k in login_keys},
        "absence_role_absent": absence == ["role_absent|true"],
        "sensitivity_row_false_with_probe": f"{SECDEF_ROW}|false"
        in (sens_readback or []),
        "sensitivity_probe_listed": any(PROBE in n for n in (sens_names or [])),
        "secdef_names_recorded": bool(names),
    }
    failed = sorted(k for k, v in checks.items() if not v)
    return {
        "status": "PASS" if not failed else "FAIL",
        "n": 999,
        "failed_checks": failed,
        "readback_rows": rows,
        "secdef_reachable_names": sorted(
            n.partition("|")[2] for n in (names or []) if "|" in n
        ),
        "login": {k: v for k, v in login.items() if k != "login_error"}
        | ({"login_error": login["login_error"]} if "login_error" in login else {}),
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
        return (
            [x for x in p.read_text().splitlines() if x.strip()] if p.is_file() else []
        )

    login_p = d / "login.json"
    login = json.loads(login_p.read_text()) if login_p.is_file() else {}
    readback = [x for x in lines("readback.txt") if "|" in x]
    absence = [x for x in lines("absence.txt") if "|" in x]
    result = judge(
        stages,
        readback,
        login,
        absence,
        [x for x in lines("secdef-names.txt") if "|" in x],
        [x for x in lines("sens-readback.txt") if "|" in x],
        [x for x in lines("sens-names.txt") if "|" in x],
    )
    Path(argv[2]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"observer_sql_native: {result['status']} failed={result['failed_checks']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
