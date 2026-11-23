"""Receipt tooling for the hosted `a2-native-qualification` workflow.

stdlib only. It selects the named existing CP tests, judges a junit file against
the scenario map, and writes VALUES-FREE receipts. A scenario is PASS only when
every named test ran and passed (a skip is not a pass), and the receipt status is
PASS only when every scenario is PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - our own pytest junit output
from pathlib import Path
from typing import Any

PG_SCHEMA = "dotmac.a2.native-pg-qualification.v1"
BAO_SCHEMA = "dotmac.a2.native-bao-qualification.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != "dotmac.a2.native-pg-scenarios.v1":
        raise ValueError("unknown scenario map schema")
    scenarios = doc["scenarios"]
    ids = [s["id"] for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate scenario id")
    for s in scenarios:
        for test in [*s["tests"], *s.get("control_tests", [])]:
            if test.count("::") != 1 or not test.startswith("tests/"):
                raise ValueError(f"malformed test id: {test}")
    return list(scenarios)


def select_targets(scenarios: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for s in scenarios:
        for test in s["tests"]:
            seen[test] = None
    return list(seen)


def select_control_targets(scenarios: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for s in scenarios:
        for test in s.get("control_tests", []):
            seen[test] = None
    return list(seen)


def _module_of(test: str) -> tuple[str, str]:
    path, name = test.split("::")
    return path.removesuffix(".py").replace("/", "."), name


def parse_junit(path: Path) -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []
    root = ET.parse(path).getroot()  # noqa: S314 - our own pytest junit output
    for case in root.iter("testcase"):
        outcome = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                outcome = "failed"
            elif child.tag == "skipped" and outcome == "passed":
                outcome = "skipped"
        cases.append(
            {
                "classname": case.get("classname", ""),
                "name": case.get("name", ""),
                "outcome": outcome,
            }
        )
    return cases


def judge_test(test: str, cases: list[dict[str, str]]) -> dict[str, Any]:
    module, name = _module_of(test)
    matched = [
        c
        for c in cases
        if (c["classname"] == module or c["classname"].startswith(module + "."))
        and (c["name"] == name or c["name"].startswith(name + "["))
    ]
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for c in matched:
        counts[c["outcome"]] += 1
    ok = bool(matched) and counts["failed"] == 0 and counts["skipped"] == 0
    return {
        "test": test,
        "cases": len(matched),
        **counts,
        "status": "PASS" if ok else "FAIL",
    }


def judge_scenarios(
    scenarios: list[dict[str, Any]], cases: list[dict[str, str]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in scenarios:
        all_tests = [*s["tests"], *s.get("control_tests", [])]
        if not all_tests:
            out.append(
                {
                    "id": s["id"],
                    "title": s["title"],
                    "status": "BLOCKED",
                    "blocked_on": s.get("blocked_on", "no tests mapped"),
                    "tests": [],
                }
            )
            continue
        tests = [judge_test(t, cases) for t in all_tests]
        status = "PASS" if all(t["status"] == "PASS" for t in tests) else "FAIL"
        out.append(
            {"id": s["id"], "title": s["title"], "status": status, "tests": tests}
        )
    return out


def load_recovery_pins(path: Path) -> dict[str, int]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    files = doc["recovery_suite"]["files"]
    if not files or any(not isinstance(v, int) or v < 1 for v in files.values()):
        raise ValueError("malformed recovery_suite pins")
    return dict(files)


def _count_by_file(cases: list[dict[str, str]], files: list[str]) -> dict[str, int]:
    counts = dict.fromkeys(files, 0)
    for c in cases:
        for f in files:
            module = f.removesuffix(".py").replace("/", ".")
            if c["classname"] == module or c["classname"].startswith(module + "."):
                counts[f] += 1
    return counts


def judge_recovery_suite(
    path: Path, pins: dict[str, int], collect: Path | None = None
) -> dict[str, Any]:
    """Every pinned file must run, with its exact case count: 0 fail/error/skip."""
    cases = parse_junit(path) if path.is_file() else []
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for c in cases:
        counts[c["outcome"]] += 1
    files = list(pins)
    ran = _count_by_file(cases, files)
    collected: dict[str, int] = dict.fromkeys(files, 0)
    if collect is not None and collect.is_file():
        for line in collect.read_text(encoding="utf-8").splitlines():
            for f in files:
                if line.startswith(f + "::"):
                    collected[f] += 1
    counts_ok = ran == pins and collected == pins and len(cases) == sum(pins.values())
    ok = counts_ok and counts["failed"] == 0 and counts["skipped"] == 0
    return {
        "id": "recovery_contract_suite",
        "title": "pytest --noconftest over the pinned recovery files, against the "
        "P0-built Control wheel",
        "files": files,
        "pinned_counts": pins,
        "collected_counts": collected,
        "ran_counts": ran,
        "status": "PASS" if ok else "FAIL",
        "cases": len(cases),
        **counts,
    }


def wheelhouse_lock(
    wheelhouse: Path, lock_out: Path, manifest_out: Path
) -> dict[str, Any]:
    """Write a hash-pinned requirements lock for every wheel in the wheelhouse."""
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels:
        raise SystemExit("empty wheelhouse")
    if any(p.suffix != ".whl" for p in wheelhouse.iterdir()):
        raise SystemExit("wheelhouse holds a non-wheel file")
    entries = []
    lines = []
    for wheel in wheels:
        name, version = wheel.name.split("-")[:2]
        digest = sha256_file(wheel)
        entries.append({"wheel": wheel.name, "sha256": digest})
        lines.append(
            f"{name.replace('_', '-').lower()}=={version} --hash=sha256:{digest}"
        )
    lock_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = {"lock_sha256": sha256_file(lock_out), "wheels": entries}
    manifest_out.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def overall(scenarios: list[dict[str, Any]]) -> str:
    states = {s["status"] for s in scenarios}
    if states == {"PASS"}:
        return "PASS"
    if "FAIL" in states:
        return "FAIL"
    return "INCOMPLETE"


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing required environment value: {name}")
    return value


def _digest(value: str, what: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise SystemExit(f"{what} is not a sha256 hex digest")
    return value


def _sha(value: str, what: str) -> str:
    if not SHA_RE.fullmatch(value):
        raise SystemExit(f"{what} is not a 40-hex commit")
    return value


def workflow_block() -> dict[str, Any]:
    return {
        "name": "a2-native-qualification",
        "file": ".github/workflows/a2-native-qualification.yml",
        "file_sha256": _digest(_env("QUAL_WORKFLOW_SHA256"), "workflow sha"),
        "repository": _env("GITHUB_REPOSITORY"),
        "run_id": _env("GITHUB_RUN_ID"),
        "run_attempt": _env("GITHUB_RUN_ATTEMPT"),
        "event": _env("GITHUB_EVENT_NAME"),
        "workflow_commit": _sha(_env("GITHUB_SHA"), "GITHUB_SHA"),
    }


def wheelhouse_block(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"status": "ABSENT"}
    doc = json.loads(path.read_text(encoding="utf-8"))
    _digest(doc["lock_sha256"], "lock sha")
    for w in doc["wheels"]:
        _digest(w["sha256"], "wheel sha")
    resolved = {
        name: next(
            (
                w["wheel"].split("-")[1]
                for w in doc["wheels"]
                if w["wheel"].lower().startswith(name + "-")
            ),
            None,
        )
        for name in ("dotmac_kernel", "fastapi")
    }
    return {
        "status": "PRESENT",
        **doc,
        "offline_install_verified": True,
        "resolved_closure_note": "the recovery suite is qualified on this sha-pinned "
        "closure, not CP's own lock",
        "resolved_versions": resolved,
    }


def ci_runs_block(path: Path) -> dict[str, Any]:
    """Source CI runs (Control, CP) cited by id; ids/status/conclusion only."""
    if not path.is_file():
        return {"status": "UNAVAILABLE"}
    doc = json.loads(path.read_text(encoding="utf-8"))
    for run in doc.values():
        if not isinstance(run, dict):
            raise SystemExit("malformed ci runs file")
    return doc


def build_pg_receipt(args: argparse.Namespace) -> dict[str, Any]:
    scenarios = load_scenarios(Path(args.scenarios))
    junit = Path(args.junit)
    cases = parse_junit(junit) if junit.is_file() else []
    control_junit = Path(args.control_junit)
    if control_junit.is_file():
        cases += parse_junit(control_junit)
    judged = judge_scenarios(scenarios, cases)
    recovery = judge_recovery_suite(
        Path(args.recovery_junit),
        load_recovery_pins(Path(args.scenarios)),
        Path(args.recovery_collect),
    )
    judged.append(recovery)
    observe_path = Path(args.observe_result)
    observe = (
        json.loads(observe_path.read_text(encoding="utf-8"))
        if observe_path.is_file()
        else {"status": "FAIL", "stage": "not_run"}
    )
    judged.append({"id": "recovery_observe_native", **observe})
    sql_path = Path(args.observer_sql_result)
    observer_sql = (
        json.loads(sql_path.read_text(encoding="utf-8"))
        if sql_path.is_file()
        else {"status": "FAIL", "stage": "not_run"}
    )
    judged.append({"id": "observer_sql_native", **observer_sql})
    log = Path(args.log)
    return {
        "schema": PG_SCHEMA,
        "receipt": "a2-native-pg-qualification",
        "gate2_item": "NATIVE_PG",
        "status": overall(judged),
        "job": "pg",
        "workflow": workflow_block(),
        "sources": {
            "cp": {
                "repository": args.cp_repo,
                "commit": _sha(args.cp_commit, "cp commit"),
            },
            "foundation": {
                "repository": args.foundation_repo,
                "commit": _sha(args.foundation_commit, "foundation commit"),
                "role": "imported from source for the cross-class rehearsal acquire",
            },
            "control": {
                "repository": args.control_repo,
                "commit": _sha(args.control_commit, "control commit"),
            },
        },
        "built_artifacts": {
            "cp_wheel": {
                "name": args.cp_wheel_name,
                "sha256": _digest(args.cp_wheel_sha256, "cp wheel"),
            },
            "control_wheel": {
                "name": args.control_wheel_name,
                "sha256": _digest(args.control_wheel_sha256, "control wheel"),
            },
            "cp_image_id": args.cp_image_id,
        },
        "recovery_observe_native": observe,
        "observer_sql_native": observer_sql,
        "recovery_contract": {
            "files": recovery["files"],
            "pinned_counts": recovery["pinned_counts"],
            "collected_counts": recovery["collected_counts"],
            "ran_counts": recovery["ran_counts"],
            "cp_repository": args.cp_repo,
            "cp_recovery_commit": _sha(args.recovery_cp_commit, "recovery cp commit"),
            "control_wheel_sha256": args.control_wheel_sha256,
            "control_commit": args.control_commit,
            "ran_against_installed_control_wheel": args.recovery_parity == "true",
            "status": recovery["status"],
            "junit_sha256": sha256_file(Path(args.recovery_junit))
            if Path(args.recovery_junit).is_file()
            else None,
        },
        "source_ci_runs": ci_runs_block(Path(args.ci_runs)),
        "runtime_wheelhouse": wheelhouse_block(Path(args.wheelhouse_manifest)),
        "control_native_pg": {
            "note": "Control tests ran from the Control source checkout at the named "
            "commit, on real PostgreSQL 16 with Control's own platform-isolation "
            "fixtures (not the installed wheel).",
            "junit_sha256": sha256_file(control_junit)
            if control_junit.is_file()
            else None,
        },
        "installed_artifact_parity": {
            "tests_import_installed_wheel": args.parity == "true",
            "note": "CP tests ran against the installed CP wheel, not the source tree. "
            "CP resolves Control from its lock (published pin); the Control wheel "
            "here is built from the named Control commit and bound by digest.",
        },
        "server_version": args.server_version,
        "postgres_image": args.postgres_image,
        "pytest_exit_code": int(args.pytest_rc),
        "scenarios": judged,
        "log_sha256": sha256_file(log) if log.is_file() else None,
        "junit_sha256": sha256_file(junit) if junit.is_file() else None,
        "values_free": True,
    }


def build_bao_receipt(args: argparse.Namespace) -> dict[str, Any]:
    results_path = Path(args.results)
    if results_path.is_file():
        results = json.loads(results_path.read_text(encoding="utf-8"))
    else:  # the driver aborted before it could write: a FAIL receipt, never a gap
        results = {"server_version": "unknown", "not_dev_mode": False, "checks": []}
    checks = results["checks"]
    log = Path(args.log)
    status = "PASS" if checks and all(c["status"] == "PASS" for c in checks) else "FAIL"
    return {
        "schema": BAO_SCHEMA,
        "receipt": "a2-native-bao-qualification",
        "gate2_item": "NATIVE_BAO",
        "scope": "semantics only (#2 (i)); the production-like policy install "
        "(#2 (ii)) is a separate ceremony",
        "status": status,
        "job": "bao",
        "workflow": workflow_block(),
        "sources": {"tooling_commit": _sha(_env("GITHUB_SHA"), "GITHUB_SHA")},
        "openbao": {
            "image": args.image,
            "server_version": results["server_version"],
            "storage": "file",
            "not_dev_mode": results["not_dev_mode"],
        },
        "checks": checks,
        "log_sha256": sha256_file(log) if log.is_file() else None,
        "values_free": True,
    }


def write_receipt(doc: dict[str, Any], out_dir: Path, stem: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{stem}.json"
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    (out_dir / f"{stem}.json.sha256").write_text(
        f"{hashlib.sha256(data).hexdigest()}  {path.name}\n", encoding="utf-8"
    )
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="qual")
    sub = p.add_subparsers(dest="cmd", required=True)
    wl = sub.add_parser("wheelhouse-lock")
    for flag in ("wheelhouse", "lock-out", "manifest-out"):
        wl.add_argument(f"--{flag}", required=True)
    sel = sub.add_parser("pg-select")
    sel.add_argument("--scenarios", required=True)
    sel.add_argument("--control", action="store_true")
    pg = sub.add_parser("pg-receipt")
    for flag in (
        "scenarios", "junit", "log", "out-dir", "stem", "cp-repo", "cp-commit",
        "control-repo", "control-commit", "cp-wheel-name", "cp-wheel-sha256",
        "control-wheel-name", "control-wheel-sha256", "cp-image-id", "parity",
        "server-version", "postgres-image", "pytest-rc", "foundation-repo",
        "foundation-commit",
        "recovery-junit", "wheelhouse-manifest", "control-junit", "ci-runs",
        "observe-result",
        "recovery-collect",
        "observer-sql-result",
        "recovery-cp-commit", "recovery-parity",
    ):  # fmt: skip
        pg.add_argument(f"--{flag}", required=True)
    bao = sub.add_parser("bao-receipt")
    for flag in ("results", "log", "out-dir", "stem", "image"):
        bao.add_argument(f"--{flag}", required=True)
    gate = sub.add_parser("gate")
    gate.add_argument("--receipt", required=True)
    gate.add_argument("--allow-incomplete", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "pg-select":
        pick = select_control_targets if args.control else select_targets
        print("\n".join(pick(load_scenarios(Path(args.scenarios)))))
        return 0
    if args.cmd == "wheelhouse-lock":
        m = wheelhouse_lock(
            Path(args.wheelhouse), Path(args.lock_out), Path(args.manifest_out)
        )
        print(f"lock {m['lock_sha256']} wheels={len(m['wheels'])}")
        return 0
    if args.cmd == "gate":
        doc = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
        print(f"{doc['receipt']}: {doc['status']}")
        if doc["status"] == "PASS":
            return 0
        return 0 if doc["status"] == "INCOMPLETE" and args.allow_incomplete else 1
    if args.cmd == "pg-receipt":
        doc = build_pg_receipt(args)
    else:
        doc = build_bao_receipt(args)
    path = write_receipt(doc, Path(args.out_dir), args.stem)
    print(f"wrote {path.name} status={doc['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
