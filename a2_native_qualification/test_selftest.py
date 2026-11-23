"""Offline self-tests for the receipt tooling: synthetic junit, no engine."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import qual  # noqa: E402

HERE = Path(__file__).resolve().parent
JUNIT = "<testsuites><testsuite>{}</testsuite></testsuites>"


def case(module: str, name: str, child: str = "") -> str:
    return f'<testcase classname="{module}" name="{name}">{child}</testcase>'


def junit_file(tmp: Path, body: str) -> Path:
    path = tmp / "j.xml"
    path.write_text(JUNIT.format(body), encoding="utf-8")
    return path


class SelectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenarios = qual.load_scenarios(HERE / "scenarios.json")

    def all_pass_cases(self) -> list[dict[str, str]]:
        out = []
        for t in qual.select_targets(self.scenarios):
            module, name = qual._module_of(t)
            out.append({"classname": module, "name": name, "outcome": "passed"})
        return out

    def test_blocked_scenarios_never_read_as_pass(self) -> None:
        judged = qual.judge_scenarios(self.scenarios, self.all_pass_cases())
        states = {s["id"][0]: s["status"] for s in judged}
        self.assertEqual(states["a"], "BLOCKED")
        self.assertEqual(states["d"], "BLOCKED")
        self.assertEqual(qual.overall(judged), "INCOMPLETE")

    def test_all_scenarios_mapped_pass_only_when_nothing_is_blocked(self) -> None:
        scenarios = [
            dict(s, tests=s["tests"] or ["tests/x.py::test_x"]) for s in self.scenarios
        ]
        cases = self.all_pass_cases() + [
            {"classname": "tests.x", "name": "test_x", "outcome": "passed"}
        ]
        self.assertEqual(qual.overall(qual.judge_scenarios(scenarios, cases)), "PASS")

    def test_skip_is_not_a_pass_and_failure_dominates(self) -> None:
        cases = self.all_pass_cases()
        cases[0]["outcome"] = "skipped"
        judged = qual.judge_scenarios(self.scenarios, cases)
        self.assertEqual(qual.overall(judged), "FAIL")

    def test_missing_test_is_a_failure(self) -> None:
        judged = qual.judge_scenarios(self.scenarios, [])
        self.assertEqual(qual.overall(judged), "FAIL")

    def test_parametrised_cases_must_all_pass(self) -> None:
        test = "tests/a/b.py::test_t"
        cases = [
            {"classname": "tests.a.b", "name": "test_t[1]", "outcome": "passed"},
            {"classname": "tests.a.b", "name": "test_t[2]", "outcome": "failed"},
        ]
        self.assertEqual(qual.judge_test(test, cases)["status"], "FAIL")

    def test_prefix_of_another_name_does_not_match(self) -> None:
        cases = [{"classname": "tests.a.b", "name": "test_tx", "outcome": "passed"}]
        self.assertEqual(
            qual.judge_test("tests/a/b.py::test_t", cases)["status"], "FAIL"
        )

    def test_junit_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = junit_file(
                Path(d),
                case("tests.a", "test_p")
                + case("tests.a", "test_s", "<skipped/>")
                + case("tests.a", "test_f", "<failure/>"),
            )
            got = {c["name"]: c["outcome"] for c in qual.parse_junit(path)}
        self.assertEqual(
            got, {"test_p": "passed", "test_s": "skipped", "test_f": "failed"}
        )

    def test_map_rejects_malformed_ids_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "s.json"
            for scenarios in (
                [{"id": "x", "title": "t", "tests": ["nope"]}],
                [
                    {"id": "x", "title": "t", "tests": []},
                    {"id": "x", "title": "t", "tests": []},
                ],
            ):
                bad.write_text(
                    json.dumps(
                        {
                            "schema": "dotmac.a2.native-pg-scenarios.v1",
                            "scenarios": scenarios,
                        }
                    )
                )
                with self.assertRaises(ValueError):
                    qual.load_scenarios(bad)


class ReceiptTests(unittest.TestCase):
    def test_pg_receipt_is_values_free_and_incomplete_while_p0_is_absent(self) -> None:
        env = {
            "QUAL_WORKFLOW_SHA256": "a" * 64,
            "GITHUB_REPOSITORY": "o/r",
            "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": "b" * 40,
        }
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            with tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                log = tmp / "pg.log"
                log.write_text("log\n")
                out = tmp / "out"
                rc = qual.main(
                    [
                        "pg-receipt",
                        "--scenarios",
                        str(HERE / "scenarios.json"),
                        "--junit",
                        str(tmp / "absent.xml"),
                        "--log",
                        str(log),
                        "--out-dir",
                        str(out),
                        "--stem",
                        "r",
                        "--cp-repo",
                        "o/cp",
                        "--cp-commit",
                        "c" * 40,
                        "--control-repo",
                        "o/ctl",
                        "--control-commit",
                        "d" * 40,
                        "--cp-wheel-name",
                        "cp.whl",
                        "--cp-wheel-sha256",
                        "e" * 64,
                        "--control-wheel-name",
                        "ctl.whl",
                        "--control-wheel-sha256",
                        "f" * 64,
                        "--cp-image-id",
                        "sha256:" + "1" * 64,
                        "--parity",
                        "true",
                        "--server-version",
                        "16.4",
                        "--postgres-image",
                        "postgres:16",
                        "--pytest-rc",
                        "1",
                        "--foundation-repo",
                        "o/f",
                        "--foundation-commit",
                        "9" * 40,
                    ]  # fmt: skip
                )
                doc = json.loads((out / "r.json").read_text())
                sums = (out / "r.json.sha256").read_text()
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual(rc, 0)
        self.assertEqual(doc["status"], "FAIL")  # junit absent: mapped tests missing
        self.assertTrue(doc["values_free"])
        self.assertEqual(doc["gate2_item"], "NATIVE_PG")
        self.assertIn("r.json", sums)
        self.assertEqual(
            {s["id"]: s["status"] for s in doc["scenarios"]}[
                "a_standing_withdrawal_locking"
            ],
            "BLOCKED",
        )

    def test_gate_refuses_anything_but_pass(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "r.json"
            for status, want in (("PASS", 0), ("INCOMPLETE", 1), ("FAIL", 1)):
                path.write_text(json.dumps({"receipt": "x", "status": status}))
                self.assertEqual(qual.main(["gate", "--receipt", str(path)]), want)
            path.write_text(json.dumps({"receipt": "x", "status": "INCOMPLETE"}))
            self.assertEqual(
                qual.main(["gate", "--receipt", str(path), "--allow-incomplete"]), 0
            )
            path.write_text(json.dumps({"receipt": "x", "status": "FAIL"}))
            self.assertEqual(
                qual.main(["gate", "--receipt", str(path), "--allow-incomplete"]), 1
            )

    def test_non_hex_digest_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            qual._digest("zz", "x")


class BaoGuardTests(unittest.TestCase):
    def test_missing_results_make_a_fail_receipt(self) -> None:
        os.environ.update(
            {
                "QUAL_WORKFLOW_SHA256": "a" * 64,
                "GITHUB_REPOSITORY": "o/r",
                "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_SHA": "b" * 40,
            }
        )
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            args = qual.argparse.Namespace(
                results=str(out / "none.json"), log=str(out / "none.log"), image="i"
            )
            doc = qual.build_bao_receipt(args)
        self.assertEqual(doc["status"], "FAIL")
        self.assertTrue(doc["values_free"])

    def test_non_loopback_address_is_refused(self) -> None:
        import bao_qualify

        with self.assertRaises(SystemExit):
            bao_qualify.Bao("http://192.0.2.1:8200")


if __name__ == "__main__":
    unittest.main()
