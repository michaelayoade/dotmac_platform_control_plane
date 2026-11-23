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
        every = qual.select_targets(self.scenarios) + qual.select_control_targets(
            self.scenarios
        )
        for t in every:
            module, name = qual._module_of(t)
            out.append({"classname": module, "name": name, "outcome": "passed"})
        return out

    def test_all_mapped_scenarios_pass_when_every_test_passes(self) -> None:
        judged = qual.judge_scenarios(self.scenarios, self.all_pass_cases())
        self.assertEqual(qual.overall(judged), "PASS")

    def test_a_scenario_with_no_tests_is_blocked_never_pass(self) -> None:
        scenarios = [dict(s, tests=[], control_tests=[]) for s in self.scenarios]
        judged = qual.judge_scenarios(scenarios, self.all_pass_cases())
        self.assertEqual(qual.overall(judged), "INCOMPLETE")

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
    def test_pg_receipt_is_values_free_and_fails_without_results(self) -> None:
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
                        "--wheelhouse-manifest",
                        str(tmp / "absent3.json"),
                        "--ci-runs",
                        str(tmp / "absent5.json"),
                        "--observer-sql-result",
                        str(tmp / "absent7.json"),
                        "--recovery-collect",
                        str(tmp / "absent8.txt"),
                        "--observe-result",
                        str(tmp / "absent6.json"),
                        "--control-junit",
                        str(tmp / "absent4.json"),
                        "--recovery-junit",
                        str(tmp / "absent2.xml"),
                        "--recovery-cp-commit",
                        "8" * 40,
                        "--recovery-parity",
                        "true",
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
        self.assertEqual(doc["recovery_contract"]["status"], "FAIL")
        self.assertEqual(doc["recovery_observe_native"]["status"], "FAIL")
        self.assertEqual(doc["observer_sql_native"]["status"], "FAIL")
        self.assertEqual(
            {s["id"]: s["status"] for s in doc["scenarios"]}[
                "a_standing_withdrawal_locking"
            ],
            "FAIL",
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


class WheelhouseTests(unittest.TestCase):
    def test_lock_pins_every_wheel_by_hash_and_refuses_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            wh = Path(d) / "wh"
            wh.mkdir()
            with self.assertRaises(SystemExit):
                qual.wheelhouse_lock(wh, Path(d) / "l", Path(d) / "m")
            (wh / "dotmac_kernel-0.1.0-py3-none-any.whl").write_bytes(b"x")
            m = qual.wheelhouse_lock(wh, Path(d) / "l", Path(d) / "m")
            text = (Path(d) / "l").read_text()
        self.assertIn("dotmac-kernel==0.1.0 --hash=sha256:", text)
        self.assertEqual(len(m["wheels"]), 1)
        self.assertEqual(len(m["lock_sha256"]), 64)


class C4Tests(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(HERE / "c4"))
        import c4

        self.c4 = c4

    def good_readback(self) -> dict:
        return {
            "canlogin": True,
            "privileged_flags": False,
            "connlimit": 2,
            "valid_until_set": True,
            "config": [
                "default_transaction_read_only=on",
                "statement_timeout=5s",
                "lock_timeout=2s",
                "idle_in_transaction_session_timeout=10s",
            ],
            "table_grants": ["SELECT"] * 4,
            "column_acl_entries": 0,
            "memberships": 0,
            "db_create": False,
            "schema_create": False,
            "other_tables_select": [False, False],
        }

    def test_verifier_shape(self) -> None:
        v = self.c4.scram_verifier("pw")
        self.assertTrue(v.startswith("SCRAM-SHA-256$4096:"))

    def test_readback_accepts_the_spec_and_refuses_each_drift(self) -> None:
        self.assertTrue(all(self.c4.judge_readback(self.good_readback()).values()))
        for key, bad in (
            ("privileged_flags", True),
            ("connlimit", 3),
            ("table_grants", ["SELECT"] * 3),
            ("table_grants", ["SELECT"] * 3 + ["UPDATE"]),
            ("column_acl_entries", 1),
            ("memberships", 1),
            ("db_create", True),
            ("other_tables_select", [True, False]),
            ("config", ["statement_timeout=5s"]),
        ):
            doc = self.good_readback()
            doc[key] = bad
            self.assertFalse(all(self.c4.judge_readback(doc).values()), key)

    def test_rendered_sql_has_no_placeholders_left(self) -> None:
        sql = self.c4.render_create("r1", "db")
        for token in ("rN", "<cp_db_name>", "<UTC now"):
            self.assertNotIn(token, sql)

    def test_observation_must_decode_with_a_parsed_authorization(self) -> None:
        good = {
            "observation": {
                "schema": "a2_recovery_oracle_observation.v1",
                "rows": {
                    "command_ledger": [{}],
                    "rollout": [{"has_authorization": True}],
                    "attempts_and_settlements": [],
                },
            },
            "original_authorization": {"k": 1},
        }
        self.assertTrue(all(self.c4.judge_observation(json.dumps(good)).values()))
        self.assertFalse(all(self.c4.judge_observation("not json").values()))
        good["original_authorization"] = {}
        self.assertFalse(all(self.c4.judge_observation(json.dumps(good)).values()))


class ObserverResultTests(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(HERE / "observer"))
        import observer_result

        self.m = observer_result
        self.stages = {s: "0" for s in observer_result.STAGES}
        self.login = dict.fromkeys(observer_result.LOGIN_KEYS, True)
        self.base = ["no_column_level_grants_to_role|true"]
        self.good_rows = [f"{r}|true" for r in ("a", "b", *observer_result.NEW_ROWS)]

    def sens(self, **over: list[str]) -> dict[str, list[str]]:
        def with_false(*names: str) -> list[str]:
            return [
                f"{r}|{'false' if r in names else 'true'}"
                for r in ("a", "b", *self.m.NEW_ROWS, self.m.SECDEF_ROW)
            ]

        out = {
            "probe": with_false(self.m.SECDEF_ROW),
            "a": with_false(self.m.ROLE_ROW),
            "b": with_false(self.m.ROLE_ROW),
            "c": with_false(self.m.PUBLIC_ROW),
            "final": with_false(),
        }
        out.update(over)
        return out

    def judge(self, **over):
        args = {
            "stages": self.stages,
            "readback": self.good_rows,
            "login": self.login,
            "absence": ["role_absent|true"],
            "names": ["secdef_reachable|none"],
            "sens": self.sens(),
            "sens_names": ["secdef_reachable|public.a2_ci_sensitivity_probe()"],
        }
        args.update(over)
        return self.m.judge(**args)

    def test_all_expected_passes_and_marks_the_pin_pending(self) -> None:
        r = self.judge()
        self.assertEqual(r["status"], "PASS", r["failed_checks"])
        self.assertEqual(r["pin"]["status"], "PENDING_MICHAEL_APPROVAL")

    def test_one_false_readback_row_fails_and_is_named(self) -> None:
        rows = [*self.good_rows, "some_row|false"]
        r = self.judge(readback=rows)
        self.assertEqual(r["status"], "FAIL")
        self.assertIn("readback_some_row", r["failed_checks"])

    def test_sensitivity_requires_the_exact_false_set(self) -> None:
        extra = self.sens(a=[*self.sens()["a"], "no_write_on_the_four_tables|false"])
        self.assertEqual(self.judge(sens=extra)["status"], "FAIL")
        wrong_row = self.sens(c=self.sens()["a"])
        self.assertEqual(self.judge(sens=wrong_row)["status"], "FAIL")
        none_false = self.sens(b=self.sens()["final"])
        self.assertEqual(self.judge(sens=none_false)["status"], "FAIL")
        missing = self.sens()
        del missing["probe"]
        self.assertEqual(self.judge(sens=missing)["status"], "FAIL")

    def test_final_readback_after_revokes_must_be_all_true(self) -> None:
        dirty = self.sens(final=self.sens()["a"])
        self.assertEqual(self.judge(sens=dirty)["status"], "FAIL")

    def test_missing_new_rows_or_pieces_fail(self) -> None:
        self.assertEqual(self.judge(readback=["a|true"])["status"], "FAIL")
        self.assertEqual(self.judge(readback=[])["status"], "FAIL")
        self.assertEqual(self.judge(login={})["status"], "FAIL")
        self.assertEqual(self.judge(absence=[])["status"], "FAIL")
        self.assertEqual(self.judge(sens_names=[])["status"], "FAIL")


class VendoredReadbackTests(unittest.TestCase):
    def test_readback_has_the_column_rows_and_not_the_defective_view(self) -> None:
        text = (HERE / "observer" / "a2-observer-readback.sql.tmpl").read_text()
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("--")
        )
        self.assertNotIn("information_schema.column_privileges", code)
        self.assertIn("aclexplode(a.attacl)", code)
        for name in (
            "no_column_level_grants_to_role",
            "no_column_level_grants_to_public_outside_catalogs",
        ):
            self.assertIn(name, code)
        self.assertIn(") a(name) WHERE", code)

    def test_pins_cover_the_vendored_bytes(self) -> None:
        import hashlib

        pins = {}
        for line in (HERE / "observer" / "PINS").read_text().splitlines():
            if line and not line.startswith("#"):
                digest, name = line.split("  ")
                pins[name] = digest
        self.assertEqual(len(pins), 6)
        for name, digest in pins.items():
            data = (HERE / "observer" / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)
        self.assertEqual(
            pins["a2-observer-readback.sql.tmpl"],
            "94fb64b6b9825b7ba628d43ac4e0fbc49d911f5a20ebbe95a07b59d4dfa79e68",
        )


class RecoverySuiteTests(unittest.TestCase):
    PINS = {"x/a.py": 2, "y/b.py": 1}

    def junit(self, tmp: Path, cases: list[tuple[str, str, str]]) -> Path:
        body = "".join(case(c, n, child) for c, n, child in cases)
        return junit_file(tmp, body)

    def collect(self, tmp: Path, n_a: int, n_b: int) -> Path:
        p = tmp / "c.txt"
        lines = [f"x/a.py::t{i}" for i in range(n_a)] + [
            f"y/b.py::t{i}" for i in range(n_b)
        ]
        p.write_text("\n".join(lines) + "\n")
        return p

    def good(self) -> list[tuple[str, str, str]]:
        return [("x.a", "t0", ""), ("x.a", "t1", ""), ("y.b", "t0", "")]

    def test_exact_counts_and_no_skips_pass(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            r = qual.judge_recovery_suite(
                self.junit(tmp, self.good()), self.PINS, self.collect(tmp, 2, 1)
            )
        self.assertEqual(r["status"], "PASS")

    def test_wrong_counts_skips_and_failures_fail(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            col = self.collect(tmp, 2, 1)
            short = self.good()[:2]
            self.assertEqual(
                qual.judge_recovery_suite(self.junit(tmp, short), self.PINS, col)[
                    "status"
                ],
                "FAIL",
            )
            skipped = [*self.good()[:2], ("y.b", "t0", "<skipped/>")]
            self.assertEqual(
                qual.judge_recovery_suite(self.junit(tmp, skipped), self.PINS, col)[
                    "status"
                ],
                "FAIL",
            )
            failed = [*self.good()[:2], ("y.b", "t0", "<failure/>")]
            self.assertEqual(
                qual.judge_recovery_suite(self.junit(tmp, failed), self.PINS, col)[
                    "status"
                ],
                "FAIL",
            )
            self.assertEqual(
                qual.judge_recovery_suite(
                    self.junit(tmp, self.good()), self.PINS, self.collect(tmp, 3, 1)
                )["status"],
                "FAIL",
            )
            self.assertEqual(
                qual.judge_recovery_suite(self.junit(tmp, self.good()), self.PINS)[
                    "status"
                ],
                "FAIL",
            )

    def test_quiet_collect_form_counts_too(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            quiet = tmp / "q.txt"
            quiet.write_text("x/a.py: 2\ny/b.py: 1\n")
            r = qual.judge_recovery_suite(
                self.junit(tmp, self.good()), self.PINS, quiet
            )
            self.assertEqual(r["status"], "PASS")
            quiet.write_text("x/a.py: 2\ny/b.py: 2\n")
            r = qual.judge_recovery_suite(
                self.junit(tmp, self.good()), self.PINS, quiet
            )
            self.assertEqual(r["status"], "FAIL")

    def test_shipped_pins_are_14_and_24(self) -> None:
        pins = qual.load_recovery_pins(HERE / "scenarios.json")
        self.assertEqual(
            sorted(pins.values()),
            [14, 24],
        )


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
