"""Offline one-shot launcher tests; all subprocesses and protected reads mocked."""

from copy import deepcopy
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import execute_canary as launcher


PACKET_HASH = "7" * 64
AUTHORITY = "synthetic-explicit-canary-approval"
LAUNCHER_BYTES = launcher.Path(launcher.__file__).read_bytes()
KNOWN_HOSTS_BYTES = b"synthetic pinned host public key"
SECRET_SENTINEL = "synthetic-unexpected-secret-do-not-persist"
STAGES = ["exclusive_attempt_recorded", "pinned_runtime_ready", "before_create_canary", "canary_created",
          "before_mint_canary", "canary_token_bound", "canary_same_token_200", "before_exact_revocation",
          "revocation_committed_absence", "same_token_401", "finished"]


def packet_fixture():
    staging = "# synthetic staging source, never executed\n"
    canary = "# synthetic canary source, never executed\n"
    return {
        "phase": "CANARY_ONLY_NO_BOOTSTRAP", "maximum_execution_attempts": 1,
        "no_automatic_retry": True,
        "staging_ssh_argv": ["synthetic-ssh", "STAGING-ONLY"],
        "canary_ssh_argv": ["synthetic-ssh", "CANARY-ONLY"],
        "staging_python_source": staging, "canary_python_source": canary,
        "staging_source_sha256": launcher.sha(staging.encode()),
        "canary_wrapper_source_sha256": launcher.sha(canary.encode()),
        "launcher_sha256": launcher.sha(LAUNCHER_BYTES),
        "known_hosts_sha256": launcher.sha(KNOWN_HOSTS_BYTES),
        "staged_file_pins": {"stage-source.py": "1" * 64, "canary-wrapper.py": "2" * 64},
        "source_pins": {"orchestrator.py": "3" * 64, "host_gate.py": "4" * 64},
        "expected_run": "synthetic-host-gated-canary-run",
        "canary_username": "synthetic-revocation-canary",
        "canary_token_name": "synthetic-revocation-once",
        "container_pins": {"forgejo_container_id": "5" * 64, "forgejo_image_id": "sha256:" + "6" * 64,
                           "database_container_id": "8" * 64, "database_image_id": "sha256:" + "9" * 64},
    }


def staged(packet):
    return {"status": "SOURCE_STAGED_NO_CANARY_EXECUTED",
            "source_pins": deepcopy(packet["staged_file_pins"]), "run": packet["expected_run"]}


def native_receipt(packet):
    binding = {"kind": "canary", "token_id": 99, "user_id": 11,
               "username": packet["canary_username"], "token_name": packet["canary_token_name"],
               "scope": "read:user", "created_unix": 1_800_000_000}
    events = [{"stage": name} for name in STAGES]
    events[2]["username"] = packet["canary_username"]
    events[3]["user_id"] = 11
    events[4].update(token_name=packet["canary_token_name"], scope="read:user")
    for index in (5, 7, 8, 9):
        events[index]["binding"] = deepcopy(binding)
    return {"schema": "cp_host_gated_receipt.v1", "run": packet["expected_run"], "phase": "canary",
            "source_pins": deepcopy(packet["source_pins"]), "container_pins": deepcopy(packet["container_pins"]),
            "started_at": "2026-11-25T21:00:00+00:00", "status": "CANARY_PASSED",
            "events": events, "failure": None}


def public_summary(packet):
    return {"schema": "cp_canary_public_summary.v1", "status": "CANARY_PASSED",
            "run": packet["expected_run"], "phase": "canary", "source_pins": deepcopy(packet["source_pins"]),
            "container_pins": deepcopy(packet["container_pins"]), "user_id": 11, "token_id": 99,
            "token_name": packet["canary_token_name"], "scope": "read:user", "proof_stages": list(STAGES)}


def passed(packet):
    return {"status": "CANARY_PASSED", "helper_exit_code": 0,
            "run": packet["expected_run"], "stderr_sha256": "a" * 64,
            "receipt_sha256": "b" * 64, "receipt_summary": public_summary(packet)}


def child(observation=None, *, returncode=0, stdout=None, stderr=""):
    return subprocess.CompletedProcess(["synthetic-ssh"], returncode,
                                       json.dumps(observation) if stdout is None else stdout, stderr)


class FakePath:
    def __init__(self, root, name):
        self.root = root
        self.name = name

    def exists(self):
        return self.name in self.root.records


class FakeRoot:
    def __init__(self):
        self.records = {}
        self.events = []
        self.fail_save = None

    def __truediv__(self, name):
        return FakePath(self, name)

    def save(self, root, name, data):
        if root is not self:
            raise AssertionError("wrong output root")
        if name == self.fail_save:
            self.events.append(("save_failed", name))
            raise OSError("synthetic durable receipt failure")
        if name in self.records:
            raise FileExistsError("synthetic exclusive-create refusal")
        self.records[name] = deepcopy(data)
        self.events.append(("save", name))


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.packet = packet_fixture()
        self.root = FakeRoot()
        self.save_patch = patch.object(launcher, "save_new", side_effect=self.root.save)
        self.save = self.save_patch.start()
        self.addCleanup(self.save_patch.stop)
        self.run_patch = patch.object(launcher.subprocess, "run")
        self.run = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.replies = [child(staged(self.packet)), child(passed(self.packet))]
        self.run.side_effect = self.fake_run

    def fake_run(self, argv, **kwargs):
        self.root.events.append(("subprocess", deepcopy(argv)))
        if not self.replies:
            raise AssertionError("unexpected additional contact")
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def execute(self):
        return launcher.execute(self.root, self.packet, PACKET_HASH, AUTHORITY)

    def test_approval_attempt_and_each_intent_precede_exact_single_contacts(self):
        self.assertEqual(self.execute(), 0)
        self.assertEqual(self.root.events, [
            ("save", "live-canary-approval.json"), ("save", "live-canary-attempt.json"),
            ("save", "live-staging-intent.json"),
            ("subprocess", self.packet["staging_ssh_argv"]),
            ("save", "live-staging-result.json"), ("save", "live-canary-intent.json"),
            ("subprocess", self.packet["canary_ssh_argv"]),
            ("save", "live-canary-result.json"),
        ])
        approval = self.root.records["live-canary-approval.json"]
        self.assertEqual(approval["authority_reference"], AUTHORITY)
        self.assertEqual(approval["phase"], "CANARY_ONLY")
        self.assertEqual(approval["packet_sha256"], PACKET_HASH)
        attempt = self.root.records["live-canary-attempt.json"]
        self.assertEqual(attempt["maximum_attempts"], 1)
        self.assertIs(attempt["retry"], False)
        self.assertEqual(attempt["packet_sha256"], PACKET_HASH)
        for phase in ("staging", "canary"):
            intent = self.root.records["live-" + phase + "-intent.json"]
            source = self.packet[phase + "_python_source"]
            self.assertEqual(intent, {"packet_sha256": PACKET_HASH, "phase": phase,
                                      "source_sha256": launcher.sha(source.encode())})
        self.assertEqual(self.run.call_count, 2)
        self.assertEqual(self.run.call_args_list[0].args, (self.packet["staging_ssh_argv"],))
        self.assertEqual(self.run.call_args_list[0].kwargs, {
            "input": self.packet["staging_python_source"], "text": True,
            "capture_output": True, "timeout": 60,
        })
        self.assertEqual(self.run.call_args_list[1].args, (self.packet["canary_ssh_argv"],))
        self.assertEqual(self.run.call_args_list[1].kwargs, {
            "input": self.packet["canary_python_source"], "text": True,
            "capture_output": True, "timeout": 300,
        })
        self.assertEqual(self.root.records["live-staging-result.json"]["status"], "STAGING_VERIFIED")
        self.assertEqual(self.root.records["live-canary-result.json"]["status"], "CANARY_PASSED_REVIEW_REQUIRED")

    def test_prior_attempt_refuses_all_contacts_and_new_records(self):
        self.root.records["live-canary-attempt.json"] = {"existing": True}
        with self.assertRaisesRegex(launcher.Refused, "attempt_already_recorded_no_retry"):
            self.execute()
        self.run.assert_not_called()
        self.save.assert_not_called()
        self.assertEqual(self.root.records, {"live-canary-attempt.json": {"existing": True}})

    def test_invalid_staging_observations_never_contact_canary(self):
        wrong_status = staged(self.packet)
        wrong_status["status"] = "CANARY_PASSED"
        wrong_pins = staged(self.packet)
        wrong_pins["source_pins"]["stage-source.py"] = "9" * 64
        wrong_run = staged(self.packet)
        wrong_run["run"] = "wrong-run"
        cases = [child(wrong_status), child(wrong_pins), child(wrong_run),
                 child(staged(self.packet), returncode=1), child([], stdout="[]"),
                 child(stdout="not JSON"), child(stdout="null")]
        for reply in cases:
            with self.subTest(stdout=reply.stdout):
                self.root.records.clear()
                self.root.events.clear()
                self.run.reset_mock()
                self.replies = [reply]
                self.assertEqual(self.execute(), 2)
                self.assertEqual(self.run.call_count, 1)
                self.assertNotIn("live-canary-intent.json", self.root.records)
                self.assertNotIn("live-canary-result.json", self.root.records)
                self.assertEqual(self.root.records["live-staging-result.json"]["status"], "UNKNOWN_OUTCOME_NO_RETRY")

    def test_staging_timeout_or_interruption_keeps_markers_without_canary_or_retry(self):
        for error, expected in (
            (subprocess.TimeoutExpired(["synthetic-ssh"], 60), "UNKNOWN_TIMEOUT_NO_RETRY"),
            (KeyboardInterrupt(), "UNKNOWN_INTERRUPTION_OR_TRANSPORT_NO_RETRY"),
            (OSError("synthetic transport interruption"), "UNKNOWN_INTERRUPTION_OR_TRANSPORT_NO_RETRY"),
        ):
            with self.subTest(error=type(error).__name__):
                self.root.records.clear()
                self.root.events.clear()
                self.run.reset_mock()
                self.replies = [error]
                self.assertEqual(self.execute(), 2)
                self.assertEqual(self.run.call_count, 1)
                self.assertEqual(self.root.records["live-staging-result.json"]["status"], expected)
                self.assertIn("live-canary-attempt.json", self.root.records)
                self.assertIn("live-staging-intent.json", self.root.records)
                self.assertNotIn("live-canary-intent.json", self.root.records)
                with self.assertRaises(launcher.Refused):
                    self.execute()
                self.assertEqual(self.run.call_count, 1)

    def test_invalid_canary_exit_status_helper_or_receipt_binding_never_passes(self):
        variants = []
        for path, value in ((["status"], "STOPPED"), (["helper_exit_code"], 2),
                            (["run"], "wrong-run"), (["receipt_summary", "status"], "STOPPED"),
                            (["receipt_summary", "phase"], "bootstrap"),
                            (["receipt_summary", "run"], "wrong-run"),
                            (["receipt_summary", "source_pins"], {"orchestrator.py": "9" * 64}),
                            (["receipt_summary", "container_pins"], {}),
                            (["receipt_summary", "proof_stages"], STAGES[:-1]),
                            (["receipt_summary", "user_id"], True),
                            (["receipt_summary", "token_id"], 2),
                            (["receipt_summary"], []), (["receipt_summary"], None)):
            observation = passed(self.packet)
            target = observation
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variants.append(child(observation))
        variants.extend([child(passed(self.packet), returncode=1), child(stdout="malformed canary output")])
        for reply in variants:
            with self.subTest(stdout=reply.stdout, rc=reply.returncode):
                self.root.records.clear()
                self.root.events.clear()
                self.run.reset_mock()
                self.replies = [child(staged(self.packet)), reply]
                self.assertEqual(self.execute(), 2)
                self.assertEqual(self.run.call_count, 2)
                self.assertNotEqual(self.root.records["live-canary-result.json"]["status"], "CANARY_PASSED_REVIEW_REQUIRED")
                with self.assertRaises(launcher.Refused):
                    self.execute()
                self.assertEqual(self.run.call_count, 2)

    def test_uncertain_canary_timeout_preserves_attempt_and_never_retries(self):
        self.replies = [child(staged(self.packet)), subprocess.TimeoutExpired(["synthetic-ssh"], 300)]
        self.assertEqual(self.execute(), 2)
        self.assertEqual(self.run.call_count, 2)
        self.assertEqual(self.root.records["live-canary-result.json"]["status"], "UNKNOWN_TIMEOUT_NO_RETRY")
        for name in ("live-canary-approval.json", "live-canary-attempt.json",
                     "live-staging-intent.json", "live-staging-result.json", "live-canary-intent.json"):
            self.assertIn(name, self.root.records)
        with self.assertRaises(launcher.Refused):
            self.execute()
        self.assertEqual(self.run.call_count, 2)

    def test_failed_receipt_write_prevents_next_contact_and_preserves_attempt(self):
        self.root.fail_save = "live-staging-result.json"
        with self.assertRaises(OSError):
            self.execute()
        self.assertEqual(self.run.call_count, 1)
        self.assertIn("live-canary-attempt.json", self.root.records)
        self.assertIn("live-staging-intent.json", self.root.records)
        self.assertNotIn("live-canary-intent.json", self.root.records)
        with self.assertRaises(launcher.Refused):
            self.execute()
        self.assertEqual(self.run.call_count, 1)

    def test_failed_approval_attempt_or_intent_write_prevents_first_contact(self):
        for name in ("live-canary-approval.json", "live-canary-attempt.json", "live-staging-intent.json"):
            with self.subTest(marker=name):
                self.root.records.clear()
                self.root.events.clear()
                self.run.reset_mock()
                self.root.fail_save = name
                with self.assertRaises(OSError):
                    self.execute()
                self.run.assert_not_called()

    def test_malformed_stdout_and_stderr_are_stored_as_hashes_only(self):
        stdout = "synthetic unstructured sensitive stdout"
        stderr = "synthetic sensitive stderr"
        self.replies = [child(stdout=stdout, stderr=stderr)]
        self.assertEqual(self.execute(), 2)
        result = self.root.records["live-staging-result.json"]
        self.assertEqual(result["stdout_sha256"], launcher.sha(stdout.encode()))
        self.assertEqual(result["stderr_sha256"], launcher.sha(stderr.encode()))
        serialized = json.dumps(self.root.records)
        self.assertNotIn(stdout, serialized)
        self.assertNotIn(stderr, serialized)
        self.assertNotIn("observation", result)

    def test_unexpected_json_fields_and_malformed_summary_are_hash_only(self):
        variants = []
        observation = staged(self.packet)
        observation["unexpected"] = SECRET_SENTINEL
        variants.append(("staging", observation))
        observation = passed(self.packet)
        observation["unexpected"] = SECRET_SENTINEL
        variants.append(("canary", observation))
        observation = passed(self.packet)
        observation["receipt_summary"]["raw_body"] = SECRET_SENTINEL
        variants.append(("canary", observation))
        observation = passed(self.packet)
        observation["receipt_summary"]["token_name"] = SECRET_SENTINEL
        variants.append(("canary", observation))
        observation = passed(self.packet)
        observation["receipt"] = {"events": [{"body": SECRET_SENTINEL}]}
        variants.append(("canary", observation))
        for phase, observation in variants:
            with self.subTest(phase=phase, fields=list(observation)):
                self.root.records.clear()
                self.root.events.clear()
                self.run.reset_mock()
                raw = json.dumps(observation)
                self.replies = ([child(stdout=raw)] if phase == "staging"
                                else [child(staged(self.packet)), child(stdout=raw)])
                self.assertEqual(self.execute(), 2)
                result = self.root.records["live-" + phase + "-result.json"]
                self.assertNotIn("observation", result)
                self.assertEqual(result["stdout_sha256"], launcher.sha(raw.encode()))
                self.assertNotIn(SECRET_SENTINEL, json.dumps(self.root.records))
                self.assertEqual(self.run.call_count, 1 if phase == "staging" else 2)


class ReceiptContractTests(unittest.TestCase):
    def setUp(self):
        self.packet = packet_fixture()
        self.receipt = native_receipt(self.packet)

    def test_all_eleven_native_stages_derive_exact_closed_summary(self):
        summary = launcher.summarize_receipt(self.receipt, self.packet)
        self.assertEqual(summary, public_summary(self.packet))
        self.assertEqual(summary["proof_stages"], STAGES)
        self.assertNotIn("events", summary)
        self.assertNotIn("started_at", summary)
        self.assertNotIn("binding", summary)
        self.assertEqual(launcher.safe_observation(passed(self.packet), "canary", self.packet), passed(self.packet))

    def test_receipt_and_event_extra_fields_never_echo(self):
        for target in ("receipt", "event", "binding"):
            with self.subTest(target=target):
                data = deepcopy(self.receipt)
                if target == "receipt":
                    data["raw_body"] = SECRET_SENTINEL
                elif target == "event":
                    data["events"][6]["code"] = SECRET_SENTINEL
                else:
                    for index in (5, 7, 8, 9):
                        data["events"][index]["binding"]["token_value"] = SECRET_SENTINEL
                result = launcher.summarize_receipt(data, self.packet)
                self.assertIsNone(result)
                self.assertNotIn(SECRET_SENTINEL, repr(result))

    def test_receipt_source_image_schema_failure_and_proof_drift_refuse(self):
        variants = []
        for key, value in (("schema", "wrong"), ("run", "wrong"), ("phase", "bootstrap"),
                           ("status", "STOPPED"), ("failure", SECRET_SENTINEL),
                           ("source_pins", {}), ("container_pins", {}),
                           ("started_at", None), ("started_at", "x" * 65)):
            data = deepcopy(self.receipt)
            data[key] = value
            variants.append(data)
        data = deepcopy(self.receipt)
        data["events"].pop(8)
        variants.append(data)
        data = deepcopy(self.receipt)
        data["events"][6]["stage"] = "same_token_401"
        variants.append(data)
        data = deepcopy(self.receipt)
        data["events"][7], data["events"][8] = data["events"][8], data["events"][7]
        variants.append(data)
        for data in variants:
            with self.subTest(changed=list(data)):
                result = launcher.summarize_receipt(data, self.packet)
                self.assertIsNone(result)
                self.assertNotIn(SECRET_SENTINEL, repr(result))

    def test_typed_uid_fresh_token_id_and_exact_binding_are_required(self):
        for field, value in (("kind", "bootstrap"), ("token_id", True), ("token_id", "99"),
                             ("token_id", 0), ("token_id", 2), ("token_id", 16),
                             ("token_id", 26), ("token_id", 28),
                             ("user_id", True), ("user_id", "11"), ("user_id", 12),
                             ("username", SECRET_SENTINEL), ("token_name", SECRET_SENTINEL),
                             ("scope", "all"), ("created_unix", True),
                             ("created_unix", "1800000000"), ("created_unix", 0)):
            with self.subTest(field=field, value_type=type(value).__name__):
                data = deepcopy(self.receipt)
                for index in (5, 7, 8, 9):
                    data["events"][index]["binding"][field] = value
                result = launcher.summarize_receipt(data, self.packet)
                self.assertIsNone(result)
                self.assertNotIn(SECRET_SENTINEL, repr(result))
        for uid in (True, "11", 0, 5):
            with self.subTest(uid_type=type(uid).__name__):
                data = deepcopy(self.receipt)
                data["events"][3]["user_id"] = uid
                self.assertIsNone(launcher.summarize_receipt(data, self.packet))
        data = deepcopy(self.receipt)
        data["events"][8]["binding"]["token_id"] = 100
        self.assertIsNone(launcher.summarize_receipt(data, self.packet))

    def test_transport_summary_requires_closed_typed_success_proofs(self):
        cases = []
        for field, value in (("schema", "wrong"), ("user_id", True), ("user_id", 5),
                             ("token_id", True), ("token_id", 28), ("scope", "all"),
                             ("proof_stages", STAGES[:-1]), ("container_pins", {}),
                             ("source_pins", {}), ("raw_body", SECRET_SENTINEL)):
            observation = passed(self.packet)
            observation["receipt_summary"][field] = value
            cases.append(observation)
        for field, value in (("helper_exit_code", True), ("helper_exit_code", "0"),
                             ("receipt_sha256", SECRET_SENTINEL), ("stderr_sha256", "X" * 64),
                             ("raw_body", SECRET_SENTINEL), ("code", SECRET_SENTINEL)):
            observation = passed(self.packet)
            observation[field] = value
            cases.append(observation)
        observation = passed(self.packet)
        del observation["receipt_sha256"]
        cases.append(observation)
        for observation in cases:
            with self.subTest(fields=list(observation)):
                result = launcher.safe_observation(observation, "canary", self.packet)
                self.assertIsNone(result)
                self.assertNotIn(SECRET_SENTINEL, repr(result))


class MainTests(unittest.TestCase):
    def setUp(self):
        self.packet = packet_fixture()
        self.guarded_paths = []
        self.run_patch = patch.object(launcher.subprocess, "run", side_effect=AssertionError("no real contact"))
        self.run = self.run_patch.start()
        self.addCleanup(self.run_patch.stop)
        self.execute_patch = patch.object(launcher, "execute", return_value=0)
        self.execute = self.execute_patch.start()
        self.addCleanup(self.execute_patch.stop)
        self.guard_patch = patch.object(launcher, "guarded", side_effect=self.fake_guarded)
        self.guarded = self.guard_patch.start()
        self.addCleanup(self.guard_patch.stop)
        self.umask_patch = patch.object(launcher.os, "umask", return_value=0o077)
        self.umask_patch.start()
        self.addCleanup(self.umask_patch.stop)

    def raw(self):
        return json.dumps(self.packet, sort_keys=True).encode()

    def fake_guarded(self, path):
        self.guarded_paths.append(path.name)
        if path.name == "canary-execution-packet.json":
            return self.raw()
        if path.name == "execute_canary.py":
            return LAUNCHER_BYTES
        if path.name == "registry_known_hosts":
            return KNOWN_HOSTS_BYTES
        raise AssertionError("unexpected protected read")

    def invoke(self, *extra, expected_hash=None):
        argv = ["execute_canary.py", "--expect-packet-sha256", expected_hash or launcher.sha(self.raw()), *extra]
        with patch.object(launcher.sys, "argv", argv), patch.object(launcher.sys, "stdout", new_callable=io.StringIO) as output:
            result = launcher.main()
        return result, output.getvalue()

    def test_default_is_plan_without_execute_or_subprocess(self):
        result, stdout = self.invoke()
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout), {"status": "PLAN_ONLY_NO_CONTACT",
                                              "packet_sha256": launcher.sha(self.raw())})
        self.execute.assert_not_called()
        self.run.assert_not_called()
        self.assertEqual(self.guarded_paths, ["canary-execution-packet.json", "execute_canary.py", "registry_known_hosts"])

    def test_apply_requires_nonblank_reference_and_both_explicit_scope_flags(self):
        cases = [[], ["--approval-reference", AUTHORITY],
                 ["--approval-reference", AUTHORITY, "--approve-registry-docker-exception"],
                 ["--approval-reference", AUTHORITY, "--approve-exact-token-row-write"],
                 ["--approve-registry-docker-exception", "--approve-exact-token-row-write"],
                 ["--approval-reference", "  ", "--approve-registry-docker-exception", "--approve-exact-token-row-write"]]
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaisesRegex(launcher.Refused, "explicit_live_scope_unbound"):
                    self.invoke("--apply", *args)
        self.execute.assert_not_called()
        self.run.assert_not_called()

    def test_apply_dispatches_only_bound_packet_hash_and_authority(self):
        result, stdout = self.invoke("--apply", "--approval-reference", AUTHORITY,
                                     "--approve-registry-docker-exception", "--approve-exact-token-row-write")
        self.assertEqual(result, 0)
        self.assertEqual(stdout, "")
        args = self.execute.call_args.args
        self.assertEqual(args[0], launcher.Path(launcher.__file__).resolve().parent)
        self.assertEqual(args[1:], (self.packet, launcher.sha(self.raw()), AUTHORITY))
        self.run.assert_not_called()

    def test_packet_hash_drift_refuses_before_source_reads_or_execution(self):
        with self.assertRaisesRegex(launcher.Refused, "packet_drift"):
            self.invoke(expected_hash="0" * 64)
        self.assertEqual(self.guarded_paths, ["canary-execution-packet.json"])
        self.execute.assert_not_called()
        self.run.assert_not_called()

    def test_scope_and_source_pin_drift_refuse_before_execution(self):
        baseline = deepcopy(self.packet)
        variants = [("phase", "BOOTSTRAP", "scope"),
                    ("maximum_execution_attempts", 2, "scope"),
                    ("no_automatic_retry", False, "scope"),
                    ("launcher_sha256", "0" * 64, "launcher_drift"),
                    ("staging_source_sha256", "0" * 64, "remote_source_drift"),
                    ("canary_wrapper_source_sha256", "0" * 64, "remote_source_drift"),
                    ("known_hosts_sha256", "0" * 64, "host_key_pin_drift")]
        for key, value, reason in variants:
            with self.subTest(field=key):
                self.packet = deepcopy(baseline)
                self.packet[key] = value
                with self.assertRaisesRegex(launcher.Refused, reason):
                    self.invoke()
        self.execute.assert_not_called()
        self.run.assert_not_called()

    def test_protected_input_refusal_never_reaches_execute(self):
        self.guarded.side_effect = launcher.Refused("input_protection")
        with self.assertRaisesRegex(launcher.Refused, "input_protection"):
            self.invoke()
        self.execute.assert_not_called()
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
