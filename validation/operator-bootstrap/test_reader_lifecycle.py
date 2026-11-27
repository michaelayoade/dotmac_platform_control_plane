"""Synthetic lifecycle failures and adapter refusals; no real effect is called."""
import copy
import json
from pathlib import Path
import runpy
import time
import unittest
from reader_lifecycle import make_reader_backend, run_reader, Refused, USER, TOKEN_NAME, SCOPE
from reader_revocation_sql import build_revocation_sql

CORE = Path(__file__).resolve().parent / "core"


def metadata():
    return {"users": [{"id": 10, "name": USER, "type": 0, "is_admin": False,
        "is_active": True, "is_restricted": False, "prohibit_login": False,
        "must_change_password": False, "login_type": 0, "login_source": 0}],
        "tokens": [], "org_memberships": [{"org_id": 2, "org_name": "dotmac", "is_owner": False}],
        "team_memberships": [{"team_id": 6, "org_id": 2, "org_name": "dotmac",
            "team_name": "cp-bundle-readers", "authorization": 1}],
        "teams": [{"team_id": 6, "org_id": 2, "org_name": "dotmac",
            "team_name": "cp-bundle-readers", "authorization": 1, "member_count": 1,
            "team_repo_count": 0, "can_create_org_repo": False, "includes_all_repositories": False,
            "units": [{"type": 9, "access_mode": 1}, {"type": 1, "access_mode": 0}]}],
        "public_keys": [], "gpg_keys": [], "owned_repos": [], "collaborations": [], "access_rows": []}


class Log:
    failed = False
    def __init__(self):
        self.events = []
        self.status = None
        self.failure = None
    def write(self, stage, **fields):
        self.events.append((stage, fields))
    def finish(self, status, failure=None):
        self.status, self.failure = status, failure


class ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = runpy.run_path(str(CORE / "host_gate.py"))
        cls.core = runpy.run_path(str(CORE / "orchestrator.py"))
        cls.audit = runpy.run_path(str(CORE / "audit.py"))

    def setUp(self):
        self.meta = metadata()
        self.log = Log()
        self.calls = []
        self.cfg = {"cp_require_restricted": False, "forgejo_container_id": "synthetic"}
        self.mode = None
        def request(kind, value):
            self.calls.append(("get", value))
            if value is None or value == "0" * 40:
                return {"status": 200 if self.mode == "public" else 404}
            if self.mode == "positive403" and self.meta["tokens"]:
                return {"status": 403}
            return {"status": 200 if self.meta["tokens"] else 401}
        def acquire(value):
            self.calls.append(("acquire", None))
            if self.mode == "acquire_failure":
                raise RuntimeError(value)
            return {"artifact_count": 14, "artifacts": {str(i): "a" * 64 for i in range(14)}}
        self.io = make_reader_backend(self.cfg, self.host, {},
            {"evaluate": lambda *a: [{"ok": True}]},
            {"build_revocation_sql": build_revocation_sql}, self.core, request, acquire)
        self.io.metadata = lambda user: copy.deepcopy(self.meta)
        def mint(*args):
            self.assertEqual(args, (USER, TOKEN_NAME, SCOPE))
            self.calls.append(("mint", None))
            self.meta["tokens"] = [{"id": 31, "uid": 10, "name": TOKEN_NAME,
                                   "scope": SCOPE, "created_unix": int(time.time())}]
            if self.mode == "lost_mint":
                raise RuntimeError("synthetic-sensitive-detail")
            return b"a" * 40
        self.io.mint = mint
        def revoke(binding):
            self.calls.append(("revoke", binding["token_id"]))
            self.assertEqual(binding["kind"], "reader")
            self.assertEqual(binding["token_id"], 31)
            self.meta["tokens"] = []
            if self.mode == "lost_delete":
                raise RuntimeError("synthetic-sensitive-detail")
        self.io.revoke = revoke

    def run_case(self, mode=None):
        self.mode = mode
        return run_reader(self.cfg, self.io, self.log)

    def count(self, kind):
        return len([x for x in self.calls if x[0] == kind])

    def test_success_exact_get_controls_acquire_cleanup_and_fresh_audit(self):
        self.assertTrue(self.run_case())
        self.assertEqual((self.count("mint"), self.count("acquire"), self.count("revoke")), (1, 1, 1))
        gets = [x[1] for x in self.calls if x[0] == "get"]
        self.assertEqual(gets, [None, "0" * 40, "a" * 40, "a" * 40])
        stages = [x[0] for x in self.log.events]
        self.assertLess(stages.index("before_mint_reader"), stages.index("reader_token_bound"))
        self.assertIn("reader_fresh_ready_audit", stages)
        self.assertNotIn("a" * 40, repr(self.log.events))

    def test_acquisition_failure_still_cleans_once_and_retains_failure(self):
        self.assertFalse(self.run_case("acquire_failure"))
        self.assertEqual(self.count("revoke"), 1)
        self.assertEqual(self.meta["tokens"], [])
        self.assertNotIn("a" * 40, self.log.failure)

    def test_positive403_not_accepted_and_cleaned(self):
        self.assertFalse(self.run_case("positive403"))
        self.assertEqual(self.count("acquire"), 0)
        self.assertEqual(self.count("revoke"), 1)

    def test_public_endpoint_prevents_mint(self):
        self.assertFalse(self.run_case("public"))
        self.assertEqual(self.count("mint"), 0)

    def test_lost_mint_reconciles_once_but_cannot_claim401(self):
        self.assertFalse(self.run_case("lost_mint"))
        self.assertEqual((self.count("mint"), self.count("revoke")), (1, 1))
        self.assertNotIn("same_token_401", [x[0] for x in self.log.events])
        self.assertNotIn("synthetic-sensitive-detail", self.log.failure)

    def test_lost_delete_never_retries(self):
        self.assertFalse(self.run_case("lost_delete"))
        self.assertEqual(self.count("revoke"), 1)
        self.assertEqual(self.count("mint"), 1)

    def test_standing_tokens_prevent_mint(self):
        self.meta["tokens"] = [{"id": 2}]
        self.assertFalse(self.run_case())
        self.assertEqual(self.count("mint"), 0)

    def test_exact_identity_and_unique_units(self):
        mutations = (
            lambda m: m["users"][0].update(id=11),
            lambda m: m["users"][0].update(is_restricted=True),
            lambda m: m["org_memberships"][0].update(is_owner=True),
            lambda m: m["teams"][0].update(member_count=2),
            lambda m: m["teams"][0]["units"].append({"type": 1, "access_mode": 0}),
            lambda m: m.update(public_keys=[{"id": 1}]),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                m = metadata()
                mutate(m)
                with self.assertRaises(Exception):
                    self.io.require_reader_ready(m)

    def test_all_creation_and_api_mutations_refused(self):
        with self.assertRaises(Refused):
            self.io.create_user(USER, restricted=False)
        for kind in ("create_team", "add_member", "bootstrap_positive_get"):
            with self.assertRaises(Refused):
                self.io.request(kind, "a" * 40)

    def test_backend_mint_cannot_use_other_principal_or_remint(self):
        calls = []
        backend = make_reader_backend(self.cfg, self.host,
            {"docker": lambda args, **kw: calls.append((args, kw)) or b"a" * 40},
            {}, {"build_revocation_sql": build_revocation_sql}, self.core,
            lambda *a: {"status": 401}, lambda v: None)
        backend.check_container = lambda kind: None
        for args in (("dotmac-admin", TOKEN_NAME, SCOPE), (USER, TOKEN_NAME, "write:package")):
            with self.assertRaises(Refused):
                backend.mint(*args)
        self.assertEqual(calls, [])
        backend.mint(USER, TOKEN_NAME, SCOPE)
        with self.assertRaises(Refused):
            backend.mint(USER, TOKEN_NAME, SCOPE)
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][1]["sensitive"], True)

    def test_noninteger_or_body_bearing_status_refused(self):
        for response in ({"status": 401.0}, {"status": 401, "body": "synthetic"}):
            backend = make_reader_backend(self.cfg, self.host, {}, {}, {}, self.core,
                lambda *a: response, lambda v: None)
            with self.assertRaises(Refused):
                backend.request("reader_get", None)

    def native_ready_backend(self):
        # Evaluate only captured nonsecret metadata through the frozen core
        # readiness owner; transport, Docker, mint and acquisition are unused.
        def no_effect(*args, **kwargs):
            raise AssertionError("readiness must not call an effect")
        return make_reader_backend(self.cfg, self.host, {}, self.audit,
            {"build_revocation_sql": build_revocation_sql}, self.core,
            no_effect, no_effect)

    def captured_metadata(self):
        return json.loads(Path(__file__).with_name("native-metadata.fixture.json").read_text())

    def test_captured_optional_owner_column_uses_real_core_audit(self):
        native = self.captured_metadata()
        self.assertIn("is_owner", native["org_memberships"][0])
        self.assertIsNone(native["org_memberships"][0]["is_owner"])
        backend = self.native_ready_backend()
        self.assertIsNone(backend.require_reader_ready(native))
        # False remains a distinct, explicitly supported observation.
        native["org_memberships"][0]["is_owner"] = False
        self.assertIsNone(backend.require_reader_ready(native))
        checks = self.audit["evaluate"](native, {
            "forgejo_user": USER, "forgejo_org": "dotmac",
            "forgejo_team": "cp-bundle-readers", "require_restricted": False}, "pre")
        self.assertTrue(checks)
        self.assertTrue(all(check["ok"] for check in checks))
        self.assertEqual([check["ok"] for check in checks
                          if check["check"] == "user_not_in_owners"], [True])

    def test_captured_owner_flag_requires_present_null_or_false(self):
        backend = self.native_ready_backend()
        for value in (True, 0, 1, 0.0, "false", "null", "", [], {}):
            with self.subTest(value=value):
                native = self.captured_metadata()
                native["org_memberships"][0]["is_owner"] = value
                with self.assertRaises(Refused):
                    backend.require_reader_ready(native)
        native = self.captured_metadata()
        del native["org_memberships"][0]["is_owner"]
        with self.assertRaises(Refused):
            backend.require_reader_ready(native)

    def test_captured_team_grant_identity_and_zero_token_guards_remain_strict(self):
        backend = self.native_ready_backend()
        mutations = (
            lambda m: m["users"][0].update(id=11),
            lambda m: m["users"][0].update(is_admin=True),
            lambda m: m["users"][0].update(is_restricted=True),
            lambda m: m["org_memberships"][0].update(org_id=3),
            lambda m: m["team_memberships"][0].update(team_id=7),
            lambda m: m["team_memberships"][0].update(team_name="Owners", authorization=4),
            lambda m: m["teams"][0].update(authorization=4),
            lambda m: m["teams"][0].update(member_count=2),
            lambda m: m["teams"][0]["units"][0].update(access_mode=2),
            lambda m: m["teams"][0]["units"].append({"type": 9, "access_mode": 1}),
            lambda m: m.update(access_rows=[{"repo_id": 1, "mode": 1}]),
            lambda m: m.update(public_keys=[{"id": 1}]),
            lambda m: m.update(tokens=[{"id": 31}]),
        )
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                native = self.captured_metadata()
                mutate(native)
                with self.assertRaises((Refused, self.host["Refused"])):
                    backend.require_reader_ready(native)
