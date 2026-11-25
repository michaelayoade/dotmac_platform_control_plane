"""Pure orchestrator tests: synthetic values, in-memory effects, no host backend.

The canary receipt is a conditional caller precondition for run_bootstrap. These
unit tests do not grant stage authority or qualify a production receipt.
"""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import orchestrator as stage


NOW = 1_800_000_000
TOKEN = "a" * 40  # Synthetic test value only.
CFG = {
    "canary_username": "sql-revocation-canary",
    "canary_token_name": "canary-once",
    "bootstrap_token_name": "bootstrap-once",
    "cp_require_restricted": True,
}


def principal(username, uid, *, owner=False, restricted=True):
    return {
        "users": [{
            "id": uid, "name": username, "lower_name": username,
            "type": 0, "is_active": True, "is_admin": owner,
            "is_restricted": restricted, "prohibit_login": False,
            "login_type": 0, "login_source": 0,
            "email": username + "@invalid.example",
        }],
        "tokens": [],
        "teams": [{"team_id": 1, "team_name": "Owners", "org_id": 2,
                   "org_name": "dotmac", "authorization": 4, "member_count": 1}] if owner else [],
        "org_memberships": [{"org_id": 2, "org_name": "dotmac"}] if owner else [],
        "team_memberships": [{"team_id": 1, "team_name": "Owners", "org_id": 2,
                              "org_name": "dotmac", "authorization": 4}] if owner else [],
        "database": "forgejo", "transaction_read_only": "on",
        "owned_repos": [], "public_keys": [], "gpg_keys": [],
        "collaborations": [], "access_rows": [],
    }


def cp_team(member_count=0):
    return {"team_id": 23, "team_name": "cp-bundle-readers", "org_id": 2,
            "org_name": "dotmac", "authorization": 1, "member_count": member_count,
            "team_repo_count": 0, "can_create_org_repo": False,
            "includes_all_repositories": False, "units": [{"type": 9, "access_mode": 1}]}


def old_token():
    return {"id": 7, "uid": 1, "name": "existing-owner-token",
            "scope": "read:organization", "created_unix": NOW - 3600}


def new_token(username, name, scope):
    return {"id": 99, "uid": 1 if username == "dotmac-admin" else 11,
            "name": name, "scope": scope, "created_unix": NOW}


class FakeLog:
    def __init__(self, events, fail_at=None):
        self.events = events
        self.records = []
        self.failed = False
        self.fail_at = fail_at
        self.final = None

    def write(self, event, **fields):
        if self.failed:
            raise OSError("log already failed")
        if event == self.fail_at:
            self.failed = True
            self.events.append(("log_failed", event))
            raise OSError("synthetic log failure")
        record = {"event": event, **deepcopy(fields)}
        self.records.append(record)
        self.events.append(("log", event))

    def finish(self, status, **fields):
        self.final = {"status": status, **deepcopy(fields)}
        self.events.append(("finish", status))


class FakeIO:
    """Implements stage effects without importing any actual backend."""
    def __init__(self, log):
        self.log = log
        self.events = log.events
        self.owner = principal("dotmac-admin", 1, owner=True, restricted=False)
        self.owner["tokens"] = [old_token()]
        self.rows = {"dotmac-admin": self.owner}
        self.team_exists = False
        self.returned_team_id = 23
        self.revoked = False
        self.mint_response = (TOKEN + "\n").encode("ascii")
        self.mint_exception = None
        self.after_mint = None
        self.after_team_create = None
        self.after_member_add = None
        self.revoke_exception = None
        self.responses = {}
        self.bound_deletes = []
        self.mint_calls = 0
        self.requests = []
        self.metadata_after_mint = 0
        self.writes_after_failed_log = []

    def _write(self, operation):
        if self.log.failed:
            self.writes_after_failed_log.append(operation)
            raise AssertionError("effect after failed journal")
        self.events.append(("effect", operation))

    def require_absent(self, username, team_absent=False):
        self.events.append(("require_absent", username, team_absent))
        if username in self.rows or (team_absent and self.team_exists):
            raise stage.Stopped("not_absent")

    def create_user(self, username, *, restricted):
        self._write("create_user")
        if username in self.rows:
            raise AssertionError("duplicate user")
        self.rows[username] = principal(username, 12 if username == "cp-bundle-reader" else 11,
                                         restricted=restricted)
        self.events.append(("created", username, restricted))

    def metadata(self, username):
        self.events.append(("metadata", username))
        if self.mint_calls and username != "cp-bundle-reader":
            self.metadata_after_mint += 1
        return deepcopy(self.rows[username])

    def require_canary(self, meta):
        self.events.append(("require_canary",))
        user = meta["users"][0]
        if user["is_admin"] or not user["is_restricted"] or meta["teams"] or meta["owned_repos"]:
            raise stage.Stopped("bad_canary")

    def require_cp_ungranted(self, meta):
        self.events.append(("require_cp_ungranted",))
        if any(meta[key] for key in ("tokens", "teams", "owned_repos", "org_memberships",
                                      "team_memberships", "public_keys", "gpg_keys",
                                      "collaborations", "access_rows")):
            raise stage.Stopped("cp_already_granted")

    def require_owner(self, meta):
        self.events.append(("require_owner",))
        if meta["users"][0]["id"] != 1 or not meta["users"][0]["is_admin"]:
            raise stage.Stopped("bad_owner")

    def _require_cp_identity(self, meta, cp_uid):
        users = meta.get("users", [])
        if (len(users) != 1 or type(users[0].get("id")) is not int
                or users[0]["id"] != cp_uid or users[0].get("name") != "cp-bundle-reader"):
            raise stage.Stopped("cp_uid_drift")

    def _require_cp_team(self, meta, team_id, member_count):
        expected = cp_team(member_count)
        if type(team_id) is not int or team_id != expected["team_id"] or meta["teams"] != [expected]:
            raise stage.Stopped("bad_cp_team_target")

    def require_cp_join_target(self, meta, team_id, cp_uid):
        self.events.append(("require_cp_join_target", team_id, cp_uid))
        self._require_cp_identity(meta, cp_uid)
        self._require_cp_team(meta, team_id, 0)
        if any(meta[key] for key in ("tokens", "org_memberships", "team_memberships",
                                      "owned_repos", "public_keys", "gpg_keys",
                                      "collaborations", "access_rows")):
            raise stage.Stopped("cp_before_join_not_isolated")

    def require_cp_ready(self, meta, team_id, cp_uid):
        self.events.append(("require_cp_ready", team_id, cp_uid))
        self._require_cp_identity(meta, cp_uid)
        self._require_cp_team(meta, team_id, 1)
        expected_member = {"team_id": team_id, "team_name": "cp-bundle-readers", "org_id": 2,
                           "org_name": "dotmac", "authorization": 1}
        if (meta["org_memberships"] != [{"org_id": 2, "org_name": "dotmac"}]
                or meta["team_memberships"] != [expected_member]
                or any(meta[key] for key in ("tokens", "owned_repos", "public_keys", "gpg_keys",
                                             "collaborations", "access_rows"))):
            raise stage.Stopped("bad_cp_metadata")

    def mint(self, username, name, scope):
        self._write("mint")
        self.mint_calls += 1
        self.events.append(("mint", username, name, scope))
        self.rows[username]["tokens"].append(new_token(username, name, scope))
        if self.after_mint:
            self.after_mint(self.rows[username])
        if self.mint_exception:
            raise self.mint_exception
        return self.mint_response

    def request(self, kind, value, *, team_id=None):
        # Validate same synthetic value without putting it in events or logs.
        if value != TOKEN:
            raise AssertionError("unexpected synthetic token")
        self.requests.append((kind, team_id))
        self.events.append(("request", kind, team_id))
        override = self.responses.get(kind)
        if isinstance(override, BaseException):
            raise override
        if override is not None:
            return deepcopy(override)
        if kind in ("canary_get", "bootstrap_positive_get", "bootstrap_revoked_get"):
            return {"status": 401 if self.revoked else 200}
        if kind == "create_team":
            self._write("create_team")
            self.team_exists = True
            self.rows["cp-bundle-reader"]["teams"] = [cp_team()]
            if self.after_team_create:
                self.after_team_create(self.rows["cp-bundle-reader"])
            return {"status": 201, "team_id": self.returned_team_id}
        if kind == "add_member":
            self._write("add_member")
            if not self.team_exists or team_id != 23:
                raise AssertionError("team not bound")
            cp = self.rows["cp-bundle-reader"]
            cp["teams"] = [cp_team(1)]
            cp["org_memberships"] = [{"org_id": 2, "org_name": "dotmac"}]
            cp["team_memberships"] = [{"team_id": 23, "team_name": "cp-bundle-readers", "org_id": 2,
                                       "org_name": "dotmac", "authorization": 1}]
            if self.after_member_add:
                self.after_member_add(cp)
            return {"status": 204}
        raise AssertionError("unexpected request kind")

    def revoke(self, binding):
        self._write("revoke")
        self.bound_deletes.append(deepcopy(binding))
        self.events.append(("delete", binding["token_id"], binding["user_id"]))
        if self.revoke_exception:
            raise self.revoke_exception
        username = binding["username"]
        row = next((row for row in self.rows[username]["tokens"]
                    if row["id"] == binding["token_id"] and row["uid"] == binding["user_id"]
                    and row["name"] == binding["token_name"] and row["scope"] == binding["scope"]
                    and row["created_unix"] == binding["created_unix"]), None)
        if row is None:
            raise AssertionError("refuse wrong deletion")
        self.rows[username]["tokens"].remove(row)
        self.revoked = True


class StageTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(stage.time, "time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def harness(self, fail_at=None):
        events = []
        log = FakeLog(events, fail_at)
        return FakeIO(log), log, events

    def assert_no_value_recorded(self, io, log):
        serialized = json.dumps({"events": io.events, "records": log.records,
                                 "final": log.final, "deletes": io.bound_deletes})
        self.assertNotIn(TOKEN, serialized)
        self.assertNotIn("Authorization", serialized)
        self.assertNotIn("value", serialized)

    def test_canary_200_exact_delete_restore_same_value_401(self):
        io, log, events = self.harness()
        self.assertTrue(stage.run_canary(CFG, io, log))
        self.assertEqual(log.final, {"status": "CANARY_PASSED", "failure": None})
        self.assertEqual(io.requests, [("canary_get", None), ("canary_get", None)])
        self.assertEqual(io.rows[CFG["canary_username"]]["tokens"], [])
        self.assertEqual(io.mint_calls, 1)
        self.assertEqual(io.bound_deletes, [{
            "kind": "canary", "token_id": 99, "user_id": 11,
            "username": CFG["canary_username"], "token_name": CFG["canary_token_name"],
            "scope": "read:user", "created_unix": NOW,
        }])
        order = [events.index(item) for item in (
            ("log", "canary_same_token_200"), ("log", "before_exact_revocation"),
            ("delete", 99, 11), ("log", "revocation_committed_absence"),
            ("log", "same_token_401"),
        )]
        self.assertEqual(order, sorted(order))
        self.assert_no_value_recorded(io, log)

    def test_bootstrap_has_conditional_caller_precondition_and_exact_effects(self):
        # No receipt key is passed: its validation is the entrypoint's job before
        # this pure stage call. Passing this test is not authorization to call it.
        io, log, events = self.harness()
        before_owner = deepcopy(io.owner)
        self.assertTrue(stage.run_bootstrap(CFG, io, log))
        self.assertEqual(log.final, {"status": "BOOTSTRAP_PASSED", "failure": None})
        self.assertEqual(io.requests, [("bootstrap_positive_get", None), ("create_team", None),
                                      ("add_member", 23), ("bootstrap_revoked_get", None)])
        self.assertEqual(io.owner, before_owner)
        self.assertEqual(io.mint_calls, 1)
        self.assertEqual(events.count(("mint", "dotmac-admin", CFG["bootstrap_token_name"],
                                       "write:organization")), 1)
        self.assertIn(("created", "cp-bundle-reader", True), events)
        self.assertEqual(io.bound_deletes, [{
            "kind": "bootstrap", "token_id": 99, "user_id": 1,
            "username": "dotmac-admin", "token_name": CFG["bootstrap_token_name"],
            "scope": "write:organization", "created_unix": NOW,
        }])
        milestones = [("require_absent", "cp-bundle-reader", True),
                      ("require_cp_ungranted",), ("require_owner",),
                      ("log", "bootstrap_token_bound"), ("request", "bootstrap_positive_get", None),
                      ("request", "create_team", None), ("require_cp_join_target", 23, 12),
                      ("request", "add_member", 23), ("require_cp_ready", 23, 12), ("delete", 99, 1),
                      ("log", "revocation_committed_absence"),
                      ("request", "bootstrap_revoked_get", None)]
        positions = [events.index(item) for item in milestones]
        self.assertEqual(positions, sorted(positions))
        self.assert_no_value_recorded(io, log)

    def test_first_cleanup_delete_occurs_after_positive_get_failure_or_exception(self):
        for runner, kind, uid in ((stage.run_canary, "canary_get", 11),
                                  (stage.run_bootstrap, "bootstrap_positive_get", 1)):
            for failure in ({"status": 403}, OSError("synthetic API failure")):
                with self.subTest(stage=runner.__name__, failure=type(failure).__name__):
                    io, log, events = self.harness()
                    io.responses[kind] = failure
                    self.assertFalse(runner(CFG, io, log))
                    self.assertEqual(len(io.bound_deletes), 1)
                    self.assertEqual(io.bound_deletes[0]["token_id"], 99)
                    self.assertEqual(io.bound_deletes[0]["user_id"], uid)
                    self.assertEqual(io.mint_calls, 1)
                    self.assertTrue(io.revoked)
                    self.assertNotIn(("request", "create_team", None), events)
                    self.assert_no_value_recorded(io, log)

    def test_revoke_response_loss_never_retries_delete_or_remints(self):
        for runner in (stage.run_canary, stage.run_bootstrap):
            with self.subTest(stage=runner.__name__):
                io, log, events = self.harness()
                io.revoke_exception = OSError("synthetic lost DELETE response")
                self.assertFalse(runner(CFG, io, log))
                self.assertEqual(io.mint_calls, 1)
                self.assertEqual(len(io.bound_deletes), 1)
                self.assertEqual(events.count(("log", "before_exact_revocation")), 1)
                self.assertFalse(io.revoked)
                self.assertNotIn(("log", "same_token_401"), events)

    def test_unknown_mint_response_reconciles_one_new_row_and_cleans_once_without_pass(self):
        for runner in (stage.run_canary, stage.run_bootstrap):
            for response_lost in (False, True):
                with self.subTest(stage=runner.__name__, response_lost=response_lost):
                    io, log, events = self.harness()
                    if response_lost:
                        io.mint_exception = OSError("synthetic lost mint response")
                    else:
                        io.mint_response = b"unrecognized output"
                    self.assertFalse(runner(CFG, io, log))
                    self.assertEqual(io.mint_calls, 1)
                    self.assertEqual(len(io.bound_deletes), 1)
                    self.assertTrue(io.revoked)
                    # One read identifies the new row; one proves post-delete restoration.
                    self.assertEqual(io.metadata_after_mint, 2)
                    self.assertEqual(io.requests, [])
                    self.assertIn(("log", "revocation_effect_unavailable_lost_mint_response",), events)
                    self.assertNotIn(("log", "same_token_401"), events)
                    self.assert_no_value_recorded(io, log)

    def test_ambiguous_or_drifted_mint_metadata_never_deletes(self):
        def extra(meta):
            meta["tokens"].append({"id": 100, "uid": 1, "name": "other",
                                   "scope": "read:user", "created_unix": NOW})
        def wrong_scope(meta):
            meta["tokens"][-1]["scope"] = "all"
        def wrong_uid(meta):
            meta["tokens"][-1]["uid"] = 1234
        def old_drift(meta):
            meta["tokens"][0]["scope"] = "all"
        def owner_drift(meta):
            meta["users"][0]["is_admin"] = False
        for mutate in (extra, wrong_scope, wrong_uid, old_drift, owner_drift):
            with self.subTest(mutation=mutate.__name__):
                io, log, events = self.harness()
                io.after_mint = mutate
                self.assertFalse(stage.run_bootstrap(CFG, io, log))
                self.assertEqual(io.mint_calls, 1)
                self.assertEqual(io.bound_deletes, [])
                self.assertEqual(io.requests, [])
                self.assertFalse(io.revoked)

    def test_failed_journal_prevents_further_mutations_and_cleanup_writes(self):
        for runner, fail_at in (
            (stage.run_canary, "before_create_canary"),
            (stage.run_canary, "before_mint_canary"),
            (stage.run_canary, "canary_token_bound"),
            (stage.run_canary, "before_exact_revocation"),
            (stage.run_bootstrap, "before_create_cp_reader"),
            (stage.run_bootstrap, "before_mint_bootstrap"),
            (stage.run_bootstrap, "bootstrap_token_bound"),
            (stage.run_bootstrap, "before_create_exact_cp_team"),
            (stage.run_bootstrap, "before_add_exact_cp_member"),
            (stage.run_bootstrap, "before_exact_revocation"),
        ):
            with self.subTest(stage=runner.__name__, fail_at=fail_at):
                io, log, events = self.harness(fail_at)
                self.assertFalse(runner(CFG, io, log))
                self.assertTrue(log.failed)
                self.assertEqual(io.writes_after_failed_log, [])
                failed_index = events.index(("log_failed", fail_at))
                self.assertFalse(any(e[0] == "effect" for e in events[failed_index + 1:]))
                self.assertEqual(io.bound_deletes, [])
                self.assert_no_value_recorded(io, log)

    def test_create201_does_not_bypass_membership_or_metadata_qualification(self):
        for response in ({"status": 403}, {"status": 201}):
            with self.subTest(response=response):
                io, log, events = self.harness()
                io.responses["add_member"] = response
                self.assertFalse(stage.run_bootstrap(CFG, io, log))
                self.assertEqual(len(io.bound_deletes), 1)
                self.assertNotIn(("log", "cp_metadata_ready"), events)
        io, log, events = self.harness()
        # A 204 alone cannot substitute for a matching full metadata snapshot.
        io.responses["add_member"] = {"status": 204}
        self.assertFalse(stage.run_bootstrap(CFG, io, log))
        self.assertEqual(len(io.bound_deletes), 1)
        self.assertNotIn(("log", "cp_metadata_ready"), events)

    def test_bad_returned_team_id_refuses_membership_and_cleans_once(self):
        for bad_id in (True, 0, -1, "23", 999):
            with self.subTest(team_id=bad_id):
                io, log, events = self.harness()
                io.returned_team_id = bad_id
                self.assertFalse(stage.run_bootstrap(CFG, io, log))
                self.assertFalse(any(kind == "add_member" for kind, _ in io.requests))
                self.assertEqual(io.mint_calls, 1)
                self.assertEqual(len(io.bound_deletes), 1)
                self.assertEqual(io.bound_deletes[0]["token_id"], 99)
                self.assertTrue(io.revoked)
                self.assertNotIn(("log", "cp_metadata_ready"), events)

    def test_cp_uid_drift_before_join_refuses_membership_and_cleans_once(self):
        io, log, events = self.harness()
        def drift(cp):
            cp["users"][0]["id"] = 1234
        io.after_team_create = drift
        self.assertFalse(stage.run_bootstrap(CFG, io, log))
        self.assertIn(("require_cp_join_target", 23, 12), events)
        self.assertFalse(any(kind == "add_member" for kind, _ in io.requests))
        self.assertEqual(len(io.bound_deletes), 1)
        self.assertEqual(io.bound_deletes[0]["token_id"], 99)
        self.assertTrue(io.revoked)

    def test_final_cp_uid_drift_fails_metadata_and_cleans_once(self):
        io, log, events = self.harness()
        def drift(cp):
            cp["users"][0]["id"] = 1234
        io.after_member_add = drift
        self.assertFalse(stage.run_bootstrap(CFG, io, log))
        self.assertIn(("request", "add_member", 23), events)
        self.assertIn(("require_cp_ready", 23, 12), events)
        self.assertNotIn(("log", "cp_metadata_ready"), events)
        self.assertEqual(len(io.bound_deletes), 1)
        self.assertTrue(io.revoked)

    def test_prejoin_requires_exact_org_team_grants_and_zero_members(self):
        def wrong_org(cp):
            cp["teams"][0]["org_id"] = 3
        def wrong_name(cp):
            cp["teams"][0]["team_name"] = "other"
        def broad_grants(cp):
            cp["teams"][0]["includes_all_repositories"] = True
        def prior_member(cp):
            cp["teams"][0]["member_count"] = 1
        def unexpected_membership(cp):
            cp["team_memberships"] = [{"team_id": 23}]
        for mutate in (wrong_org, wrong_name, broad_grants, prior_member, unexpected_membership):
            with self.subTest(mutation=mutate.__name__):
                io, log, events = self.harness()
                io.after_team_create = mutate
                self.assertFalse(stage.run_bootstrap(CFG, io, log))
                self.assertFalse(any(kind == "add_member" for kind, _ in io.requests))
                self.assertEqual(len(io.bound_deletes), 1)
                self.assertTrue(io.revoked)

    def test_postdelete_metadata_restore_and_401_are_both_required(self):
        for runner, get_kind in ((stage.run_canary, "canary_get"),
                                  (stage.run_bootstrap, "bootstrap_revoked_get")):
            with self.subTest(stage=runner.__name__):
                io, log, events = self.harness()
                original_revoke = io.revoke
                def revoke_with_drift(binding):
                    original_revoke(binding)
                    io.rows[binding["username"]]["users"][0]["email"] = "drift@invalid.example"
                io.revoke = revoke_with_drift
                self.assertFalse(runner(CFG, io, log))
                self.assertEqual(len(io.bound_deletes), 1)
                self.assertNotIn(("log", "same_token_401"), events)
        io, log, events = self.harness()
        io.responses["bootstrap_revoked_get"] = {"status": 200}
        self.assertFalse(stage.run_bootstrap(CFG, io, log))
        self.assertTrue(io.revoked)
        self.assertEqual(len(io.bound_deletes), 1)
        self.assertNotIn(("log", "same_token_401"), events)

    def test_token_values_are_not_saved_for_later_invocations(self):
        io, log, events = self.harness()
        self.assertTrue(stage.run_canary(CFG, io, log))
        self.assert_no_value_recorded(io, log)
        # A new invocation cannot silently reuse the prior value: the retained
        # canary principal causes an absence refusal before another mint or GET.
        count = len(io.requests)
        self.assertFalse(stage.run_canary(CFG, io, log))
        self.assertEqual(io.mint_calls, 1)
        self.assertEqual(len(io.requests), count)
        self.assert_no_value_recorded(io, log)


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(stage.time, "time", return_value=NOW)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.before = principal("dotmac-admin", 1, owner=True, restricted=False)
        self.before["tokens"] = [old_token()]
        self.after = deepcopy(self.before)
        self.after["tokens"].append(new_token("dotmac-admin", "once", "write:organization"))

    def bind(self):
        return stage.identify_token(self.before, self.after, "dotmac-admin", "once",
                                    "write:organization", "bootstrap", NOW)

    def test_exact_structural_binding_excludes_token_value(self):
        self.assertEqual(self.bind(), {"kind": "bootstrap", "token_id": 99, "user_id": 1,
                                      "username": "dotmac-admin", "token_name": "once",
                                      "scope": "write:organization", "created_unix": NOW})

    def test_invalid_binding_fields_are_refused(self):
        for key, value in (("id", True), ("id", 0), ("id", -1), ("id", "99"),
                           ("uid", True), ("uid", 2), ("uid", "1"),
                           ("name", "other"), ("scope", "all"),
                           ("created_unix", True), ("created_unix", "1800000000"),
                           ("created_unix", NOW - 121), ("created_unix", NOW + 121)):
            with self.subTest(field=key, value=value):
                saved = deepcopy(self.after)
                self.after["tokens"][-1][key] = value
                with self.assertRaises(stage.Stopped):
                    self.bind()
                self.after = saved

    def test_drifted_owner_old_tokens_or_extra_rows_are_refused(self):
        variants = []
        meta = deepcopy(self.after)
        meta["users"][0]["email"] = "changed@invalid.example"
        variants.append(meta)
        meta = deepcopy(self.after)
        meta["teams"][0]["member_count"] += 1
        variants.append(meta)
        meta = deepcopy(self.after)
        meta["tokens"][0]["created_unix"] += 1
        variants.append(meta)
        meta = deepcopy(self.after)
        meta["tokens"].append({**meta["tokens"][-1], "id": 100})
        variants.append(meta)
        meta = deepcopy(self.after)
        meta["tokens"].pop(0)
        variants.append(meta)
        for meta in variants:
            with self.subTest(meta=meta):
                self.after = meta
                with self.assertRaises(stage.Stopped):
                    self.bind()

    def test_existing_name_or_multiple_principals_is_refused(self):
        self.before["tokens"][0]["name"] = "once"
        with self.assertRaises(stage.Stopped):
            self.bind()
        self.before["tokens"][0]["name"] = "existing-owner-token"
        self.before["users"].append(deepcopy(self.before["users"][0]))
        self.after["users"] = deepcopy(self.before["users"])
        with self.assertRaises(stage.Stopped):
            self.bind()

    def test_mint_output_shape_is_strict(self):
        for raw in (TOKEN.encode(), (TOKEN + "\n").encode()):
            self.assertEqual(stage.token_value(raw), TOKEN)
        for raw in (TOKEN, None, TOKEN.upper().encode(), b"a" * 39, b"a" * 41,
                    (TOKEN + "\r\n").encode(), (TOKEN + "\n\n").encode(),
                    b"warning\n" + TOKEN.encode(), b"g" * 40):
            with self.subTest(raw_type=type(raw).__name__):
                with self.assertRaises(stage.Stopped):
                    stage.token_value(raw)


if __name__ == "__main__":
    unittest.main()
