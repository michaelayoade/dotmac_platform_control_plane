"""Hosted-only synthetic tests: no runtime/audit imports or live transports."""
import copy
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, call, mock_open, patch

import host_gate as hg


def config():
    suffix = "20261125-abcd"
    return {
        "schema": "cp_host_gated.v1", "run": "cp-host-" + suffix, "host": "dotmac-s3",
        "canary_username": "cp-revoke-proof-" + suffix,
        "canary_token_name": "cp-canary-read-" + suffix,
        "bootstrap_token_name": "cp-org-bootstrap-" + suffix,
        "forgejo_container_id": "a" * 64, "forgejo_image_id": "sha256:" + "b" * 64,
        "database_container_id": "c" * 64, "database_image_id": "sha256:" + "d" * 64,
        "source_pins": {"host_gate.py": "e" * 64, "orchestrator.py": "f" * 64,
                        "revocation_sql.py": "1" * 64, "bootstrap_api.py": "2" * 64,
                        **hg.FIXED_PINS},
        "operator_reference": "operator-ref", "authorization_reference": "authorization-ref",
        "exclusive_window_reference": "window-ref", "cp_require_restricted": True,
        "restricted_account_decision_reference": "decision-ref",
        "accepted_canary_receipt_sha256": "3" * 64,
    }


def empty_meta():
    return {"database": "forgejo", "transaction_read_only": "on",
            "database_container_id": "c" * 64,
            **{k: [] for k in ("users", "tokens", "public_keys", "gpg_keys", "owned_repos",
                              "collaborations", "access_rows", "org_memberships", "team_memberships", "teams")}}


def user(name="cp-bundle-reader", uid=19, admin=False, restricted=True):
    return {"id": uid, "name": name, "type": 0, "is_admin": admin, "is_active": True,
            "is_restricted": restricted, "prohibit_login": False, "must_change_password": False,
            "login_type": 0, "login_source": 0}


def cp_team(member_count=0):
    return {"team_id": 10, "team_name": "cp-bundle-readers", "org_id": 2, "org_name": "dotmac",
            "authorization": 1, "member_count": member_count, "team_repo_count": 0,
            "can_create_org_repo": False, "includes_all_repositories": False,
            "units": [{"type": 9, "access_mode": 1}]}


def cp_metadata(ready=False, restricted=True):
    meta = {**empty_meta(), "users": [user(restricted=restricted)], "teams": [cp_team(1 if ready else 0)]}
    if ready:
        meta["org_memberships"] = [{"org_id": 2, "org_name": "dotmac"}]
        meta["team_memberships"] = [{"team_id": 10, "team_name": "cp-bundle-readers", "org_id": 2,
                                      "org_name": "dotmac", "authorization": 1}]
    return meta


def owner_metadata():
    membership = {"team_id": 1, "org_id": 2, "team_name": "Owners", "org_name": "dotmac", "authorization": 4}
    return {**empty_meta(), "users": [user("dotmac-admin", 1, True, False)],
            "team_memberships": [membership], "teams": [{**membership, "member_count": 1}],
            "org_memberships": [{"org_id": 2, "org_name": "dotmac"}]}


class GuardedReadTests(unittest.TestCase):
    def state(self, **changes):
        values = dict(st_mode=stat.S_IFREG | 0o600, st_uid=42, st_nlink=1, st_dev=3,
                      st_ino=4, st_mtime_ns=5, st_ctime_ns=6, st_size=4)
        return SimpleNamespace(**{**values, **changes})

    def read(self, original, opened=None, after=None):
        path = MagicMock()
        path.lstat.return_value = original
        opened = opened or original
        after = after or opened
        with patch.object(hg.os, "geteuid", return_value=42), \
                patch.object(hg.os, "open", return_value=91) as op, \
                patch.object(hg.os, "fstat", side_effect=[opened, after]), \
                patch.object(hg.os, "fdopen", return_value=io.BytesIO(b"data")), \
                patch.object(hg.os, "close") as close:
            try:
                result = hg.guarded(path)
            finally:
                if op.called:
                    close.assert_called_once_with(91)
            op.assert_called_once_with(path, hg.os.O_RDONLY | hg.os.O_NOFOLLOW)
            return result

    def test_reads_only_protected_regular_file(self):
        self.assertEqual(self.read(self.state()), b"data")

    def test_refuses_unprotected_source_before_open(self):
        for change in ({"st_mode": stat.S_IFLNK | 0o600}, {"st_mode": stat.S_IFDIR | 0o700},
                       {"st_mode": stat.S_IFREG | 0o620}, {"st_mode": stat.S_IFREG | 0o602},
                       {"st_uid": 99}, {"st_nlink": 2}):
            path = MagicMock()
            path.lstat.return_value = self.state(**change)
            with self.subTest(change=change), patch.object(hg.os, "geteuid", return_value=42), \
                    patch.object(hg.os, "open") as op, self.assertRaisesRegex(hg.Refused, "file_protection"):
                hg.guarded(path)
            op.assert_not_called()

    def test_refuses_open_and_read_races_and_closes_descriptor(self):
        for field in ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns"):
            with self.subTest(open_field=field), self.assertRaisesRegex(hg.Refused, "file_open_race"):
                self.read(self.state(), self.state(**{field: 100}))
        for field in ("st_size", "st_mtime_ns", "st_ctime_ns"):
            with self.subTest(read_field=field), self.assertRaisesRegex(hg.Refused, "file_read_race"):
                self.read(self.state(), after=self.state(**{field: 100}))

    def test_module_hash_refusal_never_compiles_or_executes(self):
        with patch.object(hg, "guarded", return_value=b"raise RuntimeError('must not execute')"), \
                patch("builtins.compile") as compile_mock, self.assertRaisesRegex(hg.Refused, "source_drift"):
            hg.load_module("audit.py", "0" * 64)
        compile_mock.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def load(self, cfg):
        raw = json.dumps(cfg).encode()
        with patch.object(hg, "guarded", return_value=raw):
            loaded, digest = hg.load_config(Path("/mock/config.json"))
        self.assertEqual(digest, hg.sha(raw))
        return loaded

    def require(self, cfg, phase="canary"):
        pins = cfg["source_pins"]
        with patch.object(hg, "guarded", side_effect=lambda path: path.name.encode()), \
                patch.object(hg, "sha", side_effect=lambda data: pins[data.decode()]):
            hg.require_apply(cfg, phase)

    def test_exact_schema_and_valid_name_binding(self):
        self.assertEqual(self.load(config()), config())
        for change in ({"unknown": 1}, {"schema": "other"}, {"host": "other"},
                       {"run": "cp-host-short"}, {"run": "cp-host-20261125-ABC"},
                       {"run": "cp-host-20261125-abcd\n"}, {"run": "cp-host-" + "a" * 33},
                       {"canary_username": "cp-revoke-proof-other-abcd"},
                       {"canary_token_name": "cp-canary-read-other-abcd"},
                       {"bootstrap_token_name": "cp-org-bootstrap-other-abcd"},
                       {"cp_require_restricted": 1}):
            with self.subTest(change=change), self.assertRaises(hg.Refused):
                self.load({**config(), **change})
        for key in config():
            cfg = config()
            del cfg[key]
            with self.subTest(missing=key), self.assertRaises(hg.Refused):
                self.load(cfg)

    def test_unbound_preparation_loads_but_cannot_apply(self):
        for field in ("operator_reference", "authorization_reference", "exclusive_window_reference"):
            for value in (None, "", " ", "x" * 201):
                cfg = config()
                cfg[field] = value
                self.load(cfg)
                with self.subTest(field=field, value=value), self.assertRaisesRegex(hg.Refused, "authority_unbound"):
                    self.require(cfg)

    def test_apply_requires_full_container_image_and_exact_pins(self):
        self.require(config(), "bootstrap")
        for key in ("forgejo_container_id", "database_container_id"):
            for value in (None, "a" * 12, "g" * 64):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(hg.Refused, "container_unbound"):
                    self.require({**config(), key: value})
        for key in ("forgejo_image_id", "database_image_id"):
            for value in (None, "a" * 64, "sha256:" + "G" * 64):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(hg.Refused, "image_unbound"):
                    self.require({**config(), key: value})
        for pins in (None, {}, {**config()["source_pins"], "extra.py": "0" * 64}):
            with self.subTest(pins=pins), self.assertRaisesRegex(hg.Refused, "source_pin_set"):
                self.require({**config(), "source_pins": pins})

    def test_fixed_pin_source_drift_and_bootstrap_decision_refusals(self):
        for name in hg.FIXED_PINS:
            cfg = config()
            cfg["source_pins"][name] = "0" * 64
            with self.subTest(name=name), self.assertRaisesRegex(hg.Refused, "fixed_source_pin_drift"):
                self.require(cfg)
        cfg = config()
        cfg["source_pins"]["host_gate.py"] = None
        with self.assertRaisesRegex(hg.Refused, "source_pin_unbound"):
            self.require(cfg)
        with patch.object(hg, "guarded", return_value=b"changed"), self.assertRaisesRegex(hg.Refused, "source_pin_drift"):
            hg.require_apply(config(), "canary")
        for key, error in (("restricted_account_decision_reference", "restricted_decision_unbound"),
                           ("accepted_canary_receipt_sha256", "accepted_canary_unbound")):
            with self.subTest(key=key), self.assertRaisesRegex(hg.Refused, error):
                self.require({**config(), key: None}, "bootstrap")

    def test_canary_receipt_exact_hash_and_bindings(self):
        cfg = config()
        receipt = {"schema": "cp_host_gated_receipt.v1", "status": "CANARY_PASSED", "phase": "canary",
                   "run": cfg["run"], "source_pins": cfg["source_pins"], "container_pins": {
                       key: cfg[key] for key in ("forgejo_container_id", "forgejo_image_id",
                                                "database_container_id", "database_image_id")}}
        def validate(item, wrong_hash=False):
            raw = json.dumps(item).encode()
            current = {**cfg, "accepted_canary_receipt_sha256": "0" * 64 if wrong_hash else hg.sha(raw)}
            with patch.object(hg, "guarded", return_value=raw):
                hg.validate_accepted_canary(current, Path("/mock/receipt.json"))
        validate(receipt)
        with self.assertRaisesRegex(hg.Refused, "canary_receipt_hash"):
            validate(receipt, True)
        for key, wrong in (("schema", "other"), ("status", "STARTED"), ("phase", "bootstrap"),
                           ("run", "cp-host-other-abcd"), ("source_pins", {}), ("container_pins", {})):
            with self.subTest(key=key), self.assertRaisesRegex(hg.Refused, "canary_receipt_binding"):
                validate({**receipt, key: wrong})
        for key in receipt["container_pins"]:
            changed = copy.deepcopy(receipt)
            changed["container_pins"][key] = "different"
            with self.subTest(image=key), self.assertRaisesRegex(hg.Refused, "canary_receipt_binding"):
                validate(changed)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.runtime = {key: Mock() for key in ("check_container", "check_metadata", "docker")}
        self.audit = {"collect_remote": Mock(return_value=empty_meta()), "evaluate": Mock(return_value=[{"ok": True}])}
        self.sql = {"build_revocation_sql": Mock(return_value="SAFE GUARDED SQL")}
        self.backend = hg.Backend(self.cfg, self.runtime, self.audit, {"request": Mock()}, self.sql)

    def test_create_discards_both_streams_and_never_passes_password(self):
        with patch.object(hg.tempfile, "TemporaryDirectory") as directory, patch.object(hg.subprocess, "run") as run:
            directory.return_value.__enter__.return_value = "/mock/empty-client"
            run.return_value = SimpleNamespace(returncode=0, stdout=None)
            self.backend.create_user(self.cfg["canary_username"], restricted=True)
        self.runtime["check_container"].assert_called_once_with(self.cfg, "forgejo")
        argv = run.call_args.args[0]
        kw = run.call_args.kwargs
        self.assertEqual(argv[:5], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", "/mock/empty-client"])
        self.assertIn(self.cfg["forgejo_container_id"], argv)
        self.assertIn("--random-password", argv)
        for flag in ("--admin=false", "--restricted=true", "--must-change-password=false", "--access-token=false"):
            self.assertIn(flag, argv)
        self.assertNotIn("--password", argv)
        self.assertNotIn("-t", argv)
        self.assertEqual(kw["stdout"], hg.subprocess.DEVNULL)
        self.assertEqual(kw["stderr"], hg.subprocess.DEVNULL)
        self.assertEqual(kw["stdin"], hg.subprocess.DEVNULL)
        self.assertNotIn("input", kw)
        self.assertEqual(kw["env"], {"PATH": "/usr/bin:/bin"})
        self.assertEqual(kw["timeout"], 30)

    def test_creation_scope_and_container_guard_precede_effects(self):
        with patch.object(self.backend, "quiet_docker") as quiet:
            for name in ("dotmac-admin", "ci-reader", "other"):
                with self.subTest(name=name), self.assertRaisesRegex(hg.Refused, "create_principal_scope"):
                    self.backend.create_user(name, restricted=True)
            quiet.assert_not_called()
            self.runtime["check_container"].side_effect = hg.Refused("container_changed")
            with self.assertRaises(hg.Refused):
                self.backend.create_user("cp-bundle-reader", restricted=True)
            quiet.assert_not_called()

    def test_quiet_docker_refuses_failure_and_oversize_sql_output(self):
        for result in (SimpleNamespace(returncode=1, stdout=b"error"),
                       SimpleNamespace(returncode=0, stdout=b"x" * 8193)):
            with self.subTest(returncode=result.returncode, size=len(result.stdout)), \
                    patch.object(hg.tempfile, "TemporaryDirectory") as directory, \
                    patch.object(hg.subprocess, "run", return_value=result) as run, \
                    self.assertRaisesRegex(hg.Refused, "docker_step_failed"):
                directory.return_value.__enter__.return_value = "/mock/empty-client"
                self.backend.quiet_docker(["exec", "fixed"], sql_input=b"fixed sql")
            self.assertEqual(run.call_count, 1)

    def test_mint_only_exact_principal_name_scope(self):
        for username, name, scope in ((self.cfg["canary_username"], self.cfg["canary_token_name"], "read:user"),
                                       ("dotmac-admin", self.cfg["bootstrap_token_name"], "write:organization")):
            self.backend.mint(username, name, scope)
            argv = self.runtime["docker"].call_args.args[0]
            self.assertIn(self.cfg["forgejo_container_id"], argv)
            self.assertEqual(argv[-3:], ["--scopes", scope, "--raw"])
            self.assertTrue(self.runtime["docker"].call_args.kwargs["sensitive"])
        self.runtime["docker"].reset_mock()
        for args in (("ci-reader", self.cfg["canary_token_name"], "read:user"),
                     (self.cfg["canary_username"], "other", "read:user"),
                     (self.cfg["canary_username"], self.cfg["canary_token_name"], "all")):
            with self.subTest(args=args), self.assertRaisesRegex(hg.Refused, "mint_scope"):
                self.backend.mint(*args)
        self.runtime["docker"].assert_not_called()

    def test_metadata_identity_and_full_pin_delegation(self):
        self.backend.metadata(self.cfg["canary_username"])
        self.runtime["check_container"].assert_called_once_with(self.cfg, "database")
        self.audit["collect_remote"].assert_called_once_with(self.cfg["canary_username"], "dotmac", "cp-revoke-proof-unused-20261125")
        self.backend.metadata("dotmac-admin")
        self.audit["collect_remote"].assert_called_with("dotmac-admin", "dotmac", "Owners")
        for change in ({"database": "other"}, {"transaction_read_only": "off"},
                       {"database_container_id": "f" * 64}, {"database_container_id": "c" * 11},
                       {"database_container_id": None}):
            self.audit["collect_remote"].return_value = {**empty_meta(), **change}
            with self.subTest(change=change), self.assertRaisesRegex(hg.Refused, "metadata_identity"):
                self.backend.metadata("cp-bundle-reader")

    def test_schema_probe_ready_pg16_is_read_only_and_targets_exact_database(self):
        with patch.object(self.backend, "quiet_docker", return_value=
                          b'{"cleanup_schema":"ready","server_version_num":"160014"}') as quiet:
            self.backend.schema_probe()
        self.runtime["check_container"].assert_called_once_with(self.cfg, "database")
        quiet.assert_called_once()
        argv = quiet.call_args.args[0]
        sql = quiet.call_args.kwargs["sql_input"]
        self.assertIsInstance(sql, bytes)
        self.assertTrue(sql.startswith(b"BEGIN TRANSACTION READ ONLY;\n"))
        self.assertTrue(sql.rstrip().endswith(b"ROLLBACK;"))
        self.assertIn(b"SET LOCAL statement_timeout = '10s';", sql)
        self.assertIn(b'SELECT id, name, lower_name, type FROM "user" LIMIT 0;', sql)
        self.assertIn(b"SELECT id, uid, name, scope, created_unix FROM access_token LIMIT 0;", sql)
        self.assertEqual(sql.count(b"LIMIT 0"), 2)
        self.assertNotRegex(sql.decode(), r"\b(?:DELETE|INSERT|UPDATE|TRUNCATE|CREATE|ALTER|DROP|COMMIT)\b")
        for forbidden in (b"token_hash", b"token_salt", b"token_last_eight", b"last_eight", b"SELECT *"):
            self.assertNotIn(forbidden, sql)
        self.assertEqual(argv[:5], ["exec", "-i", "-u", "postgres", self.cfg["database_container_id"]])
        self.assertNotIn(self.cfg["forgejo_container_id"], argv)
        self.assertEqual(argv[argv.index("-h") + 1], "/var/run/postgresql")
        self.assertEqual(argv[argv.index("-p") + 1], "5432")
        self.assertEqual(argv[argv.index("-U") + 1], "forgejo")
        self.assertEqual(argv[argv.index("-d") + 1], "forgejo")
        self.assertIn("ON_ERROR_STOP=1", argv)
        self.assertEqual(argv[-2:], ["-f", "-"])
        self.assertNotIn("-c", argv)

    def test_schema_probe_wrong_major_schema_or_malformed_output_refuses(self):
        outputs = (
            b'{"cleanup_schema":"ready","server_version_num":"150014"}',
            b'{"cleanup_schema":"ready","server_version_num":"170001"}',
            b'{"cleanup_schema":"missing","server_version_num":"160014"}',
            b'{"cleanup_schema":"ready","server_version_num":"not-a-version"}',
            b'{"cleanup_schema":"ready"}', b"{}", b"null", b"[]", b"not-json", b"",
            b'{"cleanup_schema":"ready","server_version_num":"160014"}\n{}',
        )
        for raw in outputs:
            with self.subTest(raw=raw), patch.object(self.backend, "quiet_docker", return_value=raw) as quiet, \
                    self.assertRaises((hg.Refused, ValueError, KeyError, AttributeError, TypeError)):
                self.backend.schema_probe()
            quiet.assert_called_once()

    def test_schema_probe_container_or_column_failure_stops_without_retry(self):
        with patch.object(self.backend, "quiet_docker") as quiet:
            self.runtime["check_container"].side_effect = hg.Refused("container_changed")
            with self.assertRaisesRegex(hg.Refused, "container_changed"):
                self.backend.schema_probe()
            quiet.assert_not_called()
            self.runtime["check_container"].side_effect = None
            quiet.side_effect = hg.Refused("docker_step_failed")
            with self.assertRaisesRegex(hg.Refused, "docker_step_failed"):
                self.backend.schema_probe()
            quiet.assert_called_once()

    def test_revoke_single_id_attempt_sql_stdin_clean_psql(self):
        binding = {"user_id": 19, "token_id": 101}
        with patch.object(hg.tempfile, "TemporaryDirectory") as directory, patch.object(hg.subprocess, "run") as run:
            directory.return_value.__enter__.return_value = "/mock/empty-client"
            run.return_value = SimpleNamespace(returncode=0, stdout=b"fixed result")
            self.backend.revoke(binding)
            with self.assertRaisesRegex(hg.Refused, "revocation_retry_forbidden"):
                self.backend.revoke(dict(binding))
        self.sql["build_revocation_sql"].assert_called_once_with(binding)
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        kw = run.call_args.kwargs
        self.assertNotIn("SAFE GUARDED SQL", argv)
        self.assertEqual(kw["input"], b"SAFE GUARDED SQL")
        self.assertNotIn("stdin", kw)
        self.assertEqual(kw["stderr"], hg.subprocess.DEVNULL)
        self.assertEqual(kw["env"], {"PATH": "/usr/bin:/bin"})
        for item in ("env", "-i", "PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null", "psql", "-X",
                     "--no-password", "ON_ERROR_STOP=1", self.cfg["database_container_id"]):
            self.assertIn(item, argv)
        self.assertEqual(argv[-2:], ["-f", "-"])
        self.assertNotIn("-c", argv)

    def test_failed_or_ambiguous_revoke_is_not_retried(self):
        for error in (hg.Refused("docker_step_failed"), TimeoutError("unknown commit")):
            backend = hg.Backend(self.cfg, self.runtime, self.audit, {}, self.sql)
            with patch.object(backend, "quiet_docker", side_effect=error) as quiet:
                with self.assertRaises(type(error)):
                    backend.revoke({"user_id": 19, "token_id": 101})
                with self.assertRaisesRegex(hg.Refused, "revocation_retry_forbidden"):
                    backend.revoke({"user_id": 19, "token_id": 101})
                self.assertEqual(quiet.call_count, 1)

    def test_revoke_validation_and_container_refusals_precede_sql_effect(self):
        binding = {"user_id": 19, "token_id": 101}
        with patch.object(self.backend, "quiet_docker") as quiet:
            self.sql["build_revocation_sql"].side_effect = ValueError("invalid binding")
            with self.assertRaises(ValueError):
                self.backend.revoke(binding)
            self.runtime["check_container"].assert_not_called()
            quiet.assert_not_called()
            self.assertEqual(self.backend.revocation_attempts, set())
            self.sql["build_revocation_sql"].side_effect = None
            self.runtime["check_container"].side_effect = hg.Refused("container_changed")
            with self.assertRaisesRegex(hg.Refused, "container_changed"):
                self.backend.revoke(binding)
            quiet.assert_not_called()
            self.assertEqual(self.backend.revocation_attempts, set())

    def test_absence_fails_closed_on_missing_or_nonempty_audit_rows(self):
        with patch.object(self.backend, "metadata", return_value=empty_meta()) as metadata:
            self.backend.require_absent("cp-bundle-reader", team_absent=True)
            for key in ("users", "tokens", "public_keys", "gpg_keys", "owned_repos", "collaborations",
                        "access_rows", "org_memberships", "team_memberships", "teams"):
                for value in (None, [{"id": 1}]):
                    metadata.return_value = {**empty_meta(), key: value}
                    with self.subTest(key=key, value=value), self.assertRaises(hg.Refused):
                        self.backend.require_absent("cp-bundle-reader", team_absent=True)

    def test_canary_identity_checked_before_runtime_metadata(self):
        for uid in (1, 2, 3, 4, 5, True):
            with self.subTest(uid=uid), self.assertRaisesRegex(hg.Refused, "canary_uid"):
                self.backend.require_canary({"users": [{"id": uid}]})
        self.runtime["check_metadata"].assert_not_called()
        meta = {**empty_meta(), "users": [user(self.cfg["canary_username"])]}
        self.backend.require_canary(meta)
        self.runtime["check_metadata"].assert_called_once_with(
            meta, {**self.cfg, "username": self.cfg["canary_username"], "user_id": 19}, 0)

    def test_cp_isolation_and_exact_typed_state(self):
        meta = {**empty_meta(), "users": [user()]}
        self.backend.require_cp_ungranted(meta)
        for change in ({"id": 5}, {"id": True}, {"is_admin": True}, {"name": "other"},
                       {"is_restricted": False}, {"type": False}, {"is_active": 1}):
            with self.subTest(change=change), self.assertRaises(hg.Refused):
                self.backend.require_cp_ungranted({**meta, "users": [{**user(), **change}]})
        for key in ("tokens", "teams", "org_memberships", "team_memberships", "owned_repos",
                    "public_keys", "gpg_keys", "collaborations", "access_rows"):
            with self.subTest(key=key), self.assertRaisesRegex(hg.Refused, "cp_pregrants_not_empty"):
                self.backend.require_cp_ungranted({**meta, key: [{"id": 1}]})

    def test_owner_exact_typed_identity(self):
        meta = owner_metadata()
        self.backend.require_owner(meta)
        for change in ({"id": True}, {"name": "other"}, {"is_admin": False}, {"is_restricted": True}):
            with self.subTest(change=change), self.assertRaisesRegex(hg.Refused, "owner_state"):
                self.backend.require_owner({**meta, "users": [{**meta["users"][0], **change}]})

    def test_owner_membership_and_sole_owner_detail(self):
        meta = owner_metadata()
        for collection, changes, error in (
                ("team_memberships", [{"team_id": 2}, {"team_id": True}, {"org_id": 3}, {"org_id": True},
                                       {"team_name": "owners"}, {"org_name": "other"},
                                       {"authorization": 1}, {"authorization": True}], "owner_membership"),
                ("teams", [{"team_id": True}, {"org_id": True}, {"team_name": "other"}, {"org_name": "other"},
                            {"authorization": True}, {"authorization": 1}, {"member_count": True},
                            {"member_count": 2}], "sole_owner_team_state"),
                ("org_memberships", [{"org_id": 3}, {"org_id": True}, {"org_name": "other"}], "owner_org_membership")):
            for change in changes:
                with self.subTest(collection=collection, change=change), self.assertRaisesRegex(hg.Refused, error):
                    self.backend.require_owner({**meta, collection: [{**meta[collection][0], **change}]})
            for rows in ([], meta[collection] * 2):
                with self.subTest(collection=collection, rows=rows), self.assertRaises(hg.Refused):
                    self.backend.require_owner({**meta, collection: rows})
        with self.assertRaisesRegex(hg.Refused, "owner_token_metadata"):
            self.backend.require_owner({**meta, "tokens": None})

    def test_cp_original_identity_and_configured_restriction(self):
        for restricted in (True, False):
            self.cfg["cp_require_restricted"] = restricted
            meta = cp_metadata(restricted=restricted)
            self.backend.require_cp_identity(meta, 19)
            for uid in (18, True, False):
                with self.subTest(restricted=restricted, uid=uid), self.assertRaisesRegex(hg.Refused, "cp_uid_changed"):
                    self.backend.require_cp_identity(meta, uid)
            with self.assertRaisesRegex(hg.Refused, "cp_user_state"):
                self.backend.require_cp_identity({**meta, "users": [user(restricted=not restricted)]}, 19)
        for change in ({"id": 20}, {"id": True}, {"is_admin": True}, {"is_active": 1},
                       {"name": "other"}, {"login_type": False}):
            meta = cp_metadata(restricted=False)
            with self.subTest(change=change), self.assertRaises(hg.Refused):
                self.backend.require_cp_identity({**meta, "users": [{**meta["users"][0], **change}]}, 19)

    def test_join_requires_original_isolated_principal_and_zero_members(self):
        meta = cp_metadata()
        self.backend.require_cp_join_target(meta, 10, 19)
        for key in ("tokens", "org_memberships", "team_memberships", "owned_repos", "public_keys", "gpg_keys",
                    "collaborations", "access_rows"):
            for value in (None, [{"id": 1}]):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(hg.Refused, "cp_before_join_not_isolated"):
                    self.backend.require_cp_join_target({**meta, key: value}, 10, 19)
        with self.assertRaisesRegex(hg.Refused, "cp_uid_changed"):
            self.backend.require_cp_join_target(meta, 10, 20)
        with self.assertRaisesRegex(hg.Refused, "cp_team_grants"):
            self.backend.require_cp_join_target({**meta, "teams": [cp_team(1)]}, 10, 19)

    def test_cp_team_requires_exact_typed_org_grants_and_member_count(self):
        for ready in (False, True):
            meta = cp_metadata(ready)
            check = self.backend.require_cp_ready if ready else self.backend.require_cp_join_target
            for team_id in (True, False, 0, -1, "10", 11):
                with self.subTest(ready=ready, expected_id=team_id), self.assertRaises(hg.Refused):
                    check(meta, team_id, 19)
            for change in ({"team_id": True}, {"team_id": 11}, {"team_name": "other"},
                           {"org_id": True}, {"org_id": 3}, {"org_name": "other"},
                           {"authorization": True}, {"authorization": 4}, {"member_count": True},
                           {"member_count": 2}, {"team_repo_count": False}, {"team_repo_count": 1},
                           {"can_create_org_repo": True}, {"can_create_org_repo": 0},
                           {"includes_all_repositories": True}, {"includes_all_repositories": 0}):
                with self.subTest(ready=ready, change=change), self.assertRaisesRegex(hg.Refused, "cp_team_grants"):
                    check({**meta, "teams": [{**meta["teams"][0], **change}]}, 10, 19)
            for rows in ([], meta["teams"] * 2):
                with self.subTest(ready=ready, rows=rows), self.assertRaisesRegex(hg.Refused, "cp_team_target"):
                    check({**meta, "teams": rows}, 10, 19)

    def test_cp_units_are_package_read_only(self):
        meta = cp_metadata()
        for units in (None, [], [{"type": 9, "access_mode": 2}], [{"type": 9, "access_mode": True}],
                      [{"type": 9, "access_mode": 1}] * 2,
                      [{"type": 9, "access_mode": 1}, {"type": 1, "access_mode": 1}],
                      [{"type": 9, "access_mode": 1}, {"type": True, "access_mode": 0}],
                      [{"type": 9, "access_mode": 1}, {"type": 1, "access_mode": False}]):
            with self.subTest(units=units), self.assertRaisesRegex(hg.Refused, "cp_team_units"):
                self.backend.require_cp_join_target({**meta, "teams": [{**cp_team(), "units": units}]}, 10, 19)
        disabled = [{"type": 9, "access_mode": 1}, {"type": 1, "access_mode": 0}]
        self.backend.require_cp_join_target({**meta, "teams": [{**cp_team(), "units": disabled}]}, 10, 19)

    def test_ready_same_uid_memberships_and_flags_for_both_restriction_choices(self):
        for restricted in (True, False):
            self.cfg["cp_require_restricted"] = restricted
            meta = cp_metadata(True, restricted)
            self.backend.require_cp_ready(meta, 10, 19)
            for change in ({"id": 20}, {"is_admin": True}, {"is_active": 1}, {"is_restricted": not restricted}):
                with self.subTest(restricted=restricted, change=change), self.assertRaises(hg.Refused):
                    self.backend.require_cp_ready({**meta, "users": [{**meta["users"][0], **change}]}, 10, 19)
        meta = cp_metadata(True, False)
        for collection, changes in (
                ("org_memberships", [{"org_id": True}, {"org_id": 3}, {"org_name": "other"}]),
                ("team_memberships", [{"team_id": True}, {"team_id": 11}, {"org_id": True}, {"org_id": 3},
                                       {"team_name": "Owners"}, {"org_name": "other"},
                                       {"authorization": True}, {"authorization": 4}])):
            for change in changes:
                with self.subTest(collection=collection, change=change), self.assertRaises(hg.Refused):
                    self.backend.require_cp_ready({**meta, collection: [{**meta[collection][0], **change}]}, 10, 19)
            for rows in ([], meta[collection] * 2):
                with self.subTest(collection=collection, rows=rows), self.assertRaises(hg.Refused):
                    self.backend.require_cp_ready({**meta, collection: rows}, 10, 19)

    def test_ready_requires_nonempty_successful_audit(self):
        ready = cp_metadata(True)
        self.backend.require_cp_ready(ready, 10, 19)
        self.audit["evaluate"].assert_called_once_with(ready, {
            "forgejo_user": "cp-bundle-reader", "forgejo_org": "dotmac", "forgejo_team": "cp-bundle-readers",
            "require_restricted": True}, "pre")
        for checks in ([], [{"ok": False}], [{"ok": True}, {"ok": False}]):
            self.audit["evaluate"].return_value = checks
            with self.subTest(checks=checks), self.assertRaisesRegex(hg.Refused, "cp_grant_audit"):
                self.backend.require_cp_ready(ready, 10, 19)


class JournalTests(unittest.TestCase):
    def journal(self):
        journal = hg.Journal.__new__(hg.Journal)
        journal.failed = False
        journal.directory = MagicMock()
        journal.data = {"status": "STARTED", "events": []}
        temporary = journal.directory.__truediv__.return_value
        temporary.open = mock_open()
        return journal, temporary

    def test_exclusive_attempt_precedes_write_and_reuse_refuses(self):
        directory = MagicMock()
        directory.mkdir.side_effect = FileExistsError
        with patch.object(hg.Journal, "sync") as sync, patch.object(hg.Journal, "write") as write:
            with self.assertRaises(FileExistsError):
                hg.Journal(directory, config(), "canary")
        directory.mkdir.assert_called_once_with(mode=0o700, parents=False, exist_ok=False)
        sync.assert_not_called()
        write.assert_not_called()

    def test_success_flushes_file_then_replaces_and_syncs_directory(self):
        journal, temporary = self.journal()
        stream = temporary.open.return_value.__enter__.return_value
        order = Mock()
        order.attach_mock(stream.flush, "flush")
        order.attach_mock(temporary.replace, "replace")
        with patch.object(hg.os, "fsync") as fsync, patch.object(journal, "sync") as sync:
            order.attach_mock(fsync, "fsync")
            order.attach_mock(sync, "sync")
            journal.write("mint_intent")
        temporary.open.assert_called_once_with("x")
        self.assertEqual([c[0] for c in order.mock_calls], ["flush", "fsync", "replace", "sync"])
        self.assertFalse(journal.failed)

    def test_fsync_failure_preserves_intent_and_never_recursively_writes(self):
        journal, temporary = self.journal()
        with patch.object(hg.os, "fsync", side_effect=OSError("storage unavailable")), \
                self.assertRaisesRegex(hg.Refused, "journal_write_failed"):
            journal.write("mint_intent", token_id=101)
        self.assertTrue(journal.failed)
        self.assertEqual(journal.data["events"], [{"stage": "mint_intent", "token_id": 101}])
        temporary.replace.assert_not_called()
        with patch.object(journal, "write") as write, patch("sys.stderr", new_callable=io.StringIO):
            journal.finish("FAILED", "storage")
        write.assert_not_called()
        self.assertEqual(journal.data["status"], "STARTED")
        with self.assertRaisesRegex(hg.Refused, "journal_already_failed"):
            hg.Journal.write(journal, "retry")

    def test_existing_partial_tmp_is_not_overwritten(self):
        journal, temporary = self.journal()
        temporary.open.side_effect = FileExistsError
        with self.assertRaisesRegex(hg.Refused, "journal_write_failed"):
            journal.write("sql_intent")
        self.assertTrue(journal.failed)
        temporary.replace.assert_not_called()
        self.assertEqual(journal.data["events"][0]["stage"], "sql_intent")


class EntrypointTests(unittest.TestCase):
    def test_bootstrap_unaccepted_canary_refuses_before_modules_or_attempt(self):
        cfg = config()
        args = ["host_gate.py", "--config", "/mock/config.json", "--phase", "bootstrap", "--apply",
                "--expect-config-sha256", "config-hash", "--accepted-canary-receipt", "/mock/canary.json"]
        with patch.object(hg.sys, "argv", args), \
                patch.object(hg.resource, "setrlimit"), patch.object(hg.os, "umask"), \
                patch.object(hg.os, "geteuid", return_value=0), \
                patch.object(hg.socket, "gethostname", return_value="dotmac-s3"), \
                patch.object(hg, "root_ancestors"), patch.object(hg, "load_config", return_value=(cfg, "config-hash")), \
                patch.object(hg.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
                patch.object(hg.sys, "dont_write_bytecode", True), \
                patch.object(hg.sys, "executable", "/usr/bin/python3"), \
                patch.object(hg.Path, "resolve", lambda self: self), \
                patch.object(hg, "require_apply"), \
                patch.object(hg, "validate_accepted_canary", side_effect=hg.Refused("canary_receipt_binding")) as validate, \
                patch.object(hg, "load_module") as load, patch.object(hg, "Journal") as journal, \
                patch.object(hg, "Backend") as backend, patch.object(hg.Path, "lstat") as lstat, \
                self.assertRaisesRegex(hg.Refused, "canary_receipt_binding"):
            hg.main()
        validate.assert_called_once_with(cfg, Path("/mock/canary.json"))
        load.assert_not_called()
        journal.assert_not_called()
        backend.assert_not_called()
        lstat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
