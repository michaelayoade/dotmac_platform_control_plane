"""Secret-free boundary tests; run only in the hosted qualification lane."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import unittest
from unittest import mock
from types import SimpleNamespace

import operator_bootstrap as subject


class OperatorBootstrapTests(unittest.TestCase):
    def configuration(self):
        return {"schema": "cp_operator_artifact_bootstrap_config.v1", "run": subject.RUN,
                "host": "dotmac-s3", "reader_token_name": subject.RUN, "cp_require_restricted": False,
                "canary_username": "cp-revoke-proof-20261125-r1", "source_pins": {},
                "forgejo_container_id": "a" * 64, "forgejo_image_id": "sha256:" + "b" * 64,
                "database_container_id": "c" * 64, "database_image_id": "sha256:" + "d" * 64,
                "authorization_reference": "approved-exact-packet", "operator_reference": "operator",
                "exclusive_window_reference": "window"}

    def test_attempt_parent_is_durable_before_journal_or_backend(self):
        events = []
        output = mock.MagicMock()
        output.lstat.return_value = SimpleNamespace(st_mode=0o40700, st_uid=0)
        run = output.__truediv__.return_value
        output.mkdir.side_effect = lambda **kwargs: events.append("output_mkdir")
        run.mkdir.side_effect = lambda **kwargs: events.append("run_mkdir")

        class StopBeforeEffects(Exception):
            pass

        class Journal:
            @staticmethod
            def sync(path):
                events.append("sync_root_parent" if path is output.parent else "sync_output")

            def __init__(self, *args):
                events.append("journal")
                raise StopBeforeEffects()

        cfg = self.configuration()
        modules = {"kernel_lock": object(), "warm_reviewed_private_artifacts":
            SimpleNamespace(closed_plan=lambda *args: ({}, {str(i): "a" * 64 for i in range(14)})),
            "host_gate": SimpleNamespace(Journal=Journal), "reader_lifecycle": object()}
        with mock.patch.object(subject, "require_runtime"), \
                mock.patch.object(subject, "verified_inputs", return_value={"pyproject.toml": b"m", "poetry.lock": b"l"}), \
                mock.patch.object(subject, "load_verified", return_value=modules), \
                mock.patch.object(subject, "OUTPUT_ROOT", output):
            with self.assertRaises(StopBeforeEffects):
                subject.apply(cfg, "a" * 64)
        self.assertEqual(events, ["output_mkdir", "sync_root_parent", "run_mkdir", "sync_output", "journal"])

    def test_default_plan_never_reads_inputs_or_contacts_hosts(self):
        with mock.patch.object(sys, "argv", ["operator_bootstrap.py", "--config", "/missing"]), \
                mock.patch.object(subject, "protected_bytes", side_effect=AssertionError("input read")), \
                mock.patch.object(subject, "apply", side_effect=AssertionError("apply")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(subject.main(), 0)
        self.assertEqual(output.getvalue(), "PLAN_ONLY_NO_CONTACT_NO_AUTHORITY\n")

    def test_wrong_config_digest_cannot_reach_apply(self):
        with mock.patch.object(sys, "argv", ["operator_bootstrap.py", "--config", "/missing",
                "--apply", "--expect-config-sha256", "0" * 64]), \
                mock.patch.object(subject, "protected_bytes", return_value=b"{}"), \
                mock.patch.object(subject, "apply", side_effect=AssertionError("apply")):
            with self.assertRaises(subject.Refused):
                subject.main()

    def test_arbitrary_config_path_cannot_reach_apply_even_with_matching_hash(self):
        raw = b"{}"
        with mock.patch.object(sys, "argv", ["operator_bootstrap.py", "--config", "/other/config.json",
                "--apply", "--expect-config-sha256", hashlib.sha256(raw).hexdigest()]), \
                mock.patch.object(subject, "protected_bytes", return_value=raw), \
                mock.patch.object(subject, "apply", side_effect=AssertionError("apply")):
            with self.assertRaises(subject.Refused):
                subject.main()

    def test_pending_authority_cannot_load_source_or_mint(self):
        cfg = self.configuration()
        cfg["authorization_reference"] = "PENDING_EXACT_LIVE_APPROVAL"
        with mock.patch.object(subject, "require_runtime"), \
                mock.patch.object(subject, "verified_inputs", side_effect=AssertionError("source")):
            with self.assertRaises(subject.Refused):
                subject.apply(cfg, "0" * 64)

    def test_changed_frozen_owner_is_refused_before_source_evaluation(self):
        cfg = {"source_pins": {n: "0" * 64 for n in
               {*subject.CORE_PINS, *subject.TOOL_PINS, *subject.ADAPTER_NAMES, *subject.DATA_NAMES}}}
        with mock.patch.object(subject, "protected_bytes", side_effect=AssertionError("source read")):
            with self.assertRaises(subject.Refused):
                subject.verified_inputs(cfg)

    def test_wrong_http_kind_and_malformed_credential_never_open_socket(self):
        with mock.patch.object(subject.http.client, "HTTPSConnection", side_effect=AssertionError("network")):
            for kind, token in (("create_team", None), ("reader_get", "not-a-token"),
                                ("reader_get", "x" * 40)):
                with self.subTest(kind=kind, token=token), self.assertRaises(subject.Refused):
                    subject.request_status(kind, token)

    def test_http_request_has_fixed_verified_origin_no_body_read(self):
        response = mock.Mock(status=401)
        response.read.side_effect = AssertionError("response body read")
        connection = mock.Mock()
        connection.getresponse.return_value = response
        context = mock.Mock()
        with mock.patch.object(subject.ssl, "SSLContext", return_value=context), \
                mock.patch.object(subject.http.client, "HTTPSConnection", return_value=connection) as constructor:
            result = subject.request_status("reader_get", "1" * 40)
        self.assertEqual(result, {"status": 401})
        constructor.assert_called_once_with("registry.dotmac.io", 443, context=context, timeout=15)
        context.load_verify_locations.assert_called_once_with(cafile="/etc/ssl/certs/ca-certificates.crt")
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("GET", subject.GET_PATH))
        self.assertEqual(set(kwargs["headers"]), {"Accept", "Authorization"})
        response.close.assert_called_once()
        connection.close.assert_called_once()

    def test_fixed_http_origin_does_not_follow_redirect(self):
        connection = mock.Mock()
        connection.getresponse.return_value.status = 302
        with mock.patch.object(subject.ssl, "SSLContext"), \
                mock.patch.object(subject.http.client, "HTTPSConnection", return_value=connection):
            self.assertEqual(subject.request_status("reader_get", None), {"status": 302})
        self.assertEqual(connection.request.call_count, 1)
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
