"""Synthetic observer URL tests; no database or network access."""

import contextlib
import importlib.util
import io
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy.engine import URL, make_url

HERE = Path(__file__).resolve().parent
SCRIPTS = (HERE / "c4" / "a2_recovery_observe_container.py",)
if secondary := os.environ.get("A2_TEST_OBSERVER_SECONDARY"):
    SCRIPTS += (Path(secondary),)


def load_script(path):
    spec = importlib.util.spec_from_file_location("observer_driver_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ObserverDriverTests(unittest.TestCase):
    def setUp(self):
        self.observers = [load_script(path) for path in SCRIPTS]

    def test_bare_postgresql_selects_psycopg3(self):
        for observer in self.observers:
            with self.subTest(observer=observer.__file__):
                url = observer.observer_url(
                    "postgresql://synthetic:example@localhost:5432/test"
                )
                self.assertIsInstance(url, URL)
                self.assertEqual(url.drivername, "postgresql+psycopg")
                self.assertEqual(url.get_dialect().driver, "psycopg")

    def test_explicit_psycopg_is_preserved(self):
        dsn = "postgresql+psycopg://synthetic:example@localhost/test?sslmode=require"
        for observer in self.observers:
            self.assertEqual(observer.observer_url(dsn), make_url(dsn))

    def test_credentials_and_repeated_query_values_survive_driver_selection(self):
        # Synthetic values deliberately exercise percent-encoding and repeated keys.
        dsn = (
            "postgresql://test%40user:test%3Apass%2F%25%40@localhost:5432/test_db"
            "?sslmode=verify-full&options=-c%20application_name%3Dtest%2Bprobe"
            "&host=one.example&host=two.example&sslrootcert=%2Ftmp%2Ftest%20ca.pem"
        )
        original = make_url(dsn)
        for observer in self.observers:
            url = observer.observer_url(dsn)
            self.assertEqual(url, original.set(drivername="postgresql+psycopg"))
            self.assertEqual(url.username, "test@user")
            self.assertEqual(url.password, "test:pass/%@")
            self.assertEqual(url.query, original.query)
            self.assertEqual(url.query["host"], ("one.example", "two.example"))

    def test_unexpected_schemes_and_drivers_refuse_without_echoing_dsn(self):
        for observer in self.observers:
            for scheme in (
                "postgres",
                "postgresql+psycopg2",
                "postgresql+asyncpg",
                "mysql",
                "sqlite",
            ):
                with self.subTest(observer=observer.__file__, scheme=scheme):
                    stderr = io.StringIO()
                    with (
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as refusal,
                    ):
                        observer.observer_url(
                            scheme + "://synthetic:sensitive-marker@localhost/test"
                        )
                    self.assertEqual(refusal.exception.code, 2)
                    self.assertEqual(
                        stderr.getvalue(), "recovery-observe STOP: dsn_driver\n"
                    )

    def test_malformed_urls_refuse_without_echoing_dsn(self):
        for observer in self.observers:
            for dsn in (
                "sensitive-marker",
                "postgresql://synthetic:sensitive-marker@localhost:not-a-port/test",
            ):
                stderr = io.StringIO()
                with (
                    contextlib.redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as refusal,
                ):
                    observer.observer_url(dsn)
                self.assertEqual(refusal.exception.code, 2)
                self.assertEqual(
                    stderr.getvalue(), "recovery-observe STOP: dsn_invalid\n"
                )

    def test_main_passes_url_object_to_engine_without_connecting(self):
        auth = types.ModuleType("dotmac_deployment_control.authorization")
        auth.AuthorizationEnvelopeV2 = object

        class EngineBoundaryReached(Exception):
            pass

        for observer in self.observers:
            with (
                patch.object(
                    sys, "argv", ["observer", "rollout", "plan", "command", "dispatch"]
                ),
                patch.dict(
                    "os.environ",
                    {"A2_OBSERVE_DSN": "postgresql://synthetic:example@localhost/test"},
                ),
                patch.dict(
                    sys.modules, {"dotmac_deployment_control.authorization": auth}
                ),
                patch(
                    "sqlalchemy.create_engine", side_effect=EngineBoundaryReached
                ) as create_engine,
                self.assertRaises(EngineBoundaryReached),
            ):
                observer.main()
            url = create_engine.call_args.args[0]
            self.assertIsInstance(url, URL)
            self.assertEqual(url.drivername, "postgresql+psycopg")
            self.assertEqual(url.password, "example")


if __name__ == "__main__":
    unittest.main()
