"""Hosted PostgreSQL 16 transaction tests against a synthetic Unix-only cluster.

The workflow owns initdb/pg_ctl and cluster teardown. No Docker, network address,
DSN, credential, production fallback, or cluster startup is accepted here. Missing
fixture configuration is an error, never a skipped qualification. These tests do
not prove Forgejo cache invalidation, live authority, or same-token HTTP 401.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
import uuid

from reader_revocation_sql import build_revocation_sql


PSQL = "/usr/lib/postgresql/16/bin/psql"
PORT = "55439"
MARKER = {"status": "EXACT_TOKEN_ROW_TRANSACTION_COMMITTED", "deleted_rows": 1}


def synthetic_binding():
    return {"kind": "reader", "token_id": 31, "user_id": 10,
            "username": "cp-bundle-reader", "token_name": "cp-artifact-bootstrap-20261127-r2",
            "scope": "read:package", "created_unix": 1795644000}


class NativeRevocationTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Resolve to reject traversal and sockets reached through a symlink that
        # escapes RUNNER_TEMP. No ambient PostgreSQL connection variables survive.
        temporary = os.environ.get("RUNNER_TEMP")
        socket = os.environ.get("CP_TEST_PG_SOCKET")
        if not temporary or not socket:
            raise RuntimeError("native fixture requires RUNNER_TEMP and CP_TEST_PG_SOCKET")
        root, endpoint = Path(temporary), Path(socket)
        if not root.is_absolute() or not endpoint.is_absolute():
            raise RuntimeError("native fixture paths must be absolute")
        root, endpoint = root.resolve(strict=True), endpoint.resolve(strict=True)
        if not root.is_dir() or not endpoint.is_dir() or root == endpoint or root not in endpoint.parents:
            raise RuntimeError("native fixture socket must be strictly under RUNNER_TEMP")
        cls.socket = str(endpoint)
        # The fixed service account is the Unix account running this hosted job;
        # use its name rather than USER/PGUSER environment connection settings.
        import pwd
        cls.username = pwd.getpwuid(os.getuid()).pw_name
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", cls.username):
            raise RuntimeError("unexpected hosted fixture account name")
        cls.environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PGPASSFILE": "/dev/null",
            "PGSERVICEFILE": "/dev/null", "PGSYSCONFDIR": "/nonexistent",
            "PGCONNECT_TIMEOUT": "5",
        }
        cls.owned_databases = set()
        result = cls.psql("SELECT current_setting('server_version_num'), inet_server_addr() IS NULL;")
        if result.returncode != 0:
            raise RuntimeError("native fixture PostgreSQL unavailable")
        fields = result.stdout.strip().split("|")
        if len(fields) != 2 or not fields[0].isdigit() or not 160000 <= int(fields[0]) < 170000 or fields[1] != "t":
            raise RuntimeError("native fixture must be PostgreSQL 16 on a Unix socket")

    @classmethod
    def psql(cls, sql, database="postgres"):
        if database != "postgres" and (
                not isinstance(database, str) or not re.fullmatch(r"cp_native_[a-f0-9]{32}", database)
                or database not in cls.owned_databases):
            raise RuntimeError("only the control database or this fixture's owned databases are allowed")
        return subprocess.run(
            [PSQL, "-X", "-qAt", "--no-password", "-h", cls.socket, "-p", PORT,
             "-U", cls.username, "-d", database, "--set", "ON_ERROR_STOP=1", "-f", "-"],
            input=sql, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False, env=cls.environment,
        )

    def setUp(self):
        self.dbname = "cp_native_" + uuid.uuid4().hex
        if not re.fullmatch(r"cp_native_[a-f0-9]{32}", self.dbname):
            raise RuntimeError("invalid synthetic database")
        self.must_succeed(self.psql(f'CREATE DATABASE "{self.dbname}" TEMPLATE template0;'))
        self.owned_databases.add(self.dbname)
        self.addCleanup(self.drop_database)
        self.reset_fixture()

    def drop_database(self):
        if self.dbname not in self.owned_databases or not re.fullmatch(r"cp_native_[a-f0-9]{32}", self.dbname):
            raise RuntimeError("refusing cleanup of an unowned synthetic database")
        self.must_succeed(self.psql(f'DROP DATABASE "{self.dbname}";'))
        self.owned_databases.remove(self.dbname)

    def scoped(self, sql):
        # No preamble or rewriting: generated SQL executes byte-for-byte in its
        # own database against the same public schema as the production target.
        return self.psql(sql, database=self.dbname)

    def must_succeed(self, result):
        # Fixture queries are synthetic and contain no secret-bearing columns.
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def reset_fixture(self):
        self.must_succeed(self.scoped('''
SET search_path TO public, pg_catalog;
DROP TABLE IF EXISTS access_token;
DROP TABLE IF EXISTS "user";
CREATE TABLE "user" (
    id bigint PRIMARY KEY, name text NOT NULL, lower_name text NOT NULL, type integer NOT NULL,
    is_admin boolean NOT NULL, is_restricted boolean NOT NULL, is_active boolean NOT NULL,
    prohibit_login boolean NOT NULL, must_change_password boolean NOT NULL,
    login_type integer NOT NULL, login_source bigint NOT NULL
);
CREATE TABLE access_token (
    id bigint PRIMARY KEY, uid bigint NOT NULL, name text NOT NULL, scope text NOT NULL,
    created_unix bigint NOT NULL
);
INSERT INTO "user" VALUES
    (10, 'cp-bundle-reader', 'cp-bundle-reader', 0, FALSE, FALSE, TRUE, FALSE, FALSE, 0, 0),
    (5, 'ci-reader', 'ci-reader', 0, FALSE, FALSE, TRUE, FALSE, FALSE, 0, 0);
INSERT INTO access_token VALUES
    (2, 5, 'retained-2', 'read:package', 1700000000),
    (16, 5, 'retained-16', 'read:package', 1700000000),
    (26, 5, 'retained-26', 'read:package', 1700000000),
    (28, 5, 'retained-28', 'read:package', 1700000000),
    (31, 10, 'cp-artifact-bootstrap-20261127-r2', 'read:package', 1795644000),
    (32, 10, 'unrelated-token', 'read:package', 1795643999);
'''))

    def snapshot(self):
        raw = self.must_succeed(self.scoped('''
SELECT json_build_object(
    'users', (SELECT json_agg(row_to_json(u) ORDER BY u.id) FROM public."user" u),
    'tokens', (SELECT json_agg(row_to_json(a) ORDER BY a.id) FROM public.access_token a)
);
'''))
        return json.loads(raw)

    def assert_success_only_exact_row(self):
        binding = synthetic_binding()
        before = self.snapshot()
        result = self.scoped(build_revocation_sql(binding))
        self.assertEqual(json.loads(self.must_succeed(result)), MARKER)
        expected = {**before, "tokens": [a for a in before["tokens"] if a["id"] != binding["token_id"]]}
        self.assertEqual(self.snapshot(), expected)
        return binding

    def assert_refused_unchanged(self, binding):
        before = self.snapshot()
        result = self.scoped(build_revocation_sql(binding))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("EXACT_TOKEN_ROW_TRANSACTION_COMMITTED", result.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_reader_commit_preserves_every_other_row(self):
        self.assert_success_only_exact_row()

    def test_wrong_row_and_owner_guards_leave_all_rows_unchanged(self):
        mutations = (
            "UPDATE access_token SET id = 91 WHERE id = 31;",
            "UPDATE access_token SET uid = 5 WHERE id = 31;",
            "UPDATE access_token SET name = 'wrong-name' WHERE id = 31;",
            "UPDATE access_token SET scope = 'write:package' WHERE id = 31;",
            "UPDATE access_token SET created_unix = 2 WHERE id = 31;",
            'DELETE FROM "user" WHERE id = 10;',
            'UPDATE "user" SET name = \'wrong-owner\' WHERE id = 10;',
            'UPDATE "user" SET lower_name = \'wrong-owner\' WHERE id = 10;',
            'UPDATE "user" SET type = 1 WHERE id = 10;',
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.reset_fixture()
                self.must_succeed(self.scoped(mutation))
                self.assert_refused_unchanged(synthetic_binding())

    def test_nearby_row_is_not_adopted(self):
        self.assert_refused_unchanged({**synthetic_binding(), "token_id": 32})

    def test_permission_drift_does_not_block_cleanup(self):
        self.must_succeed(self.scoped('''UPDATE "user" SET is_admin = TRUE,
            is_restricted = TRUE, is_active = FALSE, prohibit_login = TRUE,
            must_change_password = TRUE, login_type = 3, login_source = 44
            WHERE id = 10;'''))
        self.assert_success_only_exact_row()

    def test_repeated_cleanup_refuses_without_collateral(self):
        row = self.assert_success_only_exact_row()
        self.assert_refused_unchanged(row)

    def test_exception_rolls_back_even_a_prior_transaction_local_change(self):
        # A synthetic BEFORE trigger changes a different row, then suppresses the
        # requested deletion. The generated SQL remains completely unchanged;
        # its rowcount exception must roll back even that trigger's side effect.
        self.must_succeed(self.scoped('''
CREATE FUNCTION public.cp_native_before_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE public.access_token SET created_unix = 7 WHERE id = 26;
    RETURN NULL;
END;
$$;
CREATE TRIGGER cp_native_suppress_delete BEFORE DELETE ON public.access_token
FOR EACH ROW EXECUTE FUNCTION public.cp_native_before_delete();
'''))
        before = self.snapshot()
        result = self.scoped(build_revocation_sql(synthetic_binding()))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("EXACT_TOKEN_ROW_TRANSACTION_COMMITTED", result.stdout)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
