"""Synthetic stdlib tests. Run only in the authorized hosted validation lane.

These exercise preparation, never PostgreSQL or any other external service.
They do not qualify schema availability, native commit, cache invalidation or
privileged concurrent changes; the separate native acceptance gate remains.
"""

import re
import unittest

from revocation_sql import build_revocation_sql


def canary():
    return dict(kind="canary", token_id=101, user_id=19,
                username="cp-revoke-proof-20261125-abcd",
                token_name="cp-canary-read-20261125-abcd", scope="read:user",
                created_unix=1795644000)


def bootstrap():
    return dict(kind="bootstrap", token_id=102, user_id=1, username="dotmac-admin",
                token_name="cp-org-bootstrap-20261125-abcd",
                scope="write:organization", created_unix=1795644001)


class BindingRefusalTests(unittest.TestCase):
    def reject(self, key, values, factory=canary):
        for value in values:
            with self.subTest(key=key, value=value):
                binding = factory()
                binding[key] = value
                with self.assertRaises(ValueError):
                    build_revocation_sql(binding)

    def test_exact_key_set(self):
        original = canary()
        for key in original:
            binding = dict(original)
            del binding[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                build_revocation_sql(binding)
        for key in ("sql", "token", "is_admin", "membership", "config", "scope_sql"):
            binding = dict(original, **{key: "anything"})
            with self.subTest(extra=key), self.assertRaises(ValueError):
                build_revocation_sql(binding)
        for wrong in (None, [], tuple(original), "binding"):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                build_revocation_sql(wrong)

    def test_refuses_dict_subclass(self):
        class CustomDict(dict):
            pass
        with self.assertRaises(ValueError):
            build_revocation_sql(CustomDict(canary()))

    def test_integer_types_and_database_bound(self):
        for field in ("token_id", "user_id", "created_unix"):
            self.reject(field, [True, False, None, 0, -1, 1.0, "101", 2**63])

    def test_protected_token_ids_for_both_kinds(self):
        for factory in (canary, bootstrap):
            self.reject("token_id", [2, 16, 26, 28], factory)

    def test_canary_is_never_existing_principal(self):
        self.reject("user_id", [1, 2, 3, 4, 5])
        self.reject("username", ["dotmac-admin", "ci-reader", "cp-bundle-reader"])

    def test_bootstrap_exact_identity(self):
        self.reject("user_id", [2, 5, 19], bootstrap)
        self.reject("username", ["Dotmac-admin", "dotmac", "dotmac-admin-other"], bootstrap)

    def test_fixed_kind_and_scope(self):
        self.reject("kind", ["CANARY", "", None, [], 1, "canary;COMMIT;"])
        for factory in (canary, bootstrap):
            self.reject("scope", [None, [], "all", "read:package", "read:user,write:organization",
                                  "read:user ", "write:organization;COMMIT;"], factory)
        self.reject("scope", ["write:organization"])
        self.reject("scope", ["read:user"], bootstrap)

    def test_literal_and_psql_injection_refused(self):
        for field in ("username", "token_name"):
            self.reject(field, ["x' OR TRUE--", "x\\';COMMIT;--", "x\nCOMMIT;", "x\x00",
                                "x$cp_exact_revoke$", "x\\!echo", "x\u2010y", "x\u2028y"])

    def test_suffix_min_max_and_alphabet(self):
        for field, prefix in (("username", "cp-revoke-proof-"),
                              ("token_name", "cp-canary-read-")):
            self.reject(field, [prefix, prefix + "a" * 7, prefix + "a" * 33,
                                prefix + "-abcdefg", prefix + "abcdefg-",
                                prefix + "abcdefg_", prefix + "ABCDefgh",
                                prefix + "abcd\u00e9fgh", prefix + "abcdefgh\n"])
            for suffix in ("abcdefgh", "a" * 32, "abcd-efg"):
                binding = canary()
                binding[field] = prefix + suffix
                self.assertIsInstance(build_revocation_sql(binding), str)
        self.reject("token_name", ["cp-org-bootstrap-" + "a" * 7,
                                   "cp-org-bootstrap-" + "a" * 33], bootstrap)

    def test_cross_kind_names_refused(self):
        self.reject("token_name", [bootstrap()["token_name"]])
        self.reject("token_name", [canary()["token_name"]], bootstrap)


class TransactionStructureTests(unittest.TestCase):
    @staticmethod
    def executable_sql(sql):
        return "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))

    def test_input_not_mutated_and_output_deterministic(self):
        for factory in (canary, bootstrap):
            binding = factory()
            before = dict(binding)
            sql = build_revocation_sql(binding)
            self.assertEqual(binding, before)
            self.assertEqual(sql, build_revocation_sql(dict(binding)))

    def test_single_transaction_and_post_commit_result(self):
        for factory in (canary, bootstrap):
            with self.subTest(kind=factory()["kind"]):
                sql = self.executable_sql(build_revocation_sql(factory()))
                self.assertTrue(sql.startswith("BEGIN;\n"))
                self.assertEqual(sql.count("\nCOMMIT;"), 1)
                self.assertEqual(sql.count("SET LOCAL search_path = public, pg_catalog;"), 1)
                self.assertLess(sql.index("SET LOCAL search_path = public, pg_catalog;"), sql.index("DO $cp_exact_revoke$"))
                self.assertEqual(sql.count("SET LOCAL statement_timeout = '10s';"), 1)
                self.assertEqual(sql.count("SET LOCAL lock_timeout = '5s';"), 1)
                self.assertTrue(sql.rstrip().endswith(
                    "SELECT '{\"status\":\"EXACT_TOKEN_ROW_TRANSACTION_COMMITTED\",\"deleted_rows\":1}'::json;"))
                self.assertLess(sql.index("COMMIT;"), sql.index("TRANSACTION_COMMITTED"))

    def test_one_delete_and_no_collateral_mutations(self):
        for factory in (canary, bootstrap):
            sql = self.executable_sql(build_revocation_sql(factory()))
            self.assertEqual(len(re.findall(r"\bDELETE\s+FROM\b", sql)), 1)
            self.assertIn("DELETE FROM access_token a", sql)
            self.assertNotRegex(sql, r"\b(?:INSERT|TRUNCATE|CREATE|ALTER|DROP|GRANT|REVOKE|COPY|CALL)\b")
            self.assertNotRegex(sql, r"\bUPDATE\s+[a-z_\"]")
            self.assertNotIn("RETURNING", sql)
            self.assertNotIn("SELECT *", sql)
            for forbidden in ("token_hash", "token_salt", "token_last_eight", "last_eight", "substring("):
                self.assertNotIn(forbidden, sql.lower())

    def test_exact_metadata_guards_and_rowcount(self):
        for factory in (canary, bootstrap):
            binding = factory()
            sql = build_revocation_sql(binding)
            for fragment in (f"a.id = {binding['token_id']}", f"a.uid = {binding['user_id']}",
                             f"a.name = '{binding['token_name']}'", f"a.scope = '{binding['scope']}'",
                             f"a.created_unix = {binding['created_unix']}"):
                self.assertIn(fragment, sql)
            self.assertEqual(sql.count("GET DIAGNOSTICS affected = ROW_COUNT;"), 2)
            self.assertEqual(sql.count("IF affected <> 1 THEN"), 2)
            self.assertEqual(sql.count("RAISE EXCEPTION"), 2)
            self.assertLess(sql.index("FOR UPDATE;"), sql.index("DELETE FROM"))

    def test_stable_owner_identity_rechecked_in_delete(self):
        for factory in (canary, bootstrap):
            binding = factory()
            sql = build_revocation_sql(binding)
            for fragment in (f"u.id = {binding['user_id']}", f"u.name = '{binding['username']}'",
                             f"u.lower_name = '{binding['username']}'", "u.type = 0"):
                self.assertEqual(sql.count(fragment), 2)
            self.assertEqual(sql.count("FOR UPDATE;"), 1)
            self.assertIn("revocation refused: owner identity mismatch", sql)

    def test_permission_or_grant_drift_cannot_block_exact_cleanup(self):
        # The backend checks capabilities BEFORE mint. Cleanup must still remove
        # this exact new token when later grants, flags or memberships change.
        for factory in (canary, bootstrap):
            sql = self.executable_sql(build_revocation_sql(factory()))
            for forbidden in ("is_admin", "is_restricted", "is_active", "prohibit_login",
                              "must_change_password", "login_type", "login_source", "org_user",
                              "team_user", "repository", "public_key", "gpg_key", "collaboration",
                              "authorize", "org_id", "team_id", "Owners"):
                with self.subTest(kind=factory()["kind"], predicate=forbidden):
                    self.assertNotIn(forbidden, sql)
            self.assertEqual(re.findall(r"\bFROM\s+([a-z_\"]+)", sql),
                             ['"user"', "access_token", '"user"'])
            self.assertNotRegex(sql, r"\b(?:GRANT|REVOKE|INSERT|ALTER|TRUNCATE|DROP)\b")


if __name__ == "__main__":
    unittest.main()
