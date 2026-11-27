"""Pure synthetic binding checks, prepared for separately authorized hosted tests."""
import unittest
from reader_revocation_sql import build_revocation_sql


def binding():
    return {"kind": "reader", "token_id": 31, "user_id": 10,
            "username": "cp-bundle-reader", "token_name": "cp-artifact-bootstrap-20261127-r1",
            "scope": "read:package", "created_unix": 1795644000}


class ReaderSQLTests(unittest.TestCase):
    def test_exact_transaction_and_postcommit_marker(self):
        sql = build_revocation_sql(binding())
        self.assertEqual(sql.count("DELETE FROM"), 1)
        self.assertIn("FOR UPDATE", sql)
        self.assertIn("a.id = 31", sql)
        self.assertIn("a.uid = 10", sql)
        self.assertIn("a.created_unix = 1795644000", sql)
        self.assertLess(sql.index("COMMIT;"), sql.index("SELECT '{"))
        self.assertNotIn("is_admin", sql)
        self.assertNotIn("is_restricted", sql)

    def test_fixed_identity_and_strict_types(self):
        changes = {"kind": ("canary", "bootstrap", None), "user_id": (1, 11, True, 10.0),
                   "username": ("dotmac-admin", "cp-bundle-reader'", None),
                   "scope": ("write:package", "read:package,read:user", None),
                   "token_name": ("cp-artifact-bootstrap-20261127-r2", "x';DELETE", None),
                   "token_id": (True, 31.0, 0, -1, 2**63, "31", *range(1, 31)),
                   "created_unix": (True, 1.0, 0, -1, 2**63, "1")}
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    build_revocation_sql({**binding(), field: value})

    def test_no_extra_or_missing_fields(self):
        for key in binding():
            row = binding()
            del row[key]
            with self.assertRaises(ValueError):
                build_revocation_sql(row)
        with self.assertRaises(ValueError):
            build_revocation_sql({**binding(), "value": "synthetic"})
