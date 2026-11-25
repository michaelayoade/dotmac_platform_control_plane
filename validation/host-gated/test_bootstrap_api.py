"""Offline tests; execution belongs on the authorized hosted test runner."""

import json
import os
import ssl
import unittest
from unittest.mock import Mock, patch

import bootstrap_api as api


TOKEN = "a" * 40


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.context = Mock()
        self.response = Mock(status=200)
        self.connection = Mock()
        self.connection.getresponse.return_value = self.response
        self.context_patch = patch.object(api.ssl, "SSLContext", return_value=self.context)
        self.context_constructor = self.context_patch.start()
        self.factory_patch = patch.object(api, "_connection_factory", return_value=self.connection)
        self.factory = self.factory_patch.start()
        self.addCleanup(self.factory_patch.stop)
        self.addCleanup(self.context_patch.stop)

    def assert_request(self, method, path, body=None, json_header=False):
        headers = {"Authorization": "token " + TOKEN}
        if json_header:
            headers["Content-Type"] = "application/json"
        self.connection.request.assert_called_once_with(method, path, body=body, headers=headers)
        self.context_constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations.assert_called_once_with(
            cafile="/etc/ssl/certs/ca-certificates.crt"
        )
        self.factory.assert_called_once_with(
            "registry.dotmac.io", 443, timeout=15, context=self.context
        )
        self.connection.close.assert_called_once_with()

    def test_get_endpoints_discard_bodies(self):
        for kind, path in (
            ("bootstrap_positive_get", "/api/v1/orgs/dotmac/teams"),
            ("bootstrap_revoked_get", "/api/v1/orgs/dotmac/teams"),
            ("canary_get", "/api/v1/user"),
        ):
            with self.subTest(kind=kind):
                self.assertEqual(api.request(kind, TOKEN), {"status": 200})
                self.assert_request("GET", path)
                self.response.read.assert_not_called()
                self.factory.reset_mock()
                self.connection.reset_mock()
                self.context_constructor.reset_mock()
                self.context.reset_mock()

    def test_exact_creation_payload_and_allowlisted_result(self):
        self.response.status = 201
        self.response.read.return_value = b'{"id":42,"name":"cp-bundle-readers","secret":"discard"}'
        self.assertEqual(api.request("create_team", TOKEN), {"status": 201, "team_id": 42})
        body = b'{"name":"cp-bundle-readers","permission":"read","includes_all_repositories":false,"can_create_org_repo":false,"units_map":{"repo.packages":"read"}}'
        self.assert_request("POST", "/api/v1/orgs/dotmac/teams", body, True)
        self.response.read.assert_called_once_with(65537)

    def test_exact_membership_path(self):
        self.response.status = 204
        self.assertEqual(api.request("add_member", TOKEN, team_id=42), {"status": 204})
        self.assert_request("PUT", "/api/v1/teams/42/members/cp-bundle-reader")
        self.response.read.assert_not_called()

    def test_invalid_inputs_never_construct_transport(self):
        cases = [
            ("create_team", value, {})
            for value in (None, 123, b"a" * 40, "a" * 39, "a" * 41, "g" * 40, TOKEN + "\n", TOKEN + "\r\nInjected: yes")
        ]
        cases += [("add_member", TOKEN, {"team_id": value}) for value in (None, True, False, 0, -1, "42", 1.0, "42/else")]
        cases += [(value, TOKEN, {}) for value in (None, "GET", "https://elsewhere", "create_team\n")]
        cases += [("canary_get", TOKEN, {"team_id": 42})]
        for kind, token, kwargs in cases:
            with self.subTest(kind=kind, value=repr(token), kwargs=kwargs):
                with self.assertRaises(api.Refused) as caught:
                    api.request(kind, token, **kwargs)
                self.assertEqual(str(caught.exception), "Invalid request input")
        self.factory.assert_not_called()
        self.context_constructor.assert_not_called()

    def test_statuses_never_redirect_retry_or_read_body(self):
        for status in (201, 301, 302, 307, 308, 401, 403, 409, 429, 500):
            with self.subTest(status=status):
                self.response.status = status
                self.assertEqual(api.request("canary_get", TOKEN), {"status": status})
                self.factory.assert_called_once()
                self.connection.request.assert_called_once()
                self.response.read.assert_not_called()
                self.factory.reset_mock()
                self.connection.reset_mock()

    def test_non201_creation_does_not_read_body(self):
        self.response.status = 302
        self.assertEqual(api.request("create_team", TOKEN), {"status": 302})
        self.response.read.assert_not_called()
        self.connection.request.assert_called_once()

    def test_creation_rejects_malformed_or_unqualified_metadata(self):
        self.response.status = 201
        payloads = (
            b"", b"not json", b"\xff", b"[]", b"null",
            b'{"id":true,"name":"cp-bundle-readers"}',
            b'{"id":0,"name":"cp-bundle-readers"}',
            b'{"id":-1,"name":"cp-bundle-readers"}',
            b'{"id":"42","name":"cp-bundle-readers"}',
            b'{"id":1.0,"name":"cp-bundle-readers"}',
            b'{"id":42,"name":"other"}',
            b'{"id":42}', b'{"name":"cp-bundle-readers"}',
            b'{"id":42,"id":43,"name":"cp-bundle-readers"}',
            b"x" * 65537,
        )
        for payload in payloads:
            with self.subTest(payload_size=len(payload)):
                self.response.read.return_value = payload
                with self.assertRaises(api.Refused) as caught:
                    api.request("create_team", TOKEN)
                self.assertEqual(str(caught.exception), "Request refused")
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(TOKEN, repr(caught.exception))
                self.connection.close.assert_called_once_with()
                self.connection.reset_mock()

    def test_64k_valid_creation_body_is_accepted(self):
        self.response.status = 201
        data = json.dumps({"id": 1, "name": "cp-bundle-readers"}).encode()
        self.response.read.return_value = data + b" " * (65536 - len(data))
        self.assertEqual(api.request("create_team", TOKEN), {"status": 201, "team_id": 1})

    def test_transport_errors_are_secret_free_and_not_retried(self):
        self.connection.request.side_effect = OSError("secret body " + TOKEN)
        with self.assertRaises(api.Refused) as caught:
            api.request("canary_get", TOKEN)
        self.assertEqual(str(caught.exception), "Request refused")
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(TOKEN, repr(caught.exception))
        self.factory.assert_called_once()
        self.connection.request.assert_called_once()
        self.connection.close.assert_called_once()

    def test_tls_failure_is_secret_free_without_transport(self):
        self.context.load_verify_locations.side_effect = OSError(TOKEN)
        with self.assertRaises(api.Refused) as caught:
            api.request("canary_get", TOKEN)
        self.assertEqual(str(caught.exception), "Request refused")
        self.assertIsNone(caught.exception.__context__)
        self.factory.assert_not_called()

    def test_ambient_ssl_proxy_and_auth_settings_are_ignored(self):
        ambient = {
            "SSL_CERT_FILE": "/untrusted/ca", "SSL_CERT_DIR": "/untrusted",
            "HTTPS_PROXY": "http://proxy.invalid", "https_proxy": "http://proxy.invalid",
            "ALL_PROXY": "http://proxy.invalid", "NETRC": "/untrusted/netrc",
        }
        with patch.dict(os.environ, ambient), patch("urllib.request.getproxies", side_effect=AssertionError("proxy discovery")), patch("netrc.netrc", side_effect=AssertionError("ambient auth")), patch.object(api.ssl, "create_default_context", side_effect=AssertionError("ambient TLS")):
            self.assertEqual(api.request("canary_get", TOKEN), {"status": 200})
        self.assert_request("GET", "/api/v1/user")

    def test_invalid_status_is_refused_without_body(self):
        for status in (True, "200", 99, 600):
            with self.subTest(status=status):
                self.response.status = status
                with self.assertRaises(api.Refused):
                    api.request("canary_get", TOKEN)
                self.response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
