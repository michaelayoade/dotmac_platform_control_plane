"""Fixed-endpoint HTTPS effects for the separately host-gated bootstrap.

This module supplies no stage authority. Callers must enforce their stage gates.
No response status, including 201, establishes metadata qualification.
"""

import http.client
import json
import re
import ssl


class Refused(Exception):
    """An input or transport response could not be used safely."""


_HOST = "registry.dotmac.io"
_PORT = 443
_TIMEOUT = 15
_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
_MAX_BODY = 64 * 1024
_TEAMS_PATH = "/api/v1/orgs/dotmac/teams"
_TEAM_NAME = "cp-bundle-readers"
_CREATE_BODY = json.dumps(
    {
        "name": _TEAM_NAME,
        "permission": "read",
        "includes_all_repositories": False,
        "can_create_org_repo": False,
        "units_map": {"repo.packages": "read"},
    },
    separators=(",", ":"),
).encode("ascii")
_connection_factory = http.client.HTTPSConnection


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid JSON object")
        result[key] = value
    return result


def request(kind: str, token: str, *, team_id=None) -> dict:
    """Perform one pinned request; return status and validated creation team_id.

    The private connection factory is replaceable in offline tests. There are no
    redirects, retries, proxy discovery, ambient authentication, or body logging.
    Every failure exposes only a fixed message.
    """
    if type(token) is not str or re.fullmatch(r"[0-9a-fA-F]{40}", token) is None:
        raise Refused("Invalid request input")
    if type(kind) is not str or kind not in (
        "bootstrap_positive_get",
        "create_team",
        "add_member",
        "bootstrap_revoked_get",
        "canary_get",
    ):
        raise Refused("Invalid request input")
    if kind == "add_member":
        if type(team_id) is not int or team_id <= 0:
            raise Refused("Invalid request input")
        method = "PUT"
        path = f"/api/v1/teams/{team_id}/members/cp-bundle-reader"
    else:
        if team_id is not None:
            raise Refused("Invalid request input")
        method = "POST" if kind == "create_team" else "GET"
        path = "/api/v1/user" if kind == "canary_get" else _TEAMS_PATH

    connection = None
    result = None
    failed = False
    try:
        # Deliberately avoid create_default_context and SSL_CERT_* discovery.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=_CA_FILE)
        connection = _connection_factory(
            _HOST, _PORT, timeout=_TIMEOUT, context=context
        )
        headers = {"Authorization": "token " + token}
        body = None
        if kind == "create_team":
            headers["Content-Type"] = "application/json"
            body = _CREATE_BODY
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Invalid status")
        result = {"status": status}
        if kind == "create_team" and status == 201:
            payload = response.read(_MAX_BODY + 1)
            if type(payload) is not bytes or len(payload) > _MAX_BODY:
                raise ValueError("Invalid body")
            metadata = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
            if (
                type(metadata) is not dict
                or type(metadata.get("id")) is not int
                or metadata["id"] <= 0
                or type(metadata.get("name")) is not str
                or metadata["name"] != _TEAM_NAME
            ):
                raise ValueError("Invalid team metadata")
            result["team_id"] = metadata["id"]
    except Exception:
        failed = True
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                failed = True
    # Raise outside the handler so transport exceptions cannot become context.
    if failed:
        raise Refused("Request refused")
    return result
