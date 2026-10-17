"""One fixed GitHub signature and claims verifier; no authority or cache."""

from __future__ import annotations

import base64
import re
import time
from datetime import UTC, datetime
from typing import TypedDict, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
    json_record,
    json_string,
    strict_json,
)


class VerifiedClaims(TypedDict):
    iat: int
    nbf: int
    exp: int
    jti: str
    run_id: str
    run_attempt: str


GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_PATH = "/.well-known/jwks"
_FIXED_CLAIMS = {
    "iss": GITHUB_ISSUER,
    "aud": "urn:dotmac:gate0:rehearsal-issuer",
    "repository": "dotmac-tech/gate0-issuer-execution",
    "repository_id": "1397614140",
    "repository_owner_id": "335992433",
    "environment": "rehearsal-issuer-protected",
    "ref": "refs/heads/main",
    "workflow_ref": (
        "dotmac-tech/gate0-issuer-execution/"
        ".github/workflows/gate0-issuer.yml@refs/heads/main"
    ),
    "event_name": "workflow_dispatch",
}


def _decode(value: str, maximum: int) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise ProviderRefused()
    raw = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ProviderRefused()
    return raw


def verify_github_claims(
    token: str, *, transport: BoundedJSONTransport, deadline: float
) -> VerifiedClaims:
    if time.monotonic() >= deadline:
        raise ProviderRefused()
    if type(token) is not str or not 0 < len(token) <= 32768:
        raise ProviderRefused()
    parts = token.split(".")
    if len(parts) != 3:
        raise ProviderRefused()
    header = strict_json(_decode(parts[0], 4096), 4096)
    if (
        not {"alg", "kid", "typ"} <= set(header)
        or set(header) - {"alg", "kid", "typ", "x5t"}
        or header["alg"] != "RS256"
        or header["typ"] != "JWT"
        or not 0 < len(json_string(header["kid"])) <= 512
    ):
        raise ProviderRefused()
    claims = cast(VerifiedClaims, strict_json(_decode(parts[1], 24576), 24576))
    if any(claims.get(key) != value for key, value in _FIXED_CLAIMS.items()):
        raise ProviderRefused()
    if "job_workflow_ref" in claims or "job_workflow_sha" in claims:
        raise ProviderRefused()
    now = datetime.now(UTC).timestamp()
    if (
        any(type(claims.get(key)) is not int for key in ("iat", "nbf", "exp"))
        or not claims["iat"] <= now < claims["exp"]
        or not claims["nbf"] <= now
        or not claims["iat"] <= claims["nbf"] < claims["exp"]
        or not 0 < claims["exp"] - claims["iat"] <= 300
        or type(claims.get("jti")) is not str
        or not 0 < len(claims["jti"]) <= 512
        or any(
            type(claims.get(key)) is not str
            or re.fullmatch(r"[1-9][0-9]{0,19}", json_string(claims.get(key))) is None
            for key in ("run_id", "run_attempt")
        )
    ):
        raise ProviderRefused()
    jwt_deadline = min(deadline, time.monotonic() + claims["exp"] - now)
    if (
        type(transport) is not BoundedJSONTransport
        or transport.origin.rstrip("/") != GITHUB_ISSUER
    ):
        raise ProviderRefused()
    jwks = transport.request(
        GITHUB_JWKS_PATH,
        method="GET",
        token=None,
        document=None,
        deadline=jwt_deadline,
    )
    raw_keys = jwks.get("keys")
    if (
        type(raw_keys) is not list
        or not 0 < len(raw_keys) <= 16
        or any(type(k) is not dict for k in raw_keys)
    ):
        raise ProviderRefused()
    keys = [json_record(k) for k in cast(list[object], raw_keys)]
    ids = [json_string(k.get("kid")) for k in keys]
    if any(type(kid) is not str for kid in ids) or len(ids) != len(set(ids)):
        raise ProviderRefused()
    selected = [k for k in keys if k["kid"] == header["kid"]]
    if len(selected) != 1:
        raise ProviderRefused()
    key = selected[0]
    if (
        key.get("kty") != "RSA"
        or key.get("alg") != "RS256"
        or key.get("use") != "sig"
        or any(name in key for name in ("d", "p", "q", "dp", "dq", "qi", "oth"))
        or ("key_ops" in key and key["key_ops"] != ["verify"])
    ):
        raise ProviderRefused()
    n = int.from_bytes(_decode(json_string(key["n"]), 1400), "big")
    e = int.from_bytes(_decode(json_string(key["e"]), 16), "big")
    if not 2048 <= n.bit_length() <= 8192 or e != 65537:
        raise ProviderRefused()
    rsa.RSAPublicNumbers(e, n).public_key().verify(
        _decode(parts[2], 1400),
        (parts[0] + "." + parts[1]).encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if (
        datetime.now(UTC).timestamp() >= claims["exp"]
        or time.monotonic() >= jwt_deadline
    ):
        raise ProviderRefused()
    return claims
