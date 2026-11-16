"""OpenBao transit signing custody for the a2 Control V2 identities (E6).

Michael's 2026-11-15 ruling: the authorization and dispatch private halves are
generated INSIDE OpenBao transit and never leave it. CP holds no key and no
standing credential. Issuance is an attended operator command:

* the credential is ONE use-limited transit token that the operator mints and
  pipes on stdin (never argv, environment, file, repr, log or exception text);
* the route is a unix socket that exists only while the operator's session is
  open (an SSH relay); there is no network client, no proxy, no redirect;
* the adapter is SIGN-ONLY: it posts exactly `{input, key_version}`, never
  `batch_input`, `context`, `prehashed` or an algorithm, and refuses a response
  that carries `batch_results`;
* the signature is parsed strictly (`vault:v1:` + standard base64, re-encoded
  identically, exactly 64 bytes), handed to `materials_producer`, which converts
  it to unpadded base64url and verifies it against the PINNED public identity
  before Control sees it. A wrong key, a swapped purpose, a rotated version or
  garbage therefore refuses before anything is persisted as signed.

There is no default mode and no fallback: with the configuration, the token or
the socket missing or malformed, the command refuses (typed, names only).

This module is imported only by `materials_producer.main` (an operator command)
and never by `vendor_cp.main` or any route (architecture-tested): ADR-0009's
rule against dereferencing in a request path is kept.

Ceremony helpers (`identity`, `pop-challenge`, `pop-verify`, `policy`) pin a
transit public key to `PlatformCpPublicVerificationIdentity.v1` with a
proof-of-possession, and render the exact least-privilege policy text. They
never contact OpenBao.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, BinaryIO, Final

from vendor_cp.deployment.materials_producer import Custody
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    IDENTITY_SCHEMA,
    PinnedVerificationIdentity,
)

__all__ = [
    "POP_PREFIX",
    "SIGNATURE_PREFIX",
    "TransitClient",
    "TransitCustodyConfig",
    "build_custody",
    "load_config",
    "main",
    "parse_signature",
    "readback_token_role",
    "render_token_role",
    "read_token",
    "render_policy",
]

SIGNATURE_PREFIX: Final = "vault:v1:"
POP_PREFIX: Final = b"dotmac.platform-cp.transit-pop.v1\x00"
MAX_RESPONSE_BYTES: Final = 16 * 1024
MAX_TOKEN_BYTES: Final = 512
#: One issuance makes exactly two sign calls: authorization, then dispatch.
MAX_SIGNS: Final = 2
_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_TOKEN: Final = re.compile(r"^[A-Za-z0-9._-]{8,512}$")
_CONFIG_FIELDS: Final = frozenset(
    {
        "mount",
        "authorization_key",
        "dispatch_key",
        "key_version",
        "authorization_identity",
        "dispatch_identity",
        "socket",
    }
)
_AUTHORIZATION_PURPOSE: Final = "deployment_authorization"
_DISPATCH_PURPOSE: Final = "deployment_dispatch"
_PURPOSES: Final = (_AUTHORIZATION_PURPOSE, _DISPATCH_PURPOSE)


def _refuse(message: str) -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(
        message, code=TargetRefusal.CUSTODY_NOT_CONFIGURED
    )


# ── configuration: closed, typed, no defaults ───────────────────────────────


@dataclass(frozen=True, slots=True)
class TransitCustodyConfig:
    mount: str
    authorization_key: str
    dispatch_key: str
    key_version: int
    authorization_identity: str
    dispatch_identity: str
    socket: str


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def strict_json(raw: bytes) -> Any:
    """JSON with duplicate keys refused. Raises ValueError on any defect."""
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)


def config_schema() -> dict[str, str]:
    return {
        "mount": "transit mount, a dedicated mount holding these keys only",
        "authorization_key": "transit key name for deployment_authorization",
        "dispatch_key": "transit key name for deployment_dispatch (distinct)",
        "key_version": "exactly 1",
        "authorization_identity": "absolute path of the pinned identity file",
        "dispatch_identity": "absolute path of the pinned identity file",
        "socket": "absolute path of the relay unix socket",
    }


def load_config(path: str) -> TransitCustodyConfig:
    """The closed configuration document, or a typed refusal."""
    try:
        document = strict_json(open(path, "rb").read(4097))
    except Exception:
        raise _refuse("the custody configuration cannot be read") from None
    if not isinstance(document, dict) or set(document) != _CONFIG_FIELDS:
        raise _refuse("the custody configuration does not match the closed contract")
    for field in ("mount", "authorization_key", "dispatch_key"):
        value = document[field]
        if not isinstance(value, str) or not _NAME.fullmatch(value):
            raise _refuse(f"the custody configuration {field} is not a plain name")
    for field in ("authorization_identity", "dispatch_identity", "socket"):
        value = document[field]
        if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
            raise _refuse(f"the custody configuration {field} is not an absolute path")
    if document["key_version"] != 1 or type(document["key_version"]) is not int:
        raise _refuse("the custody configuration must pin key_version 1")
    if document["authorization_key"] == document["dispatch_key"]:
        raise _refuse("the authorization and dispatch keys must be distinct")
    for name in (
        document["mount"],
        document["authorization_key"],
        document["dispatch_key"],
    ):
        if "licen" in name or name.startswith("secret"):
            raise _refuse("the custody configuration names a forbidden key or mount")
    return TransitCustodyConfig(**{k: document[k] for k in _CONFIG_FIELDS})


# ── token: stdin only ───────────────────────────────────────────────────────


def read_token(stream: BinaryIO | None = None) -> bytes:
    """One token from stdin. Refused on a TTY, oversized, or oddly shaped."""
    source = stream if stream is not None else sys.stdin.buffer
    try:
        if source.isatty():
            raise _refuse("the transit token must be piped on stdin, not typed")
        raw = source.read(MAX_TOKEN_BYTES + 2)
    except FoundationBindingsUnavailable:
        raise
    except Exception:
        raise _refuse("the transit token cannot be read from stdin") from None
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if (
        not _TOKEN.fullmatch(raw.decode("ascii", "replace"))
        or len(raw) > MAX_TOKEN_BYTES
    ):
        raise _refuse("the transit token on stdin is missing or malformed")
    return raw


# ── signature parsing ───────────────────────────────────────────────────────


def parse_signature(response: bytes, *, key_version: int = 1) -> bytes:
    """Raw 64 signature bytes from a transit sign response, or refuse."""
    if len(response) > MAX_RESPONSE_BYTES:
        raise _refuse("the transit response exceeds the size bound")
    try:
        document = strict_json(response)
    except Exception:
        raise _refuse("the transit response is not strict JSON") from None
    data = document.get("data") if isinstance(document, dict) else None
    if not isinstance(data, dict):
        raise _refuse("the transit response carries no data")
    if "batch_results" in data:
        raise _refuse("the transit response carries a batch; batch signing is refused")
    signature = data.get("signature")
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        raise _refuse("the transit signature is not a v1 signature")
    body = signature[len(SIGNATURE_PREFIX) :]
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raise _refuse("the transit signature is not standard base64") from None
    if base64.b64encode(raw).decode("ascii") != body:
        raise _refuse("the transit signature is not canonical base64")
    if len(raw) != 64:
        raise _refuse("the transit signature is not 64 bytes")
    if "key_version" in data and data["key_version"] != key_version:
        raise _refuse("the transit signature is from an unexpected key version")
    return raw


# ── client: unix socket only ────────────────────────────────────────────────


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = path

    def connect(self) -> None:  # pragma: no cover - exercised against a real socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class TransitClient:
    """Sign-only client. The token is held in a closure-less private attribute and
    is never in repr, a log line or an exception."""

    def __init__(
        self, config: TransitCustodyConfig, token: bytes, *, timeout: float = 10.0
    ) -> None:
        self._config = config
        self.__token = token
        self._timeout = timeout
        self._signs = 0

    def __repr__(self) -> str:
        return "TransitClient(<redacted>)"

    def sign(self, key_name: str, message: bytes) -> bytes:
        if self._signs >= MAX_SIGNS:
            raise _refuse("the single-issuance token has no signs left")
        self._signs += 1
        if key_name not in (self._config.authorization_key, self._config.dispatch_key):
            raise _refuse("the key is not one of the two configured keys")
        body = json.dumps(
            {
                "input": base64.b64encode(message).decode("ascii"),
                "key_version": self._config.key_version,
            },
            separators=(",", ":"),
        ).encode()
        path = f"/v1/{self._config.mount}/sign/{key_name}"
        try:
            connection = _UnixConnection(self._config.socket, self._timeout)
            try:
                connection.request(
                    "POST",
                    path,
                    body=body,
                    headers={
                        "X-Vault-Token": self.__token.decode("ascii"),
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
            finally:
                connection.close()
        except Exception:
            raise _refuse(
                "the transit service is unreachable or refused the call"
            ) from None
        if status != 200:
            raise _refuse(f"the transit service answered {status}")
        return parse_signature(payload, key_version=self._config.key_version)


def build_custody(
    config: TransitCustodyConfig, token: bytes, *, owner_uid: int = 0
) -> Custody:
    """The producer's `Custody` over transit. Installs nothing; contacts nothing."""
    authorization = PinnedVerificationIdentity.read(
        config.authorization_identity,
        purpose=_AUTHORIZATION_PURPOSE,
        what="authorization verification identity (custody config)",
        owner_uid=owner_uid,
    )
    dispatch = PinnedVerificationIdentity.read(
        config.dispatch_identity,
        purpose=_DISPATCH_PURPOSE,
        what="dispatch verification identity (custody config)",
        owner_uid=owner_uid,
    )
    if (
        authorization.public_key == dispatch.public_key
        or authorization.key_id == dispatch.key_id
        or authorization.public_key_fingerprint == dispatch.public_key_fingerprint
    ):
        raise _refuse("the two pinned identities must be distinct keys")
    client = TransitClient(config, token)

    def signer(key: str) -> Callable[[bytes], bytes]:
        return lambda message: client.sign(key, message)

    return Custody(
        authorization_identity=authorization,
        dispatch_identity=dispatch,
        authorization_sign=signer(config.authorization_key),
        dispatch_sign=signer(config.dispatch_key),
    )


# ── policy text ─────────────────────────────────────────────────────────────


def render_policy(config: TransitCustodyConfig) -> str:
    """The exact least-privilege policy. `allowed_parameters` is load-bearing: it
    refuses `batch_input` (so a use limit means one signature), `context`,
    `prehashed` and every algorithm parameter."""
    lines = []
    for key in (config.authorization_key, config.dispatch_key):
        lines.append(
            f'path "{config.mount}/sign/{key}" {{\n'
            '  capabilities       = ["update"]\n'
            '  allowed_parameters = { "input" = [], "key_version" = [] }\n'
            "}\n"
        )
    return "".join(lines)


# ── token role (ceremony config, rendered by the image) ─────────────────────

#: One issuance makes two signs and lives minutes, so the ROLE itself carries the
#: limits: a token cannot be minted looser than the role.
TOKEN_NUM_USES: Final = 2
TOKEN_TTL_SECONDS: Final = 600


def render_token_role(policy: str, bound_cidr: str) -> dict[str, Any]:
    """The exact `auth/token/roles/<name>` body. Every value is required.

    No default: the bound CIDR (the relay's source as OpenBao sees it) is a
    ceremony input, never authored here. Refused: a broad network, an unspecified
    one, or a malformed value. The role is a non-orphan child of the minting
    token, so revoking the ceremony root revokes every token, even if everything
    else fails. The ten minute life is `token_explicit_max_ttl`, the hard cap
    (a token role has no default-ttl field of its own). Not renewable, no default policy (which would add self-lookup,
    renew, cubbyhole and wrapping), service tokens (batch tokens cannot be
    use-limited or revoked individually).
    """
    if not _NAME.fullmatch(policy):
        raise _refuse("the policy name is not a plain name")
    try:
        network = ipaddress.ip_network(bound_cidr, strict=True)
    except ValueError:
        raise _refuse("the bound CIDR is not a network") from None
    minimum = 24 if network.version == 4 else 64
    if network.is_unspecified or network.prefixlen < minimum:
        raise _refuse("the bound CIDR is too broad to bind a token to its relay")
    return {
        "allowed_policies": [policy],
        "orphan": False,
        "renewable": False,
        "token_bound_cidrs": [str(network)],
        "token_explicit_max_ttl": f"{TOKEN_TTL_SECONDS}s",
        "token_no_default_policy": True,
        "token_num_uses": TOKEN_NUM_USES,
        "token_type": "service",
    }


def readback_token_role(response: bytes, expected: dict[str, Any]) -> list[str]:
    """Names of the fields in `GET auth/token/roles/<name>` that differ from the
    rendered config (empty means the role is exactly as rendered)."""
    try:
        data = strict_json(response)["data"]
    except Exception:
        raise _refuse("the token role description is not an OpenBao response") from None

    def seconds(value: Any) -> Any:
        if isinstance(value, str) and value.endswith("s") and value[:-1].isdigit():
            return int(value[:-1])
        return value

    def cidrs(value: Any) -> Any:
        try:
            return sorted(str(ipaddress.ip_network(item)) for item in value)
        except (ValueError, TypeError):
            return value

    different = []
    for field, wanted in sorted(expected.items()):
        got = data.get(field)
        if field == "token_explicit_max_ttl":
            same = seconds(got) == seconds(wanted)
        elif field == "token_bound_cidrs":
            same = cidrs(got) == cidrs(wanted)
        else:
            same = got == wanted
        if not same:
            different.append(field)
    return different


# ── ceremony helpers ────────────────────────────────────────────────────────


def identity_document(
    key_response: bytes, *, purpose: str, key_id: str
) -> dict[str, str]:
    """`PlatformCpPublicVerificationIdentity.v1` from `GET keys/<name>` JSON."""
    if purpose not in _PURPOSES or not key_id.strip():
        raise _refuse("the purpose or key id is not usable")
    try:
        data = strict_json(key_response)["data"]
        version = data["keys"]["1"]
    except Exception:
        raise _refuse("the key description is not a transit key response") from None
    if (
        data.get("type") != "ed25519"
        or data.get("exportable") is not False
        or data.get("allow_plaintext_backup", False) is not False
        or data.get("latest_version") != 1
        or set(data["keys"]) != {"1"}
    ):
        raise _refuse(
            "the key is not a non-exportable, never-rotated ed25519 key at version 1"
        )
    raw = None
    try:
        raw = base64.b64decode(version["public_key"], validate=True)
    except (binascii.Error, ValueError, KeyError, TypeError):
        pass
    if raw is None or len(raw) != 32:
        raise _refuse("the key description carries no 32 byte ed25519 public key")
    text = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    try:
        from dotmac_deployment_control import PublicKeyFingerprintV1

        fingerprint = PublicKeyFingerprintV1.from_public_key_b64(text).canonical
    except Exception:
        raise _refuse("Control fingerprint derivation is unavailable") from None
    return {
        "schema": IDENTITY_SCHEMA,
        "key_id": key_id,
        "algorithm": "ed25519",
        "purpose": purpose,
        "public_key_b64url": text,
        "public_key_fingerprint": fingerprint,
    }


def pop_message(purpose: str, nonce: bytes) -> bytes:
    """Domain-separated challenge: never parses as a Control canonical envelope."""
    if purpose not in _PURPOSES or len(nonce) != 32:
        raise _refuse("the proof-of-possession challenge is malformed")
    return POP_PREFIX + purpose.encode("ascii") + b"\x00" + nonce


def pop_verify(
    identity: PinnedVerificationIdentity, *, purpose: str, nonce: bytes, signature: str
) -> bool:
    """Proves the pinned key is the one transit signs with, as pure Ed25519."""
    raw = parse_signature(
        json.dumps({"data": {"signature": signature}}).encode(), key_version=1
    )
    signature_b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return identity.purpose == purpose and identity.verify_signature(
        pop_message(purpose, nonce), signature_b64
    )


def _print(document: Any) -> None:
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("print-schema")
    p_id = sub.add_parser("identity")
    p_id.add_argument("--purpose", required=True)
    p_id.add_argument("--key-id", required=True)
    p_ch = sub.add_parser("pop-challenge")
    p_ch.add_argument("--purpose", required=True)
    p_ch.add_argument("--nonce-hex")
    p_vf = sub.add_parser("pop-verify")
    p_vf.add_argument("--identity", required=True)
    p_vf.add_argument("--purpose", required=True)
    p_vf.add_argument("--nonce-hex", required=True)
    p_vf.add_argument("--owner-uid", type=int, default=0)
    p_po = sub.add_parser("policy")
    p_po.add_argument("--config", required=True)
    for name in ("role", "role-readback"):
        p_role = sub.add_parser(name)
        p_role.add_argument("--policy", required=True)
        p_role.add_argument("--bound-cidr", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "print-schema":
            _print(config_schema())
        elif args.action == "identity":
            _print(
                identity_document(
                    sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1),
                    purpose=args.purpose,
                    key_id=args.key_id,
                )
            )
        elif args.action == "pop-challenge":
            nonce = bytes.fromhex(args.nonce_hex) if args.nonce_hex else os.urandom(32)
            message = pop_message(args.purpose, nonce)
            _print(
                {
                    "purpose": args.purpose,
                    "nonce_hex": nonce.hex(),
                    "input_b64": base64.b64encode(message).decode("ascii"),
                    "input_sha256": hashlib.sha256(message).hexdigest(),
                }
            )
        elif args.action == "pop-verify":
            identity = PinnedVerificationIdentity.read(
                args.identity,
                purpose=args.purpose,
                what="identity",
                owner_uid=args.owner_uid,
            )
            signature = sys.stdin.read(512).strip()
            if not pop_verify(
                identity,
                purpose=args.purpose,
                nonce=bytes.fromhex(args.nonce_hex),
                signature=signature,
            ):
                raise _refuse("the proof of possession does not verify")
            print("proof of possession verified")
        elif args.action == "role":
            _print(render_token_role(args.policy, args.bound_cidr))
        elif args.action == "role-readback":
            rendered = render_token_role(args.policy, args.bound_cidr)
            different = readback_token_role(
                sys.stdin.buffer.read(MAX_RESPONSE_BYTES + 1), rendered
            )
            if different:
                raise _refuse("the token role differs in: " + ", ".join(different))
            print("token role read-back verified")
        else:
            sys.stdout.write(render_policy(load_config(args.config)))
    except FoundationBindingsUnavailable as refusal:
        print(f"transit custody refused: {refusal.code}: {refusal}", file=sys.stderr)
        return 2
    except ValueError:
        print("transit custody refused: malformed input", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
