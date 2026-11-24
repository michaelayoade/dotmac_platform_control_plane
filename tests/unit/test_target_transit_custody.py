"""Transit custody adapter against a faithful stub of OpenBao's sign endpoint.

The stub listens on a unix socket and verifies the request shape the adapter
must send. The real OpenBao 2.5.3 behaviour (policy refusals, use limits, key
version pinning) is proven in the harness job.
"""

from __future__ import annotations

import base64
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment import transit_custody as transit
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    IDENTITY_SCHEMA,
    PinnedVerificationIdentity,
)

_UID = os.getuid()
_TOKEN = b"s.TESTONLYtoken1234567890"


class _Stub:
    """A one-key-per-name transit sign endpoint on a unix socket."""

    def __init__(self, directory: str) -> None:
        self.keys = {
            "auth-key": Ed25519PrivateKey.generate(),
            "disp-key": Ed25519PrivateKey.generate(),
        }
        self.requests: list[dict[str, Any]] = []
        self.mutate: Any = None
        self.status = 200
        self.path = os.path.join(directory, "s")
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                body = json.loads(self.rfile.read(length))
                stub.requests.append(
                    {
                        "path": self.path,
                        "token": self.headers.get("X-Vault-Token"),
                        "body": body,
                    }
                )
                name = self.path.rsplit("/", 1)[-1]
                message = base64.b64decode(body["input"])
                signature = stub.keys[name].sign(message)
                payload: dict[str, Any] = {
                    "data": {
                        "signature": "vault:v1:" + base64.b64encode(signature).decode(),
                        "key_version": 1,
                    }
                }
                if stub.mutate:
                    payload = stub.mutate(payload)
                raw = (
                    stub.mutate_raw(payload)
                    if hasattr(stub, "mutate_raw")
                    else json.dumps(payload).encode()
                )
                self.send_response(stub.status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_a: Any) -> None:
                return

        class Server(socketserver.ThreadingUnixStreamServer):
            def get_request(self) -> Any:
                request, _ = super().get_request()
                return request, ("unix", 0)

        self.server = Server(self.path, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub() -> Iterator[_Stub]:
    with tempfile.TemporaryDirectory(prefix="tc", dir="/tmp") as directory:
        instance = _Stub(directory)
        try:
            yield instance
        finally:
            instance.close()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.fixture
def control(monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    class _Fp:
        def __init__(self, canonical: str) -> None:
            self.canonical = canonical

        @classmethod
        def from_public_key_b64(cls, value: str) -> _Fp:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            return cls("sha256:" + hashlib.sha256(raw).hexdigest())

    module = ModuleType("dotmac_deployment_control")
    module.PublicKeyFingerprintV1 = _Fp  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dotmac_deployment_control", module)


def _identity_file(
    directory: Path, key: Ed25519PrivateKey, purpose: str, key_id: str
) -> Path:
    import hashlib

    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    document = {
        "schema": IDENTITY_SCHEMA,
        "key_id": key_id,
        "algorithm": "ed25519",
        "purpose": purpose,
        "public_key_b64url": _b64url(raw),
        "public_key_fingerprint": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    path = directory / f"{key_id}.json"
    path.write_text(json.dumps(document))
    path.chmod(0o644)
    return path


def _config(
    tmp_path: Path, stub: _Stub, control: None, **overrides: Any
) -> transit.TransitCustodyConfig:
    auth = _identity_file(
        tmp_path, stub.keys["auth-key"], "deployment_authorization", "a"
    )
    disp = _identity_file(tmp_path, stub.keys["disp-key"], "deployment_dispatch", "d")
    document: dict[str, Any] = {
        "mount": "transit-test",
        "authorization_key": "auth-key",
        "dispatch_key": "disp-key",
        "key_version": 1,
        "authorization_identity": str(auth),
        "dispatch_identity": str(disp),
        "socket": stub.path,
    }
    document.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document))
    return transit.load_config(str(path))


def _refused(call: Any) -> FoundationBindingsUnavailable:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        call()
    assert "TESTONLY" not in str(caught.value)
    assert caught.value.code is TargetRefusal.CUSTODY_NOT_CONFIGURED
    return caught.value


# ── configuration ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides",
    [
        {"mount": "Bad Mount"},
        {"authorization_key": "disp-key"},
        {"key_version": 2},
        {"key_version": True},
        {"socket": "relative.sock"},
        {"authorization_key": "licensing-key"},
        {"mount": "secret-x"},
        {"extra": "x"},
    ],
)
def test_the_configuration_is_closed_and_refuses_defects(
    tmp_path: Path, stub: _Stub, control: None, overrides: dict[str, Any]
) -> None:
    with pytest.raises(FoundationBindingsUnavailable):
        _config(tmp_path, stub, control, **overrides)


def test_a_missing_or_duplicate_key_configuration_refuses(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    with pytest.raises(FoundationBindingsUnavailable):
        transit.load_config(str(path))
    path.write_text('{"mount":"a","mount":"b"}')
    with pytest.raises(FoundationBindingsUnavailable):
        transit.load_config(str(path))


# ── token ───────────────────────────────────────────────────────────────────


class _Stdin(io.BytesIO):
    def __init__(self, data: bytes, tty: bool = False) -> None:
        super().__init__(data)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_token_is_read_from_stdin_only() -> None:
    assert transit.read_token(_Stdin(_TOKEN + b"\n")) == _TOKEN
    assert transit.read_token(_Stdin(_TOKEN)) == _TOKEN


@pytest.mark.parametrize(
    "stream",
    [
        _Stdin(_TOKEN, tty=True),
        _Stdin(b""),
        _Stdin(b"short"),
        _Stdin(b"x" * 513),
        _Stdin(b"has space token1234"),
        _Stdin(_TOKEN + b"\nsecond"),
        _Stdin(b"s.TESTONLY\x00token123"),
    ],
)
def test_a_bad_token_refuses_without_echo(stream: _Stdin) -> None:
    _refused(lambda: transit.read_token(stream))


def test_the_token_is_never_in_a_repr(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    client = transit.TransitClient(_config(tmp_path, stub, control), _TOKEN)
    assert "TESTONLY" not in repr(client)


# ── signing ─────────────────────────────────────────────────────────────────


def test_sign_posts_exactly_input_and_key_version_and_verifies(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    custody = transit.build_custody(
        _config(tmp_path, stub, control), _TOKEN, owner_uid=_UID
    )
    message = b"canonical bytes"
    raw = custody.authorization_sign(message)
    stub.keys["auth-key"].public_key().verify(raw, message)
    request = stub.requests[0]
    assert request["path"] == "/v1/transit-test/sign/auth-key"
    assert request["token"] == _TOKEN.decode()
    assert (
        set(request["body"]) == {"input", "key_version"}
        and request["body"]["key_version"] == 1
    )
    assert base64.b64decode(request["body"]["input"]) == message
    custody.dispatch_sign(b"x")
    assert stub.requests[1]["path"].endswith("/sign/disp-key")


def test_the_token_is_single_issuance_two_signs_only(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    custody = transit.build_custody(
        _config(tmp_path, stub, control), _TOKEN, owner_uid=_UID
    )
    custody.authorization_sign(b"a")
    custody.dispatch_sign(b"b")
    _refused(lambda: custody.authorization_sign(b"c"))
    assert len(stub.requests) == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: {"data": {**p["data"], "batch_results": [{"signature": "x"}]}},
        lambda p: {
            "data": {
                **p["data"],
                "signature": p["data"]["signature"].replace("vault:v1:", "vault:v2:"),
            }
        },
        lambda p: {"data": {**p["data"], "signature": "vault:v1:" + "A" * 10}},
        lambda p: {"data": {**p["data"], "signature": p["data"]["signature"] + "="}},
        lambda p: {
            "data": {
                **p["data"],
                "signature": "vault:v1:" + base64.b64encode(b"x" * 63).decode(),
            }
        },
        lambda p: {
            "data": {
                **p["data"],
                "signature": "vault:v1:"
                + base64.urlsafe_b64encode(b"\xfb" * 64).decode(),
            }
        },
        lambda p: {"data": {**p["data"], "key_version": 2}},
        lambda p: {"data": {}},
        lambda p: {},
        lambda p: [],
    ],
)
def test_a_malformed_signature_response_refuses(
    tmp_path: Path, stub: _Stub, control: None, mutate: Any
) -> None:
    stub.mutate = mutate
    custody = transit.build_custody(
        _config(tmp_path, stub, control), _TOKEN, owner_uid=_UID
    )
    _refused(lambda: custody.authorization_sign(b"m"))


def test_a_non_200_an_oversize_or_duplicate_key_response_refuses(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    custody = transit.build_custody(
        _config(tmp_path, stub, control), _TOKEN, owner_uid=_UID
    )
    stub.status = 403
    _refused(lambda: custody.authorization_sign(b"m"))
    with pytest.raises(FoundationBindingsUnavailable):
        transit.parse_signature(b"x" * (transit.MAX_RESPONSE_BYTES + 1))
    with pytest.raises(FoundationBindingsUnavailable):
        transit.parse_signature(b'{"data":{"signature":"a","signature":"b"}}')


def test_an_unreachable_socket_refuses_without_fallback(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    config = _config(tmp_path, stub, control)
    stub.close()
    custody = transit.build_custody(config, _TOKEN, owner_uid=_UID)
    _refused(lambda: custody.authorization_sign(b"m"))


def test_swapped_or_equal_pinned_identities_refuse(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    same = stub.keys["auth-key"]
    stub.keys["disp-key"] = same
    with pytest.raises(FoundationBindingsUnavailable):
        transit.build_custody(_config(tmp_path, stub, control), _TOKEN, owner_uid=_UID)


def test_the_policy_text_names_exact_paths_and_refuses_batch(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    policy = transit.render_policy(_config(tmp_path, stub, control))
    assert policy.count("path ") == 2
    assert 'path "transit-test/sign/auth-key"' in policy
    assert '"input" = [], "key_version" = []' in policy
    assert "batch_input" not in policy and "*" not in policy


# ── ceremony helpers ────────────────────────────────────────────────────────


def _key_response(key: Ed25519PrivateKey, **overrides: Any) -> bytes:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    data: dict[str, Any] = {
        "type": "ed25519",
        "exportable": False,
        "allow_plaintext_backup": False,
        "latest_version": 1,
        "keys": {"1": {"public_key": base64.b64encode(raw).decode()}},
    }
    data.update(overrides)
    return json.dumps({"data": data}).encode()


def test_identity_is_rendered_from_the_key_description(control: None) -> None:
    key = Ed25519PrivateKey.generate()
    document = transit.identity_document(
        _key_response(key),
        purpose="deployment_authorization",
        key_id="platform-cp-a2-authorization-v1",
    )
    assert set(document) == {
        "schema",
        "key_id",
        "algorithm",
        "purpose",
        "public_key_b64url",
        "public_key_fingerprint",
    }
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert document["public_key_b64url"] == _b64url(raw)


@pytest.mark.parametrize(
    "overrides",
    [
        {"exportable": True},
        {"allow_plaintext_backup": True},
        {"type": "ed448"},
        {"latest_version": 2},
        {"keys": {"1": {"public_key": "AAAA"}}},
        {"keys": {"1": {"public_key": "x"}, "2": {"public_key": "y"}}},
    ],
)
def test_identity_refuses_an_exportable_rotated_or_wrong_key(
    control: None, overrides: dict[str, Any]
) -> None:
    with pytest.raises(FoundationBindingsUnavailable):
        transit.identity_document(
            _key_response(Ed25519PrivateKey.generate(), **overrides),
            purpose="deployment_dispatch",
            key_id="k",
        )


def test_proof_of_possession_binds_purpose_nonce_and_key(
    tmp_path: Path, control: None
) -> None:
    key = Ed25519PrivateKey.generate()
    path = _identity_file(tmp_path, key, "deployment_authorization", "k")
    identity = PinnedVerificationIdentity.read(
        str(path), purpose="deployment_authorization", what="i", owner_uid=_UID
    )
    nonce = os.urandom(32)
    message = transit.pop_message("deployment_authorization", nonce)
    assert message.startswith(transit.POP_PREFIX)
    signature = "vault:v1:" + base64.b64encode(key.sign(message)).decode()
    assert transit.pop_verify(
        identity, purpose="deployment_authorization", nonce=nonce, signature=signature
    )
    assert not transit.pop_verify(
        identity,
        purpose="deployment_authorization",
        nonce=os.urandom(32),
        signature=signature,
    )
    other = (
        "vault:v1:"
        + base64.b64encode(Ed25519PrivateKey.generate().sign(message)).decode()
    )
    assert not transit.pop_verify(
        identity, purpose="deployment_authorization", nonce=nonce, signature=other
    )
    with pytest.raises(FoundationBindingsUnavailable):
        transit.pop_message("deployment_dispatch", b"short")
    # The challenge can never be a Control canonical envelope (JSON object).
    assert not message.startswith(b"{")


def test_the_module_is_imported_only_by_the_producer_command() -> None:
    import ast

    root = Path(transit.__file__).resolve().parents[1]
    importers = []
    for path in root.rglob("*.py"):
        if path == Path(transit.__file__).resolve():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any(name.endswith("transit_custody") for name in names):
                importers.append(path.name)
    assert set(importers) <= {"materials_producer.py"}


# ── token role (review F13) ─────────────────────────────────────────────────

_ROLE_PINNED = (
    '{"allowed_policies":["cp-a2-sign"],"orphan":false,"renewable":false,'
    '"token_bound_cidrs":["192.0.2.7/32"],"token_explicit_max_ttl":"600s",'
    '"token_no_default_policy":true,"token_num_uses":2,'
    '"token_type":"service"}'
)


def test_the_token_role_config_is_pinned_exactly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rendered = transit.render_token_role("cp-a2-sign", "192.0.2.7/32")
    assert json.dumps(rendered, sort_keys=True, separators=(",", ":")) == _ROLE_PINNED
    assert (
        transit.main(["role", "--policy", "cp-a2-sign", "--bound-cidr", "192.0.2.7/32"])
        == 0
    )
    assert capsys.readouterr().out.strip() == _ROLE_PINNED
    # Two uses, ten minutes, not renewable, no default policy, a child (not an
    # orphan) of the minting token.
    assert rendered["token_num_uses"] == 2
    assert rendered["token_explicit_max_ttl"] == "600s"
    assert rendered["renewable"] is False and rendered["orphan"] is False
    assert rendered["token_no_default_policy"] is True


@pytest.mark.parametrize(
    "cidr",
    [
        "",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/8",
        "192.0.2.0/24",
        "192.0.2.4/30",
        "192.0.2.6/31",
        "2001:db8::/32",
        "2001:db8::/64",
        "2001:db8::/127",
        "192.0.2.7/24",
        "nonsense",
        "300.0.0.1/32",
    ],
)
def test_the_token_role_binds_to_a_single_address_only(cidr: str) -> None:
    with pytest.raises(FoundationBindingsUnavailable):
        transit.render_token_role("cp-a2-sign", cidr)


@pytest.mark.parametrize(
    ("given", "bound"),
    [
        ("192.0.2.7/32", "192.0.2.7/32"),
        ("192.0.2.7", "192.0.2.7/32"),
        ("2001:db8::1/128", "2001:db8::1/128"),
    ],
)
def test_a_single_address_is_accepted(given: str, bound: str) -> None:
    assert transit.render_token_role("cp-a2-sign", given)["token_bound_cidrs"] == [
        bound
    ]


def test_the_token_role_has_no_default_cidr_or_policy(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for argv in (["role", "--policy", "p"], ["role", "--bound-cidr", "192.0.2.7/32"]):
        with pytest.raises(SystemExit):
            transit.main(argv)
    with pytest.raises(FoundationBindingsUnavailable):
        transit.render_token_role("Bad Policy", "192.0.2.7/32")
    capsys.readouterr()


def _readback(**overrides: Any) -> bytes:
    data: dict[str, Any] = {
        "allowed_policies": ["cp-a2-sign"],
        "orphan": False,
        "renewable": False,
        "token_bound_cidrs": ["192.0.2.7"],
        "allowed_policies_glob": [],
        "disallowed_policies": [],
        "disallowed_policies_glob": [],
        "allowed_entity_aliases": [],
        "path_suffix": "",
        "token_period": 0,
        "period": 0,
        "explicit_max_ttl": 0,
        "bound_cidrs": [],
        "token_explicit_max_ttl": 600,
        "token_no_default_policy": True,
        "token_num_uses": 2,
        "token_type": "service",
        "name": "x",
    }
    data.update(overrides)
    return json.dumps({"data": data}).encode()


def test_the_readback_accepts_exactly_the_rendered_role() -> None:
    rendered = transit.render_token_role("cp-a2-sign", "192.0.2.7/32")
    assert transit.readback_token_role(_readback(), rendered) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("renewable", True),
        ("orphan", True),
        ("token_num_uses", 0),
        ("token_num_uses", 3),
        ("token_explicit_max_ttl", 3600),
        ("token_explicit_max_ttl", 0),
        ("token_no_default_policy", False),
        ("token_type", "batch"),
        ("allowed_policies", ["cp-a2-sign", "default"]),
        ("token_bound_cidrs", []),
        ("token_bound_cidrs", ["192.0.2.0/24"]),
        # Fields that can only widen a token: each must be empty or zero.
        ("allowed_policies_glob", ["*"]),
        ("disallowed_policies", ["x"]),
        ("disallowed_policies_glob", ["x*"]),
        ("allowed_entity_aliases", ["alias"]),
        ("path_suffix", "anything"),
        ("token_period", 3600),
        ("period", 3600),
        ("explicit_max_ttl", 3600),
        ("bound_cidrs", ["0.0.0.0/0"]),
    ],
)
def test_the_readback_names_every_drift(field: str, value: Any) -> None:
    rendered = transit.render_token_role("cp-a2-sign", "192.0.2.7/32")
    assert transit.readback_token_role(_readback(**{field: value}), rendered) == [field]


def test_the_readback_command_exits_by_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["role-readback", "--policy", "cp-a2-sign", "--bound-cidr", "192.0.2.7/32"]
    monkeypatch.setattr(sys, "stdin", SimpleNamespaceBuffer(_readback()))
    assert transit.main(argv) == 0
    monkeypatch.setattr(sys, "stdin", SimpleNamespaceBuffer(_readback(renewable=True)))
    assert transit.main(argv) == 2
    assert "renewable" in capsys.readouterr().err


class SimpleNamespaceBuffer:
    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


def test_a_field_outside_the_2_5_3_read_list_is_refused_by_name() -> None:
    rendered = transit.render_token_role("cp-a2-sign", "192.0.2.7/32")
    drift = transit.readback_token_role(_readback(brand_new_widening="x"), rendered)
    assert drift == ["unknown:brand_new_widening"]


def test_absent_widening_fields_are_fine_and_values_are_never_echoed() -> None:
    rendered = transit.render_token_role("cp-a2-sign", "192.0.2.7/32")
    data = json.loads(_readback())["data"]
    for field in transit._ROLE_MUST_BE_EMPTY:
        data.pop(field, None)
    assert (
        transit.readback_token_role(json.dumps({"data": data}).encode(), rendered) == []
    )
    leaked = transit.readback_token_role(
        _readback(path_suffix="SECRET-MARKER"), rendered
    )
    assert leaked == ["path_suffix"] and "SECRET-MARKER" not in str(leaked)


def test_recovery_policy_and_role_are_closed_and_distinct(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    config = _config(tmp_path, stub, control)
    policy = transit.render_recovery_policy(config)
    assert config.authorization_key not in policy
    assert f"{config.mount}/sign/{config.dispatch_key}" in policy
    assert '"key_version" = [1]' in policy
    assert 'required_parameters = ["input", "key_version"]' in policy
    role = transit.render_recovery_token_role("192.0.2.8/32")
    assert role["allowed_policies"] == ["cp-a2-recovery-dispatch"]
    assert role["token_num_uses"] == 1
    assert role["token_explicit_max_ttl"] == "600s"
    assert role["orphan"] is False and role["renewable"] is False
    assert role["token_no_default_policy"] is True
    assert (
        transit.readback_recovery_token_role(
            json.dumps({"data": role}).encode(), "192.0.2.8/32"
        )
        == []
    )
    assert transit.readback_recovery_token_role(
        json.dumps({"data": {**role, "token_num_uses": 2}}).encode(), "192.0.2.8/32"
    ) == ["token_num_uses"]
    assert transit.readback_recovery_token_role(
        json.dumps({"data": {**role, "name": "normal"}}).encode(), "192.0.2.8/32"
    ) == ["name"]


def test_recovery_custody_refuses_authorization_and_duplicate_dispatch(
    tmp_path: Path, stub: _Stub, control: None
) -> None:
    config = _config(tmp_path, stub, control)
    custody = transit.build_recovery_custody(
        config, b"test-token", owner_uid=os.getuid()
    )
    with pytest.raises(FoundationBindingsUnavailable):
        custody.authorization_sign(b"authorization")
    assert stub.requests == []
    custody.dispatch_sign(b"dispatch")
    with pytest.raises(FoundationBindingsUnavailable):
        custody.dispatch_sign(b"duplicate")
    assert len(stub.requests) == 1
    assert stub.requests[0]["path"].endswith("/" + config.dispatch_key)


@pytest.mark.parametrize(
    "field,value",
    [
        ("allowed_policies", ["normal"]),
        ("token_num_uses", 0),
        ("token_num_uses", 2),
        ("token_explicit_max_ttl", 601),
        ("renewable", True),
        ("orphan", True),
        ("token_no_default_policy", False),
        ("token_type", "batch"),
        ("token_bound_cidrs", ["192.0.2.9/32"]),
        ("allowed_policies_glob", ["*"]),
        ("token_period", 600),
    ],
)
def test_recovery_role_readback_refuses_every_widened_limit(field, value):
    role = transit.render_recovery_token_role("192.0.2.8/32")
    role[field] = value
    assert field in transit.readback_recovery_token_role(
        json.dumps({"data": role}).encode(), "192.0.2.8/32"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_num_uses", True),
        ("token_num_uses", 1.0),
        ("token_no_default_policy", 1),
        ("token_no_default_policy", 1.0),
        ("orphan", 0),
        ("orphan", 0.0),
        ("renewable", 0),
        ("renewable", 0.0),
        ("token_explicit_max_ttl", True),
        ("token_explicit_max_ttl", 600.0),
        ("token_explicit_max_ttl", "0600s"),
        ("allowed_policies", "cp-a2-recovery-dispatch"),
        ("allowed_policies", [1]),
        ("token_bound_cidrs", [3221225992]),
        ("token_bound_cidrs", "192.0.2.8/32"),
        ("period", False),
        ("period", 0.0),
        ("token_period", False),
        ("token_period", 0.0),
        ("explicit_max_ttl", False),
        ("explicit_max_ttl", 0.0),
        ("allowed_entity_aliases", ""),
        ("allowed_policies_glob", ""),
        ("bound_cidrs", ""),
        ("disallowed_policies", ""),
        ("disallowed_policies_glob", ""),
        ("path_suffix", 0),
    ],
)
def test_recovery_role_readback_refuses_type_coercion(field, value):
    role = transit.render_recovery_token_role("192.0.2.8/32")
    role[field] = value
    assert field in transit.readback_recovery_token_role(
        json.dumps({"data": role}).encode(), "192.0.2.8/32"
    )


@pytest.mark.parametrize("ttl", [600, "600s"])
def test_recovery_role_readback_accepts_only_documented_seconds_shapes(ttl):
    role = transit.render_recovery_token_role("192.0.2.8/32")
    role["token_explicit_max_ttl"] = ttl
    role.update(period=0, token_period=0, explicit_max_ttl=0)
    assert (
        transit.readback_recovery_token_role(
            json.dumps({"data": role}).encode(), "192.0.2.8/32"
        )
        == []
    )
