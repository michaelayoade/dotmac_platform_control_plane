"""Synthetic keys, fake transport and scratch files; never contacts GitHub."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vendor_cp import github_app_credentials as g

NOW = 1792800000
SYNTHETIC_TOKEN = "ghs_synthetic_" + "x" * 70 + ".a-b.c_d"


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "key.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pem.chmod(0o600)
    auth = tmp_path / "auth"
    auth.mkdir(mode=0o750)
    # pytest's scratch ancestry is neither root-owned nor production-protected.
    monkeypatch.setattr(g, "_ancestry", lambda *_: None)
    return key, pem, auth


def response():
    return {
        "token": SYNTHETIC_TOKEN,
        "expires_at": datetime.fromtimestamp(NOW + 3600, UTC).isoformat(),
        "permissions": dict(g.PERMISSIONS),
        "repository_selection": "selected",
        "repositories": [{"id": g.REPOSITORY_ID, "full_name": g.REPOSITORY}],
    }


def invoke(setup, transport):
    _, pem, auth = setup
    return g.renew_credentials(
        private_key_file=pem,
        auth_directory=auth,
        owner_uid=os.getuid(),
        reader_gid=os.getgid(),
        clock=lambda: NOW,
        request=transport,
    )


def test_issues_narrow_jwt_and_atomic_auth_file(setup):
    key, _, auth = setup
    calls = []

    def transport(method, path, bearer, body):
        calls.append((method, path))
        header, claims, signature = bearer.split(".")

        def decode(value):
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

        assert json.loads(decode(header)) == {"alg": "RS256", "typ": "JWT"}
        assert json.loads(decode(claims)) == {
            "iat": NOW - 60,
            "exp": NOW + 540,
            "iss": g.CLIENT_ID,
        }
        key.public_key().verify(
            decode(signature),
            (header + "." + claims).encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        assert json.loads(body) == {
            "repository_ids": [g.REPOSITORY_ID],
            "permissions": g.PERMISSIONS,
        }
        return 201, json.dumps(response()).encode()

    receipt = invoke(setup, transport)
    assert calls == [("POST", f"/app/installations/{g.INSTALLATION_ID}/access_tokens")]
    text = (auth / "hosts.yml").read_text()
    assert json.loads(text.split("\n", 1)[1]) == {
        "github.com": {"oauth_token": SYNTHETIC_TOKEN, "git_protocol": "https"}
    }
    assert SYNTHETIC_TOKEN not in repr(receipt)
    assert json.loads(text.split("\n", 1)[0].split(" ", 2)[2]) == receipt
    assert (auth / "hosts.yml").stat().st_mode & 0o777 == 0o640
    assert (auth / "hosts.yml").stat().st_gid == os.getgid()
    assert list(auth.iterdir()) == [auth / "hosts.yml"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("permissions", {"contents": "write", "metadata": "read", "issues": "read"}),
        ("permissions", {"contents": "read", "metadata": "read"}),
        ("repository_selection", "all"),
        ("repositories", []),
        ("repositories", [{"id": 1, "full_name": g.REPOSITORY}]),
        ("repositories", [{"id": g.REPOSITORY_ID, "full_name": "other/repository"}]),
        ("expires_at", datetime.fromtimestamp(NOW + 2699, UTC).isoformat()),
        ("expires_at", datetime.fromtimestamp(NOW + 3901, UTC).isoformat()),
        ("expires_at", "2026-10-24T00:00:00"),
    ],
)
def test_validation_revokes_only_new_token_and_preserves_old(setup, field, value):
    _, _, auth = setup
    old = auth / "hosts.yml"
    old.write_text("old lease")
    old.chmod(0o640)
    data = response()
    data[field] = value
    calls = []

    def transport(method, path, bearer, body):
        calls.append(method)
        if method == "DELETE":
            assert bearer == SYNTHETIC_TOKEN
            assert path == "/installation/token" and body is None
            return 204, b""
        return 201, json.dumps(data).encode()

    with pytest.raises(g.GitHubCredentialError, match="^lease renewal failed$"):
        invoke(setup, transport)
    assert calls == ["POST", "DELETE"]
    assert old.read_text() == "old lease"


def test_persistence_failure_revokes_and_preserves(setup, monkeypatch):
    _, _, auth = setup
    old = auth / "hosts.yml"
    old.write_text("old lease")
    old.chmod(0o640)

    def refuse(*args, **kwargs):
        raise OSError("synthetic failure with sensitive detail")

    monkeypatch.setattr(g.os, "replace", refuse)
    calls = []

    def transport(method, *_):
        calls.append(method)
        return (
            (201, json.dumps(response()).encode()) if method == "POST" else (204, b"")
        )

    with pytest.raises(g.GitHubCredentialError, match="^lease renewal failed$"):
        invoke(setup, transport)
    assert calls == ["POST", "DELETE"]
    assert old.read_text() == "old lease"
    assert list(auth.iterdir()) == [old]


@pytest.mark.parametrize("kind", ["mode", "symlink", "hardlink"])
def test_protected_key_refusals_precede_issuance(setup, kind):
    _, pem, _ = setup
    if kind == "mode":
        pem.chmod(0o640)
    elif kind == "symlink":
        target = pem.with_name("target")
        pem.rename(target)
        pem.symlink_to(target)
    else:
        os.link(pem, pem.with_name("linked"))

    def transport(*_):
        pytest.fail("must not issue")

    with pytest.raises(g.GitHubCredentialError):
        invoke(setup, transport)


def test_revocation_failure_explicitly_public_and_sanitized(setup):
    data = response()
    data["permissions"] = {}

    def transport(method, *_):
        if method == "DELETE":
            raise OSError(SYNTHETIC_TOKEN)
        return 201, json.dumps(data).encode()

    with pytest.raises(
        g.GitHubCredentialError, match="revocation unconfirmed"
    ) as error:
        invoke(setup, transport)
    assert SYNTHETIC_TOKEN not in str(error.value)


def test_direct_transport_fixed_origin_no_redirect(monkeypatch):
    calls = []

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.github.com" and timeout == 15

        def request(self, *args, **kwargs):
            calls.append(args)

        def getresponse(self):
            return self

        status = 302

        def read(self, bound):
            assert bound == g.MAX_RESPONSE + 1
            return b"redirect body"

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(g.http.client, "HTTPSConnection", Connection)
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted.invalid")
    assert (
        g.github_request("DELETE", "/installation/token", "synthetic", None)[0] == 302
    )
    assert len(calls) == 2
    with pytest.raises(g.GitHubCredentialError):
        g.github_request("POST", "https://untrusted.invalid", "synthetic", None)


def test_ancestry_rejects_writable_and_symlink_paths(tmp_path):
    writable = tmp_path / "writable"
    writable.mkdir(mode=0o777)
    writable.chmod(0o777)
    with pytest.raises(g.GitHubCredentialError, match="ancestry"):
        g._ancestry(writable, os.getuid())
    link = tmp_path / "link"
    link.symlink_to(writable, target_is_directory=True)
    with pytest.raises(g.GitHubCredentialError, match="ancestry"):
        g._ancestry(link, os.getuid())


def test_host_wrapper_uses_existing_lock_and_fixed_paths(monkeypatch):
    from contextlib import contextmanager

    from vendor_cp import production_secrets

    events = []

    @contextmanager
    def lock():
        events.append("lock")
        yield
        events.append("unlock")

    def renew(**kwargs):
        assert events == ["lock"]
        assert kwargs == {
            "private_key_file": g.PRIVATE_KEY_FILE,
            "auth_directory": g.AUTH_DIRECTORY,
        }
        return {"public": True}

    monkeypatch.setattr(g.os, "geteuid", lambda: 0)
    monkeypatch.setattr(production_secrets, "production_deployment_lock", lock)
    monkeypatch.setattr(g, "renew_credentials", renew)
    assert g.renew_host_credentials() == {"public": True}
    assert events == ["lock", "unlock"]
    monkeypatch.setattr(g.os, "geteuid", lambda: 10001)
    with pytest.raises(g.GitHubCredentialError, match="root operator"):
        g.renew_host_credentials()


@pytest.mark.parametrize("target", ["auth_mode", "auth_owner", "old_symlink"])
def test_unsafe_auth_directory_or_file_never_issues(setup, target):
    _, _, auth = setup
    if target == "auth_mode":
        auth.chmod(0o770)
    elif target == "old_symlink":
        (auth / "hosts.yml").symlink_to(auth / "absent")
    else:
        # Inject a mismatched expected group; never chown a real host object.
        with pytest.raises(g.GitHubCredentialError):
            g.renew_credentials(
                private_key_file=setup[1],
                auth_directory=auth,
                owner_uid=os.getuid(),
                reader_gid=os.getgid() + 1,
                request=lambda *_: pytest.fail("must not issue"),
            )
        return
    with pytest.raises(g.GitHubCredentialError):
        invoke(setup, lambda *_: pytest.fail("must not issue"))


def test_repeat_renewal_replaces_inode_for_directory_mount_consumers(setup):
    _, _, auth = setup
    calls = []

    def transport(method, *_):
        calls.append(method)
        data = response()
        data["token"] += str(len(calls))
        return 201, json.dumps(data).encode()

    first = invoke(setup, transport)
    old_path = auth / "hosts.yml"
    old_inode = old_path.stat().st_ino
    with old_path.open() as held:
        second = invoke(setup, transport)
        assert old_path.stat().st_ino != old_inode
        assert SYNTHETIC_TOKEN + "1" in held.read()
        assert SYNTHETIC_TOKEN + "2" in old_path.read_text()
    assert first == second
    assert calls == ["POST", "POST"]


def test_host_lock_contention_sanitized_without_issuance(monkeypatch):
    from vendor_cp import production_secrets

    def refuse():
        raise production_secrets.ProductionSecretError("private diagnostic")

    monkeypatch.setattr(g.os, "geteuid", lambda: 0)
    monkeypatch.setattr(production_secrets, "production_deployment_lock", refuse)
    monkeypatch.setattr(
        g, "renew_credentials", lambda **_: pytest.fail("must not issue")
    )
    with pytest.raises(
        g.GitHubCredentialError, match="^production deployment lock unavailable$"
    ):
        g.renew_host_credentials()
