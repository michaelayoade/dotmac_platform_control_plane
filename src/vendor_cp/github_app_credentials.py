"""Root-operated ledger App lease primitive; caller holds production_deployment_lock.

No runtime composition or deployment authority. Mount AUTH_DIRECTORY read-only
into the application: directory mounting allows atomic hosts.yml replacement.
The /run lease is ephemeral: rename commits, without directory crash durability.
A reboot requires fresh issuance before the application can authenticate.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

APP_ID = 5448762
CLIENT_ID = "Iv23liYdG6wscEtDVNsV"
INSTALLATION_ID = 174650996
REPOSITORY_ID = 1431613388
REPOSITORY = "michaelayoade/dotmac-deploy-ledger"
PRIVATE_KEY_FILE = Path("/etc/dotmac/platform-cp/github-app/private-key.pem")
AUTH_DIRECTORY = Path("/run/secrets/dotmac/platform-cp/github")
PERMISSIONS = {"contents": "write", "metadata": "read"}
MAX_RESPONSE = 65536
TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,4096}\Z")
Transport = Callable[[str, str, str, bytes | None], tuple[int, bytes]]


class GitHubCredentialError(RuntimeError):
    """Safe public refusal; never includes request, response or key material."""


def _ancestry(path: Path, owner_uid: int) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise GitHubCredentialError("unsafe credential path")
    for parent in (path, *path.parents):
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise GitHubCredentialError("unsafe credential ancestry")


def _regular(fd: int, uid: int, gid: int | None, mode: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != mode
        or (gid is not None and info.st_gid != gid)
    ):
        raise GitHubCredentialError("unsafe credential file")


def _jwt(path: Path, now: int, uid: int) -> str:
    _ancestry(path.parent, uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        _regular(stream.fileno(), uid, None, 0o600)
        pem = stream.read(MAX_RESPONSE + 1)
    if len(pem) > MAX_RESPONSE:
        raise GitHubCredentialError("invalid signing key")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise GitHubCredentialError("invalid signing key")

    def encode(value: bytes) -> bytes:
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    header = encode(b'{"alg":"RS256","typ":"JWT"}')
    payload = encode(
        json.dumps({"iat": now - 60, "exp": now + 540, "iss": CLIENT_ID}).encode()
    )
    signing = header + b"." + payload
    signature = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    return (signing + b"." + encode(signature)).decode("ascii")


def github_request(
    method: str, path: str, bearer: str, body: bytes | None
) -> tuple[int, bytes]:
    """Fixed-origin direct TLS; no proxy, redirect or caller-selected origin."""
    if (method, path) not in {
        ("POST", f"/app/installations/{INSTALLATION_ID}/access_tokens"),
        ("DELETE", "/installation/token"),
    }:
        raise GitHubCredentialError("unsupported GitHub request")
    connection = http.client.HTTPSConnection("api.github.com", timeout=15)
    try:
        connection.request(
            method,
            path,
            body=body,
            headers={
                "Authorization": "Bearer " + bearer,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "Content-Type": "application/json",
                "User-Agent": "dotmac-ledger-app-lease",
            },
        )
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise GitHubCredentialError("oversized GitHub response")
        return response.status, data
    finally:
        connection.close()


def _validate(data: dict[str, Any], now: int) -> dict[str, Any]:
    repositories = data.get("repositories")
    if (
        data.get("permissions") != PERMISSIONS
        or data.get("repository_selection") != "selected"
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or not isinstance(repositories[0], dict)
        or repositories[0].get("id") != REPOSITORY_ID
        or repositories[0].get("full_name") != REPOSITORY
    ):
        raise GitHubCredentialError("unexpected GitHub lease authority")
    expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
    if expires.tzinfo is None or not 2700 <= expires.timestamp() - now <= 3900:
        raise GitHubCredentialError("unexpected GitHub lease expiry")
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "repository_id": REPOSITORY_ID,
        "repository": REPOSITORY,
        "permissions": dict(PERMISSIONS),
        "issued_at": now,
        "expires_at": expires.astimezone(UTC).isoformat(),
    }


def _directory(path: Path, uid: int, gid: int) -> int:
    _ancestry(path, uid)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
        os.close(fd)
        raise GitHubCredentialError("unsafe auth directory")
    try:
        existing = os.open(
            "hosts.yml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
        )
    except FileNotFoundError:
        return fd
    except BaseException:
        os.close(fd)
        raise
    try:
        _regular(existing, uid, gid, 0o640)
    except BaseException:
        os.close(fd)
        raise
    finally:
        os.close(existing)
    return fd


def _persist(fd: int, token: str, receipt: dict[str, Any], uid: int, gid: int) -> None:
    name = ".hosts-" + secrets.token_hex(12)
    temporary = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    try:
        with os.fdopen(temporary, "w") as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write("# dotmac-github-app-lease " + json.dumps(receipt) + "\n")
            json.dump(
                {"github.com": {"oauth_token": token, "git_protocol": "https"}}, stream
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, "hosts.yml", src_dir_fd=fd, dst_dir_fd=fd)
        name = ""
    finally:
        try:
            if name:
                os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def renew_credentials(
    *,
    private_key_file: Path = PRIVATE_KEY_FILE,
    auth_directory: Path = AUTH_DIRECTORY,
    clock: Callable[[], float] = time.time,
    request: Transport = github_request,
    owner_uid: int = 0,
    reader_gid: int = 10001,
) -> dict[str, Any]:
    """Issue and atomically persist one lease; caller serializes with its lock.

    A successful call always renews. Failed renewal preserves the old lease;
    a newly issued token is revoked on validation/persistence failure when known.
    uid/gid and ports are injectable for synthetic tests, never exposed by CLI.
    """
    token: str | None = None
    fd: int | None = None
    try:
        now = int(clock())
        fd = _directory(auth_directory, owner_uid, reader_gid)
        jwt = _jwt(private_key_file, now, owner_uid)
        status, raw = request(
            "POST",
            f"/app/installations/{INSTALLATION_ID}" "/access_tokens",
            jwt,
            json.dumps(
                {"repository_ids": [REPOSITORY_ID], "permissions": PERMISSIONS}
            ).encode(),
        )
        if len(raw) > MAX_RESPONSE:
            raise GitHubCredentialError("oversized GitHub response")
        data = json.loads(raw)
        candidate = data.get("token")
        if isinstance(candidate, str) and TOKEN.fullmatch(candidate):
            token = candidate
        if status != 201 or token is None:
            raise GitHubCredentialError("GitHub lease issuance refused")
        receipt = _validate(data, now)
        _persist(fd, token, receipt, owner_uid, reader_gid)
        return receipt
    except Exception:
        if token is not None:
            try:
                status, _ = request("DELETE", "/installation/token", token, None)
                if status != 204:
                    raise GitHubCredentialError("lease revocation unconfirmed")
            except Exception:
                raise GitHubCredentialError(
                    "lease renewal failed; new lease revocation unconfirmed"
                ) from None
        raise GitHubCredentialError("lease renewal failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def renew_host_credentials() -> dict[str, Any]:
    """Installed operator adapter; lock authority belongs to production_secrets."""
    from vendor_cp.production_secrets import (
        ProductionSecretError,
        production_deployment_lock,
    )

    if os.geteuid() != 0:
        raise GitHubCredentialError("root operator required")
    try:
        with production_deployment_lock():
            return renew_credentials(
                private_key_file=PRIVATE_KEY_FILE, auth_directory=AUTH_DIRECTORY
            )
    except (ProductionSecretError, OSError):
        raise GitHubCredentialError("production deployment lock unavailable") from None
