"""A disposable OpenBao (dev server) harness for the transit custody conformance.

CI only. The server is started by the workflow from an image pinned by digest, with
a root token that is random per job and never echoed; its address and token reach
the tests through `CONFORMANCE_OPENBAO_ADDR` and `CONFORMANCE_OPENBAO_ROOT_TOKEN`.
Missing configuration is a FAILURE, never a skip. This module talks to that one
server with no proxy and no redirects, and names nothing it creates after a real
mount, key or policy: every name carries a per-run suffix.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


class OpenBao:
    def __init__(self, address: str, root_token: str) -> None:
        assert address.startswith(
            ("http://127.0.0.1:", "http://localhost:")
        ), "the disposable OpenBao must be on loopback"
        self.address = address.rstrip("/")
        self._root = root_token

    @classmethod
    def from_env(cls) -> OpenBao:
        address = os.environ.get("CONFORMANCE_OPENBAO_ADDR", "")
        token = os.environ.get("CONFORMANCE_OPENBAO_ROOT_TOKEN", "")
        assert address and token, (
            "CONFORMANCE_OPENBAO_ADDR and CONFORMANCE_OPENBAO_ROOT_TOKEN are "
            "required: the transit cases need the disposable OpenBao server. "
            "Missing is a failure, not a skip"
        )
        return cls(address, token)

    def call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> tuple[int, Any]:
        request = urllib.request.Request(  # noqa: S310 - loopback http, asserted
            f"{self.address}/v1/{path.lstrip('/')}",
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "X-Vault-Token": token or self._root,
                "Content-Type": "application/json",
            },
        )
        try:
            with _OPENER.open(request, timeout=10) as response:  # noqa: S310
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw, status = error.read(), error.code
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def must(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        status, payload = self.call(method, path, body)
        assert 200 <= status < 300, f"OpenBao {method} {path} answered {status}"
        return payload

    def version(self) -> str:
        status, payload = self.call("GET", "sys/health")
        assert status in (200, 429, 472, 473), status
        return str(payload["version"])

    # ── the ceremony's own steps, as the design lists them ──

    def provision(self, tag: str | None = None) -> _Kit:
        suffix = tag or uuid.uuid4().hex[:8]
        mount = f"transit-a2-{suffix}"
        kit = _Kit(
            bao=self,
            mount=mount,
            authorization_key=f"cp-a2-auth-{suffix}",
            dispatch_key=f"cp-a2-disp-{suffix}",
            policy=f"cp-a2-sign-{suffix}",
            role=f"cp-a2-signer-{suffix}",
        )
        self.must("POST", f"sys/mounts/{mount}", {"type": "transit"})
        for name in (kit.authorization_key, kit.dispatch_key):
            self.must(
                "POST",
                f"{mount}/keys/{name}",
                {
                    "type": "ed25519",
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "derived": False,
                    "auto_rotate_period": 0,
                },
            )
        return kit


class _Kit:
    def __init__(
        self,
        *,
        bao: OpenBao,
        mount: str,
        authorization_key: str,
        dispatch_key: str,
        policy: str,
        role: str,
    ) -> None:
        self.bao, self.mount = bao, mount
        self.authorization_key, self.dispatch_key = authorization_key, dispatch_key
        self.policy, self.role = policy, role

    def key_description(self, name: str) -> bytes:
        status, payload = self.bao.call("GET", f"{self.mount}/keys/{name}")
        assert status == 200
        return json.dumps(payload).encode()

    def install_policy_and_role(self, hcl: str) -> None:
        self.bao.must("PUT", f"sys/policies/acl/{self.policy}", {"policy": hcl})
        self.bao.must(
            "POST",
            f"auth/token/roles/{self.role}",
            {
                "allowed_policies": [self.policy],
                "token_no_default_policy": True,
                "renewable": False,
                "token_type": "service",
                "token_explicit_max_ttl": "15m",
                "orphan": False,
            },
        )

    def mint(self, *, uses: int = 2, ttl: str = "10m") -> tuple[str, str]:
        payload = self.bao.must(
            "POST",
            f"auth/token/create/{self.role}",
            {"num_uses": uses, "ttl": ttl},
        )
        return payload["auth"]["client_token"], payload["auth"]["accessor"]

    def revoke_accessor(self, accessor: str) -> None:
        self.bao.must("POST", "auth/token/revoke-accessor", {"accessor": accessor})

    def accessor_is_gone(self, accessor: str) -> bool:
        status, _ = self.bao.call(
            "POST", "auth/token/lookup-accessor", {"accessor": accessor}
        )
        return status >= 400

    def root_sign(self, name: str, message: bytes, **extra: Any) -> bytes:
        import base64

        body = {"input": base64.b64encode(message).decode(), **extra}
        payload = self.bao.must("POST", f"{self.mount}/sign/{name}", body)
        return json.dumps(payload).encode()

    def teardown(self) -> None:
        for name in (self.authorization_key, self.dispatch_key):
            self.bao.call(
                "POST", f"{self.mount}/keys/{name}/config", {"deletion_allowed": True}
            )
        self.bao.call("DELETE", f"sys/mounts/{self.mount}")
        self.bao.call("DELETE", f"auth/token/roles/{self.role}")
        self.bao.call("DELETE", f"sys/policies/acl/{self.policy}")


class UnixRelay:
    """The test-side stand-in for the SSH relay: a unix socket forwarded to the
    dev server's TCP port. (The production relay also allowlists the two sign
    paths; that is the workstation forwarder's job and is not proven here.)"""

    def __init__(self, path: str, address: str) -> None:
        parsed = urllib.parse.urlparse(address)
        self._target = (parsed.hostname or "127.0.0.1", parsed.port or 8200)
        self.path = path
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(path)
        os.chmod(path, 0o600)
        self._server.listen(8)
        self._running = True
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while self._running:
            try:
                client, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._pipe, args=(client,), daemon=True).start()

    def _pipe(self, client: socket.socket) -> None:
        try:
            upstream = socket.create_connection(self._target, timeout=10)
        except OSError:
            client.close()
            return

        def forward(source: socket.socket, sink: socket.socket) -> None:
            try:
                while chunk := source.recv(65536):
                    sink.sendall(chunk)
            except OSError:
                pass
            finally:
                for end in (source, sink):
                    try:
                        end.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=forward, args=(upstream, client), daemon=True).start()
        forward(client, upstream)

    def close(self) -> None:
        self._running = False
        self._server.close()
        Path(self.path).unlink(missing_ok=True)
