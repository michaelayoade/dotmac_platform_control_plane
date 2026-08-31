"""The console answers a browser session, and only a browser session.

The graph assertions in
`tests/architecture/test_browser_authentication_ownership.py` prove there is
exactly one browser authentication owner. These prove the owner WORKS, over
real HTTP through the composed application: a valid platform session renders
the console, and every other credential shape is refused.

Both halves are needed and neither substitutes for the other. A status-code
suite alone would go green if someone "fixed" the defect by loosening the
second guard until it stopped saying no — the abort condition this repair was
given, because a 200 obtained that way is worse than the 403 it replaced. A
graph suite alone would go green on a route that resolves its owner and then
raises for an unrelated reason.

## Why the tenant resolver is patched and nothing else is

`TenantResolverMiddleware` opens `resolver_session()` on the kernel's real
engine — the one built from `DATABASE_URL`, which under the SQLite unit lane
points at a deliberately unreachable host (`tests/conftest.py`). It is not the
subject here, and it is the only seam these tests redirect. Authentication,
CSRF, the facet composition and the error handlers all run exactly as composed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from dotmac_kernel import PlatformAdmin, create_app
from dotmac_kernel.config import settings
from dotmac_kernel.middleware import tenant as tenant_middleware
from dotmac_kernel.middleware.csrf import CSRF_COOKIE, CSRF_HEADER
from dotmac_kernel.models_platform import PlatformSession
from dotmac_kernel.platform_auth import PLATFORM_COOKIE, issue_platform_token
from dotmac_kernel.security import hash_token, issue_access_token
from dotmac_kernel.testing import (
    assembly_test_client,
    create_test_engine,
    isolated_session,
)
from sqlalchemy.orm import Session

from vendor_cp.assembly import build_spec
from vendor_cp.deployment_profile import FULL, deployment_profile

#: The platform surface exists ONLY on the platform root host — off it the
#: middleware and `require_platform_host` both 404, by design. Read from
#: configuration rather than hardcoded so the suite states the real premise.
HOST = settings.platform_root_domain
CONSOLE = f"http://{HOST}/platform/console"
LOGIN = "/platform/login"
LOGOUT = f"http://{HOST}/platform/logout"
VENDOR_API = f"http://{HOST}/platform/vendor/accounts"


@dataclass(frozen=True)
class _Harness:
    """Module-private on purpose, and typed loosely on purpose.

    `client` is whatever the kernel's supported test kit hands back, and its
    responses are that client's own type. Neither is imported here by name.
    This assembly's external-connector surface is ratcheted at zero measured
    `outbound_transport` spellings (`docs/external-connector-surface.md`); the
    ratchet measures Git-tracked Python rather than runtime reachability, so a
    test module naming an HTTP client library raises the count for real. A test
    is not the thing that gets to do that, and the baseline is not the thing
    that gets adjusted to let it.
    """

    client: Any
    db: Session

    def session_for(
        self, *, session_expires_in: int = 3600, revoked: bool = False
    ) -> str:
        """A platform admin plus a live `platform_sessions` row; returns the token.

        The token and the session row are varied INDEPENDENTLY on purpose. An
        expired session is not the same event as an expired token: the token can
        still verify while the server-side session has lapsed or been revoked,
        and that is the case a client-side-only check would wave through.
        """
        admin = PlatformAdmin(
            email=f"ops-{uuid4().hex}@dotmac.io",
            password_hash="not-a-real-hash",
            is_active=True,
        )
        self.db.add(admin)
        self.db.flush()
        token, _expires = issue_platform_token(admin.id)
        self.db.add(
            PlatformSession(
                admin_id=admin.id,
                token_hash=hash_token(token),
                expires_at=datetime.now(UTC) + timedelta(seconds=session_expires_in),
                revoked_at=datetime.now(UTC) if revoked else None,
            )
        )
        self.db.flush()
        return token

    def present(self, token: str) -> None:
        self.client.cookies.set(PLATFORM_COOKIE, token)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.client.get(url, follow_redirects=False, **kwargs)


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Harness]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as db:

            @contextmanager
            def _resolver() -> Iterator[Session]:
                yield db

            monkeypatch.setattr(tenant_middleware, "resolver_session", _resolver)
            app = create_app(build_spec(deployment_profile(FULL)))
            with assembly_test_client(app, session=db) as client:
                yield _Harness(client=client, db=db)
    finally:
        engine.dispose()


def _redirects_to_login(response: Any) -> bool:
    return response.status_code == 302 and response.headers["location"].startswith(
        LOGIN
    )


# ── The case the defect broke ────────────────────────────────────────────────
def test_a_valid_platform_browser_session_renders_the_console(
    harness: _Harness,
) -> None:
    """The whole point. Before the repair this was a 401: the browser cookie
    satisfied the facet and then met a bearer-only guard on the handler."""
    harness.present(harness.session_for())
    response = harness.get(CONSOLE)
    assert response.status_code == 200, response.text
    assert "Platform Control Plane" in response.text


# ── Everything that must be refused ──────────────────────────────────────────
def test_no_session_redirects_to_the_platform_login_route(harness: _Harness) -> None:
    """A browser gets sent somewhere it can fix the problem, not a JSON 401."""
    response = harness.get(CONSOLE)
    assert _redirects_to_login(response), (response.status_code, response.headers)


def test_an_expired_session_is_refused(harness: _Harness) -> None:
    """The token still verifies; the server-side session has lapsed."""
    harness.present(harness.session_for(session_expires_in=-60))
    response = harness.get(CONSOLE)
    assert response.status_code != 200
    assert _redirects_to_login(response), (response.status_code, response.headers)


def test_a_revoked_session_is_refused(harness: _Harness) -> None:
    """Logout must actually end the session, not merely drop a cookie."""
    harness.present(harness.session_for(revoked=True))
    response = harness.get(CONSOLE)
    assert response.status_code != 200
    assert _redirects_to_login(response), (response.status_code, response.headers)


def test_a_tenant_plane_identity_is_refused(harness: _Harness) -> None:
    """A tenant access token is signed by the SAME signer and still refused.

    This is the one that matters about the two token populations: the signature
    verifies, so nothing about cryptography stops it. What stops it is the
    `aud` claim a tenant token does not carry — the platform plane's identity
    boundary — plus the absence of a `platform_sessions` row.
    """
    harness.present(issue_access_token(uuid4(), uuid4())[0])
    response = harness.get(CONSOLE)
    assert response.status_code != 200
    assert _redirects_to_login(response), (response.status_code, response.headers)


def test_an_api_bearer_token_alone_does_not_become_a_browser_session(
    harness: _Harness,
) -> None:
    """A genuinely valid API credential, presented the API way, opens no page.

    The token here would authenticate the JSON API right now. Sent as an
    `Authorization` header with no session cookie, it must not render the
    console — and this is the assertion that fails if the repair is ever undone
    by teaching the browser route to read a bearer header instead of removing
    the second owner.
    """
    token = harness.session_for()
    response = harness.get(CONSOLE, headers={"authorization": f"Bearer {token}"})
    assert response.status_code != 200
    assert _redirects_to_login(response), (response.status_code, response.headers)


def test_a_browser_cookie_does_not_authenticate_the_json_api(
    harness: _Harness,
) -> None:
    """And the converse. The same live session, presented as a cookie, is not an
    API credential: the vendor API answers `require_platform_admin` alone."""
    harness.present(harness.session_for())
    response = harness.get(VENDOR_API)
    assert response.status_code == 401, response.text


# ── CSRF stays on every unsafe browser route ─────────────────────────────────
def test_an_unsafe_browser_mutation_without_a_valid_csrf_proof_is_refused(
    harness: _Harness,
) -> None:
    """Held on a LIVE session, so the 403 is the CSRF decision and not the
    authentication one — a test driving an anonymous request would pass whether
    or not CSRF existed, since the facet would have refused it anyway.

    The proof sent is well-formed transport carrying the wrong value, which is
    what makes the assertion about the signed, session-bound comparison rather
    than about the header's presence.

    **The absent-header case is deliberately not asserted here, and it is a
    real gap this suite found.** `require_csrf` falls back to
    `await request.form()` when no `X-CSRF-Token` header is present, and this
    assembly declares no form parser — the kernel calls that an assembly
    concern and ships none — so a header-less unsafe browser request raises
    instead of answering 403. The same missing dependency makes the kernel's
    own `POST /platform/login` unable to read its form at all. That is a
    separate defect with a separate owner, recorded in ADR-0014 § 5; codifying
    its current behaviour as an expected status here would turn a gap into a
    contract.
    """
    harness.present(harness.session_for())
    assert harness.get(CONSOLE).status_code == 200
    response = harness.client.post(
        LOGOUT, headers={CSRF_HEADER: "not-the-issued-token"}, follow_redirects=False
    )
    assert response.status_code == 403, response.text
    assert response.json()["code"] == "csrf_failed"


def test_a_valid_cookie_plus_csrf_proof_succeeds(harness: _Harness) -> None:
    """The positive half. The token is the one the middleware issued on the
    console GET, carried on the header bridge exactly as `csrf.js` does it."""
    harness.present(harness.session_for())
    assert harness.get(CONSOLE).status_code == 200
    proof = harness.client.cookies[CSRF_COOKIE]
    response = harness.client.post(
        LOGOUT, headers={CSRF_HEADER: proof}, follow_redirects=False
    )
    assert _redirects_to_login(response), (response.status_code, response.text)
