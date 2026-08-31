"""Nginx cannot route around the application's documentation policy.

The defect was that `/docs`, `/redoc` and `/openapi.json` were public on
vendor-cp-prod. The cheap repair is three `location` blocks in the vhost. This
file exists to record why that repair was NOT taken, and to keep the reasoning
enforceable rather than remembered:

* The vhost is one ingress. `docker-compose.production.yml` publishes the
  application on `127.0.0.1:${VENDOR_APP_PORT:-8100}:8000`, which nginx does not
  sit in front of — an operator forwarding that port, a second vhost, a future
  load balancer or a `location` block that matches first all reach the
  application with the nginx rule absent. A deployment artifact cannot be the
  authority for what an application serves.
* So the vhost deliberately still proxies `/` WHOLESALE, the documentation paths
  really do arrive at the application, and the application refuses them. These
  assertions are the coupling: if the nginx side ever starts looking like the
  control, or if the application side ever stops being one, this fails.

The application-side proof lives in `tests/unit/test_api_documentation_policy.py`
— including the planted-default sensitivity case. This file only proves that
nothing in the deployment layer is standing in for it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from vendor_cp.api_documentation import (
    OPENAPI_PATH,
    PRODUCTION,
    REDOC_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    SWAGGER_PATH,
    DocumentationExposure,
    api_documentation_policy,
)

ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "deploy" / "nginx"

#: The documentation coordinates, as an ingress would have to spell them.
DOCUMENTATION_PATHS: Final[tuple[str, ...]] = (
    SWAGGER_PATH,
    SWAGGER_OAUTH2_REDIRECT_PATH,
    REDOC_PATH,
    OPENAPI_PATH,
)

_LOCATION = re.compile(r"^\s*location\s+(?P<matcher>[^{]+?)\s*\{", re.M)


def _confs() -> list[Path]:
    files = sorted(NGINX.glob("*.conf"))
    assert files, f"no vhost files under {NGINX}"
    return files


def _locations(text: str) -> list[str]:
    return [match.group("matcher").strip() for match in _LOCATION.finditer(text)]


def test_no_nginx_location_stands_in_for_the_application_policy() -> None:
    """No vhost mentions a documentation path, in any directive.

    This is a ratchet, not a preference. The moment a `location /docs` appears,
    a reader — and the next person editing the application — is entitled to
    believe the routing layer is handling it, and the application-side policy
    starts looking like belt-and-braces that can be simplified away. Adding one
    is allowed; doing it without revisiting this reasoning is not.
    """
    offenders = [
        f"{conf.name}: {path}"
        for conf in _confs()
        for path in (*DOCUMENTATION_PATHS, "/openapi")
        if path in conf.read_text(encoding="utf-8")
    ]
    assert not offenders, (
        "the application, not the ingress, is the authority for which "
        f"documentation paths are served: {offenders}"
    )


def test_the_production_vhost_proxies_the_documentation_paths_to_the_application() -> (
    None
):
    """The TLS server block forwards `/` wholesale, so the app really decides.

    An assertion that the documentation paths are BLOCKED here would be the
    wrong shape: what makes the application-level policy load-bearing is
    precisely that these requests arrive.
    """
    vhost = (NGINX / "vendor.dotmac.io.conf").read_text(encoding="utf-8")
    tls_block = vhost.split("listen 443 ssl;", 1)[1]

    assert _locations(tls_block) == ["/"], _locations(tls_block)
    assert "proxy_pass http://127.0.0.1:8100;" in tls_block


def test_the_bootstrap_vhost_is_not_the_documentation_control_either() -> None:
    """The certificate-bootstrap vhost 503s everything and holds no doc rule.

    It is a maintenance state, not a security control: it stops serving the
    moment the real vhost replaces it.
    """
    bootstrap = (NGINX / "vendor.dotmac.io.bootstrap.conf").read_text(encoding="utf-8")
    assert set(_locations(bootstrap)) == {"^~ /.well-known/acme-challenge/", "/"}
    assert "return 503;" in bootstrap


def test_the_application_is_reachable_without_any_vhost() -> None:
    """The premise that makes an ingress rule insufficient, stated as a fact.

    The production compose publishes the application port on the host loopback.
    Anything on that host — an operator's SSH forward, a sidecar, a future
    reverse proxy — reaches the application with nginx entirely out of the path.
    """
    compose = (ROOT / "docker-compose.production.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:${VENDOR_APP_PORT:-8100}:8000"' in compose


def test_the_application_side_of_the_coupling_still_denies() -> None:
    """The other half: nginx forwards, so the application must refuse.

    Without this, someone could relax the application policy while these nginx
    assertions stayed green — which is the exact failure mode of a repair that
    lives in the deployment layer.
    """
    policy = api_documentation_policy(PRODUCTION)
    assert policy.interactive is DocumentationExposure.DISABLED
    assert policy.document is not DocumentationExposure.PUBLIC


def test_the_production_environment_marker_that_selects_the_policy_is_required() -> (
    None
):
    """`ENVIRONMENT` is what selects the policy, so its production value is gated.

    Resolution already fails closed — an unset or unrecognised value takes the
    production policy — so this is not the thing preventing an accident. It is
    the enforceable premise behind the docstring claim that the production host
    declares its environment, rather than a sentence asserting it.
    """
    deploy = (ROOT / "scripts" / "deploy_production.sh").read_text(encoding="utf-8")
    assert "grep -Fqx 'ENVIRONMENT=production'" in deploy
    example = (ROOT / ".env.production.example").read_text(encoding="utf-8")
    assert "\nENVIRONMENT=production\n" in example
