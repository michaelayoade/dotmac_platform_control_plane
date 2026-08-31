"""ASGI entrypoint — the vendor control plane is `create_app(build_spec())`.

`uvicorn vendor_cp.main:app`. All composition lives in `assembly.build_spec()`;
this module is the thinnest possible adapter, exactly as the kernel intends.

The one thing it adds is the API-documentation policy. `create_app` returns a
FastAPI application carrying FastAPI's DEFAULT `/docs`, `/docs/oauth2-redirect`,
`/redoc` and `/openapi.json` routes, which on the production host were reachable
by anyone who could reach the vhost. `install_api_documentation_policy` resolves
this process's declared policy from `ENVIRONMENT` and makes the live route
inventory match it, raising at import if it cannot — so the process refuses to
start rather than serving documentation it declared it would not serve.

It sits here rather than in `build_spec()` because a spec has no application to
correct. That is the shape the kernel should own instead
(`docs/adr/0016-api-documentation-exposure-policy.md`); when it does, this line
becomes a field on `ProductAssemblySpec` and `vendor_cp.api_documentation` is
deleted rather than rewritten.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from vendor_cp.api_documentation import install_api_documentation_policy
from vendor_cp.assembly import build_spec

app = install_api_documentation_policy(create_app(build_spec()))
