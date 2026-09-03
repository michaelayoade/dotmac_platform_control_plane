# ADR-0016: API documentation exposure is a declared assembly policy, not a FastAPI default

- **Status:** ACCEPTED 2026-08-31 by Michael Ayoade, the owner and only approver.
  **Acceptance is not deployment.** The application half is merged here; § 6
  records the kernel obligation that has NOT been discharged and names its owner.
- **Date:** 2026-08-31 proposed, 2026-08-31 accepted
- **Owner:** Michael Ayoade
- **Relates to:** `dotmac_starter_mt` ADR-0003 (a deployment profile selects
  surfaces and nothing else), ADR-0014 (the console has one browser
  authentication owner — the plane rule in § 3 is the same rule, applied to a
  surface FastAPI mounts for free),
  ADR-0015 (a production profile publishes no simulation),
  `dotmac_starter_mt` ADR-0018 (a guard exemption states an enforceable
  premise)

## 1. Context — the defect

`dotmac_kernel.create_app` constructs `FastAPI(title=spec.name, lifespan=lifespan)`
and passes none of `docs_url`, `redoc_url`, `openapi_url` or
`swagger_ui_oauth2_redirect_url`. FastAPI's defaults therefore apply, and every
assembly built on the kernel mounts:

    /docs                    Swagger UI
    /docs/oauth2-redirect    Swagger's OAuth2 callback
    /redoc                   ReDoc
    /openapi.json            the OpenAPI document

`deploy/nginx/vendor.dotmac.io.conf` proxies `location /` wholesale to the
application. So on vendor-cp-prod the control plane's complete endpoint
inventory, every request and response schema, and every enum vocabulary were
readable by anyone who could reach the host, with no credential.

This is not a missing feature. It is a decision nobody made: FastAPI enables
documentation by default, which means "forgot to think about it" and "decided to
publish it" produce identical bytes. Anything that repairs only today's
composition and not that property will regress the moment a new assembly appears.

## 2. Decision

An assembly DECLARES its API-documentation exposure, per environment and per
plane, as a typed value. `src/vendor_cp/api_documentation.py` holds the type, the
declared policies and the gate; `vendor_cp.main` applies it to the application
`create_app` returns and refuses to start if the resulting route inventory does
not match what was declared.

Two planes, because they authenticate differently and always will:

| plane | paths | audience |
| --- | --- | --- |
| `INTERACTIVE` | `/docs`, `/docs/oauth2-redirect`, `/redoc` | a human in a browser |
| `DOCUMENT` | `/openapi.json` | a bearer-authenticated API client |

Three exposures: `DISABLED` (the route does not exist), `PUBLIC`, and
`PLATFORM_BEARER` (behind `dotmac_kernel.platform_auth.require_platform_admin`,
which is host-exact then bearer-only).

The declared policies:

| environment | interactive | document |
| --- | --- | --- |
| `development` | `PUBLIC` | `PUBLIC` |
| `test` | `PUBLIC` | `PUBLIC` |
| `production` | `DISABLED` | `PLATFORM_BEARER` |

Environment resolution FAILS CLOSED. Only the enumerated development and test
spellings select a publishing policy; unset, blank, `staging`, `prod` and any
typo resolve to `production`. This is stricter than
`assembly.build_spec()`'s `os.getenv("ENVIRONMENT", "development")` and stricter
than `Settings.is_production`, deliberately: both differences withhold a surface
and neither can add one.

## 3. Why the browser pages are DISABLED rather than protected

`PLATFORM_BEARER` is expressible for the `DOCUMENT` plane only, and the policy
type REFUSES to construct an interactive plane that claims it.

A browser navigating to `/docs` sends no `Authorization` header. It cannot: the
navigation is not made by the page's own JavaScript. So the only way to make a
"bearer-protected" Swagger UI actually load for an operator is to accept a
session COOKIE on that path instead — which is the cookie/bearer plane confusion
being repaired on the console in the same wave. Declaring the intent and then
discovering it does not work is how that fallback gets added six months later by
somebody who does not know why the path is sensitive. So the type refuses the
declaration, and `audit_api_documentation` independently fails any documentation
route that depends on `require_platform_web_auth` or `require_web_auth` under any
exposure.

The OpenAPI document keeps a real audience — an API client that already holds a
platform-admin bearer token — so it is protected rather than deleted. The browser
pages have no production operator task, so they are deleted rather than protected.

## 4. Why NOT an nginx location

Three `location` blocks returning 404 would close the hole on vendor-cp-prod
today. They would not be the authority for it:

* `docker-compose.production.yml` publishes the application on
  `127.0.0.1:${VENDOR_APP_PORT:-8100}:8000`. Nginx does not sit in front of that
  port. An operator's SSH forward, a sidecar, or any future proxy reaches the
  application with the rule absent.
* A second vhost, a different ingress, or a `location` block ordered ahead of the
  deny rule removes it silently — nginx reports no error for a rule that never
  matches.
* A deployment artifact is not versioned, reviewed or tested with the application
  whose surface it is claiming to define.

So the vhost is left proxying `/` wholesale ON PURPOSE, the documentation paths
really do arrive at the application, and the application refuses them.
`tests/architecture/test_api_documentation_ingress.py` asserts both halves of
that coupling, and fails if any vhost starts naming a documentation path — not
because defence in depth is wrong, but because a `location /docs` invites the
next reader to treat the application-side policy as redundant.

## 5. The sensitivity proof

The assertion that matters is not that today's production route set is correct.
It is that an assembly which FORGETS the policy fails.

`tests/unit/test_api_documentation_policy.py` plants FastAPI's default
configuration twice — on a bare `FastAPI()` and on this assembly's own
`create_app(build_spec())` before the policy is applied — and requires
`audit_api_documentation` to report a violation naming each of `/docs`, `/redoc`
and `/openapi.json`. The second plant is the real one: a gate proven against a
toy has not been proven against the product, and that un-policed application is
the exact state the production host was in.

The mirror case is checked too. An application serving NO documentation must fail
the DEVELOPMENT gate, so the gate cannot pass merely by objecting to routes being
present.

## 6. The kernel obligation — NOT discharged

This module is the consumer half of a contract the kernel should own. Every
assembly over `create_app` inherits the same default and would otherwise write
this file again — which is the "each product reinvents it" outcome ADR-0006's
extraction rule exists to prevent, and `platform_surface_enabled` already
establishes the precedent: the kernel's own comment says a product surface
decision "must not require deleting FastAPI routes after the factory has
validated them", which is precisely what `vendor_cp.main` now does.

The requested kernel surface, stated exactly. The defect in the kernel is one
line — `dotmac_kernel/app_factory.py` builds `FastAPI(title=spec.name,
lifespan=lifespan)` and passes none of the four suppression arguments.

**1. A new supported module `dotmac_kernel.api_documentation`** — pure
configuration, importable without `DATABASE_URL` (the same class as
`web_surfaces`), added to `SUPPORTED_MODULES` and the top-level `__all__`:

```python
class DocumentationPlane(StrEnum):
    INTERACTIVE = "interactive"   # /docs, /docs/oauth2-redirect, /redoc
    DOCUMENT = "document"         # /openapi.json

class DocumentationExposure(StrEnum):
    DISABLED = "disabled"                # the route does not exist
    PUBLIC = "public"
    PLATFORM_BEARER = "platform-bearer"  # behind require_platform_admin

@dataclass(frozen=True, slots=True)
class ApiDocumentationPolicy:
    environment: str
    interactive: DocumentationExposure
    document: DocumentationExposure
    rationale: str
    def exposure(self, plane: DocumentationPlane) -> DocumentationExposure: ...

def documentation_routes(app) -> tuple[DocumentationRoute, ...]: ...
def audit_api_documentation(app, policy) -> tuple[str, ...]: ...  # () == satisfied
```

Four construction refusals, all load-bearing: `interactive is PLATFORM_BEARER`
(§ 3 — this is the plane rule and the reason the type exists at all);
`production` with any `PUBLIC`; `interactive is PUBLIC` without
`document is PUBLIC`; an empty rationale.

`documentation_routes` must locate routes by PATH — the union of FastAPI's four
defaults and the app's current attribute values — never by reading
`app.docs_url`. Clearing an attribute must not be able to hide a route that is
still mounted. `audit_api_documentation` must additionally fail, under ANY
exposure, on a documentation route depending on `require_platform_web_auth` or
`require_web_auth`.

**2. `ProductAssemblySpec.api_documentation: ApiDocumentationPolicy | None = None`.**
`None` must NOT mean "FastAPI's default" — that is the defect. It means the
assembly has not declared one, and `create_app` refuses to build, the way an
unbound migration prerequisite refuses. A permissive fallback would reproduce
this bug with extra ceremony.

**3. `create_app` passes the resolved paths to the `FastAPI(...)` CONSTRUCTOR**
rather than removing routes afterwards, and mounts the `PLATFORM_BEARER`
document itself with `dependencies=[Depends(require_platform_admin)],
include_in_schema=False`. Not mounting is the point; post-hoc surgery is what
this assembly is doing in the meantime and what the field exists to retire.

**4. The knob is the existing `Settings.environment`, already read from
`ENVIRONMENT`** — no new variable. It is classified fail-closed, as a NARROWING
introduced under its own name rather than by changing `Settings.is_production`:
`{"dev", "development", "local"}` and `{"test", "testing", "ci"}` select the
publishing policies, and everything else, INCLUDING UNSET AND BLANK, is
production. The assembly declares a policy per environment; the kernel resolves
which one applies.

**5. The kernel's own architecture suite carries the planted-default case from
§ 5**, in both directions: FastAPI's default configuration on a bare app AND on
the reference assembly's own `create_app(build_spec())` must FAIL the production
gate, and an app serving no documentation must FAIL the development gate.

Ownership: `dotmac_starter_mt` has a single integration owner working a
serialized queue; the specification above was routed there rather than
implemented across the boundary. Until it lands, `vendor_cp.api_documentation` is
this assembly's local expression of it and is expected to be DELETED, not
rewritten, when the kernel field exists — the declared policies move to
`build_spec()` and `vendor_cp.main` returns to one line.

## 7. Consequences

* `/docs` and `/redoc` return 404 on vendor-cp-prod. No operator workflow used
  them; the deploy runbook does not reference them.
* `/openapi.json` returns 404 off the platform root host and 401 without a live
  platform-admin bearer token.
* A developer must set `ENVIRONMENT=development` (or `dev`, `local`) to see the
  documentation locally. Nothing in this repository ran the server without an
  environment, so this costs a line in a shell profile and buys a host that
  cannot publish its API by omission.
* This change alters no data, no migration, no privilege and no module
  composition. It removes routes and adds one guarded route.

## 8. Kernel ownership adopted — 2026-09-03

The obligation in § 6 is discharged by the Platform CP kernel-a100 adoption.
`dotmac_kernel.api_documentation` is a supported public module in the official
a100 artifact, and `ProductAssemblySpec.api_documentation` is enforced by
`create_app` at construction. `assembly.build_spec()` now imports and calls
`environment_api_documentation_policy()` directly; the local
`vendor_cp.api_documentation` implementation is deleted, and `main.py` contains
no post-construction route mutation.

The existing fail-closed environment split is preserved: the documentation
helper reads raw `ENVIRONMENT`, so an unset or unfamiliar value selects the
production policy even though the separate deployment-profile resolver has a
development default. Product tests now exercise the installed kernel seam and
plant removal of the spec field; kernel tests remain the owner of the policy's
internal construction and audit mechanics.

This is an ownership cutover, not a production-deployment claim. The official
a100 wheel was measured at
`sha256:60a9ba68e4f659ada1d38583e2e5a8d6c803f387a692496cb49e60019772b88c`
(release run `33483169850`, artifact `9790730793`); deployment remains governed
by the separately authorized production path.
