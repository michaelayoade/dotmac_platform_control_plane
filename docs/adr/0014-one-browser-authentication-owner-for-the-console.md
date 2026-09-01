# ADR-0014: One browser authentication owner for the platform console

- **Status:** ACCEPTED 2026-08-31 by Michael Ayoade, the owner and only
  approver. The repair is composed in this repository and enforced by tests;
  nothing here claims a deployment.
- **Date:** 2026-08-31 proposed, 2026-08-31 accepted
- **Follows:** the contract-v2 conversion that moved the console onto the
  kernel's `platform_admin` facet
- **Amends:** deny case **D4** (AGENTS.md rule 5), which named exactly one
  authentication owner because, when it was written, there was exactly one

## 1. Context — a guard that used to be the only one

D4 was written when the vendor control plane had a single authentication
transport. `require_platform_admin` reads an `Authorization: Bearer` header,
and every vendor surface — JSON and HTML alike — depended on it. "Auth goes
through the kernel" and "every route depends on `require_platform_admin`" were
the same sentence.

The contract-v2 conversion made them different sentences without anyone
noticing. The console became a `WebSurfaceContribution` against the kernel's
`platform_admin` facet, and that facet declares an authentication profile —
`kernel_platform_session`, whose provider is `require_platform_web_auth`,
reading the platform session COOKIE. The kernel's browser-surface runtime
attaches it to every non-entry route it mounts, nested inside the composed
context dependency.

So `/platform/console` ran two authentication owners:

```
require_csrf → facet cookie authentication → handler → require_platform_admin
```

A browser holding a valid platform session satisfied the facet and was then
refused by the handler for want of a header a browser has no reason to send.
The console was unreachable with exactly the credential it exists to accept.

**This is a plane mismatch, not a missing guard, and the difference decides
the repair.** The composition census (`docs/operations/composition-census-2026-08-30.md`,
measured at `539f0ee`) found 44 routes: all 43 JSON routes behind a
character-identical `require_platform_admin` alias across seven routers, and
zero unguarded handlers. Guard discipline here is already sound. What went
wrong on the one browser route is that a COOKIE met a BEARER-only authority.
So the instinctive fix — "the browser route is failing, give it a guard that
accepts cookies" — is exactly backwards: it would add a third opinion to a
route that already had two. The repair is subtraction.

**Why review did not catch it.** The D4 test read
`inspect.signature(endpoint)`. That sees only what a handler spells in its own
parameter list — not a dependency the ROUTER attached, and not one nested
inside another dependency. Both blindnesses point the same way: the facet's
authentication was invisible to the guard, so the guard could only conclude the
route was unguarded and insist the bearer dependency stay. The check was
actively holding the defect in place.

## 2. Decision

**The facet is the sole browser authentication owner for the console, and the
handler declares no authentication dependency at all.**

Concretely:

1. `require_platform_admin` is removed from `console_shell`. It is not
   replaced, softened, or made cookie-aware.
2. The JSON API is untouched. Every `/platform/vendor/*` route keeps
   `require_platform_admin`.
3. The two credential populations stay apart in both directions: a browser
   cookie never authenticates an API route, and an API bearer credential never
   becomes a browser session.
4. `require_csrf` stays on every unsafe browser route.
5. When a later screen needs the authenticated administrator, it reads a
   kernel-supported request-scoped principal projection. It does not
   re-authenticate, and this assembly does not build a local projection of its
   own — that would be the same parallel-authority defect wearing a new name.

**A 200 obtained by loosening a guard would be worse than the 403 it
replaced.** Deleting the second owner is the repair; making it agree is not.
Two owners that currently agree are two owners that can later disagree, and the
disagreement surfaces as an authorization outcome nobody chose.

## 3. What D4 means now

One authority for platform-actor identity, reached through two kernel-owned
transports, with **exactly one owner per route**:

| Plane | Transport | Owner | Attached by |
|---|---|---|---|
| JSON API | `Authorization: Bearer` | `require_platform_admin` | the route |
| Browser | platform session cookie | `require_platform_web_auth` | the `platform_admin` facet's declared profile |

A facet's declared ENTRY routes (the login form and its submission) carry zero
owners, by construction: they are where a session comes from.

## 4. Enforcement, and why it is on the graph

Every assertion builds the composed application and walks `route.dependant` —
the tree FastAPI itself solves per request — via
`tests/architecture/route_dependency_graph.py`. A regex over `console/web.py`
would prove a string is absent from one file; it would not prove a callable is
absent from the graph, and it would keep passing if the guard returned through
either door the old signature scan was blind to.

The detector carries its own sensitivity proof: a probe route declaring both
owners must be REPORTED as two, and a probe with an owner nested two levels
deep must still be seen. Without those, "exactly one owner" is an assertion
over a detector that might see nothing.

Behaviour is proven separately over real HTTP
(`tests/unit/test_console_browser_authentication.py`): a valid session renders
the console; a missing session redirects to the platform login route; an
expired or revoked session, a tenant-plane token, and a bare API bearer token
are each refused; an unsafe browser mutation without CSRF is refused and the
same mutation with the issued proof succeeds. Neither suite substitutes for the
other — the status-code half would go green on a loosened guard, and the graph
half would go green on an owner that resolves and then fails for an unrelated
reason.

## 5. Consequences

- AGENTS.md rule 5, the README boundary table and `docs/ARCHITECTURE.md`'s D4
  row are restated together with this decision, so no canonical document is
  left describing the single-transport arrangement (AGENTS.md rule 13).
- **This is now the reference shape.** The census also found this repository
  has zero templates, static assets, CSS, JS and no template engine — there was
  no browser-surface precedent here, correct or otherwise. Six module surfaces
  will copy whatever this leaves behind, so the graph helper
  (`tests/architecture/route_dependency_graph.py`) is written to be inherited:
  it quantifies over every composed browser route in the application, reads the
  entry-route set off `app.state.web_surface_registry` rather than a literal,
  and names its authentication owners exhaustively instead of matching a
  `require_*` prefix that `require_platform_host` and `require_tenant` would
  also satisfy. A new facet or module surface is covered the day it is
  composed, with no test edited.
- A future browser facet in this assembly inherits the rule for free: the
  general graph test quantifies over every composed browser route, not over the
  console.
- The narrower claim, stated as narrow: this ADR governs which dependency
  decides identity. It does not add authorization. The facet declares no
  admission permission and cannot — the kernel refuses one on a platform-plane
  profile, because admission is evaluated against a tenant-scoped `Party` that
  a `PlatformAdmin` does not have.

## 6. A separate defect this work found, and did not fix

> **Resolved 2026-09-01, by the lane that owns `pyproject.toml`.** `#97`
> declared `python-multipart` as a main dependency, which is exactly the fix
> this section says is not its own to make. Both consequences below are gone,
> and were verified against the ARTIFACT rather than the declaration: the
> candidate acceptance battery obtains a platform browser session through
> `POST /platform/login` and reaches `/platform/console`, and the header-less
> path is exercised by a proof-less `POST` that is still refused 403
> (`.github/candidate/acceptance.sh` step 7; release run `33474406793` at
> `2c9800d2`). Kept as written for the record.

**This assembly declares no form parser, and the browser surface needs one.**
The kernel's `platform_web.login_submit` reads its login form with
`await request.form()`, and `middleware.csrf.require_csrf` falls back to the
same call whenever an unsafe browser request carries no `X-CSRF-Token` header.
Starlette asserts a form-parsing library is installed before it looks at the
content type, so both paths RAISE rather than answer in a deployment without
one. The kernel is explicit that this is not its dependency to hold — its
`login_submit` docstring calls form parsing an assembly concern and says it
deliberately does not depend on the library — and this assembly never picked
it up.

Two consequences, both outside this ADR's subject:

1. `POST /platform/login` cannot read its form, so no platform browser session
   can be created through the login page at all.
2. A header-less unsafe browser mutation raises instead of returning the 403
   the CSRF contract promises. The header-bridge path (`X-CSRF-Token`, which is
   how every htmx control in this design submits) is unaffected and is what the
   behaviour suite asserts.

Recorded rather than repaired, on purpose. It is a dependency and lockfile
change with its own supply-chain review, it is not an authentication-ownership
question, and folding it into this repair would mean two unrelated decisions
under one commit. It is stated here so nobody reads § 2 as a claim that the
browser surface is end-to-end usable today: this ADR makes the console reachable
BY a valid platform session, and issue 1 above is why obtaining one still needs
its own change.
