# Composition census — Platform CP, measured at `539f0ee`

> ## MEASURED REVISION: `main` at `539f0ee`, on 2026-08-30
>
> Nothing in this document has been re-measured since. `main` has moved on —
> see [Divergence from `main` after the measurement](#divergence-from-main-after-the-measurement)
> at the end — and this census is deliberately NOT updated to match it. A
> census that quietly absorbs later repairs stops being evidence of what was
> true and becomes a claim about what is true now, which is a different
> document and a worse one. Re-measuring is a new census with a new date, not
> an edit to this one.

**This is a census. It is not an adoption claim, and it is not a
production-readiness claim.** It records what is composed, what is reachable,
and what has actually been used, at one revision and one moment.

**Composed does not mean exercised.** A module can be exactly pinned, honestly
declared, correctly migrated, correctly isolated and completely unused. Four of
the five modules installed in production are precisely that, and the census
says so rather than grading generously. Nothing below should be read as
evidence that a capability works in production; where that evidence exists it
is a named row with a timestamp, and where it does not the document says the
absence out loud.

It changes no composition, adopts no module and migrates nothing back into
local code. It replaces nothing: `docs/cutover-readiness.md` remains the
programme record and `src/vendor_cp/cutover_readiness.py` remains the
machine-readable half.

It exists because the adoption claims for the inherited modules rest on
dossiers written once. A claim recorded once is not a claim that still holds —
this programme has already found a published version reporting the wrong
`__version__`, a supersession asserted without a property matrix, and a
monitoring binding recorded UNKNOWN twice. So every row below was read from the
tree at `539f0ee`, from the installed wheels, or from the live database, and
each says where.

## Where the facts came from

| Source | Coordinate |
| --- | --- |
| Repository | `main` at `539f0ee`, this repository — every tree fact below was read with `git show 539f0ee:<path>`, not from a working checkout |
| Module manifests | The published wheels at the locked versions, unpacked and parsed — not a source tree and not the composing assembly's description of them |
| Production host | `149.102.158.144`, `/etc/dotmac-host-id` reads `vendor-cp-prod` — the marker was checked, not the address |
| Database | `vendor_control_plane` in `dotmac_vendor_control_plane-db-1` |
| Running image | `ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:45715e425dc248d85fe374fa5d347087328a445cf7ead1f8abc29f05f0117b0d`, label `org.opencontainers.image.revision` = `af9fcf6d3fbd259fbef6b589d37b39d548f7ba8e` |
| Applied heads | `v016_licensing_authority`, `ap_0002_outbox_relay`, `ea_0003_platform_audit_log`, `rl_0001_release_artifacts` |
| Observed at | 2026-08-30T21:46Z |
| Method | Read-only. Privileges via `has_table_privilege` / `has_schema_privilege` / `has_column_privilege`, never `information_schema.table_privileges` |

Effective privilege, not the direct-grant view, is the whole point of the
method: `information_schema.table_privileges` sees only direct grants, so a role
reaching a table through a membership reads as holding none. Here the role
closure happens to be flat — `pg_auth_members` holds no membership among
`app_admin`, `app_user`, `platform_api`, `outbox_dispatcher` or
`platform_outbox_dispatcher` — but a gate that is right only because the closure
is flat is a gate that fails silently the day someone grants a membership.

## What this assembly composes

`build_spec()` in `src/vendor_cp/assembly.py` composes exactly two kinds of
thing and nothing else: six `ModuleManifest`s that own persistence, and nine
vendor surfaces that own HTTP. `main.py` is `create_app(build_spec())` and holds
no route of its own.

### Six module manifests, 23 platform tables, zero web or API contribution

Six modules are composed, not five. The eight-point audit further down covers
the five that are INSTALLED in production; `dotmac-deployment-control` is
composed on `main` and is not installed on the host at this measurement, so it
has no row there and no schema in the database.

| Module | Contract `version` | Short code | Schema | `tables` | `platform_tables` |
| --- | --- | --- | --- | --- | --- |
| `dotmac-release-catalog` | `0.1.0a4` | `rel` | `mod_rel` | `()` | 2 |
| `dotmac-entitlement-allocation` | `0.1.0a6` | `ealloc` | `mod_ealloc` | `()` | 2 |
| `dotmac-approvals` | `0.1.0a5` | `approvals` | `mod_approvals` | 3, NOT selected | 3 |
| `dotmac-commercial-agreements` | `0.1.0a2` | `agreements` | `mod_agreements` | `()` | 3 |
| `dotmac-licensing` | `0.1.0a1` | `licensing` | `mod_licensing` | `()` | 6 |
| `dotmac-deployment-control` | `0.1.0a2` | `deploy` | `mod_deploy` | `()` | 7 |
| | | | | | **23** |

The 23, named, because a count is not an inventory:

| Schema | Platform tables |
| --- | --- |
| `mod_rel` | `release_artifacts`, `artifact_attestations` |
| `mod_ealloc` | `allocations`, `allocation_entries` |
| `mod_approvals` | `platform_approval_policies`, `platform_approval_requests`, `platform_approval_decisions` |
| `mod_agreements` | `agreements`, `agreement_lines`, `agreement_events` |
| `mod_licensing` | `signing_keys`, `licences`, `licence_issuances`, `licence_acknowledgements`, `revocations`, `revocation_lists` |
| `mod_deploy` | `deployment_targets`, `target_credentials`, `deployment_plans`, `rollouts`, `rollout_attempts`, `observation_receipts`, `observation_attempts` |

Sixteen of the 23 exist in the production database; the seven in `mod_deploy` do
not, because the lineage root has never run there. That is the same pending
deploy recorded in section 1, seen from the schema side.

Two readings the version column invites and both are wrong.
`dotmac-deployment-control`'s manifest `version` is `0.1.0a2` while the pinned
DISTRIBUTION is `0.1.0a6`; the manifest field is the module CONTRACT version and
moves only when the declared surface moves, so the gap is correct and closing it
would make a metadata repair read as a contract change. Conversely, the other
five happen to have contract and distribution versions that agree, and that is
coincidence rather than a rule anything enforces.

**None of the six contributes a route.** Not one declares `routers`,
`web_routers`, `nav`, `api_routers` or `web_surfaces` — the manifests carry
`code`, `version`, `short_code`, migration identity, table declarations,
`requires`/`tenant_requires` and `audit_actions`, and stop there. Every HTTP
route in this deployment is vendor-authored.

That is a real property and not a throwaway one. It means a composed module's
reachability is entirely a fact about vendor code: adopting these six moved
persistence and decisions and moved no surface, so nothing a module does can
make itself reachable. It is the structural reason four modules can be green on
every composition point in this document and still have never run.

### The route dependency graph

44 routes at `539f0ee`, and one dependency on every one of them.

| Surface | Manifest kind | Mount | Routes | Guard | DB dep | Reaches |
| --- | --- | --- | --- | --- | --- | --- |
| `console` | `ModuleManifest`, contract v2 | facet `platform_admin` → `/platform` | 1 (`GET /console`) | `require_platform_admin` | none | nothing — an inline HTML constant |
| `accounts` | `FeatureManifest` | `/platform/vendor/accounts` | 3 | `require_platform_admin` | `get_platform_db` ×3 | `public.vendor_accounts`, Vendor-local |
| `offers` | `FeatureManifest` | `/platform/vendor/offer-versions` | 3 | `require_platform_admin` | ×3 | `public.offer_versions`, Vendor-local |
| `vendor_approvals` | `FeatureManifest` | `/platform/vendor/approvals` | 3 | `require_platform_admin` | ×3 | `approvals/adapter.py` → `dotmac_approvals` → `mod_approvals` |
| `contracts` | `FeatureManifest` | `/platform/vendor/contracts` | 10 | `require_platform_admin` | ×10 | `contracts/adapter.py` → `dotmac_commercial_agreements` → `mod_agreements` |
| `allocations` | `FeatureManifest` | `/platform/vendor/allocations` | 1 | `require_platform_admin` | ×1 | `allocations/adapter.py` → `dotmac_entitlement_allocation` → `mod_ealloc`, READ only |
| `licence_delivery` | `FeatureManifest` | `/platform/vendor/licences` | 19 | `require_platform_admin` | ×18 | `licensing/adapter.py` → `dotmac_licensing` → `mod_licensing`, plus Vendor's own delivery projection |
| `provisioning` | `FeatureManifest` | `/platform/vendor/provisioning` | 4 | `require_platform_admin` | none | the fake provider laboratory; no persistence at all |
| `release_evidence` | `FeatureManifest` | — | 0 | — | — | declarations only: one audit action |

Three things the graph is for.

**The guard is uniform, and it is one guard.** All 43 JSON routes take
`Annotated[PlatformAdmin, Depends(require_platform_admin)]`, through a line
each of the seven routers declares for itself, character-for-character
identical in all seven; the single web route takes
`Depends(require_platform_admin)` directly. A sweep of every `@router.*`
handler at `539f0ee` finds zero without it. There is no second authentication
path and no route-local re-implementation.

That uniformity is exactly why `public.platform_admins` holding zero rows is
sufficient on its own to make four modules unreachable, as section 6 records.
The finding is not "most routes are guarded so most things are unreachable" —
it is that there is a single admission point and nobody can pass it.

**Two composed modules have no route at all.** `dotmac-release-catalog` is
reached only from `scripts/catalogue_product_release.py` →
`vendor_cp.release_evidence.service.ingest_product_release_evidence`, and
`dotmac-deployment-control` only through `vendor_cp.deployment.adapter`, whose
one in-tree consumer is `vendor_cp.licensing.projection`. So the single module
with a real production act is the one with no HTTP surface, and the module with
the largest surface — licensing, 19 routes — has written nothing. Route count
is not a proxy for use, in either direction.

**Nineteen of the 44 routes belong to one feature.** `licence_delivery` is 43%
of the surface, and it is one of the two features production withholds.

### Profile-to-surface matrix

Two profiles are declared, four surfaces are withholdable, and one profile
withholds anything. `WITHHOLDABLE_SURFACES` is
`{licence_delivery, offers, provisioning, console}`; a profile naming anything
else fails `VendorDeploymentProfile.__post_init__`, which is the mechanism that
stops a profile dropping a persistence owner.

| Surface | Routes | `full` (v1) | `production-bootstrap` (v2) |
| --- | --- | --- | --- |
| `console` | 1 | exposed | exposed |
| `accounts` | 3 | exposed | exposed — not withholdable |
| `offers` | 3 | exposed | **withheld** |
| `vendor_approvals` | 3 | exposed | exposed — not withholdable |
| `contracts` | 10 | exposed | exposed — not withholdable |
| `allocations` | 1 | exposed | exposed — not withholdable |
| `licence_delivery` | 19 | exposed | **withheld** |
| `provisioning` | 4 | exposed | exposed |
| `release_evidence` | 0 | no surface | no surface |
| **Routes mounted** | **44** | **44** | **22** |

Production runs `production-bootstrap`, so exactly half the route surface is not
mounted there — the 19 licensing routes plus the 3 offer routes.
`_profiled_surface` clears `routers`/`web_routers`/`nav` on a `FeatureManifest`
and `api_routers`/`web_surfaces` on a `ModuleManifest`, leaving every
declaration installed. The profile is read once, in `build_spec()`, and nothing
downstream reads it; an unknown profile code fails closed rather than falling
back to `full`.

Two things the matrix does not say, and both matter for reading the rest of this
document.

A withheld surface is not a disabled subsystem. `install_runtime_licence_signers`
still runs at boot under `production-bootstrap`, so licensing key custody is
loaded, in memory, in a deployment where no licensing route exists. And
withholding a route never moves ownership: Vendor owns the delivery projection
and the product-held signing keys whether or not `/platform/vendor/licences`
answers.

A profile also cannot explain the empty tables on its own. It withholds two of
the nine surfaces; `vendor_approvals`, `contracts` and `allocations` are mounted
in production and their schemas are still empty. The profile is the second of
section 6's three reasons, and it covers licensing only.

### Package, template, static and stylesheet inventory

| Kind | At `539f0ee` | Detail |
| --- | --- | --- |
| Python distributions built here | 1 | `dotmac-vendor-control-plane`, `packages = [{ include = "vendor_cp", from = "src" }]` |
| Import packages | 1 | `vendor_cp` |
| Sub-packages under `vendor_cp` | 11 | `accounts`, `allocations`, `approvals`, `commercial_backfill`, `console`, `contracts`, `deployment`, `licensing`, `offers`, `provisioning`, `release_evidence` |
| Python files under `src/` | 82 | |
| Jinja or HTML template files | **0** | |
| Packaged template directories | **0** | no `packaged_template_dirs` declaration anywhere |
| Static asset directories | **0** | no `packaged_static_dirs`, no `StaticFiles` mount |
| Stylesheets | **0** | no `.css` in the tree, no `stylesheets` declaration |
| JavaScript files | **0** | |
| `dotmac-ui` | **absent** | not a dependency, not imported |
| Template engine in the request path | **none** | no `Jinja2Templates` |

The entire HTML surface of this deployment is a seven-line string constant,
`_SHELL` in `src/vendor_cp/console/web.py`, returned by one route to one
authenticated platform admin. There is no design system, no build step, no asset
pipeline and no npm.

This is recorded because it bounds a class of risk to zero rather than leaving
it unexamined. The template-escaping rule, the `| safe` guard, the CSRF
transport contract and the compiled-stylesheet drift check all have EMPTY
subject sets here. They are not passing — there is nothing for them to be about.
The distinction is the same one this census makes everywhere else: an absence of
subject is not a clean result, and the day a real console screen lands, all four
acquire one at once.

### Two reader shapes worth naming

**`accounts` and `offers` list raw and unbounded.**
`vendor_cp.accounts.service.list_accounts` is
`select(VendorAccount).order_by(VendorAccount.created_at)` — no `limit`, no
`offset`, no cursor — and `GET /platform/vendor/accounts` returns
`list[AccountResponse]`: the whole table, every call.
`vendor_cp.offers.service.list_offer_versions` has the same shape, narrowed by a
`product_code`/`offer_code` filter and ordered by `version`, again with no bound.

Both read Vendor-local tables in `public`, both of which held zero rows at the
measurement, and neither route is reachable today because no platform admin
exists — and `offers` is withheld in production besides. So this is a recorded
shape, not an incident. It is what these endpoints will do on the first day they
have both an operator and data, and an empty estate is the only reason it has
not mattered.

**Commercial Agreements has a cursor reader and no HTTP route that uses it.**
`dotmac_commercial_agreements.service.list_agreements` is a proper keyset
reader: ordered by the stable total key `Agreement.id`, an `after` cursor,
`limit` validated into `1..200` (`MAX_AGREEMENT_PAGE_SIZE`, with `bool`
explicitly rejected as an `int`), and a `limit + 1` probe that distinguishes a
full final page from one that really has a successor without a count query.
Views and promised lines are materialized before return, so no ORM row or lazy
loader crosses the module boundary. `vendor_cp.contracts.adapter` re-exports it
as `list_agreements`.

`vendor_cp/contracts/router.py` publishes ten POSTs and exactly one GET, and
that GET is `/{agreement_id}`. **There is no list route.** The cursor reader's
only in-tree caller is not HTTP at all:
`vendor_cp.commercial_backfill.enumeration`, which walks the estate in pages
for the shadow comparison.

Hold the two halves together. The best-bounded reader in this repository is the
one with no public surface; the two unbounded ones are the two that are
published. Which way round that landed says something about how surface was
added here — per feature, at the time each feature was written, rather than
against a reader policy — and noticing it is a census's job. Fixing it is not:
nothing here proposes a change, and the unbounded readers are recorded as they
are.

## The eight points, per module

The five INSTALLED in production. `dotmac-deployment-control` is composed and
not installed here, so it is absent by fact rather than by omission — there is
nothing on the host to audit.

`RC` release catalogue · `EA` entitlement allocation · `AP` approvals ·
`CA` commercial agreements · `LI` licensing.

| # | Point | RC | EA | AP | CA | LI |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Exact installed distribution and artifact digest | PASS | PASS | PASS | **DRIFT** | PASS |
| 2 | Platform plane DECLARED, never inferred | PASS | PASS | PASS | PASS | PASS |
| 3 | Migrations supplied by the installed package via public `versions_dir()` | PASS | PASS | PASS | PASS | PASS |
| 4 | No copied migration surviving in the assembly | PASS | PASS | PASS | PASS | PASS |
| 5 | Correct effective privileges, zero `app_user` access | PASS | PASS | PASS | PASS | PASS |
| 6 | One real reader and one real writer | PASS | **FAIL** | **FAIL** | **FAIL** | **FAIL** |
| 7 | No surviving local owner | PASS | PASS | PASS | PASS | PARTIAL |
| 8 | Schema covered by the recovery descriptor | PASS | PASS | PASS | PASS | PASS |

### 1 — Installed distribution and artifact digest

From `poetry.lock` and from the wheels themselves, not from the `pyproject.toml`
constraint. Every cached wheel's SHA-256 equals the lockfile hash, and for the
four whose version matches, the installed `RECORD` in the production container
is byte-identical to the published wheel's `RECORD`, so the running bytes ARE
the published bytes.

| Distribution | Locked on `main` | Wheel SHA-256 | Installed in production |
| --- | --- | --- | --- |
| `dotmac-release-catalog` | `0.1.0a4` | `401cf95a…5e00dd8` | `0.1.0a4` |
| `dotmac-entitlement-allocation` | `0.1.0a6` | `bf2db1e9…f4aa909590e7` | `0.1.0a6` |
| `dotmac-approvals` | `0.1.0a5` | `26beac36…78f83a` | `0.1.0a5` |
| `dotmac-commercial-agreements` | `0.1.0a2` | `303195fc…0bb66a86` | **`0.1.0a1`** |
| `dotmac-licensing` | `0.1.0a1` | `a1e9a7c4…04fd3ceb` | `0.1.0a1` |
| `dotmac-kernel` | `0.1.0a98` | `27405c57…c1d0859fa` | **`0.1.0a77`** |
| `dotmac-deployment-control` | `0.1.0a6` | `9b02cf33…f117b8fc0` | **not installed** |

The three drifts are one fact, not three: production runs the image built at
`af9fcf6d`, and `main` has moved past it. The pending deploy carries all of
them. Recorded so nobody reads the lockfile as a statement about production.

Declared kernel floors, read out of the published wheel metadata rather than a
source tree: RC `>=0.1.0a56`, EA `>=0.1.0a68`, AP `>=0.1.0a67`, CA
`>=0.1.0a77`, LI `>=0.1.0a77`. Every one is satisfied by both the pinned a98 and
the running a77. **None of the five carries a minimum-floor canary** of the kind
`dotmac-deployment-control` a6 acquired after a5's declared floor turned out to
be wrong — resolution succeeded, the lock wrote cleanly, the hashes matched, and
the container died at boot. The floors above are declarations, not contracts,
and this census does not upgrade them by repeating them.

### 2 — The platform plane is declared

`dotmac-approvals` is the one SELECTABLE module composed here, and
`ASSEMBLY_MODULE_PLANES` in `src/vendor_cp/migration_bindings.py` selects
`ModulePlane.PLATFORM` explicitly. The database agrees: `mod_approvals` holds
`platform_approval_policies`, `platform_approval_requests` and
`platform_approval_decisions`, and no tenant-plane approval table exists.

The other four are ATOMIC. Their manifests declare `tables=()` and a populated
`platform_tables`, which is the ADR-0023 declaration; a `ModulePlaneSelection`
is not merely unnecessary for them, it is refused, because
`validate_module_plane_selections` rejects a selection for a module supporting
one plane set. So "explicit `ModulePlaneSelection.PLATFORM`" is satisfied for
approvals by the selection and for the other four by the manifest declaration —
in neither case by the absence of a `tenant_id` column.

All sixteen tables the five manifests declare exist, and nothing else does:

| Schema | Tables |
| --- | --- |
| `mod_rel` | `release_artifacts`, `artifact_attestations` |
| `mod_ealloc` | `allocations`, `allocation_entries` |
| `mod_approvals` | `platform_approval_policies`, `platform_approval_requests`, `platform_approval_decisions` |
| `mod_agreements` | `agreements`, `agreement_lines`, `agreement_events` |
| `mod_licensing` | `signing_keys`, `licences`, `licence_issuances`, `licence_acknowledgements`, `revocations`, `revocation_lists` |

### 3 — Composed from the installed package

`composed_version_locations()` evaluated inside the running container resolves
every module path into
`/opt/venv/lib/python3.12/site-packages/<package>/migrations/versions`, with
only the vendor path at `/app/alembic/versions`.
Nothing is a repository path, a copy or an import-path shim.

One inconsistency, cosmetic: `src/vendor_cp/migrations.py` imports approvals'
locator as `from dotmac_approvals.migrations import versions_dir` while the
other four use the top-level re-export. Both are public — the package docstring
names `migrations` as public surface and `__init__` re-exports `versions_dir` —
so this is style, not a boundary crossing.

### 4 — Nothing copied

No revision in `alembic/versions` creates a table in a module schema. `v012`,
`v013` and `v014` name `mod_approvals` and `mod_ealloc` only to issue and verify
grants. The `create_table` calls in `v003`, `v004`, `v005`, `v006` and `v008`
built the LOCAL predecessors in `public`, and `v013`–`v016` dropped them; the
database confirms all twelve are gone.

### 5 — Effective privileges

Measured on all sixteen tables, for all five roles, across `SELECT`, `INSERT`,
`UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES` and `TRIGGER`, plus schema `USAGE`
and `CREATE`, plus every column.

`app_user` holds **nothing**: no schema `USAGE` on any of the five module
schemas, no table privilege of any kind, and no column privilege of any kind.
The revocation IS the isolation on this plane, and it is intact.

`platform_api` holds schema `USAGE` on all five and, per table:

| Schema | Privileges held by `platform_api` |
| --- | --- |
| `mod_rel` | `SELECT`, `INSERT` on both |
| `mod_ealloc` | `SELECT`, `INSERT` on both; `UPDATE` on `allocations` restricted to columns `sealed` and `updated_at` |
| `mod_approvals` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on all three |
| `mod_agreements` | `SELECT`, `INSERT` on all three; `UPDATE` on `agreements` |
| `mod_licensing` | `SELECT`, `INSERT` on all six; `UPDATE` on `signing_keys` and `licence_issuances` |

Every one matches what its authority revision issues. The `mod_ealloc` column
grant is the case a table-level check would misread in the permissive direction
had it been written the other way round: `has_table_privilege(…,'UPDATE')` is
false there while `has_column_privilege` is true for exactly two columns.

Neither dispatcher role reaches any module schema.

### 6 — A real reader and a real writer

This is where four of the five fail, and the failure is not about code.

**`dotmac-release-catalog` passes.** `mod_rel.release_artifacts` holds artifact
`9094efe1-7cab-4fc7-a2f6-c1787e452e14` and `mod_rel.artifact_attestations` holds
attestation `db269812-d99b-4529-9270-9435a8249124` against it, both written
2026-08-17T09:23:04Z, with the matching `platform_idempotency_records` row
(`vendor.release_evidence.ingest` / `vendor.release_evidence.catalogue`) and the
single `platform_audit_events` row (`vendor.release_evidence.catalogued`). The
writer is the operator entry point `scripts/catalogue_product_release.py` →
`vendor_cp.release_evidence.service.ingest_product_release_evidence`; the reader
is `vendor_cp.offers.catalog.configured_product_capability_catalogues`. A real
production act, verifiable against the row.

**The other four have written nothing, ever.** Every table in `mod_ealloc`,
`mod_approvals`, `mod_agreements` and `mod_licensing` holds zero rows, and so do
`public.platform_outbox_events`, `public.offer_versions` and
`public.vendor_accounts`. `platform_audit_events` holds one row, and it is the
release-catalogue one.

Three independent reasons, each sufficient on its own:

1. **No operator identity exists.** `public.platform_admins` holds zero rows.
   Every route that reaches these modules carries `require_platform_admin`, so
   no authenticated caller can reach any of them. This is ADR-0013's subject.
2. **Licensing's surface is withheld.** Production runs
   `VENDOR_DEPLOYMENT_PROFILE=production-bootstrap`, which withholds the
   `licence_delivery` and `offers` routers. No licensing route is mounted at
   all, so licensing has neither a reachable reader nor a reachable writer in
   the running deployment — independently of the admin problem.
3. **Allocation staging has no invoker.** `stage_allocation` is the only writer
   for `dotmac-entitlement-allocation`, and it is reached only from
   `vendor_cp.allocations.consumer.ContractEventConsumer`. That class is
   constructed **nowhere under `src/`** — only in tests — and neither
   `FeatureManifest` nor `ModuleManifest` has a field that would register a
   platform transport. No relay or dispatcher process runs in production
   either: `docker-compose.production.yml` defines `db`, `manifest-init`, `app`
   and an `ops` service whose command is `python --version`, and the host has no
   cron entry or systemd timer that would drain the platform outbox. So the
   chain contract-activation → outbox → consumer → staged allocation is broken
   at two places at once, and would remain broken after an operator existed.

Green tables with no production act are not adoption. Four of these five are
composed, correctly isolated, correctly declared and correctly migrated, and
none of them has been used.

### 7 — No surviving local owner

All twelve displaced local tables are gone from production:
`approval_policies`, `approval_records`, `contracts`, `contract_lines`,
`allocations`, `allocation_entries`, `licences`, `licence_versions`,
`licence_issuances`, `licence_revocations`, `revocation_lists`, `signing_keys`.
No `__tablename__` under `src/` declares any of them, and
`vendor_cp/allocations/`, `vendor_cp/approvals/` and `vendor_cp/contracts/` hold
no `models.py` at all.

Licensing is PARTIAL by design rather than by omission: the ISSUER is retired,
while the delivery projection (`licence_deliveries`, `licence_delivery_states`,
`licence_delivery_targets`, `licence_delivery_attempts`, `licence_ack_records`)
and product-held key custody remain Vendor's, and ADR-0010 owns their
retirement. All five delivery tables hold zero rows.

`public.offer_versions` and `public.vendor_accounts` also survive, and neither
belongs to these five. `offer_versions` and its `product_code` column, added by
`v011`, are what `dotmac-subscriptions` adoption has to retire.

### 8 — Recovery-descriptor coverage

`deploy/product.toml` lists all five module schemas in
`database.expected_schemas`, and its `database.isolation` block names all five
for both directions — `app_user` denied schema `USAGE`, `platform_api` granted
it — checked with `has_table_privilege` / `has_schema_privilege` semantics.
`migration.expected_heads` matches the four applied heads exactly.

Coverage is at SCHEMA granularity. Revoking `USAGE` does make every object in a
schema unreachable regardless of table grants, so the denial half is sound and
does not go stale when a module adds a table; but the descriptor asserts no
table- or column-level privilege, so it would not notice `platform_api` gaining
`DELETE` inside a schema it is supposed to reach.

## The gate item that fails for all five

Coverage is not restoration. `docs/operations/backup-restore-rehearsal-2026-08-30.md`
records that the production backup does not restore: `pg_dump` of one database
never emits role definitions, so a restore produces a database with no
`app_admin`, no `app_user` and no `platform_api`, every object owned by whoever
ran the restore, and every `GRANT` and `REVOKE` discarded.

For these five modules that is total: their isolation is the grant/revoke matrix
on the platform role, so a recovery that drops the role layer drops their plane
separation entirely, while `pg_policies` still lists policies and looks fine.
**No module here currently satisfies "RecoveryBundle restores it correctly."**
It is one defect in the backup command, not five defects in five modules, and
its repair belongs to the recovery work already under way.

## What no module here has

Stated once rather than repeated in each row, because it is the same absence
five times: no shadow comparison against a live predecessor (the estates were
measured empty, which is why the switches were greenfield), no Observability
binding confirming the new owner, and no production act to confirm for four of
the five. The `EXTRACTION.toml` dossiers say as much when read closely — four of
them carry a `live_observation` whose subject is a MIGRATION applied by a deploy
run, described in the dossier itself as "an attestation and not an assertion".
Only release catalogue's names a row, and that row exists.

One dossier defect worth fixing at the source: release catalogue's
`live_observation` names subject `mod_relcat`. The schema is `mod_rel`.

## Divergence from `main` after the measurement

A dated observation, appended rather than folded in. Nothing above was edited to
match anything in this section.

Between `539f0ee` and this document merging, `main` acquired `81d324a`,
`e8d5b54`, `b934562`, `93b75e1`, `b1a1d35` and `d2bc501`: the first PROVED
Platform CP recovery bundle, the a77→a98 migration gate discharged against
restored production state, an ADR-0013 amendment for an in-place bootstrap with
a create-only launcher (`scripts/bootstrap/bootstrap_once.sh`), and three
repairs to that launcher.

**Nothing under `src/` moved.** So the six manifests, the 23 platform tables,
the route dependency graph, the profile-to-surface matrix, the asset inventory
and both reader shapes above are byte-identical on `main` today; those sections
diverge from current `main` in no respect.

The database findings are the other matter, and this is the divergence that must
not be quietly resolved. Section 6's first reason — `public.platform_admins`
holds zero rows, so no authenticated caller can reach four of these modules — is
a measurement taken at 2026-08-30T21:46Z, and `bootstrap_once.sh` exists to
change exactly that. This census is NOT re-measured against it, and the row
stays as written.

Two reasons for keeping it rather than updating it. First, it is what was true:
a document that silently acquires the fix reads as though the fix were always
there, which destroys its value as a before-picture for the very repair it
motivated. Second, the finding never rested on that reason alone. Licensing's
surface is withheld by profile, and `ContractEventConsumer` is constructed
nowhere under `src/` — each is independently sufficient, and neither is touched
by an operator existing. An operator identity being created would move reason 1
into the past tense and leave the conclusion standing.

Section 1's three drifts are the same shape. They describe the image running on
2026-08-30 against the lockfile on `539f0ee`; a later deploy does not make them
wrong, it makes them historical. Read them with the measured revision attached,
which is why it is at the top of this file in the largest type it has.

The correct successor to this document is another census, with its own revision
and its own date. It is not an edit to this one.
