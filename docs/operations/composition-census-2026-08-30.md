# Composition census — the five inherited modules, re-measured

**Taken 2026-08-30 against `main` at `539f0ee` and against production.** This
changes no composition, adopts no module and migrates nothing back into local
code. It is evidence, and it replaces nothing: `docs/cutover-readiness.md`
remains the programme record and `src/vendor_cp/cutover_readiness.py` remains
the machine-readable half.

It exists because the adoption claims for these five rest on dossiers written
once. A claim recorded once is not a claim that still holds — this programme has
already found a published version reporting the wrong `__version__`, a
supersession asserted without a property matrix, and a monitoring binding
recorded UNKNOWN twice. So every row below was read from the current tree, the
installed wheels, or the live database, and each says where.

## Where the facts came from

| Source | Coordinate |
| --- | --- |
| Repository | `main` at `539f0ee`, this repository |
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

## The eight points, per module

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
every module path into `/opt/venv/lib/python3.12/site-packages/<package>/
migrations/versions`, with only the vendor path at `/app/alembic/versions`.
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
