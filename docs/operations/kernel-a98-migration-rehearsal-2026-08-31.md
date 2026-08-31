# The a77 → a98 migration rehearsal, on restored production state

2026-08-31. The gate Michael named — *"the a77→a98 upgrade receives its own
migration and compatibility run; do not let Poetry silently choose it without
evidence"* — discharged against a restored isolated copy of `vendor-cp-prod`,
not against production and not by CI's fresh-database run.

**Result: PASS.** `scripts/migrate.py` exited 0.

## What was actually applied

Six revisions advanced across three of the eight composed lineages, plus the
kernel jump, in one run onto populated production data:

```
                       -> dc_0001_deployment_control      (creates mod_deploy)
v016_licensing_authority -> v017_deployment_target_authority
v017                     -> v018_licence_delivery_intents
dc_0001                  -> dc_0002_canonical_plan_digest
0026_platform_audit_log  -> 0027_machine_credential
0027                     -> 0028_machine_attribution
```

Heads before: the four production heads. Heads after: six —
`0028_machine_attribution`, `ap_0002_outbox_relay`,
`dc_0002_canonical_plan_digest`, `ea_0003_platform_audit_log`,
`rl_0001_release_artifacts`, `v018_licence_delivery_intents`.

## Why CI's green migration job was not this evidence

CI applies the chain to an EMPTY database. This applied it to a restored copy
of production — `v016` plus five module schemas plus real rows. The upgrade
path from an existing state is the one that can fail, and it is not the one CI
exercises.

## Three properties verified afterwards

**`mod_deploy` now exists.** The issuer's tables are created by `dc_0001`, and
their absence is why no receipt can be issued today.

**The ADR-0011 seal applies cleanly.** `platform_api` on
`public.licence_delivery_targets` goes from `SELECT, INSERT, UPDATE, DELETE` to
`SELECT, INSERT, UPDATE` — the DELETE revocation lands exactly as `v017`
specifies. The production drift closes with this deploy, as designed.

**Isolation survives and extends to the new schema.** `app_user` holds no
effective `USAGE` on any of the six module schemas including `mod_deploy`;
`platform_api` holds it on all six. Measured with `has_schema_privilege`.

## One rehearsal-fidelity defect, and it is worth keeping

The first run failed:

```
permission denied for database vendor_control_plane
[SQL: CREATE SCHEMA IF NOT EXISTS mod_deploy;]
```

Not a migration defect. In production `app_admin` OWNS the database; in a
restored copy created by `initdb` through `POSTGRES_DB`, `postgres` owns it, so
`app_admin` cannot create a schema. The rehearsal target was wrong, not the
migration.

**This is a gap in the recovery bundle worth naming.** `CatalogEvidence.ownership`
covers schema, table and sequence ownership — not DATABASE ownership. A bundle
can therefore be PROVED while restoring into a database whose owner differs
from the source, and the difference only surfaces the next time a migration
creates a schema. The deploy script already checks it (`OWNER_CONTRACT` must be
`app_admin|app_admin`); the bundle does not.

## Method

Dump plus `pg_dumpall --globals-only --no-role-passwords` from production,
restored into a disposable `postgres:16` container, database owner set to match
production, migrations driven from the workstation over an SSH tunnel using the
exact locked dependency set (Kernel `a98`, Deployment Control `a6`).

Driving from the workstation was deliberate: the host cannot pull the new image
without registry credentials, and streaming a broad personal token onto a
production host to rehearse a migration is a worse trade than tunnelling to a
disposable database. Production was never written to and stayed healthy; the
container, dump, globals and tunnel were all destroyed afterwards.
