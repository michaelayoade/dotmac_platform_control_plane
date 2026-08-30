# PROVED — the first Platform CP recovery bundle

2026-08-30. `PostgresRecoveryBundleV1`, captured from the host whose
`/etc/dotmac-host-id` reads `vendor-cp-prod`, restored into a disposable
`--network none` PostgreSQL 16 container, verified by the facility, and the
target destroyed. Production was never written to and stayed healthy.

- **Receipt** `sha256:6b1fd6fafe0a7b96c0d4deeabbc4986389029fc7247315282608e2c93c2a1c37`
  — `docs/operations/recovery-receipt-2026-08-30.json`
- **Bundle** `sha256:f282bbc900d52e06297569687cface987c247c0ed63deac96a08d10ed8b71246`
- **Dump component** `sha256:635e25b6752b6789272c1aa2a15999c72b64c430dcf5f16c91a7e6fa74cfc48a`
- `proved: true`, findings `0`, roles restored `5`, restore `4s`

## The contrast with the same backup two runs earlier

The identical artefact, restored WITHOUT cluster globals, produced 114
missing-role errors and a database that looked recovered — 45 tables, 23 of 26
policies, 16 RLS-enabled tables, no roles, no grants, everything owned by the
restoring superuser. With globals restored first, `pg_restore` exits 0 with
zero errors.

The bytes never changed. The procedure did.

## What was compared

`verify_recovery` compared source and restored catalogues across roles,
memberships, ownership, direct privileges, **effective** privileges, function
security, default privileges, policies, RLS enable/force, extensions, schemas
and migration heads — plus the three isolation invariants
`deploy/product.toml` declares. Zero findings.

## The comparison is not vacuous, and here is the proof

Seven planted defects, each in the restored evidence, each reported:

| planted defect | findings |
| --- | --- |
| drop the `platform_api` role | 1 |
| flip `app_admin` INHERIT off | 1 |
| give `app_user` `bypassrls` | 1 |
| un-force RLS on every table | 17 |
| hand `app_user` USAGE on `mod_approvals` | 1 |
| reassign every object to `postgres` | 54 |
| drop one migration head | 1 |

The fifth is the descriptor's own invariant firing:
`RESTORE DEFECT - app-user-cannot-reach-platform-schemas`.

## Readiness, and the test that was worthless first

Readiness was proved from real authenticated sessions against the restored
database, with **ephemeral** credentials created in the isolated target. No
production secret was used, and the globals were captured with
`--no-role-passwords`, so no verifier ever left the source.

| check | result |
| --- | --- |
| `platform_api` authenticates | yes |
| `app_user` authenticates | yes |
| **wrong credential** | **refused** |
| `platform_api` reads `mod_approvals.platform_approval_requests` | 0 rows — works |
| `app_user` reads the same table | `ERROR: permission denied for schema mod_approvals` |
| `app_user` reads `public.audit_events` | 0 rows — works |

**The first run of that table was meaningless and said so.** The `postgres`
image ships `pg_hba.conf` with `host all all 127.0.0.1/32 trust`, so every
loopback connection succeeded regardless of password — including the
deliberately wrong one. A wrong-credential test on a trust-authenticated
container proves nothing whatsoever. The target's loopback rules were switched
to `scram-sha-256` (keeping `local` as trust so the admin socket still works)
and the run repeated. Only then did the refusal mean anything.

Both halves are checked on purpose. A role revoked from everything passes every
"cannot reach" assertion and cannot run the product.

## Where the capture lives, and why here

`scripts/recovery/capture_catalog.sql` and `scripts/recovery/build_bundle.py`.

The facility owns the fact types, the role closure, the completeness refusals
and the comparison — and **connects to nothing**. A validator able to read the
database it validates can always make its own check pass. So the SQL that fills
the evidence is the product's, and it is the only part of this that is ours.

## Two capture defects the facility caught before they mattered

Both were mine, and both were refused at build time rather than discovered
during an incident:

1. **`pg_get_userbyid(0)` does not return NULL.** Grantee OID 0 is the `PUBLIC`
   pseudo-role, and that function returns the string `unknown (OID=0)`, so the
   `COALESCE(..., 'PUBLIC')` never fired and a fabricated role name reached the
   closure. The bundle refused it as an undefined role — the same refusal that
   catches a genuinely missing role.
2. **`pg_policies` renders `PUBLIC` lowercase.** A policy naming no role names
   `public`, which is not a real role and is not the bundle's spelling.

Both now normalise to `PUBLIC`, which `derive_role_closure` records as
built-in-referenced rather than required.

## One exclusion, printed rather than silent

`postgres` is excluded from the bundle: `RoleFact` refuses a SUPERUSER, because
restoring one turns possession of the artefact into possession of the cluster.
The driver prints every excluded role, so a PRODUCT role that had wrongly
become superuser appears as a finding instead of quietly vanishing from the
bundle at the moment it most needs reporting.
