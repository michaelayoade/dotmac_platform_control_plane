# The production backup does not restore

Rehearsed 2026-08-30 against the newest backup on the production host, in a
disposable network-isolated PostgreSQL 16 container that was destroyed
afterwards. The production stack was not touched and stayed healthy throughout.

**Verdict: the backup/restore gate FAILS.** This is the state Deployment
Control's own gate exists to prevent, found in this assembly's own production
backups.

## What was rehearsed

- Artifact: `/opt/backups/dotmac-vendor-control-plane/vendor-control-plane-20260821T131407Z.dump`,
  156,667 bytes, the most recent of six.
- Target: a throwaway `postgres:16` container started with `--network none` and
  removed on completion.
- Command: a plain `pg_restore` into an empty database, which is what a
  disaster recovery would actually run.

## Result

`pg_restore` exited **1** with **114 errors**, every one of them a missing role:

| role | errors |
| --- | --- |
| `app_admin` | 56 |
| `platform_api` | 34 |
| `app_user` | 20 |
| `outbox_dispatcher` | 2 |
| `platform_outbox_dispatcher` | 2 |

## The cause is one flag

`scripts/deploy_production.sh:72`:

```
exec pg_dump --username app_admin --dbname "$POSTGRES_DB" --format custom
```

`pg_dump` of a single database captures object-level `GRANT`s and RLS policies
but **never role definitions** — those live in the cluster, and only
`pg_dumpall --globals-only` (or a full `pg_dumpall`) emits them. The dump's own
table of contents shows the asymmetry plainly: **55 ACL entries and 26 POLICY
entries, and zero role objects.** Eighty-one security-relevant entries naming
five principals the backup does not carry.

## Why this is worse than a backup that fails outright

The restore does not stop. It leaves a database that **looks** restored:

- 45 user tables present
- 23 of 26 RLS policies present
- 16 tables with row-level security enabled

and, underneath that, no `app_user`, no `platform_api`, no `app_admin`, every
object owned by whoever ran the restore, and every `GRANT` and `REVOKE`
discarded. An operator checking `pg_policies` after a recovery would see
policies and conclude the isolation model came back.

It did not. This assembly's tenant/platform separation is not the policies
alone — it is the policies **plus** the `platform_api` grant/revoke matrix
(`dotmac_starter_mt` ADR-0023, `AGENTS.md` rule 24), where the revocation IS the isolation. A
restore that silently drops the role layer produces a control-plane database
with no plane separation at all, and the application cannot start against it
anyway, because the roles it connects as do not exist.

So the failure mode is: recovery appears to succeed, isolation is gone, and
nothing says so.

## What has to change before the gate can pass

1. Capture cluster globals alongside the database dump — `pg_dumpall
   --globals-only` — and treat the pair as one artifact. Role passwords are
   part of that output, so it inherits the dump's handling and must never be
   world-readable.
2. Make restore rehearsal a routine that runs, not a procedure that is written
   down. This rehearsal is the first evidence either way, and the backups have
   existed since 2026-08-17.
3. Assert the recovered SECURITY state, not the row counts: roles exist, the
   `platform_api` revocations are in place, RLS is forced, ownership is
   `app_admin`. A restore check that counts tables passes in exactly the case
   documented above.

Until then, **no production authorization should be admitted on the strength of
these backups**, because the recovery path they imply does not exist.
