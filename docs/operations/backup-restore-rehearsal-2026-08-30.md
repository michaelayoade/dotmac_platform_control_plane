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

---

## Disposition, 2026-09-01 — item 1 is implemented; items 2 and 3 are not

**Nothing above is edited.** The rehearsal stands as what was measured on
2026-08-30, and this section states what has changed since. A record quietly
rewritten to read as though it always said the right thing teaches nobody what
the mistake was.

**Item 1 is implemented.** `scripts/deploy_production.sh` now captures
`pg_dumpall --globals-only --no-role-passwords` alongside the custom-format
dump, as `vendor-control-plane-<timestamp>.globals.sql` beside
`vendor-control-plane-<timestamp>.dump`. The two share one timestamp and are
published together: both are written to `.tmp` and moved only once the globals
capture has been checked to create all five roles by name. A globals file
carrying only tablespaces — the shape that produces 114 errors while looking
like a capture — fails the deploy at that point, before the migration and
before the application is replaced.

`--no-role-passwords` is chosen because it is the configuration that was
actually PROVED (`recovery-proved-2026-08-30.md`: same artefact, globals
captured that way, `pg_restore` exit 0, zero findings). It also needs no
superuser, which this cluster deliberately has no password for, and it keeps
every SCRAM verifier out of a file at rest on the host. The consequence is
explicit: a restored cluster has the five roles with no passwords, so an
operator restoring for real sets them from the host's own `.env` or from
OpenBao before the application can connect.

**Item 2 is NOT implemented.** Restore rehearsal is still a procedure that is
written down rather than a routine that runs. No rehearsal has been performed
against a pair produced by the changed script — the change is repository-local
and the only evidence that would discharge it is a restore from this host.

**Item 3 is NOT implemented.** Nothing asserts the recovered SECURITY state
after a restore. The facility's `verify_recovery` does exactly that and was the
instrument on 2026-08-30, but it is not wired into this deploy path.

So the sentence above — *"no production authorization should be admitted on the
strength of these backups"* — is narrowed rather than lifted. What is fixed is
that the artifact now CONTAINS the role layer. What remains unproved is that a
restore of it succeeds, and only a rehearsal against a real pair can say so.
