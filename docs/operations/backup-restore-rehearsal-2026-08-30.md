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

**Item 1 is implemented, and as a bundle rather than a second file.**
`scripts/deploy_production.sh` no longer produces a backup FILE. It assembles a
recovery bundle in a hidden temporary directory, validates it in full, and moves
it into place with one `mv` — `rename(2)` within one filesystem, so a reader
either sees a complete bundle or sees nothing:

```
/opt/backups/dotmac-vendor-control-plane/bundle-<timestamp>/
    database.dump      pg_dump --format custom, ownership and grants INTACT
    globals.sql        pg_dumpall --globals-only --no-role-passwords
    manifest.json      PlatformCpRecoveryBundle.v1
    SHA256SUMS         both components
```

Globals are captured through the **container-local PostgreSQL superuser** over
the unix socket. `app_admin` is `NOSUPERUSER` by contract and owns one database;
a cluster dump is not its authority. No password is needed or retained, because
this cluster deliberately has none for `postgres`.

The deploy **refuses to migrate** unless the published bundle is complete and
`sha256sum --check` passes on it. A rollback discovered to be absent after the
schema has advanced is not a rollback.

Four validations run before the bundle is accepted, each one a way the pair can
be present and useless: `pg_restore --list` must parse the archive; the globals
must `CREATE ROLE` all five declared roles by name; **no SCRAM or MD5 verifier
may appear** — `--no-role-passwords` is a flag and a flag can be dropped; and
the cluster's own facts (PostgreSQL major, system identifier, database name,
migration heads) are measured rather than declared. The image's source revision
is read off its OCI label rather than accepted as an argument.

`--no-role-passwords` is the configuration that was actually PROVED
(`recovery-proved-2026-08-30.md`: same artefact, globals captured that way,
`pg_restore` exit 0, zero findings). The consequence is stated rather than left
to be discovered: **a restored cluster has the five roles with NULL passwords**,
and the operator resupplies them from OpenBao before the application connects.
That step is in the restore order below.

`deploy/product.toml` now declares the widened verification set —
`schema, row_counts, migration_heads, roles, ownership, memberships,
effective_privileges` — promoted as a new candidate through the ledger rather
than edited in place. The old three are satisfied by exactly the database this
rehearsal produced: 45 tables, correct row counts, correct heads, and no
isolation model at all.

### Restore order

1. a fresh PostgreSQL 16 cluster;
2. `globals.sql` as the local superuser;
3. create the database owned by `app_admin`;
4. `database.dump`;
5. resupply role passwords from OpenBao;
6. check schema, rows, heads, roles, ownership, memberships and **effective**
   privileges — `information_schema` sees only direct grants, so a role reaching
   an object through a membership reads as having none.

**Item 2 is NOT implemented.** Restore rehearsal is still a procedure that is
written down rather than a routine that runs. No rehearsal has been performed
against a bundle produced by the changed script — the change is
repository-local, and the only evidence that would discharge it is a restore
from this host.

**Item 3 is NOT implemented.** Nothing asserts the recovered SECURITY state
after a restore. The Foundation's `verify_recovery` does exactly that and was
the instrument on 2026-08-30, but it is not wired into this deploy path, and the
verification set the descriptor now declares is a DECLARATION with no consumer
installed here.

So the sentence above — *"no production authorization should be admitted on the
strength of these backups"* — is narrowed rather than lifted. What is fixed is
that the artifact now contains the role layer and cannot be half-written. That a
restore of it succeeds remains unproved, and only a rehearsal against a real
bundle can say so.
