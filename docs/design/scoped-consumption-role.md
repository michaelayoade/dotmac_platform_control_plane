# Scoped dispatch-consumption database role (Gate 2 a2, E6)

Status: SPECIFICATION ONLY. Nothing here is executed by this repository. No role,
credential, key or grant is created by this change. Everything below is rendered as
text by `python -m vendor_cp.deployment.consumption_role_spec` (which never connects)
and run later by a Michael-approved ceremony, after review.

## Rulings

- E3-Q1 (2026-11-14): the a2 target consumes Control's dispatch through a
  short-lived database role limited to the dispatch-consumption records, issued per
  disposable target and revoked after the rehearsal. A CP consumption API (no database
  credential on any target) is built BEFORE D3.
- 2026-11-15: that role connects to the PRODUCTION CP database under these limits:
  1. lock tables get column-level `UPDATE (updated_at)` only;
  2. no UPDATE on the replay ledger;
  3. ledger INSERT and SELECT are restricted at the database by per-run row level
     security (below), installed and removed by the role ceremony, no Kernel change;
  4. `CONNECTION LIMIT` 4, `temp_file_limit`, `log_statement = 'all'`, and a 1 second
     tripwire watchdog (below), because the timeouts are not a bound.
- Role lifetime is tied to the run and hard-capped at 4 hours.
- The password is never plaintext in SQL: creation takes a client-computed
  `SCRAM-SHA-256$` verifier (`scram_verifier`).

## What the proof is, and is not (R5)

`prove_scoped_role` runs at bindings startup ON the target. A compromised target skips
it, so it detects ceremony mistakes and bounds nothing against an attacker. The control
is (a) the creation statements below and (b) an INDEPENDENT read-back of the same proof
by the ceremony before the credential is handed over, with the dispatch id read from the
controller-side `dispatch-materials.json`:

    python -m vendor_cp.deployment.consumption_role_check --role NAME --dispatch-id UUID

Record its exit status and typed output as E8/E10 ceremony evidence.

The proof refuses on: any of superuser, createrole, createdb, replication, bypassrls,
inherit; a role that cannot log in; ANY role membership (SET ROLE reaches a member role
whatever inherit says); no `VALID UNTIL` or more than 4 hours remaining; no connection
limit of 1 to 4; missing or loose `statement_timeout` (at most 60 s),
`lock_timeout` (10 s), `idle_in_transaction_session_timeout` (60 s), `temp_file_limit`
(at most 256MB) or `log_statement = 'all'`; CREATE on the database or any schema; owning
any object; executing a SECURITY DEFINER function; any sequence privilege; any privilege
beyond the table below at table AND column level, schema-qualified (lock tables must hold
no table-level UPDATE and exactly `UPDATE (updated_at)`); and any deviation of the ledger
guard: row level security must be ON without FORCE, exactly one permissive `TO PUBLIC
USING (true)` policy, and exactly this role's one restrictive INSERT and one restrictive
SELECT policy, binding the scope, the dispatch id being consumed and (INSERT)
`created_at = now()`. PostgreSQL ignores policies when RLS is off, so the proof checks it.

## Grants (schema-qualified; derived from Control `ad95f4e1`, Approvals a8, CP `approval_barrier`)

| Privilege | Tables |
|---|---|
| SELECT only | `platform_approval_decisions` (`mod_approvals`), `attestation_current_roots` (`mod_deploy`), `attestation_enrolments` (`mod_deploy`), `attestation_fingerprint_closures` (`mod_deploy`), `attestation_root_descriptors` (`mod_deploy`), `rollout_attempt_settlements` (`mod_deploy`), `rollout_attempts` (`mod_deploy`), `target_admission_policies` (`mod_deploy`), `target_admission_policy_closures` (`mod_deploy`), `target_host_association_closures` (`mod_deploy`), `target_host_associations` (`mod_deploy`) |
| SELECT plus `UPDATE (updated_at)` | `platform_approval_requests` (`mod_approvals`), `attestation_subject_locks` (`mod_deploy`), `deployment_plans` (`mod_deploy`), `deployment_targets` (`mod_deploy`), `rollouts` (`mod_deploy`), `target_credentials` (`mod_deploy`), `target_current_admission_policies` (`mod_deploy`), `target_current_hosts` (`mod_deploy`) |
| SELECT, INSERT (no UPDATE), under the RLS policies | `platform_idempotency_records` (`public`): the permanent dispatch replay marker, written once per dispatch by Kernel `execute_once_platform` |

Never, on any relation: DELETE, TRUNCATE, REFERENCES, TRIGGER. No DDL: no CREATE on the
database or any schema, no owned object, no role attribute, no membership.

`SELECT ... FOR UPDATE` and `FOR SHARE` both need UPDATE privilege on at least one column
(a PostgreSQL rule). `updated_at` is the column nothing on the admission or consumption
path reads as authority, so it is the one lock-only column.

## Ledger guard (RLS), per run

Kernel marks the ledger "platform plane, no RLS" and its migration verifier refuses a
table with RLS on. The guard therefore exists only for the run window and is removed
with it; a forgotten teardown makes the next requiring migration refuse loudly, so it
cannot be silently kept. The CP deploy line must be CLOSED for the guard window.
Nothing is changed for any other role: the permissive `TO PUBLIC` policy returns exactly
what they saw before, and the owner and superusers are not subject to RLS (no FORCE).

Because RLS applies to the run role, PostgreSQL refuses `COPY ... FROM` on the ledger for
it (SQLSTATE 0A000), so the earlier "COPY inserts rows the log cannot show" residual is
closed. `created_at = now()` also closes "the inserter chooses created_at". Prechecks
before use (E10a): no operational script `COPY`s into the ledger; the backup role is a
superuser or has BYPASSRLS; `ALTER TABLE`/`CREATE POLICY` take an ACCESS EXCLUSIVE lock
for milliseconds (`lock_timeout 3s`, retry).

Once per rehearsal, before any run role:

```sql
BEGIN;
SET LOCAL lock_timeout = '3s';
ALTER TABLE public.platform_idempotency_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY dotmac_ledger_unrestricted ON public.platform_idempotency_records AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
COMMIT;
```

## Creation (text only; one transaction per run role)

`consumption_role_spec template` prints the documentation form below: the password is the
psql variable `:'scram_verifier'`, which is a syntax error if executed, so a template can
never create a role with a known plaintext password. The command that renders SQL to run
is `create`, and it requires EVERY value and refuses any placeholder, empty value or
`valid-until` beyond 4 hours:

    python -m vendor_cp.deployment.consumption_role_spec create --role NAME \\
        --dispatch-id UUID --scram-verifier VERIFIER --valid-until ISO8601

The `--dispatch-id` comes from the CONTROLLER-side `dispatch-materials.json` that `issue`
wrote, never from a copy the target holds, for `create` and for the independent check.
The kit sends the rendered statements ONE AT A TIME (a single multi-statement query is
logged whole on receipt, defeating `SET LOCAL log_statement = 'none'`), and records the
digest of the rendered SQL in the receipt.

```sql
-- SPECIFICATION TEXT. NOT EXECUTED. Placeholders are filled at the ceremony.
BEGIN;
SET LOCAL log_statement = 'none';
SET LOCAL lock_timeout = '3s';
CREATE ROLE "<run_role>" LOGIN PASSWORD :'scram_verifier' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4 VALID UNTIL '<run end UTC, at most 4 hours after creation>';
ALTER ROLE "<run_role>" SET statement_timeout = '30s';
ALTER ROLE "<run_role>" SET lock_timeout = '5s';
ALTER ROLE "<run_role>" SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE "<run_role>" SET temp_file_limit = '256MB';
ALTER ROLE "<run_role>" SET log_statement = 'all';
GRANT USAGE ON SCHEMA mod_deploy, mod_approvals, public TO "<run_role>";
GRANT SELECT ON mod_approvals.platform_approval_decisions, mod_approvals.platform_approval_requests, mod_deploy.attestation_current_roots, mod_deploy.attestation_enrolments, mod_deploy.attestation_fingerprint_closures, mod_deploy.attestation_root_descriptors, mod_deploy.attestation_subject_locks, mod_deploy.deployment_plans, mod_deploy.deployment_targets, mod_deploy.rollout_attempt_settlements, mod_deploy.rollout_attempts, mod_deploy.rollouts, mod_deploy.target_admission_policies, mod_deploy.target_admission_policy_closures, mod_deploy.target_credentials, mod_deploy.target_current_admission_policies, mod_deploy.target_current_hosts, mod_deploy.target_host_association_closures, mod_deploy.target_host_associations, public.platform_idempotency_records TO "<run_role>";
GRANT UPDATE (updated_at) ON mod_approvals.platform_approval_requests, mod_deploy.attestation_subject_locks, mod_deploy.deployment_plans, mod_deploy.deployment_targets, mod_deploy.rollouts, mod_deploy.target_credentials, mod_deploy.target_current_admission_policies, mod_deploy.target_current_hosts TO "<run_role>";
GRANT INSERT ON public.platform_idempotency_records TO "<run_role>";
CREATE POLICY "<run_role>_insert" ON public.platform_idempotency_records AS RESTRICTIVE FOR INSERT TO "<run_role>" WITH CHECK (scope = 'deployment.consume_dispatch_challenge.v1' AND "key" = '<dispatch uuid>' AND operation = scope AND status = 'executed' AND expires_at IS NULL AND correlation_id IS NULL AND fingerprint ~ '^[0-9a-f]{64}$' AND created_at = now() AND updated_at = now());
CREATE POLICY "<run_role>_select" ON public.platform_idempotency_records AS RESTRICTIVE FOR SELECT TO "<run_role>" USING (scope = 'deployment.consume_dispatch_challenge.v1' AND "key" = '<dispatch uuid>');
COMMIT;
```

Preconditions the statements assume and the proof checks: no CREATE on any schema for
PUBLIC, no PUBLIC-executable SECURITY DEFINER function, TLS on the server. The ceremony
also adds a pg_hba `hostssl` line for this role, this database and the target address
only (typed parameters), removed at revocation: PUBLIC has CONNECT on every database and
this proof is per database. That path, with the firewall rule from the target to the
production CP database, is widening W1 and belongs in the E10 packet.

## Watchdog (the real bound on lock abuse)

`statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` are USERSET:
`ALTER ROLE ... SET` sets only a default and the role can `SET ... = 0`. `pg_advisory_lock`
is executable by PUBLIC and PostgreSQL has no negative privilege. `log_statement`,
`temp_file_limit`, `CONNECTION LIMIT` and `VALID UNTIL` are enforceable and are set above.
The bound on locking is the watchdog:

    CONSUMPTION_WATCHDOG_DATABASE_URL=... python -m vendor_cp.deployment.consumption_watchdog --role NAME

Each second it checks whether any backend of the role holds an advisory lock, has been
idle in a transaction for over 30 s, has had a transaction open for over 120 s, has run
one statement for over 10 s, or blocks another backend that has waited over 5 s. On any
violation it revokes the ROLE (below) and reads back; reconnecting does not reopen the
window. On deadline, error or loss of the database it also revokes. Abuse is bounded to about
one tick, once.

Signals: SIGTERM, SIGINT, SIGHUP (an SSH drop, the ruled session model) and SIGQUIT take
one exit path that revokes; once revocation starts further signals are ignored; revocation
is retried with bounded backoff (12 attempts, capped at 15 s) until the read-back is
(0,0,0), and if it never is the watchdog exits LOUDLY with code 5 and the ceremony revokes
by hand. Exit codes: 0 clean end, 3 tripped, 4 failed, 5 revocation not clean, 6 signalled.
It cannot survive SIGKILL, and a revocation can take minutes (each attempt is several
fresh connections plus lock waits, and the retry sleeps alone total about two minutes), so
run it where nothing sends SIGKILL: `systemd-run` (journal stdout; survives SSH loss), or
docker with `--stop-timeout 600` and never `docker stop` it. The watchdog's DSN carries
`connect_timeout=5`, so a blackholed database cannot hang a connect. After ANY watchdog
exit the ceremony kit's trap runs `revoke` and `verify` unconditionally. A signal at any
instant, including inside the mask-and-revoke window, cannot skip revocation: once
revoking starts the handler is a no-op and the revoke is re-entered if anything still
interrupts it.
Its DSN is a superuser-grade credential and is visible to root-equivalent users of the
ceremony host (root, the docker group) however it is supplied: an `--env-file` still
appears in `docker inspect` and in `/proc`, and the watchdog reads it from the environment
only. That exposure is accepted and bounded by the host's trust and the 4 hour window; it
is not removed by the env-file. Never place it on a target.

Its own database access: it runs on the ceremony host, never on a target, with the SAME
administrative session credential that created the role (a superuser, or a role holding
ALTER ROLE, `pg_terminate_backend`, DROP OWNED and ownership of the ledger), because it
reads `pg_stat_activity`/`pg_locks` across roles. No new credential is created for it.

## Revocation: end of run, or any doubt (R4)

`VALID UNTIL` is checked only at login, so pooled sessions outlive it, and `DROP ROLE`
fails while the role holds privileges. Run the whole sequence, then the verification
query; all three counts must be 0. Do not report the run closed until they are.

```sql
ALTER ROLE "<run_role>" NOLOGIN CONNECTION LIMIT 0;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '<run_role>';
DROP POLICY IF EXISTS "<run_role>_insert" ON public.platform_idempotency_records;
DROP POLICY IF EXISTS "<run_role>_select" ON public.platform_idempotency_records;
DROP OWNED BY "<run_role>";
DROP ROLE "<run_role>";
```

Verification (expect `roles_remaining = 0`, `sessions_remaining = 0`, `policies_remaining = 0`):

```sql
SELECT (SELECT count(*) FROM pg_roles WHERE rolname = '<run_role>') AS roles_remaining, (SELECT count(*) FROM pg_stat_activity WHERE usename = '<run_role>') AS sessions_remaining, (SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename = 'platform_idempotency_records' AND roles @> ARRAY['<run_role>']::name[]) AS policies_remaining;
```

After BOTH runs, remove the guard (refuses while any restrictive policy remains):

```sql
BEGIN;
SET LOCAL lock_timeout = '3s';
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'platform_idempotency_records' AND permissive = 'RESTRICTIVE') THEN RAISE EXCEPTION 'restrictive ledger policies remain'; END IF; END $$;
DROP POLICY dotmac_ledger_unrestricted ON public.platform_idempotency_records;
ALTER TABLE public.platform_idempotency_records DISABLE ROW LEVEL SECURITY;
COMMIT;
```

After revocation review the database log for every statement the role ran, and compare
the ledger before and after the role window: every new row must be the expected dispatch
marker or attributable to CP's own activity. Attach both to the run's evidence.

## Residuals, stated

1. **Memory amplification.** PostgreSQL 16 has no per-role memory cap. Within the one-tick
   window the role can `SET work_mem` and run a large join. Bounded by the tick, the small
   CP tables and the one-rehearsal scope. Removed at D3.
2. **The role can read every row of the contract tables**, including plans, rollouts and
   approvals, on the production database. The ledger SELECT is restricted to its own
   `(scope, key)`.
3. **Row locks.** The role can hold row locks on the lock tables until the watchdog trips
   (about one tick). It can take advisory locks; the watchdog treats any as a violation.
   Repeated lock bursts shorter than the 5 s blocking threshold never trip it, so CP write
   latency can degrade for up to 4 h. The kit therefore revokes as soon as the run's ledger
   row appears: the role has nothing legitimate left to do.
4. **Local-clock re-check inside Control (R6).** Control `service.py` re-checks authorization
   expiry under its locks with `_control_now()`, the local clock. CP cannot avoid that path:
   it sits inside `_stage_dispatch_consumption`, which `admit_and_consume_host_admission`
   calls, and changing Control is not a2 work. The DB-clock check (`security.clock`) precedes
   it, so a backdated target gains only the lock-wait window. The skew check in `bindings()`
   runs inside the target, so it is self-reported; the launcher-side skew check (T5) and the
   E9 join against a launcher-observed DB-time bracket are the independent controls.
5. **Kernel pools versus the connection limit.** Kernel opens a tenant pool and a platform
   pool on the one DSN; under concurrency, overflow can hit `CONNECTION LIMIT 4`. The
   consumption path is sequential; a refused connection fails closed.
6. **`~/.pgpass`** is still consulted by libpq. The `PG*` environment variables are refused;
   the target must not carry a password file.
7. The startup proof is a tripwire (above).

TODO(before D3): CP consumption API. CP performs resolve/finalize; the target's provider is
a client; this role, the guard, the watchdog, `consumption_scope.py` and the scoped DSN
input are removed. Not part of this change.
