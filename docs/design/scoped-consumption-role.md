# Scoped dispatch-consumption database role (Gate 2 a2, E6)

Status: SPECIFICATION ONLY. Nothing here is executed by this repository. No role,
credential, key or grant is created by this change. The role is created later, by
a Michael-approved ceremony, with the SQL below reviewed first.

## Rulings

- E3-Q1 (2026-11-14): the a2 target consumes Control's dispatch through a
  short-lived database role limited to the dispatch-consumption records, issued
  per disposable target and revoked after the rehearsal. A CP consumption API (no
  database credential on any target) is built BEFORE D3.
- 2026-11-15: that role connects to the PRODUCTION CP database, under four limits:
  1. lock tables get column-level `UPDATE (updated_at)` only;
  2. no UPDATE on the replay ledger (insert-only);
  3. every statement the role runs is logged (`ALTER ROLE ... SET log_statement =
     'all'`, no Kernel schema change), so ledger inserts are reviewable;
  4. `CONNECTION LIMIT` 4 plus statement, lock and idle-in-transaction timeouts.
- Role lifetime is tied to the run and hard-capped at 4 hours.

## What the proof is, and is not (R5)

`prove_scoped_role` runs at bindings startup ON the target. A compromised target
skips it, so it detects ceremony mistakes and bounds nothing against an attacker.
The control is (a) the creation statements below and (b) an INDEPENDENT read-back
of the same proof by the ceremony before the credential is handed over:

    python -m vendor_cp.deployment.consumption_role_check            # about the credential's own role
    python -m vendor_cp.deployment.consumption_role_check --role NAME  # about a named role

Record its exit status and output (typed code only) as E8/E10 ceremony evidence.

The proof refuses on: any of superuser, createrole, createdb, replication,
bypassrls, inherit; a role that cannot log in; ANY role membership (SET ROLE
reaches a member role whatever inherit says); no `VALID UNTIL` or more than 4
hours remaining; no connection limit of 1 to 4; missing or loose
`statement_timeout` (at most 60 s), `lock_timeout` (10 s), `idle_in_transaction_session_timeout`
(60 s) or `log_statement = 'all'`; CREATE on the database or any schema; owning
any object; executing a SECURITY DEFINER function; any sequence privilege; and,
schema-qualified and at table AND column level, any privilege beyond the table
below. Lock tables must hold no table-level UPDATE and exactly `UPDATE (updated_at)`.

## Grants (schema-qualified; derived from Control `ad95f4e1`, Approvals a8, CP `approval_barrier`)

| Privilege | Tables |
|---|---|
| SELECT only | `platform_approval_decisions` (`mod_approvals`), `attestation_current_roots` (`mod_deploy`), `attestation_enrolments` (`mod_deploy`), `attestation_fingerprint_closures` (`mod_deploy`), `attestation_root_descriptors` (`mod_deploy`), `rollout_attempt_settlements` (`mod_deploy`), `rollout_attempts` (`mod_deploy`), `target_admission_policies` (`mod_deploy`), `target_admission_policy_closures` (`mod_deploy`), `target_host_association_closures` (`mod_deploy`), `target_host_associations` (`mod_deploy`) |
| SELECT plus `UPDATE (updated_at)` | `platform_approval_requests` (`mod_approvals`), `attestation_subject_locks` (`mod_deploy`), `deployment_plans` (`mod_deploy`), `deployment_targets` (`mod_deploy`), `rollouts` (`mod_deploy`), `target_credentials` (`mod_deploy`), `target_current_admission_policies` (`mod_deploy`), `target_current_hosts` (`mod_deploy`) |
| SELECT, INSERT (no UPDATE) | `platform_idempotency_records` (`public`): the permanent dispatch replay marker, written once per dispatch by Kernel `execute_once_platform` |

Never, on any relation: DELETE, TRUNCATE, REFERENCES, TRIGGER. No DDL: no CREATE on
the database or any schema, no owned object, no role attribute, no membership.

`SELECT ... FOR UPDATE` and `FOR SHARE` both need UPDATE privilege on at least one
column (a PostgreSQL rule). `updated_at` is the column nothing on the admission or
consumption path reads as authority, so it is the one lock-only column. The
real-PostgreSQL conformance test (`conformance/test_host_admission_conformance.py`,
rehearsal-issuer-harness job) creates the role from this SQL, runs Control's
actual resolve and consume as that role, and asserts that out-of-scope writes
(for example UPDATE of a verification key column, UPDATE of the ledger) are
refused.

## Creation (text only)

```sql
-- SPECIFICATION TEXT. NOT EXECUTED. Placeholders are filled at the ceremony.
-- `python -m vendor_cp.deployment.consumption_role_spec create --role NAME`
-- prints this with the role name filled in; it never connects.
CREATE ROLE <run_role> LOGIN PASSWORD '<generated>' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4 VALID UNTIL '<run end UTC, at most 4 hours after creation>';
ALTER ROLE <run_role> SET statement_timeout = '30s';
ALTER ROLE <run_role> SET lock_timeout = '5s';
ALTER ROLE <run_role> SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE <run_role> SET log_statement = 'all';
GRANT USAGE ON SCHEMA mod_deploy, mod_approvals, public TO <run_role>;
GRANT SELECT ON mod_approvals.platform_approval_decisions, mod_approvals.platform_approval_requests, mod_deploy.attestation_current_roots, mod_deploy.attestation_enrolments, mod_deploy.attestation_fingerprint_closures, mod_deploy.attestation_root_descriptors, mod_deploy.attestation_subject_locks, mod_deploy.deployment_plans, mod_deploy.deployment_targets, mod_deploy.rollout_attempt_settlements, mod_deploy.rollout_attempts, mod_deploy.rollouts, mod_deploy.target_admission_policies, mod_deploy.target_admission_policy_closures, mod_deploy.target_credentials, mod_deploy.target_current_admission_policies, mod_deploy.target_current_hosts, mod_deploy.target_host_association_closures, mod_deploy.target_host_associations, public.platform_idempotency_records TO <run_role>;
GRANT UPDATE (updated_at) ON mod_approvals.platform_approval_requests, mod_deploy.attestation_subject_locks, mod_deploy.deployment_plans, mod_deploy.deployment_targets, mod_deploy.rollouts, mod_deploy.target_credentials, mod_deploy.target_current_admission_policies, mod_deploy.target_current_hosts TO <run_role>;
GRANT INSERT ON public.platform_idempotency_records TO <run_role>;
```

Preconditions the statements assume and the proof checks: no CREATE on any schema
for PUBLIC, no PUBLIC-executable SECURITY DEFINER function, TLS on the server.

## Revocation: end of run, or any doubt (R4)

`VALID UNTIL` is checked only at login, so pooled sessions outlive it, and
`DROP ROLE` fails while the role holds privileges. Run the whole sequence, then the
verification query; both counts must be 0. Do not report the run closed until they are.

```sql
ALTER ROLE <run_role> NOLOGIN CONNECTION LIMIT 0;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '<run_role>';
DROP OWNED BY <run_role>;
DROP ROLE <run_role>;
```

Verification (read-back; expect `roles_remaining = 0` and `sessions_remaining = 0`):

```sql
SELECT (SELECT count(*) FROM pg_roles WHERE rolname = '<run_role>') AS roles_remaining, (SELECT count(*) FROM pg_stat_activity WHERE usename = '<run_role>') AS sessions_remaining;
```

After revocation review the database log for every statement the role ran (the
control over ledger inserts), and attach that review to the run's evidence.

## Residuals, stated

1. **Ledger INSERT stays unrestricted by scope.** The role can insert replay-ledger
   rows under any scope key: burn another dispatch, or plant a result for another
   CP platform operation. Control is statement logging plus review, not prevention.
2. **The role can read every row of the tables above**, including plans, rollouts
   and approvals, on the production database.
3. **Bounded lock denial.** The role can hold row locks on the lock tables, bounded
   by `lock_timeout`, `statement_timeout` and `idle_in_transaction_session_timeout`.
4. **Local-clock re-check inside Control (R6).** Control `service.py` re-checks
   authorization expiry under its locks with `_control_now()`, the local clock. CP
   cannot avoid that path: it sits inside `_stage_dispatch_consumption`, which
   `admit_and_consume_host_admission` calls, and changing Control is not a2 work.
   The DB-clock check (`security.clock`) precedes it, so a backdated target gains
   only the lock-wait window. The skew check in `bindings()` runs inside the target,
   so it is self-reported; the launcher-side skew check (T5) and the E9 join against a
   launcher-observed DB-time bracket (not the ledger `created_at`, which the inserter
   can set) are the independent controls.
5. The startup proof is a tripwire (above).

TODO(before D3): CP consumption API. CP performs resolve/finalize; the target's
provider is a client; this role, `consumption_scope.py` and the scoped DSN input are
removed. Not part of this change.
