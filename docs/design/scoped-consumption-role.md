# Scoped dispatch-consumption database role (Gate 2 a2, E6)

Status: SPECIFICATION ONLY. Nothing here is executed by this repository. No role,
credential, key or grant is created by this change. The role is created later,
by a Michael-approved ceremony, with the SQL below reviewed first.

Ruling (Michael, 2026-11-14, E3-Q1): for the a2 disposable targets the target
consumes Control's dispatch through a short-lived database role limited to the
dispatch-consumption records, issued per target and revoked after the rehearsal.
A CP consumption API (no database credential on any target) is built BEFORE D3.

## What CP enforces in code

* `DISPATCH_CONSUMPTION_DATABASE_URL` is a separate input. A host carrying
  `DATABASE_URL` or `PLATFORM_DATABASE_URL` refuses (`general_dsn_present_on_target`):
  those are the write-capable general credentials. A role name that reads as an
  owner/administrator, or a DSN option that can change the effective role,
  refuses (`consumption_dsn_not_scoped`). Both are tripwires.
* The control is the catalogue proof at bindings startup
  (`vendor_cp.deployment.consumption_scope.prove_scoped_role`): as the connected
  role, the database must report that it is not superuser, createrole, createdb,
  replication or bypassrls; has a `VALID UNTIL` no more than 12 hours away; can
  create in no schema; owns no relation; holds DELETE, TRUNCATE, REFERENCES or
  TRIGGER nowhere; and holds SELECT / INSERT / UPDATE only on the tables below.
  An unreadable catalogue refuses (`consumption_role_unverifiable`).
* Freshness uses CP database time (`clock_timestamp()` through this same role)
  and a skew check (`DISPATCH_CLOCK_SKEW_LIMIT_SECONDS`, default 5 s, at most 60 s).

## Grants the role needs (names only; schemas shown for the ceremony)

The sets live in code as `READ_ONLY_TABLES`, `LOCK_ONLY_TABLES` and
`WRITE_TABLES`; a test pins this section to them. They are derived by reading
Deployment Control `ad95f4e1` (`host_admission_coordinator`,
`foundation_consumption`, `service._stage_dispatch_consumption`,
`attestation_trust_registry`, `host_admission_service`) and CP's
`approval_barrier`. They are NOT yet confirmed against a real database.

| Privilege | Tables |
|---|---|
| SELECT only | `attestation_current_roots`, `attestation_enrolments`, `attestation_fingerprint_closures`, `attestation_root_descriptors`, `target_host_associations`, `target_host_association_closures`, `target_current_hosts`, `target_admission_policies`, `target_admission_policy_closures`, `target_current_admission_policies` (all `mod_deploy`); `platform_approval_requests` (`mod_approvals`, FOR SHARE hold) |
| SELECT plus row-lock UPDATE | `attestation_subject_locks`, `deployment_targets`, `target_credentials`, `deployment_plans`, `rollouts`, `rollout_attempts` (all `mod_deploy`) |
| SELECT, INSERT, UPDATE | `platform_idempotency_records` (`public`): the permanent dispatch replay marker, written once per dispatch by Kernel `execute_once_platform` |

Never, on any relation: DELETE, TRUNCATE, REFERENCES, TRIGGER. No DDL: no CREATE
on any schema, no ownership of any relation, no role attributes.

```sql
-- SPECIFICATION TEXT. NOT EXECUTED. <placeholders> are filled at the ceremony.
-- Preferred: an OpenBao database-secrets role whose creation_statements are this
-- block and whose TTL does not exceed the run (and is capped at 12 hours).
CREATE ROLE <run_role> LOGIN PASSWORD '<generated>'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT
  VALID UNTIL '<run end, at most 12 hours from creation>';

GRANT USAGE ON SCHEMA mod_deploy, mod_approvals, public TO <run_role>;
-- Do NOT grant CREATE on any schema. If `public` still grants CREATE to PUBLIC
-- on this server (PostgreSQL before 15), revoke it for the run role's reach.

GRANT SELECT ON
  mod_deploy.attestation_current_roots,
  mod_deploy.attestation_enrolments,
  mod_deploy.attestation_fingerprint_closures,
  mod_deploy.attestation_root_descriptors,
  mod_deploy.target_host_associations,
  mod_deploy.target_host_association_closures,
  mod_deploy.target_current_hosts,
  mod_deploy.target_admission_policies,
  mod_deploy.target_admission_policy_closures,
  mod_deploy.target_current_admission_policies,
  mod_approvals.platform_approval_requests
  TO <run_role>;

GRANT SELECT ON
  mod_deploy.attestation_subject_locks,
  mod_deploy.deployment_targets,
  mod_deploy.target_credentials,
  mod_deploy.deployment_plans,
  mod_deploy.rollouts,
  mod_deploy.rollout_attempts
  TO <run_role>;
-- Row locks (SELECT ... FOR UPDATE) need UPDATE. Column level only; see open
-- point 1. One statement per table, naming a column no consumption path writes:
--   GRANT UPDATE (<lock_column>) ON mod_deploy.<table> TO <run_role>;

GRANT SELECT, INSERT, UPDATE ON public.platform_idempotency_records TO <run_role>;
-- plus USAGE on any sequence that table's default draws from.

-- Revocation after the rehearsal (also implied by VALID UNTIL):
--   REASSIGN OWNED / DROP OWNED are not needed (the role owns nothing).
--   DROP ROLE <run_role>;
```

## Open points for the architect review

1. **Row locks need UPDATE.** PostgreSQL requires UPDATE privilege (column level
   suffices) for `SELECT ... FOR UPDATE`. Control locks mutable tables
   (`deployment_targets`, `target_credentials`, `rollouts`, `rollout_attempts`,
   `deployment_plans`). A column-level UPDATE on one column limits the damage but
   does not remove it: the role could still rewrite that column. Choose a column
   no path reads as authority, or accept the risk for disposable targets only.
   This is the main reason the CP consumption API precedes D3.
2. **The write set may be wider than this table.** `finalize_foundation_dispatch`
   runs a Control transition under the Approvals hold. Control `ad95f4e1` stages
   only the Kernel idempotency marker, but a conformance run against a real
   database (not a static read) must confirm no other write, audit-event or outbox
   insert is reached. If one is, `prove_scoped_role` refuses at startup, which is
   the intended failure.
3. **Schema of the Kernel marker table** is taken from `data_governance`
   (`public.platform_idempotency_records`); confirm at the ceremony.
4. The proof matches table NAMES, not schemas. A same-named table in another
   schema would be treated as allowed. Acceptable for a disposable target; a
   schema-qualified match is the follow-up if this role outlives a2.

TODO(before D3): CP consumption API. CP performs resolve/finalize; the target's
provider is a client; this role, `consumption_scope.py` and the scoped DSN input
are removed. Not part of this change.
