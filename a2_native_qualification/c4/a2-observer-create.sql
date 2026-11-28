-- REVIEW-P2-L1.md r3 (b409d732) section 3, C5, verbatim except that the C4
-- harness renders the run suffix, the database name and the expiry time.
BEGIN;
CREATE ROLE a2_recovery_observer_rN LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 2
  VALID UNTIL '<UTC now + 3 hours>' PASSWORD :'scram_verifier';
ALTER ROLE a2_recovery_observer_rN SET default_transaction_read_only = on;
ALTER ROLE a2_recovery_observer_rN SET statement_timeout = '5s';
ALTER ROLE a2_recovery_observer_rN SET lock_timeout = '2s';
ALTER ROLE a2_recovery_observer_rN SET idle_in_transaction_session_timeout = '10s';
GRANT CONNECT ON DATABASE <cp_db_name> TO a2_recovery_observer_rN;
GRANT USAGE ON SCHEMA mod_deploy, public TO a2_recovery_observer_rN;
GRANT SELECT ON mod_deploy.rollouts, mod_deploy.rollout_attempts,
  mod_deploy.rollout_attempt_settlements, public.platform_idempotency_records
  TO a2_recovery_observer_rN;
COMMIT;
