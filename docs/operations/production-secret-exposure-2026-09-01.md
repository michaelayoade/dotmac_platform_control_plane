# Platform CP production secret exposure — 2026-09-01

Status: remediation facility implemented; production rotation not executed.

The window `platform-cp-first-authorization-2026-09-01T10:00-11:00WAT` is
cancelled and must never be resumed. A read-only container inspection emitted
the running application's database, JWT and session materials. It did not emit
CSRF, signing private-key, deployment-key, OpenBao-token or bootstrap material.
No issuer, plan, approval, rollout, deployment, database or OpenBao mutation
occurred.

The affected names are:

- `admin_password`, `app_user_password`, `platform_api_password` at
  `secret/dotmac/vendor-control-plane/production/database`;
- `jwt_secret`, `session_hash_secret` at
  `secret/dotmac/vendor-control-plane/production/runtime`.

## Names-only exposure and remediation matrix

| Emitted environment name or alias | Canonical OpenBao field | Live projection / principal | Required remediation and proof |
| --- | --- | --- | --- |
| `VENDOR_DB_ADMIN_PASSWORD`; derived alias `MIGRATION_DATABASE_URL` | `secret/dotmac/vendor-control-plane/production/database` → `admin_password` | `.env` → app; PostgreSQL role `app_admin` | Rotate in the shared three-role PostgreSQL transaction; prove the protected prior value succeeds and the candidate fails over TCP/SCRAM before mutation, then prove the inverse; recreate app on the exact authorized image. |
| `VENDOR_DB_APP_USER_PASSWORD`; derived alias `DATABASE_URL` | `secret/dotmac/vendor-control-plane/production/database` → `app_user_password` | `.env` → app; PostgreSQL role `app_user` | Rotate in the same transaction with the same two-direction TCP/SCRAM proof; recreate app on the exact authorized image. |
| `VENDOR_DB_PLATFORM_API_PASSWORD`; derived alias `PLATFORM_DATABASE_URL` | `secret/dotmac/vendor-control-plane/production/database` → `platform_api_password` | `.env` → app; PostgreSQL role `platform_api` | Rotate in the same transaction with the same two-direction TCP/SCRAM proof; recreate app on the exact authorized image. |
| `JWT_SECRET` | `secret/dotmac/vendor-control-plane/production/runtime` → `jwt_secret` | `.env` → app | Rotate, invalidate every current API token/session derived from the prior JWT material, prove prior refusal and candidate acceptance, and recreate app. |
| `SESSION_HASH_SECRET` | `secret/dotmac/vendor-control-plane/production/runtime` → `session_hash_secret` | `.env` → app | Rotate, invalidate every current browser/session token derived from the prior hash material, prove prior mismatch and candidate acceptance, and recreate app. |
| `VENDOR_LICENCE_SIGNING_KEY_ID` | `secret/dotmac/licensing/signing-key` → `key_id` | `.env` → app; non-secret identifier only | No credential rotation: retain as an observed identifier. The private signing key is separately file-mounted and was not present in the emitted names. |

The matrix intentionally records names, locations, principals and consequences
only. It contains no value and no value-derived hash.

Based only on name presence in the retained names-only inventory—the environment
was not re-inspected—the following material was absent and **not exposed**:

- `CSRF_SECRET` / runtime field `csrf_secret`; preserve it byte-for-byte and
  prove equality before and after the app recreation;
- the file-mounted licence-signing private key at
  `secret/dotmac/licensing/signing-key`;
- the deploy SSH private/public key material at
  `secret/dotmac/vendor-control-plane/production/deploy-ssh`;
- any OpenBao token or other OpenBao authentication material; and
- the database bootstrap material, including `VENDOR_DB_BOOTSTRAP_PASSWORD`.

`csrf_secret` at the runtime record was not exposed and must remain
byte-for-byte unchanged. The signing and deploy records are outside the
rotation set.

The checked-in remedy is `rotate-production` in
`scripts/materialize_production_secrets.py`, owned by the typed state machine in
`vendor_cp.production_secrets`. Its receipt contains only the incident id,
field names, KV versions, phases, immutable image/revision and named verdicts.
Values and value-derived hashes are forbidden. The complete production
preconditions, command, proofs, retry rule and incident-only rollback are in
`docs/operations/production-deployment.md`.

The host leg is not the mutable production checkout. It is a deterministic
archive installed at a fixed root-owned mode-`0555` path, bound by digest in the
payload and proof, and retired after the incident result is reviewed. Its
names-only target receipt distinguishes a fresh proof from a historical replay.

Production stays frozen until a separately named rotation window earns a
`proved` receipt. Only then may Michael name a new authorization window.
