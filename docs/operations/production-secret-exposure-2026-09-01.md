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
