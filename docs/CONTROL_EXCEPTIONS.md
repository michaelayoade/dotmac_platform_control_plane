# Control exceptions

Append-only inventory. An entry is never deleted; remediation state changes in
place and keeps the original event visible.

## 2026-09-01 — production container environment inspection

- **State:** remediation facility implemented; two windows failed closed; live
  rotation outstanding behind a separately deployed readiness-capable image.
- **Event:** a read-only container inspection emitted Platform CP database,
  JWT and session material into an agent transcript.
- **Failed premise:** runtime identity could be observed by inspecting the
  container without exposing its configuration environment.
- **Refused recurrence:** identity is read only from `.Config.Image` and the OCI
  revision label after exact Docker-label selection. This read-only preflight
  uses neither Compose nor Docker environment inspection and runs before any
  OpenBao identity, custody or adapter installation. It separately proves
  liveness and database-reaching readiness; tests assert the forbidden selector
  is absent and every failed preflight leaves all mutation counters at zero.
- **Remediation:** rotate exactly the five exposed fields through typed KV-v2
  CAS, preserve CSRF, atomically update all database roles, recreate only the
  app on its authorized unchanged image through a separately installed,
  digest-bound, single-use host adapter, and retain a names-only proof. See
  `docs/operations/production-secret-exposure-2026-09-01.md`.
- **Close condition:** a separately named production rotation window produces
  a `proved` receipt and the prior credentials are all refused.
