# a2-native-qualification

Hosted CI that produces the receipts closing Foundation a2 Gate 2 items #1
(`NATIVE_PG`) and #2 (i) (`NATIVE_BAO`). Workflow:
`.github/workflows/a2-native-qualification.yml` (workflow_dispatch and pull_request
only; read-only permissions; publishes nothing).

- `pg`: disposable PostgreSQL 16, the BUILT CP wheel (installed, not source-linked),
  the CP image built locally and bound by id, the Control wheel built and bound by
  digest. Scenario map: `scenarios.json` (existing CP tests invoked by name).
  Scenarios (a) and (d) run Control #76's native-PG tests from the Control checkout
  (Control's own platform-isolation fixtures). A scenario with no tests is BLOCKED; it makes the receipt INCOMPLETE, which fails a
  dispatch run (`require_complete`, default true) and is tolerated on PR runs only.
- `bao`: a real OpenBao 2.5.3 server (file storage, initialised in the job).
- Receipts: `a2-native-pg-qualification-<date>.json` and
  `a2-native-bao-qualification-<date>.json`, each with a `.sha256` and the log,
  uploaded as `a2-native-{pg,bao}-qualification-<run_id>-<attempt>`. Values-free:
  names, booleans, counts and digests only.
- Offline self-tests: `python -I a2_native_qualification/test_selftest.py`.
