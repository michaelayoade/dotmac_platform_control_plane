# Conformance suites

## Installed Foundation render and CP approval/finalizer composition

The required `CI / postgres` job runs
`test_candidate_renderer_real_foundation.py` and
`test_host_admission_conformance.py` against the complete CP wheel, its locked
Kernel `0.1.0a100` dependency,
plus Control `0.1.0a17` and Approvals `0.1.0a8`,
and a test-only Foundation wheel built from clean exact Starter source
`d74bf8dd8c399dd92047174365403b861f82ddd0`. The job migrates the full composition
on disposable PostgreSQL, then invokes these cases as `platform_api`.

The workflow replaces CP's editable install with the built wheel, installs the
Foundation wheel without changing the runtime lock, copies only the two test
files, conftest, separately authored `fixtures/renderer-component.toml` and the
unchanged production descriptor into `RUNNER_TEMP`, and runs there.
Each imported owner/service must resolve under that interpreter's installed
`purelib`/`platlib`. Build hashes and installed versions/origins are recorded in
CI. The source commit plus build hash identifies tested Foundation bytes;
it is **not** evidence of an eligible published Foundation successor, a new
runtime pin, a candidate allocation or deployment adoption.

The installed module `python -m vendor_cp.deployment.conformance_report`
requires twenty-one exact named cases: five renderer variants, ten component
security cases and six CP V3 composition cases. An omitted, duplicated, renamed,
skipped or failed case refuses the gate. The separate rehearsal-issuer harness keeps its restricted
Control/Kernel dependency closure and no longer runs these full CP tests.

Positive renderer cases use the independently authored fictional
`conformance/fixtures/renderer-component.toml`, never a stripped or modified
production descriptor. They compare CP's exact two-field candidate substitution
with real Foundation canonical descriptor/plan output, prove changed prestate
and synthetic profile coordinates change the execution digest, and refuse a
dictionary pretending to be `HostPrestateV1`. These are transport/render
component proofs, not production compatibility or canonical profile admission.

A separate required case reads the actual promoted `deploy/product.toml`
byte-for-byte, establishes its promised `row_counts` verification and absent
`external_executor`, and requires the real installed Foundation `SpecError`:
`backup.verification.unperformable` at `backup.datasets[0]`. CI compares the
copied production file to the original before execution. This expected refusal
is negative compatibility evidence; it is never counted as a positive
production render. D7's actual row-count verification owner remains **OPEN**.
No verification promise is removed and no replacement executor is invented.

Every host fixture now opens and decides an actual Approvals request, approves
through CP's live shared-lock barrier, then requests a signed rollout and
signed dispatch through fresh barriers. Each authority phase commits before
the next, preserving Approvals-before-Control lock order. Ten component cases
retain the test-owned resolve/verify/finalize driver and its signature, semantic
binding, expiry/revocation, marker durability and commit-order refusals.

The six CP cases exercise the startup composition with real Foundation F2,
actual installed-artifact reads and Control's sole finalizer. They require a
real held approval at consumption, prove withdrawal-first refusal and
transition-first blocking through the caller commit, preserve missing-startup-
barrier refusal, reject autocommit, refuse consumed-dispatch replay and recover
a deliberately lost commit acknowledgement through a fresh committed lookup.
Session A closes before Foundation verification; Session B owns the single
finalizer commit. These tests stage durable consumption but launch no workload.

The signature adapters remain deterministic SHA-256/HMAC **test doubles**,
not Ed25519 custody evidence. This gate executes real signature verification
ports, rejects tampering, and tests real database locks. It does not establish
asymmetric signer custody, OIDC, live controller authentication, canonical
profile admission, eligible release or receipt-producing deployment.

The fixture retains Control's test reset hooks, stored-dispatch locator and
marker-scope constant as test-only private dependencies. They are not production
imports and must be re-proven at each artifact change. Public committed lookup
independently checks durable marker assertions.

The ordinary migration run also emits a separate approval report. After the
actual CP wheel is installed and execution moves outside the checkout, the same
installed module with `--approval` requires all twenty-one named cases from
`tests/migration/test_foundation_approval.py`, including both withdrawal
orderings at actual approve, signed rollout and signed dispatch commands, with
caller single-commit and peer lock-timeout probes. Its ephemeral HMAC signer
ports are test cryptography, not production custody. The report gate does not
permit this file to disappear or skip while unrelated migration cases pass.

New source/tests are prepared for hosted execution; no passing result is implied
by their presence. Unmet integrated acceptance still includes complete admitted
profile/selection provenance, actual Executor/effects and receipt production,
and production-shaped host/UI deploy/redeploy/rollback. No green result in
these suites discharges those separate obligations.

## Preconditions and evidence

A normal `pytest tests/` run does not collect `conformance/`. An explicit
host-admission or whole-directory invocation requires
`CONFORMANCE_DATABASE_URL`; the conftest hard-errors before collection if it
is absent. Missing wheels, symbols or incompatible API shapes fail collection;
they are never converted into skips.

Use the workflow's migrated disposable database and closed dependency bundle,
not CP's existing workstation venv or a production database. Tests must never
start workstation Docker; the prescribed CI Docker environment is disposable.
Record only non-secret host/database identifiers, never credential-bearing
DSNs.

For every Control/Foundation pin change, the required isolated CI lane must
execute again before merge. Record its exact CP revision, released Control/Approvals
source/tag/verify coordinates, Foundation source commit, all installed wheel
hashes/import origins, migration heads and the twenty-case/no-skip result.
Ordinary lint, Protocol-shaped unit doubles or a previously green run do not
discharge that gate for a new dependency revision. The protected lock workflow
alone owns application dependency resolution; conformance must never rewrite
`pyproject.toml` or `poetry.lock` to make a test pass.

## D16 source-only transition-verifier conformance

`test_d16_source_verifier_real_foundation.py` has a different precondition:
the public Starter repository checked out cleanly at exact commit
`d74bf8dd8c399dd92047174365403b861f82ddd0`. It needs no database and
never executes migrations, workload launch or routing. CP's required `check`
job fetches those exact bytes into `.d16-foundation-source` and invokes this
file explicitly. To run it manually in an isolated environment:

    D16_FOUNDATION_CHECKOUT=/absolute/path/to/clean/starter-at-d74bf8dd \
      pytest -q conformance/test_d16_source_verifier_real_foundation.py

The test hard-errors if the source checkout is absent or wrong; it does not
skip. A whole-directory or mixed conformance invocation still requires
`CONFORMANCE_DATABASE_URL` for the host-admission tests. This is source-tool
conformance only: it does not authenticate the future CP host producer's
write-time checksum, full-decompression proof, catalogue capture, image or
observed migration heads, and it is not production deployment evidence.

## D16 bundle-producer and dump-evidence conformance

The required `postgres` CI job also runs the two bundle-producer and two
dump-evidence migration tests against a disposable Postgres database. It
checks out Starter at the exact same `d74bf8dd8c399dd92047174365403b861f82ddd0`
commit and puts only its Foundation package source on `PYTHONPATH` for that
step. CI verifies the checkout commit and Python import origin before running
the tests; `scripts/check_d16_bundle_junit.py` requires all four named cases
to pass with no skips. The normal migration test invocation may still skip
the optional Foundation import, but that green result is not the D16 gate.

This is CI-only source conformance, not an installed CP dependency or a
production bundle/receipt producer. It proves that a live CP catalogue maps
to a Foundation-accepted manifest, and that a nonempty `pg_dump` archive has
write-time checksum, size and full-decompression evidence mapped into
Foundation's backup record types. It does not prove restore rehearsal,
transition receipt construction, deploy wiring, or permission to restore
routing. Those remain separate D16 gates.
