# Conformance suites

## Host-admission components and current CP V3 refusal

The required `rehearsal-issuer-harness` CI job runs
`test_host_admission_conformance.py` explicitly against released Control
`0.1.0a17`,
Kernel `0.1.0a100`, the CP wheel built from the revision under
test, and a test-only Foundation wheel built from exact Starter source
`d74bf8dd8c399dd92047174365403b861f82ddd0`.

The workflow is the executable recipe: it verifies the private wheel hashes,
builds and installs the two local test wheels without resolving private
credentials, checks installed versions and import origins outside the checkout,
migrates a disposable PostgreSQL database as `app_admin`, and invokes the
suite as `platform_api`. Its JUnit gate requires exactly eleven passing cases
and zero skips. This source validation build is not a Foundation candidate
allocation, publication, runtime dependency or rehearsal receipt.

The ten component cases exercise real Control context resolution, Foundation
attestation-pair verification, and Control's sole finalizer with the complete
`FoundationDispatchConsumptionV1` signed authorization/dispatch pair. Expected
business facts come from Control-owned rows, not from the presented envelope.
They prove positive verification, tamper and semantic-binding refusal, fresh
revocation/expiry checks, durable consumption and component commit ordering.

These ten cases use a **test-owned driver**, not CP's obsolete pre-V3
`admit_and_launch_host_source` reference. That reference no longer matches
Control's finalizer and is not an executable compatibility path for a17.
The former claims that this suite proved CP's positive orchestration are
retired, along with the historical manual recipe that built obsolete sources.

The eleventh case exercises CP's real `compose_foundation_v3_providers`:
genuine Foundation F2 verifies the pair and checks its actual installed wheel,
then the V3 provider reads the real approval-requiring plan and refuses with
`c2_dispatch_approval_subject_unavailable` before finalization or consumption.
It proves separate sessions and no committed marker. This is the C2-D1
fail-closed boundary, not a failed adoption claim: positive CP execution still
requires Gate 3's owned Approvals subject/barrier and eligible Foundation
release. This change neither bypasses that boundary nor launches a workload.

The signature adapters are deterministic SHA-256/HMAC **test doubles**, not
Ed25519. The tests execute real component verification logic and reject
tampering, but do not prove asymmetric signer custody, OIDC, live controller
authentication, deployment, or end-to-end execution authority.

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
execute again before merge. Record its exact CP revision, released Control
source/tag/verify coordinates, Foundation source commit, all installed wheel
hashes/import origins, migration heads and the eleven-case/no-skip result.
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
