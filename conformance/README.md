# Conformance suites

## Host-admission components and CP approval composition

The required `rehearsal-issuer-harness` CI job runs
`test_host_admission_conformance.py` explicitly against released Control
`0.1.0a17`,
Kernel `0.1.0a100`, the CP wheel built from the revision under
test, released Approvals `0.1.0a8`, and a test-only Foundation wheel built from exact Starter source
`d74bf8dd8c399dd92047174365403b861f82ddd0`.

The workflow is the executable recipe: it verifies the private wheel hashes,
builds and installs the two local test wheels without resolving private
credentials, checks installed versions and import origins outside the checkout,
migrates a disposable PostgreSQL database as `app_admin`, and invokes the
suite as `platform_api`. The workflow and its exact-name JUnit inventory own
the required cases and zero-skip gate. The source inventory currently requires
24 collected cases; this is a collection expectation, not an observed passing
result. The historical eleven-case suite below
is the baseline; the new approval lifecycle coverage is pending hosted
validation and no new passing count is asserted here. This source validation
build is not a Foundation candidate
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

The baseline's eleventh case exercises CP's real `compose_foundation_v3_providers`:
genuine Foundation F2 verifies the pair and checks its actual installed wheel,
then the V3 provider reads the real approval-requiring plan and refuses with
`c2_dispatch_approval_subject_unavailable` before finalization or consumption.
It proves separate sessions and no committed marker. This is the C2-D1
fail-closed boundary. That public default retains its refusal even though the
separate source-only `compose_approved_foundation_v3_providers` now owns the
guarded path. Neither source composition is an installed executor binding or
runtime adoption claim.

Required hosted coverage for the new source contract must use real Approvals
`0.1.0a8` policy creation, request opening and decision recording, rather than
constructing `ApprovalEvidence` or inventing a decision reference. It must
exercise `propose_foundation_plan`, `open_foundation_approval`,
`approve_foundation_plan`, `request_foundation_rollout`,
`dispatch_foundation_attempt` and `finalize_foundation_dispatch`, with the
actual `compose_approved_foundation_v3_providers` factory. That factory binds
the actual Control functions and guarded owner; a self-authorizing callback
is not a substitute. The required evidence includes:

- genuine approval standing held by `held_transition` in the same transaction
  through each approval-dependent Control transition and the final commit;
- lifecycle helpers returning uncommitted state without committing, with one
  lifecycle stage per caller-owned transaction; preparation/decision commits
  release Control locks before the later approval `FOR SHARE` hold, preserving
  Approvals request -> Control target -> plan -> rollout order;
- concurrent withdrawal serialized against that hold through commit, using
  the prescribed lifecycle transaction boundaries;
- wrong subject, purpose, operation, digest, decision reference or frozen
  policy refused, along with unapproved/withdrawn standing and autocommit;
- default unguarded composition still refusing approval-dependent dispatch;
- real F2 verification, separate sessions and genuine Control finalization,
  with no host effect before genuine authority is consumed and committed;
- durable committed-consumption lookup and no committed marker on refusal.

This list states required coverage, not completed or passed tests. The caller
lock-order contract does not claim runtime detection of every possible
caller-held lock. Control's context expiry remains part of its existing
checks; no new approval TTL is
defined. Synchronous standing checks do not close asynchronous withdrawal
consequences: relay handling of the new subject remains open and the current
relay explicitly refuses unknown subjects.

Source/candidate-independent conformance is required before freeze. After the
single candidate build, exact installed-candidate rehearsal must separately
prove the adopted-path guarantees; published CP pinning/production activation
follows publication. Q2/Rule 49 remain open: installed Foundation CLI commands
still hardwire `RefusingHostSourceAdmissionProvider`, `ExecutionBindings` has
no admission field, and recovery lacks an `ExecutionGrant`/V3 consumption
path. Host provenance alone must not enable recovery. This work adds no
runtime Foundation dependency and authorizes no allocation, freeze, candidate
build/publication, governed execute or revival of the stopped issuer programme.

The signature adapters are deterministic SHA-256/HMAC **test doubles**, not
Ed25519. The tests execute real component verification logic and reject
tampering, but do not prove asymmetric signer custody, OIDC, live controller
authentication, deployment, or end-to-end execution authority.

The fixture uses Control's test reset hooks, stored-dispatch locator and marker
scope constant. These private test dependencies are not production imports;
they can change across releases and must be re-proven by this exact-wheel gate.
Public committed-consumption lookup independently checks every marker assertion.

## Preconditions and evidence

A normal `pytest tests/` run does not collect `conformance/`. An explicit
host-admission or whole-directory invocation requires
`CONFORMANCE_DATABASE_URL`, `CONFORMANCE_PRIVATE_WHEELHOUSE` and
`CONFORMANCE_PUBLIC_WHEELHOUSE`; the conftest hard-errors before collection
if any is absent. The private wheelhouse must include the Approvals `0.1.0a8`
wheel alongside Control and Kernel, at the exact filenames and hashes in
`rehearsal_issuer_harness/artifacts.json`. The in-process guard verifies these
private wheels, installed distributions and public-wheelhouse dependency
closure independently of the workflow download checks. Missing wheels,
symbols or incompatible API shapes fail collection; they are never converted
into skips.

In the prescribed isolated hosted environment, after migration and installation,
the host-admission invocation must supply all three inputs:

    CONFORMANCE_PRIVATE_WHEELHOUSE=/path/to/privatewheels \
      CONFORMANCE_PUBLIC_WHEELHOUSE=/path/to/publicwheelhouse \
      CONFORMANCE_DATABASE_URL="$DISPOSABLE_CONFORMANCE_DATABASE_URL" \
      pytest -q conformance/test_host_admission_conformance.py

The database variable above is supplied privately by the hosted fixture; do
not print it or substitute a credential-bearing literal into recorded commands.
The separate sshd workflow copies its standalone test files outside this
conftest's scope; that recipe does not waive the database suite's guards.

Use the workflow's migrated disposable database and closed dependency bundle,
not CP's existing workstation venv or a production database. Tests must never
start workstation Docker; the prescribed CI Docker environment is disposable.
Record only non-secret host/database identifiers, never credential-bearing
DSNs.

For every Control/Foundation pin change, the required isolated CI lane must
execute again before merge. Record its exact CP revision, released Control
source/tag/verify coordinates, Foundation source commit, all installed wheel
hashes/import origins, migration heads and the exact-inventory/no-skip result.
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
the database URL and both wheelhouses for the host-admission tests. Only the
explicit single-file D16 invocation above is exempt from those guards.
This is source-tool
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
