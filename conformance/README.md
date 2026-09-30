# Conformance suites

The host-admission suite below is database-backed. The separate D16
source-verifier test is read-only and database-free; its requirements and
command are at the end of this file. An explicit whole-directory run still
requires the host-admission database precondition.

## Host-admission suite

Proves CP's `admit_and_launch_host_source` orchestration
(`src/vendor_cp/deployment/host_admission_adapter.py`, a leaf module -- see
its own docstring) against the REAL `dotmac_deployment_control` and
`dotmac_deployment_foundation` functions -- real PostgreSQL, real
transaction/locking semantics, real Foundation/Control refusal codes. Every
signer/verifier is a deterministic SHA-256/HMAC double, NOT real Ed25519 --
see the test module's own docstring for why that is still a legitimate proof
of the real function logic (the functions under test only call an injected
verifier's boolean-returning method; they never inspect its internals). The
fast unit tests in `tests/unit/test_host_admission_adapter.py` prove the
adapter's own wiring with injected fakes; this suite proves those fakes were
faithful to the real implementations.

This directory is deliberately OUTSIDE `tests/` (this repo's `pyproject.toml`
pins `testpaths = ["tests"]`), so a normal `pytest` invocation in this
repository never collects it and never tries to import
`dotmac_deployment_control`'s or `dotmac_deployment_foundation`'s real, not-
yet-installable APIs. The host-admission file is not run as part of this
repository's normal CI; the D16 file is invoked explicitly by the required
`check` job. The host-admission suite exists so it is ready once both real
dependencies are installable, without anyone having to reconstruct the real
fixture-building patterns from scratch under time pressure.

## Preconditions

1. **Control's ADR-0073 host-admission redesign** -- already merged:
   https://github.com/michaelayoade/dotmac_deployment_control/pull/58
   merge-commit SHA: `71641077b6a8115c40ce0f22eac6a2e945a2e544`
   (confirmed via `gh pr view 58 --repo michaelayoade/dotmac_deployment_control
   --json mergeCommit,state` at scaffold time -- 2026-09-22).

2. **Foundation's ADR-0073 attestation-pair redesign** -- lives in
   `dotmac_starter_mt` as the `packages/dotmac-deployment-foundation`
   sub-package, NOT as a standalone repository. As of scaffold time
   (2026-09-22) it is ALSO already merged:
   https://github.com/michaelayoade/dotmac_starter_mt/pull/742
   merge-commit SHA: `47a116d8d4490470fcff2784fc655102d1a78d09`
   (confirmed via `gh pr view 742 --repo michaelayoade/dotmac_starter_mt
   --json mergeCommit,state`).

   **Correction to this suite's original brief:** the brief that produced
   this scaffold assumed PR #742 had not merged yet and assumed Foundation
   was its own standalone repository clonable at a bare `<repo-url>`. Both
   assumptions are wrong as of the date above -- record the ACTUAL state
   (both merged, both SHAs above) rather than the brief's stale claim before
   this suite is ever run. Re-verify both merge states and SHAs again
   immediately before building wheels, since more time may have passed.

Never run this suite against a branch tip for Control or Foundation -- only
exact, verified merge commits, recorded in the evidence this suite's
execution produces. **CP's own wheel is the one exception**: it is built from
whatever commit on THIS branch is under test (the code being proven, not an
external dependency), and is rebuilt whenever that code changes.

3. **CP's own host-admission adapter** --
   `src/vendor_cp/deployment/host_admission_adapter.py`, a deliberate LEAF
   module (stdlib + SQLAlchemy only -- see its own docstring and
   `tests/architecture/test_host_admission_adapter_import_boundary.py`).
   Built from THIS repository's current branch HEAD, not a merge commit --
   there is nothing external to pin yet.

## Build the wheels (NOT done by this scaffold -- a later manual step)

**Control** (its own repository):

    git clone https://github.com/michaelayoade/dotmac_deployment_control.git /tmp/control-conformance-build
    cd /tmp/control-conformance-build
    git checkout 71641077b6a8115c40ce0f22eac6a2e945a2e544
    poetry build   # or: python -m build
    # produces dist/dotmac_deployment_control-*.whl

**Foundation** (a sub-package inside `dotmac_starter_mt` -- build from that
subdirectory, not the monorepo root):

    git clone https://github.com/michaelayoade/dotmac_starter_mt.git /tmp/foundation-conformance-build
    cd /tmp/foundation-conformance-build
    git checkout 47a116d8d4490470fcff2784fc655102d1a78d09
    cd packages/dotmac-deployment-foundation
    poetry build   # or: python -m build
    # produces dist/dotmac_deployment_foundation-*.whl

Always pin Control and Foundation to the exact merge-commit SHA, never a
branch tip -- re-resolve both SHAs with `gh pr view <n> --json
mergeCommit,state` immediately before this step, since either could be
superseded by a later force-push-free merge of a follow-up PR.

**CP** (this repository, current branch -- NOT a merge commit, this is the
code under test):

    cd <this repository's own checkout>
    git rev-parse HEAD   # record this in the evidence -- it moves as fixes land
    poetry build         # or: python -m build
    # produces dist/dotmac_platform_control_plane-*.whl (or vendor_cp-*.whl,
    # whatever the current distribution name is -- check dist/ after building)

This is a NORMAL, whole-repository `poetry build` -- it is the `--no-deps`
install below, not a special narrow build, that keeps the leaf boundary real.
Nothing besides `vendor_cp/__init__.py`, `vendor_cp/deployment/__init__.py`
(both docstring-only, no imports) and
`vendor_cp/deployment/host_admission_adapter.py` itself ever actually
executes, because the conformance suite imports only that one submodule.

## Install into a disposable environment (NOT this repo's own .venv, NOT pyproject.toml)

    python3 -m venv /tmp/host-admission-conformance-venv
    /tmp/host-admission-conformance-venv/bin/pip install \
      /tmp/foundation-conformance-build/dist/dotmac_deployment_foundation-*.whl \
      /tmp/control-conformance-build/dist/dotmac_deployment_control-*.whl \
      -r conformance/requirements.txt
    # `dotmac-kernel` itself needs the private Forgejo registry -- see
    # requirements.txt's own comment on why it is NOT reused from this
    # repo's own .venv (a disposable venv has nothing to derive it from).

    # CP's own wheel, installed SEPARATELY and with --no-deps: this is what
    # actually proves the leaf boundary. If host_admission_adapter.py ever
    # regains a vendor_cp/dotmac_kernel/fastapi import, THIS install fails
    # with a real ModuleNotFoundError the moment the suite tries to import
    # it -- the architecture test catches the same regression earlier, at
    # ordinary `pytest tests/` time, without needing this venv at all.
    /tmp/host-admission-conformance-venv/bin/pip install --no-deps \
      dist/dotmac_platform_control_plane-*.whl   # built in this repo, above

## Database

Control's `resolve_host_admission_context`/`admit_and_consume_host_admission`
need a real, migrated PostgreSQL `mod_deploy` schema (SQLite cannot express
the row-locking behavior this suite proves -- see
`host_admission_coordinator.py`'s own module docstring on why resolve takes
no lock and admit re-locks and re-derives everything fresh). Run against the
dedicated test server's PostgreSQL, never a local/workstation Docker
container -- per standing policy, tests never start a local daemon or
container. Apply Control's own Alembic migrations from the exact checked-out
commit before running:

    DATABASE_URL=postgresql://<test-server-dsn> \
      /tmp/host-admission-conformance-venv/bin/python -m alembic \
      -c /tmp/control-conformance-build/alembic.ini upgrade head

(adjust the alembic invocation to however Control's own repository documents
running its migrations against an external database -- check its own
`Makefile`/`AGENTS.md` at the pinned commit rather than assuming this
one-liner is exact).

## Run

    CONFORMANCE_DATABASE_URL=postgresql://<test-server-dsn> \
      /tmp/host-admission-conformance-venv/bin/pytest conformance/ -v

There is NO skip anywhere in this suite. For a host-admission or whole-directory
invocation, if `CONFORMANCE_DATABASE_URL` is unset,
`conformance/conftest.py`'s `pytest_configure` raises a hard
`pytest.UsageError` before collection even starts -- a loud, non-zero-exit
usage error, never a quiet "0 passed, N skipped" that could be mistaken for
a pass. `conformance/` is excluded from default `testpaths`, so an explicit
`pytest conformance/` invocation is always a deliberate
act, and this suite treats "not configured" the same as any other real
defect (a missing wheel, a stale API, a broken leaf import): fail loudly,
never skip. A genuine run with `CONFORMANCE_DATABASE_URL` set must report
**zero skipped** tests; any skip under that condition means the run did not
actually execute what it claims
to.

## Evidence to record

For marking PR #192 ready for review, record:

- Both exact merge-commit SHAs actually used for Control and Foundation
  (re-verified at run time, not copied from this file, in case either has
  since been superseded), plus the exact CP commit (`git rev-parse HEAD`)
  the CP wheel was built from.
- The exact wheel filenames actually installed (`pip list` or `pip freeze`
  from the disposable venv), including the CP wheel installed with
  `--no-deps`.
- The full `pytest conformance/ -v` output, showing zero skipped.
- The PostgreSQL server/database identity the suite ran against (never a
  connection string containing credentials -- name the host, not the DSN).

Do NOT run this suite against this repository's own `.venv`, commit its
disposable venv or wheel artifacts, or edit `pyproject.toml`/`poetry.lock` to
make it installable in this repository's own environment -- that would
silently change CP's exact `dotmac-deployment-control` pin, which is
its own, separate, deliberate decision (see
`host_admission_adapter.py`'s own module docstring and this repository's
`pyproject.toml` comments above the `dotmac-deployment-control` pin).

## Mandatory re-run gate for future host-admission pin changes

As of this change, `dotmac-deployment-control` is pinned at `0.1.0a16`;
`dotmac-deployment-foundation` is still not a CP dependency. Ordinary mypy
does not type-check `conformance/` against the real functions. The Protocols in
`host_admission_adapter.py` are proven to match the real functions ONLY by
this suite's runtime execution, at the exact commits recorded above.

Any future PR that changes the Control pin, or adds/changes
`dotmac-deployment-foundation` as a real dependency, MUST re-run this
suite against wheels built from the new pinned commits and record fresh
evidence in that PR, before merge -- not as a follow-up. A signature change
on either real function with no test anywhere in CI to catch it is exactly
the gap this gate closes.

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
