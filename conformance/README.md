# Host-admission conformance suite

Proves CP's `admit_and_launch_host_source` orchestration
(`src/vendor_cp/deployment/adapter.py`) against the REAL
`dotmac_deployment_control` and `dotmac_deployment_foundation` functions --
real Ed25519 signatures, real PostgreSQL, real transaction semantics. The
fast unit tests in `tests/unit/test_host_admission_adapter.py` prove the
adapter's own wiring with injected fakes; this suite proves those fakes were
faithful to the real implementations.

This directory is deliberately OUTSIDE `tests/` (this repo's `pyproject.toml`
pins `testpaths = ["tests"]`), so a normal `pytest` invocation in this
repository never collects it and never tries to import
`dotmac_deployment_control`'s or `dotmac_deployment_foundation`'s real, not-
yet-installable APIs. Nothing here is run as part of this repository's normal
CI. It exists so the suite is ready to execute the moment both real
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

Never run this suite against a branch tip. Only exact, verified merge
commits, recorded in the evidence this suite's execution produces.

## Build the two wheels (NOT done by this scaffold -- a later manual step)

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

Always pin to the exact merge-commit SHA, never a branch tip -- re-resolve
both SHAs with `gh pr view <n> --json mergeCommit,state` immediately before
this step, since either could be superseded by a later force-push-free merge
of a follow-up PR.

## Install into a disposable environment (NOT this repo's own .venv, NOT pyproject.toml)

    python3 -m venv /tmp/host-admission-conformance-venv
    /tmp/host-admission-conformance-venv/bin/pip install \
      /tmp/foundation-conformance-build/dist/dotmac_deployment_foundation-*.whl \
      /tmp/control-conformance-build/dist/dotmac_deployment_control-*.whl \
      -r conformance/requirements.txt

`conformance/requirements.txt` also brings in this repo's own runtime
dependencies the suite needs directly (`sqlalchemy`, `cryptography`,
`psycopg`, `alembic`, `pytest`) -- `dotmac-kernel` itself is already a real,
installed dependency of this repository (pinned `0.1.0a98`) and is reused
from this repo's own `.venv`'s resolution; it does not need a separate wheel
here, since `PlatformIdempotencyRecord`, `install_audit_actions`, and `Base`
already import successfully in this repo today.

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

If `CONFORMANCE_DATABASE_URL` is unset, every test in this suite skips
cleanly rather than erroring -- this is what lets the suite live in this
repository today without ever breaking an accidental `pytest conformance/`
invocation before the real dependencies exist.

## Evidence to record

For marking PR #192 ready for review, record:

- Both exact merge-commit SHAs actually used (re-verified at run time, not
  copied from this file, in case either has since been superseded).
- The exact wheel filenames actually installed (`pip list` or `pip freeze`
  from the disposable venv).
- The full `pytest conformance/ -v` output.
- The PostgreSQL server/database identity the suite ran against (never a
  connection string containing credentials -- name the host, not the DSN).

Do NOT run this suite against this repository's own `.venv`, commit its
disposable venv or wheel artifacts, or edit `pyproject.toml`/`poetry.lock` to
make it installable in this repository's own environment -- that would
silently move CP's own pin off `dotmac-deployment-control==0.1.0a6`, which is
its own, separate, deliberate decision (see `adapter.py`'s host-admission
section docstring and this repository's `pyproject.toml` comments above the
`dotmac-deployment-control` pin).
