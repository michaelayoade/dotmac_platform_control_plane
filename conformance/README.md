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

If `CONFORMANCE_DATABASE_URL` is unset, every test in this suite skips
cleanly rather than erroring -- this is what lets the suite live in this
repository today without ever breaking an accidental `pytest conformance/`
invocation before the real dependencies exist. Once it IS set, a real defect
(a missing wheel, a stale API, a broken leaf import) fails collection loudly
instead of skipping -- see the module docstring. A genuine run with
`CONFORMANCE_DATABASE_URL` set must report **zero skipped** tests; any skip
under that condition means the run did not actually execute what it claims
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
silently move CP's own pin off `dotmac-deployment-control==0.1.0a6`, which is
its own, separate, deliberate decision (see `adapter.py`'s host-admission
section docstring and this repository's `pyproject.toml` comments above the
`dotmac-deployment-control` pin).
