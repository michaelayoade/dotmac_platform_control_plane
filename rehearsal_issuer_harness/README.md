# Disposable Control a14 rehearsal issuer proof

<!-- kernel-pin: snapshot -->

This directory is an explicit, candidate-independent test suite. It does not
compose the Platform CP application, launch Foundation, or deploy anything.
It creates a new scratch PostgreSQL database on the named test server, applies
only installed Kernel a100 and Control a14 lineages as `app_admin`, exercises
Control's real issuer and ledger as `platform_api` -- the real online CP
runtime role `dc_0014`'s own migration grants the rehearsal-issuer ledger to,
not the migrator that owns it -- and drops the scratch database after the run.

The provided database URL is the disposable `postgres` bootstrap identity --
the same one `deploy/postgres/init-roles.sh` itself runs as -- reached over
local trust auth (`docker-compose.test.yml`'s
`POSTGRES_HOST_AUTH_METHOD: trust`, so no password is needed). Bring up
`docker-compose.test.yml` first: it mounts `init-roles.sh`, which is what
creates the five production roles (`app_admin`, `app_user`, `platform_api`,
`outbox_dispatcher`, `platform_outbox_dispatcher`) with their exact
production attributes before this suite ever runs. The harness verifies
those five roles' exact contract -- `app_admin` is
`NOSUPERUSER NOCREATEROLE BYPASSRLS`, matching `docs/ARCHITECTURE.md`'s
"Production topology" exactly, never the elevated `CREATEROLE` an earlier
version of this harness wrongly required -- and it never grants or alters a
role itself; the only privileged statement it issues is
`CREATE DATABASE ... OWNER app_admin` for its own scratch database, and
`DROP DATABASE` at teardown. No database URL is checked in.

This repository's own wheel must also be installed, separately and with
`--no-deps`, into the same isolated environment: `test_issuer.py`/
`runtime.py` import `vendor_cp.deployment.rehearsal_issuer_seam`, and without
this step that import fails with `ModuleNotFoundError` the moment pytest
collects `rehearsal_issuer_harness/`. Build and install it exactly the way
`conformance/README.md` documents for the identical leaf-boundary reason: a
NORMAL, whole-repository `poetry build` -- not a narrow one -- is what keeps
the leaf boundary real, and the `--no-deps` install is what actually proves
it (a regression that reintroduces a `dotmac_kernel`/`fastapi` import into
the seam module fails this install with a genuine `ModuleNotFoundError`).

Install the complete public dependency closure from
`public-requirements.lock` with pip's `--require-hashes`, then install the
two locally supplied private wheels with `--no-index --no-deps`. The public
lock was derived offline from exact a100/a14 wheel METADATA and the existing
checked-in Poetry artifact hashes; it includes the `pydantic[email]` and
`psycopg[binary]` transitives and SQLAlchemy's Linux `greenlet` dependency
(31 public packages). Keep the public wheels selected by that install in a
dedicated wheelhouse and pass it to pytest. The suite verifies every selected
wheel's identity and hash, then compares its installed behavior-bearing bytes
with the wheel. It separately compares the supplied private wheel bytes and
METADATA with `artifacts.json` and checks their installed imports and bytes.
Wheel paths are supplied at execution, never stored in this repository.

```sh
<isolated-python> -m pip download --require-hashes \
  --dest /path/to/public-wheelhouse \
  -r rehearsal_issuer_harness/public-requirements.lock
<isolated-python> -m pip install --require-hashes --no-index \
  --find-links /path/to/public-wheelhouse \
  -r rehearsal_issuer_harness/public-requirements.lock
<isolated-python> -m pip install --no-index --no-deps \
  /path/to/dotmac_kernel-0.1.0a100-py3-none-any.whl \
  /path/to/dotmac_deployment_control-0.1.0a14-py3-none-any.whl

# This repository's own wheel -- built normally, installed separately and
# with --no-deps, exactly as conformance/README.md documents:
cd <this repository's own checkout>
poetry build   # or: python -m build
# produces dist/dotmac_vendor_control_plane-*.whl (check dist/ for the exact
# name -- it follows [tool.poetry].name in pyproject.toml)
<isolated-python> -m pip install --no-deps dist/dotmac_vendor_control_plane-*.whl
```

```sh
REHEARSAL_ISSUER_DATABASE_URL='postgresql+psycopg://postgres@<test-server-host>:<port>/<db>' \
  <isolated-python> -m pytest rehearsal_issuer_harness/ -q \
  --control-wheel /path/to/dotmac_deployment_control-0.1.0a14-py3-none-any.whl \
  --kernel-wheel /path/to/dotmac_kernel-0.1.0a100-py3-none-any.whl \
  --public-wheelhouse /path/to/public-wheelhouse
```

Missing URL, wheel paths, the exact public wheelhouse, mismatched bytes,
installed versions, or import origins are hard errors. This suite is outside
the application's default `testpaths`; `.github/workflows/rehearsal-issuer-harness.yml`
is what actually runs it in CI, on every pull request, with zero skips
permitted.
Keys are generated in memory on each run and are never persisted or logged.
The approval seeded here is test data, not genuine protected-runner approval.
