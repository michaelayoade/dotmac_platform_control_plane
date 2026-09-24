# Disposable Control a14 rehearsal issuer proof

This directory is an explicit, candidate-independent test suite. It does not
compose the Platform CP application, launch Foundation, or deploy anything.
It creates a new scratch PostgreSQL database on the named test server, applies
only installed Kernel a100 and Control a14 lineages, exercises Control's real
issuer and ledger, and drops that scratch database after the run. The provided
database URL must connect to a dedicated test server with `app_admin`,
`platform_api`, and `app_user` roles. The `app_admin` role must have
`CREATEROLE`, required by the installed Kernel migration lineage; the harness
checks this before creating a scratch database and never grants or alters roles.
No database URL is checked in.

Install the complete public dependency closure from
`public-requirements.lock` with pip's `--require-hashes`, then install the two
locally supplied private wheels with `--no-index --no-deps`. The public lock
was derived offline from exact a100/a14 wheel METADATA and the existing
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
```

```sh
REHEARSAL_ISSUER_DATABASE_URL='postgresql+psycopg://<test-server-admin-dsn>' \
  <isolated-python> -m pytest rehearsal_issuer_harness/ -q \
  --control-wheel /path/to/dotmac_deployment_control-0.1.0a14-py3-none-any.whl \
  --kernel-wheel /path/to/dotmac_kernel-0.1.0a100-py3-none-any.whl \
  --public-wheelhouse /path/to/public-wheelhouse
```

Missing URL, wheel paths, the exact public wheelhouse, mismatched bytes,
installed versions, or import origins are hard errors. This suite is outside
the application's default `testpaths`.
Keys are generated in memory on each run and are never persisted or logged.
The approval seeded here is test data, not genuine protected-runner approval.
