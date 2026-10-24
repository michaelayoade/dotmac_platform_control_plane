# Candidate acceptance

Two files and a declaration, all consumed by
`.github/workflows/production-image.yml` **before** anything reaches the
registry.

| file | what it is |
| --- | --- |
| `acceptance.sh` | the battery every candidate must pass to be publishable |
| `ui-assets.expected` | the exact asset inventory the artifact is required to serve |
| `required-gates.json` | the checks a source revision must have passed |

## Why this is not under `scripts/`

`scripts/` holds production instructions, and those are being retired into the
installed console script. This is a CI-only harness that must never become a
production entry point — `vendor_cp.installed_surface` refuses new
`scripts/`-shaped production invocations, and putting an acceptance runner there
would have been the first one.

## `ui-assets.expected`

Two lines: the number of files the artifact serves under its static root, and a
SHA-256 over the sorted `name  sha256` manifest of all of them.

It is an exact expectation rather than a lower bound because the failure it
catches is silent. An image built against a different design-system version
serves different bytes at the same URLs, and every page still renders — so
nothing else in the pipeline would notice. Regenerating it is therefore a
deliberate act, and the diff shows a reviewer that the UI surface moved:

```bash
docker run --rm --entrypoint python <candidate> -c "
import hashlib, pathlib
from dotmac_kernel.templating import static_dir
root = pathlib.Path(static_dir())
entries = sorted(
    (p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
    for p in root.rglob('*') if p.is_file())
manifest = '\n'.join(f'{n}  {d}' for n, d in entries)
print(len(entries)); print(hashlib.sha256(manifest.encode()).hexdigest())"
```

## `required-gates.json`

The check-run names a source revision must carry, all `completed/success`,
before a candidate may be built from it. It is compared against the workflow
files in both directions by
`tests/architecture/test_candidate_before_publication.py`, so a gate added to CI
and forgotten here — or listed here and quietly deleted from CI — fails the
build rather than silently weakening the admission rule.

A `skipped` conclusion is refused explicitly. A workflow reports success at the
run level when one of its jobs skipped, which is precisely the shape that lets
an unrun gate look like a passed one.

## Historical native transition trust boundary

`build_native_source_fixture.sh` rebuilds a disposable validation image from
immutable historical Git revision `348c31315efaaca9ea23ea7c025d137a3afaad74`.
It uses the existing read-only dependency BuildKit secret and never publishes
that image. It is **not** the byte-identical previous accepted release. Its
installed migrations construct v016 SQL; that state is **not** a production
capture. Both source and candidate coordinates are measured from genuine local
OCI exports, with descriptor digest/size, config, platform and layer joins.
These local manifest coordinates may differ from the later registry index;
publication independently joins the accepted config and layer identities.

`native_transition_acceptance.py` runs with `python -I` inside the exact
candidate, with imports checked against its installed library directories.
It copies the image's actual migration tree unchanged into a protected root,
retains actual Git objects without credential configuration, and checks the
migration bytes against the candidate's actual source revision. The historical
source descriptor is the verbatim pinned Git blob. The target descriptor is an
explicit CI prospective fixture bound to the candidate's observed OCI identity,
revision and installed heads; it does not promote the accepted descriptor.

The native migration, immutable store/reservation, fence, negative reconnect,
`PlatformCpRecoveryBundle` capture/verification, fresh PostgreSQL restore,
closed globals recipe, independent observer and transactional `app_admin`
connection are real owners. A narrow capture adapter maps only the exact
reviewed Compose database commands and logical image inspections to measured
fixture resources. Unknown commands fail closed. Source writer containers are
explicitly disposable fixtures with measured image identities and stopped
states, and only returned CIDs with verified run labels are cleaned up.
A disposable loopback HTTP maintenance gate supplies measured 503 and drain
counters; held HTTP and WebSocket connections prove both counters rise then
drain, and a new WebSocket Upgrade at the maintenance endpoint must receive 503.
Its endpoint and measurements are retained separately from the production-shaped stage record.

The GitHub authorization executable and environment-protection proof are
**explicitly synthetic**, even though the fixture's actor now names the
repository owner. The real `GhAttestationVerifier` validates their bindings;
the fixture does not establish actual GitHub approval, protected-environment
issuance or protection settings. This battery also does not establish
production maintenance, production routing or full host acceptance. Its report
states these limits alongside native success, restored heads and bound
catalogue comparison, host source-preflight `_observe` wrong-owner refusal
before DDL, the separate rollback-only database privilege probe, malformed
authorization/evidence and tree/revision sensitivity, and durable replay
refusal. It never issues a private migration capability or uses direct Alembic
as candidate deployment proof.

The PostgreSQL scratch image uses a measured immutable repository digest. Before
restore, the driver joins the running source database container's image ID to an
independent inspection of the requested PostgreSQL image and its digest reference.
A mutable input tag alone cannot establish the scratch image's identity.

The catalogue comparison preserves complete source and restored bytes with their
actual, potentially different digests. PostgreSQL 16 can reparse an array cast
into a different textual CHECK definition during dump/restore. The shared
comparison owner requires every other category, constraint identity and flag to
match exactly. For changed ordinary local table CHECKs only, PostgreSQL parses
both recorded expressions against the same restored table in temporary views;
their complete non-pretty view definitions must match. The views are never read,
and their creation is rolled back before the restored catalogue is remeasured.
Domains and unsupported inherited shapes fail closed. Recovery additionally
requires a fresh cluster; initial CI fixture comparisons use separate disposable
databases in one cluster. Offline evidence verification establishes complete
bindings to these root-measured parser outputs, not provenance against a
malicious root. No raw catalogue, expression or parser output is logged.
