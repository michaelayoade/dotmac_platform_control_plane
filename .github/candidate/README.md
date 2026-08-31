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
