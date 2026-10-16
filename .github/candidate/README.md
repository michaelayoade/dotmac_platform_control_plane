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

## Publisher private inventory

`inspect_gate0_publisher.py inspect PRODUCTION PUBLISHER SHAPE OUTPUT [FILES]`
compares the actual production manifest and installed source owners against the
publisher wheel and dependency closure. It does not retain a production wheel
or qualify an installation. Optional `FILES` is a canonical complete private
roster: path, type, full mode, UID/GID, size, regular-file SHA-256 and link target.
Members are hashed in bounded chunks without extraction. Inputs must be owned
regular single-link files with owner-only permissions; descriptors remain held.
Outputs are exclusive owner-only files.

Fixed candidate ceilings are 8 GiB per rootfs tar, 250,000 entries, 512 MiB per
regular file, 4 KiB per path/link target, 128 MiB for the files roster, and 1 MiB
for shape/source-owner data. The hosted image step logs aggregate footprint
counts only and keeps the roster under private `RUNNER_TEMP` cleanup. Exceeding
a ceiling refuses inspection; it never increases a limit dynamically.

The adopted encrypted runtime design is design-only. Encryption, public runtime
upload, retained-artifact acceptance, custody use and native installation need
the separately reviewed implementation and operational authorization. Ordinary
CI currently builds and privately inspects the publisher, then deletes it.

`retain_gate0_publisher.py` is the separate runtime mechanism. The optional
`workflow_dispatch.retention_packet_sha256` selects exact canonical bytes of
`DotmacPublisherRuntimeRetentionExecution.v1`; the adopted design digest cannot
stand in for that execution packet. Push, pull request and empty manual inputs
continue to inspect privately and delete the runtime. A nonempty input refuses
unless source/ref/workflow, authenticated current run/attempt/image job, exact
recipient and qualified native tools match the closed packet. Fixed nonsecret
repository configuration variables deliver packet JSON, base64 public
certificate and qualified-tool JSON; absent configuration refuses. This change
provisions none of them and authorizes no dispatch.

The original private packaging clock bounds the whole publisher step to twenty
minutes, reserving cleanup time; packet/tool expiry can only shorten it. The
same inspected publisher export is gzip-compressed once with reproducible
headers. The inner archive contains exactly `publisher-rootfs.tar.gz`,
`files.json`, `build.json` and `shape.json`. The private build manifest binds
source/workflow/tools, actual immutable image identities and base layer prefix,
compressed/uncompressed archive bytes, complete roster, distribution/wheel
identities, shape and applied limits. It contains no future ciphertext, receipt
or artifact identity.

The production entrypoint uses the fixed public-certificate digest and forced
primary encryption fingerprint. It checks public-only primary certificate
packets, actual self signatures, current encryption usability, isolated GnuPG
configuration and the measured `/usr/bin/gpg` package/tool identity. Encryption
uses AES-256, MDC and no GnuPG compression. A separate streaming runtime parser
requires one selected-recipient PKESK followed by version-1 tag 18 and exact
EOF. Ciphertext is capped at 2 GiB plus 160 MiB; compressed rootfs at 2 GiB.
Only complete ciphertext and the closed producer receipt become eligible for
the exact two-file, thirty-day public CI transport artifact. Failure uploads
nothing; private staging and public transport staging are cleaned explicitly.

The packet checksum is selection, not approval or authentication of origin.
Michael's existing concrete operational review and coordinator dispatch remain
outside this helper. Coordinator authenticated artifact/job/download readback
and workstation exact-byte retention are still required later; no artifact ID
is inserted into its own producer receipt. These sources and synthetic tests
have not qualified production B, runtime encryption/decryption, retention,
native tools or installation. The dedicated hosted synthetic GPG unittest lane
uses a new ephemeral recipient and exercises actual roundtrip/roster/refusals;
it never receives a production certificate or custody material.
