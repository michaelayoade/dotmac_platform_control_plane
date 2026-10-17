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

## Private role qualification retention

The existing SSH conformance `role-image` job has an optional manual
`retention_packet_sha256` selection. PR, push and empty manual selections retain
only the existing public identity/smoke/network observations. Selected retention
uses the fixed `role-preflight PRIVATE_DIR`, `role-inspect PRIVATE_DIR`, and
`role PRIVATE_DIR` entrypoints in the existing inspector/retention owners.
The role profile fixes `gate0-role`, Ubuntu 24.04's Dockerfile digest,
`linux/amd64`, this workflow/job, and `gate0-role-qualification-runtime`.
No CLI argument or packet chooses a target, recipient, workflow or command.
The original publisher CLI, schemas, targets and public/private output names
remain publisher-only.

A closed canonical `DotmacRoleRuntimeQualificationRetentionExecution.v1` packet
adds the fixed `purpose: private-native-qualification-input-only` to the existing
publisher packet's top-level field grammar. Its build has exactly `mode`,
`platform`, `base_image`, `target`; its source file hashes additionally cover the
native preparation/artifact/smoke/network owners. Its GitHub coordinates must
match authenticated current manual same-repository named-branch metadata, exact
source/workflow bytes, actor and numeric attempt-1 job. This admits reviewed
candidate bytes for qualification transport and grants no production admission.
The fixed existing public recipient is reused. Role tool validation requires a
genuine `DotmacRoleRuntimeGpgQualification.v1` record with
`role-runtime-public-key-encryption.v1`; a publisher record is refused.
This source work creates no operational record or repository configuration.

Only a completed encrypted bundle and closed
`Gate0RoleQualificationProducerReceipt.v1` receipt are staged for the exact
two-file artifact, for 30 days without overwrite. The receipt's existing
publisher fields additionally carry the fixed `purpose` and
`image_target: gate0-role`. No future artifact identifier or native acceptance
claim is generated. The private inner archive contains exactly
`role-rootfs.tar.gz`, `files.json`, `build.json`, `qualification.json`.

`Gate0RoleQualificationFiles.v1` retains the complete sorted roster with exact
row keys `path,type,mode,uid,gid,size,sha256,link_target`. The separate role policy
retains traversal, sparse, duplicate, special-file, credential/cache, protected
ownership/write/hardlink/ancestry refusals. Only exact app project/lock inputs,
Poetry's installed environment, fixed native Python links, `lib64 -> lib`, and
bounded dependency sibling links are admitted in protected paths. It never
uses an unprotected inventory as rootfs acceptance. The role Dockerfile alone
disables pip caching and removes the two known dependency caches; it fails if
unexpected cache material remains. Other Docker stages are unchanged.

`Gate0RoleSyntheticQualification.v1` has exactly
`schema,purpose,source_revision,image_id,smoke_sha256,network_sha256,smoke,network,live_readiness,installed_native_qualified,operationally_accepted,gate0_accepted`.
It embeds the actual existing smoke and network documents after their existing
owner predicates pass and hashes their original bytes. All four terminal
acceptance fields are false. Measured Python/SSL/psycopg/native versions remain
measurements, not installed launch or full WireGuard qualification.

`Gate0RoleQualificationPrivateBuild.v1` has exactly
`schema,source,producer,images,runtime,limits,footprint,tool_qualification_sha256`.
`source` carries revision/workflow/source-file hashes; `producer` uses the
existing authenticated numeric producer fields. `images` is exactly `base,role`:
the fixed base reference/ID/ordered diffIDs, and the actual role target/ID/source
label/diffIDs/inspection SHA plus actual config SHA/size from the saved image.
The never-started export container must name this immutable image ID, have no
mounts and remain created. The same ID is passed to smoke, network and the one
export; no postcheck rebuild, re-export or mutable tag selects retained bytes.

The closed role `runtime` keys are:

- `uncompressed_tar_sha256`, `uncompressed_tar_bytes`
- `compressed_archive_sha256`, `compressed_archive_bytes`
- `files_manifest_sha256`, `files_manifest_bytes`
- `qualification_manifest_sha256`, `qualification_manifest_bytes`
- `distribution_manifest_sha256`, `role_wheel_sha256`
- `foundation_profile_sha256`, `deployment_declarations_sha256`
- `migration_heads_sha256`, `native_tools_sha256`

All are measured from the held actual export or resulting private bytes. The
wheel's installed owner bytes and complete application owner closure, actual
project/lock inputs, profile/declarations/wheel/source joins, native binary
inventory/source pins and fixed role UID/home custody are checked as bounded
data. No member is executed or extracted. `footprint` has exactly
`entries,regular_files,regular_bytes,largest_member_bytes,role_tar_bytes`;
packet limits can only narrow the publisher maxima. Role footprint and actual
hosted image compatibility remain unmeasured until hosted validation.

Packaging's original wall/monotonic clocks start after build/smoke/network,
before preflight/export/inspection. Packet/tool expiry shortens the 1200-second
bound with a 20-second cleanup reserve. A single outer timeout covers export,
inspection and packaging; helpers recheck the original clocks and re-inventory
and compress the same held descriptor. Completion names are removed on helper
failure. Workflow upload follows successful owned-container cleanup, then all
owned private/staging paths are removed. Cancellation relies on the workflow's
`always()` cleanup; missing cleanup confirmation fails the job. This source
contract adds no decryption, extraction, installer or native qualification runner.

Role base inspection accepts Docker's precise tag-free `ubuntu@sha256:<pinned
manifest digest>` RepoDigest as equivalent to the source-pinned
`ubuntu:24.04@sha256:<same digest>`, checking the exact repository and digest.
The actual base image ID and ordered layer prefix remain measured and bound.
Publisher base-reference matching remains unchanged. Role completion uses the
existing publisher no-overwrite link/unlink primitive and tracks FD-derived
inode identities; refusal cleans only completion files created by that attempt,
preserving preexisting outputs and replacement inodes. Focused hosted canaries
exercise actual role context, image/config/tar inspection, compression, complete
archive/receipt binding, expiry and deterministic byte/filesystem faults. Actual
provider output and image footprint remain unmeasured by source-only checks.

Ordinary hosted `role-image` CI now checks the actual already-smoked immutable
role image export before uploading its existing public observations. The bounded
`conformance/check_gate0_role_export.py` adapter calls the same pure image/config
and rootfs/subject/roster joins used by retention, with current checkout hashes
and unchanged maximum limits. It creates no operational packet, authentication
context, certificate use, encryption, producer receipt or accepted runtime. It
logs only bounded count/hash measurements and false readiness, without a new
artifact or private member/roster logging. A five-minute original clock reserves
twenty seconds for exact owned-container cleanup; the workflow adds a hard timeout
and an `always()` cleanup fallback with the held CID and private directory.

This check runs only for ordinary events or empty manual selection. Selected
manual retention uses its existing one export and inspection path, with no second
source-conformance export. The ordinary check uses a separate owner-private
folder and never-started container, pulls only the exact pinned source base when
needed, and deletes no unrelated container or image. Its measurements are hosted
source-conformance evidence, never retained-runtime or native launch acceptance.

Both ordinary source conformance and selected retention now reuse the fixed
export creation/cleanup owner in the already role-pinned retention helper.
Selected workflow calls only its `role-export-create PRIVATE_DIR` and
`role-export-cleanup PRIVATE_DIR` entries; it executes no unpinned conformance
adapter. Creation writes closed private attempt/CID ownership records with the
captured fixed name, immutable image ID, original deadline, private-directory
identity and held CID-file identity. Every removal independently inspects the
strict CID and requires exact actual ID/name/image matches. Unknown, missing or
changed custody preserves the CID/private folder and fails; final recursive
cleanup requires confirmed ownership cleanup. Focused hosted canaries exercise
actual record/descriptor validation and wrong CID/name/image/inode refusals.
