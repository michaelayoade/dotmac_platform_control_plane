# Gate 0 installed official gh release verifier — source candidate

This candidate verifies a GitHub release assertion using official `gh` 2.102.0,
source commit `fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd`. It grants no E
acceptance, workflow/reviewer approval, publication permission or B custody.
No installed binary, Linux profile, native receipt or operational installation
has been qualified by preparing this source. Missing qualification raises
`ATTESTATION_TRANSPORT_UNQUALIFIED` before a command runs.

`InstalledGhReleaseVerifier.from_installed()` has no caller options.
`verify_published(reads, facts)` accepts the exact concrete
`InstalledGate0GitHubReads` and its original `DownloadedReleaseFacts` object;
`reads.owns_facts(facts)` must hold. It does not perform a second snapshot read.
The reader's originally loaded installation and qualification must match the
fixed reader root binding pinned by this verifier. Constructing a DTO or parsing
JSON does not establish provenance. The adapter is single use even on failure.
Its returned frozen `VerifiedReleaseAssertion` is inert evidence.

## Installed input proposal

These new formats are source proposals requiring review and an operator-installed
native qualification. They are not an adopted lifecycle or an `accepted` flag.
All documents are strict bounded JSON with duplicate keys refused. Installation,
binding and qualification use canonical UTF-8 JSON (sorted keys, compact
separators, no trailing newline). Digests below are lowercase bare SHA256 hex.
A pin is exactly `{path, sha256}`. Pinned paths are absolute and read through the
existing GitHub owner's no-follow, protected-ancestry file reader.

Fixed `/run/dotmac-gate0-e/release-verifier.json` has exactly:

- `schema`: `Gate0EGhReleaseInstallation.v1`.
- `repository`: `{owner, name, repository_id, owner_id}`; IDs positive integers.
- `release`: `{release_id, tag, raw_tag_sha, peeled_commit, assets}`. The two Git
  hashes are independently selected 40-character SHA1 values. Assets are exactly
  ordered `gate0-evidence.pgp`, `gate0-evidence-public.json`,
  `gate0-readiness-receipt.json`, each `{id, name, size, sha256}` with distinct IDs.
- `gh`, `interpreter`, `qualification`: pins. `interpreter.path` must equal the
  real running interpreter path; the binary must be executable.

Fixed `/etc/dotmac-gate0-e/release-verifier-binding.json` has exactly:
`schema=Gate0EGhReleaseRootBinding.v1`, `installation_sha256`,
`qualification_sha256`, `native_receipt` (pin), `source_sha256`, `runtime_uid`,
`credential_uid`, `reader_binding_sha256`, `runtime_image_digest`.
Runtime UID must be nonzero and equal real/effective UID; credential UID is that
UID or root. `source_sha256` pins this wrapper's actual installed bytes.
`reader_binding_sha256` pins `/etc/dotmac-gate0-e/github-read-published-release-binding.json`.
The runtime image identity is an externally installed native trust input, not a
claim independently measured by a Python JSON parser.

Qualification has exactly:
`schema=Gate0EGhReleaseNativeQualification.v1`, `gh_source`, `gh_version`,
`installation_policy_sha256`, `resource_policy`, `runtime_uid`, `credential_uid`,
`kernel`, `boot_id`, `work_mountinfo_sha256`, `ca_sha256`, `source_sha256`,
`reader_binding_sha256`, `runtime_image_digest`, `output_profile`,
`process_profile`, `network_profile`, `native_receipt`.
The policy digest hashes canonical installation **excluding `qualification`**,
which avoids a circular pin. Qualification bytes and the installation bytes are
separately pinned by the root binding. The qualification's shared fields must
match the root binding; kernel/boot, mount record/capacity, interpreter, binary,
wrapper and CA bytes are checked against the actual runtime.

The profile names are fixed candidate values:
`gh-2.102-release-single-result-v1`,
`dedicated-uid-contained-gh-group-v1`, and
`github-release-tuf-ca-isolated-cache-v1` respectively. Naming a profile in JSON
cannot qualify it. The external native-review receipt uses the existing exact
`Gate0ENativeReviewReceipt.v1` shape: `schema`,
`qualification_measurements_digest`, `runtime_identity_digest`,
`reviewer_record_digest`. All three evidence digests are required. The installer
and independent operator review remain the trust source for those evidence
bytes and the dedicated UID, image, containment and network profile.

## Fixed invocation and joins

The adapter issues exactly one command:

```
gh release verify TAG --repo OWNER/REPO --format json
```

It then issues exactly three sequential commands with its own staged paths:

```
gh release verify-asset TAG OWNED_PATH --repo OWNER/REPO --format json
```

No latest-tag fallback, retries, caller command/path/deadline/trust-root options
or custom cryptography are provided. The fixed protected credential
`/run/dotmac-gate0-e/github-read-token` reaches only the child `GH_TOKEN`
environment. Child environment is an allowlist with `GH_HOST=github.com`,
private HOME/config/cache/scratch, noninteractive/no-update/no-color controls
and `GOMAXPROCS=2`; ambient proxy, debug, loader and custom-host variables are
excluded. Stderr is discarded and errors contain no diagnostics or credentials.
The parent clears its environment mapping on every exit; this does not claim
cryptographic erasure of Python's immutable strings or the external token file.

Each bounded output is one actual `AttestationProcessingResult` object, not an
array or a success Boolean. The verifier checks a nonnull result, recognized
media types, certificate-signature result and RFC3161 timestamp result shapes,
strict decoded DSSE data and semantic equality to the verified statement.
It does not verify signatures itself. That authority belongs to the actual
pinned child exiting zero after stdout EOF and wait/reap.

The independently authenticated repository/owner/release IDs and tag must match
canonical decimal-string predicate IDs. The exact signed roster contains the
release URI/PURL `pkg:github/OWNER/REPO@VERSION` and three distinct named asset
subjects; VERSION uses percent-encoded tag characters. The release URI carries
the **raw tag-ref SHA1**, and each named asset carries its exact SHA256.
The peeled commit remains a separate authenticated read fact. Every asset
command must return the same full statement as the release command; renamed,
extra, missing or duplicate subjects and cross-command rebindings refuse.

The actual pinned official fixture uses bundle media type
`application/vnd.dev.sigstore.bundle.v0.3+json`, a release subject `uri` rather
than `name`, optional omitted signature `keyid`, and empty reconstructed
`bundle_url`/`initiator`. The latter strings are not used as signer authority.
Primary sources: [official fixture](https://github.com/cli/cli/blob/fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd/pkg/cmd/attestation/test/data/github_release_bundle.json),
[official command policy](https://github.com/cli/cli/blob/fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd/pkg/cmd/release/shared/attestation.go),
[sigstore-go result type](https://github.com/sigstore/sigstore-go/blob/v1.3.0/pkg/verify/signed_entity.go).

## Actual resource and cleanup boundary

Candidate constants are 120 seconds aggregate, including a shared two-second
cleanup reserve, and 1 MiB stdout per command. Every command receives the same
absolute end. EOF, zero exit and wait must complete before its work end; cleanup
errors stay failures. Cancellation attempts group kill, independent owned-child
kill on group-kill failure, every pipe close and actual wait within that same end.
A reaped PID is never signaled. No new cleanup deadline is minted after failure.
The native-qualified fixed binary/process profile must prove group cancellation
contains all possible descendants; group kill alone does not establish that
property for arbitrary executables. Parent launch requires one actual Linux
`/proc/self/task` task before its fixed child-only rlimit setup.

Child kernel limits are address space 8 GiB, CPU 120 seconds, per-file output
32 MiB, open files 64, tasks per dedicated real UID 64 and core size zero.
These are candidate constants awaiting native measurement; `GOMEMLIMIT` is not
used as a security boundary. Dedicated UID isolation is required because the
kernel task limit applies to that UID. Per-file size is supplemented by a
separate actual tmpfs mounted at fixed `/run/dotmac-gate0-e/gh-work`, owner UID
mode0700, with total capacity at most 64 MiB and at most 4096 inodes. Its complete
mountinfo record is independently pinned. The private finite invocation uses
new mode0700 children and mode0600 staged assets with byte/hash/size/inode checks
before use and cleanup. Staged reads open with `O_NOFOLLOW|O_NONBLOCK`
before checking type and inode, so a substituted FIFO with no writer refuses
without blocking in open. Before/after I/O guards consume the original work
deadline; failure cleanup consumes only the original aggregate end. Expired or
uncertain checks retain evidence and refuse; no cleanup budget is reset.
Ciphertext is at most 17 MiB; public projection at most
64 KiB; readiness receipt at most 128 KiB. Only ciphertext and public documents
are staged; no collection plaintext, recipient private key or signing key.

An altered staged inode/bytes is a sticky refusal and can retain its private
work directory for investigation; successful verification requires actual
cleanup of the original owned directory. The adapter does not remove the
external read token or own outer runner key/certificate teardown.

Official gh retains its own GitHub trust/TUF/RFC3161 owner and default CA policy.
The fixed CA bytes are pinned. The wrapper does not count every internal HTTP
request or cap each attestation blob body. Qualification must measure actual
GitHub attestation blob destinations/redirects and TUF, isolated cache behavior,
CA/trust refresh and credential redirect isolation under these real outer
memory/CPU/storage/time limits.

## Validation owed

Only AST parsing and Ruff0.6.9 are authorized locally. Authored tests use actual
official JSON field shapes with deliberately fake signature bytes and mocked
process control; they do not qualify cryptography or a host. They cover complete
four-command orchestration, strict output/DSSE joins, raw versus peeled tag,
identity/asset tampering, closed installation and changed pins, caller DTO and
owner-binding rejection, once-only use, regular-file and actual FIFO inode
substitution before use and during cleanup, expired original deadlines,
retained substituted evidence, EOF/zero/wait,
shared deadline and cleanup faults.

Separately authorized Linux native qualification must bind the exact official
binary/source/image/interpreter, measure real signature success and wrong
byte/tag/identity refusal, verify the actual release/PURL/JSON vectors including
annotated tags, prove TUF/cache/CA/egress and credential isolation, and measure
resource enforcement, descendant containment, EOF/wait/kill/reap and cleanup
within the fixed reserve. A native failure requires reporting failure or an
explicit reviewed policy revision; it cannot silently increase limits. No host,
release verification, credential ceremony, publication or E acceptance is
performed by this source preparation.


## Public metadata and exact final reader slot

Initial load and runtime rechecks use `private=False` only for root-owned
nonwritable public installation/binding metadata, qualified source/binary/
interpreter/CA bytes and closed digest projections. Qualification is fixed at
`/etc/dotmac-gate0-e/release-verifier-qualification.json`; native projection is
`/etc/dotmac-gate0-e/release-verifier-native.json`. Private credentials and detailed
native measurement bodies retain their private restrictions.

Both initial qualification and `_reader_profile` read exactly
`/etc/dotmac-gate0-e/github-read-published-release-binding.json`.
`reader_binding_sha256` now means this actual published-release slot, matching the
final adapter's separate `from_installed_published_release()` owner. Default,
transfer or draft binding aliases do not qualify. Exact live reader installation/
qualification/source identity and official gh release/all-asset verification
remain mandatory.

The positive Linux runtime UID remains nonzero. Normal public leaves are root0644
with root0755 ancestry; source work does not alter an actual host. Repin wrapper/
reader source hashes, root bindings, qualification and native evidence for the
new access semantics and exact `reader_binding_sha256` meaning. Old measurements
cannot establish that qualification. Actual nonroot OS access/private credential
isolation and official native execution proof remain outstanding; mocked unit
boundaries and source checks are not acceptance.
