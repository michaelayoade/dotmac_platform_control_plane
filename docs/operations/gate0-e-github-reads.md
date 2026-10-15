# Gate 0 E finite GitHub reader candidate

This source candidate owns authenticated GET facts and exact encrypted bytes. It
creates no acceptance, prerequisite decision, signer, publication mutation or
readiness result. Operational installation, credential provision, native
qualification and actual GitHub reads remain separately authorized work. The
focused tests are supplied as source and have not been executed in this preparation.

`InstalledGate0GitHubReads.from_installed()` is the only supported constructor.
It loads `/run/dotmac-gate0-e/github-read.json` and requires a separate root-owned
`/etc/dotmac-gate0-e/github-read-binding.json`. The token is read privately from
`/run/dotmac-gate0-e/github-read-token`; no token or token digest enters output,
argv, DTOs or reports. Every path component is opened relative to an already
opened directory with `O_NOFOLLOW`; ancestry must be root owned and not group or
world writable. Selection, qualification, root binding and native receipt leaves
must be private root-owned regular files. The credential leaf UID is selected by
the root-reviewed qualification, either root or the exact runtime UID, with private
mode. The installed source file must be root owned, not writable by group/other,
and match the root binding SHA256. Runtime real/effective UIDs must match.

## Closed installation and external review records

All installation records are canonical ASCII JSON with sorted keys, compact
separators and no final newline. All fields below are required; null is supported
only as stated. Bare digest fields are 64 lowercase hex unless named projection
`*_digest`, which use `sha256:` followed by 64 lowercase hex. JSON matching pins
is a binding to an externally reviewed record, **not native proof** that a
measurement occurred. This reader cannot authorize its own root binding or issue
native receipts. Actual root installation, workload isolation, scoped credential
permissions, source review and native measurements must be reviewed outside it.
Missing records or inconsistent pins refuse.

The installation has exactly `schema`, `policy_digest`, `phase`, `repository`,
`producer`, `publication`, `transfer`, `release`, `download_origins`, `credential`,
`qualification`. Schema is `Gate0EGitHubReadInstallation.v1`; credential is the
fixed token path above. Qualification is `{path,digest}` under
`/etc/dotmac-gate0-e/`. Origins are a nonempty unique list of exact qualified
lowercase DNS names, without wildcards or IP literals. They are not inferred from
a redirect. No credentials are forwarded to them.

| Phase | Non-null selections | Method |
| --- | --- | --- |
| protected_job | producer | protected_job_snapshot(deadline=original provisioning end) |
| producer | producer | producer_snapshot(closed ProducerStage) |
| transfer | producer, transfer | encrypted_transfer() |
| draft | producer, release | draft_snapshot() |
| published | producer, release | published_snapshot() |
| publication | publication | publication_snapshot() |

Every other selection is null. Each owner has one method attempt for its installed
phase. Any method failure is sticky and invalidates `owns_facts()`. Later phases
need fresh exact installations, not retry loops. `owns_facts(result)` checks live
object identity; constructing a DTO, copying it or parsing JSON never restores
live provenance. Returned immutable DTOs carry private repr-disabled exact
observations and bytes. They have no acceptance/readiness field.

The protected-job phase observes an assigned, in-progress job before collection.
It preserves source, runner, review and policy checks without claiming future
step success. The exact source-pinned courier step must be in progress and all
its predecessors must have succeeded. Its one-use deadline is the earlier of the
original provisioning
end and the existing 90-second read cap. These GitHub facts do not authenticate
local PID/cgroup ownership; the native JIT launcher must supply that separately.
`PROTECTED_JOB_STARTED` marks only that courier step. Later producer stages
require its successful completion; it cannot mark the sole artifact-upload step.

Repository selection is `{owner,name,repository_id,owner_id}`. Run selection is
`{repository,workflow,run_id,attempt,head_sha,branch,event,actor_id,triggering_actor_id}`.
IDs are positive exact integers, never booleans. The first profile requires
attempt 1, main, workflow_dispatch, and workflow commit equal to head SHA. Workflow
selection is `{id,path,commit,blob_sha,sha256,job_key,job_name,environment_id,
environment_name,reviewer_id,runner_group_id,runner_id,runner_name,required_steps,
action_source_pins,source_policy_pin}`. Paths are fixed `.github/workflows/NAME.yml`
or `.yaml`; required steps have `{number,name,required_stage}`, in unique ordinal
order. Action pins are exact `owner/repository/path@40hex` strings. Dynamic jobs,
matrices, reusable workflows and dynamic artifact/environment selection are outside
this initial profile.

Transfer selection is `{artifact_id,name,expected_artifact_names,ciphertext_name,
projection_name}`, with fixed member names `gate0-evidence.pgp` and
`gate0-evidence-public.json`. Release selection is `{release_id,tag,commit,assets}`;
assets have `{id,name,size,sha256}`. Draft assets are exactly ciphertext then
projection; published assets add `gate0-readiness-receipt.json` third. Exact tag and
commit are root-selected; target_commitish is never commit proof.

The root binding has exactly `schema`, `installation_sha256`,
`qualification_sha256`, `source_sha256`, `native_receipt_pin`, `runtime_uid`, with
schema `Gate0EGitHubRootBinding.v1`. Its source hash pins this installed module.
The qualification has exactly `schema`, `installation_policy_digest`,
`native_receipt_pin`, `api_version`, `runtime_uid`, `credential_uid`, `permissions`,
`action_time`, `source_policy_digests`, `transfer_profile`, `immutable_setting`;
schema is `Gate0EGitHubNativeQualification.v1`, API version `2026-03-10`.
Permissions must record exact selected repository Metadata-read, Actions-read,
Contents-read, as `{metadata:"read",actions:"read",contents:"read",repository_id}`.
Read success does not prove token least privilege: actual App scope or effective
GITHUB_TOKEN job permissions must be measured in the external native packet.

The independently pinned native receipt has exactly `schema`,
`qualification_measurements_digest`, `runtime_identity_digest`,
`reviewer_record_digest`, with schema `Gate0ENativeReviewReceipt.v1`. These digests
refer to the external native review packet, not measurements fabricated by JSON.
`source_policy_digests` is the sorted exact list of selected source policy hashes.
For published reads `immutable_setting` is `{repository_id,state,response_sha256,
native_record_digest,observed_at}`, with state `enabled`, from the separately
qualified operator Administration-read observation. Routine reader permissions do
not expand to Administration. Draft reads do not claim immutable verification.

`action_time` maps decimal run IDs to closed records `{run_id,head_sha,runner_id,
runner_group_id,job_name,environment_id,qualified_at,protection_rules_sha256,
branch_policies_sha256,source_policy_digest,native_record_digest}`. Qualification
must predate the admitted job start and bind its actual runner, source and
protected environment. Current REST policy cannot prove historical protection.

Each root-reviewed source policy has schema `Gate0EGitHubSourcePolicy.v1` and
exactly `schema`, `workflow_sha256`, `workflow_blob_sha`, `job_key`, `job_name`,
`environment_id`, `environment_name`, `required_steps`, `action_source_pins`,
`mandatory_jobs`, `sole_artifact_step`, `publication_title`,
`selected_summary_digest`, `projection_sha256`, `ciphertext_sha256`,
`branch_policies`, `environment_rules`, `policy_digest`, `campaign_digest`,
`source_bundle_digest`. It maps the exact reviewed workflow bytes/blob to its job
key, unique job names, all step ordinals, sole upload step, environment and all
source dependencies. The client verifies the bytes against that reviewed map;
API display names alone are never a source proof. Branch policies are sorted
`{name,type}` records; protection rules bind the exact reviewed rule records.
Publication title and summary hash may be null outside publication. Optional
prior ciphertext/projection hashes may be null when first outputs have not yet
been independently observed. Release asset byte pins remain mandatory.

## Transport and finite observations

Only the finite enum-owned repository, selected workflow/source/run/attempt/jobs,
review, pending deployment, environment/branch policy, selected artifact,
selected release/assets and tag-ref/annotated-tag GET endpoints exist. Paths are
built from installed selections; response URLs never become API selectors. The
reader never uses search, newest/latest, logs, writes, generic gh or arbitrary
caller URLs. Tag peeling permits at most four annotated objects and refuses cycles.

Each HTTP operation spawns an owned child using private socket IPC. One original
phase deadline covers startup, DNS, exact checked public-IP connect, TLS with
original-host SNI, headers/body, permitted redirect, IPC EOF and process teardown.
Metadata calls have 10 seconds, binary calls 45, producer/publication phases 90,
transfer/release phases 180, with teardown reserved inside the call deadline.
Socket operations use remaining time, not renewed full budgets. A parent watchdog
kills an unfinished child and requires reap before success. Cleanup failure clears
owner-retained buffers and facts; immutable Python bytes are not claimed zeroized.
No daemon thread, polling, automatic retry, credential refresh, proxy, netrc,
caller trust override or ambient CA override exists. TLS uses the fixed system CA
bundle `/etc/ssl/certs/ca-certificates.crt`, which native installation must qualify.

API requests authenticate only to api.github.com. API metadata redirects refuse.
Only artifact ZIP and asset-byte endpoints permit one 302 capability redirect to
an independently installed exact origin. The new CDN GET has fresh headers and
no Authorization/Cookie/Referer/API token. Signed path/query remain private in
memory, never observations or logs. Further redirects refuse. Direct asset 200
is also supported. Every unsupported HTTP status refuses without exception prose.

Limits: at most 48 exchanges, four pages per endpoint, 128 jobs and steps per job,
32 artifacts/branch policies/reviews, 1 MiB JSON bodies, 16 MiB aggregate metadata,
512 KiB decoded workflow source, depth 32, bounded containers/strings. Pagination
uses fixed page coordinates and checks counts, uniqueness and Link next/last
semantics without following Link URLs. HTTP headers/status have a 64 KiB cap,
128 headers and 8 KiB lines/Location. Duplicate framing, unsupported encoding,
premature EOF, residual data and unbounded chunk extensions/trailers refuse.
Success requires complete length/chunked body, actual HTTP EOF, exact bounded IPC,
IPC EOF and owned child exit 0/reap. No Content-Encoding decompression occurs.

Ciphertext is at most 17 MiB, projection 64 KiB, receipt 128 KiB, compressed ZIP
17 MiB + 256 KiB, total expanded ZIP 17 MiB + 64 KiB. Native upload qualification
must name `flat-two-stored-or-deflate-no-extra.v1`: exactly two fixed ASCII flat
members, no ZIP64/multidisk/comments/extras/encryption/descriptors/UTF8 flags,
regular-or-unspecified mode, and stored/deflate only. Contiguous local/central
layout, exact compressed/expanded sizes, complete deflate stream and CRC are
checked without extraction. This strict candidate profile is not asserted to
accept unmeasured upload-artifact output; a mismatch refuses, not relaxes limits.

The jobs observation is bound to the fixed attempt-1 jobs endpoint and fresh
current-run/exact-attempt anchors. The documented job DTO does not require a
job-level `run_attempt` property; if additionally present it must be exact integer
1. Upstream timestamp fields support strict aware RFC3339 with uppercase T/Z,
whole seconds or 1–6 fractional digits, and explicit `±HH:MM` offsets. Comparisons
normalize to UTC and preserve all accepted fractional precision; original strings
and authenticated response bytes remain unchanged. Higher precision is refused,
not truncated. Naive timestamps, unknown `-00:00`, leap seconds, invalid dates or
offsets, controls, oversized forms and UTC normalization overflow refuse. This is
an explicit bounded precision profile; canonical JSON installation encoding does
not require upstream timestamps to use whole-second Z spelling.

Producer reads check repository/owner/fork/run/attempt/actor/source/blob/job/runner,
complete roster and every stage-required successful step, exact single relevant
Michael review, no pending selected environment, current policy and independent
action-time protection qualification, then fresh run anchors. Collection stage
can observe queued future upload/finalizer steps; job-complete and run-complete
stages require their exact additional success facts. Artifact transfer joins the
selected nonexpired ID/name/source to the sole completed upload step and its time
interval, checks API ZIP digest and exact metadata readback. Release reads check
exact inventory, per-ID metadata, digests/bytes and fresh anchors; published reads
also require immutable=true and the exact third receipt asset.

## Public encrypted projection and authority limits

The unpublished candidate public allowlist is `Gate0EncryptedEvidenceProjection.v1`
with exactly `schema`, `policy_digest`, `campaign_digest`, `source_bundle_digest`,
`collection_digest`, `plaintext_archive_digest`, `inner_manifest_digest`,
`ciphertext_digest`, `ciphertext_bytes`, `producer`, `result`. Digests use prefixed
SHA256, result is exactly `encrypted_evidence`. Producer has exactly
`repository_id`, `owner_id`, `workflow_id`, `run_id`, `attempt`, `job_id`,
`source_revision`; IDs are exact positive integers, attempt is 1, revision is
40 lowercase hex. Reader checks protected policy/campaign/source pins, actual
GitHub producer coordinates and actual ciphertext digest/length. Collection,
plaintext archive and inner manifest hashes remain **retained producer claims**
until actual B decryption, archive inverse and full retained verification. No
private URLs, identities, timestamps or free error text are allowed in this public
projection. A later finalizer owns writing it from actual verified inputs.

`PublicationFacts` observes an exact digest-bound title and this run's review.
Interpreting that review as the actor's assertion that B verified exact bytes is
still pending human provenance-design adoption. Existing corrected B/C1 owner
closure decisions remain their own accepted source records; this client neither
redecides nor manufactures prerequisite acceptance.

`InstalledGhReleaseVerifier.from_installed()` delegates lazily to the separately
reviewed official-tool owner in `gate0_e_release_verification.py`. Missing or
inconsistent installed qualification still refuses with
`ATTESTATION_TRANSPORT_UNQUALIFIED`. No fake crypto result, custom signer or
unsigned JSON substitute is accepted. Actual pinned official gh transport,
trust and native resource qualification remain unproven. Downloaded release
facts or source review alone do not close that gap.

