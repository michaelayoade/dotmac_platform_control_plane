# Gate 0 E finite publication owner

This is source preparation. Nothing here installs credentials, performs custody,
creates a release, adopts B-review meaning or accepts E. The genuine digest-bound
B-verification publication-review meaning remains UNADOPTED. Actual qualified
runtime/source/API evidence and the exact human adoption/review are operational
inputs, never caller flags or a new approval lifecycle.

`InstalledEPublication.from_installed()` loads only
`/run/dotmac-gate0-e/publication.json` with independent root binding
`/etc/dotmac-gate0-e/publication-binding.json`. It uses the existing protected,
no-follow, root-owned ancestry/leaf reader. The contents-write credential is only
`/run/dotmac-gate0-e/github-publication-token`, scoped to the fixed execution
repository `dotmac-tech/gate0-issuer-execution`. The credential leaf is private,
owned by root or the selected runtime UID. No token or token digest enters results,
logs, response projections or errors. The API returns no caller URL/client,
factory/callback, replace/delete/retry interface or acceptance boolean.

## Closed installed inputs

Canonical ASCII JSON uses sorted keys, compact separators, no final newline,
no duplicate/unknown fields and exact non-boolean IDs. Digests below are bare
lowercase SHA256 unless a reused writer/summary schema names `sha256:` digests.
Every path pin is `{path,sha256}` under `/etc/dotmac-gate0-e/`.

The installation has exactly `schema`, `operation`, `policy_digest`, `repository`,
`release`, `producer`, `transfer_selection_digest`, `draft_selection_digest`,
`publication_selection_digest`, `summary_digest`, `credential`, `qualification`,
`download_origins`. Schema is `Gate0EPublicationInstallation.v1`. Operation is
`prepare_draft` or `publish`. Repository uses the existing repository pin schema
and must name the fixed execution repository. CDN origins use the same bounded,
explicit DNS-host selection as the read owner, never IP literals or server URLs.

Release is `{id,tag,target_commit,title,body,author_id}`. ID is null only for first
create, otherwise the exact B-verified draft release ID. Tag is bounded ASCII
letters/digits/dot/underscore/hyphen; target is exact lowercase 40-hex commit.
Title/body are fixed bounded printable ASCII; author is the qualified writer ID.
Producer is `{run_id,attempt,workflow_id,job_id,head_sha,workflow_digest,
source_policy_digest}`; attempt is exactly 1 and head equals target. Reader-selection
digests bind the independently installed live phase objects, never caller DTOs.
Summary digest binds exactly the canonical B summary selected by the real writer.

Root binding is `Gate0EPublicationBinding.v1` with `installation_sha256`,
`qualification_sha256`, `runtime_uid`, `owners`, `native_receipt`. Owners are exact
source byte hashes for `publication`, `github`, `writer`; native receipt is a
protected pin. Runtime real/effective UID must equal the binding. Source files
must be root-owned and not group/other writable. Binding cannot be authorized by
this process, and self-consistent fixture JSON is not native qualification.

Qualification is `Gate0EPublicationNativeQualification.v1` with `selection_digest`
(the installation excluding its qualification pin), `policy_digest`, `runtime_uid`,
`credential_uid`, `permissions`, `method_scope`, `owners`, `native_receipt`,
`immutable_setting`, `action_time`. Permissions are exactly contents-write,
metadata-read and the selected repository ID. Method scope is
`gate0-e-first-create-upload-publish-reconcile.v1`; the former GET-only profile is
insufficient. Native review schema `Gate0EPublicationNativeReview.v1` contains
that same method scope/source owner map plus external qualification-measurements,
runtime-identity and reviewer-record digests. No runtime claim of native success
is synthesized.

Immutable setting uses the existing closed `{repository_id,state,response_sha256,
native_record_digest,observed_at}` qualification and must be enabled for the
selected repository. Action-time evidence has `selection_digest`,
`native_record_digest`, `qualified_at`, `valid_until`, `repository_id`, `operation`,
`target_commit`, `method_scope`, `source_policy_digest`,
`credential_identity_digest`, `exclusive_writer_record_digest`. All joins must
match the selection; the action-time interval must include the whole 180-second
attempt. These records come from the external qualified native owner and must
cover actual credential scope/identity, exclusive mutation attempt, immutable
setting, and GitHub's exact draft target/absent-tag behavior. Merely filling in
hash-shaped values does not establish those observations. Missing real native
records, operational values or qualified source scope refuses installation/use.

## First create and publication

`prepare_draft_once(transfer_reads, transfer)` accepts only the exact concrete
installed transfer reader and its live owned `VerifiedProducerTransfer`. It joins
selected producer/workflow/job/source policy and actual ciphertext/projection
bytes. It reads current repository identity, proves exact tag-ref and exact-tag
release absence using endpoint-specific 404, and scans at most four 100-item
release pages to exclude conflicting drafts. It POSTs one draft at the exact
commit, then uploads the exact ciphertext and public projection once each using
internally built fixed paths/names. It checks unique release identity/target,
actual returned IDs where available, inventory/metadata, exact re-downloaded
bytes and stable readback. It rechecks tag absence after creation and before
`DRAFT_PREPARED`. Its returned locator is nonauthorizing.

`publish_once(writer, draft_reads, draft, publication_reads, publication, summary)`
requires actual concrete installed owners and live phase-owned objects. The
[draft and publication fixed slots](gate0-e-github-reads.md) allow both independent
selections without swapping protected files. It calls the actual
`InstalledEWriter.construct_receipt` first. That sole writer checks its installed
policy/proofs/source/operational evidence, actual B summary, genuine adoption
provenance and actual digest-bearing publication workflow/review. There is no
receipt JSON argument and no caller-accepted flag. Any refusal precedes receipt
or publication mutation.

After that gate, the publisher joins the returned receipt to its exact original
producer/policy/summary, rechecks repository and tag absence, independently
re-downloads B's exact two asset IDs/bytes, uploads the newly constructed receipt
once and requires an exact three-asset draft inventory with every byte checked.
After another tag-absence check it PATCHes only `draft=false` once, then reads
actual published/immutable release state, all three IDs/metadata/bytes and actual
raw tag/peeled commit. `PUBLICATION_OBSERVED` only records this finite attempt.

Final E requires the existing writer's later independent readback after the
publication workflow completes, using separately installed producer-completion,
publication-completion and published-release readers and direct official gh
verification. The publisher neither invokes premature final acceptance nor
substitutes its own boolean for that independent result.

## Uncertain replies and finite limits

An uncertain create, upload or PATCH reply enters bounded read-only reconciliation
of the same selected tag/release/names/IDs/bytes. Malformed JSON/partial metadata,
lost responses, framing/process/deadline failures and non-success statuses never
cause a retry. A create is confirmed only by one exact matching observed draft,
with qualified exclusive-attempt provenance and no prior conflict; upload/PATCH
completion requires actual exact inventory/bytes/state. Ambiguous/conflicting or
partial drafts remain intact and produce `PUBLICATION_INCOMPLETE`. A consumed
owner cannot rearm. There is no deletion, replacement, retag, polling loop,
rollback of issued evidence or “502 then delete” convenience. Insufficient time
to reconcile is incomplete evidence, never permission to extend the attempt.

One original 180-second phase deadline includes all work; shared exchanges retain
one second for owned child cleanup/reap. Individual metadata GETs use at most ten
seconds and binary/write exchanges at most 45 seconds, always clipped by the
original phase deadline. At most 64 exchanges (CDN downloads count twice) and
128 MiB aggregate request/response bytes are allowed. Original response capacity
is reserved even for failed replies. Ciphertext is at most 17 MiB, projection
64 KiB, receipt 128 KiB and each API JSON response 1 MiB. Release/asset lists use
at most four pages of 100 with exact pagination checks. Unknown API fields,
URLs, headers and raw JSON responses are discarded; only closed projections and
exact selected public bytes reach results.

## Validation and remaining operational work

The focused tests are supplied for hosted execution: real protected loaders/live
read phases with owned native-file/HTTP fixture seams, first create and exact
inventories/bytes, uncertain create/each upload/PATCH reconciliation, conflict and
source/summary/adoption/review refusals before mutation, fixed-slot provenance,
finite endpoints, TLS/framing, child EOF/exit/wait/reap and original deadline.
Fixtures claim neither native GPG/GitHub qualification nor genuine human adoption.
Only AST parsing and Ruff 0.6.9 were run locally; project imports/tests/build/mypy,
dependencies, Docker, Git, network, credentials, GPG and host operations were not
performed for this slice.

Remaining live inputs include actual new method-scope native qualification,
scoped credential identity/permissions, action-time immutable setting and exclusive
attempt provenance, exact producer/source-policy/workflow/tag/title/body and
phase-reader selections, B custody result and genuine adopted digest-bound review.
The existing owners retain archive, holder, receipt, official verifier and later
final acceptance responsibilities. This module adds no approval lifecycle or
operational authorization.

The argument-free workflow entries are `run_installed_prepare_e_draft()` and
`run_installed_publish_e()`. The former loads the default concrete transfer-phase
reader and calls its actual `encrypted_transfer()`. The latter loads the actual
installed writer plus the independent draft-release/publication-start slots and
calls their actual snapshot methods. It reads the exact public B summary only
from protected `/run/dotmac-gate0-e/b-archive-verification.json`; the installed
publisher digest and sole writer's selected summary must match those bytes.
Success prints only `DRAFT_PREPARED` or `PUBLICATION_OBSERVED` and returns 0.
Fixed refusal/incomplete categories return 3. These entries accept no caller
arguments, do not print locators/JSON, and confer no final E acceptance.

## Publication failure privacy boundary

Public loaders, prepare/publish methods and installed workflow entries now use
private checked work helpers and bounded inert failure outcomes. They reuse the
existing writer owner's recursive completed-frame/exception-chain/group
sanitizer. Fresh errors cross a clean public frame only after input references
have been dropped. Ordinary refusals preserve the fixed refused/incomplete
category; KeyboardInterrupt, bounded SystemExit, cancellation and GeneratorExit
preserve their control category and stop the attempt. An interruption is never
reclassified as a successful publication or silently reconciled as ordinary
uncertainty. Existing finite transport deadlines and owned-child cleanup remain
unchanged.

A failed publisher is consumed and detaches its selected installation and native
qualification references. Raw server JSON, unknown fields, URLs, token-bearing
transport frames, receipt/asset work state and input owners do not enter the
emitted exception graph. The installed entries also detach owners they loaded
if an earlier phase fails. This is reference detachment, not memory zeroization
or alteration of caller-owned evidence, credentials or keys. Caught exception
traceback, cause and context metadata is intentionally detached.

The sole writer detaches its consumed public selection immediately after a
successful canonical receipt construction, retaining only its one-shot used
state. The publisher captures the public selected workflow digest before that
call and performs the same exact digest comparison afterwards. Receipt,
provenance, adoption, source and policy checks retain their order and meaning.
The writer's public installation contains no collection/prerequisite bytes or
root-host bindings. Publication relies on the authenticated B v2 full private
verification and independently verifies public predicates, source coordinates,
completed producer and protected review. Its native method scope is
`public-evidence-publication-readback.v1`; the private preparation installation
cannot act as a publisher. The adopted review meaning is enforced through the
exact v2 contract, proposal/adoption digests and independently qualified native
decision provenance. This source change selects no executor or credentials.

Authored hosted-only privacy regressions inspect recursive emitted exception
chains/groups, owned traceback locals, separately captured completed owned frames
and reachable publisher/consumed-writer state. They cover post-PATCH unknown raw
metadata, early and late preparation refusal, credential/receipt/post-PATCH
interruption and cancellation, actual publisher root/source/native/reviewer
binding tampering, and no-follow/ownership/mode/ancestry failures at the native
protected-file seam. These tests have not been executed locally.


## Public metadata access

The fixed publication installation/root binding, exact
`/etc/dotmac-gate0-e/publication-qualification.json` and
`/etc/dotmac-gate0-e/publication-native.json` closed digest projections, and fixed
`/run/dotmac-gate0-e/b-archive-verification.json` public summary use existing
`private=False` checks. Arbitrary private pin paths refuse before opening.
Detailed native measurement bodies, full historical wrappers and private proof
inputs are absent. The selected publication token remains private0600 with exact
credential UID; root/nonwrite/no-follow checks and the helper's default remain.

Root0644 public leaves with root0755 ancestry are the normal native arrangement,
not an observed installation. Repin changed source/path hashes and independently
requalify the actual nonzero UID/access scope. Existing method scope and human
review meaning remain unchanged. The writer now uses only the existing historical
owner's distinct qualified public coordinate mode, retaining B's archived digest.
Actual nonroot filesystem proof and the separate B private historical access
obligation remain outstanding.
