# Gate 0 finite historical source references

This source-only reader supplies sealed historical source facts to the future
single CP E writer. It does not accept E, establish readiness, publish anything,
activate a route, or supply a human publication review.
B/C1 source acceptance and A7/A6/R1–R3 decisions remain recorded decisions.

`InstalledHistoricalSourceReads.from_installed()` accepts no arguments. It reads
canonical selection `/run/dotmac-gate0-e/source-references.json` (256 KiB), root
binding `/etc/dotmac-gate0-e/source-references-binding.json` (64 KiB), and fixed
qualification `/run/dotmac-gate0-e/source-references-qualification.json` (64 KiB).
The selection's `qualification` is exactly `{path,sha256}` naming that fixed file.
The complete selection hash is bound separately from qualification's
`selection_sha256`, which hashes canonical selection with only `qualification`
omitted. SHA256 values are bare lowercase hexadecimal.

The binding's exact fields are `schema`, `installation_sha256`,
`qualification_sha256`, `reader_source_sha256`, `github_mechanics_sha256`,
`native_receipt_pin`, `runtime_uid`. Schema is
`Gate0EHistoricalSourceBinding.v1`. Source paths derive from imported modules.
The actual real/effective runtime UID and protected ancestry must match.

Selection fields are exactly `schema`, `policy_digest`, `repositories`,
`decisions`, `packets`, `credential`, `qualification`, with schema
`Gate0EHistoricalSourceSelection.v1`. Repositories are exactly `cp` and `starter`,
each `{owner,name,repository_id,owner_id}` for michaelayoade's
`dotmac_platform_control_plane` and `dotmac_starter_mt`. IDs are measured inputs;
the reader checks them against authenticated live identities.

Qualification fields are exactly `schema`, `selection_sha256`, `policy_digest`,
`runtime_uid`, `credential_uid`, `api_version`, `repositories`, `permissions`,
`native_receipt_pin`, `decision_provenance_pin`, with schema
`Gate0EHistoricalSourceQualification.v1`. `repositories` equals selection's exact
CP/Starter identity records. `permissions` is exactly
`{metadata: "read", actions: "read", contents: "read", pull_requests: "read"}`.
API version aliases the shared HTTP owner's constant. Credential UID is root or
runtime UID. Only the fixed transient token file
`/run/dotmac-gate0-e/source-references-token` is read, inside each request.
Credentials and HTTP headers never enter facts.

The qualification owner must supply actual bounded CP/Starter access and confirm
that the reused native HTTP/process/protected-read context covers this reader.
Missing qualification refuses. Native receipt and decision provenance are exact
`{path,sha256}` pins below `/etc/dotmac-gate0-e/source-references/`. The existing
`Gate0ENativeReviewReceipt.v1` has exactly `schema`,
`qualification_measurements_digest`, `runtime_identity_digest`, and
`reviewer_record_digest`; binding and qualification must select identical bytes.
No receipt or native-success generator is supplied. The provenance dossier is
retained verbatim. The qualification owner authenticates its selection; this
reader cannot independently prove an off-Git human utterance and never parses
natural language into a decision.

Decisions are exactly `a7`, `a6`, `rulings`, `source_completion`. A7/A6 name CP
#197/#199 and the immutable ADR-0013 source using
`{repository,pr,revision,path,blob_sha,sha256,retained_pin}`. Knowledge decisions
use `{system,slug,version,retained_pin}`, system `dotmac_knowledge`, programme
`dotmac-build-once-programme-queue-2026-08-30` v120 and
`dotmac-debt-d1-gate-0-protected-rehearsal-issuer-readiness` v1. Their retained
JSON retrieval record contains the authenticated record's top-level `slug` and
`version`; other actual record fields are preserved. The reader never queries
Knowledge or treats latest status as authority.

Packets use `{id,repository,pr,merge_sha,pr_head_sha,sources,runs}`. Mandatory IDs
are `b` (CP #200), `c1_foundation` (Starter #753), `c1_cp` (CP #201), and
`c1_dependencies` (CP #204). At most 12 additional `c2_<PR>` rows select from CP
#200/#201/#204–#210/#212/#214–#216. Applicable C2 rows are selected by the existing
qualified composition dossier, not discovered by this reader. Each packet has
1–16 sources and 1–4 historical runs. Source shape is
`{revision,path,blob_sha,sha256,retained_pin}` and revision equals selected head
or merge. Runs use `{run_id,attempt,workflow_id,workflow_path,event,tested_sha,
required_jobs}`, with 1–32 `{id,name}` required jobs. Missing real coordinates
must be supplied by the qualification owner; fixtures cannot fill installation.

PR responses bind same-repository tested heads to merged source commits, without
assuming ancestry for squash merges. CI is checked on the selected historical
head, never represented as CI on the merge. A synthetic-merge run SHA refuses
instead of silently substituting another SHA. Source GET responses bind exact
path, Git blob SHA1, SHA256, decoded size, and retained bytes. Actual API fields
outside these joins are discarded without inventing schema requirements.

Raw GitHub JSON is discarded immediately after bounded parsing and projection.
Neither raw-body digests nor unknown fields enter the cache, observations or
reference bytes. Each endpoint has a closed projection: repository identity
`id/full_name/owner.id`; PR number/merge fields and base/head repository identities;
contents type/path/blob SHA/encoding/size/truncation and normalized exact decoded
source content; run IDs/attempt/workflow/event/path/head/status/conclusion and
repository identities; jobs total count, all job IDs/run IDs/optional attempts,
and only selected required jobs' names/status/conclusions. All nested objects are
rebuilt from these fields. URL fields, `download_url`, unknown nested metadata and
HTTP headers are discarded. Only exact installed selected source/decision/dossier
bytes are retained in full. Observations are validated projections, not raw API
response proof. Their authenticity rests on the actual qualified shared transport
and live sealed reader result; the future writer must reverify evidence.

Only internally built repository, pull, immutable contents, exact run-attempt,
and exact attempt-jobs endpoints reach the shared JSON GET transport. No redirects,
artifacts, releases, downloads, PR discovery or reviews are queried. Jobs require
unique IDs, complete bounded pagination and exact total counts. Required jobs
must succeed; unrelated skipped jobs are permitted. Job `run_attempt` is optional
corroboration: wrong present values refuse; absence is valid because the attempt
endpoint and run's mandatory `run_attempt` bind jobs.

`verify(deadline=...)` is one-shot and caps the caller's future finite deadline at
180 seconds. Each shared JSON request retains its tighter 10-second lifecycle
bound. Limits: 1 MiB/response, 16 MiB HTTP aggregate, 256 exchanges, four job pages,
1 MiB/retained file, 4 MiB retained aggregate and 16 MiB final reference bytes.
Exact duplicate GETs are cached only within the call. No retries or writes occur.
Every failure invalidates all issued facts and yields only
`HISTORICAL_REFERENCES_REFUSED`.

`HistoricalSourceFacts` retains exact reference bytes and digest, installation,
qualification and source-policy digests, validated authenticated metadata
projections and their digests, and
exact selected source and decision bytes/digests. Its fixed result is
`historical_source_references_verified`. The future writer must check live
`owns_facts`, policy binding and exact equality to the archived
`prerequisites.json` source-reference section. Serialization loses producer
identity. This seal is an integration guard, not protection against hostile
Python in the same process. Existing preparation and pure collection verification
remain unchanged.

C2 source and bounded CP projections/composition must be reachable and qualified
before E. E's own B withdrawal, durable relay, correlation and later-use refusal
are observed during E and evaluated by its writer. They are not circular start
gates. Full later production cutover, Foundation candidate, Gate-3 and Lane3 are
not new Gate-0 requirements. D requires real applicable protected evidence,
reusing prior witnesses only for their precisely covered rows.

Validation: focused source tests use only a test monkeypatch at the imported
transport seam. They provide no operational qualification. Hosted tests must
follow repository/parent rules; this source slice performs only AST and canonical
Ruff checks. Rollback removes these three files or leaves the reader uninstalled;
the future writer refuses missing references and no decision history is changed.


## Separate public historical mode

Publication and final readback use the same owner through argument-free
`InstalledHistoricalSourceReads.from_installed_public()` followed by
`verify_public(deadline=...)`. The full `from_installed()` / `verify()` private
mode remains for producer/B. Public mode has no private fallback and never reads
full Knowledge envelopes, provenance dossiers, retained pins or full reference
wrappers. The writer's public historical slot now requires
`Gate0EHistoricalSourceCoordinates.v1`, rather than the private wrapper.

The public selection is `/run/dotmac-gate0-e/source-references-public.json`, with
exact fields `schema`, `coordinates`, `credential`, `qualification` and schema
`Gate0EPublicHistoricalSourceSelection.v1`. Its embedded coordinates have exactly
`schema`, bare `policy_digest`, `repositories`, `decisions`, `packets`.
Every nested roster is closed. Existing CP/Starter identities, A7/A6 PRs and ADR,
fixed Knowledge slug/version, mandatory/allowed packet selection, merge/head,
source path/blob/SHA256, historical run attempt/workflow/event/tested head and
required jobs remain exact. Only `retained_sha256` replaces local retained pins;
source retained hashes must equal source SHA256. Knowledge hashes name the
original authenticated envelope; their bodies are absent and are not refetched.

The public binding is
`/etc/dotmac-gate0-e/source-references-public-binding.json`, with the original
binding fields and distinct `Gate0EPublicHistoricalSourceBinding.v1` schema.
Qualification is fixed at
`/run/dotmac-gate0-e/source-references-public-qualification.json`, with schema
`Gate0EPublicHistoricalSourceQualification.v1`. It retains the full mode's closed
policy/runtime/API/repository/permission/native-pin fields, replaces
`decision_provenance_pin` with bare `decision_provenance_digest`, and requires
method scope `public-historical-source-coordinates.v1`. The native three-digest
projection is fixed at
`/etc/dotmac-gate0-e/source-references/public/native.json`. These metadata leaves
use existing `private=False` checks: root ownership, nonwritable no-follow
ancestry, bounded regular leaves. Normally metadata is root0644 under root0755
ancestry; no host modes are changed by source work. The existing transient token
stays private0600 for root or its exact selected credential UID.

The actual independent installation/native reviewer must establish that the
closed coordinates correspond to the original B-qualified historical selection,
policy and B holder profile, bound to the exact summary and adopted human review.
Matching hashes cannot establish that correspondence. Private decision dossiers
and measurement bodies remain with their existing authority. Source/native pins
and the distinct public method scope require actual requalification.

The same finite transport and source/PR/run/job checks serve both modes. Public
contents responses decode real bytes and recompute SHA256 and Git blob SHA1,
checking size, type, path, encoding, blob and truncation. The owner caches only
closed computed metadata, never source content/base64 or unknown API fields.
`PublicHistoricalSourceFacts` is separately sealed and contains only
`coordinates_bytes`, `coordinates_sha256`, `installation_sha256`,
`qualification_sha256`, `source_policy_digest`, and the fixed result
`public_historical_source_coordinates_verified`. It has no private records or
observations. Failure clears temporary owned frames, caches and issued facts;
copying a DTO does not preserve live ownership.

The writer compares exact public coordinate bytes with its independent public
selection and still takes the readiness receipt's `source_reference_digest`
from B v2's archived-reference hash. It never substitutes the coordinate digest.
Hosted-only source fixtures derive coordinates from the same private selection,
exercise real installed public loading and fresh transport checks, trap every
private read, plant opaque/unknown-field markers, and check failures and ownership.
These native-boundary fixtures are not real nonroot filesystem proof.

The separate B private access obligation is repaired in source as described below;
actual native access remains unproven. Public mode grants no access to private
inputs. No world-readable private body, ACL, capability, root B executor or new
recipient is introduced here.

## Qualified private retained-leaf ownership

The full producer/B loader keeps its existing schemas and verification duties.
Its root-owned nonwritable installation, binding and qualification are closed
nonsecret metadata, read through `private=False`. Installation contains only
schema, policy digest, repository identities, source/decision/packet coordinates
and retained path/hash pins, the fixed credential **path**, and qualification pin.
Binding contains only installation/qualification/source hashes, native receipt pin
and runtime UID. Qualification contains only selection/policy hashes, runtime and
credential UIDs, API/repository/permission metadata, native receipt pin and
decision-provenance pin. Nested source/decision/packet schemas remain closed;
opaque Knowledge envelopes, dossier bodies, retained source bytes and credentials
are absent. Unknown fields refuse. Only the native receipt's closed schema and
three digest projection are also root-readable metadata. Its path cannot alias a
private retained slot. Root no-follow/nonwrite/size checks and exact pinned content
hashes remain authoritative; source work changes no installed mode.

After the independently root-pinned qualification's `runtime_uid` equals the root
binding and the actual real/effective process UID, the loader derives private leaf
ownership from that exact runtime UID. It does not derive it from `credential_uid`.
Opaque decision-provenance, Knowledge envelope and retained source leaves use the
same existing retained namespace, exact mode0600 and that exact owner. Producer
UID0 retains root ownership; an already-qualified ordinary B UID owns only its
selected private leaves. Root-owned nonwritable ancestry remains required at every
component, with no-follow/nonblocking opens, bounded regular-file reads and exact
root-qualified SHA256 checks. The private helper checks ownership and exact0600
on the held leaf descriptor, so0400,0700 and group/other access also refuse.

The existing credential path and its separately qualified credential UID/private
checks are unchanged. Full private historical verification and retained wrapper
construction remain mandatory for producer/B. Public loading/verification is
unchanged and never invokes the private retained helper or opens these leaves.

Authored hosted tests use the genuine full loader and private walker through
synthetic native boundaries for UID0 and an ordinary UID, independent credential
ownership, wrong owner/mode/type/size/hash, writable or wrongly owned ancestry,
symlink refusal, qualification/actual-UID mismatch, native/private alias refusal
and a public-mode private-read trap. These are source-policy fixtures, not an OS
permission proof, and they have not been executed locally. Changed source pins,
native qualification and actual B custody installation must be independently
reviewed and refreshed. A real ordinary UID must read only its authorized0600
private leaves; an unrelated UID must fail, metadata must remain nonwritable and
all native refusal cases must be observed before operational use. No host/custody
execution, credential provisioning or private-data transfer is authorized here.
