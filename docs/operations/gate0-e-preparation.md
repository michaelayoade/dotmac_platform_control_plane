# Gate 0 E inert encrypted preparation candidate

`prepare_encrypted_e` composes actual historical retained-byte verification with
the existing private archive owner. It returns exact ciphertext and canonical
public projection bytes. It grants no readiness, prerequisite acceptance,
producer authentication, B custody verification, publication or installation.
This is source preparation only; the focused tests have not been executed.

The public API is:

```python
prepare_encrypted_e(
    raw_collection: bytes,
    selection: ESelection,
    producer: EProducerCoordinates,
    source_bundle_digest: str,
    prerequisite_bytes: bytes,
    profile: GpgArchiveProfile,
    *,
    deadline: float,
) -> PreparedEncryptedEvidence
```

`EProducerCoordinates` has exactly repository_id, owner_id, workflow_id, run_id,
attempt, job_id and source_revision. Numeric fields must be actual positive
integers, excluding bool; attempt is exactly 1 and revision is 40 lowercase hex.
These are independently supplied selected coordinates, not authenticated GitHub
facts. Repository/owner/run/attempt must match both selected windows' original
GitHub string claims in their exact canonical decimal spelling. Revision must
match both windows' workflow_sha and `selection.source.workflow_revision`.
Workflow/job IDs have no counterpart in ESelection and remain supplied pins.
CP revision may differ from workflow revision.

`source_bundle_digest` is an explicit independently selected `sha256:` plus
64 lowercase hex pin. It is not derived here: the current source selection has
no authoritative source-bundle derivation. The preparation owner never
substitutes module_bundle_digest or invents a source bundle format. Its reviewed
installed origin remains a later integration obligation.

The owner itself invokes `verify_retained_collection(raw_collection, selection)`.
A caller-created VerifiedCollection is not an input or a verification shortcut.
It checks the returned collection's exact bytes, digest, policy and historical
result, then constructs these four exact archive payloads:

| Name | Bytes and meaning |
| --- | --- |
| collection.json | Actual verified.collection_bytes, unchanged, including pending acceptance fields. |
| producer.json | Canonical Gate0EProducerSelection.v1 with exactly schema, producer, source_bundle_digest. This states selection, not observed provenance. |
| prerequisites.json | Nonempty supplied prerequisite_bytes, unchanged and opaque. No parsing, accepted flag, placeholder or substitute is manufactured. |
| receipt.json | Canonical Gate0ERetainedCollectionReceipt.v1 with exactly schema, policy_digest, collection_digest, bundle_digests, root_record_digests, join_digests, result. Digests and their array order come from actual retained verification; result is retained_bytes_verified. |

The private receipt is historical byte-verification evidence, with no acceptance
or readiness field. Existing VerifiedCollection continues to report readiness
false. Actual prerequisite bytes must come from their existing evidence owner;
preserving them does not authenticate their origin or decide their semantics.

The canonical inner manifest has schema Gate0EArchiveManifest.v1 and exactly
`files`, mapping those four fixed names to `{length,sha256}`. Lengths and bare
SHA256 hashes are computed over the actual exact payload bytes; there is no
manifest self-entry. The owner invokes the concrete
`package_private_collection(manifest, payloads, profile, deadline=deadline)` once.
No caller-created EncryptedArchive, encryption callback, verification callback,
private `_pack` call or duplicate USTAR implementation exists in production.
The archive owner alone builds the tar and computes its plaintext digest.

Returned ciphertext size and SHA256 are checked against its actual bytes; the
returned manifest SHA256 is checked against the actual manifest. Bare archive
hashes are validated and prefixed exactly once for the projection. The plaintext
archive hash comes from that actual concrete packager return, not a different
input or an invented tar calculation.

The public object is exactly `Gate0EncryptedEvidenceProjection.v1` with schema,
policy_digest, campaign_digest, source_bundle_digest, collection_digest,
plaintext_archive_digest, inner_manifest_digest, ciphertext_digest,
ciphertext_bytes, producer and result. All seven digest fields use the SHA256
prefix. Ciphertext length is an exact positive integer; producer contains only
the seven selected coordinates above; result is `encrypted_evidence`.
`validate_encrypted_e_projection` is a pure closed-schema parser. It validates
data, not producer provenance, ciphertext authenticity or acceptance. The
existing installed GitHub reader separately joins this same shape to its own
actual ProducerFacts and downloaded bytes. No existing reader file was changed
by this preparation slice.

Public JSON contains no original selections, prerequisite bytes, root records,
private receipt, GPG key profile, credential, environment token, free error or
acceptance/readiness flag. Internal DTO/profile/evidence objects are never
published through asdict. Both output fields are repr-disabled and the output
class has no generated repr. Output DTO construction itself proves no provenance.

All constructed JSON uses sorted keys, compact separators, ASCII escaping,
allow_nan=False and no newline. Collection input is bounded by the verifier's
8 MiB cap; opaque prerequisites and the combined manifest/payload budget use the
archive's existing MAX_PRIVATE_BYTES - 65536 ceiling. Producer, receipt, manifest
and public projection each fit 64 KiB. Ciphertext uses the existing
MAX_CIPHERTEXT_BYTES limit. No independent operational size policy is added.

A finite future original monotonic deadline is checked before work, between
bounded phases and before return, and passed unchanged to the archive owner.
There is no reset, grace period, retry or new duration cap. These boundary checks
do not claim to preempt synchronous retained verification; late completion
refuses. The archive owner retains its existing subprocess/temp-directory cleanup
and deadline authority. This module creates no files, processes, network
connections, environment loader or CLI of its own. Plaintext remains in memory;
immutable Python bytes are not claimed zeroized.

Existing closed retained-verifier and archive refusal categories are preserved.
Other errors become the fixed `gate0_e_preparation_refused`, with no private
payload, path, command output or credential in exception prose.

Operational integration still owes the authoritative source-bundle pin and
coordinates, actual prerequisite bytes, externally qualified GPG binary and
recipient profile, workload/root cleanup, actual protected producer and transfer
facts, and an original operation deadline. The official gh attestation transport
remains unqualified. Digest-bound B publication-review interpretation remains
pending human adoption. Existing B/C1 owner decisions are not reopened, and this
preparation owner adds no prerequisite lifecycle or acceptance state.

The focused source fixtures reuse the existing signed retained collection and
adjust only its independently supplied workflow revision pin to match the
original selected windows. Their declared mock packager tests exact composition
and byte binding; it is not evidence of native encryption success. They cover
payload/manifest closure, unchanged opaque bytes, producer/source/byte splices,
integer/hash/size/type bounds, original deadline handling, archive return
mismatches, and public disclosure/refusal behavior. AST/Ruff checks are separate
from test execution, native qualification and protected E acceptance.
