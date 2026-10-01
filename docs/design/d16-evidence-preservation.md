# D16 descriptor evidence preservation (2026-10-01)

This slice preserves the exact descriptor bytes in CP's frozen source and
target observations. `capture_genesis_baseline` reads
`deploy/product.toml` from Git history at a caller-supplied revision; this
module does not verify that revision against the running image.
`capture_target_state` reads the caller-selected working-tree file. Each takes
one byte read and retains that result with its raw SHA-256 digest and the
database migration heads measured at capture time. Comments, CRLF and other
byte-level differences survive without decoding or normalization. Later
working-tree edits cannot change an already captured value.

`raw_bytes_descriptor_digest` remains CP promotion/provenance evidence. It is
not Foundation's `TransitionSide.descriptor_sha256` or
`TargetSide.descriptor_sha256`. Those receipt fields require
`ProductDeploymentSpec.to_canonical_document().sha256_digest()`, calculated
by an eligible published Foundation implementation from the preserved bytes.
No canonicalization, receipt mapping, receipt producer, or deploy action is
introduced here.

These dataclasses hold in-memory observations only. This slice does not
verify running-image source identity, prove the D16 fence is holding, bind the
observation to a host/product/environment, durably store a genesis baseline,
or create a valid Foundation chain anchor. The required first-receipt baseline
remains the separately retained, fenced, canonical and host-bound record ruled in
`d16-transition-receipt-decisions.md` decision 4. The existing production
Foundation release gate in that decision remains in force.
