# D16 temporary Foundation source verifier

Status: source adapter under review. Michael approved a bounded, read-only use
of the immutable Foundation source commit
`d74bf8dd8c399dd92047174365403b861f82ddd0` before the Foundation
successor is allocated. This is an exception for transition verification only;
it expires when CP adopts a published Foundation verifier. It does not confer
Foundation execution, migration, candidate activation, routing, or deploy
authority.

`vendor_cp.deployment.d16_source_verifier.verify_d16_transition` takes explicit
evidence already collected by CP. It checks the checkout's exact commit and
clean state, validates tracked package blobs against Git, rejects untracked
package files, and materializes the package from the exact commit's Git blobs
into a fresh private snapshot. A fresh `-I -S -B` Python interpreter imports only
that snapshot and the standard library for the policy call; ambient `.pth` and
`sitecustomize` startup code cannot run. Preloaded modules in the CP process and
checkout changes after the preflight cannot supply executable Foundation code.
Git runs with the local file monitor and optional index locks disabled and
hooks disabled, and with replacement objects disabled so a local replace ref
cannot redirect the pinned commit. The result records snapshot import origins,
the commit package tree object and package metadata visible to the child
(normally none with site loading disabled). It opens the local
`database.dump` and `PostgresRecoveryBundle.v1` manifest without following
symlinks, enforces size bounds, hashes the bytes and checks the dump against the
manifest's `database_dump` component. The child receives the already-read
manifest bytes, dump digest and size, and an inert artefact-identity string;
it never opens the mutable dump path. It then constructs Foundation's
`BackupRecord(RECOVERY_BUNDLE, VERIFIED, LOCAL_ARTEFACT)` and invokes the real
`verify_transition_receipt`. A result carries named refusal codes and the
Foundation's finding codes; it carries no secret material.

The `VerifiedDumpEvidence` input is a **trusted CP producer's proof**, not a
property this reader can derive from a later hash. Its fields are
`write_time_sha256`, `size_bytes`, `magic_verified`,
`full_decompression_verified`, `completed_at_epoch` and `evidence_id`. The
reader requires both verified booleans and compares the recorded checksum and
size with the local bytes. The producer must capture the checksum at write
time, verify PostgreSQL archive magic and fully decompress the archive. A
`pg_restore --list` table of contents is insufficient. Until the trusted CP
producer exists and owns those checks, this adapter cannot be used to claim a
VERIFIED backup in an operational transition.

The caller must also independently establish the accepted and target
descriptors, source and target migration heads, the actual running image, run
identity, chain anchor, target host, and complete physical globals role
closure. In particular, the caller must re-read source heads at the fence and
prove physical `globals.sql` matches the role-closure evidence before it
supplies a manifest. Values passed in `D16SourceInputs` are not authenticated
by this module. Matching two caller-authored values is not evidence that either
was measured. The result cannot be used as an authorization or receipt by
itself.

The source checkout must be a separate, clean checkout of the pinned commit.
No Foundation distribution is installed into CP's normal runtime and no
Foundation policy is copied into CP. The source tool is tested separately from
CP's standard dependency closure, which intentionally does not pin Foundation.
Its real-source conformance invocation must name an exact checkout and fail
collection when the checkout is absent; CI must not turn that into a skip. A
protected operational composition must record the source commit, import
origins, dependency versions, and exact input and output evidence coordinates
before it may rely on the result.
