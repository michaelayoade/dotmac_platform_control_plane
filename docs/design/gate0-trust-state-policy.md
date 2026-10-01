# Gate 0 rehearsal-issuer trust-state policy (preparation only)

`vendor_cp.deployment.rehearsal_issuer_trust_state` is an isolated public-data
eligibility gate prepared for a later Control verifier composition. Nothing in
this change calls it from CP startup or consumption. It does not verify a
signature, decide Control authorization or replay standing, or audit a refresh.
The composing verifier must require both a successful cryptographic check and
`TrustEligibility.ELIGIBLE` before asking Control to consume an authorization.

The caller provides `minimum_version` from a durable authority and a reader
that returns exactly `version`, `trusted_key_ids` (key ID to public fingerprint)
and `revoked_key_ids`. Michael's 2026-09-28 ruling, recorded in merged
[CP PR #217](https://github.com/michaelayoade/dotmac_platform_control_plane/pull/217)
at immutable commit `d598aa0e092ad4a837d0ed7d4e4632d054de7d0b`, selects
independently controlled, immutable CP deployment configuration as the floor
source. The decision record now includes main's public Free specification;
it is not evidence of current runtime enforcement. This slice accepts the
floor as an injected value; the actual
value, provisioned record and runtime wiring remain pending. No trust-state
path or operator command is selected here. `start` reads and validates one
record. A missing/unreadable/malformed record or a version below
the injected floor raises `TrustStateInstallError` and prevents construction.
The reader is invoked only by `start` or an explicit `refresh`; this module has
no poller, timer, network client or private key material.

The installed snapshot copies the public identifiers into immutable containers.
`refresh` serializes attempts under a dedicated refresh lock. It first closes
eligibility under a short state lock, then reads and parses outside that lock.
Eligibility and snapshot reads return promptly while a source reader is
blocked; they see the prior snapshot with eligibility unavailable. A valid
refresh atomically installs the complete next snapshot and reopens the gate.
A lower version is refused. Equal version with changed content is also refused,
preventing a same-version replacement from changing trust standing; an
identical equal version is a valid idempotent retry. Any failed refresh retains
the last snapshot and version for diagnosis but closes eligibility for **every** key
until a successful refresh. The caller cannot treat a retained snapshot as
permission to continue. Refusal errors contain no source payload or exception
text.

On an available snapshot, revoked IDs win even if also trusted. An unknown ID
or fingerprint mismatch refuses independently of signature validity. The
cache window remains: a compromise is not visible to a process until its
explicit refresh succeeds. The later composition must wire an audited refresh
on every running process, report versions, inject the chosen durable floor,
and pass the public standing check into Control's verifier port. This
implementation makes no claim that runtime acceptance is safe before the
remaining provisioning and wiring are complete.
