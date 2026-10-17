# Public hosted GnuPG measurements

The ordinary CI `check` job keeps `cp-gpg-tool-identities.json` unchanged for its
existing synthetic conformance consumers. A separate stdlib helper emits
`cp-gpg-native-measurements.json` and `cp-gpg-native-measurements.sha256` into a
separate artifact gated on the measurement helper step's successful outcome.
The existing always-uploaded source-test/legacy-identity artifact is unchanged
and never includes the new pair. The sidecar is the bare SHA256 of the complete
canonical JSON manifest, followed by newline; the manifest contains no cyclic
self-hash.

`DotmacPublisherGpgToolMeasurements.v1` records actual public facts:

- `source`: GitHub's source revision plus hashes of the checked-out workflow,
  measurement helper and reused bounded subprocess primitive.
- `github`: repository/id, run/attempt, `check` job key, ref, workflow ref and
  workflow revision. The job key is not a numeric GitHub job ID. PR source SHA
  can be a synthetic merge; these environment coordinates are not independently
  authenticated release or operational authority.
- `operating_system`: actual OS ID/version and dpkg architecture.
- `tools`: fixed `/usr/bin/gpg` and `/usr/bin/gpgconf` path, stable root-owned
  file SHA256 and actual first version line.
- `packages`: sorted actual `gpg`/`gpgconf` package name/version/architecture.
- `package_verification`: fixed per-package `dpkg --verify` command, observed
  zero exit code and empty-output digest/count. Modified packages refuse.
- `legacy_tool_identities_sha256`: exact existing identity artifact digest.

The helper admits Linux x86_64/amd64 only, reads a strict public environment
whitelist, and invokes six fixed metadata commands with a clean environment.
It reuses the existing retention owner's bounded subprocess primitive with a
sixty-second shared budget, ten-second command caps and five seconds reserved
inside that budget for failure cleanup. Binary/OS/source reads and canonical
output are bounded; output files are create-once and private to the CI user.
Initial bounded snapshots cover workflow, helper and primitive source before
any metadata commands. The primitive executes from those exact measured bytes
in a fixed non-main module context; the producer entrypoint is never invoked.
All three source snapshots must match after measurement and their recorded
digests are rechecked before staging, before commit and after pair completion.
There is no embedded source self-hash or circular digest.

Both outputs first enter fixed create-once pending names under a held directory
FD. Final names are linked only after both writes/fsyncs and source checks.
Publication checks each exact owned inode and completed bytes. Failures attempt
finite rollback of only the known newly created inodes, preserving all foreign
or preexisting names. Cleanup uncertainty remains helper failure, and the
separate upload step requires helper success, so a partial pair is ineligible
even when rollback cannot be confirmed. The legacy artifact keeps its original
`always()` behavior.

The two standard root-controlled OS-release aliases are supported. No package
installation, network lookup, recipient/certificate access, credential reads,
producer dispatch or retention execution occurs in this measurement helper.

These are observations for later independent review. Package database
verification and self-hashes do not authenticate Ubuntu packages, establish a
shared-library/runtime closure or qualify production tools. The existing
`qualify_tools` acceptance owner and guards are unchanged. An external owner
must review the actual hosted artifact, supply an independently reviewed native
qualification/reviewer record and explicitly authorize any later operational
step. This helper emits no qualification or reviewer record and configures no
`GATE0_RETENTION_*` selector. Source tests are synthetic; no native acceptance
is inferred from them.
