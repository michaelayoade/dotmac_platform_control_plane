# Finite installed E final readback

`dotmac-platform gate0 verify-e-published` has no arguments or policy overrides.
It first loads and reads the independently qualified publication-completion slot,
then the producer-completion slot and published-release slot. Every slot uses the
concrete GitHub owner's fixed installation/root-binding loader, source hashes,
native receipt and credential restrictions. Missing or mismatched qualification
refuses rather than selecting another slot.

The existing read phases remain single use: publication completion and producer
completion each have a 90-second cap; the published release has a 180-second cap.
Their existing exchange, metadata and binary byte limits remain enforced. These
snapshot methods do not expose an external deadline parameter. The adapter adds
no campaign lifetime, retry, polling, acceptance lifecycle or deadline extension.

The adapter passes the same concrete live readers and the same original issued
facts into `InstalledEWriter.from_installed().verify_published`. That owner retains
all existing provenance, source, terminal-success, tag, exact asset roster and
receipt checks, and directly invokes the installed official GitHub release
verifier. Copies of facts cannot authenticate through the live ownership check.
No private field, seal, injected client or caller-selected path is used.

Only successful completion emits `E_PUBLISHED_VERIFIED` and status 0. Failure emits
`GATE0_E_UNAVAILABLE` on stderr and status 3. No private facts, coordinates or
exception detail are printed, and no state or result file is written.

Run final readback only after the publication workflow is terminally successful.
A job cannot establish its own future terminal success. Installed host/native
qualification requires its separate reviewed operational packet. Source tests
use protected-file/HTTP and typed official-verifier boundaries; they establish
source composition only. This adapter does not accept Gate 0, set admission,
dispatch a job, publish a release or qualify custody.
