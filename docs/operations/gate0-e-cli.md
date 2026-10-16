# Fixed E preparation, custody verification and final readback

`dotmac-platform gate0 finalize-e` delegates without arguments to the installed E writer.
Its owner independently loads and verifies the protected original selection,
collection and owner evidence before staging the two encrypted/public transfer
files. Preparation is not readiness acceptance or publication.

`dotmac-platform gate0 verify-e-b-archive` delegates without arguments to the installed B
holder. Its owner requires the qualified existing custody context and selected
GitHub draft, decrypts and verifies the private evidence, retains its private
record and emits only the exact public hash/coordinate summary. CLI dispatch
neither unlocks custody nor supplies a password, key, arbitrary path or policy.

`dotmac-platform gate0 verify-e-published` delegates without arguments to the
finite final-readback owner. It loads three independently qualified fixed slots
for completed publication, completed producer and immutable published release,
then calls the installed writer with the original reader/fact pairs. It emits
only `E_PUBLISHED_VERIFIED` after the existing official verification succeeds.
Its CLI owner is read-only; it writes no acceptance record. Run it after the
publication workflow reaches terminal success, outside that workflow.

`dotmac-platform gate0 prepare-e-draft` delegates without arguments to the
fixed publication owner. It reads the selected producer transfer and makes one
bounded draft-creation attempt with the exact encrypted/public asset pair.
`dotmac-platform gate0 publish-e` delegates without arguments to the same
module's separate publication owner. It loads the fixed qualified draft and
publication-start slots and the protected B-summary input. The existing writer
must validate the selected B evidence and adopted digest-bound human review
before any publication mutation. These two commands mutate GitHub only under
their separately reviewed operational authorization and native installation.
Uncertain mutations retain incomplete state; neither command retries or clobbers.

`dotmac-platform gate0 await-e-transfer` delegates without arguments to the
read-only transfer owner. It waits within the original root-issued deadline and
verifies the exact root-owned encrypted/public pair before emitting
`E_TRANSFER_READY`. It accepts no path or lifetime override and grants no root
access to the job. The producer uploads only the two literal qualified paths.

All six leaves have one declared owner and preserve its return status and public
output bytes. Unexpected owner failures return status 3 with only
`GATE0_E_UNAVAILABLE` on stderr. Operational authorization, actual installation,
human custody presence and native qualification remain separate requirements.
These commands do not dispatch workflows, set admission or close Gate 0.
The publication commands can create/publish only their fixed selected release;
source availability does not authorize running them. The writer and holder source reviews must pass before this
integration is landed or installed; tests with synthetic owners prove dispatch
and refusal mechanics only.
