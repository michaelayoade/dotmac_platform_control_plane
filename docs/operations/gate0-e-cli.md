# Fixed E preparation and custody-verification entrypoints

`dotmac-platform gate0 finalize-e` delegates without arguments to the installed E writer.
Its owner independently loads and verifies the protected original selection,
collection and owner evidence before staging the two encrypted/public transfer
files. Preparation is not readiness acceptance or publication.

`dotmac-platform gate0 verify-e-b-archive` delegates without arguments to the installed B
holder. Its owner requires the qualified existing custody context and selected
GitHub draft, decrypts and verifies the private evidence, retains its private
record and emits only the exact public hash/coordinate summary. CLI dispatch
neither unlocks custody nor supplies a password, key, arbitrary path or policy.

Both leaves have one declared owner and preserve its return status and public
output bytes. Unexpected owner failures return status 3 with only
`GATE0_E_UNAVAILABLE` on stderr. Operational authorization, actual installation,
human custody presence and native qualification remain separate requirements.
These commands do not dispatch workflows, publish releases, set admission
or close Gate 0. The writer and holder source reviews must pass before this
integration is landed or installed; tests with synthetic owners prove dispatch
and refusal mechanics only.
