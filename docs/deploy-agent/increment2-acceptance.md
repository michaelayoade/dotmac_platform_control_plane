# Increment 2 acceptance and approved source budget

Michael approved this bounded replacement of the original design's section 2.7
limits on 2026-10-21, for the existing staging signer/agent/ledger scope and its
required proofs. It adds no product capabilities and authorizes no live activation.
The coordinator retains the explicit approval and measured decision record at
`.cutover-private/inc2-budget-amendment-20261021.json` outside the repository.

The hard limits count nonblank, noncomment source, including fixtures, helpers,
vectors and any shipped implementation. They do not permit moving implementation
to uncounted templates or private wrappers. Any new excess stops for a new measured
scope/design decision; it must not remove a security control or negative case.

| Component | Approved ceiling |
| --- | ---: |
| Shared contracts | 450 |
| CP Python implementation, migration and wiring | 1,250 |
| Mandatory CP immutable descriptor, promotion and prospective metadata | 250 |
| Combined CP implementation and mandatory metadata | 1,500 |
| Agent Python | 1,100 |
| Launcher, systemd and public config | 150 |
| CI YAML additions/changes | 350 |
| OpenBao definitions/apply | 250 |
| Egress renderer/config | 150 |
| Gate-0 proof harness and restore acceptance tool changes | 750 |
| Required tests across increments 1–2 and approved engine guard | 3,000 |
| Overall new source | 8,000 |

At approval, measured contracts were 427, CP 1,202, agent 1,091, OpenBao 233,
and known required tests 2,320. The known overall subtotal was 5,681 before the
remaining proof and provisioning work. These are source measurements, not a
runtime acceptance claim. The separately approved predecessor guard counts in
the overall inventory; its tests count in the test ceiling. No additional engine
behavior changes are authorized by this budget amendment.

Michael subsequently approved a separate 250-line allowance for mandatory CP
governance metadata on the same date, retaining the 1,250-line Python limit and
the 8,000-line overall limit. The required immutable candidate and promotion,
accepted descriptor copy and prospective composition metadata add 233 lines;
with 1,235 implementation lines the combined count is 1,468. All these artifacts
remain counted. The source-only correction is recorded in
`.cutover-private/inc2-cp-governance-metadata-amendment-20261021.json`.

## Source merge gates

* Independent review of the final source and retained malformed-input cases.
* Exact CP assembly with the pinned kernel, not a different installed alpha.
* Required exact-head hosted checks, including the actual migrated PostgreSQL
  suite and `test_deploy_agent_projection.py`: receipt mutation triggers, runtime
  privileges, idempotent rebuild/key advancement and retained-row corruption.
* Byte-identical canonical CP/Sub contracts and conformance vectors.
* Public GitHub candidate evidence, signing identity and immutable image binding.

## Live gates remain required

Private-only OpenBao access and governed JWT apply; ledger branch protection;
signer and host-key custody with approved public fingerprints; a signed immutable
agent package and pinned root-owned runtime/tools; the guarded executor; all five
same-day Seabone proofs; and the next-morning rerun remain required. Feature
enablement stays explicit and production profiles continue withholding the routes.
The production digest must be the staging-accepted immutable digest. Old Lane 3
execution remains stopped and its retirement follows replacement acceptance.

Offline source tests do not establish assembly, PostgreSQL, key custody, egress
TTL enforcement, or deployment acceptance. The current PostgreSQL test source is
included by the hosted migration job; its presence is not a passing run.
