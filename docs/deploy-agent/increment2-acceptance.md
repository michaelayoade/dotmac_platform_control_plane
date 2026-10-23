# Increment 2 acceptance and approved source budget

Michael approved the complete bounded source-only amendment on 2026-10-22.
It retains the existing deployment/agent/restore owners and adds the finite
proof/provisioning adapters and one authenticated CP evidence endpoint. It
adds no product capability and authorizes no activation or production change.
Michael approved the enabled-runtime shipping amendment on 2026-10-24.
Its frozen measurement and decision packet has SHA-256
`776e1a4c9db3301db6f3d4917ee9cf2cdaf07da679adbad42dd913f04e83fb77`.
The coordinator retains that packet at
`.cutover-private/keyless-enabled-runtime-reviewed-20261024/measurement-and-decision.json`
and its explicit approval; the historical October 22 packet remains retained.

Count all nonblank, noncomment source, fixtures, helpers, physical vendored
contracts, mandatory metadata and adopted documentation under the explicit
conservative baseline method. Implementation cannot move to an uncounted
wrapper/template. The corrected conservative baseline is 10,168, including all
565 lines of private test source, CP implementation 1,236, CP metadata 233 and
both contract copies 854. These are source measurements, never live acceptance
evidence.

| Component | Approved shipping ceiling |
| --- | ---: |
| Shared contracts, per physical module | 450 |
| CP Python implementation, migration, wiring and evidence admission | 3,100 |
| Mandatory CP metadata | 300 |
| Combined CP implementation and mandatory metadata | 3,400 |
| Agent runtime | 1,100 |
| Launcher, systemd and public config | 150 |
| CI workflows and candidate tooling | 350 |
| OpenBao and adopted credential helpers | 1,400 |
| Egress renderer/config | 150 |
| Gate0 proof and restore acceptance runtime, including adopted diagnostics | 4,200 |
| Finite agent/resolver/runner provisioning, including adopted wrappers | 950 |
| Required tests across all increments and the approved engine guard | 9,900 |
| Approved predecessor guard runtime | 60 |
| Overall counted new source | 23,000 |

The measured shipping approval supersedes the earlier drafting-only budget
restriction for this same bounded feature. All other component ceilings remain
unchanged. Reserve covers necessary review and exact-CI corrections only, with
updated hashes, counts and independent review before merge. The reviewed packet
records the complete measurement; documentation corrections are remeasured by
the coordinator. No security check or meaningful negative case may be removed
to make a measurement pass. This source approval grants no live authority.

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
Seabone proofs; and the same-session repeatability rerun remain required. Feature
enablement stays explicit. Existing production profiles withhold the routes;
`production-keyless-v1` declares opt-in publication, with no live adoption implied.
The production digest must be the staging-accepted immutable digest. Old Lane 3
execution remains stopped and its retirement follows replacement acceptance.

Offline source tests do not establish assembly, PostgreSQL, key custody, egress
TTL enforcement, or deployment acceptance. The current PostgreSQL test source is
included by the hosted migration job; its presence is not a passing run.
