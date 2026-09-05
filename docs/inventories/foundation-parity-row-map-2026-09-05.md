# The row-by-row half of Foundation's §11 parity map

**Platform CP's contribution to the parity gate, 2026-09-05.** Measured against
Platform `main` at `d7b8ca6` and Foundation's concern-contribution contract
**revision 2**
(`docs/superpowers/specs/2026-09-05-foundation-concern-contribution-contract.md`).

The machine-readable half is
[`platform-parity-row-map.json`](platform-parity-row-map.json), schema
`platform-parity-row-map/1`. Foundation's `foundation-admission-parity-map.json`
**joins on it** rather than restating it — its author declined to copy the rows
on the grounds that *a copy is a second authority that drifts*, which is right
and is why this file exists.

`tests/unit/test_parity_row_map.py` holds every claim below to the fixtures in
`tests/unit/profile_refusal_matrix.py`, in both directions. A map that has
drifted from the fixtures is worse than no map, because the successor is
measured against it and the drift is invisible from the other repository.

## Row identity is a contract; the case name is documentation

Foundation's map is two-directional, so a row must survive both sides being
edited. `PCP-<surface>-<ordinal>` is allocated **once** and never reused; a
retired row spends its identifier into `RETIRED_ROW_IDS` rather than freeing it,
because reusing an ordinal would silently re-point a foreign reference at a
different property and nothing on the far side would notice.

The identifier set is written out (`FROZEN_ROW_IDS`) rather than derived from
the name→ID table. Deriving it would make the check a statement that one
mapping agrees with itself, and the whole point is that a row cannot move
without an explicit edit here.

## The count, and what each state means

| state | rows | meaning |
| --- | ---: | --- |
| `mapped` | 33 | a named Foundation code or stated mechanism covers the same property |
| `migrates` | 13 | the property survives under a different Foundation mechanism, not a code |
| `retires` | 2 | the property belonged to a producer Platform will no longer have |
| **`unmapped`** | **5** | **no named code and no stated mechanism — BLOCKS DELETION** |

## The gate: five rows block deletion

Under Michael's rule an unmapped row blocks deletion of this dialect. All five
are about the **document**, not about a concern, and that is the shape of the
gap: Foundation's contract discriminates contributions superbly and says less
about the envelope they arrive in.

| row | case | what has no code |
| --- | --- | --- |
| `PCP-V-01` | `document_absent` | an artifact carrying **no profile document at all**. `missing` (N9) is per-concern, and N17 requires every refusal to name the highest stage *actually attained* — a document never read attained none, so 13×`missing` is unrepresentable. **This is the only verdict this programme has ever observed against a real image.** |
| `PCP-V-02` | `document_not_utf8` | undecodable bytes. §4.4 closes documents on decode but names only `unknown_key` |
| `PCP-V-03` | `document_not_json` | malformed JSON. N11e implies a *refusal at the parse* exists; it has no code in §3.3 |
| `PCP-V-04` | `document_not_an_object` | valid JSON that is not an object |
| `PCP-V-11` | `contract_unknown` | a **document** declaring an unknown schema. `contract_mismatch` covers a *consumer* naming another contract id or version — a join-key fact, not an envelope fact |

Platform kept `DOCUMENT_UNREADABLE` and `*_MISMATCHED` as separate verdicts
because a corrupt build and an unauthorized artifact have different repairs.
That distinction has no expression in the successor's vocabulary yet.

## Three further gaps, named but not blocking

These have a stated Foundation mechanism, so they do not block; they are
places where §10's negative matrix is thinner than the property it must protect.

1. **No negative row for a stale self-digest.** `PCP-V-13`
   (`profile_digest_stale`) is the load-bearing row on this side — it is the
   reason three independent encodings of one digest exist in Platform's tree,
   and it can only fail if producer and verifier encode independently. §8 and §9
   own canonical bytes and a golden fixture with a sensitivity pair; §10 has no
   `N` row for a document whose declared digest does not cover its content.
2. **Eight establish-failures fold into one row.** `PCP-V-22`…`PCP-V-29` are
   eight distinct triggers; §10 gives them N12. By this map's own stated
   principle — *a successor that refuses "somewhere in absence-proof validation"
   is not the same as one that refuses an unregistered family* — that is a
   granularity loss, and it is the exact granularity §6.1 otherwise argues for.
3. **Two Foundation outcomes are not codes.** N13 and N12 are stated as
   *"finding"*, and N15's is *"coordinate refusal"*. A finding that is not a code
   cannot be joined on, which matters for `PCP-V-17`, `PCP-V-24`, `PCP-B-05`,
   `PCP-B-06`, `PCP-B-08`, `PCP-B-09`, `PCP-T-02` and `PCP-T-05`.

## Two rows that split, and one that inverts

* `PCP-V-31` (`concerns_incomplete_empty_binding`) — *a placeholder is not an
  owner* — **splits** in the successor into `uninjected` or `unexercised`
  depending on which of the three facts is absent. That is the discrimination
  Platform's dialect could not make, and it is the clearest single illustration
  of what the three-fact separation buys.
* `PCP-T-06` (`concern_spec_bound_without_a_consumer`) is the **most informative
  row in the map**. Platform asserted *a provider nothing discovers is inert* at
  the **type boundary**, because it could not observe injection. `uninjected` is
  the same intent **observed** rather than **declared** — which is why it
  belongs in Foundation's added list even though the intent is not new.
* `PCP-V-23` (`absence_proof_inventory_digest_mismatch`) **inverts**. Platform
  compared a caller-supplied digest against a locally derived one;
  `InventoryDigest.v1` removes the caller's digest entirely. Platform supplies
  typed inventory and Foundation computes. The dormant
  `canonical_inventory_digest` is **superseded by that, not adopted** — its rows
  migrate to the Foundation-owned computation and it acquires no consumer here.

## The ceiling: nine added cases, and which are genuinely new

**The brief handed to this lane said eight and omitted `answers_everything`** —
the refusal revision 2 exists to add, and the dual of `broken_shut`. Foundation's
§11 step 3 says nine and includes it. Nine is used here, and the discrepancy is
recorded rather than silently corrected, because a two-directional map cannot be
built on a count that is wrong on either side.

Of the nine: **six have no legacy counterpart**, one is a declaration-time
approximation, and **two are not actually new**.

### Verifier rows (33)

| row | case | legacy outcome | map state | Foundation code | stage | Foundation reference |
| --- | --- | --- | --- | --- | --- | --- |
| `PCP-V-01` | `document_absent` | `document_absent` | **unmapped** | — | — | §3.3 · §10 |
| `PCP-V-02` | `document_not_utf8` | `document_unreadable` | **unmapped** | — | — | §4.4 · §10 N11e |
| `PCP-V-03` | `document_not_json` | `document_unreadable` | **unmapped** | — | — | §4.4 · §10 N11e |
| `PCP-V-04` | `document_not_an_object` | `document_unreadable` | **unmapped** | — | — | §4.4 |
| `PCP-V-05` | `second_witness_absent` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A · §10 N11c |
| `PCP-V-06` | `second_witness_wrong_contract` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-V-07` | `second_witness_no_files` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-V-08` | `second_witness_entry_missing_digest` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-V-09` | `second_witness_two_wheels` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-V-10` | `second_witness_no_wheel` | `document_unreadable` | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-V-11` | `contract_unknown` | `contract_unknown` | **unmapped** | — | — | §3B · §3.3 #3 |
| `PCP-V-12` | `profile_digest_absent` | `profile_digest_mismatched` | **migrates** | — | — | §8 · §9 |
| `PCP-V-13` | `profile_digest_stale` | `profile_digest_mismatched` | **migrates** | — | — | §8 · §9 |
| `PCP-V-14` | `revision_mismatch` | `artifact_coordinates_mismatched` | **mapped** | `contract_mismatch` | `resolved` | §3.3 #3 · §10 N5 |
| `PCP-V-15` | `wheel_claim_mismatch` | `wheel_digest_mismatched` | **mapped** | `contract_mismatch` | `resolved` | §3.3 #3 · §10 N5 |
| `PCP-V-16` | `wheel_carried_mismatch` | `wheel_digest_mismatched` | **migrates** | `foreign_inventory` | — | §5A · §10 N11c |
| `PCP-V-17` | `absence_proof_foreign` | `absence_proof_foreign` | **mapped** | — | `resolved` | §6 property 2 · §10 N13 |
| `PCP-V-18` | `absence_proof_unknown_schema` | `absence_proof_inadmissible` | **mapped** | `unknown_key` | `declared` | §4.4 · §6.1 |
| `PCP-V-19` | `absence_proof_wrong_concern` | `absence_proof_inadmissible` | **mapped** | `absence_proof.wrong_concern` | `declared` | §10 N14 · §6.1 property 4 |
| `PCP-V-20` | `absence_proof_shapeless_escape_hatch` | `absence_proof_inadmissible` | **mapped** | — | `declared` | §6 property 1 · §10 N12 · §11 step 1 |
| `PCP-V-21` | `absence_proof_and_declared_binding` | `absence_proof_inadmissible` | **mapped** | `duplicate` | `resolved` | §10 N8 · §6 |
| `PCP-V-22` | `absence_proof_wrong_state` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6 property 1 |
| `PCP-V-23` | `absence_proof_inventory_digest_mismatch` | `absence_proof_unestablished` | **migrates** | `foreign_inventory` | — | §5A · §10 N11c |
| `PCP-V-24` | `absence_proof_artifact_digest_mismatch` | `absence_proof_unestablished` | **mapped** | — | `resolved` | §6 property 2 · §10 N13 |
| `PCP-V-25` | `absence_proof_no_family_map` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6.1 property 2 |
| `PCP-V-26` | `absence_proof_incomplete_enumeration` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6.1 property 2 |
| `PCP-V-27` | `absence_proof_unregistered_family` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6.1 property 1 |
| `PCP-V-28` | `absence_proof_occupied_family` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6 |
| `PCP-V-29` | `absence_proof_no_positive_control` | `absence_proof_unestablished` | **mapped** | — | `declared` | §6.1 property 3 |
| `PCP-V-30` | `concerns_incomplete_missing_slot` | `concerns_incomplete` | **mapped** | `missing` | — | §10 N9 · §3A |
| `PCP-V-31` | `concerns_incomplete_empty_binding` | `concerns_incomplete` | **mapped** | `missing` | — | §10 N9 · §3.3 #2/#4 |
| `PCP-V-32` | `concerns_not_a_mapping` | `concerns_incomplete` | **migrates** | — | — | §4.4 |
| `PCP-V-33` | `admitted_control` | `admitted` | **mapped** | — | `admitted` | §10 N16 · N9 partner |

### Builder rows (14)

| row | case | legacy outcome | map state | Foundation code | stage | Foundation reference |
| --- | --- | --- | --- | --- | --- | --- |
| `PCP-B-01` | `builder_probe_module_missing` | ProfileBuildRefusal: …does not import… | **mapped** | `unresolvable` | `declared` | §3.3 #1 · §10 N1 |
| `PCP-B-02` | `builder_probe_symbol_missing` | ProfileBuildRefusal: …has no… | **mapped** | `unresolvable` | `declared` | §3.3 #1 · §10 N1 |
| `PCP-B-03` | `builder_lock_unreadable` | ProfileBuildRefusal: …missing or unreadable… | **retires** | — | — | §7 |
| `PCP-B-04` | `builder_lock_has_no_packages` | ProfileBuildRefusal: …no single-wheel package… | **retires** | — | — | §7 |
| `PCP-B-05` | `builder_distribution_absent_from_lock` | ProfileBuildRefusal: …no single wheel for it… | **mapped** | — | `declared` | §10 N15 |
| `PCP-B-06` | `builder_lock_version_disagrees_with_installed` | ProfileBuildRefusal: …not the one in this image… | **mapped** | — | `declared` | §10 N15 · §1.1 |
| `PCP-B-07` | `builder_distribution_not_installed` | ProfileBuildRefusal: …is not installed… | **mapped** | `unresolvable` | `declared` | §3.3 #1 · §10 N1 |
| `PCP-B-08` | `builder_revision_is_a_branch_name` | ProfileBuildRefusal: …peeled… | **mapped** | — | `declared` | §10 N15 |
| `PCP-B-09` | `builder_revision_is_abbreviated` | ProfileBuildRefusal: …peeled… | **mapped** | — | `declared` | §10 N15 |
| `PCP-B-10` | `builder_no_wheel_built` | ProfileBuildRefusal: …exactly one… | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-B-11` | `builder_two_wheels_built` | ProfileBuildRefusal: …exactly one… | **migrates** | `foreign_inventory` | — | §5A |
| `PCP-B-12` | `builder_concern_specified_twice` | ProfileBuildRefusal: …specified twice… | **mapped** | `duplicate` | — | §10 N8 |
| `PCP-B-13` | `builder_slot_has_no_spec` | ProfileBuildRefusal: …no spec covers… | **mapped** | `missing` | — | §10 N9 |
| `PCP-B-14` | `builder_spec_names_an_unknown_concern` | ProfileBuildRefusal: …not concerns this profile has slots for… | **mapped** | `unknown_key` | — | §10 N11d · §4.4 |

### Type-boundary rows (6)

| row | case | legacy outcome | map state | Foundation code | stage | Foundation reference |
| --- | --- | --- | --- | --- | --- | --- |
| `PCP-T-01` | `expected_artifact_without_a_revision` | ValueError: …there is nothing to bind to… | **mapped** | — | — | §10 N11 · §1.1 |
| `PCP-T-02` | `expected_artifact_wheel_not_a_digest` | ValueError: …must be a `sha256:`-prefixed digest… | **mapped** | — | — | §10 N11 · N15 |
| `PCP-T-03` | `concern_spec_unbound_and_provided` | ValueError: …has not decided which it is… | **mapped** | `duplicate` | — | §6 · §10 N8 |
| `PCP-T-04` | `concern_spec_bound_without_a_probe` | ValueError: …at least one probe… | **mapped** | `unresolvable` | `declared` | §3.3 #1 · §10 N1 |
| `PCP-T-05` | `concern_spec_bound_without_a_coordinate` | ValueError: …needs a coordinate… | **mapped** | — | — | §1.1 · §10 N11 |
| `PCP-T-06` | `concern_spec_bound_without_a_consumer` | ValueError: …runtime consumer… | **mapped** | `uninjected` | `resolved` | §3.3 #2 · §10 N2 |

### The nine added cases

| case | legacy counterpart | row | why |
| --- | --- | --- | --- |
| `uninjected` | **approximated** | `concern_spec_bound_without_a_consumer` | Platform asserted the requirement at construction time and could not observe it. The runtime refusal is new; the intent is not. |
| `wrong_site` | **no_counterpart** | — | Platform has no declared injection site, so an object present at another site cannot be stated, let alone tested. |
| `nonce_only` | **no_counterpart** | — | No counterpart. FLAGGED FOR FOUNDATION: §3.0 records that the nonce echo was DEFEATED and §3.1 replaces it with the scenario battery, yet `nonce_only` remains in the §11 added list. Under revision 2 this case looks like it has been absorbed by `answers_everything`. Two names for one case is the shape a two-directional count is supposed to prevent. |
| `all_negative` | **no_counterpart** | — | `broken_shut`. Platform never ran a provider, so it could not observe every outcome being negative. |
| `answers_everything` | **no_counterpart** | — | The five-line stub that satisfies both halves. THE CASE REVISION 2 EXISTS TO ADD, and no legacy counterpart is possible: Platform's import probe could not distinguish a stub from an implementation at all. |
| `wrong_assembly` | **no_counterpart** | — | Platform has one assembly and no assembly-scoped join components, so a verification joining another assembly is unstateable. |
| `foreign_inventory` | **has_counterpart** | `absence_proof_inventory_digest_mismatch` | NOT NEW. Platform has two rows for this property — PCP-V-23 and PCP-V-16. What IS new is the inversion: Platform compared a caller's digest against a locally derived one; Foundation removes the caller's digest entirely. |
| `unknown_key` | **has_counterpart** | `builder_spec_names_an_unknown_concern` | NOT NEW. Platform refuses an unknown concern key at build (PCP-B-14) and an unknown-shaped concerns block at verify (PCP-V-32). What is new is closing DECODE as well as encode. |
| `retirement_round_trip` | **no_counterpart** | — | Platform has no retirement concept at all (§6B, N11e). |

## What this map does not settle

* **The five unmapped rows are Foundation's to close or to rule out of scope.**
  Either answer is fine; the gate is that the question is asked before the
  dialect is deleted. If the envelope-level refusals belong to a different layer
  than the contribution contract, saying so closes them.
* **`nonce_only` may no longer be its own case.** §3.0 records that the nonce
  echo was *defeated* and §3.1 replaces it with the versioned scenario battery,
  yet `nonce_only` remains in the §11 added list beside `answers_everything`.
  Under revision 2 it looks absorbed. Two names for one case is the shape a
  two-directional count exists to prevent — flagged for Foundation, not resolved
  here.
* **N19 is Foundation's acceptance criterion, not this map's.** Reproducing all
  53 while producing no new refusal would mean the generic path had reproduced
  the dialect rather than replaced it. This map supplies the floor and names the
  ceiling; showing the inertness refusals actually firing is step 3 and is
  Foundation's.

## Standing

Platform is held at implementation. **Nothing is deleted by this change** —
`test_nothing_has_been_deleted_while_the_gate_is_open` asserts both superseded
modules are still present while any row is unmapped. No candidate build, no
deployment, no host contact. ADR 0039 is Proposed and unenforced; this map is
contract-design input, not an enforced gate on either side yet.
