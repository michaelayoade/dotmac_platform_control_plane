# Profile refusal parity — every refusal Platform's local dialect produces

**Measured 2026-09-05 against `main` at `39ef16a`.** Driven, not described:
every row below is a fixture in `tests/unit/profile_refusal_matrix.py` that
`tests/unit/test_profile_refusal_parity.py` runs against the implementation it
claims to describe.

## Why this exists

Michael redirected the architecture. **Foundation becomes the single canonical
owner** of `ApplicationFoundationProfile.v1` — the concern vocabulary,
contribution validation, canonical encoding and digest, admission and refusal
rules, execution-plan binding, artifact verification. **Platform CP supplies
declarations and no profile semantics.**

`vendor_cp.deployment.profile` and `vendor_cp.deployment.profile_readback` are
therefore **superseded, not adapted**: translating between two canonical
contracts is compatibility plumbing, not composition. Superseded is not the same
as wrong, and it is not the same as gone.

**The ruled migration sequence, and this document is step 1:**

1. preserve behaviour and negative cases as parity fixtures
2. Foundation lands the canonical contract and generic verifier
3. prove the generic path produces at least these refusals against real bytes
4. replace Platform's acceptance invocation
5. delete the builder and verifier in that same composed change
6. add a ratchet proving the local dialect cannot return

> *"That avoids a temporary state with neither verifier."*

**Nothing is removed by this change.** The hard constraint on this lane is that
the local dialect comes out only when the generic replacement goes in, in one
composed change. Step 5 before step 3 is the failure this ordering exists to
prevent.

## How to read a row

One **planted defect** and the **exact outcome** it must produce. A description
of a refusal is not an acceptance bar; an input that triggers it is. Each row
plants exactly ONE thing against an otherwise-valid artifact, because the
verifier checks in a declared precedence order and a fixture broken in two
places only ever demonstrates the earlier one.

Several verdicts have several distinct triggers, and they are listed separately
on purpose: a successor that refuses "somewhere in absence-proof validation" is
**not** the same as one that refuses an unregistered surface family.

**53 rows: 33 verifier, 14 builder, 6 type boundary.** Verdict coverage is
exact — every member of `ProfileVerdict` is reached by at least one row, and the
suite fails if the enum gains or loses one without the matrix moving.

## A correction to the brief, recorded rather than propagated

The migration brief attributed to this lane a live defect in
`test_this_images_own_absence_proof_is_accepted` — a proof carrying only a
concern name, a revision and free text being ADMITTED, with the instruction that
the generic path must refuse it too.

**That is not the state of the code, and it has not been since #166.** Read at
the line: that test now passes a proof that fully establishes (schema, state,
five enumerated empty families, the image-derived inventory digest, a positive
control), and the shapeless shape is recorded as its own named property in
`test_the_shape_that_used_to_be_admitted_is_the_escape_hatch_and_is_refused`,
which asserts `ABSENCE_PROOF_INADMISSIBLE`. The repair happened in the same PR
that introduced the absence route.

The **requirement** stands regardless of the citation, and it is carried here as
`absence_proof_shapeless_escape_hatch`. It is an active acceptance bar for the
successor, not an open defect in this implementation.

### Verifier — `verify_embedded_profile` (33 rows)

| case | planted defect | verdict | what the successor is held to |
| --- | --- | --- | --- |
| `document_absent` | the profile file is not written at all | `document_absent` | an artifact carrying no profile document is refused, not admitted by default |
| `document_not_utf8` | raw bytes `ff fe 00` at the profile path | `document_unreadable` | an undecodable document is UNREADABLE, never MISMATCHED: a corrupt build and an unauthorized artifact have different repairs |
| `document_not_json` | truncated JSON `{"contract":` | `document_unreadable` | a truncated or malformed document is unreadable rather than empty |
| `document_not_an_object` | valid JSON that is a list | `document_unreadable` | valid JSON that is not an object is not a document |
| `second_witness_absent` | `distributions.json` not written | `document_unreadable` | with no independent per-file record, the document's wheel claim has no second witness — an artifact that describes itself is not evidence about itself |
| `second_witness_wrong_contract` | `contract` = `something/9` | `document_unreadable` | a distribution record of an unknown contract is unusable, not empty |
| `second_witness_no_files` | `files` = `[]` | `document_unreadable` | an empty inventory is a truncated capture, and treating it as zero files would make every digest over it agree |
| `second_witness_entry_missing_digest` | one entry loses its `sha256` | `document_unreadable` | ONE malformed entry makes the WHOLE inventory unusable; silently skipping it produces a digest over the wrong set |
| `second_witness_two_wheels` | a second `.whl` entry added | `document_unreadable` | two wheels means no single second witness, and picking one would be choosing which witness to believe |
| `second_witness_no_wheel` | the `.whl` entry removed | `document_unreadable` | an inventory naming no wheel cannot witness a wheel claim |
| `contract_unknown` | `contract` = `some-other-profile/2` | `contract_unknown` | a verifier does not guess at the meaning of a schema it does not know |
| `profile_digest_absent` | `profile_digest` removed | `profile_digest_mismatched` | a document with no digest of its own is not self-covering |
| `profile_digest_stale` | `source_revision` edited AFTER sealing | `profile_digest_mismatched` | content edited after sealing is detected — this is the whole point of the digest, and it fails only if producer and verifier encode independently |
| `revision_mismatch` | `source_revision` = a different peeled commit | `artifact_coordinates_mismatched` | a profile describing a different revision is refused even when it is internally perfect |
| `wheel_claim_mismatch` | document `wheel_sha256` = another digest | `wheel_digest_mismatched` | the document's own wheel claim must equal what the caller expects |
| `wheel_carried_mismatch` | the IMAGE's inventory wheel digest changed | `wheel_digest_mismatched` | the IMAGE's independent record must agree too — a document that is right about a wheel the image does not carry is still refused |
| `absence_proof_foreign` | proof `source_revision` = another commit | `absence_proof_foreign` | a well-formed proof produced for ANOTHER artifact says nothing about this one |
| `absence_proof_unknown_schema` | proof `schema` = `SomeOtherAbsenceProofV1` | `absence_proof_inadmissible` | an unrecognised proof schema is REFUSED, never ignored — ignoring it lets a document carry a certification nobody rejected |
| `absence_proof_wrong_concern` | integration schema naming `data_governance` | `absence_proof_inadmissible` | a schema may certify only the concern it is granted; absence is not a general 'nothing applies' route |
| `absence_proof_shapeless_escape_hatch` | proof = concern + revision + free text ONLY | `absence_proof_inadmissible` | a concern name, a revision and a sentence must NOT satisfy anything. This shape was admitted before #166 and is the escape hatch the ruling closed; the successor must refuse it and will not know to unless it is written down |
| `absence_proof_and_declared_binding` | `integration` declared bound AND proven absent | `absence_proof_inadmissible` | a concern declared bound AND proven absent has not decided which is true; accepting either would be the verifier deciding for it |
| `absence_proof_wrong_state` | `state` = `assumed_absent` | `absence_proof_unestablished` | a proof that does not declare the proven-absent state is not making the claim |
| `absence_proof_inventory_digest_mismatch` | `observed_inventory_digest` = another digest | `absence_proof_unestablished` | the observed inventory digest must equal one the VERIFIER derives from the image's own record — this is the half a caller cannot manufacture |
| `absence_proof_artifact_digest_mismatch` | `image_digest` = another digest | `absence_proof_unestablished` | the proof must bind to the artifact being judged |
| `absence_proof_no_family_map` | `families` = a string | `absence_proof_unestablished` | no family mapping means nothing was enumerated |
| `absence_proof_incomplete_enumeration` | one of the five families dropped | `absence_proof_unestablished` | a family never visited is not a family found empty; a subset is the shape complete enumeration exists to refuse |
| `absence_proof_unregistered_family` | a sixth family `carrier_pigeon` added | `absence_proof_unestablished` | a family outside the closed inventory silently satisfies 'none present', which is the failure mode absence proofs actually have |
| `absence_proof_occupied_family` | `outbound_connector` non-empty | `absence_proof_unestablished` | a scan that FOUND something means the concern is unbound and needs a provider, not a proof |
| `absence_proof_no_positive_control` | `positive_control` = `[]` | `absence_proof_unestablished` | without the instrument shown finding something known to exist, a scan that never finds anything and an artifact that has nothing are the same colour |
| `concerns_incomplete_missing_slot` | one concern removed from `concerns` | `concerns_incomplete` | there is no partial admission, and the refusal NAMES what is missing |
| `concerns_incomplete_empty_binding` | `data_governance` = `{}` | `concerns_incomplete` | a placeholder is not an owner — an empty binding does not fill a slot |
| `concerns_not_a_mapping` | `concerns` = `[]` | `concerns_incomplete` | a document whose concerns are not a mapping satisfies none of them |
| `admitted_control` | NOTHING — the control | `admitted` | NON-VACUITY. Every row above asserts a refusal, and a verifier that refused everything would satisfy all of them |

### Builder — `build_profile_document` (14 rows)

| case | planted defect | refusal must name | what the successor is held to |
| --- | --- | --- | --- |
| `builder_probe_module_missing` | a probe naming a module that does not exist | `…does not import…` | a concern whose provider module is gone must fail the BUILD, not ship a document claiming it |
| `builder_probe_symbol_missing` | a probe naming a symbol the module lacks | `…has no…` | a provider that moved is the same failure as one that vanished, and the refusal must name the symbol |
| `builder_lock_unreadable` | the lock is not valid TOML | `…missing or unreadable…` | with no coordinate source, no provider can be given an immutable coordinate |
| `builder_lock_has_no_packages` | a lock with no `[[package]]` at all | `…no single-wheel package…` | an empty coordinate source produces a document with no coordinates and no complaint — the vacuous pass |
| `builder_distribution_absent_from_lock` | a lock that omits an installed provider | `…no single wheel for it…` | a provider that is installed but uncoordinated must not be claimed |
| `builder_lock_version_disagrees_with_installed` | lock says `0.1.0a97`, image has `0.1.0a98` | `…not the one in this image…` | a lock/image disagreement would hand every binding a hash for some other build while reporting agreement |
| `builder_distribution_not_installed` | a spec naming an uninstalled distribution | `…is not installed…` | a profile naming a provider the image does not carry describes another image |
| `builder_revision_is_a_branch_name` | `--source-revision main` | `…peeled…` | a document built from a branch name describes an artifact the deploy then rejects, because the deploy already refuses that shape |
| `builder_revision_is_abbreviated` | a 7-character commit | `…peeled…` | an abbreviated commit is not an immutable coordinate |
| `builder_no_wheel_built` | an empty `dist/` | `…exactly one…` | a profile binds to THE artifact; with none there is nothing to bind to |
| `builder_two_wheels_built` | two `.whl` files in `dist/` | `…exactly one…` | picking one of several would be choosing which artifact to describe |
| `builder_concern_specified_twice` | a duplicated `ConcernSpec` | `…specified twice…` | two specs for one slot is two answers, and whichever won would be arbitrary |
| `builder_slot_has_no_spec` | one of the thirteen specs removed | `…no spec covers…` | a slot with no spec produces a document short by one and silent about why |
| `builder_spec_names_an_unknown_concern` | a spec for concern `telepathy` | `…not concerns this profile has slots for…` | the verifier ignores an unknown key, so a document carrying one claims something nobody reads |

### Type boundary — refused before any file is read (6 rows)

| case | refusal must name | what the successor is held to |
| --- | --- | --- |
| `expected_artifact_without_a_revision` | `…there is nothing to bind to…` | an expectation with no revision cannot bind a document to an artifact |
| `expected_artifact_wheel_not_a_digest` | `…must be a `sha256:`-prefixed digest…` | a wheel expectation that is not a digest cannot be compared with one |
| `concern_spec_unbound_and_provided` | `…has not decided which it is…` | a slot cannot be both declared unbound and given a provider |
| `concern_spec_bound_without_a_probe` | `…at least one probe…` | a binding with nothing to resolve is bound because a table said so |
| `concern_spec_bound_without_a_coordinate` | `…needs a coordinate…` | a version alone can be re-pointed; a binding needs an immutable coordinate |
| `concern_spec_bound_without_a_consumer` | `…runtime consumer…` | a provider nothing discovers is inert |

## What the matrix does NOT cover, named rather than left implied

* **Execution and settlement.** The local dialect never had them; the redirected
  contract does. Nothing here is a bar for execution-plan binding or settlement
  translation, and a successor passing every row above has said nothing about
  those.
* **The three-fact separation.** The new contract separates `ConcernProvider`
  (declares), `ConsumerBinding` (proves the assembly injects and uses it) and
  `ConcernVerification` (exercises the composed path and reports evidence),
  joining on the same typed contract identity and artifact coordinates, with the
  lifecycle `declared → resolved → injected → exercised → admitted` and **only
  `admitted` filling a slot**. Platform's dialect collapses all three into one
  declaration plus an import probe. So the rows above are a **floor**: the
  generic path must produce at least these refusals, and it will correctly
  produce more — notably for a provider that resolves but is never injected, and
  for one that is injected but never exercised, neither of which this dialect
  can even express.
* **`canonical_inventory_digest`.** Dormant. It has no consumer here: the only
  thing that needed it was an absence proof this assembly cannot construct, and
  ownership sits with Foundation. It is exercised by the fixtures above ONLY as
  the value an absence proof must match, re-implemented in the fixture module so
  the comparison is not one function agreeing with itself.
* **The wheel expectation.** Acceptance step 18 takes it from the image's own
  distribution record because no external source exists today — the release
  receipt itself reads it from there. The rows above therefore exercise the
  document-versus-record comparison and not an expectation held by a receipt.

## Three encodings of one digest, deliberately

`profile_readback.canonical_profile_digest` is a SPECIFICATION;
`profile.profile_digest` is the producer's independent implementation; and
`profile_refusal_matrix._canonical` is a third, in the fixtures. Each exists
because sharing an encoder makes the check a statement that one function agrees
with itself — a fixture that imported the verifier's could not fail
`profile_digest_stale`. A successor inherits the same obligation: its producer
and its verifier must encode independently, or its digest proves nothing.

## Standing

Platform is held at implementation. No candidate build, no deployment, no host
contact. This change adds fixtures and this document and **deletes nothing**.
