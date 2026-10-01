# D16 transition-receipt decisions (2026-09-30)

> **Decision record, not an implementation.** Michael ruled all five items
> below on 2026-09-30. This file fixes what the D16 transition receipt must
> do before `TransitionReceiptV1` construction is built; it authorizes no
> deploy wiring, no production Foundation dependency, and no host action.

#224/#226 (source verifier, bundle-producer test coverage, write-time dump
evidence) and #225 (nginx-helper runbook provenance) are separate,
already-merged or in-flight slices; none of them depend on these rulings,
and none of them are changed by this record.

Contract cited throughout:
`packages/dotmac-deployment-foundation/src/dotmac_deployment_foundation/transition_receipt.py`
at exact Starter commit `d74bf8dd8c399dd92047174365403b861f82ddd0` (the same
commit #224/#226's CI conformance step pins). Field and code names below are
taken directly from that file, not paraphrased.

## Corrected finding, and the digest-convention ruling (not one of the four numbered decisions below)

Earlier session notes described `deploy/descriptor-promotions.json`'s
2026-09-01 entry as "an unresolved ordering conflict." Re-read directly
against `origin/main` on 2026-09-30: this is wrong. All eight ledger entries
are clean, internally consistent, and correctly chained via `supersedes`; the
2026-09-01 entry is a fully resolved, well-documented widening of the
`primary` dataset's verification set (three checks → seven) after a real,
already-closed incident (a 2026-08-30 restore rehearsal that passed its then-
declared checks while missing 114 roles). There is no open ordering conflict
to reconcile. The only genuinely open thing here was the digest-form split
the ledger's own header documents:

> "Digests here are RAW-BYTES sha256 of the file, the same convention the
> bootstrap receipt's `product_descriptor_sha256` uses — NOT the
> canonical-bytes convention `assembly.manifest_digest` uses."

Ruling: **keep both conventions, named explicitly, never substituted for one
another — and they serve different consumers, not two fields of one
receipt.** `deploy/descriptor-promotions.json` keeps its raw-bytes sha256 of
`deploy/product.toml` as promotion evidence — that is what
`test_descriptor_promotion.py` byte-compares and what the ledger's own
history is written against; changing it would invalidate the existing chain.
That raw-bytes digest has no field in Foundation's `TransitionReceiptV1`
schema at all — it is not a receipt input, and must be kept in a separate
CP-owned provenance record, not forced into the receipt.

The D16 transition receipt's `TransitionSide.descriptor_sha256` /
`TargetSide.descriptor_sha256` fields instead carry
`ProductDeploymentSpec.to_canonical_document().sha256_digest()` — the digest
of the `DeploymentDescriptorDocumentV1` that method returns (`spec.py`,
Foundation, same pinned commit). This is NOT the same calculation as
`assembly.manifest_digest`: that field hashes a different document entirely
(the product/assembly manifest — `deploy/product-manifest.json` — a separate
artefact from the descriptor), and citing it as though it were the same
computation was a mistake in an earlier draft of this record. Only the
canonical descriptor digest goes into the receipt; the ledger's raw-bytes
digest and the receipt's canonical digest are two separate values, computed
over two separate documents, for two separate consumers, and neither
substitutes for the other anywhere in new code.

## Decision 1 — does the receipt gate restoring public routing?

**Ruled: yes, necessary but not sufficient.** A verified transition receipt
is REQUIRED before public routing is restored after a deploy. It is not, by
itself, SUFFICIENT: target migration heads, candidate readiness (the D16
candidate-role preflight — CP #222/#223), and routing checks must also pass
before routing restores. This is an AND of independent gates, not a single
receipt-only condition. On any failure among these, the deploy retains
nginx maintenance and follows the already-ruled re-fence compensation path
(PR2 rulings, 2026-09-28: failed post-migration deploy stays in maintenance;
restore routing only after compatible heads, health and ACL restoration are
proved).

**Not yet implemented:** the actual gate — the code path that checks all of
receipt-verified AND heads-compatible AND candidate-ready AND routing-checks-
passed before calling whatever restores nginx to serving traffic — does not
exist yet. This is deploy-rewire work, explicitly out of scope for the
bundle-producer/dump-evidence slice (#226) by Michael's own earlier
constraint, and remains out of scope here too.

## Decision 2 — is Foundation an explicit CP dependency?

**Ruled: yes for the final production path, not as an unreleased pin now.**
CP must explicitly pin an ELIGIBLE PUBLISHED Foundation release
(`pyproject.toml` + `poetry.lock`) before any PRODUCTION code path imports
Foundation's bundle/receipt implementation. The exact-commit-pinned,
read-only source verifier pattern #224/#226 established (checking out
`d74bf8dd8c399dd92047174365403b861f82ddd0`'s source onto `PYTHONPATH` for a
single CI step) remains a legitimate, approved TEMPORARY exception for CI
conformance proof only — it does not authorize shipping or using unreleased
Foundation source as the actual production bundle/receipt producer. This
rule "exposes a release gate rather than hiding a runtime dependency": the
real blocker on building the production receipt producer is that there is no
eligible published Foundation release carrying this contract, not a design
question CP owns.

**Not yet implemented / not yet true:** no eligible published Foundation
release carries the bundle/receipt contract cited in this record;
`pyproject.toml`/`poetry.lock` are unchanged and must stay that way until one
exists. The production bundle/receipt producer cannot be built as production
code until this gate clears — a release-readiness question for
Foundation/Starter release management, tracked as a precondition here, not
solved here. Separately: CP already has a LEGACY production deploy path
(`scripts/deploy_production.sh`; see `dotmac-debt-register` D5, currently
disabled) — this record does not claim CP has no deploy workflow at all. What
is pending is the SUCCESSOR protected deploy workflow (Gate-0 D's topology
work), which decision 3 below depends on for `run_id`; that is a distinct gap
from the Foundation-release gate this decision names.

## Decision 3 — source of `run_id`

**Ruled: derive from the protected deploy workflow's own run ID and attempt
number, passed to the host as workflow-derived evidence — never a
`workflow_dispatch` input, never an operator-entered label.** Concretely:
`run_id` must identify the specific GitHub Actions run of the PROTECTED
DEPLOY workflow (not the CI/build workflow that produced the image — these
are distinct runs with distinct IDs, and conflating them is explicitly
refused). A rerun/retry of a deploy must carry a distinct transition
identity from its predecessor.

This maps directly onto the contract's own refusal codes:
`TransitionReceiptV1.run_id` is "who is claiming to have done the work," and
`verify_transition_receipt`'s `RUN_ID_REUSED` finding exists specifically to
catch "a receipt that reuses its predecessor's `run_id`... claiming two
distinct hops happened under one run." A workflow-derived
`${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}` (of the deploy workflow, evaluated
at the point the deploy actually launches) satisfies this: GitHub increments
`run_attempt` on every retry of the same run, and a wholly new deploy gets a
new `run_id`, so no legitimate rerun can accidentally collide with its
predecessor's identity, and no operator can hand-type a stale or reused
value.

**Not yet implemented:** the deploy workflow itself is not yet running under
this identity scheme; this depends on Gate-0 D's still-unresolved runner/
execution-topology work (see `dotmac-debt-register` D1's "D runner blocker"
and `gate0-d-execution-topology-ruling-2026-09-28`) landing an actual
protected deploy workflow to derive `run_id` from.

## Decision 4 — genesis/chain anchor for the first receipt

**Ruled: a separately retained, pre-migration genesis baseline — never
derived from the receipt being checked, never assumed from the ledger's
penultimate promotion.** While the D16 database fence holds, and BEFORE
migration runs, independently measure and retain: the actual source
descriptor's canonical digest (the digest-convention ruling above —
`ProductDeploymentSpec.to_canonical_document().sha256_digest()`, not the
ledger's raw-bytes digest) and the actual source migration heads read
directly off the fenced database — bound to the named host, product and
environment. That retained
record is supplied to the verifier as Foundation's `genesis_source`
argument; later receipts chain to their immediately preceding VERIFIED
receipt via `previous_receipt_digest`, never back to this genesis baseline
directly.

This maps directly onto the contract: `verify_transition_receipt` requires
exactly one of `previous_receipt` or `genesis_source` for any receipt
(`CHAIN_ANCHOR_AMBIGUOUS` if both or neither are given); a first receipt has
no `previous_receipt` to check against, so "the descriptor and heads the
chain actually left from" (`genesis_source`, a `TransitionSide` value) must
be "established independently of the receipt" per the module's own
docstring — exactly the independently-measured-while-fenced baseline ruled
above, and exactly why it must not be inferred from the receipt or assumed
from a promotion record that may not reflect what is actually running.

**Implementation status (2026-10-01):** CP has
`capture_genesis_baseline` and `capture_target_state` in
`src/vendor_cp/deployment/transition_evidence.py`. The source capture reads
the descriptor blob at a caller-supplied Git revision; it does not verify that
revision against the running image. Both captures preserve the exact descriptor
bytes alongside their raw-byte digests and measured migration heads. These are
in-memory CP observations. Neither capture proves that a D16 fence is holding,
binds a named host/product/environment, computes Foundation's canonical
descriptor digest, or durably retains a pre-migration genesis record. The
existing source capture is therefore **not yet a valid `genesis_source` chain
anchor**. The separately retained, fenced,
canonical and host-bound baseline ruled above remains to be implemented.
See `d16-evidence-preservation.md` for this slice's precise boundary.

## What this record does not decide

- The actual `TransitionReceiptV1`-constructing code. These four rulings are
  inputs to that design, not the design itself.
- The deploy rewire (routing-restore gate, decision 1's AND-condition
  implementation).
- Naming or authorizing a production host — still Michael's, still separate,
  still ungated by anything in this record.
- Foundation's release timeline — decision 2 exposes it as a precondition;
  it does not set it.

## Status

All five prior "next-slice decisions" named in the `dotmac-debt-register`
Knowledge slug's D16 section are now RULED. That register entry, and this
file, should be read together going forward; update this file (not the
register) if any ruling here is later revisited, and update the register to
point at this file rather than restating the rulings inline.
