# Adjudicated post-ACL recovery source contract

This contract supports a separately typed, finite manual decision after a
contained failed V2 attempt retained ACL restoration. It does not change the
strict post-ACL contract: changed full measurements still refuse there.

The 2026-11-05 source amendment permits implementation, a draft PR, hosted CI
and independent review. It grants no live acceptance of a historical assurance
gap, host action, release, merge, installation, protected authorization dispatch
or native execution. A source fixture or locally written approval file is not
an operational authorization. Expired proofs and consumed authorizations stay
expired or consumed.

## A policy decision, not a historical proof

An older backup and a current heartbeat rowset can establish two complete end
states and their column differences. They cannot by themselves link the backup
to a retained measurement baseline, identify the intervening writer, exclude
intermediate writes or prove business-row equality or harmlessness. Equal null
claim timestamps do not prove that no work was claimed between snapshots.

`HeartbeatDriftAdjudicationV1` therefore requires
`HISTORICAL_INTERVAL_NOT_ATTRIBUTED`. All six `unavailable_assurance` fields
remain false, including in successful adjudicated receipts. A later protected
human authorization must explicitly decide whether to admit the exact reviewed
present boundary despite these limits. Hashes of the reviewed qualification,
comparison and decoder reports are supporting commitments, not a new authority
or a forensic predicate that becomes true through acknowledgment.

## Separate request and protected context

The existing protected request author accepts
`dotmac.cp_adjudicated_post_acl_plan/1` and produces
`dotmac.cp_adjudicated_post_acl_request/1`. Both the nested basis and inline
adjudication enter the canonical plan digest. Workflow identity, actor, run,
attempt and expiry remain runner-owned. The normal attestation verifier must
verify the genuine new request; it is never relabelled as an unsigned strict
request. There is no new public CLI: the existing `admin cp-transition` adapter
delegates to the new typed owner.

The protected operator context has schema
`dotmac.cp_adjudicated_post_acl_recovery_context/1` and exactly these fields:

- `historical_context`: a held path/digest pin loaded by the existing strict
  post-ACL historical loader;
- `adjudication`: the closed policy document matching the signed request;
- `present_measurement`: the complete reviewed measurement.

Its `context_digest` is the digest of the actual held document bytes, checked
against the protected installation pin. The new context wraps the original
`PostAclRecoveryContext`; it does not replace its historical `.measurement`.
Installation continuation selectors are mutually exclusive. Receipt dispatch
uses exact schemas and context types; strict and adjudicated receipts cannot
substitute for each other. Adjudicated failures are not new predecessors for
recursive recovery.

## One exact difference and one claim domain

The adjudication binds distinct historical and reviewed present measurement
digests. The comparator requires complete relation and sequence inventories,
unchanged tracking/reset/start epochs, catalogue digest, relation identities
and storage, and all other counters. Only the named
`public.relay_heartbeats.n_tup_upd` cell may differ, strictly increasing.
The signed present digest fixes that particular value: this is not permission
for another heartbeat increment or a general table exclusion. Duplicate,
missing, malformed or unavailable witnesses refuse.

The named relation commitment uses the canonical qualified name. Full OID and
storage identity still come from and must match in the complete measurements.
The current heartbeat commitment covers the complete one-worker rowset, with
aware timestamps normalized to UTC microseconds, nulls retained and rows sorted
by worker identity before canonical hashing. An aggregate maximum cannot prove
that rowset. Overflow or an additional row refuses. Raw row values are not
public receipt or diagnostic fields, and existing relay readiness semantics and
the heartbeat writer remain unchanged.

The canonical failed installation/store is derived from the signed failed
operator revision. All fifteen retained records, every ancestor, spent claim,
fence binding and failed execution remain required. Strict and adjudicated
requests reserve the same `post_acl_recovery_frontier_key` in that canonical
owner. Another protocol, context, fresh store or authorization cannot create an
extra attempt. The claim body binds the actual new request and adjudication.
No baseline, prior record or spent claim is rewritten or deleted.

## Execution and receipts

Under the existing host lock, the owner validates protected authorization and
the complete historical frontier, requires a distinct empty fresh store, and
checks current containment, identity, target heads, maintenance, candidate
absence, complete measurement and heartbeat commitment. The current values
must equal the signed reviewed present values exactly.

Only after the exclusive canonical claim is owned may the existing owner stop
and drain writers. Full present measurement and heartbeat checks repeat before
fence rebinding and candidate execution. Additional movement refuses rather
than revising the reviewed boundary. Existing fence, candidate, cleanup, ACL,
readiness, receipt and routing owners perform the bounded suffix. Failures
before mutation do not invoke compensation; later failures retain existing
fail-closed behavior and leave the claim consumed.

`adjudicated-post-acl-rebound` retains the actual complete measurement,
heartbeat digest/count, adjudication and historical/present digests, and fence
bindings for independent core validation. Candidate cleanup compares production
against the reviewed present measurement on this path. The new typed receipt
retains the historical context, adjudicated context, actual request, exclusive
claim and evidence, distinguishing the admitted present boundary from the
unchanged historical baseline.

## Warning refusal and validation

The known warning-bearing diagnostic remains an independent strict refusal.
Repeated warning hashes and an exit-zero observer do not establish clean output
or benign meaning. No warning allowlist, caller-supplied clean flag or
acknowledgment override is part of this protocol. In-process database reads and
a process return-code check do not qualify a separate collector's stderr.
Fresh operational evidence must pass its existing strict collection boundary.

Hosted validation must cover strict-path drift refusal; exact new bindings;
wrong acknowledgment or true assurance flags; changed current values, another
relation/counter, epochs, catalogue, identities, sequences and rowset;
missing ancestry, crossed contexts, receipt substitution, shared claim replay,
preclaim ordering and post-stop movement. PostgreSQL tests exercise actual
measurement and heartbeat changes. Source tests establish repository behavior,
not production acceptance. Local validation is static only; no local product
tests, imports, dependency installation or Docker daemon are used.
