# `HostLease.v2` — what Platform CP must produce, measured against the landed schema

Rewritten 2026-09-04 against the schema as it actually landed, replacing an
earlier revision of this document that was measured against a guess.

`HostLease.v2` exists. It landed in `michaelayoade/dotmac_starter_mt`
`2288b4d68f6b93d3e391d0dafa04987fb3f750f7` — the commit whose subject is
`HostLeaseRelease.v1`, which is why a reader looking for a commit named after
the lease will not find one. Line references below are to that commit.

Platform CP's own bootstrap input remains Foundation **`0.3.0a3`**, pinned by
immutable build coordinates in `deploy/foundation-candidate.json` at
`source_sha` `005490b278be73112fa9600bffb6e00a37c77a59`. That sha is an ancestor
of `2288b4d6` and still carries `HOST_LEASE_SCHEMA = "HostLease.v1"` with no
`workload_principal` field at all. **The artifact this repository pins cannot
write a V2 lease.** Everything below describes what a producer would have to
supply, not what the pinned tool does.

## The three fields are three facts, and the earlier revision collapsed two of them

`lease.py` at `2288b4d6`:

```
64   HOST_LEASE_SCHEMA: Final = "HostLease.v2"
69   HOST_LEASE_SCHEMA_V1: Final = "HostLease.v1"
78   _HOLDER: Final = "deployment-foundation-rehearsal"
111  controller_identity_fingerprint: str
119  workload_principal: str
142  if self.holder != _HOLDER:  ->  SpecError
```

| field | what it is | who supplies it |
| --- | --- | --- |
| `holder` | the authorized ROLE — and **still the fixed token** `deployment-foundation-rehearsal`, not free text and not a Platform CP input | the schema. A writer does not choose it |
| `workload_principal` | the **separately authenticated** runner identity that holds and releases the lease | the Lane 3 workload, from its own authenticated run — see below |
| `controller_identity_fingerprint` | the credential that **mutated the host**. Host-mutation evidence, a different fact from who held the lease | the SSH controller key, and nothing else |

The previous revision of this document asserted that `holder` had been
semantically reassigned to mean "the authorized role", and that Platform CP
would supply `platform_outbox_dispatcher` for it. **Both halves are wrong.**

`holder` was not reassigned. `lease.py:142` still refuses any value other than
`deployment-foundation-rehearsal`, with the same stated reason V1 gave: the
holder name is what another agent reads to know the host is taken, so it is a
fixed token rather than free text. V2 did not widen that field; it **added**
`workload_principal` beside it, and the docstring at `lease.py:114-118` says so
in as many words — *"Distinct from `holder`, which is the authorized ROLE and is
a fixed token. Three fields, three facts."*

And `platform_outbox_dispatcher` is not a lease role in any sense. In this
repository it is a **Postgres login role** for the outbox relay:
`src/vendor_cp/deployment/credential_bootstrap.py:97` allowlists it as the one
database principal whose password may be installed from an OpenBao pointer, and
`docker-compose.production.yml:134` uses it as a DSN username. An OpenBao
pointer was provisioned for it and nothing else was. Putting it in
`workload_principal` would place a database account where an authenticated
workload identity belongs, which is the substitution the field was added to
prevent.

Nor may the controller fingerprint stand in for the principal.
`lease_release.py:878-888` and `:889-899` are two **separate** checks against two
**separate** lease fields — host-mutation evidence against
`controller_identity_fingerprint`, releasing principal against
`workload_principal`. A producer that wrote the fingerprint into both would pass
one check by accident and destroy the distinction the other exists to enforce.

## What `workload_principal` has to be, from the reader that consumes it

`lease_release.py` constrains it from the far end. `ReleasingPrincipal`
(`:451`, fields at `:470-472`) is `kind` / `subject` / `run_binding`,
`RELEASING_PRINCIPAL_KINDS` (`:444`) is the closed one-member tuple
`("github_actions_workload",)`, the subject pattern `_SUBJECT` (`:447`) accepts a
workload subject such as
`repo:michaelayoade/dotmac_starter_mt:ref:...`, and `:889` requires
`release.released_by.subject == lease.workload_principal` exactly.

So `workload_principal` is a **GitHub Actions workload subject belonging to the
Lane 3 run**. Platform CP does not have one to give. It is not the party that
takes the host, it does not run the rehearsal, and a value it invented here
would be a claim rather than a derivation — the precise thing
`ReleasingPrincipal.run_binding` exists to make impossible.

**What Platform CP does own is `authorization_run_id`.** `lease.py:130-141`
refuses an empty one on the grounds that a holder writing its own lease has
proved only that it can write a file, and `lease_release.py:869-877` requires
the release to reference the same authorization run. That is the one field in
this record that is genuinely Platform CP's, and it is an authorization
reference rather than an identity.

## The producer is absent, and this document does not imply one exists

Stated rather than left to be inferred from a table with an empty cell.

**No lease release record is written by any code, anywhere, today.** At
`2288b4d6`, `HostLeaseReleaseV1` is referenced only by its own module, by
`__init__.py`'s export list, and by its own tests. `lease_release.py` exposes
`lease_digest`, `host_standing` and `require_release_before_destruction` — a
digest, a reader and a gate. It exposes **no writer at all** — nothing
corresponding to `lease.py:268`'s `write_lease` — and
`exposure_rehearsal_runner.py` does not import the module. The record type can
be constructed and serialized through `as_document()`; nothing constructs or
persists one outside tests.

(`scripts/write_release_record.py` in the Starter repository is not this. It
writes a PACKAGE release record for the published-manifest ledger and has no
relation to a host lease. A reader grepping for "write_release" will find it and
should not mistake it for the producer.)

**Platform CP writes no lease either, of either version.** `HostLease`,
`write_lease` and `host_lease` appear nowhere in `src/`, `scripts/`, `deploy/`
or `.github/` in this repository. The only occurrences of the word "lease" in
`src/` are the outbox row lease (`relay/health.py`, `config.py`) — an unrelated
mechanism that leases a queue row to a worker, not a host to a run.

The lease-release producer is being built in the Starter repository by another
lane. It is not this lane's work and this document does not describe it. Until
it exists, the fields tabulated above are a **specification of what a producer
would have to supply**, and a reader must not take the table as a description of
behaviour that ships.

## Two things this producer will not do when it is written

**Infer a principal.** If the authenticated workload identity is absent the
producer refuses rather than filling it. `ReleasingPrincipal`'s own docstring
already rules this at the release end — *"If the writer cannot prove its
principal there is no release, and the host stays held"* — and the acquisition
end must fail the same way, or the refusal is only enforced against whoever
happens to reach it second.

**Carry material.** The fingerprint is an identity; the key stays in OpenBao and
is resolved at execution time on the target, which is the property
`tests/architecture/test_pointer_resolved_at_execution.py` already holds this
assembly to.

## The earlier open question is closed by the landed schema

The previous revision asked whether V2 keeps `target` and
`compose_project_prefix`. It keeps both, unchanged and required:
`lease.py:98`, `lease.py:106`, both in the emptiness check at `:122-141` and both
in `as_document()` at `:183-193`. No answer needed from the Foundation lane.

## V1 is legible and cannot authorize, and that is in the type

`HistoricalLeaseV1` (`lease.py:201`) carries the seven V1 fields and
deliberately has **no `covers()` and no `workload_principal`**. Its docstring:
*"not 'it would be rejected', but there is no method to call and no principal to
bind."* A V1 lease does not acquire a principal by being read. The
"no V1 to V2 defaulting" rule is therefore enforced by the absence of the
member, not by a check a future caller could route around — which is a stronger
guarantee than the earlier revision of this document argued for.
