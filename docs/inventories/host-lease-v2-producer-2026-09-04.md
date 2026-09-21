# `HostLease.v2` — what Platform CP must produce, measured against the landed lifecycle

Revised 2026-09-04, a second time, and the revision changes the document's
central finding rather than its details.

**Line references below are to `michaelayoade/dotmac_starter_mt` `ff26e7eb`**
(`a run that ends without saying so leaves the host held, not released`, #623),
the head of that repository's `main` at the time of writing. The earlier
revision of this document was measured at `2288b4d6` — the commit that landed
`HostLeaseRelease.v1` — and reported, correctly for that commit, that **no code
anywhere wrote a lease release record**. That is now false. #624 added the store
writer and #623 added the runner that calls it, so the lifecycle is complete and
the section that said otherwise has been replaced rather than softened.

What has NOT changed is the reason this document exists: the four constraints on
what Platform CP may put in a V2 lease. All four survive the merge unchanged,
and they are restated below against the merged code rather than carried over.

Platform CP's own bootstrap input remains Foundation **`0.3.0a3`**, pinned by
immutable build coordinates in `deploy/foundation-candidate.json` at `source_sha`
`005490b278be73112fa9600bffb6e00a37c77a59`. That sha is an ancestor of `ff26e7eb`
and still carries `HOST_LEASE_SCHEMA = "HostLease.v1"`, has no
`workload_principal` field, and has **no `lease_release.py` at all**. **The
artifact this repository pins can neither write a V2 lease nor read a release.**

---

## 1. The three fields are three facts

`lease.py` at `ff26e7eb`:

```
 67  HOST_LEASE_SCHEMA: Final = "HostLease.v2"
 72  HOST_LEASE_SCHEMA_V1: Final = "HostLease.v1"
 81  _HOLDER: Final = "deployment-foundation-rehearsal"
101  target: str
109  compose_project_prefix: str
114  controller_identity_fingerprint: str
122  workload_principal: str
145  if self.holder != _HOLDER:  ->  SpecError
```

| field | what it is | who supplies it |
| --- | --- | --- |
| `holder` | the authorized ROLE — **still the fixed token** `deployment-foundation-rehearsal`, not free text and not a Platform CP input | the schema. A writer does not choose it |
| `workload_principal` | the **separately authenticated** runner identity that holds and releases the lease | the Lane 3 workload, from its own authenticated run |
| `controller_identity_fingerprint` | the credential that **mutated the host**. Host-mutation evidence, a different fact from who held the lease | the SSH controller key, and nothing else |

`holder` was never semantically reassigned. `lease.py:145` refuses any value
other than `deployment-foundation-rehearsal`, for the reason V1 gave: the holder
name is what another agent reads to know the host is taken, so it is a fixed
token. V2 did not widen that field; it **added** `workload_principal` beside it,
and the docstring at `lease.py:117-121` says so — *"Three fields, three facts:
what role was authorized, who held it, and what credential touched the machine."*

**`platform_outbox_dispatcher` may not be substituted for any of them.** In this
repository it is a **Postgres login role** for the outbox relay:
`src/vendor_cp/deployment/credential_bootstrap.py:97` allowlists it as the one
database principal whose password may be installed from an OpenBao pointer, and
`docker-compose.production.yml:134` uses it as a DSN username. An OpenBao pointer
was provisioned for it and nothing else was. It has no role in leasing at all.
Putting it in `workload_principal` would place a database account where an
authenticated workload identity belongs — the substitution the field was added to
prevent.

**Nor may the controller fingerprint stand in for the principal.**
`lease_release.py:891` and `lease_release.py:902` are two **separate** checks
against two **separate** lease fields — host-mutation evidence against
`controller_identity_fingerprint`, releasing principal against
`workload_principal`. The runner enforces the same pair independently at the
producing end (`exposure_rehearsal_runner.py:881` and `:888`) rather than relying
on the gate to catch it later. A producer writing the fingerprint into both would
pass one check by accident and destroy the distinction the other exists to
enforce.

### The fingerprint contract is IN FLIGHT — do not build against its current shape

Stated plainly because this document is otherwise a shape a producer would code
to. On `ff26e7eb`:

* the **lease** field is already named `controller_identity_fingerprint`
  (`lease.py:114`) and is validated only for emptiness — no format constraint at
  all;
* the **release** field is still named `host_mutation_evidence`
  (`lease_release.py:637`) and is validated against
  `_DIGEST = ^sha256:[0-9a-f]{64}$` (`lease_release.py:336`) — a lower-case hex
  digest, not an OpenSSH fingerprint.

A retyping and rename is being prepared in the Foundation lane:
`host_mutation_evidence` becomes `controller_identity_fingerprint` on the release
too, typed `ControllerSshFingerprintV1`, parsing canonical OpenSSH
`SHA256:<base64>` by decoding to a 32-byte digest. **That type does not exist in
any pushed ref of `dotmac_starter_mt` today** — searched across every
`refs/remotes/origin/*`, zero hits — so this document describes the merged hex
shape and flags it as the one field here that is expected to move. A Platform CP
producer should treat the *field's existence and its two-field separation* as
settled and its *encoding* as not yet settled.

---

## 2. What `workload_principal` has to be, from the reader that consumes it

`lease_release.py` constrains it from the far end. `ReleasingPrincipal`
(`:464`, fields at `:483-485`) is `kind` / `subject` / `run_binding`,
`RELEASING_PRINCIPAL_KINDS` (`:457`) is the closed one-member tuple
`("github_actions_workload",)`, the subject pattern `_SUBJECT` (`:460`) accepts a
workload subject such as `repo:michaelayoade/dotmac_starter_mt:ref:...`, and
`:902` requires `release.released_by.subject == lease.workload_principal`
exactly.

The merged producer confirms this from the other side.
`exposure_rehearsal_runner.py:798`'s `prove_principal` derives both the subject
and the run binding from **one** GitHub Actions OIDC token — never `GITHUB_RUN_ID`
beside a subject from elsewhere, because a mismatched pair from two sources would
look like a derivation. It refuses (`PrincipalUnprovable`) when the identity
endpoint is absent, not HTTPS, unanswerable, or names no repository/run.

So `workload_principal` is a **GitHub Actions workload subject belonging to the
Lane 3 run**. Platform CP does not have one to give: it is not the party that
takes the host, does not run the rehearsal, and a value it invented would be a
claim rather than a derivation — precisely what `run_binding` exists to make
impossible.

**What Platform CP does own is `authorization_run_id`.** `lease.py:125-144`
refuses an empty one on the grounds that a holder writing its own lease has
proved only that it can write a file, and `lease_release.py:882` requires the
release to reference the same authorization run. That is the one field in this
record genuinely Platform CP's, and it is an authorization reference rather than
an identity.

---

## 3. The producer EXISTS. This section replaces the one that said it did not

The lifecycle is complete in `dotmac_starter_mt` `main`. Three parts:

**A writer, on every *nameable* terminal outcome.**
`exposure_rehearsal_runner.py:929`'s `record_terminal` is called on both terminal
paths — after a receipt is produced (`:1606`, *"a receipt is a terminal outcome
whether or not every item passed"*) and from the `DeploymentFoundationError`
handler in `main` (`:1674`). `build_release` (`:868`) assembles the record and
refuses rather than filling a gap: no lease in hand, an unprovable principal, a
proven principal that is not this lease's `workload_principal` (`:881`), or a
controller identity that is not this lease's fingerprint (`:888`).

The qualifier *nameable* is load-bearing and is the merged design, not a gap. An
exception with no member in the closed terminal vocabulary writes **no** release
(`:1659-1677`); there is deliberately no `except Exception`, so an unexpected
error, a SIGKILL or the runner dying all leave the lease **HELD**. Absence means
held. `record_terminal` itself never raises — a record that failed to be written
must not become a second verdict on top of the one already reached — and it
appends a `NO RELEASE WRITTEN: …` note either way, so a run that released nothing
is still distinguishable from one that never happened.

**An atomic store, shared with the lease.** `lease_release.py:951`'s
`write_release` derives the path through `lease.release_path` (`lease.py:266`) so
the destroy gate reads one place, and publishes through
`lease.write_store_record_once` (`lease.py:320`). That primitive writes the
completed, fsynced bytes to a `.partial` opened `O_WRONLY|O_CREAT|O_EXCL` and
then `os.link`s it to the final name: **creating the name and failing on a taken
name are one syscall, so `EEXIST` *is* the refusal.** There is no `path.exists()`
check, because check-then-write leaves a window in which two contending runs both
see no file and both write. `write_release` converts the `FileExistsError` into
`PreconditionFailed(code=RELEASE_DUPLICATE)` — a contract, not an accident — and
the runner catches that type **by name** (`:964-975`), since a handler catching
only `OSError` would let it escape a function that promises never to raise.

`write_release` takes **no path override**. `--release-out` copies the stored
record *after* the store write succeeded, for artifact upload; it is never a
second write path.

**A destroy gate that refuses without a release.**
`lease_release.py:813`'s `require_release_before_destruction` refuses a premature
destroy outright, then binds the release to the machine about to be wiped:
lease digest by content, `vm_slot` (a slot, not an address — an address is what a
destroy-and-restore can re-point), `vm_installation_id` when both sides have one,
candidate version, authorization run, host-mutation evidence, releasing
principal, release date against lease start, and a replay check on the release
digest. `HostClosure.INSPECTION_REQUIRED` is refused even with a valid release,
because destroying the host is the one act that makes the inspection impossible.

**Platform CP still writes no lease, of either version.** `HostLease`,
`write_lease` and `host_lease` appear nowhere in `src/`, `scripts/`, `deploy/` or
`.github/` in this repository — verified by grep at the commit this branch is
based on. The only occurrences of "lease" in `src/` are the outbox **row** lease
(`relay/health.py`, `config.py`): a queue mechanism that leases a row to a
worker, not a host to a run.

(`scripts/write_release_record.py` in the Starter repository is still not this.
It writes a PACKAGE release record for the published-manifest ledger. A reader
grepping "write_release" will find it and should not mistake it for the host
lease producer.)

---

## 4. What this means for a Platform CP producer

Unchanged by the merge, and now checkable against real code rather than asserted:

**Do not infer a principal.** If the authenticated workload identity is absent
the producer refuses and the host stays held. `ReleasingPrincipal`'s docstring
rules it at the release end — *"If the writer cannot prove its principal there is
no release, and the host stays held"* — and `prove_principal` now demonstrates it
at the acquisition end.

**Do not carry material.** The fingerprint is an identity; the key stays in
OpenBao and is resolved at execution time on the target, which is the property
`tests/architecture/test_pointer_resolved_at_execution.py` holds this assembly
to. The runner takes `--controller-key` as *a path*, described in its own help
text as a POINTER.

---

## 5. Settled by the landed schema

**`target` and `compose_project_prefix` are kept.** Unchanged and required:
`lease.py:101` and `:109`, both in the emptiness check at `:125-144` and both in
`as_document()` at `:185-196`. No answer needed from the Foundation lane; the
earlier revision's open question is closed.

**V1 is legible and cannot authorize, and that is in the type.**
`HistoricalLeaseV1` (`lease.py:204`) carries the seven V1 fields and deliberately
has **no `covers()` and no `workload_principal`**. Its docstring: *"not 'it would
be rejected', but there is no method to call and no principal to bind."* A V1
lease does not acquire a principal by being read, so "no V1→V2 defaulting" is
enforced by the absence of the member rather than by a check a caller could route
around.
