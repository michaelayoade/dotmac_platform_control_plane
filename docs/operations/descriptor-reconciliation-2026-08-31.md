# Descriptor reconciliation — the promotion the bootstrap never made

2026-08-31. **This is an incident repair, not maintenance.** For one day the
accepted production descriptor described a database that had stopped existing,
and nothing in this repository could have told anyone. It surfaced because a
relayed claim about production was checked by hand.

## What happened

The single-use issuer bootstrap (`scripts/bootstrap/bootstrap_once.sh`,
authorised by ADR-0013 as amended 2026-08-31) ran `dotmac-platform admin
migrate` in a short-lived `ops` container on `vendor-cp-prod`. That advanced the
composed lineage to its heads: `mod_deploy` was created, `v017`'s ADR-0011
revocation landed, and the version table went from four rows to six.

It updated no declaration. `deploy/product.toml` — the ACCEPTED descriptor, the
artifact `dotmac-deploy drift` compares a running deployment against — went on
declaring five module schemas, four migration heads, and no invariant denying
`platform_api` DELETE on `public.licence_delivery_targets`. Its own header said
those absences were **"ABSENCES OF FACT, not oversights"**, and on the day it was
written that was exactly right. The bootstrap made the sentence false without
touching the file.

## Every descriptor coordinate in the receipt points backwards

| | |
| --- | --- |
| receipt | `sha256:ffce65ec6e755c83d8a1418d382fae3966b7ef2e7955f1d15f22af926451d272` |
| `product_descriptor_sha256` | `sha256:99eef0cc…` |
| which is | `deploy/product.toml` at revision `e8d5b543`, the bootstrap's SOURCE |
| accepted descriptor on main | `sha256:f7443829…` — moved since, for unrelated reasons, and still described five schemas |

State this precisely, because the loose version — "the receipt is silent about
where it left things" — is false. It records `migration_heads`, measured from
`alembic_version` after the migrate, and `pre_bootstrap_revision`.

The defect is narrower. The receipt carries **exactly one descriptor field**,
`product_descriptor_sha256`; it is a literal fixed at authorship
(`bootstrap_once.sh:48`) rather than computed from the file at run time; and it
names the descriptor at the revision the run STARTED from. **Every descriptor
coordinate in it points backwards.** Nothing diffs the heads it did record
against any declaration.

So the receipt is not defective on its own terms — it records what it was
specified to record. It simply cannot close this: a reader has no way to notice
that the descriptor it names stopped being true during the very run that named
it. (That digest is a RAW-BYTES sha256 of the file, unlike
`assembly.manifest_digest`, which is over canonical bytes. The promotion ledger
follows the receipt's convention and says so, because comparing one to the other
produces a mismatch that looks like tampering.)

## ADR-0017's atomicity was already broken, and this does not restore it

ADR-0017 § 2 requires that a successful deployment promote candidate to accepted
ATOMICALLY, and that migrations and declarations land together. **That property
was violated by the bootstrap, before this change existed.** The database
advanced and no descriptor was promoted, and there is no way to make those two
events retroactively simultaneous.

This change is therefore a **repair of a state that already violated the rule**,
not a change that preserves it. The window ADR-0017 says must not exist did
exist, it lasted about a day, and the honest record of it is this document
rather than a promotion note that reads as though the process worked.

The contract change that would prevent the next one — *an operation that
advances the database carries a candidate descriptor and promotes it atomically,
or refuses to run; and its receipt binds both descriptors* — is being ratified
in `dotmac_governance` and is deliberately **not** implemented here. The
`DatabaseContract` that would express it lives in Foundation `0.3.0a2`, which is
held unpublished (ADR-0017 § 6), so it cannot be fully enforced yet either.

## What was done

A **candidate** descriptor was authored and **promoted**. The accepted
descriptor was not edited to match production, and that distinction is the whole
point: editing it would make the database the authority and the descriptor a
transcript of it, and once hand-editing the accepted descriptor is ordinary, the
next DRIFT is indistinguishable from the next CORRECTION.

| | |
| --- | --- |
| candidate | `deploy/candidates/2026-08-31-post-bootstrap.toml` |
| digest | `sha256:dcc6ef7d…` (raw bytes) |
| promoted | 2026-08-31, recorded in `deploy/descriptor-promotions.json` |
| supersedes | `sha256:f7443829…` |

`tests/architecture/test_descriptor_promotion.py` compares the accepted
descriptor with its candidate byte for byte, so from here on an edit made
directly to `deploy/product.toml` fails the build. A candidate is immutable once
the ledger records it; a change means a new candidate.

## How the candidate was derived

**Not by reading production and writing it down.** A descriptor copied from a
catalogue can only ever agree with that catalogue, including where the catalogue
is wrong, and the agreement proves nothing about whether the declaration is
correct. Each declaration below comes from what the bootstrap was SPECIFIED to
do; the measurement was then used to confirm the derivation.

**Migration heads.** The composed revision graph, resolved offline from the
installed lineages with no database, has eight heads. Two of them —
`cg_0001_agreements` and `li_0001_licensing` — are named in another revision's
`depends_on` (vendor `v015` and `v016`), and Alembic prunes a subsumed
dependency from `alembic_version` rather than leaving a second row. Subtracting
every `depends_on` target gives six:

```
0028_machine_attribution      ap_0002_outbox_relay
dc_0002_canonical_plan_digest ea_0003_platform_audit_log
rl_0001_release_artifacts     v018_licence_delivery_intents
```

The same pruning explains the shape of the descriptor this replaces: its four
heads carried no kernel revision at all, because the kernel lineage then ended
at `0026_platform_audit_log`, which `ea_0003_platform_audit_log` depends on.
`0028_machine_attribution` is a head now because nothing depends on it.

**Schemas.** `public` plus every schema a composed migration creates, scanned
out of the eight lineages: `mod_agreements`, `mod_approvals`, `mod_deploy`,
`mod_ealloc`, `mod_licensing`, `mod_rel`. Seven.

**The privilege declarations.** `dc_0001_deployment_control` grants `USAGE ON
SCHEMA mod_deploy` to `platform_api` and `app_admin` and to no other role, so
`mod_deploy` joins both schema-scoped isolation entries — the `app_user` denial
and the `platform_api` permission. `v017_deployment_target_authority` revokes
`DELETE` on `public.licence_delivery_targets` from `platform_api`, and its own
in-transaction post-condition proves `SELECT`, `INSERT` and `UPDATE` survive,
because a projection nothing can rebuild is a broken delivery path rather than a
sealed one (ADR-0010 § 1). Both halves are declared, table-scoped.

That is **ADR-0011's Amendment of 2026-08-21**, not its § 4 as written: § 4
required revoking `INSERT` and `UPDATE` as well, and the amendment keeps them
for the reconciler. `v017`'s own docstring says so. The descriptor this replaces
cited "§ 4" for the DELETE-only revoke, and that shorthand sends a reader to the
wrong paragraph; the candidate names the amendment.

Every one of these derivations is re-run by
`tests/architecture/test_descriptor_promotion.py`, so the candidate cannot drift
from the migrations that justify it.

**And then confirmed.** The read-only measurement taken on `vendor-cp-prod` on
the morning of 2026-08-31 — seven schemas including `mod_deploy`, the six heads
above, DELETE revoked with SELECT/INSERT/UPDATE retained — agrees with the
derivation in every particular. The restored-production rehearsal recorded in
`kernel-a98-migration-rehearsal-2026-08-31.md`, which applied the same six
revisions to a restored copy and verified the same three properties
independently, agrees as well. **Nothing disagrees.** There is no state in
production that no operation declared.

## The image half did NOT advance, and that is also derived

The bootstrap is create-only: it did not replace, restart or repin the running
application, and its own step 8 refuses if the running revision changed. So the
application is still `sha256:45715e42…` at revision `af9fcf6d…`, and the
candidate carries `[image]` and `[assembly]` across unchanged. Those values are
recorded in the promotion as `carried_forward` and checked, so a future
promotion that advances the image has to say so rather than arriving disguised
as a database repair.

This is the part ADR-0017 § 2 got half right and half wrong, and ADR-0017 § 8
now records it: the descriptor is one file describing two things that advance on
different events. Its refusal to let the descriptor "run ahead" is correct for
the image half and left the database half describing a database that no longer
existed.

## Why nothing caught it, and what now does

The loose statement — "nothing compared the accepted descriptor to a live
database" — is FALSE, and the true one is narrower and worse.

The Foundation's `classify_invariant_breaches` **does** evaluate a descriptor's
declared `[[database.isolation]]` invariants against a catalogue captured from
live production, labelling the difference `SOURCE DRIFT` against `RESTORE
DEFECT`. It could not have caught this, for two independent reasons: it runs
inside a recovery rehearsal, and it is scoped to the invariants the descriptor
**declares** — and this descriptor declared no DELETE invariant. *A comparison
scoped to what was declared cannot report what was never declared.* That is the
present-but-undeclared problem one level up, living in the checker rather than
in the database.

What had no live comparison at all was `expected_schemas` and `expected_heads`:
parsed, and consumed by nothing, anywhere. `dotmac-deploy drift` compares image,
config and manifest digests and never opens a database. **Being wrong about
those two declarations cost nothing**, which is its own reason nobody noticed —
and the command below is the first live consumer either has ever had.

`dotmac-platform admin descriptor-drift` closes it, in **both** directions:

* **declared but absent** — the descriptor names something the database lacks. A
  deployment that half-ran, a restore that lost an object, a declaration written
  ahead of its migration.
* **present but undeclared** — the database holds something no declaration
  names. **This is the direction that would have caught the bootstrap**, and it
  is the one a conformance check normally lacks: on 2026-08-30 every declared
  schema still existed and every declared head was still applied, so "does
  everything declared exist?" was green on a database that had moved.

It connects to nothing. The target-side read is the catalogue capture
`dotmac-platform recovery capture-sql` already emits, run by an operator, a
deployment run or a recovery run against the target; the comparison is a pure
function over two documents. Deny case D1's connecting-entrypoint allowlist
stays empty, and a checker that could read the database it validates could also
arrange for its own check to pass.

**It has not been run against production.** No host access was authorised for
this work, and the first live run is an operator action against a host Michael
names.

## One more unmonitored region, closed in passing

`deploy/product.toml` is a long prose document — it argues at length for what it
declares — and it sat outside every prose guard in this repository, because
`test_stale_claims.py` scanned `.md` and `.py` under six roots that did not
include `deploy`. Its header stated an atomicity rule and a list of unapplied
revisions that the bootstrap falsified, and nothing could see the claim at all.
`deploy` and `.toml` are in scope now. A descriptor is exactly the kind of file
a reader treats as authoritative.

Both directions are planted and observed in `tests/unit/test_descriptor_drift.py`,
along with the half that is usually skipped: a MATCHING descriptor and capture
must pass, and a clean report carries how many subjects it actually compared —
because a checker that refuses everything passes every planted-violation test,
and a checker that examined nothing returns the same empty findings list as a
conforming database.
