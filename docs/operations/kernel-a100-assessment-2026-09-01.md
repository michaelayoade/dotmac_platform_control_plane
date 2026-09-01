# Kernel 0.1.0a100 — measured, and not adopted

**Status:** assessed on 2026-09-01. The pin holds at `0.1.0a98`. The obligation
moves to a101 and to the ADR-0016 cutover, both named below with their owners.

This is an as-of observation carrying its coordinates and a named refresh
responsibility, not a release claim (`AGENTS.md` rule 17).

## What the pin actually was

`0.1.0a98`, pinned EXACTLY, and it had been since the `dotmac-deployment-control`
a6 repin. Two as-built documents still said `0.1.0a77` — `docs/ARCHITECTURE.md`
and this repository's pin-state table — and had said so ever since the pin moved.
Nothing broke and nothing could see it, which is the point: a document that
confidently states last month's pin is worse than one that says nothing.
`test_kernel_floor.py` now derives that claim instead of trusting it.

## The five things measured

**1. The pin is exactly the highest floor anything composed declares.** Read out
of each composed artifact's own `Requires-Dist`, never from a source tree and
never from this document:

| Composed distribution | Declared kernel floor |
| --- | --- |
| `dotmac-release-catalog` `0.1.0a4` | `>=0.1.0a56` |
| `dotmac-approvals` `0.1.0a5` | `>=0.1.0a67` |
| `dotmac-entitlement-allocation` `0.1.0a6` | `>=0.1.0a68` |
| `dotmac-commercial-agreements` `0.1.0a2` | `>=0.1.0a77` |
| `dotmac-licensing` `0.1.0a1` | `>=0.1.0a77` |
| **`dotmac-deployment-control` `0.1.0a6`** | **`>=0.1.0a98`** |

The pin equals the maximum. It is neither under-constrained (a5's defect) nor
over-constrained. Nothing in this composition asks for a100.

**2. The bump crosses no kernel migration.** Determined three ways in the
kernel's home repository, and this is the answer that removes the schema risk
rather than managing it. The migrations subtree object is the SAME at all three
tags — `d5ccb09fc9dd` at `dotmac-kernel-v0.1.0a98`, `…a99` and `…a100` — so
`git diff --stat` over that path between a98 and a100 is empty, the revision
count is 28 at both, and the head is still `0028_machine_attribution`. There is
no revision to enumerate, no `down_revision` to chase, and no DDL, RLS policy,
grant or backfill that a100 would apply to this database.

`tests/migration/test_vendor_migration_rehearsals.py` names `KERNEL_HEAD =
"0028_machine_attribution"` and rehearses the composed lineage against real
PostgreSQL, so this is not only a static reading: a kernel repin that DID move
the head would fail that rehearsal in the `postgres` job.

**3. a100 requires a change to how this assembly is composed.** Kernel a100's
`app_factory.create_app` raises `RuntimeError` when
`ProductAssemblySpec.api_documentation` is `None`; the field does not exist at
a98. `src/vendor_cp/main.py` currently corrects the application AFTER
`create_app` returns, through `vendor_cp.api_documentation
.install_api_documentation_policy`, and its docstring already says what that
means:

> That is the shape the kernel should own instead
> (`docs/adr/0016-api-documentation-exposure-policy.md`); when it does, this
> line becomes a field on `ProductAssemblySpec` and `vendor_cp.api_documentation`
> is deleted rather than rewritten.

The kernel has now done it. Adopting a100 is therefore the ADR-0016 cutover —
one owner replacing another, with the local module retired — and not a version
bump. It is out of scope for the change that installed this measurement, and it
is the work the repin is actually waiting on.

**4. The kernel's owner says a100 is not adoptable, and we could not reproduce
the mechanism.** `dotmac_starter_mt` `docs/inventories/kernel-a101-release-handoff.md`,
on protected `main`, states that a100 "is published and tagged but is not
adoptable: a clean install of its declared dependency set cannot import the
package surface because the root import reaches a product-owned PostgreSQL
driver", and that a101 is the intended target.

Asked directly, from this consumer's position, that mechanism did not appear.
One procedure held constant across a98, a99 and a100 — install only the declared
dependency set into an empty virtual environment, then import:

| | `import dotmac_kernel` | `create_app`, no driver / no DSN | `create_app`, driver + DSNs |
| --- | --- | --- | --- |
| `0.1.0a98` | ok | fails | ok |
| `0.1.0a99` | ok | fails | ok |
| `0.1.0a100` | ok | fails | ok |

The package root imports at a100. The `create_app` path does reach a
product-owned driver — and it reaches it identically at a98, which is the
version running in production, so what the handoff describes is a long-standing
property rather than an a100 regression, at least as far as this repository can
see it. Recorded because a claim we could not reproduce is a fact about our
evidence and not a licence to ignore the owner's statement: the kernel's home
repository remains the authority on its own artifact, and a101 remains the
target. Evidence: CI run 33506350578, job `kernel-adoptability-probe`, branch
`probe/kernel-a100-adoptability`, 2026-09-01.

**5. a100 makes the readiness ratchet's dormant half live.** The same probe
asked each version whether `ModuleManifest` carries the `database_catalog` field
that `scripts/check_product_database_catalog_readiness.py` looks for: absent at
a98 and a99, **present at a100**. So the repin is also the moment the module
half of that ratchet stops being a forward probe, and
`test_the_module_probe_is_dormant_because_the_pinned_kernel_carries_no_field`
will go red in the same review and demand that it be re-read as a measurement of
the modules rather than of the kernel generation.

## Coordinates

| Fact | Value | Oracle |
| --- | --- | --- |
| a100 peeled commit | `917181b38dcc5954bac932b630909afdfb19012b` | `peeled_tag` `dotmac-kernel-v0.1.0a100` |
| a100 on the private index | listed | the simple index, read in run 33506350578 |
| a100 release run | **none recorded** | the kernel's publication commit carries no run id or artifact digest; a99 has such a record and a100 does not |
| a100 wheel / sdist sha256 | relayed, **not independently verified here** | no release-run oracle to verify against |

That third row is why this is an assessment and not an adoption. A peeled tag
makes a100 pinnable; it does not make it published-and-installable, and the two
are different oracle kinds under rule 17.

## What discharges this

1. Kernel a101 reaches protected `main` with its evidence record — owner:
   `dotmac_starter_mt`, tracked in that repository's a101 release handoff.
2. The ADR-0016 cutover here: `ProductAssemblySpec.api_documentation` supplied
   in `build_spec()`, `vendor_cp.api_documentation` deleted rather than
   rewritten, and `src/vendor_cp/main.py` returned to the thin adapter it says
   it wants to be.
3. `dotmac-deployment-control 0.1.0a7` published with a release-run oracle. It
   declares `dotmac-kernel >=0.1.0a100`, so the moment it is pinned here the
   binding floor moves and `test_the_pin_is_exactly_the_highest_floor_anything_composed_declares`
   fails until the pin moves with it. Today a7 has no tag and a pin against it
   resolves to nothing.

The refresh responsibility for this observation is not a reminder: (1) and (3)
are both facts the `kernel-pin` job re-derives on every run, and (2) fails at
boot rather than drifting.
