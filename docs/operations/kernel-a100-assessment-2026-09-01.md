# Kernel a98, a99 and a100 — one boundary, measured; a100 is not a regression

**Status:** assessed on 2026-09-01, and revised the same day when an independent
arbitration settled the question this document had left open. The pin holds at
`0.1.0a98`. **No pin move is possible yet**: the repair lands in a101, and a101
has not been allocated, published, tagged or verified. The obligation moves to
that artifact and to the ADR-0016 cutover, both named below with their owners.

This is an as-of observation carrying its coordinates and a named refresh
responsibility, not a release claim (`AGENTS.md` rule 17).

## The finding, in one paragraph

`dotmac-kernel` a98, a99 and a100 share a long-standing under-declared public
import boundary: importing the public `create_app` symbol reaches a
product-owned PostgreSQL driver that no declared dependency supplies. The three
versions behave IDENTICALLY under it. **a100 therefore introduced no regression**
— it inherited the defect, and a98 is the version this repository pins and runs
in production today. Production is not broken by this: the deployed assembly
supplies the missing driver itself. What the boundary costs is INDEPENDENT
ARTIFACT ADOPTABILITY — a clean install of the kernel's own declared dependency
set cannot reach that symbol — and those are different properties. The repair is
kernel a101.

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

**3. a100 — and every kernel after it — requires a change to how this assembly
is composed.** Kernel a100's
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

This obligation is NOT discharged by waiting for a101. The same `RuntimeError`
and the same required field are present on the kernel's protected `main` after
the a101 import-boundary repair merged (`6f1a2a47`), so whichever version this
assembly moves to, the cutover is owed with it.

**4. The import boundary is real, is identical at a98, a99 and a100, and a100
did not introduce it.** `dotmac_starter_mt`
`docs/inventories/kernel-a101-release-handoff.md`, on protected `main`, states
that a100 "is published and tagged but is not adoptable: a clean install of its
declared dependency set cannot import the package surface because the root
import reaches a product-owned PostgreSQL driver", and that a101 is the intended
target.

A first probe from this consumer's position could not reproduce that as an a100
property, and this document originally recorded it as unreproduced. That was
under-measured rather than wrong: it collapsed two DIFFERENT failures into one
"fails" column. An independent arbitration then settled it. Run
**33513594292**, job `kernel-a100-arbitration`, branch
`probe/kernel-a100-adoptability`, 2026-09-01: the digest-verified published a98,
a99 and a100 wheels installed with `--only-binary=:all:`, no checkout, no
`PYTHONPATH`, and an installed set EQUAL to the resolved `Requires-Dist` closure
(23 distributions), with a stray-source detector proved sensitive by three
planted bypasses and one unplanted negative control.

| condition | root import | `create_app` symbol | invoke |
| --- | --- | --- | --- |
| no driver, no DSN | PASS | FAIL `ArgumentError` | FAIL |
| **no driver, DSN set** | PASS | **FAIL `ModuleNotFoundError: psycopg`** | FAIL |
| driver + DSN | PASS | PASS | PASS |

**Identical at all three versions.** The middle row is the one the first probe
never asked for, and it is the whole mechanism: with a DSN present, resolving
`create_app` walks `dotmac_kernel/__init__.py`'s `__getattr__` into
`app_factory`, into `middleware/tenant.py`, into `dotmac_kernel.db`, into
`DatabaseRuntime.from_urls`, and out to a driver nothing declares. Without a
DSN the same walk dies one frame earlier on an unparseable URL, which is what
the first probe saw and read as "fails for an unrelated reason".

Two corrections follow, and both matter:

* **The handoff's mechanism is real.** It is the `create_app` symbol rather than
  the package root — the root imports cleanly at all three versions — but the
  under-declared reach it describes is there.
* **It is not an a100 property.** `Requires-Dist` is byte-identical across a98,
  a99 and a100 and declares no `psycopg` in any extra; the only module-scope
  path is `middleware/tenant.py` importing `dotmac_kernel.db`; and the six
  modules new to a100's package root — `api_documentation`,
  `credential_lifecycle`, `database_catalog_comparator`, `facet_principal`,
  `permission_provisioning`, `product_database_catalog` — introduce no driver.
  **a100 regressed nothing.** The defect is present at least at a98, and a98 is
  what this repository pins and what runs in production.

So a100 is not adoptable as an independent artifact — and neither is a99, and
neither is the a98 this deployment runs. That is not a reason to adopt a100: it
is a reason to stop describing the defect as a100's.

**5. A repin to a100-or-later makes the readiness ratchet's dormant half live.**
The same probe asked each version whether `ModuleManifest` carries the
`database_catalog` field that
`scripts/check_product_database_catalog_readiness.py` looks for: absent at a98
and a99, **present at a100**. Whichever version this assembly eventually moves
to — a101 on current evidence — carries it, so the repin is also the moment the
module half of that ratchet stops being a forward probe, and
`test_the_module_probe_is_dormant_because_the_pinned_kernel_carries_no_field`
will go red in the same review and demand that it be re-read as a measurement of
the modules rather than of the kernel generation. (a101 has not been published,
so "a101 carries it" is an expectation from a100's surface and not a
measurement; it is measured when a101 exists.)

## Coordinates

| Fact | Value | Oracle |
| --- | --- | --- |
| a100 peeled commit | `917181b38dcc5954bac932b630909afdfb19012b` | `peeled_tag` `dotmac-kernel-v0.1.0a100` |
| a100 on the private index | listed | the simple index, read in run 33506350578 |
| a100 release run | **none recorded** | the kernel's publication commit carries no run id or artifact digest; a99 has such a record and a100 does not |
| a100 wheel / sdist sha256 | relayed, **not independently verified here** | no release-run oracle to verify against |
| a98/a99/a100 import boundary | identical | run **33513594292**, job `kernel-a100-arbitration` |
| **a101** | **not allocated, not published, not tagged, not verified** | no oracle of any kind exists for it; the repair commit `6f1a2a47` is a source fact, not a release one |

The release-run row is why this is an assessment and not an adoption. A peeled
tag makes a100 pinnable; it does not make it published-and-installable, and the
two are different oracle kinds under rule 17. The last row is why this change
moves no pin: an unallocated version has no coordinates to pin, and a repin
against one would resolve to nothing.

## Operational functionality is not artifact adoptability

The ruling this document was revised under, stated so a later reader cannot
collapse the two again:

> Production a98 is not declared broken at runtime; its assembly currently
> supplies the missing product dependency. The distinction is **operational
> functionality versus independent artifact adoptability.**

Both statements are true at once, and each is checked by a different thing:

| property | who answers | today |
| --- | --- | --- |
| this deployment boots and serves | this assembly's own lanes — `image`, `postgres`, the clean-install acceptance | yes, on a98 |
| the kernel imports from its own declared dependency set alone | the kernel's home repository, on a clean install | no, at a98, a99 and a100 alike |

Nothing in this repository can repair the second, and pinning a different
already-published version does not either — a99 and a100 have the identical
boundary. The repair is a101, and it is a kernel-side change.

## What discharges this

1. Kernel **a101** is allocated, published, tagged and independently verified,
   and its evidence record reaches protected `main` — owner: `dotmac_starter_mt`,
   tracked in that repository's a101 release handoff. The import-boundary repair
   itself is merged there as `6f1a2a47` (starter PR #573), which makes the
   database import lazy and adds clean-environment gates proving the public
   `create_app` symbol imports with DSNs and `PYTHONPATH` absent and `psycopg`
   uninstalled, while `dotmac_kernel.db` stays out of `sys.modules`. **a101 is
   the first release that would have an honest operation-2 boundary. It does not
   exist yet**, and no pin in this repository may name it until it does.
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

## The floor has a second input, and now it is executed

Governance ADR 0021 § 10, as RULED on 2026-09-01: the effective floor of an
assembly is the maximum of (a) every composed distribution's installed
`Requires-Dist` and (b) the assembly's own declared direct kernel constraint —
its own imports join the maximum.

Cite that carefully, because the checked-in record does not yet say it. § 10 as
written states the opposite in as many words — "An assembly's OWN imports are
not an input to the maximum as written above" — and carries the question into
open decision 24, naming this repository's test as the place the premise is
"recorded ... as a condition to be added in the same change that first breaks
it". This repository's PINNED governance revision (`a19259b1`) predates § 10
altogether. So the ruling runs ahead of the record: this lane is deliberately
STRICTER than the governance text it cites, the premise is executed here rather
than recorded for later, and the record owes an amendment.

The measured equality above, `pin == max(composed floors)`, is correct today
only because nothing in `src/vendor_cp` imports a kernel name its composed
modules do not already require. That was a coincidence, it was an UNSTATED
PREMISE, and nothing checked it. Left unstated, the equality rule would one day
drag the pin DOWN to a kernel this assembly cannot run on: the defect of
`dotmac-deployment-control 0.1.0a5`, wearing the assembly's clothes, and just as
silent.

`kernel_floor.py assembly-satisfied`, executed in the `kernel-pin` job, states
it where it can fail: every kernel module and every top-level name the
assembly's own source imports must be provided by an installation of the
composed maximum. It refuses when the installed kernel is not that maximum, when
the assembly imports nothing (an empty question passes for the wrong reason),
and — the distinction this whole programme turned on — when an import fails
because something OUTSIDE the kernel is missing from the environment, because a
missing driver is not a missing kernel symbol.

Its sensitivity is not argued, it is observed, in both directions on the same
day. Unplanted, run **33516652998** job `kernel-pin`:

> 65 kernel names across 14 modules, all provided by dotmac-kernel 0.1.0a98 —
> the composed maximum, from dotmac-deployment-control

Planted — `src/vendor_cp/api_documentation.py` importing
`dotmac_kernel.api_documentation`, a module first shipped at a100, absent at the
a98 pin, and the exact module the ADR-0016 cutover will one day make this
assembly import for real — run **33516674334**, branch
`verify/assembly-floor-plant` (PR #113, never merged), job `kernel-pin` RED:

> error this assembly's own source imports `['dotmac_kernel.api_documentation']`,
> which dotmac-kernel 0.1.0a98 does not provide. The assembly's OWN floor is
> therefore ABOVE the highest floor anything composed declares …

The planted job stopped THERE, before the mutation lane ran, so the red is
attributable to this check and to nothing else in the job.
