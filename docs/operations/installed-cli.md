# `dotmac-platform` — the installed operator CLI

The Platform Control Plane's operator surface is a **console script on an
installed wheel**, not a directory of files an interpreter is pointed at.

```
docker compose --env-file .env -f docker-compose.production.yml \
  --profile ops run --rm --no-deps ops dotmac-platform <group> <command> [...]
```

That is the production form. There is no `python scripts/...` any more, because
there is no `scripts/` in the runtime image and no `PYTHONPATH` telling Python
to import from one.

## Why it is a wheel

The image used to set `PYTHONPATH=/app/src` and copy the source tree in. Two
things follow from that, and both matter more than the convenience it bought.

Nothing answered for the version. `vendor_cp` had no distribution metadata, so
any self-report had to come from a literal in a source file — the shape that let
`dotmac-deployment-control 0.1.0a4` ship correct bytes while reporting itself as
`0.1.0a2`. Every version this CLI prints now comes from what the **installer**
recorded.

And an entry point that is a PATH resolves against a working directory. A
container given `scripts/migrate.py` runs whatever is at that path, which is
whatever was last copied there. A console script resolves against a package.

## The command surface

`dotmac-platform diagnose owners` prints the authoritative table; it is the same
data every check reads, so it cannot drift from what the CLI actually does.

| group | what it covers |
| --- | --- |
| `admin` | platform administrators, vendor accounts, the composed migration, descriptor drift |
| `release` | product release evidence, pins, capability catalogues |
| `agreement` | commercial agreements |
| `approval` | approval policies, requests and decisions |
| `allocation` | entitlement allocations |
| `licence` | issuance, revocation, signing keys, delivery |
| `relay` | the platform outbox relay: activation -> allocation |
| `deployment` | the operator workflow over Deployment Control |
| `recovery` | the catalogue capture query and the recovery bundle |
| `diagnose` | questions about this process rather than about the fleet |

Global flags: `--format json|table` (default `table`) and `--version`.

## Draining the platform outbox

`dotmac-platform relay drain --worker-id <id>` claims one batch of
`public.platform_outbox_events` and delivers it. It is the drain that turns an
activated commercial agreement into a staged entitlement allocation: the
agreement owner enqueues `agreement.activated.v1` atomically with the
transition, and this is what carries it to
`vendor_cp.allocations.consumer.ContractEventConsumer`.

Two credentials are involved and they are different roles on the ONE
control-plane database. The delivery half is the ordinary `platform_api` DSN the
process already holds. The claim half is `VENDOR_RELAY_DISPATCHER_DATABASE_URL`,
the `platform_outbox_dispatcher` role — which holds `EXECUTE` on the kernel's
two leasing functions and no table privilege of any kind, so it can lease and
settle and can never read a business table.

**It refuses when that variable is unset**, with `config.invalid` and exit `2`.
That is deliberate and is the whole point of the command: "drained 0 events"
from a relay that never had a credential is indistinguishable from "drained 0
events" from a healthy idle relay, and one of those has to be a refusal.

`--worker-id` is required rather than defaulted. The lease is held BY that
identifier, so two invocations that silently shared one would each believe they
held the other's claim.

`dotmac-platform relay health` reports whether the drain is happening: pending
and overdue depths, the oldest overdue age, abandoned leases, dead letters, and
the same three counts narrowed to activation facts. A count that could not be
TAKEN comes back as null rather than zero — a zero that means "could not query"
reads exactly like a zero that means "nothing is wrong".

It also reports `relay_liveness_during_quiescence_measurable: false`, and that
is a real limitation rather than a placeholder. A relay that dies while nothing
is queued is invisible from the queue alone; proving it lives during quiescence
needs a durable heartbeat, which needs a table and a migration, and that is
scoped to the slice that composes the relay into the deployment. Until then the
gap is declared where a reader meets it.

The unauthenticated `/health/ready` probe publishes the VERDICT alone — one
member of a closed vocabulary, never a count. The numbers are here, behind a
shell on the host.

## Exit codes

| code | meaning |
| --- | --- |
| `0` | success |
| `2` | invalid invocation or configuration — nothing was attempted |
| `3` | an owner refused |
| `4` | the evidence needed is incomplete, absent or unreachable |
| `5` | execution began and failed |
| `6` | an integrity or identity mismatch |

**`3` and `4` are deliberately different numbers.** From outside the process
they look identical — it did not happen — and they mean opposite things about
whether to retry. A refusal is a decision: the owner looked and said no, and the
same command will be refused again. An absence is not a decision: nothing
looked, or what would have answered was unreachable, and the same command may
well succeed once the missing thing exists. A script that collapses them retries
the refusal and gives up on the absence, which is exactly backwards.

They stay apart through the container too: `docker run` and `docker compose run`
both propagate the container's exit status unchanged, and CI asserts that a
`4` observed inside is a `4` observed outside.

`6` exists next to `3` for the same reason at one level down. `0.1.0a4`
compared two digest encodings with a raw `!=` and refused with "the plan changed
after approval" — a formatting bug wearing a tampering refusal, which is the
worst failure mode available because it looks like the system working. A digest
that could not be READ is `6`; a digest that did not MATCH what an owner froze
is `6`; an owner declining is `3`.

Every refusal also carries a stable machine code (`owner.approval_refused`,
`evidence.not_found`, `integrity.digest_mismatch`, …). The message is for a
human and may change; the code may not.

## Secrets

**A secret never arrives as the value of a flag.** `/proc/<pid>/cmdline` is
world-readable for as long as a process lives, and `ps -ef` shows another user's
command line — a registration token leaked into a transcript on this fleet
exactly that way. Commands that need one take `--<name>-file` (a path this host
already holds) or `--<name>-stdin`.

```bash
printf '%s' "$password" | docker compose ... run --rm --no-deps -T ops \
  dotmac-platform admin create ops@example.com --password-stdin
```

Naming neither source is refused rather than silently waiting on stdin: a
forgotten flag would otherwise hang a deploy forever. Nothing secret is ever
printed — every credential-named field in any output is replaced with
`<redacted>`, recursively.

## The deployment workflow

Five commands, in this order, and the middle one is not ours.

Steps 1 and 2 exist because the ones after them could not otherwise be reached.
`deployment propose` freezes a target's desired state; until a command could
register a target and declare a desired state, there was nothing for it to
freeze, and the authorize step everybody described as "the installed CLI" had no
path to a plan. A surface whose later steps are unreachable reads as built and
is not.

```bash
# 1. Name a deployment this control plane is responsible for. Idempotent on
#    --target-ref: registering the same reference twice returns the same target.
dotmac-platform --format json deployment register-target \
  --command-id "$id-register" --target-ref vendor-cp-prod \
  --subject-ref "$customer_ref" --product-code vendor-control-plane \
  --environment production

# 2. Declare what it should converge on. --spec names a file holding a JSON
#    object; it is required, because an omitted spec would freeze an EMPTY
#    specification into an immutable plan digest and the approver would never
#    see that it was empty. Optionally bind to the target's current
#    --expect-record-version.
dotmac-platform --format json deployment set-desired-state \
  --command-id "$id-desired" --target-id "$target" \
  --release-ref "$release" --spec ./desired-spec.json

# 3. Freeze the target's desired state into an immutable plan.
dotmac-platform --format json deployment propose \
  --command-id "$id" --target-id "$target" \
  --policy-code deployment.rollout --policy-version 1

# 4. Open and decide the approval, bound to what step 3 printed.
dotmac-platform approval open \
  --command-id "$id-open" --policy-code deployment.rollout --policy-version 1 \
  --subject-type deployment_plan --subject-id "$plan_id" \
  --content-hash "$approval_content_hash" --requested-by "$admin_id"
dotmac-platform approval decide \
  --command-id "$id-decide" --request-id "$request_id" \
  --approver-id "$admin_id" --content-hash "$approval_content_hash"

# 5. Carry the decision into the frozen plan and request the rollout.
dotmac-platform --format json deployment authorize \
  --command-id "$id-auth" --plan-id "$plan_id" \
  --approval-request-id "$request_id" --rollout-ref "$rollout_ref" \
  --expect-plan-digest "$plan_digest"
```

Step 5 prints an `authorization_ref`. **That is the authorization run identity**
the deployment foundation binds between the canonical descriptor and its own
execution report. It is the reason this command exists.

`--expect-plan-digest` is optional and compares byte for byte against what the
module froze. A difference exits `6` before the approvals owner is asked
anything: the assembly stopped first, so nobody refused.

**Registration is not authorisation.** A registered target with no desired
state converges on nothing, and step 1 says so in its own output: the module
leaves it `REGISTERED`, this assembly maps that onto delivery `SUSPENDED`, and
step 2 is what promotes it. Do not read a successful step 1 as permission for
anything.

The CLI decides none of this. It calls `register_target`, `set_desired_state`
and `propose_plan`, carries an `ApprovalEvidence` the approvals module produced,
and calls `request_rollout` — the six things ADR-0013 § 2 permits, as amended by
A6. What a plan contains, whether a target may take a desired state, whether a
transition is legal and whether evidence binds are all upstream. In particular
there is no local "has anything changed?" check before step 2: the module bumps
`desired_revision` unconditionally, on purpose, because the revision records
that a decision was taken.

## Rendering, applying, observing, rolling back

Those belong to `dotmac-deployment-foundation` and are not reimplemented here.
`dotmac-platform deployment foundation — <args>` forwards the argument vector
to that project's own `dotmac-deploy` console script, verbatim, and returns its
exit status unchanged — remapping it would invent a verdict this process did not
compute. If the Foundation is not installed the passthrough exits `4`: the tool
was absent, nothing refused.

## Diagnosing an installation

```bash
dotmac-platform --format json diagnose self --strict
```

Resolves every `vendor_cp` module this process reached and asserts it lives
under the interpreter's `purelib` or `platlib`, taken from `sysconfig` rather
than from anything the package says about itself. It also checks that
`vendor_cp` resolves to exactly one path, that every declared owner module can
be located, and that no mutating owner is claimed by two commands.

Run from a checkout it **fails**, and that failing is the point: a check that
passed in both places would prove nothing while looking like proof.

## The production-shape ratchet

`src/vendor_cp/installed_surface.py` holds the set of production shapes that are
refused — `PYTHONPATH=src`, an interpreter handed a path under `scripts/`, an
`ops` container handed a script path, rsync of executable deployment assets, and
checkout-relative production commands — together with the exact set of
occurrences that still exist and, for each, why and what retires it.

It is **set-shaped and two-directional**: it records the matched text rather
than a count, because a count survives a swap — one path retired while another
gains the same ability — and a swap is the move worth catching. A new occurrence
fails until it is declared, a retired one fails until the declaration is
lowered, and an exchange of one for another fails both ways at once.

The sanctioned side is checked by **identity, not by string**:
`sanctioned_entry_points()` reads the console-script names the installer
recorded and never writes one down, because a literal would restore exactly the
substring matching it replaces. A sanctioned invocation runs code inside the
installed distribution — which is not in this tree — so it can never appear in a
scan of it; an unsanctioned one is in the tree and always does. When the
distribution cannot be resolved the region is **unmonitored**, reported as such,
and never treated as a pass.

## Migrations

`dotmac-platform admin migrate` is the one composed migration owner. It applies
`heads` and refuses every other target, because `alembic upgrade
ap_0001_approvals` stops after that module's own migration and COMMITS a DML
grant vendor `v012` exists to remove — an ordinary-looking command with a
dangerous stopping point.

The lineage travels beside the deployment as **data**, not inside the wheel:
packaging it would put a top-level `alembic` directory at the wheel root,
colliding with the Alembic distribution's own import name.
`VENDOR_MIGRATION_ROOT` names where it landed (`/app` in the image) and defaults
to the checkout layout everywhere else.

## Descriptor drift, in both directions

`dotmac-platform admin descriptor-drift` compares the accepted descriptor
(`deploy/product.toml`) with a catalogue capture from a target, and reports
**declared-but-absent** AND **present-but-undeclared**. The second is the one
that sees an operation nobody declared: on 2026-08-30 a create-only bootstrap
created `mod_deploy` and applied two revisions, every declared object still
existed, and a check asking only "does everything declared exist?" was green on
a database that had moved out from under its contract
(`docs/operations/descriptor-reconciliation-2026-08-31.md`).

It is two steps, because **this command connects to nothing**. A checker that
could read the database it validates could also arrange for its own check to
pass, and deny case D1's connecting-entrypoint allowlist is empty.

```
# 1. on the target, as an operator, a deployment run or a recovery run.
#    `--format` is a global flag and goes before the group.
dotmac-platform --format json recovery capture-sql \
  | jq -r .data.sql \
  | psql -tA -d "$TARGET_DSN" -f - > capture.json

# 2. anywhere the descriptor is
dotmac-platform admin descriptor-drift \
  --descriptor deploy/product.toml --capture capture.json
```

Exit `0` when the two agree, `6` when they do not — a mismatch, not a refusal:
nobody decided anything, something is simply not what it claimed to be. `4` when
the capture is absent or missing a key it needs; an absent key is never read as
an empty one, because that would turn a truncated capture into a clean report.

A clean report carries how many subjects it compared. An empty findings list is
also what a check that examined nothing produces, and the counts are what tell
those apart.

Scope, stated rather than implied: the **database half** only. `[image]` and
`[assembly]` describe the running application, and a catalogue capture is not
evidence about either — those halves advance on different events (ADR-0017 § 8).

## What was migrated, and what deliberately was not

| script | disposition |
| --- | --- |
| `scripts/migrate.py` | → `dotmac-platform admin migrate` |
| `scripts/create_platform_admin.py` | → `dotmac-platform admin create` |
| `scripts/catalogue_product_release.py` | → `dotmac-platform release record` |
| `scripts/recovery/build_bundle.py` | → `dotmac-platform recovery bundle` |
| `scripts/recovery/capture_catalog.sql` | → packaged data, `recovery capture-sql` |
| `scripts/check_governance_pin.py` | kept — stdlib-only, and its CI job's value is that it needs no install |
| `scripts/reconcile_backfill_shadow.py` | kept — a rehearsal tool that connects to nothing and is never a production instruction |
| `scripts/verify_ghcr_package_state.py` | kept — a workstation tool needing a credential CI must not hold |
| `scripts/deploy_production*.sh`, `bootstrap*.sh` | kept — they run on the HOST, outside any container, and retire when the deployment foundation owns the host leg |
| `scripts/materialize_production_secrets.py` | kept — same host leg; its `PYTHONPATH=src` is declared debt with a named retirement |
