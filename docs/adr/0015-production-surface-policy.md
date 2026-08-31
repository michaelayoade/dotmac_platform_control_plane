# ADR-0015: The production surface policy, and the profile that states it

- **Status:** ACCEPTED 2026-08-31 by Michael Ayoade, the owner and only
  approver. **Acceptance is not deployment.** `production-composed-v1` is
  declared here and adopted nowhere; § 6 records the gate it waits on and is
  kept current rather than deleted on acceptance.
- **Date:** 2026-08-31 proposed, 2026-08-31 accepted
- **Owner:** Michael Ayoade
- **Follows:** `dotmac_starter_mt` ADR-0003, which made a deployment profile a
  surface selector and forbade feature code branching on a profile name
- **Depends on:** ADR-0014, which made the `platform_admin` facet the console's
  only browser authentication owner. `production-composed-v1` names the console
  as its primary surface, so that repair is a precondition of this profile
  being adoptable at all — see § 6, which records what is still missing
- **Relates to:** `docs/operations/composition-census-2026-08-30.md`, which
  measured the production estate this decision is calibrated against

## 1. Context — the production host published a simulation

`vendor_cp.providers.build_provisioning_provider` builds exactly one
implementation of the kernel's provisioning contract, and it is
`LaboratoryProvisioningProvider`: a side-effect-free simulation that invents a
plan, pretends to apply it, and can be asked to pretend to fail.
`VENDOR_PROVIDER_MODE=fake` is not a stub standing in for a real driver behind
the same routes. It is the only implementation that exists, and
`validate_runtime_configuration` fails startup for every other value (hard rule
4, deny case D3).

`production-bootstrap` version 2 withheld `licence_delivery` and `offers`. It
did not withhold `provisioning`. So the production host published
`POST /platform/vendor/provisioning/plan`,
`POST /platform/vendor/provisioning/apply`,
`GET /platform/vendor/provisioning/operations/{id}` and
`POST /platform/vendor/provisioning/operations/{id}/cancel`, with the real
response shapes and nothing marking them as fiction.

Calling that a withheld-surface oversight would be generous. The surface was
published, and what it published was a fabricated result returned to an
operator through an authenticated production API.

The second half of the context is quieter. `load_deployment_profile` fell back
to `full` when `VENDOR_DEPLOYMENT_PROFILE` was unset, everywhere, including
production. `scripts/deploy_production.sh` greps the host env file for the
exact line, which covers the deploy path and only the deploy path: a container
restarted by `docker compose up`, by the Docker daemon's restart policy, or by
a host reboot never passes that grep. The fallback published every withheld
surface — the two commercial ones and the laboratory.

## 2. Decision — three rules, stated separately because they fail separately

**R1 — a profile that publishes the provisioning laboratory declares itself a
laboratory.** `VendorDeploymentProfile.laboratory` is required to be true for
any profile exposing `provisioning`, and a laboratory profile can never be
`production_accepted`. Checked in `__post_init__`, so the combination cannot be
written down at all.

**R2 — a production environment refuses a profile that mounts provisioning
while the provider mode is `fake`.** `validate_profile_for_environment` runs at
boot, before licence key custody is installed. It is keyed on the PROVIDER MODE
rather than on R1's flag: the flag is the profile module's own bookkeeping,
while the provider mode is what decides whether an operator receives a real
result or an invented one. R1 makes R2 unreachable today. R2 is written anyway,
because R1 protects the profiles declared in this repository and R2 protects
the process that actually boots.

**R3 — production has no default profile.** Outside production an unset
`VENDOR_DEPLOYMENT_PROFILE` still resolves `full`, because a developer should
see the whole assembly. In a production environment an unset or blank value
raises. The deploy-path grep stays; it is now the cheap early check rather than
the only one.

## 3. Decision — `production-composed-v1`, and what "accepted" means

`production-bootstrap` is corrected in place to version 3, which additionally
withholds `provisioning`. It remains the deployed profile. A version bump
rather than a silent redefinition: its effective surface set changed, and
someone reading `VENDOR_DEPLOYMENT_PROFILE=production-bootstrap` on a host is
entitled to know which composition that name meant.

`production-composed-v1` is the TARGET composition. It publishes:

| Surface | Why it is accepted |
| --- | --- |
| `console` | The platform-admin shell. Read-only, and since ADR-0014 authenticated by exactly one owner — the `platform_admin` facet. Accepted, not yet usable: see § 6. |
| `allocations` | One `GET`. The read-only allocation view over the composed module. |
| `release_evidence` | Declarations only — it contributes no router at all. |

and withholds:

| Surface | Why it is not published |
| --- | --- |
| `provisioning` | R1/R2. Its only implementation simulates. |
| `offers` | Vendor-owned pricing whose complete browser and API evidence does not exist. § 5. |
| `licence_delivery` | Same, and its ownership moves under ADR-0010. § 5. |
| `accounts` | An operator WRITE surface. § 4. |
| `contracts` | An operator WRITE surface, nine mutating routes. § 4. |
| `vendor_approvals` | An operator WRITE surface. § 4. |

Every profile now carries an explicit `surface_inventory` stating what it
publishes, checked at construction against the full roster of composed vendor
surfaces. A withheld set says what a profile removes and is silent about
everything added after it was written; an inventory says what a deployment
publishes, and its completeness check means a tenth vendor feature cannot join
a production profile by simply existing.

## 4. Why the write surfaces start withheld

The 2026-08-30 composition census measured the production database directly:
every table in `mod_ealloc`, `mod_approvals`, `mod_agreements` and
`mod_licensing` holds zero rows, and `platform_admins` is empty, so no
authenticated caller has ever reached any of them.

That is not an argument that these surfaces are wrong. It is an argument about
ORDER. The first production write through `POST /platform/vendor/contracts`
will create the first production commercial agreement, through a path no one
has exercised end to end in production. Publishing the read surfaces first
makes that first write a deliberate, separately-reviewed step rather than a
side effect of adopting a profile.

Each of these returns to the inventory by the same route as offers and
licensing: its own evidence, its own version bump.

## 5. Offers and licensing wait for evidence, not for time

ADR-0006 § "Offers and licensing stay disabled" already withholds both. This
ADR does not relax that and does not schedule it. The condition is stated as an
ENFORCEABLE premise rather than a date: both surfaces enter a production
profile's inventory when their complete browser and API evidence exists —
authenticated end-to-end exercise of the operator flow on a real deployment,
not a repository-local test. Per hard rule 17 that evidence is an external
oracle this repository cannot observe, so no test here discharges it.

## 6. Adoption gate — `production-composed-v1` is declared, not adopted

`scripts/deploy_production.sh` and `.env.production.example` still pin
`production-bootstrap`. Two things have to be true before that changes, and
only the first of them is done.

**Done — the console has one browser authentication owner.** ADR-0014 landed
the repair, and it landed as SUBTRACTION: `console_shell` now declares no
authentication dependency of its own, leaving the composed `platform_admin`
facet as the sole owner. Before it, a valid browser session passed the facet
and was then refused by the handler's bearer-only guard, so the route was
unreachable with exactly the credential it accepts. That is why the console can
be listed as an accepted surface here at all.

**Not done — no session can currently be obtained.** The assembly declares no
form-parsing library, so `POST /platform/login` cannot read its own form. The
console is therefore reachable BY a valid session while no valid session can be
created. That defect is not this profile's to fix — it is a dependency
declaration in `pyproject.toml`, owned by the lane that owns that file — and
this section states it rather than letting the inventory imply an end-to-end
operator experience that does not exist today.

So the inventory's claim is precise and deliberately narrow: `console` is an
ACCEPTED SURFACE (single-owner authentication, platform-admin only, read-only),
not a USABLE one. Adoption additionally requires the login path to work and an
explicit operator action switching the host profile. Until both, this profile is
a checked-in declaration and nothing else. No production state is changed by
this ADR.

## 7. Consequences

- The provisioning laboratory disappears from the production host at the next
  deploy of `production-bootstrap`. No data is affected: the laboratory owns no
  table.
- A production container restarted outside the deploy path with no profile now
  fails to boot rather than starting with `full`. This is the intended trade:
  a failed boot is visible, a silently over-published API is not.
- `tests/unit/test_production_runtime.py` must now name a profile. It reached
  key custody through the fallback R3 removes, so leaving it alone would have
  meant a suite asserting against a boot that can no longer happen.
- Withholding remains a SURFACE decision. Every stateful module manifest stays
  composed under every profile, and
  `tests/architecture/test_deployment_profile.py` proves both halves per
  profile — the manifest is still registered in a `ModuleRegistry` built from
  that profile's spec, and the lineage head still resolves in the composed
  Alembic graph under the branch label the surviving manifest declares.
