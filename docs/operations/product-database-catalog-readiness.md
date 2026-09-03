# Product database catalogue readiness

**Status:** held on 2026-08-31. This checkout publishes no product database
catalogue and its descriptor binds no such digest.

The product database catalogue is a build-once declaration composed from typed
facts supplied by their owners. A running database is comparison evidence only;
it is never an authoring source.

## Repository-local blockers

The exact pins in `pyproject.toml` currently compose six stateful module
manifests without a database-catalogue contribution:

- `approvals`
- `commercial_agreements`
- `deployment_control`
- `entitlement_allocation`
- `licensing`
- `release_catalog`

`scripts/check_product_database_catalog_readiness.py` derives that set from
`assembly.STATEFUL_MODULES`. Its test compares the result with the declared debt
in both directions, so adding or removing a composed stateful owner cannot pass
silently. The set names ownership gaps, not table structure, and therefore does
not duplicate any module's schema contract. Presence is all this part proves: a
non-null attribute is not proof that canonical bytes parse, cover the selected
plane or agree with a live observation.

**The other direction — a module adopting a contribution — is live at the a100
pin.** The exact-pinned kernel's `ModuleManifest` declares `database_catalog`,
so each of the six rows now records a fact about that module's pinned release,
not a fact about an unreachable kernel axis. The prior dormant premise was
retired in the same change that raised the pin;
`test_the_module_probe_is_live_on_the_pinned_kernel` holds the inverse so a
future kernel cannot silently make the axis unreachable again.

The command itself is now executed by
`test_the_commands_exit_code_is_observed_in_both_directions` rather than only
described here. Nothing else calls it — not CI, not the `Makefile` — so its
documented exit 2 had never been run and its zero branch had never been reached
by anything at all.

Deployment Control's candidate source contribution is not evidence available to
this assembly. It becomes usable only after its kernel dependency exists in a
published version, Deployment Control publishes a verified artifact carrying
the contribution, and this repository exact-pins that artifact.

## Fail-closed product-level register

Seven further obligations are explicit in the script's typed blocker register.
They are not folded into the module ratchet because this checkout cannot derive
their truth without unpublished APIs or release-time held bytes:

1. **Observer and comparator availability.** The exact-pinned kernel must expose
   a supported Postgres tables/columns observer and a pure comparator. Platform
   CP must invoke them over held snapshot and observation bytes. Recognising an
   identifier string or accepting a caller-built “equal” result is not
   verification.
2. **Held snapshot digest verification.** The release path must hold the exact
   canonical bytes, recompute their digest, and attest or compare only those
   verified bytes. A digest supplied alongside bytes but never recomputed is not
   a binding.
3. **Product identity mapping.** The accepted descriptor's frozen product
   coordinate is `dotmac_vendor_control_plane`; the assembly name is
   `dotmac-vendor-control-plane`. The difference is not silently normalised and
   neither string is renamed here. The product factory needs one explicit,
   reviewed typed mapping between them.
4. **Complete schema coverage.** The product factory must require every selected
   stateful module contribution exactly once and also require kernel-owned and
   Platform-CP-owned `public` fragments. Module presence alone cannot prove
   this, and neither the descriptor's schema-name list nor a live catalogue is
   an authoring source.
5. **Release Catalog attestation support.** The exact-pinned Release Catalog
   must support distinct typed, singular attestations for module and product
   database catalogues. A generic attachment or one kind overloaded across both
   scopes cannot prove which completeness contract was attested.
6. **Release artifact binding.** Platform CP's release path must emit the
   canonical product-catalogue bytes beside the existing product manifest and
   attest both against the same image or artifact. Two individually valid
   attestations from different builds do not describe one releasable product.
7. **Accepted descriptor-v2 binding.** This checkout's accepted descriptor is
   `ProductDeploymentSpec.v1` and has no `database.catalogs` coordinates. A
   candidate v2 must embed the verified product snapshot's schema, contained
   path and digest, and successful deployment must promote that descriptor
   atomically. Only Foundation's published v2 parser may validate the coordinate
   shape; this source check deliberately does not approximate it.

The blocker register is fail-closed review debt, not a claim that those checks
already exist. An entry is removed only in the same review that installs its
machine proof. Consequently the command continues to exit 2 even after all six
module owners publish contributions.

## Further required publication

Clearing both debt sets additionally requires:

1. kernel-owned structure for the kernel tables in `public`;
2. assembly-owned structure for Platform CP tables in `public`;
3. a published kernel containing the canonical factories and verifier;
4. a published Foundation descriptor-v2 and structural-evidence contract.

`ModuleManifest.version` is the module release version according to the pinned
kernel's authoritative type; `contract_version` is the kernel manifest
generation. The existing product-manifest generator therefore continues to use
installed distribution metadata as artifact identity and records a differing
manifest version as a defect rather than relabelling it a contract version.

No future package version is named here. Versions become facts only through the
release/tag oracles required by `AGENTS.md` rule 17.
