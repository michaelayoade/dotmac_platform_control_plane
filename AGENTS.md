# AGENTS.md — hard rules (canonical)

The Vendor Control Plane is an **assembly** over the pinned `dotmac-kernel`. It
owns **vendor/product lifecycle** (accounts, provisioning contracts, later
deployment lifecycle). It is **not** a product data plane and never holds a
product's tenants, subscribers, or customer records.

Each rule names the test/contract that enforces it. If a rule here and a test
disagree, fix the drift.

1. **Kernel is a pinned dependency, consumed public-surface-only.** Import only
   the kernel's public API — `SUPPORTED_MODULES` + top-level `__all__`. No copied
   kernel files, no private/internal names, no import-path shims
   (`tests/architecture/test_deny_cases.py::test_d5_*`, **D5**).
2. **One control-plane database; the kernel owns the engine.** No `create_engine`
   / `sessionmaker` in vendor code, no product database DSNs (**D1**).
3. **No product data-plane imports.** Never import `dotmac_sub`/`crm`/`erp`/`app`
   (**D2**). Cross-system collaboration is via APIs/webhooks only, per the
   Dotmac app-independence standard.
4. **Vendor-owned simulation provider only, this phase.** A non-`fake`
   `VENDOR_PROVIDER_MODE` FAILS STARTUP; no real-provider SDKs are imported
   (**D3**). Runtime code implements the side-effect-free laboratory provider
   locally and never imports `dotmac_kernel.testing`; the kernel test kit is
   test-only. No **Vendor-owned** fleet tables and no Vendor
   `DeploymentRunner`: ADR-0011 contracts the cutover that composes the
   independent Deployment Control module's `mod_deploy` desired-state tables,
   while real provider transport remains exclusively behind Dotmac Integrator
   (ADR-0007). The prohibition is on a VENDOR-owned fleet owner; composing the
   independent one is what makes it affordable. `src/vendor_cp/provisioning/`
   and `src/vendor_cp/deployment_profile.py` are neither — a contract
   laboratory that owns no table, and a surface selector.
5. **Platform-actor auth through the kernel, and ONE owner per route.** One
   authority, two kernel-owned transports: the JSON API depends on
   `dotmac_kernel.platform_auth.require_platform_admin` (bearer), and the
   composed `platform_admin` facet authenticates every non-entry browser route
   through its declared `kernel_platform_session` profile, whose provider is
   `require_platform_web_auth` (session cookie). Vendor code re-implements
   neither and DECLARES neither on a browser route: a route answering to two
   authentication owners has no single authority over who may reach it, and the
   console proved it — a valid browser session passed the facet and was then
   refused by a bearer-only handler guard, making `/platform/console`
   unreachable with exactly the credential it accepts. Browser cookies never
   authenticate API routes and API bearer credentials never become browser
   sessions. Every unsafe browser route keeps `require_csrf`. Checked on the
   CONSTRUCTED dependency graph, never on source text — a signature scan cannot
   see a router-attached or nested dependency, which is how the two-owner shape
   survived (**D4**; ADR-0014;
   `tests/architecture/test_browser_authentication_ownership.py`,
   `tests/unit/test_console_browser_authentication.py`).
6. **Vendor logic lives in services; routes/web are thin adapters.** Business
   decisions have one named owner; adapters validate-authorise-delegate.
7. **Atomic, idempotent, audited mutations.** Account/lifecycle commands are
   typed, own their transaction, are idempotent, and write audit — reusing the
   kernel's transaction authority (`get_db`/`conflict_savepoint`) and audit
   write-side.
8. **Branch before committing; merge only on green.** Protected `main`. Pin the
   kernel to an EXACT version (`==`, never a range or caret); bump deliberately
   when a new alpha ships. **`pyproject.toml` is the authority for which
   version that is** — this file deliberately does not repeat the number. A
   second copy of a version literal is a second thing to forget, which is
   exactly how this line came to say `a8` while the pin said `a9`.
9. **Bindings state facts; plane selections state intent.** A
   `PrerequisiteBinding` says where an effect comes from, and this assembly
   binds every kernel effect required by the currently composed modules —
   including `tenant_scope_catalog.v1`, because
   kernel `0001` really does create `public.tenants` here. A
   `ModulePlaneSelection` says what this product installs, and it selects
   `PLATFORM` alone for `approvals` — never as a side effect of a version bump,
   and only behind the cutover contract that authorised it. Never reintroduce
   the a60
   model in which an absent binding selected a plane, and never create a tenants
   table, a sentinel tenant, or a nullable tenant column to satisfy a module
   (ADR-0028; `tests/architecture/test_migration_prerequisite_bindings.py`,
   `tests/migration/test_selected_planes.py`).
10. **Coverage is catalogue-derived; exceptions are named and ratcheted.** Two
    halves, and the distinction between them is the rule. WHICH tables get
    audited is never a literal list: module schemas go through the kernel's
    `audit_live_schemas`, `public` is classified from the live catalogue, and
    the vendor-owned subset is derived by diffing the lineages — so a table
    added tomorrow is covered the moment its migration runs. WHAT an exceptional
    category contains IS named exactly — `TENANT_CATALOGUE`,
    `UNMONITORED_SPLIT_SCOPE` — and every such set is
    ratcheted in both directions, so it cannot grow quietly or shrink without
    the declaration being lowered in the same change. A privilege proof over a
    hand-listed set of TABLES is the regression; a hand-listed set of
    EXCEPTIONS, each justified and dated, is the contract
    (`tests/migration/test_composed_live_catalog.py`,
    `tests/architecture/test_shadow_overlaps.py`).
11. **A deployment profile selects surfaces and nothing else, and production
    accepts only a profile that says so.** Read it once, in `build_spec()`. It
    may not withhold a persistence owner and may not change behaviour; feature
    code never branches on a profile name (ADR-0003, deny case D6).

    ADR-0015 adds the production half. A profile that publishes the
    `provisioning` surface must declare `laboratory=True` and can never be
    `production_accepted`, because that surface's only implementation is a
    side-effect-free simulation — publishing it in production answers an
    operator with a fabricated plan through an authenticated API. A production
    environment refuses such a profile at boot, keyed on
    `VENDOR_PROVIDER_MODE` rather than on the flag, and refuses an ABSENT
    profile rather than inheriting the `full` fallback that publishes every
    withheld surface. The deploy-script grep is the cheap early check, not the
    only one: it never runs on a restart.

    Every profile carries a `version` and an explicit `surface_inventory`
    checked for COMPLETENESS against the composed vendor surface roster, so a
    new feature cannot join a production profile by simply existing, and a
    profile whose effective surface set changes is a version bump rather than
    a silent redefinition of a name already on a host.

    **Withholding a route and dropping a manifest are different acts.** A
    withheld surface keeps its declarations, its behaviour, its schema and its
    migration lineage; only the routes go. The guard is derived from
    `assembly.STATEFUL_MODULES` rather than listing modules by hand — the
    earlier version named five while the assembly composed six — and proves
    both halves per profile: the manifest is still registered in a
    `ModuleRegistry` built from that profile's own spec, and the lineage's head
    revision still resolves in the composed Alembic graph under the branch
    label the surviving manifest declares
    (`tests/architecture/test_deployment_profile.py`).
12. **An authority cutover is contracted before it is composed, and its premise
    is checked.** ADR-0005 records the Approvals switch: the estate was MEASURED
    (`TARGET_ABSENT`), not assumed, and `v013` re-checks emptiness under
    `ACCESS EXCLUSIVE` in the same transaction that drops the legacy tables,
    failing closed if a row exists. `dotmac-approvals` is the authority;
    `vendor_cp.approvals.adapter` is the ONLY seam and is typed with no `Any`.
    The retired local writer's call sites are ratcheted at ZERO. Commercial
    Agreements follows the same checked-premise shape under ADR-0008 and
    `v015`: `dotmac-commercial-agreements` is the sole agreement lifecycle,
    history, audit and outbox owner; `vendor_cp.contracts.adapter` is the only
    seam; and the retired service/models call sites stay at zero. Licensing
    follows under ADR-0009 and `v016`: `dotmac-licensing` is the sole issuer,
    lifecycle, acknowledgement and revocation owner;
    `vendor_cp.licensing.adapter` is the only seam; Vendor temporarily retains
    product-held signing custody and delivery; and all six retired or
    ownership-ambiguous module paths stay at zero. Do not build
    parity, backfill, synthesized requests or sealed evidence against an empty
    estate — ADR-0031 governs a cutover WITH data, and this was not one. Composed
    and authoritative in code is NOT adopted
    (`tests/architecture/test_approvals_authority.py`,
    `tests/migration/test_authority_switch.py`,
    `tests/architecture/test_commercial_agreements_authority.py`,
    `tests/migration/test_commercial_agreements_authority_switch.py`,
    `tests/architecture/test_licensing_authority.py`,
    `tests/migration/test_licensing_authority_switch.py`).

    **Adoption is per owner and is evidence, not a neighbour's milestone.**
    Approvals and Entitlement Allocation cleared it on 2026-08-17 with
    production deploy `32022599873`; Commercial Agreements and Licensing
    switched after that deploy and are still below adopted. Each owner's
    ADR § "Adoption plan" carries what each owed. Both are discharged: approvals
    is at `0.1.0a5` with the `outbox_relay.v1` binding, allocation at `0.1.0a6`
    needing no new binding. **An effect a composed module declares must be
    bound**, and the requirement is DERIVED from the composed manifests rather
    than listed, because approvals wrote the relay from a1 and declared it only
    at a5 — for three releases this assembly satisfied an effect no test could
    see it needed.
13. **A guard exemption dies with its premise.** The assembly-local waiver for
    the legacy allocation tables shadowing `mod_ealloc` was REMOVED when `v014`
    dropped those tables, not lowered and not left describing nothing: an
    exemption whose premise has evaporated keeps widening a gate for facts nobody
    has examined (ADR-0018). The composed live-catalogue audit now consumes the
    kernel gate raw, with no subtraction at all. When you retire an exemption,
    delete its prose in the same change — `test_stale_claims.py` fails if a
    document still describes a retired exemption as live.
14. **Cross-repository engineering governance is pinned and required.**
    `.dotmac/standards-profile.json` names the enrolled authority and fully typed
    contract surface, and pins the accepted Governance source by exact commit.
    The `Dotmac engineering standards` CI job must execute that same immutable
    revision. Mutable tags/branches, copied rules, candidate mode, or a missing
    required check are not substitutes. The schema-9 external-connector ratchet
    is Governance-owned and transitional: this assembly records its measured
    baseline in `docs/external-connector-surface.md`, but never copies the
    detector or treats the ratchet as runtime isolation.
15. **Platform audit actions are declared vocabulary.** Every `vendor.*` action
    passed to `write_platform_audit_event` is declared by exactly one installed
    Vendor feature manifest, and every declaration has a real caller. Kernel
    a68 made the platform writer enforce the manifest registry; the a77 pin may
    not cross that boundary with undeclared actions
    (`tests/architecture/test_platform_audit_actions.py`; ADR-0007).
16. **Vendor licence delivery is transitional and frozen.** ADR-0010 schedules
    its transfer after Deployment Control and before Brand Profiles. Until that
    cutover, preserve only the current logging and authenticated offline-bundle
    paths: do not add network transport, a provider client or credential,
    scheduling, checkpoints, leases, backoff, or another retry owner. The
    Governance connector ratchet must remain at zero. At cutover,
    `dotmac-integration` in Dotmac Integrator becomes the sole owner of
    delivery attempts, retry, health and repair; Vendor retains only private-key
    custody plus thin immutable-artifact and acknowledgement adapters
    (`docs/external-connector-surface.md`; ADR-0010).
17. **Repository-local transition claims must be derived from repository-local
    facts. Release, registry and production-adoption claims require an
    authoritative external oracle.** Fleet rule, approved 2026-08-21.

    A test here proves what this repository contains — declared tables,
    per-file symbol call sites, `pyproject.toml` contents, a decision an ADR
    recorded. It cannot observe a registry tag, another product's cutover, or a
    production row count. Claims of that second kind are permitted only with
    the oracle named in the claim: a release run for "published and
    installable", a `<distribution>-v<version>` tag for "pinnable", the owning
    repository's `EXTRACTION.toml` `adoption_evidence` for "a product runs it",
    a deploy run id plus immutable image digest for "it deployed". Where no
    oracle exists, name the obligation and its owner instead of writing an
    assertion whose shape implies a check it cannot perform — the estate
    measurement in ADR-0011 § 4 is measured by an operator against a target
    Michael names explicitly, never inferred, and no test discharges it.

    **An absence describes a moment**, so it is never cited like a release. It
    is either an as-of observation carrying its coordinates, its date and a
    named refresh responsibility, or it is replaced by the repository-local
    decision it was standing in for. Prefer the second: "this assembly is
    deferred by ADR-0007 § 6" is derivable here and permanent until the ADR
    changes, where "another product has no first adopter yet" is a claim about
    a repository this one cannot see. Brand Profiles is the second form. The
    delivery-target estate is the first: measured empty on 2026-08-21 against
    the host Michael named, and its refresh responsibility is not a reminder —
    it is the under-lock re-check inside the forward revision that measurement
    licenses (ADR-0011 § 4). An as-of observation whose refresh lives in code
    cannot quietly age.

    The rule exists because a declaration called `AWAITING_RELEASE_TAG` asserted
    a distribution was absent from `pyproject.toml`, was described as gating on
    the release tag, and stayed green when the tag was published. It proved
    intent, not availability. `DEFERRED_BY_LOCAL_DECISION` is the corrected
    shape.

    Accepted fleet-wide as `dotmac_governance` ADR 0013 (merge
    `2d711cd594979ba0bc368382b7f5ea69bf21eaa4`, effective 2026-08-22), which
    defines the four oracle kinds and their required immutable coordinates.

18. **Composing an owner is not the same as retiring the writer that shares its
    subject.** ADR-0011's Deployment Control slice is greenfield for plans,
    rollouts, credentials and observations, and a narrow AUTHORITY CUTOVER for
    deployment-target identity — `register_delivery_target` and
    `licence_delivery_targets` held that subject. Classify by SUBJECT and
    WRITER, never by table name: the narrow name avoided the wrong owner LABEL,
    not the ownership.

    Both halves landed together in `v017`, and the seal is narrower than first
    specified. `DELETE` is revoked from `platform_api`; `INSERT` and `UPDATE`
    are RETAINED, because staging resolves against a projection row and an
    unwritable projection removes the delivery path ADR-0010 § 1 requires
    preserved. So the single-writer guarantee here is PROVENANCE plus a ratchet
    — `DeploymentTargetFacts` is constructible only in the deployment adapter —
    not a privilege. Weaker than a grant, and to be described as weaker.

    The inventory is at SYMBOL level with per-file call-site counts in
    `src/vendor_cp/cutover_readiness.py`, ratcheted in both directions and split
    between the write authority and the projection that outlives it. A
    path-level ledger stays green when a function is deleted and its module
    remains, which is the transition that matters. This technique is
    assembly-local and is deliberately not claimed as a fleet standard
    (`tests/architecture/test_cutover_readiness.py`;
    `docs/cutover-readiness.md`).
19. **A backfill is contracted before it moves anything, and its reports carry
    counts, categories and blocker reasons ONLY.** ADR-0012 contracts the
    commercial backfill: the cohort is stated exactly, every enumerated source
    row lands in exactly one of `MAPPED` / `EXCLUDED` with a stated reason /
    `BLOCKED` with a named dimension, and coverage — whether a source could be
    enumerated at all — is a SEPARATE claim, because an unenumerable source is
    an unknown number of rows and not zero.

    **No report emits an identifier, an amount, a label or a timestamp**, and
    that is structural rather than a convention: a report holds a cardinality or
    a member of a closed enum, report enum members carry `auto()` so a member
    value is never text, `Report` has no free-text field, `Count(` is ratcheted
    to one module, and `render()` checks every line against a grammar and the
    declared vocabulary. Stated as WEAKER than it sounds — the alphabet is
    closed, the meaning of each integer is not guaranteed.

    **Row-count parity and target semantic parity are different claims and are
    never collapsed.** There is no combined verdict; an unobserved dimension is
    `NOT_COMPARABLE`, never a quiet `MATCHED`. A transformation returns a
    CATEGORY, never a converted value, and refuses rather than repairs: an
    over-precise amount is not quantized, a differently-cased product code is not
    folded, a 24-month term is not called annual.

    The rehearsal reconciler emits SQL and never connects (deny case D1's
    allowlist stays empty), emits no `GRANT` at all, and its shadow schema is
    declared by no model and created by no revision — so it never reaches
    production. Its replay shape has no timestamp column or surrogate key; the
    PostgreSQL canary owns verification of that shape, while this rule records
    no transient test result.

    **Commercial term translation happens once at the typed Vendor boundary.**
    Commercial Agreements' `expiry_date` is inclusive; `ContractView` exposes
    the first uncovered day as `term_end_exclusive`, and the backfill source
    contract accepts only that named end-exclusive field. There is no
    caller-selectable convention. Full-cohort enumeration must come from an
    exactly pinned, upstream typed paginated agreement reader through the Vendor
    adapter — never a local replacement, a raw module-table query, or direct
    cross-application database access.

    The bounded assembly page walker derives run coverage from the owner's
    final-page sentinel inside one database-enforced `REPEATABLE READ, READ
    ONLY` snapshot; page-budget exhaustion stays NOT ENUMERABLE even when some
    rows were observed. Incomplete source coverage makes row-count AND
    target-semantic parity `NOT_COMPARABLE`, so a truncated count can never
    become green evidence.

    Gate definitions state enforceable conditions, not their current status. A
    gate condition whose evidence is a release run, peeled tag, deploy run or
    adoption citation cannot be recorded as discharged from repository-local
    evidence — rule 17, made structural
    (`tests/architecture/test_commercial_backfill.py`,
    `tests/migration/test_commercial_backfill_replay.py`;
    `docs/commercial-backfill-dossier.md`; ADR-0012). Current evidence and state
    belong in the dossier or the named external oracle, never in this rule.
20. **A surface a framework enables by DEFAULT is still a declared decision, and
    the application is its authority.** FastAPI mounts `/docs`,
    `/docs/oauth2-redirect`, `/redoc` and `/openapi.json` unless told otherwise,
    and `create_app` tells it nothing — so "forgot to think about it" and
    "decided to publish it" are the same bytes. `ApiDocumentationPolicy` makes
    the decision typed and per-environment, split into the two planes that
    authenticate differently and always will: browser pages, which are DISABLED
    in production, and the OpenAPI document, which is served only behind the
    bearer guard `require_platform_admin`. `PLATFORM_BEARER` is not expressible
    for the interactive plane — a browser navigating to `/docs` sends no
    `Authorization` header, so the only way to make that "work" is a session
    cookie, and no documentation route may depend on a cookie-transport guard
    under any exposure. Environment resolution FAILS CLOSED: publishing is
    opt-in by name, and unset, blank, `staging` or a typo takes the production
    policy.

    **The ingress is not the control.** The vhost proxies `/` wholesale ON
    PURPOSE and names no documentation path; the application refuses. An nginx
    `location` is removed by a second ingress, by the loopback container port
    the compose file publishes, or by a block that matches first, and it is not
    reviewed with the application whose surface it claims to define.

    The gate reads the LIVE route inventory rather than the source, and its
    sensitivity case is the one that matters: FastAPI's default configuration,
    planted on a bare app AND on this assembly's own `create_app(build_spec())`,
    must FAIL the production gate (ADR-0016;
    `tests/unit/test_api_documentation_policy.py`,
    `tests/architecture/test_api_documentation_ingress.py`).
