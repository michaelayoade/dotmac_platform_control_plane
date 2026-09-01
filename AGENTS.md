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
   (`dotmac_starter_mt` ADR-0028; `tests/architecture/test_migration_prerequisite_bindings.py`,
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
    code never branches on a profile name (`dotmac_starter_mt` ADR-0003, deny case D6).

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
    estate — `dotmac_starter_mt` ADR-0031 governs a cutover WITH data, and this was not one. Composed
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
    has examined (`dotmac_starter_mt` ADR-0018 — distinct from this
    repository's ADR-0018, which rule 22 cites). The composed live-catalogue
    audit now consumes the kernel gate raw, with no subtraction at all. When you retire an exemption,
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
21. **The operator surface is an INSTALLED console script, and its exit codes
    are a contract.** The production image installs the wheel; it sets no
    `PYTHONPATH` and copies no `src` and no `scripts`, so production usage is
    `docker compose run --rm --no-deps ops dotmac-platform ...` and a
    checkout-relative invocation has nothing to resolve against. Every version
    the process reports comes from installed distribution metadata, never from a
    literal — `dotmac-deployment-control 0.1.0a4` shipped correct bytes while
    reporting itself as `0.1.0a2`, and the fix is removing the second copy
    rather than keeping two and correcting one.

    **The CLI is an adapter and owns no decision.** Every command names one
    service or query owner in `vendor_cp.cli.owners`; the table is compared
    against the parser in both directions, no mutating owner may live inside
    `vendor_cp.cli`, and no mutating symbol may be claimed by two commands. A
    policy that existed only in the CLI would be a second authority, and an
    operator at a shell would get a different answer from one at a screen.
    Render, apply, observe and rollback are **the published Foundation CLI's**,
    reached through one verbatim passthrough that returns the delegate's own
    status; re-growing any of them here is a second deployment engine.

    **`3` and `4` are different numbers and stay different**, including through
    `docker compose run`, which propagates the container's status unchanged. An
    owner refused and there is no evidence look identical from outside and mean
    opposite things about whether to retry. `6` is separate from `3` for the
    same reason one level down: `0.1.0a4` reported a digest ENCODING difference
    as "the plan changed after approval" — a formatting bug wearing a tampering
    refusal, which looks like the system working.

    **A secret arrives through a held file or stdin, never argv.**
    `/proc/<pid>/cmdline` is world-readable for as long as a process lives, and
    a registration token leaked into a transcript on this fleet exactly that
    way. The guard builds the real parser and inspects every option name; a flag
    added tomorrow in a module nobody thought to grep is the one that would
    leak. No secret value is ever printed.

    **The production shapes are ratcheted SET-shaped and two-directionally.**
    `src/vendor_cp/installed_surface.py` records the matched TEXT of every
    surviving occurrence of a `PYTHONPATH` pointing at `src`, an interpreter
    handed a path under
    `scripts/`, an `ops` container handed a script path, rsync of executable
    deployment assets, and checkout-relative production commands — each with why
    it is still there and what retires it. Text rather than a count, because a
    count survives a SWAP (one path retired while another gains the same
    ability), and the swap is the move worth catching. The sanctioned side is
    checked by IDENTITY: `sanctioned_entry_points()` reads the console-script
    names the installer recorded and never writes one down, an unresolvable
    distribution is UNMONITORED rather than a pass, and installed-or-not is
    deliberately absent from the baseline. Both directions of sensitivity are
    proven — a planted violation fires, and the conforming replacement form
    stays silent (`tests/architecture/test_installed_cli.py`;
    `docs/operations/installed-cli.md`).

    **The clean-install acceptance runs against the built image, and step 3 is
    the load-bearing one.** Build the wheel, install into an empty environment,
    remove access to the repository root, run every documented command's help
    and safe diagnostic path, prove nothing imports from a checkout, prove no
    duplicate mutation owner exists. "Remove access to the repository root" is
    satisfied structurally rather than by a flag, and the proof resolves each
    module's `__file__` against `sysconfig`'s `purelib`/`platlib` — a canary run
    against a checkout passes for the wrong reason, which is exactly how the
    `a4` defect survived.

22. **A candidate is accepted before it is published, and the ORDER is the
    contract.** Select an exact protected-main revision; verify required CI
    succeeded on it; build ONE local candidate; record its config digest, layer
    digests, RootFS chain, source revision, lock digest and Dockerfile digest;
    test THOSE EXACT BYTES; publish the same config and layers; read the
    immutable registry digest back; prove the registry holds what was accepted;
    emit a receipt. The previous pipeline pushed and then smoked, so a failing
    smoke left published bytes nobody had accepted, with no way to unpublish
    them and every consumer free to pin them. The read-back must LEAVE the
    runner — comparing a local tag with itself is a tautology that reads exactly
    like a proof — and no `docker push`, nor even a registry login, may appear
    before acceptance.

    **A pasted identifier is not evidence.** Manual dispatch verifies seven
    properties of a named CI run: repository, workflow, terminal conclusion,
    protected main and not a fork, 40-character SHA, still current main, and
    every required gate completed and passing. The last is the one that matters
    most — **a workflow reports success at the run level when one of its jobs
    SKIPPED**, so a gate that never ran looks identical to one that passed.
    `skipped` is refused by name alongside the other non-passing conclusions,
    enumerated rather than written as "anything but success". Gates are read as
    CHECK-RUNS at the SHA, because the required set spans several workflows. And
    a pasted image digest is refused too: the deploy path requires the release
    receipt binding those exact bytes to that exact revision.

    **The candidate battery tests the artifact, not the checkout**, because the
    defect class is an artifact that disagrees with its source. Twelve
    properties, and two of them carry their own sensitivity: the restored
    -production migration runs BOTH lanes — a correctly-owned copy that must
    upgrade, and a `postgres`-owned copy that must fail with `permission denied
    for database` — because a bundle can be PROVED and still restore into a
    differently-owned database (`CatalogEvidence` covers schema, table and
    sequence ownership, not DATABASE ownership); and readiness runs its NEGATIVE
    case first, with liveness as a positive control, because a probe returning
    200 unconditionally passes a positive-only test.

    **Readiness is the assembly's, liveness is the kernel's.** `/health` does
    not touch the database by design, and `up -d app --wait` was satisfied by
    it — so a container that could not reach its database reported healthy and
    the deploy was declared successful. `/health/ready` is published under every
    profile and withheld by none: a probe with an off switch is not a probe
    (this repository's ADR-0018 — not `dotmac_starter_mt` ADR-0018, which
    rule 13 cites; `tests/architecture/test_candidate_before_publication.py`,
    `tests/unit/test_readiness.py`; `.github/candidate/`).

23. **The accepted descriptor is a promoted candidate, never a hand edit — and
    it has two halves that advance on different events.** ADR-0017 § 2 and its
    2026-08-31 amendment (§ 8). `deploy/product.toml` holds the exact bytes of a
    candidate under `deploy/candidates/` that `deploy/descriptor-promotions.json`
    records as promoted; the comparison is byte for byte, a promoted candidate is
    immutable, and a change means a NEW candidate plus a promotion entry. Editing
    the accepted descriptor to agree with a database makes the database the
    authority and the descriptor a transcript of it, and once that is ordinary
    the next DRIFT is indistinguishable from the next CORRECTION.

    **A candidate's database declarations are DERIVED from the migrations that
    produce them**, never transcribed from a catalogue read: the composed
    revision graph's effective heads (graph heads minus every `depends_on`
    target, because Alembic prunes a subsumed dependency from `alembic_version`),
    the schemas the composed lineages create, and the privilege changes the
    revisions perform. A descriptor copied from a database can only ever agree
    with that database, including where it is wrong. Agreement with a measurement
    is the confirmation, not the method.

    **The image half must not run ahead; the database half must not fall
    behind.** A create-only operation advanced the database on 2026-08-31 and
    promoted nothing, and the descriptor spent a day declaring five module
    schemas against a database holding seven. A promotion records which sections
    it changed and which application values it carried forward, so one that
    advances the image cannot arrive disguised as a database repair.

    **Drift is checked in BOTH directions or it is not checked.**
    `dotmac-platform admin descriptor-drift` reports declared-but-absent AND
    present-but-undeclared over schemas, migration heads, roles and effective
    privileges. The second is the one that sees an operation nobody declared:
    every declared object still existed the day this happened. It connects to
    nothing — the target-side read is the existing catalogue capture, and deny
    case D1's allowlist stays empty — and both directions are planted and
    observed, alongside a matching pair that must PASS and a compared-subject
    count that makes a vacuous run visible
    **And the descriptor's PROSE is monitored too.** `deploy/product.toml`
    argues at length for what it declares and sat outside every prose guard,
    because `test_stale_claims.py` scanned `.md` and `.py` under six roots that
    did not include `deploy`. Its header stated an atomicity rule and a list of
    unapplied revisions that the bootstrap falsified, and no check could see the
    claim (`tests/architecture/test_descriptor_promotion.py`,
    `tests/unit/test_descriptor_drift.py`, `tests/architecture/test_stale_claims.py`;
    `docs/operations/descriptor-reconciliation-2026-08-31.md`).
24. **The kernel pin is DERIVED and EXECUTED, never compared by eye.** The
    census of 2026-08-30 recorded each composed module's declared kernel floor
    and then declined to upgrade the numbers by repeating them; this is the
    upgrade. Three facts are derived and none is written down twice: the exact
    pin comes from `pyproject.toml` (any shape but an exact version is refused —
    a range makes the running kernel a resolver outcome), each composed
    distribution's floor comes from its INSTALLED artifact's `Requires-Dist`,
    and the mutation target comes from the private index rather than from
    arithmetic, because the index has gaps and a version that was never
    published fails a lane while reporting it proven.

    **The pin equals the highest floor anything composed declares.** Too LOW is
    `dotmac-deployment-control 0.1.0a5` — byte-perfect artifacts that could not
    boot, because it imported a kernel module its declared floor did not
    require. Too HIGH is a kernel upgrade taken on nobody's behalf, which still
    owes the migration rehearsal a kernel upgrade owes. A hash comparison proves
    you got the published bytes; it cannot prove they import.

    **The assembly's own imports join that maximum, and the premise is
    executed.** Governance ADR 0021 § 10, as RULED 2026-09-01: the effective
    floor is the maximum of (a) every composed distribution's installed
    `Requires-Dist` and (b) this assembly's own declared direct kernel
    constraint. The checked-in record does not yet say this — § 10 states that
    an assembly's own imports are NOT an input, carries the question into open
    decision 24, and names this repository's test as where the premise is
    recorded for later; the governance revision pinned here predates § 10
    entirely. The ruling runs ahead of the record, so this lane is deliberately
    stricter than the text it cites and the record owes an amendment. Equality
    with the composed maximum alone is correct only while
    (b) sits at or below (a) — true today, and true by COINCIDENCE. That
    coincidence may not remain an unstated premise: `assembly-satisfied`
    requires every kernel module and every top-level name `src/vendor_cp`
    imports to be provided by an installation of the composed maximum, and a
    planted assembly import of a kernel name first shipped above it turns the
    lane red. When the premise dies, the answer is to record the assembly as a
    floor contributor and move the pin — never to loosen the equality. The
    refusal distinguishes a missing kernel symbol from a missing ENVIRONMENT
    dependency, because conflating those is how a boundary defect gets
    attributed to the wrong artifact.

    **The mutation lane installs the newest version the pin excludes and
    requires this assembly to fail on it** — and to fail for the RIGHT reason:
    the traceback must name a `dotmac_kernel` module that installation was
    MEASURED to be missing, compared against the real files of a real install
    rather than against a hand-kept version-to-module table whose missing row is
    invisible. A lane satisfied by any non-zero exit is satisfied by a typo'd
    index URL. Every version and module name in the workflow is derived; a
    literal there is how a lane keeps passing after it has stopped testing
    anything, and the architecture test greps for both.

    **A kernel version stated in canonical prose is checked against the pin.**
    `docs/ARCHITECTURE.md` and the pin-state table said `0.1.0a77` for as long
    as the pin had been `0.1.0a98`; nothing broke and nothing could see it.

    **A published version is not blamed for a boundary its predecessors share.**
    Kernel a98, a99 and a100 reach a product-owned PostgreSQL driver on the
    public `create_app` symbol identically; a100 regressed nothing, a98 is what
    runs in production, and the repair is a101. Operational functionality and
    independent artifact adoptability are different properties with different
    oracles, and a pin may not name a version that has not been published
    (`scripts/kernel_floor.py`, `tests/architecture/test_kernel_floor.py`, CI job
    `kernel-pin`; `docs/operations/kernel-a100-assessment-2026-09-01.md`).
