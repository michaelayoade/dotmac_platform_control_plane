# Gate-0 Work Packet D — protected rehearsal-issuer identity, custody and runner isolation

> **Status — Amended: § 10 rulings approved 2026-09-28 (item 5 pending the
> execution repository); the execution topology is ruled subject to
> verification of account controls and a live negative test;
> credential-bearing provisioning stays blocked until those are met.** This
> is not a new ADR; it implements
> ADR-0013 § A7 Work Packet D. **Provisioning: none performed.** No GitHub
> Environment, OpenBao role, OpenBao SSH CA, or signing key exists yet as a
> result of this document. Every value below marked `<placeholder>` is
> Michael's to choose at provisioning time. See "Runner placement blocker"
> below: the topology assumed by §§ 2, 3, 6, 7 and 8 as originally written
> cannot be provisioned as-is — those sections now depend on the ruled
> execution-repository-and-runner-group topology, subject to the two
> conditions stated there.

## 0. Scope and citations

This spec implements ADR-0013 § A7 Work Packet D only:
`docs/adr/0013-operator-authorization-issuer-and-its-bootstrap.md`, Amendment
2026-09-24 ("Work Packet A: the Gate 0/2/3 authority contract"). It does not
reopen anything A7 already decided; it names the concrete configuration and
refusal behavior D must produce so that Work Packet E (§ A7.7) can accept a
candidate-independent Gate-0 readiness receipt.

Read together with this spec: § A7.2 (the three-gate table — D operates
entirely inside Gate 0 and produces no candidate authorization), § A7.4 (the
identity/custody table this spec fills in the "Gate 0's protected issuer
composition" column for the harness-evidence row), § A7.5 (the three absences
this spec closes: no protected Environment, no OIDC/OpenBao role, no
observer/jump/vantage repository variables beyond `LANE3_PROBE_HOST`), and
§ A7.7 (what Work Packet E consumes from D).

D does not touch: `dotmac-deployment-control`'s issuance/standing/revocation
logic (owned per § A7.6), `dotmac-approvals`'s decision flow (owned per
§ A7.6), or Foundation's `ExecutionGrant` semantics (Work Packet C1, per
§ A7.3's document-purpose matrix). D supplies identity, custody and runner
configuration; it decides no plan legality, no approval, and no execution
authorization.

## Runner placement blocker

**This blocks §§ 2, 3, 6, 7 and 8 as originally written. The topology below
is Ruled by Michael 2026-09-28, subject to two conditions; credential-bearing
provisioning stays blocked until both are met.**

Facts, as found by a live check on 2026-09-27:

- CP (`michaelayoade/dotmac_platform_control_plane`) is a public,
  personal-account repository with ZERO registered runners.
- `control-runner-starter-mt` is registered to the Starter repository, so a
  CP workflow cannot use it.
- A runner label routes jobs; it does NOT restrict which workflow can use
  the runner.
- A private personal-account repository plus an ephemeral runner is NOT a
  workflow-selection ACL: any matching workflow in that repository can
  schedule the runner. Neither a dedicated personal repository, nor an
  ephemeral runner, by itself restricts workflow selection.
- GitHub's workflow-restricted runner groups (organization-level
  selected-workflow runner-group access) are organization/enterprise
  controls, unavailable on a personal account
  (https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access).
- **Consequence:** the current § 6 isolation cannot be met by the existing
  runner and label. Do not claim it is.

**Topology — Ruled by Michael 2026-09-28, subject to two conditions:**

- an organization-owned PRIVATE execution repository, holding only the
  protected, directly defined, non-reusable workflow;
- a runner group restricted to the exact protected workflow, using GitHub's
  organization-level selected-workflow runner-group access
  (https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access);
- the runner stays isolated and ephemeral;
- Starter's runner stays dedicated to Lane 3.

This ruling is subject to two conditions:

1. verifying the account's actually available controls (organization plan
   and runner-group features);
2. a live negative test — non-vacuous, per § 7's
   `test_only_the_protected_workflow_can_select_the_runner` row. There is
   ONE ephemeral runner: if the positive control ran first, it would consume
   that runner, and the negative case would then stay queued for lack of a
   runner, not because of the restriction — so the order matters and is
   fixed:
   1. With the runner shown idle and registered in the group's listing,
      queue the negative-case workflow (a second workflow targeting the
      group itself and its labels).
   2. The runner stays shown idle for the whole stated bound
      `<placeholder: N minutes>` while the negative job never starts on it.
   3. Only then dispatch the positive control (the protected workflow), and
      show the SAME runner picks it up, while the negative job is still not
      started.
   The negative job's final status is recorded — it never starts on the
   runner, whether that ends as "queued past the bound, then cancelled" or
   "rejected outright"; state which. Both run IDs are recorded as evidence.
   The test workflow is removed afterward, evidenced by a commit SHA, or
   kept on a non-default branch — state which — so the repository still
   holds only the protected workflow on its default branch. Run for real, in
   the organization, against the provisioned group, not a mock.

**The condition-2 fixture workflow is a STUB.** At the ref-pinned coordinate
(§ 6), it declares no `environment:` key and requests no `id-token: write`
permission. Referencing an Environment that does not yet exist can
auto-create it unprotected — the stub avoids that by not referencing one at
all. § 7's non-default-ref row
(`test_non_default_ref_run_of_the_protected_workflow_file_cannot_select_the_runner`)
also runs in this fixture phase, before any Environment exists, so its
refusal can only come from the runner group's ref-pinned selected-workflow
restriction, never from Environment branch policy — it keeps the same idle,
negative-first, then positive-control order as condition 2 above. The § 2
Environment's own `main`-only branch-policy refusal
(`test_non_main_run_cannot_reach_the_protected_job`) is a separate, later
test, run only once the Environment actually exists.

**#217 is design-only: nothing in this spec authorizes provisioning.**
Credential-bearing provisioning stays blocked until the confirmed
organization plan (condition 1) and a passing live negative test
(condition 2) are both met — the § 2 Environment's secrets/approvals
binding, the OpenBao JWT role, the signers, the trust state, the SSH CA.
The only thing Michael may provision ahead of that, as his own step in
order to run condition 2, is a credential-free topology fixture: the
organization, the execution repository, the runner group, and an ephemeral
runner with no OpenBao binding and no secrets. This spec does not authorize
that fixture either — it names what condition 2 requires to exist before it
can be run; Michael provisions it, or not, at his own discretion.

Until both conditions are met, §§ 2, 3, 6, 7 and 8 below describe the ruled
shape only, not a provisionable configuration.

## 1. Four separate facts — why OIDC is only one of them

§ A7.4's identity/custody table names several distinct identity claims. This
section states them as four independently evidenced facts so that no single
piece of evidence is read as answering more than one question — the same
discipline § A7.3's document-purpose matrix applies to the five documents.

| # | Fact | What proves it | What is refused if the evidence is missing or wrong |
| --- | --- | --- | --- |
| 1 | **Which workflow job asked OpenBao for a limited capability.** | The GitHub OIDC token presented to OpenBao's JWT auth method, validated against the bound claims in § 3 below. | OpenBao's JWT role refuses the token exchange; no OpenBao token is issued at all. |
| 2 | **A human approved this specific plan.** | A genuine `dotmac-approvals` `ApprovalEvidence`, reached through Work Packet B's protected (non-rollout) adapter, per § A7.3's `ApprovalEvidence` row. | `approve_plan` (or the rehearsal issuer's `_standing_plan_terms` read) refuses; no standing plan exists for the lease to reference. |
| 3 | **Control's issuer signature over the authorization.** | `RehearsalIssuerAuthorizationV1`, signed by the real Ed25519 key described in § 4, verified by the rehearsal issuer's own verifier using that key's public half (§ A7.4, "Rehearsal-issuer authorization verifier" row). | Signature verification fails; the authorization is rejected before any consumption attempt. |
| 4 | **The runner used the SSH key it claims.** | The controller's per-run OpenSSH key fingerprint, derived from the actual key material generated for that run (§ 5 below), bound into independently signed harness evidence and cross-checked against the lease record (§ A7.4, "Harness-evidence verifier / controller identity" row). | Harness-evidence signature or fingerprint verification fails; the lease is refused before any target action. |

**Who signs the harness evidence itself.** ADR-0013 § A7.4's "Harness-evidence
verifier / controller identity" row and § A7.3's "Harness evidence" row both
name what the evidence must be bound to — the real controller's per-run
OpenSSH key fingerprint — and require the evidence to be "independently
signed," but neither names the signing key that produces that signature (the
OpenSSH key is the fingerprinted identity carried inside the evidence, not
necessarily the key that signs the evidence envelope). **Ruled by Michael
2026-09-28 (§ 10 item 1):** a DEDICATED harness-evidence signing key, held
by a distinct attester identity (not the issuer, not the runner), under its
own OpenBao custody path, distinct from the § 4 rehearsal-issuer signer,
with its own trust-state record — § 4's `trusted_key_ids`/`revoked_key_ids`
remain declared for the rehearsal-issuer signer specifically and are not
shared. A second key readable by the same compromised principal would give
no meaningful separation. The runner and the workflow token never hold or
read this key, identically to § 4's rule for the rehearsal-issuer signer —
the runner presents harness evidence and controller identity, it does not
produce the signature over them.

OIDC (fact 1) proves only that a specific GitHub Actions job, running under a
specific ref/workflow/environment, is the caller asking OpenBao for a
short-lived credential. It is not, and does not substitute for, facts 2, 3,
or 4. A protected-Environment job that never obtained real `ApprovalEvidence`,
a job whose signature does not chain to the custodied key, or a job presenting
a fingerprint that does not match the key it actually generated must each be
refused independently — collapsing any two of these four checks into one is
exactly the kind of document-purpose collapse § A7.3 exists to prevent, one
level down at the identity layer.

## 2. Human approval — the rehearsal-issuer GitHub Environment

**Follows from the 2026-09-28 topology ruling, subject to the two
conditions in the Runner placement section:** per the "Runner placement
blocker" above, this Environment is created on the approved execution
repository, `<derived from the approved execution repository>`, not on CP or
Starter.

A dedicated GitHub Environment, name `rehearsal-issuer-protected` (fixed per
§ 10 item 5 — not a placeholder), is created on that repository with:

- **Required reviewer:** Michael Ayoade, one reviewer required.
- **Deployment branch policy:** `main` only — no other branch, and no tag
  pattern, may target this Environment.
- **No wait timer**, unless Michael later decides otherwise; none is
  specified by this spec.

**This is a deliberate human gate, not independent two-person approval.** As
a solo developer, Michael is both the sole required reviewer and the sole
person who could otherwise approve their own change; recording this plainly
here is the point, not a limitation this spec proposes to work around. The
Environment gate answers only fact 1's *authorization to invoke the
protected job at all*; it is not fact 2's `ApprovalEvidence` (§ A7.3), which
`dotmac-approvals` issues independently through Work Packet B's adapter.

Refusal: a workflow run targeting this Environment from any branch other than
`main`, or without the required reviewer's approval, does not reach the job
that requests an OpenBao token — GitHub's own Environment protection rule
enforces this before the job starts.

## 3. Workflow identity — GitHub OIDC to a scoped OpenBao token

**Follows from the 2026-09-28 topology ruling, subject to the two
conditions in the Runner placement section:** per the "Runner placement
blocker" above, the `repository`, `environment` and `workflow_ref` claims
bound below are `<derived from the approved execution repository>`, not from
CP. `workflow_ref` names the directly defined, non-reusable protected
workflow held in that repository — see § 10 item 7. This workflow declares
no `pull_request` or `pull_request_target` trigger (§ 6).

Only the protected job (the one running inside the `rehearsal-issuer-protected`
Environment from § 2) exchanges its GitHub OIDC token for a short-lived,
narrowly scoped OpenBao token. No other job, and no job outside that
Environment, requests this exchange.

The OpenBao JWT auth role (`auth/jwt` backend, role name
`rehearsal-issuer-protected`, fixed per § 10 item 5 — not a placeholder)
sets `bound_audiences` to the audience below and binds `bound_claims` on the
rest. The audience is NOT a `bound_claims` entry: OpenBao checks it through
`bound_audiences`.

| Claim | Bound value | Why binding the Environment name alone is not enough |
| --- | --- | --- |
| `repository` | `<derived from the approved execution repository>` | Scopes the role to the approved execution repository only. |
| `environment` | `rehearsal-issuer-protected` (the § 2 Environment name, fixed) | GitHub's environment-based `sub` claim can omit the branch entirely — an Environment-only bound claim would accept the same job running from a non-`main` ref if the Environment's own branch policy were ever misconfigured or bypassed by a different trigger. |
| `ref` | `refs/heads/main` | Independently pins the branch at the OpenBao layer, so OpenBao's own policy does not rely solely on GitHub's Environment configuration remaining correct. |
| `workflow_ref` | `<derived from the approved execution repository>` — ref-pinned as `<org>/<repo>/.github/workflows/<file>.yml@refs/heads/<default branch>` (the directly defined, non-reusable protected workflow's exact file and ref) | Pins the exact workflow file and ref of a normal (non-reusable) workflow, not just "some workflow in this repo." `job_workflow_ref` is bound instead ONLY if D deliberately runs the protected job as a reusable-workflow call; this spec does not (§ 10 item 7). |

Audience (`bound_audiences`, not `bound_claims`): `<placeholder: e.g. https://openbao.dotmac.internal>`.
The protected job requests its OIDC token for exactly this audience.

`ref` is bound to `refs/heads/main` as its own claim, separately from
`environment`; neither substitutes for the other. The bound values are
checked against the ACTUAL claims of the protected job (captured from a real
run of that job, not assumed from documentation) before the role is accepted.

Token TTL: `<placeholder, short — e.g. 5m>`, no renewal.
**Ruled in principle (§ 10 item 5); cannot be finalized until the execution
repository is chosen:** a starting OIDC-derived OpenBao token TTL of five
minutes, non-renewable. Policy scope: the
resulting OpenBao token's attached policy grants exactly the SSH CA signing
endpoint named in § 5, for the per-run controller certificate, and nothing
else. It grants NO read on the issuer signer path in § 4: only CP's service
identity reads the signer, never the runner or its workflow token.

Refusal (see § 7 table for the paired test): a token presented with any
other `ref`, a `workflow_ref` naming a different workflow file or ref, a
`repository` or `environment` claim mismatch, a wrong or missing `aud`, or an
expired token is refused by OpenBao's JWT role at the login step, before any
OpenBao path is read.

References: GitHub OIDC —
https://docs.github.com/en/actions/reference/security/oidc ; OpenBao JWT auth
— https://openbao.org/docs/2.4.x/api/auth/jwt/

## 4. The issuer signing key — custody, not possession

The rehearsal-issuer signer is Ed25519, held at the already-declared path
`secret/dotmac/platform-cp/rehearsal-issuer/signing-key`
(`SIGNER_OPENBAO_PATH`, `src/vendor_cp/deployment/protected_rehearsal_issuer.py`).

- **Read access:** CP's own service identity only. The self-hosted runner's
  OpenBao token (§ 3) does NOT include read access to this path — the
  runner drives the workflow and presents controller/harness evidence; it
  never holds or reads the signing key.
- **Load pattern:** loaded once at process start, through
  `install_rehearsal_issuer_security`, as § A7.4 requires (mirroring
  `authorization_v3`'s "no OpenBao call on the controller path" discipline
  from ADR-0013 § 5). No per-request OpenBao read.
- **What is recorded (here and at provisioning time):** key ID, fingerprint,
  and version only — never the private key material. `<placeholder: key ID>`,
  `<placeholder: fingerprint>`, `<placeholder: version, e.g. v1>`. The
  private key is never copied into a GitHub secret, workflow artifact, log
  line, or this document.
- **Lifecycle:**
  - *Generation:* where the keypair is actually generated. Neither the ADR
    nor this spec originally settled this, and the two obvious paths
    conflict with something else this spec already requires: a KV v2 engine
    (the declared custody path,
    `secret/dotmac/platform-cp/rehearsal-issuer/signing-key`) cannot
    generate a keypair itself — it only stores a value handed to it — so
    something must generate the Ed25519 keypair BEFORE writing it there;
    and OpenBao's Transit engine, which can generate a key in-place, is
    typically configured non-exportable, which conflicts with
    `install_rehearsal_issuer_security`'s "load the raw key once at process
    start" pattern (§ A7.4) — a non-exportable Transit key cannot be loaded
    into CP's process memory the way this section already describes.

    **Ruled by Michael 2026-09-28 (§ 10 item 3):** the Ed25519 keypair is
    generated by a controlled, short-lived provisioning process and sealed
    into KV v2. Not exportable Transit merely to satisfy the load-at-start
    contract: exportability cannot later be disabled
    (https://openbao.org/docs/next/api/secret/transit/).

    **Carried-over mechanics (not part of the ruling) — the specific
    procedure the spec originally proposed, retained as the working
    assumption unless Michael specifies otherwise:** the process runs
    offline (e.g. on Michael's own machine or a dedicated bootstrap step);
    the private key is written to the KV v2 path above as version 1; every
    transient copy (memory, disk, shell history) is wiped immediately after
    the write — mirroring § 5's per-run key destruction discipline. Any
    transient copy of the private key material outside its final custody
    location is wiped, and the private key is never copied into a GitHub
    secret, workflow artifact, log line, or this document (unchanged from
    the rule already stated above). Michael performs this (§ 8).
  - *Rotation:* a new key VERSION is written to the same path, followed by
    the explicit reload the kernel's secret-source rules require — this is
    `refresh_secrets()`/an equivalent explicit re-install call, never a TTL
    or background poll (per CLAUDE.md, "Install secret material a product
    resolved itself": a failed refresh keeps the working set; a failing
    source raises rather than starting degraded). The rehearsal-issuer
    verifier must accept authorizations signed under either the retiring or
    the new version for a defined overlap window, `<placeholder>`.

    **Ruled by Michael 2026-09-28 (§ 10 item 6):** two
    signing versions only, for a bounded overlap equal to the maximum
    outstanding authorization lifetime plus clock skew. Establish that
    maximum before setting the duration.
  - *Revocation* has TWO distinct meanings, with different owners. Do not
    conflate them.
    1. **Authorization / lease revocation stays with Control.** Revoking an
       issued authorization or its lease is Control's decision
       (`revoke_rehearsal_issuer_authorization`), recorded in Control's
       ledger, and consumption refuses a revoked authorization by reading that
       ledger. It involves no key operation.
    2. **Key compromise is an explicit, tested verifier trust state.** Marking
       an OpenBao KV version deleted, destroyed or otherwise revoked does NOT,
       by itself, revoke anything. A verifier holding the public key it loaded
       at process start still verifies every signature that key made, and
       learns nothing from a metadata change it never reads (OpenBao KV v2
       version operations: https://openbao.org/docs/secrets/kv/kv-v2/).
       Therefore:
       - The verifier's trust state is an explicit, installed value:
         `trusted_key_ids` (key ID plus fingerprint per trusted version) and
         `revoked_key_ids`. It holds public key material and identifiers only,
         never the private key. It is sourced from a non-secret, access-
         controlled record, `<placeholder: trust-state path>`, and installed at
         process start alongside the signer.
       - **Write access.** Only Michael, via the provisioning identity used at
         § 8, may write the trust-state record. CP's runtime service identity
         (which reads it at install and refresh) is never granted write
         access, and neither the self-hosted runner nor its OpenBao-scoped
         workflow token (§ 3) may read or write it at all — the same
         separation § 4's signer-read rule already draws between "produces
         the record" and "consumes the record." This is a new provisioning
         action, alongside the § 8 table's existing "Create the verifier
         trust-state record" row.
       - **Monotonic version, rollback refused.** The trust-state record
         carries a monotonically increasing `version`. A refresh that reads a
         record whose `version` is lower than the version currently installed
         on that process is refused — the process keeps its current
         (higher-versioned) trust state rather than accepting a rollback,
         since a lower version could be a stale or tampered copy silently
         re-admitting a key § 4's (a)/(b) steps already revoked. The
         compromise-runbook step (b) above ("run the refresh on every CP
         process and confirm each reports the new trust-state version")
         confirms specifically that every process reports a version at least
         as high as the one just written in step (a) — a process still
         reporting an older version has not completed the refresh.
       - **Revoked wins.** A key ID present in both `revoked_key_ids` and
         `trusted_key_ids` is refused — `revoked_key_ids` always takes
         precedence, regardless of ordering or how the record was assembled.
       - **Refusal gate:** at consumption, a signature whose key ID is in
         `revoked_key_ids`, or is absent from `trusted_key_ids`, is refused,
         independently of the signature verifying.
       - **Refresh is explicit, never a TTL or background poll** (the kernel
         secret-source rule): a named, audited operator command that re-reads
         the trust state and installs it on every running CP process.
       - **Unlike rotation, a failed compromise refresh FAILS CLOSED.** If the
         trust state cannot be read or installed, the verifier refuses every
         consumption until a refresh succeeds. It must never keep the working
         set, because the working set is what is compromised.
       - **Startup also fails closed.** If the trust-state record cannot be
         read or fails validation (missing, malformed, or a version below
         the DURABLE version floor — ruled per § 10 item 4 below; a
         freshly started process has installed nothing, so an in-memory
         high-water mark alone cannot refuse a rollback) at process start, the
         process refuses to start, or — if it must stay up for other reasons
         — refuses every rehearsal-issuer-authorization consumption rather
         than proceeding. It never falls back to trusting whatever the
         signer's own public half verifies: the public key alone answers
         "did this key sign it," not "is this key still trusted," and only
         the trust state answers the second question.

         **Ruled by Michael 2026-09-28 (§ 10 item 4):**
         the durable version floor is pinned in independently controlled,
         IMMUTABLE CP deployment configuration, not beside the mutable
         trust-state record.
       - **The cache window is explicit.** Between marking a key compromised
         and the refresh completing on every process, a cached verifier still
         accepts that key's signatures. The compromise runbook is therefore:
         (a) add the key ID to `revoked_key_ids` in the trust-state record;
         (b) run the refresh on every CP process and confirm each reports the
         new trust-state version;
         (c) revoke every outstanding authorization signed by that key through
         Control (meaning 1);
         (d) rotate the signer.
         The runbook is complete only when (b) is confirmed. Marking the
         OpenBao version alone is never the step that stops acceptance.

       **Ruled by Michael 2026-09-28 (§ 10 item 8):**
       trust-state hardening confirmed — Michael-only writes, monotonic
       rollback refusal, revoked-wins, and fail-closed startup and
       failed-compromise refresh, as specified above.

## 5. Controller identity — per-run OpenSSH key

A fresh OpenSSH keypair is generated inside the protected job for each
protected run — never a persistent, reused runner key.

- The fingerprint bound into the run's independently signed harness evidence
  and into the lease record (§ A7.4) is derived from the ACTUAL public key
  generated that run, not a pre-declared or configured value. This is a
  materially different identity shape from the disposable harness's ad hoc
  Ed25519 keypair (§ A7.4's harness-evidence row) — Work Packet D owns
  deriving this OpenSSH fingerprint correctly, not substituting a "more
  real" Ed25519 key for it.
- **Reuse detection.** The per-run key's fingerprint is bound, inside the
  harness evidence, to the run ID, a nonce, and the lease it is presented
  against. ADR-0013 § A7.4 already establishes that the fingerprint is
  bound "into the lease record" — that record is Control's own
  rehearsal-issuer authorization/lease state (§ A7.6: `dotmac-deployment-
  control` owns "issuance, standing, revocation, single-use consumption"),
  so a fingerprint's binding to a specific run/lease is checked against
  that existing Control-owned record, not a new store this spec invents.
  The ADR did not settle whether the reuse check is (a) an extension of
  Control's existing single-use consumption logic (§ 7's "Replayed
  consumption" row) — i.e. a fingerprint is simply one more field Control's
  existing consumption check compares for freshness — **rejected per the
  § 10 item 2 ruling: a per-lease single-use check alone does not catch
  reuse of the same fingerprint on a *different* or *concurrent* lease** —
  or (b) a separate index, keyed by fingerprint across all prior runs and
  leases, that the rehearsal issuer or harness-evidence verifier consults
  before Control's consumption check ever runs — **neither option as
  written. Ruled (§ 10 item 2): fingerprint uniqueness lives in Control's
  durable lease/consumption authority, enforced transactionally across
  leases, not as a pre-check by the issuer or the verifier.** Either way, a
  fingerprint already bound to an earlier run or lease is refused as a
  stale/reused controller identity, never treated as evidence of the
  current run.

  **Ruled by Michael 2026-09-28 (§ 10 item 2):**
  cross-run fingerprint uniqueness lives in Control's durable
  lease/consumption authority, enforced transactionally ACROSS leases. The
  single use of one lease does not catch reuse on another.
- **Selected — Michael 2026-09-28:** short-lived OpenBao-issued SSH
  certificate; CA role, `valid_principals`, extensions, the certificate key
  ID binding, and the measured TTL remain pending provisioning (§ 10 note
  below). Rather than a long-lived key trusted by the target host, the
  controller requests a short-lived OpenBao-issued SSH certificate
  (`secret/ssh` engine, `<placeholder>` role) signed over the per-run public
  key, scoped to the target(s) named by `LANE3_PROBE_HOST` and the vantage
  variables in § 6, with:
  - **TTL:** `<placeholder, short — e.g. matching or shorter than the run's
    expected duration>`. **Ruled in principle (§ 10 item 5); cannot be
    finalized until the execution repository is chosen:** measure the SSH
    certificate lifetime against the real run before fixing this value.
  - **`valid_principals`:** `<placeholder, restricted to the exact
    controller/service account(s) the target(s) accept for this role — not
    a wildcard>`.
  - **Extensions:** `<placeholder, restricted to only the extensions the
    controller's actual connection needs (e.g. no `permit-agent-forwarding`,
    no `permit-port-forwarding` unless the controller genuinely requires
    them)>`.
  - **Certificate key ID:** `<placeholder, bound to the run — e.g. the run
    ID or the same identifier used elsewhere in this section — so the
    certificate itself, not just the harness evidence, carries a
    per-run-traceable identity>`.
  Reference: https://openbao.org/docs/secrets/ssh/signed-ssh-certificates/
- **Destruction:** both the private key and any issued certificate are
  deleted from the runner's filesystem at the end of the run, in the
  workflow's cleanup step, regardless of run outcome (success, refusal, or
  job failure) — the ephemeral OpenBao token from § 3 also naturally expires
  at its short TTL.

## 6. Runner isolation

**Follows from the 2026-09-28 topology ruling, subject to the two
conditions in the Runner placement section:** per the "Runner placement
blocker" above, isolation comes from the runner group's repository access
(restricted to the organization-owned execution repository holding only the
protected workflow) together with the runner group's selected-workflow
restriction (restricted to the exact protected workflow, entered as the
ref-pinned coordinate `<org>/<repo>/.github/workflows/<file>.yml@refs/heads/<default branch>`,
not a bare workflow-file name) — not from a label alone, and not from the
repository or the runner being private/ephemeral by themselves.
`control-runner-starter-mt` stays dedicated to Lane 3 and is never used for
this protected job. The no-`pull_request*` rule below still applies to
whichever runner group is provisioned.

A protected GitHub Environment (§ 2) gates which jobs may target it; it does
not, by itself, isolate a self-hosted runner from other workloads that
runner might execute. This spec therefore requires, independently of the
Environment gate:

- No workflow triggered by `pull_request` or `pull_request_target` may
  select the protected job's runner, WHATEVER the pull request's
  origin — including a pull request opened from a branch of this same
  repository, not only a fork. `pull_request_target` runs with base-repo
  context and base-repo secrets even for a fork-originated PR, which is
  exactly why scoping this rule to "from a fork" would miss it: a
  `pull_request_target`-triggered workflow already executes as if it were
  trusted, regardless of where the PR came from, so the runner isolation
  below is what must exclude it, not the trigger's PR-origin check. The
  protected workflow itself also declares no `pull_request` or
  `pull_request_target` trigger at all — belt-and-braces with the runner
  isolation this section requires, not a substitute for it.
- A job from any OTHER repository cannot use the runner group. The
  mechanism is the runner group's repository access.
- A workflow in the execution repository OTHER than the exact protected
  workflow is refused by the runner group's selected-workflow restriction —
  the restriction is entered as the ref-pinned coordinate
  `<org>/<repo>/.github/workflows/<file>.yml@refs/heads/<default branch>`,
  not a bare workflow-file name, so a same-named workflow file run from a
  different ref does not match either (see § 7's non-default-ref row). A
  label alone does not restrict which workflow may use a runner (see
  "Runner placement blocker"). This is the live negative test required by
  condition 2 above (§ 7).
- The runner is ephemeral and holds no state between runs. This is hygiene,
  NOT the selection control — selection is enforced by the runner group's
  repository access and selected-workflow restriction above, not by
  ephemerality — `<derived from the approved execution repository>`'s
  actual runner configuration confirms this at provisioning time.

Reference: GitHub Actions secure-use guidance —
https://docs.github.com/en/actions/reference/security/secure-use ; GitHub
selected-workflow runner-group access —
https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access

## 7. Refusal tests

**Follows from the 2026-09-28 topology ruling, subject to the two
conditions in the Runner placement section:** per the "Runner placement
blocker" above, the runner-isolation refusal tests below are stated against
the ruled organization-owned execution-repository-plus-runner-group
topology, not against `control-runner-starter-mt`'s label. The OIDC rows
are tested against the provisioned JWT role for the approved execution
repository's real claims, once that repository exists.

Each row names the planned test's intent; naming a test here does not create
it — these are written when D's workflow YAML and harness code exist. Every
row below whose "Enforced where" cites OpenBao's JWT role runs against the
PROVISIONED role configuration from § 3/§ 8 (the actual bound claims and
policy Michael configures, for the approved execution repository's real
claims), not a mock or a hand-constructed stand-in role.

| Missing/invalid condition | Enforced where | Expected refusal | Planned test |
| --- | --- | --- | --- |
| Wrong `ref` (not `refs/heads/main`) | OpenBao JWT role `bound_claims.ref` | OpenBao login denied, no token issued | `test_oidc_login_refuses_non_main_ref` |
| Wrong `workflow_ref` | OpenBao JWT role `bound_claims.workflow_ref` | OpenBao login denied | `test_oidc_login_refuses_wrong_workflow` |
| Wrong `environment` claim | OpenBao JWT role `bound_claims.environment` | OpenBao login denied | `test_oidc_login_refuses_wrong_environment` |
| Wrong `repository` claim | OpenBao JWT role `bound_claims.repository` (§ 3) | OpenBao login denied | `test_oidc_login_refuses_wrong_repository` |
| Wrong or missing `aud` | OpenBao JWT role `bound_audiences` | OpenBao login denied | `test_oidc_login_refuses_wrong_audience` |
| Expired OIDC or OpenBao token | Token TTL enforcement, both layers | Login/token-use denied | `test_expired_token_is_refused` |
| **Follows from the 2026-09-28 topology ruling, subject to the two conditions in the Runner placement section:** A job from any OTHER repository reaches the protected job's runner | Runner isolation via the runner group's repository access (§ 6), independent of the § 2 Environment gate | Job cannot use the runner group | `test_other_repository_job_cannot_reach_the_protected_runner` |
| **Follows from the 2026-09-28 topology ruling, subject to the two conditions in the Runner placement section. This row IS the live negative test (condition 2) and must be non-vacuous — order matters because there is only ONE ephemeral runner:** A workflow in the execution repository other than the exact protected one selects the runner | Runner isolation via the runner group's selected-workflow restriction (§ 6), against the STUB fixture workflow (no `environment:` key, no `id-token: write`). **Fixed order, negative case first:** (1) with the runner shown idle and registered in the group's listing, queue the negative-case workflow — a second workflow targeting the group itself (`runs-on: group: <placeholder>`) AND its labels; (2) the runner stays shown idle for the whole stated bound `<placeholder: N minutes>` while the negative job never starts on it; (3) only then dispatch the positive control — the protected workflow at its ref-pinned coordinate — and show the SAME runner picks it up while the negative job is still not started. Running the positive control first would consume the one runner and make the negative case queue for lack of a runner, not because of the restriction, so this order is required, not optional. **Evidence:** both run IDs recorded, plus the negative job's final status. **Clean-up:** the test workflow lives on a non-default branch, or is removed afterward with the removal evidenced by a commit SHA — state which — so the repository still holds only the protected workflow on its default branch. Run for real, in the organization, against the provisioned group, not a mock. | The negative job never starts on the runner (queued past the bound `<placeholder: N minutes>`, or rejected — status recorded); the positive control's run then starts on the SAME runner while the negative job is still not started | `test_only_the_protected_workflow_can_select_the_runner` |
| **Follows from the 2026-09-28 topology ruling, subject to the two conditions in the Runner placement section:** The runner retains state between runs | Ephemeral-runner recreation (§ 6) — hygiene, not the selection control | No state carries across runs; runner holds no state between runs | `test_the_runner_is_ephemeral_and_holds_no_state_between_runs` |
| **Follows from the 2026-09-28 topology ruling. Runs in the condition-2 fixture phase, before any Environment exists,** so its refusal can only come from runner selection, never from Environment branch policy (see below): the protected workflow FILE (the same STUB), run from a non-default ref | Runner isolation via the runner group's ref-pinned selected-workflow entry (§ 6): `<org>/<repo>/.github/workflows/<file>.yml@refs/heads/<default branch>` does not match a run from any other ref. Same fixed order as the live negative test above, negative case first: (1) with the runner shown idle, queue the non-default-ref run; (2) it never starts on the runner for the stated bound; (3) only then dispatch the same file from the default-branch ref and show the SAME runner picks it up. | The non-default-ref run never starts on the runner (queued past the bound, or rejected — status recorded); the default-branch run then starts on the same runner | `test_non_default_ref_run_of_the_protected_workflow_file_cannot_select_the_runner` |
| A `pull_request`/`pull_request_target`-triggered workflow selects the protected job's runner | Runner isolation via the runner group's ref-pinned selected-workflow entry (§ 6): a `pull_request`/`pull_request_target`-triggered run does not match the pinned `<org>/<repo>/.github/workflows/<file>.yml@refs/heads/<default branch>` coordinate, and the protected workflow itself declares no such trigger, independent of the § 2 Environment gate | Job never dispatches to the protected job's runner | `test_pull_request_triggered_workflow_cannot_select_the_protected_runner` |
| **A separate, later test, run only once the § 2 Environment actually exists** (distinct from the fixture-phase non-default-ref row above): a non-`main` run reaches the protected job | § 2's Environment branch policy (`main`-only) AND § 3's `bound_claims.ref` (defense in depth — see § 3's own note that `ref` is independently pinned at the OpenBao layer) | Environment protection blocks the run before the job starts; OpenBao would independently refuse the token exchange even if it did | `test_non_main_run_cannot_reach_the_protected_job` |
| Runner attempts a signer read | OpenBao policy attached to the runner's scoped token (§ 4) excludes the signer path | OpenBao permission denied | `test_runner_token_cannot_read_signer_path` |
| A per-request OpenBao read occurs on the consumption path | `install_rehearsal_issuer_security`'s load-once-at-start pattern (§ 4); no per-request call is wired | No OpenBao call observed during consumption (structural/static check, not a live-OpenBao assertion) | `test_no_per_request_openbao_read_on_the_consumption_path` |
| Missing human approval | `dotmac-approvals`' `approve_plan` / rehearsal issuer's `_standing_plan_terms` (fact 2, § 1) | No standing plan; issuance refused | `test_issuance_refuses_without_approval_evidence` |
| Evidence not signed by the dedicated harness-evidence attester key (§ 10 item 1) | Harness-evidence signature verification against the dedicated attester key named per § 1's "Who signs the harness evidence itself" ruling | Harness evidence rejected before any consumption attempt | `test_harness_evidence_refuses_a_signature_from_an_unnamed_key` |
| Evidence signed by the § 4 rehearsal-issuer signer instead of the dedicated attester key | Harness-evidence signature verification against the dedicated attester key (§ 10 item 1) — the issuer key is refused here even though it verifies as a valid signature, because it is not the named attester key | Harness evidence rejected — a valid signature from the WRONG key is not accepted | `test_harness_evidence_refuses_a_signature_from_the_issuer_key` |
| The same controller-key fingerprint presented on a different or concurrent lease | Control's durable lease/consumption authority (§ 5, § 10 item 2): cross-run fingerprint uniqueness is enforced transactionally, across leases, not merely within one | Harness evidence/consumption refused as a stale/reused controller identity, refused transactionally even under concurrent presentation, not accepted as either run's presenter | `test_harness_evidence_refuses_reused_controller_key` |
| Fingerprint mismatch between evidence and lease | Rehearsal-issuer consumption check cross-referencing harness-evidence fingerprint against the lease record (§ A7.4) | Consumption refused | `test_consumption_refuses_fingerprint_mismatch` |
| Replayed consumption | `dotmac-deployment-control`'s existing single-use consumption logic | Second consumption refused | `test_consumption_refuses_replay` (extends existing single-use coverage per § A7.1's mechanism proof) |
| Use after authorization/lease revocation | Control's authorization ledger, read at consumption (§ 4, meaning 1) | Consumption refused | `test_consumption_refuses_a_control_revoked_authorization` |
| Use of a compromised key before the trust-state refresh | Verifier trust state (§ 4, meaning 2): the cache window is explicit | Still ACCEPTED (documents the window; the runbook closes it) | `test_cached_trust_state_accepts_until_refreshed` |
| Use of a compromised key after the trust-state refresh | Verifier refusal gate on `revoked_key_ids` (§ 4, meaning 2) | Consumption refused, even though the signature verifies | `test_refreshed_trust_state_refuses_a_revoked_key_id` |
| A key ID absent from the trusted set | Verifier refusal gate on `trusted_key_ids` (§ 4) | Consumption refused | `test_untrusted_key_id_is_refused` |
| A failed compromise refresh | Verifier trust-state refresh (§ 4, meaning 2) | FAIL CLOSED: every consumption refused until a refresh succeeds | `test_failed_trust_state_refresh_fails_closed` |
| A trust-state refresh presents a version lower than the one installed | § 4 meaning-2 monotonic-version rule | Refresh refused; the process keeps its current, higher-versioned trust state (rollback refused) | `test_trust_state_refresh_refuses_a_lower_version` |
| A key ID appears in both `revoked_key_ids` and `trusted_key_ids` | § 4 meaning-2 "revoked wins" rule | Consumption refused — `revoked_key_ids` takes precedence | `test_revoked_key_id_is_refused_even_if_also_trusted` |
| The trust-state record cannot be read or fails validation at process start | § 4 meaning-2 startup-fails-closed rule | Process refuses to start, or refuses every consumption; never falls back to trusting whatever the signer's public half verifies | `test_startup_fails_closed_when_trust_state_is_unreadable` |
| A fresh process starts with a trust-state record whose `version` is present and readable, but below the immutable durable floor (§ 10 item 4) | § 4 meaning-2 startup-fails-closed rule, checked against the immutable version floor pinned in CP deployment configuration — distinct from the general "cannot be read or fails validation" row above, which covers a missing/malformed record | Process refuses to start (or refuses every consumption), even though the record itself parses and verifies | `test_startup_refuses_a_readable_trust_state_below_the_immutable_floor` |
| A third signing-key version is presented while two versions are already within their overlap window (§ 10 item 6) | § 4 rotation rule: the verifier accepts at most two signing versions — the current and the immediately retiring one | Third version's signature refused | `test_a_third_concurrent_signing_version_is_refused` |
| A retiring signing-key version is presented after its overlap window has elapsed (§ 10 item 6) | § 4 rotation rule: the bounded overlap window is enforced, not open-ended | Signature refused once the overlap window has elapsed | `test_a_retiring_signing_version_is_refused_after_the_overlap_window` |
| The per-run key or its issued certificate survives past run end | § 5 Destruction step, workflow cleanup | Filesystem check in the workflow's cleanup step confirms both are gone regardless of run outcome | `test_per_run_key_and_certificate_are_destroyed_at_run_end` |

## 8. Who does what

**Provisioning proceeds in this order, per the Runner placement section's
two conditions.** Condition 1 is confirmed first. Then Michael may, at his
own discretion and as his own step in order to run condition 2, provision a
credential-free topology fixture — the organization, the execution
repository, the runner group, and an ephemeral runner with no OpenBao
binding and no secrets — sufficient to run the live negative test. Only once
BOTH conditions are met does credential-bearing provisioning begin: the § 2
Environment's secrets/approvals binding, the OpenBao JWT role, the signers,
the trust state, and the SSH CA. This spec authorizes none of it; it names
the order and the boundary between the credential-free fixture and
credential-bearing provisioning.

Provisioning — Michael only; no agent performs any of these:

| Action | Owner |
| --- | --- |
| **Condition 1:** Confirm the plan supports selected-workflow runner groups | Michael |
| **Credential-free fixture, follows from the 2026-09-28 topology ruling:** Create or choose the organization and its private execution repository | Michael |
| **Credential-free fixture, follows from the 2026-09-28 topology ruling:** Create the runner group restricted to the exact protected workflow (the ref-pinned coordinate, § 6), and register the ephemeral runner in it — no OpenBao binding, no secrets | Michael |
| **Condition 2, the live negative test:** Run it per § 7's `test_only_the_protected_workflow_can_select_the_runner` row's fixed negative-first, then positive-control order and its evidence/clean-up requirements | Michael |
| **Credential-free fixture, same phase as condition 2, run right after it:** Run § 7's non-default-ref row (`test_non_default_ref_run_of_the_protected_workflow_file_cannot_select_the_runner`) against the same STUB fixture workflow, before any Environment exists. First cancel any still-queued job from condition 2, then register a FRESH ephemeral runner in the group (the condition-2 positive control consumed the previous one) and show it idle; "the SAME runner" means the same runner within this test | Michael |
| **Blocked until both conditions are met:** Create the § 2 GitHub Environment and configure the required reviewer + `main`-only branch policy | Michael |
| **Blocked until both conditions are met:** Create the OpenBao JWT auth role and its policies (§ 3, § 4) | Michael |
| **Blocked until both conditions are met:** Generate and store the Ed25519 rehearsal-issuer signer at `secret/dotmac/platform-cp/rehearsal-issuer/signing-key` (§ 4) | Michael |
| **Blocked until both conditions are met:** Generate the dedicated harness-evidence attester key (§ 10 item 1) — a distinct attester identity from the rehearsal-issuer signer, at its own custody path, with its own trust-state record | Michael |
| **Blocked until both conditions are met:** Create the verifier trust-state record (`trusted_key_ids`, `revoked_key_ids`; public identifiers only) at `<placeholder: trust-state path>`, write EVERY update to it (including future revocations), and grant CP's service identity read-only access — never write — on it (§ 4) | Michael, via the provisioning identity only — never CP's runtime identity, and never the runner or its workflow token |
| **Blocked until both conditions are met:** Pin the minimum trust-state version — the durable floor (§ 10 item 4) — in independently controlled, immutable CP deployment configuration | Michael |
| **Blocked until both conditions are met:** Configure the OpenBao SSH CA / signing role for controller certificates (§ 5) — CA role, `valid_principals`, extensions and measured TTL, per the § 5 selection | Michael |
| **Blocked until both conditions are met:** Set the repository variables — the observer user, the jump key reference, and the inside-vantage variable that `docs/inventories/lane3-acceptance-criteria.md` requires, alongside the existing `LANE3_PROBE_HOST` (§ A7.5) — on the execution repository | Michael |

Agent-doable source work, once the above is accepted and provisioned:

- The workflow YAML implementing §§ 2–6 (Environment reference, OIDC step,
  OpenBao token exchange, per-run key generation and destruction, runner
  isolation) — **follows from the 2026-09-28 topology ruling, subject to
  the two conditions in the Runner placement section:** in the
  organization-owned execution repository, using the runner group
  restricted to the exact protected workflow's ref-pinned coordinate (per
  "Runner placement blocker" above) — not via a label alone on a shared
  runner.
- The controller-fingerprint derivation code (§ 5).
- The startup signer install call site (`install_rehearsal_issuer_security`,
  § 4) wiring CP's process start to the OpenBao read.
- The verifier trust state (§ 4, meaning 2): its install at start, the
  explicit audited refresh command (which fails closed on failure), and the
  consumption refusal gate on `revoked_key_ids`/`trusted_key_ids`, with the
  eight § 7 trust-state tests (including the immutable-floor test) plus the
  two signer-rotation overlap tests (§ 10 item 6). Authorization/lease
  revocation stays Control's.
- **Control-owned change, tracked here but implemented in
  `dotmac-deployment-control`:** the transactional, cross-lease fingerprint
  uniqueness check (§ 5, § 10 item 2) — enforced in Control's durable
  lease/consumption authority, not in this repository.
- Work Packet E's harness and receipt, once D's workflow evidence exists to
  consume (§ 9).

## 9. What D must hand Work Packet E

Per ADR-0013 § A7.7, Work Packet E's candidate-independent readiness receipt
must record the protected environment and run identity, exact source
revisions, evidence digests, and pass/refusal outcomes across issuance,
standing, single-use consumption with replay refused, and a separate
revocation lease with later use refused. D is the packet that makes each of
these actually available to E: the § 2 Environment/run identity to record,
the § 3 OIDC-derived job identity, the § 4 signer's key ID/fingerprint/version
to cite (never its value), and the § 5 per-run controller fingerprint bound
into independently verified harness evidence. That harness-evidence
verification depends on which key signs the harness evidence
(**Ruled by Michael 2026-09-28, § 10 item 1: a dedicated attester key,
distinct from the § 4 rehearsal-issuer signer**) being provisioned before D
can hand E a genuinely independently-verified evidence digest — E cannot
accept a digest verified against an unnamed or ambiguous signer. E performs
no provisioning of
its own and consumes D's evidence as-is; D does not itself produce the
receipt or decide any pass/refusal outcome — that is E's job per § A7.7.

## 10. Open decisions for Michael

Neither ADR-0013 nor an earlier instruction from Michael originally settled
these. Items 1–4, 6, 7 and 8 are now ruled (2026-09-28); item 5 is ruled in
principle and pending the execution repository. They are collected here so
none is missed before provisioning:

1. **Who signs the harness evidence (§ 1, § 5, § 7, § 9).** Same key as the
   § 4 rehearsal-issuer signer, or a dedicated harness-evidence signing key
   with its own custody path and (if separate) its own trust state.
   **Trade-off to decide knowingly:** reusing the § 4 signer puts fact 3
   (issuer signature) and fact 4 (controller-key proof via signed harness
   evidence) under ONE key and ONE compromise domain. § 1 treats collapsing
   any two of the four facts as the failure to refuse, and ADR-0013 § A7.3 /
   § A7.4 require the evidence to be "independently signed". A shared key may
   still meet the letter only if the two checks stay separate; a dedicated
   key keeps the compromise domains apart.
   **Ruled by Michael 2026-09-28:** a DEDICATED signer,
   held by a distinct attester identity (not the issuer, not the runner),
   with its own trust state. A second key readable by the same compromised
   principal gives no meaningful separation.
2. **Where the reuse-detection check lives (§ 5).** An extension of
   Control's existing single-use consumption logic, or a separate
   fingerprint index consulted before Control's consumption check.
   **Ruled by Michael 2026-09-28:** cross-run fingerprint
   uniqueness lives in Control's durable lease/consumption authority,
   enforced transactionally ACROSS leases. The single use of one lease does
   not catch reuse on another.
3. **Where the Ed25519 signer keypair is actually generated (§ 4).** An
   offline process under Michael's control writing into the declared KV v2
   path, or an OpenBao Transit key configured exportable — the ADR does not
   decide this, and a KV engine cannot generate the key itself while a
   typical non-exportable Transit key cannot be loaded at process start.
   **Ruled by Michael 2026-09-28:** each Ed25519 key is
   generated under Michael's controlled, short-lived provisioning process
   and sealed into KV v2. Not exportable Transit merely to satisfy the
   load-at-start contract: exportability cannot later be disabled
   (https://openbao.org/docs/next/api/secret/transit/).
4. **Startup rollback protection for the trust state (§ 4).** Refresh refuses
   a version lower than the installed one, but a freshly started process has
   installed nothing, so on its own it would accept a stale or tampered record
   and could re-admit a revoked key. A DURABLE version floor is needed. Options:
   a minimum trust-state version pinned in CP's configuration at deploy time,
   or a floor recorded by the provisioning identity alongside the record and
   read at startup. Until one is chosen, § 4's startup rule is incomplete.
   **Ruled by Michael 2026-09-28:** the minimum
   trust-state version is pinned in independently controlled, IMMUTABLE CP
   deployment configuration, not beside the mutable trust-state record.
5. Every `<placeholder: ...>` value throughout §§ 2–8 (audience, trust-state
   path, SSH CA role/`valid_principals`/extensions/key ID, the runner-group
   name, the live-negative-test bound `<placeholder: N minutes>` (§ 7), and
   the rotation overlap window in item 6 below) is Michael's to choose at
   provisioning time, not a decision this spec makes. Plain names that do
   not depend on
   the execution repository are settled now, not deferred to provisioning:
   **Ruled by Michael 2026-09-28:** the Environment name and the OpenBao JWT
   role name are both fixed as `rehearsal-issuer-protected` (§§ 2, 3 — no
   longer placeholders).
   **Ruled in principle; cannot be finalized until the execution repository
   is chosen:** the repository, `workflow_ref`, runner-group and runner
   identity (its ID and registration, as distinct from the group NAME,
   which is Michael's to choose above), SSH principals and fingerprints
   remain `<derived from the approved execution repository>`. The 5-minute non-renewable token
   proposal stays. The certificate TTL is still to be measured.

Design choices already made in this spec, confirmed by Michael's 2026-09-28
ruling below:

6. **The signer-rotation overlap window (§ 4)** — the verifier accepts
   authorizations signed under either the retiring or the new key version
   for a defined window (`<placeholder>`); confirm this two-version-overlap
   approach itself, separately from picking the window's length.
   **Ruled by Michael 2026-09-28:** two signing versions
   only, for a bounded overlap equal to the maximum outstanding
   authorization lifetime plus clock skew. Establish that maximum before
   setting the duration.
7. **"D does not use a reusable workflow" (§ 3)** — `workflow_ref` (not
   `job_workflow_ref`) is bound because this spec assumes the protected job
   runs as a normal workflow, not a reusable-workflow call. Confirm this
   assumption; if a reusable workflow is later wanted, § 3's bound-claims
   choice changes.
   **Ruled by Michael 2026-09-28:** the protected
   workflow is directly defined, non-reusable, in the chosen execution
   repository (see "Runner placement blocker"); bind `workflow_ref`.
8. **Trust-state hardening rules (§ 4)** — Michael-only writes, a monotonic
   version with rollback refusal, revoked-wins over trusted, and fail-closed
   startup. These are fail-closed extensions of Michael's key-compromise
   decision rather than new owners; confirm them.
   **Ruled by Michael 2026-09-28:** trust-state
   hardening confirmed — Michael-only writes, monotonic rollback refusal,
   revoked-wins, and fail-closed startup and failed-compromise refresh.

**Note (§ 5) — not an open item.** The mechanism is already selected, not
pending a decision: **Selected — Michael 2026-09-28:** a short-lived
OpenBao-issued SSH certificate, not a long-lived host-trusted key. What
remains pending is provisioning detail only — the CA role, `valid_principals`,
extensions, the certificate key ID binding, and the measured TTL — not the
choice of mechanism itself.
