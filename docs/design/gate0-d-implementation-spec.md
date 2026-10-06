# Gate-0 Work Packet D — protected rehearsal-issuer identity, custody and runner isolation

> **Status — § 10 custody and identity rulings approved 2026-09-28; § 11's
> public GitHub Free execution topology supersedes the earlier private
> placement as of 2026-09-30.** This implements ADR-0013 § A7 Work Packet D,
> not a new ADR. § 11 records partial public-control provisioning as of
> 2026-09-30, with no Gate-0 admission. The OpenBao role, signer keys, trust
> records, SSH CA, and private-vantage delivery remain unprovisioned or
> unproved in this document. Historical placement and fixture instructions
> below must be read through § 11; a placeholder is not an authorization or
> evidence of a deployed value.

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
composition" column for the harness-evidence row), § A7.5 (the three gaps
observed on 2026-09-24: no protected Environment, no OIDC/OpenBao role, no
observer/jump/vantage repository variables beyond `LANE3_PROBE_HOST`; § 11
records partial public controls and keeps private-vantage delivery open), and
§ A7.7 (what Work Packet E consumes from D).

D does not touch: `dotmac-deployment-control`'s issuance/standing/revocation
logic (owned per § A7.6), `dotmac-approvals`'s decision flow (owned per
§ A7.6), or Foundation's `ExecutionGrant` semantics (Work Packet C1, per
§ A7.3's document-purpose matrix). D supplies identity, custody and runner
configuration; it decides no plan legality, no approval, and no execution
authorization.

## Runner placement blocker

**Historical placement analysis (2026-09-28):** the private-repository
topology below was ruled subject to two conditions, then superseded by
Michael's 2026-09-30 public GitHub Free ruling in § 11. It is retained to
explain the original isolation blocker, not as current provisioning guidance.
§ 11's public controls, isolation and negative evidence govern admission.

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

**Superseded private topology — ruled 2026-09-28, replaced by § 11:**

- an organization-owned PRIVATE execution repository, holding only the
  protected, directly defined, non-reusable workflow;
- a runner group restricted to the exact protected workflow, using GitHub's
  organization-level selected-workflow runner-group access
  (https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access);
- the runner stays isolated and ephemeral;
- Starter's runner stays dedicated to Lane 3.

The superseded private-placement ruling had two conditions:

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

**The original #217 packet was design-only: it did not authorize provisioning.**
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

The condition sequence above is historical. § 11 records the later public
topology and its dated partial provision record; no Gate-0 admission follows
from either sequence without the required evidence.

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

**Current placement (§ 11):** this Environment belongs to the public
`dotmac-tech/gate0-issuer-execution` repository, not CP or Starter. The
2026-09-30 partial read-back in § 11 reports its configuration; that dated
observation does not establish live Gate-0 admission.

A dedicated GitHub Environment, name `rehearsal-issuer-protected` (fixed per
§ 10 item 5 — not a placeholder), must have:

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

**Current placement (§ 11):** the `repository` and `workflow_ref` claims bind
the public `dotmac-tech/gate0-issuer-execution` repository and its directly
defined, non-reusable protected workflow. § 11 also binds immutable
`repository_id`, `repository_owner_id` and `event_name` claims. The protected
workflow declares no `pull_request` or `pull_request_target` trigger (§ 6).

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
| `repository` | `dotmac-tech/gate0-issuer-execution` (§ 11) | Scopes the role to the approved execution repository only. |
| `repository_id` | `1397614140` (§ 11's 2026-09-30 provision record; re-read before role provisioning) | Refuses a repository-name replacement. |
| `repository_owner_id` | `335992433` (§ 11's 2026-09-30 provision record; re-read before role provisioning) | Refuses an owner-name replacement. |
| `environment` | `rehearsal-issuer-protected` (the § 2 Environment name, fixed) | GitHub's environment-based `sub` claim can omit the branch entirely — an Environment-only bound claim would accept the same job running from a non-`main` ref if the Environment's own branch policy were ever misconfigured or bypassed by a different trigger. |
| `ref` | `refs/heads/main` | Independently pins the branch at the OpenBao layer, so OpenBao's own policy does not rely solely on GitHub's Environment configuration remaining correct. |
| `workflow_ref` | `dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main` (§ 11) | Pins the exact workflow file and ref of the directly defined, non-reusable workflow, not just "some workflow in this repo." `job_workflow_ref` is not substituted (§ 10 item 7). |
| `event_name` | `workflow_dispatch` (§ 11) | Refuses a different trigger even if workflow guards regress. |

Audience (`bound_audiences`, not `bound_claims`): `urn:dotmac:gate0:rehearsal-issuer` (adopted 2026-10-06, § 12).
The protected job requests its OIDC token for exactly this audience.

`ref` is bound to `refs/heads/main` as its own claim, separately from
`environment`; neither substitutes for the other. The bound values are
checked against the ACTUAL claims of the protected job (captured from a real
run of that job, not assumed from documentation) before the role is accepted.

Token TTL: `<placeholder, short — e.g. 5m>`, no renewal.
**Ruled in principle (§ 10 item 5); the repository is now identified in
§ 11, while the token and role remain to be provisioned and tested:** a
starting OIDC-derived OpenBao token TTL of five minutes, non-renewable.
Policy scope: the
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
  and version only — never the private key material. Key ID
  `gate0-rehearsal-issuer-v1` (adopted 2026-10-06, § 12); the fingerprint is
  measured from the public half at provisioning and is not a chosen value;
  the KV version is read back after the write, with the path asserted absent
  before it. The
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
         controlled record, `secret/dotmac/platform-cp/rehearsal-issuer/trust-state`
         (the attester's is `secret/dotmac/platform-cp/rehearsal-attester/trust-state`;
         adopted 2026-10-06, § 12), and installed at
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
  (dedicated `gate0-ssh/` mount, role `rehearsal-controller`, adopted
  2026-10-06, § 12; it replaces the earlier `secret/ssh` proposal) signed over the per-run public
  key, scoped to the target(s) named by `LANE3_PROBE_HOST` and the vantage
  variables in § 6, with:
  - **TTL:** a **600-second ceiling**; the issued TTL is **measured**, never
    assumed from the role (adopted 2026-10-06, § 12). **Ruled in principle (§ 10 item 5); the execution
    repository is selected in § 11:** measure the certificate lifetime
    against the provisioned real run and SSH signing role before fixing it.
  - **`valid_principals`:** `dotmac-gate0-controller` only; no wildcard, no
    root, no general deploy principal (adopted 2026-10-06, § 12).
  - **Extensions:** none: no forwarding of any kind and no PTY (adopted
    2026-10-06, § 12).
  - **Certificate key ID:** `gate0:<repository-id>:<run-id>:<run-attempt>`,
    bound at runtime (adopted 2026-10-06, § 12). **The key ID alone is not
    evidence.** Controller key possession and the run, attempt and lease
    binding are independently verified, not read from the certificate's own
    label.
  Reference: https://openbao.org/docs/secrets/ssh/signed-ssh-certificates/
- **Destruction:** both the private key and any issued certificate are
  deleted from the runner's filesystem at the end of the run, in the
  workflow's cleanup step, regardless of run outcome (success, refusal, or
  job failure) — the ephemeral OpenBao token from § 3 also naturally expires
  at its short TTL.

## 6. Runner isolation

**Current public topology (§ 11):** isolation comes from the organization
runner group's selected repository ID and selected, ref-pinned workflow,
`dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main`.
A label alone does not restrict workflow selection, and a public repository
requires the additional PR-trigger, review, claim and runner-isolation
controls stated in § 11. The 2026-09-28 private placement above is historical.
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
  `dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main`,
  not a bare workflow-file name, so a same-named workflow file run from a
  different ref does not match either (see § 7's non-default-ref row). A
  label alone does not restrict which workflow may use a runner (see
  "Runner placement blocker"). This is the live negative test required by
  condition 2 above (§ 7).
- The runner is ephemeral and holds no state between runs. This is hygiene,
  NOT the selection control — selection is enforced by the runner group's
  repository access and selected-workflow restriction above, not by
  ephemerality. Its actual configuration and cleanup must be verified before
  privileged attachment (§ 11).

Reference: GitHub Actions secure-use guidance —
https://docs.github.com/en/actions/reference/security/secure-use ; GitHub
selected-workflow runner-group access —
https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access

## 7. Refusal tests

**Current public topology (§ 11):** the refusal tests apply to the public
`dotmac-tech/gate0-issuer-execution` repository and its selected-workflow
runner group, not `control-runner-starter-mt`'s label. The OIDC rows require
the provisioned JWT role and observed claims; § 11's dated read-backs alone
do not discharge them.

Each row names the planned test's intent; naming a test here does not create
it — these are written when D's workflow YAML and harness code exist. Every
row below whose "Enforced where" cites OpenBao's JWT role runs against the
PROVISIONED role configuration from § 3/§ 8 (the actual bound claims and
policy Michael configures, for the approved execution repository's real
claims), not a mock or a hand-constructed stand-in role.

Rows describing a stub fixture **before an Environment exists** preserve the
2026-09-28 test design as history. § 11's 2026-09-30 read-back reports that
the Environment now exists; current admission uses § 11's separately
isolated canary, complete public-control tuple, and positive and negative
evidence. No historical row proves a live refusal or authorizes a runner.

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

The 2026-09-28 two-condition private-fixture sequence in the Runner placement
section is historical. § 11 governs the public Free execution repository and
records partial controls as of 2026-09-30; those read-backs are not Gate-0
admission. Credential-bearing provisioning remains pending the § 11 positive
and negative evidence, isolated-runner controls, and exact public coordinate
read-backs. This design document grants no provisioning authority.

Provisioning and admission obligations — protected provisioning remains
Michael's; private-vantage delivery retains its ADR-0013 § A7.6 owner. This
spec grants no agent authority to perform these actions:

| Action | Owner |
| --- | --- |
| **Public fixture (§ 11):** Re-read the existing public repository, Environment, workflow and selected runner-group coordinates before any further admission step; the 2026-09-30 observations are dated | Michael |
| **Isolated canary (§ 11):** Complete the named, separately isolated canary's public-control and negative scheduling probes, remove it, and read back runner-group membership before privileged attachment | Michael |
| **Pending § 11 admission:** Provision the OpenBao JWT auth role and its policies (§ 3, § 4) against the exact public repository and workflow claims | Michael |
| **Pending § 11 admission:** Generate and store the Ed25519 rehearsal-issuer signer at `secret/dotmac/platform-cp/rehearsal-issuer/signing-key` (§ 4) | Michael |
| **Pending § 11 admission:** Generate the dedicated harness-evidence attester key (§ 10 item 1) — a distinct attester identity from the rehearsal-issuer signer, at its own custody path, with its own trust-state record | Michael |
| **Pending § 11 admission:** Create the verifier trust-state record (`trusted_key_ids`, `revoked_key_ids`; public identifiers only) at `secret/dotmac/platform-cp/rehearsal-issuer/trust-state` (and the attester's at `secret/dotmac/platform-cp/rehearsal-attester/trust-state`), write every update to it (including future revocations), and grant CP's service identity read-only access — never write — on it (§ 4) | Michael, via the provisioning identity only — never CP's runtime identity, and never the runner or its workflow token |
| **Pending § 11 admission:** Pin the minimum trust-state version — the durable floor (§ 10 item 4) — in independently controlled, immutable CP deployment configuration | Michael |
| **Pending § 11 admission:** Configure the OpenBao SSH CA / signing role for controller certificates (§ 5) — CA role, `valid_principals`, extensions and measured TTL, per the § 5 selection | Michael |
| **Unresolved (§ 11):** Design and verify private delivery of observer, jump and inside-vantage configuration through Starter/Foundation infrastructure; put none of it in the public execution repository | Starter/Foundation infrastructure owner (ADR-0013 § A7.6) |

Agent-doable source work after the applicable § 11 admission and provisioning:

- The workflow YAML implementing §§ 2–6 (Environment reference, OIDC step,
  OpenBao token exchange, per-run key generation and destruction, runner
  isolation) in § 11's public execution repository, using its selected
  repository and ref-pinned workflow restrictions — not a shared-runner label.
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

## 10. Decision record and remaining provisioning values

Neither ADR-0013 nor an earlier instruction from Michael originally settled
these. Michael ruled items 1–4 and 6–8 on 2026-09-28. § 11's later public
Free ruling selects the execution repository and supersedes the private
placement premise of item 5; exact credential, trust-record and SSH-CA
provisioning values remain pending. The original alternatives below remain
as decision history, not questions to put to Michael again:

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
5. Originally, `<placeholder: ...>` values throughout §§ 2–8 (audience, trust-state
   path, SSH CA role/`valid_principals`/extensions/key ID, the runner-group
   name, the live-negative-test bound `<placeholder: N minutes>` (§ 7), and
   the rotation overlap window in item 6 below) required Michael's choices
   at provisioning time. Plain names independent of the execution repository
   were then settled:
   **Ruled by Michael 2026-09-28:** the Environment name and the OpenBao JWT
   role name are both fixed as `rehearsal-issuer-protected` (§§ 2, 3 — no
   longer placeholders).
   **Superseded in part by § 11 (2026-09-30):** the public execution
   repository, ref-pinned `workflow_ref`, Environment and runner-group names
   are now specified there, with a dated partial control read-back. The
   runner identity and registration, OpenBao audience and role admission,
   SSH principals and fingerprints, trust-state path, floor value, and
   measured certificate TTL remain pending. The five-minute non-renewable
   token proposal remains subject to provisioned-role validation.

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

## 11. Amendment — public GitHub Free execution topology (2026-09-30)

Michael ruled on 2026-09-30 that Gate-0 D uses a **public, `dotmac-tech`-owned
execution repository on GitHub Free**. This supersedes only the earlier
private/in-this-repository placement assumed in §§ 2, 3, 6, 8 and 10 item 7.
The § A7.5 observation that this repository lacked an Environment on
2026-09-24 remains a historical fact, not the location of the new gate.
Platform CP retains the operator-workflow and Gate-0 receipt ownership in
§ A7.6–A7.7; the separate repository is its execution surface, not a new
approval, issuer, or execution-authority owner. All other identity, custody,
document-purpose, and Gate-0/2/3 boundaries above remain in force.

**Proposed coordinates, all uncreated as of this amendment:** public repository
`dotmac-tech/gate0-issuer-execution`; directly defined, non-reusable workflow
`dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main`;
Environment `rehearsal-issuer-protected`; organization runner group
`gate0-issuer-protected`. These are proposed names for the implementation,
not claims that the repository, workflow, Environment, group, or runner exists.
Provisioning must record the final exact coordinates and update this spec if
any name changes; every GitHub runner-group restriction and OpenBao claim
binding must use those same coordinates before a privileged runner is
registered, moved into the group, or allowed to take a job.

The public execution repository has a protected `main`: require a pull request
with **zero required approving reviews** (a solo owner cannot independently
approve their own PR), require non-privileged checks selected for this
workflow, apply protection to administrators, and refuse direct pushes, force
pushes, deletion, and configured bypass actors. Read back the effective rule.
This is a change-record and CI gate, **not** an independently reviewed-code
claim; the separate Environment review below is the one-person human gate.
Its sole privileged workflow is defined directly in the named file and dispatches only
from `refs/heads/main`. It has no `pull_request`, `pull_request_target`, or
reusable `workflow_call` trigger, and no job from a PR event may select the
privileged group. The protected job has a job-level condition requiring both
`workflow_dispatch` and `refs/heads/main`. A manual dispatch from another
ref must be refused before runner scheduling as well as by the Environment
branch rule and OpenBao `bound_claims.ref`. The Environment permits `main`
only and requires Michael as its reviewer before the job starts, with
administrator bypass explicitly disabled and read back. Because Michael is
the sole approver, the Environment must allow his own review; it is a
deliberate human gate, not two-person approval. The workflow's `GITHUB_TOKEN`
gets the minimum read permissions plus `id-token: write` only for the protected
job; no untrusted
checkout, artifact, or third-party action executes on the privileged runner.

The organization runner group must be admitted with **all** of this tuple:
`allows_public_repositories=true` (GitHub defaults it to `false`),
`visibility=selected`, `selected_repository_ids=[the exact ID of
dotmac-tech/gate0-issuer-execution]`, `restricted_to_workflows=true`, and
`selected_workflows=[dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main]`.
The group must contain no other repository or workflow. Read the group back
through GitHub's API and compare every field, including the resolved
repository ID, before attaching a runner. A label alone is not isolation.
The runner must be dedicated to this group and cleaned or recreated between
runs per § 6; the chosen mode and its observed effectiveness are admission
evidence, not an assumption from configuration.

The OpenBao JWT role in § 3 binds `repository` to
`dotmac-tech/gate0-issuer-execution`, `environment` to
`rehearsal-issuer-protected`, `ref` to `refs/heads/main`, and `workflow_ref`
to the exact workflow coordinate above. It also binds `repository_id` and
`repository_owner_id` to the immutable IDs read from GitHub at repository
creation and `event_name` to `workflow_dispatch`, with the separately
configured exact `bound_audiences`. Names alone are insufficient identity:
the IDs refuse rename/recreation substitution, and the event claim refuses
a different trigger even if a workflow YAML guard regresses. Since the
privileged job is directly defined, the role does not substitute
`job_workflow_ref` or accept a reusable caller. The
workflow's OIDC-derived token can reach only the short-lived SSH CA signing
capability in § 5. Its policy explicitly denies read of the § 4 issuer signer
and of any separate harness-evidence signer. CP's distinct service identity
alone reads the issuer signer at process start. Test the provisioned role and
policy, not a stand-in configuration.

Public visibility exposes workflow source, repository history, run metadata,
and any public logs or artifacts to anyone. It grants no trust to a job, no
approval of a plan, no safe isolation for a self-hosted runner, and no
protection for a value once workflow code or logs disclose it. The public
repository therefore holds **no secrets, credentials, host addresses, jump
details, inside-vantage topology, or private OpenBao material** in tracked
files, GitHub secrets/variables, logs, or artifacts. § 8's observer, jump and
vantage variables remain outside this public repository; no public copy of
`LANE3_PROBE_HOST` is made. ADR-0013 § A7.6 still assigns the Lane-3 vantage
configuration to Starter/Foundation infrastructure; this public-repository
amendment does not move its owner. A file readable by the Actions runner user
is also readable by workflow steps, so putting private topology on that host
under the runner's identity is not a confidentiality boundary. The private
delivery mechanism for § 8's vantage configuration remains **unresolved**;
no target address, jump detail, or inside-vantage value may be copied to the
public repository as a shortcut. Its owner must design and prove a delivery
mechanism separately before D can claim that part of its contract is closed.

Gate-0 D/E proves candidate-independent issuer readiness, not a target
action. A Control `RehearsalIssuerAuthorizationV1` lease never authorizes a
connection or command against a target. The protected Gate-0 workflow must
make no target connection. Any later broker, proxy, or direct Lane-3 transport
belongs to Gate 3 and must refuse absent or mismatched Foundation
`ExecutionGrant` binding the exact candidate, target, host, and controller.
This amendment neither chooses nor provisions that transport. Configuring
GitHub's public controls alone does not close D or authorize a target action.

Before any privileged runner registration or group attachment, retain
independent evidence of these **positive and negative** outcomes. Scheduling
probes use only a disposable canary runner in the same selected group, on a
**separately named and authorized** isolated host/VM with a privately verified
absence of target-network routes, private material, and trusted workspace.
Neither the existing control-runner VM nor the shared Docker/Postgres testing
server qualifies. At amendment time no such canary was authorized; the dated
partial record below reports a later isolated VM attempt but no completed
admission. Remove the canary after the probes and read back
group membership before attaching the privileged runner. The canary cannot stand in for the
later per-run key, cleanup, or target-vantage proof; those remain post-attach
acceptance evidence for D and E, and no target action is authorized by these
pre-registration probes:

| Admission check | Required evidence |
| --- | --- |
| Public-repo controls | Read back public visibility, `dotmac-tech` ownership, protected `main` with PR required/zero approvals, required checks, admin enforcement and no bypass, exact Environment reviewer, admin-bypass refusal and `main` branch policy, and the complete runner-group tuple above. Missing or disabled controls refuse admission. |
| Authorized scheduling | A main-branch PR/check-gated workflow followed by Michael's Environment-reviewed dispatch reaches only the selected group and protected job; the observed OIDC claims, including immutable repository and owner IDs and `event_name`, match the provisioned role. |
| PR exclusion | Both same-repository and fork-origin `pull_request` **and** `pull_request_target` probes, including attempts to select the group by label or name, cannot schedule on the privileged runner. A malicious PR workflow edit must not change the selected `@refs/heads/main` workflow. |
| Ref/workflow failure | A non-`main` manual dispatch, a different workflow file or ref, and a reusable-workflow call cannot schedule on the group or obtain an OpenBao token; a missing reviewer blocks the protected job. |
| Credential failure | Wrong repository name, immutable `repository_id`, immutable `repository_owner_id`, environment, ref, workflow, `event_name`, audience, or expired token is denied by the live OpenBao role; the runner token cannot read either signer path or the private topology record, even after successful SSH CA access. |
| No Gate-0 target action | The protected Gate-0 workflow makes no connection or command to a target. A Control issuer lease alone cannot enable any target transport; a later Gate-3 attempt with no matching Foundation `ExecutionGrant` is refused before dialing. § 8's private vantage delivery remains open and no topology value appears in public source, variables, logs, or artifacts. |
| Isolation and disclosure | The canary's failed/cancelled run leaves no per-run key or certificate; its next run sees no prior workspace state. Published source, variables, logs, and artifacts contain no secret or host-topology value. Repeat the cleanup proof on the privileged runner after attachment and before D acceptance. |

Record the exact repository ID, configuration read-backs, test run IDs,
refusal outcomes, and source revision for Work Packet E. A positive dispatch
alone is insufficient: the negative scheduling and failure cases are part of
the gate. GitHub warns that public-repository fork PRs can compromise
self-hosted runners; the selected-repository **and** selected-workflow
restriction, PR-trigger exclusion, review gate, branch policy, OpenBao
claims, and runner isolation must all be demonstrated together before
registration. A private repository on GitHub Team does not repair this
specific gate: GitHub makes required Environment reviewers available only to
public repositories on Free, Pro, and Team.

GitHub plan and runner-group references: [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[Environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[runner groups](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access),
[runner-group API](https://docs.github.com/en/rest/actions/self-hosted-runner-groups), and
[self-hosted runner security](https://docs.github.com/en/actions/reference/security/secure-use).

### Provisioning record — 2026-09-30 (partial; no Gate-0 admission)

The amendment's proposed coordinates now exist. CP #229 merged as
`6f5efe2176e25477816f24e6762d5ce9e9fb34ed`. The public execution
repository `dotmac-tech/gate0-issuer-execution` has repository ID
`1397614140` under organization ID `335992433`. Its refusal-only source
PR #1 merged as `f218660b6ff7c3a01b877e6ab080efcd31672805`. The
protected workflow exits unsuccessfully by design and has no issuer,
OpenBao, SSH, or target action.

GitHub API read-back showed the following configured controls:

- Main ruleset `24240825`: pull request required with zero approving
  reviews, `source_policy` required, no configured bypass actors, deletion
  and non-fast-forward refused.
- Environment `rehearsal-issuer-protected` (`23103080174`): Michael is
  the required reviewer, admin bypass disabled, and only `main` admitted.
- Organization runner group `gate0-issuer-protected` (`3`): public
  repositories allowed, selected repository ID `1397614140` only, selected
  workflow
  `dotmac-tech/gate0-issuer-execution/.github/workflows/gate0-issuer.yml@refs/heads/main`
  only. The group contained **zero runners** at last read-back.

`source_policy` runs from the same repository as the workflow it checks.
It catches accidental drift but can be changed alongside that workflow;
its green status is **not independent admission evidence**. A disposable,
separately isolated canary VM was created on a named authorized testing
host, and its guest had no default route. From within it, an explicitly
forwarded, host-owned proxy reached GitHub's API and refused the test host,
production host, unrelated public site, and arbitrary Azure Blob account.
The official runner archive was verified against its GitHub-published
SHA-256 and extracted, but unattended registration timed out before the
runner appeared in GitHub. At this 2026-09-30 observation, no live scheduling
refusal or OIDC/OpenBao negative test had run. The VM was powered off and its
temporary proxy stopped after the failed attempt; its disk is retained for
diagnosis. The canary is not the privileged runner. This partial setup
neither closes D nor permits Foundation successor allocation.

## 12. Amendment — provisioning values adopted 2026-10-06

Michael ruled on 2026-10-06. The values below replace the corresponding
placeholders in §§ 3–5 and § 8. **This amendment authorizes no provisioning.**
Key generation, auth-mount changes, VM creation and privileged runner
attachment remain **not authorized**. Step A1's human-run metadata inventory
(read-only) must first confirm the planned paths and mounts are absent.

| Item | Adopted value | Status |
| --- | --- | --- |
| OIDC audience (§ 3) | `urn:dotmac:gate0:rehearsal-issuer` in `bound_audiences` | Adopted |
| SSH CA mount and principal (§ 5) | Dedicated mount `gate0-ssh/`, role `rehearsal-controller`, `valid_principals` = `dotmac-gate0-controller` only, no wildcard or root. This replaces the earlier `secret/ssh` proposal | Adopted |
| Controller certificate (§ 5) | No extensions (no forwarding, no PTY); **600 s ceiling**; issued TTL **measured**; key ID `gate0:<repository-id>:<run-id>:<run-attempt>` bound at runtime. **The key ID alone is insufficient:** controller key possession and the run, attempt and lease binding are independently verified | Adopted |
| Issuer and attester keys (§ 4) | `gate0-rehearsal-issuer-v1` at `secret/dotmac/platform-cp/rehearsal-issuer/signing-key`; `gate0-harness-attester-v1` at `secret/dotmac/platform-cp/rehearsal-attester/signing-key`. Fingerprints are measured from the public halves at provisioning | Adopted |
| Trust-state records (§ 4, § 8) | `secret/dotmac/platform-cp/rehearsal-issuer/trust-state` and `secret/dotmac/platform-cp/rehearsal-attester/trust-state`. Public identifiers only; Michael-only writes; CP service identity read-only | Adopted |
| Initial trust floor (§ 10 item 4) | Version 1 for the new records only, pinned in immutable CP deployment configuration; never lowered by an OpenBao or Observe backup | Adopted |
| Issuer and attester service auth | Separate AppRoles `platform-cp-rehearsal-issuer` and `platform-cp-rehearsal-attester`; response-wrapped, single-use bootstrap SecretIDs delivered through the provisioner only; `auth/approle` enabled explicitly | Adopted (design) |
| Issuer and attester runtimes | VMs `gate0-issuer-01` and `gate0-attester-01` on two different physical hosts (ruled 2026-10-02) | **Pending:** physical host selection and VM creation |
| Runner-to-OpenBao transport | The existing Observe WireGuard path | **Pending live proof:** accepted only after the route, the peer identity and the absence of any non-tunnel path are proven |
| OIDC token TTL (§ 3) | Five minutes, non-renewable, as the starting proposal | Unchanged: subject to provisioned-role validation; non-renewability is checked on the role, not inferred from a max TTL |

The fixed names in §§ 2, 3 and 11 (repository, workflow, Environment, runner
group, JWT role `rehearsal-issuer-protected`) are unchanged.

