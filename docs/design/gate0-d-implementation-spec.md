# Gate-0 Work Packet D — protected rehearsal-issuer identity, custody and runner isolation

> **Status — proposed, awaiting Michael's acceptance, 2026-09-27.** This is
> not a new ADR; it implements ADR-0013 § A7 Work Packet D. **Provisioning:
> none performed.** No GitHub Environment, OpenBao role, OpenBao SSH CA, or
> signing key exists yet as a result of this document. Every value below
> marked `<placeholder>` is Michael's to choose at provisioning time.

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

A dedicated GitHub Environment, name `<placeholder: e.g. rehearsal-issuer-protected>`,
is created on this repository with:

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

Only the protected job (the one running inside the `<placeholder>`
Environment from § 2) exchanges its GitHub OIDC token for a short-lived,
narrowly scoped OpenBao token. No other job, and no job outside that
Environment, requests this exchange.

The OpenBao JWT auth role (`auth/jwt` backend, role name
`<placeholder: e.g. rehearsal-issuer-protected>`) sets `bound_audiences` to
the audience below and binds `bound_claims` on the rest. The audience is NOT a
`bound_claims` entry: OpenBao checks it through `bound_audiences`.

| Claim | Bound value | Why binding the Environment name alone is not enough |
| --- | --- | --- |
| `repository` | `<placeholder: org/repo>` | Scopes the role to this repository only. |
| `environment` | `<placeholder>` (the § 2 Environment name) | GitHub's environment-based `sub` claim can omit the branch entirely — an Environment-only bound claim would accept the same job running from a non-`main` ref if the Environment's own branch policy were ever misconfigured or bypassed by a different trigger. |
| `ref` | `refs/heads/main` | Independently pins the branch at the OpenBao layer, so OpenBao's own policy does not rely solely on GitHub's Environment configuration remaining correct. |
| `workflow_ref` | `<placeholder: org/repo/.github/workflows/<file>.yml@refs/heads/main>` | Pins the exact workflow file and ref of a normal (non-reusable) workflow, not just "some workflow in this repo." `job_workflow_ref` is bound instead ONLY if D deliberately runs the protected job as a reusable-workflow call; this spec does not. |

Audience (`bound_audiences`, not `bound_claims`): `<placeholder: e.g. https://openbao.dotmac.internal>`.
The protected job requests its OIDC token for exactly this audience.

`ref` is bound to `refs/heads/main` as its own claim, separately from
`environment`; neither substitutes for the other. The bound values are
checked against the ACTUAL claims of the protected job (captured from a real
run of that job, not assumed from documentation) before the role is accepted.

Token TTL: `<placeholder, short — e.g. 5m>`, no renewal. Policy scope: the
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
  - *Generation:* a fresh Ed25519 keypair is generated directly in OpenBao
    (or generated and immediately sealed into OpenBao) at
    `secret/dotmac/platform-cp/rehearsal-issuer/signing-key`, version 1.
    Michael performs this (§ 8).
  - *Rotation:* a new key VERSION is written to the same path, followed by
    the explicit reload the kernel's secret-source rules require — this is
    `refresh_secrets()`/an equivalent explicit re-install call, never a TTL
    or background poll (per CLAUDE.md, "Install secret material a product
    resolved itself": a failed refresh keeps the working set; a failing
    source raises rather than starting degraded). The rehearsal-issuer
    verifier must accept authorizations signed under either the retiring or
    the new version for a defined overlap window, `<placeholder>`.
  - *Revocation:* the key version is marked revoked in OpenBao's version
    metadata; any authorization signed under a revoked version is refused by
    the rehearsal issuer's verifier at consumption time (§ 7, "use after
    revocation").

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
- **Recommended:** rather than a long-lived key trusted by the target host,
  the controller requests a short-lived OpenBao-issued SSH certificate
  (`secret/ssh` engine, `<placeholder>` role) signed over the per-run public
  key, scoped to the target(s) named by `LANE3_PROBE_HOST` and the vantage
  variables in § 6. Reference:
  https://openbao.org/docs/secrets/ssh/signed-ssh-certificates/
- **Destruction:** both the private key and any issued certificate are
  deleted from the runner's filesystem at the end of the run, in the
  workflow's cleanup step, regardless of run outcome (success, refusal, or
  job failure) — the ephemeral OpenBao token from § 3 also naturally expires
  at its short TTL.

## 6. Runner isolation

A protected GitHub Environment (§ 2) gates which jobs may target it; it does
not, by itself, isolate the self-hosted runner (`control-runner-starter-mt`,
per § A7.5) from other workloads that runner might execute. This spec
therefore requires, independently of the Environment gate:

- Untrusted PR jobs never run on `control-runner-starter-mt` — no workflow
  triggered by `pull_request` (including `pull_request_target`) from a fork
  is permitted to select this runner's label/runner-group.
- The runner is restricted by label or runner-group (`<placeholder>`) to
  only the protected workflow(s) that use the § 2 Environment.
- The runner is cleaned between runs (workspace wipe) or is ephemeral
  (recreated per run), `<placeholder: which mode Michael selects>`.

Reference: GitHub Actions secure-use guidance —
https://docs.github.com/en/actions/reference/security/secure-use

## 7. Refusal tests

Each row names the planned test's intent; naming a test here does not create
it — these are written when D's workflow YAML and harness code exist.

| Missing/invalid condition | Enforced where | Expected refusal | Planned test |
| --- | --- | --- | --- |
| Wrong `ref` (not `refs/heads/main`) | OpenBao JWT role `bound_claims.ref` | OpenBao login denied, no token issued | `test_oidc_login_refuses_non_main_ref` |
| Wrong `workflow_ref` | OpenBao JWT role `bound_claims.workflow_ref` | OpenBao login denied | `test_oidc_login_refuses_wrong_workflow` |
| Wrong `environment` claim | OpenBao JWT role `bound_claims.environment` | OpenBao login denied | `test_oidc_login_refuses_wrong_environment` |
| Wrong or missing `aud` | OpenBao JWT role `bound_audiences` | OpenBao login denied | `test_oidc_login_refuses_wrong_audience` |
| Expired OIDC or OpenBao token | Token TTL enforcement, both layers | Login/token-use denied | `test_expired_token_is_refused` |
| Runner attempts a signer read | OpenBao policy attached to the runner's scoped token (§ 4) excludes the signer path | OpenBao permission denied | `test_runner_token_cannot_read_signer_path` |
| Missing human approval | `dotmac-approvals`' `approve_plan` / rehearsal issuer's `_standing_plan_terms` (fact 2, § 1) | No standing plan; issuance refused | `test_issuance_refuses_without_approval_evidence` |
| Reused controller key across runs | Per-run key-generation step (§ 5) plus fingerprint-freshness check in harness evidence validation | Harness evidence refused as stale/reused identity | `test_harness_evidence_refuses_reused_controller_key` |
| Fingerprint mismatch between evidence and lease | Rehearsal-issuer consumption check cross-referencing harness-evidence fingerprint against the lease record (§ A7.4) | Consumption refused | `test_consumption_refuses_fingerprint_mismatch` |
| Replayed consumption | `dotmac-deployment-control`'s existing single-use consumption logic | Second consumption refused | `test_consumption_refuses_replay` (extends existing single-use coverage per § A7.1's mechanism proof) |
| Use after revocation | Rehearsal-issuer verifier checking key-version revocation status (§ 4) | Verification refused | `test_verification_refuses_revoked_key_version` |

## 8. Who does what

Provisioning — Michael only; no agent performs any of these:

| Action | Owner |
| --- | --- |
| Create the § 2 GitHub Environment and configure the required reviewer + `main`-only branch policy | Michael |
| Create the OpenBao JWT auth role and its policies (§ 3, § 4) | Michael |
| Generate and store the Ed25519 signer at `secret/dotmac/platform-cp/rehearsal-issuer/signing-key` (§ 4) | Michael |
| Configure the OpenBao SSH CA / signing role for controller certificates (§ 5) | Michael |
| Set the repository variables — the observer user, the jump key reference, and the inside-vantage variable that `docs/inventories/lane3-acceptance-criteria.md` requires, alongside the existing `LANE3_PROBE_HOST` (§ A7.5) | Michael |

Agent-doable source work, once the above is accepted and provisioned:

- The workflow YAML implementing §§ 2–6 (Environment reference, OIDC step,
  OpenBao token exchange, per-run key generation and destruction, runner
  label/group restriction).
- The controller-fingerprint derivation code (§ 5).
- The startup signer install call site (`install_rehearsal_issuer_security`,
  § 4) wiring CP's process start to the OpenBao read.
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
into independently verified harness evidence. E performs no provisioning of
its own and consumes D's evidence as-is; D does not itself produce the
receipt or decide any pass/refusal outcome — that is E's job per § A7.7.
