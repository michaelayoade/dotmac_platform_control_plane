# Increment 2 staging source contract

This source implements the staging signer, host public-key registry, signed
report ingest, git evidence authority and rebuildable PostgreSQL projection.
`increment2-acceptance.md` records Michael's 2026-10-22 amendment and 2026-10-24
shipping approval, measurements and gates. Review/exact-head CI remain required;
**source approval grants no live activation or acceptance**. Offline proofs cannot
establish pinned assembly, PostgreSQL migration, GitHub/OpenBao access, environment
approval or staging. Governed JWT apply, custody, approved public fingerprints and
explicit activation approval remain required.

The feature imports no `vendor_cp.deployment` seam or fleet desired-state owner.
Its two tables retain evidence and public-identity projections. `full` inventories
its routes at version7; existing production profiles withhold them except the
explicit keyless selection below.

## Signed transition, bootstrap and API custody

`contracts.PLAN_FIELDS` projects the required `from_image_digest` into the
canonical plan, allowing hosts to rederive the approved digest from signed bytes.
CP derives that baseline from healthy accepted reports in desired-issuance Git
order, never host clock or arrival order. Delayed reports remain evidence without
regressing baseline or drift; key rotation cannot overwrite accepted applied state.
A missing baseline refuses issuance.

Bootstrap uses the existing key-activation route. The distinct Ed25519 domain
and `dotmac.deploy_host_possession/1` payload bind every challenge field and the
host-observed image digest. The host helper checks its independently configured
key/deployment identity. CP checks the pending, unexpired matching challenge and
the admin's out-of-band approved public-key fingerprint. This establishes only
a baseline, without asserting apply, health or staging acceptance.

All admin routes use kernel bearer `require_platform_admin`; `PlatformAdmin.id`
binds idempotency, key events and projection audit. Upstream `approvals[].actor`
never substitutes for that principal. Public GET serves signed envelopes with
`Cache-Control: no-store`; public ingest authenticates host signatures.

* `POST /platform/deploy/desired-state`: `{command_id, desired,
  approved_plan_digest}`, with exactly unsigned fields in `desired`.
  `{mode:"preview",desired}` returns unsigned `{plan,plan_digest}` and omits
  `from_image_digest`, which CP derives.
* `POST /platform/deploy/host-keys`: register `{key_id,deployment_ref,
  public_key_b64}` or revoke `{operation:"revoke",key_id}`.
* `POST /platform/deploy/host-keys/{key_id}/challenge` returns the challenge.
* `POST /platform/deploy/host-keys/challenge-response`: `{envelope,
  approved_public_key_fingerprint}`.
* `POST /platform/deploy/applied-state` accepts canonical envelope bytes, returning
  `{verdict:"accepted"}`, `idempotent_replay` or `quarantined:<code>`; conflicting
  bytes under one report id and unknown desired evidence quarantine.
* `GET /platform/deploy/drift` is admin-only.

Mandatory inputs/mounts appear below. The signer reads a service-owned regular
0600 file once; symlinks/ephemeral fallback refuse. CP tooling owns authentication;
the feature never reads/prints credentials. Signing requires both completed,
successful `workflow_dispatch` runs on `main`, fixed repository/workflow, exact
run ids/revision and same-repository head. The reader privately downloads the
fixed artifact and verifies exact schema, six plan facts and canonical manifest
bytes/digest through the public kernel parser; failure refuses issuance.

## Evidence transactions and operational recovery

Mutex/flock serialize Git transactions; dirty worktrees, remote movement and
modified/deleted paths refuse. Desired envelope/receipt share one pushed commit;
host bytes stay canonical and immutable key events live under `keys/`. Git remains
authoritative across crashes before the atomic DB receipt/kernel-audit projection.
`dotmac-platform admin deploy-ledger-rebuild` verifies signatures, possession,
immutable/unique keys, transitions, nonce joins and success observations, compares
all hashes/indexed fields, refuses divergence and repairs missing receipts/registry.

Failed push retains the local commit and returns no signed envelope. Subsequent
reads/writes refuse `ledger_conflict` unless a successful fetch confirms equal
tips, including when the remote accepted a push whose acknowledgement was lost.
An unavailable fetch never trusts the local tracking ref.
**Recovery owner: Michael and the CP deployment owner.**

1. Stop CP, preserve both histories and exclusively acquire `.git/deploy-agent.lock`.
2. Fetch `origin`, record `HEAD`/`origin/main`, and require
   `git merge-base --is-ancestor origin/main HEAD`; otherwise retain the hold for
   reviewed reconciliation. Never reset, delete or force-push unknown remote data.
3. Validate retained signatures and identity/nonce/state semantics against pinned
   public keyrings, and confirm required branch protection. The stopped-service
   fixture uses `DeployAgentService.validate_history`; the deployment owner owes
   a reviewed live invocation. No installed recovery command is added;
   `deploy-ledger-rebuild` refuses while remote and local differ.
4. Retry only `git push origin HEAD`, fetch and require equal tips before restart.
   Retry the original command id as the original authenticated admin to return the
   identical envelope and repair missing DB projection.

`tests/deploy_agent/test_ledger_recovery.py` uses real signed local-bare-remote
history for rejected push, accepted push/lost acknowledgement and independently
advanced remote. Ordinary retry adds no commit or rewritten evidence. Live branch
protection, credentials, PostgreSQL projection, public verifier rotation/history
and production endpoint publication remain deployment-specific obligations.

## Gate0 machine-evidence admission

`POST /platform/deploy/gate-evidence` uses kernel bearer auth and closed
`GateEvidence` types; payload `actor_admin_id` is forbidden. The immutable command
and projection audit attribute the authenticated admin. `gate_admission` owns
campaign authorization/joins; the router validates and delegates. It adds no CLI
auth, deployment executor, database, signer authority or human signoff.

Optional `VENDOR_DEPLOY_GATE_SCOPE_FILE` requires a public regular root-owned file
under canonical root-owned non-writable parents; symlinks and group/other writable
files/parents refuse. Validated canonical bytes last for the process lifetime;
change requires an external configuration/restart ceremony. Absent scope disables
admission while preserving the deploy API. Closed `CampaignScope` binds complete
`GateContext`, allowed admin UUIDs, enrolled host public-key hash, complete selected
plans, observation window (at most 24h), exact proof1 run/artifacts, restore source/
test host and bundle/capture/inventory hashes, prepared-source artifact digest,
egress DNS/probe target and prior-run digest for same-session repeatability.
Scope contains public evidence/approval references, never credentials/private keys.

Admission resolves exact desired/applied/quarantine ledger bytes, verifies history
and enrollment, and binds nonce, candidate, report classification, original fixture
bytes, receipt digest and commit contents. Newly signed refusal/transition reports
must satisfy campaign and actual observation intervals; only nonce replay retains
an intentionally historical terminal receipt. Proofs3/4 share one genuine applied
transition. Host observations are submitter-attributed claims, not CP execution.
DNS proofs require kernel expiry bounded by observed A/AAAA TTL and independently
bounded disappearance of every old A/AAAA destination. Restore binds protected
controlled capture/source inventory and successful cleanup.

Evidence and actor-bound commands share serialized `append_many`/push under
`gate0/<date>/<run>/evidence.json` and `gate0/commands/<command>.json`. Append-only
history rejects renames/type changes; pinned no-follow traversal/creation refuses
symlink ancestors before writes. Receipts bind exact evidence, digest and original
addition commit. An identical authenticated second POST returns the same receipt,
even after expiry/unrelated appends. Changed bytes/actor under one command, or a
second command for one run, refuse. Terminal FAIL retains only performed outcomes
with bounded failure codes. Missing payload is allowed only for early
`evidence_missing`/`transport_failed`; supplied signed references remain verified.
Attempted restore exceptions may retain null restored-inventory/source-parity/
scratch-absence, never PASS. Receipts declare `verdict:PASS|FAIL`; FAIL cannot grant
Gate PASS. The proof client verifies identical second-POST readback before exit.
Push failure publishes no receipt and retains the manual non-force recovery hold.
Machine evidence never supplies Michael signoff.

Forward transitions, including failed attempts carrying signed evidence, must
match campaign revision/tree. Repeatability binds the published initial PASS but
uses new revision/tree/nonce/target digest; its before image equals the initial
after image. Deployment, enrolled host and tool revision stay fixed. Partial
failure invents no unperformed candidate or host observation.
Full PASS binds proof2 replay to the same proofs3/4 nonce, report UUID and digest.
Replay follows forward3/4 within the signed validity window (exclusive expiry),
then refusal fixtures run from the post-forward baseline. Older receipts cannot
substitute. Public evidence types are unchanged. Fixtures may leave latest desired/
report refused and `drift=true`; the healthy baseline remains the accepted target.
The live packet reads that final state; polling restoration grants no signoff.

Same-session `repeatability` after initial PASS retains immutable joins and image
continuity. Proofs2–4 repeat bad signature, signed rollback and same-run replay
across daemon stop/start, proved by distinct validated InvocationIDs/fresh matching
journals; nonce bytes/original report survive. Nonce/outbox/ledger resets, rotation,
reinstall and test-hook residue are forbidden; enrollment hashes/cleanup stay exact.
`next_morning` is retained only for immutable historical decoding: `validate` and
`scope_bytes` reject it except through ledger readers' explicit history-only flag.
Original bytes preserve historical fingerprints/hashes and the original calendar
rule; future API admission/scope loading remain strict.

`scripts/generate_product_manifest.py:build_manifest` retains module identities,
versions, planes/web enablement; no promotion/regeneration is needed, checked by
`test_product_manifest.py`/`test_descriptor_promotion.py`. Image CI generates the
separate embedded profile from exact source/wheel through
`deployment/profile.py:build_profile_document`. Frozen metadata remains 233 lines;
keyless adds 30 CP wiring lines. Offline Git/crypto/router proofs used a different
kernel; pinned assembly, migrated PostgreSQL and image acceptance remain CI gates.

## Opt-in keyless production profile

`production-keyless-v1` version1 adds `deploy_agent` to `production-bootstrap` v6's
seven surfaces, preserving accounts, contracts, vendor approvals, allocations,
console, withdrawal conflicts and readiness. It withholds `deployment_control`,
`licence_delivery`, `offers` and the provisioning laboratory. Other profile
versions/inventories are unchanged; production acceptance selects surfaces only.

The existing adapter defaults to `production-bootstrap`; explicit
`EXPECTED_DEPLOYMENT_PROFILE=production-keyless-v1` requires exactly one canonical
matching `VENDOR_DEPLOYMENT_PROFILE` assignment. Missing, duplicate, alternate,
colon, bare-key or mismatched assignments refuse before containers/DB work.
Its validated `ENV_FILE` becomes absolute `VENDOR_CP_RUNTIME_ENV_FILE` for app,
relay and ops even across Compose directories; manual Compose defaults to `.env`.
Only bootstrap/keyless are permitted, never `full`; enablement remains separate.

### Runtime configuration through the existing CP owner

For a separately authorized keyless deployment, select
`COMPOSE_OVERRIDE_FILE=docker-compose.keyless.yml`. The existing adapter adds an
optional second `-f` after `COMPOSE_FILE`; absent/empty preserves the single-file
and validated-env defaults. Assembly owns profiles; no executor/behavior branch
is added. Only app receives `VENDOR_DEPLOY_AGENT_ENABLED=true`; omit it from the
shared environment so relay/ops stay disabled and migrate without signer/GitHub.
Base read-only root filesystems, dropped capabilities and restrictions remain.
No host binary is mounted: the image supplies `/usr/local/bin/gh`, configured as
`VENDOR_DEPLOY_GH_EXECUTABLE` with `VENDOR_DEPLOY_GH_SHA256` equal to
`sha256:a95a4e011d77e9cd0e9922c13fda2b95195c6be29dfa58207075fd983bbae744`.

The deployment owner must provision these inputs before selecting the overlay:

| Public configuration | Protected host source and container use |
| --- | --- |
| `VENDOR_DESIRED_SIGNING_KEY_ID` | Required public identity of the independently provisioned desired-state key. |
| Fixed desired-state key source | `/run/secrets/dotmac/platform-cp/desired-state/primary.key`, mounted at the same path read-only, the fixed `VENDOR_DESIRED_SIGNING_KEY_FILE`. `VENDOR_DESIRED_SIGNING_KEY_POINTER` is `secret/dotmac/platform-cp/desired-state/signing-key`. Never reuse the licence or D16 key. |
| `VENDOR_DEPLOY_CP_LEDGER_HOST_DIR` | Required existing checkout, mounted read-write at `/var/lib/dotmac-deploy/ledger`, the fixed `VENDOR_DEPLOY_LEDGER_DIR`; the only writable overlay mount. |
| `VENDOR_DEPLOY_CP_GATE_SCOPE_HOST_FILE` | Required protected public scope, mounted read-only at `/etc/dotmac-deploy/gate-scope.json`, the fixed `VENDOR_DEPLOY_GATE_SCOPE_FILE`. |
| `VENDOR_DEPLOY_CP_GITHUB_AUTH_HOST_DIR` | Required protected auth directory, mounted read-only at `/run/secrets/dotmac/platform-cp/github`, the fixed `GH_CONFIG_DIR`. |
| `VENDOR_DEPLOY_CP_GIT_CONFIG_HOST_FILE` | Required protected public Git configuration, mounted read-only at `/etc/dotmac-deploy/gitconfig`, the fixed `GIT_CONFIG_GLOBAL`; existing gh credential helper, no embedded credentials. |

All added binds set `bind.create_host_path=false`; required public inputs use `:?`
to refuse missing/empty values. Key checks remain service-owned regular 0600;
ledger must be service-writable, and scope/parents must satisfy the loader's
ownership/protection/canonical-byte checks. Auth must be service-readable and
preprovisioned. No token enters env/argv; `GIT_TERMINAL_PROMPT=0` and
`GH_PROMPT_DISABLED=1` prohibit interactive fallback.
CP deployment tooling owns auth, public helper configuration and checkout.
Its `origin` must be `https://github.com/michaelayoade/dotmac-deploy-ledger.git`
on `main`, with service author configuration and history-rewrite protection.
The overlay neither clones, configures nor attests it. Fresh deployment-owner
validation must prove protection, exact checkout, read/write auth and helper
operation; this source wiring generates/reads no secret material.

Offline architecture tests check YAML, mounts, restrictions and fake-docker shell
composition. Strict missing-input interpolation/merged Compose rendering, image
acceptance, provisioning, startup and authenticated GitHub/ledger operation remain
hosted CI or separately authorized live proofs. Host identity is unchanged;
`PLATFORM_ROOT_DOMAIN`/`TRUSTED_HOSTS` require `platform.dotmac.io`. Candidate inputs
permit bootstrap/keyless with assembly admission; TLS, ingress and immutable-image
adoption need separate evidence. Mandatory metadata remains 233 counted lines;
profile/guard count as CP runtime/wiring. Approved ceilings: 23,000 overall, 9,900
required tests, 3,100 CP, 4,200 proof, 350 CI; other limits remain unchanged.

### Ledger GitHub App credential provisioning

The owner-only `dotmac-deployment-ledger` App (5448762, installation 174650996)
is restricted to `michaelayoade/dotmac-deploy-ledger` (1431613388), Contents write/
Metadata read. Its root-only key `/etc/dotmac/platform-cp/github-app/private-key.pem`
is outside app mounts. Installed `admin github-auth-renew` delegates issuance to
the credential owner under the production deploy lock, requesting only that scope,
validating scope/expiry and atomically replacing auth-directory `hosts.yml`.
The app reads the directory and never receives the App private key.
The checked-in service/twenty-minute timer require a root-owned installed operator
wheel at `/opt/dotmac/vendor-control-plane/operator`, protected auth ancestry and
successful manual issuance before activation. `cp-github.gitconfig` contains only
the noninteractive gh helper. Failed renewal retains the previous file; expiry
closes access. Public lease receipts expose no token. Issuance, restart/renewal,
protected-main append and Sub candidate reads still need live proof. These inputs
neither install the timer nor enable the app.
