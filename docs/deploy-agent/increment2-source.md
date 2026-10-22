# Increment 2 staging source contract

This source implements the staging signer, host public-key registry, signed
report ingest, git evidence authority and rebuildable PostgreSQL projection.
It has **no live acceptance or activation approval**. Michael approved the
complete bounded amendment and measured source shipping ceilings on 2026-10-22;
source publication may proceed through normal review and prescribed exact-head
CI. The approved limits and retained acceptance gates are recorded in
`increment2-acceptance.md`. Approval does not authorize live activation.
Focused offline proofs do not establish CP assembly, PostgreSQL migration,
GitHub/OpenBao access, environment approval, or any Gate-0 staging proof.

The new feature imports no existing `vendor_cp.deployment` seam and owns no
fleet desired-state tables. Its two tables contain retained evidence and a
public-identity projection. Production profiles withhold its routes; `full`
explicitly inventories them and advances its surface version.

## Corrected signed transition and bootstrap

The desired exact schema adds required `from_image_digest`. The canonical plan
projects the fields in `contracts.PLAN_FIELDS`, including that baseline. Every
host can rederive the approved digest from signed bytes. CP obtains its baseline
from accepted healthy reports, ordered by desired issuance in git, never by host
clock or report arrival. A delayed older report remains evidence and cannot
regress baseline or drift. Key rotation cannot overwrite accepted applied state.

A host without an accepted report bootstraps through the existing key-activation
route. A distinct `dotmac.deploy_host_possession/1` payload and Ed25519 domain
bind every stored challenge field plus the host-observed image digest. The host
helper checks independently configured key and deployment identity before
signing. CP requires the pending unexpired matching challenge and the admin's
out-of-band approved public-key fingerprint. This observation establishes a
baseline; it asserts no apply, health or staging acceptance. Missing baseline
refuses issuance.

## API and custody

All admin routes use the kernel's bearer `require_platform_admin` owner.
Authenticated `PlatformAdmin.id` binds command idempotency, key events and
projection audit. Supplied `approvals[].actor` is upstream evidence and never
substitutes for that principal. Public GET returns signed envelopes with
`Cache-Control: no-store`; public ingest authenticates the host's signature.

* `POST /platform/deploy/desired-state`: `{command_id, desired,
  approved_plan_digest}`. `desired` contains exactly the unsigned fields.
  `{mode:"preview",desired}` on that same route returns `{plan,plan_digest}`;
  preview omits `from_image_digest`, which CP derives. No signature is issued.
* `POST /platform/deploy/host-keys`: register `{key_id,deployment_ref,
  public_key_b64}` or revoke `{operation:"revoke",key_id}`.
* `POST /platform/deploy/host-keys/{key_id}/challenge` returns the challenge.
* `POST /platform/deploy/host-keys/challenge-response` accepts `{envelope,
  approved_public_key_fingerprint}`.
* `POST /platform/deploy/applied-state` accepts canonical envelope bytes and
  returns `{verdict:"accepted"}`, `idempotent_replay`, or `quarantined:<code>`.
  Same report id with different bytes and unknown desired evidence quarantine.
* `GET /platform/deploy/drift` is admin-only.

Enablement is explicit: `VENDOR_DEPLOY_AGENT_ENABLED=true`. Startup requires
`VENDOR_DESIRED_SIGNING_KEY_ID`, `VENDOR_DESIRED_SIGNING_KEY_FILE`,
`VENDOR_DESIRED_SIGNING_KEY_POINTER` equal to
`secret/dotmac/platform-cp/desired-state/signing-key`,
`VENDOR_DEPLOY_LEDGER_DIR`, `VENDOR_DEPLOY_GH_EXECUTABLE` (absolute path), and
`VENDOR_DEPLOY_GH_SHA256`. The signer file is read once, must be a regular
service-owned 0600 file, and cannot be a symlink. No ephemeral fallback exists.
The configured gh binary is checksum pinned. Its existing authentication is
owned by CP deployment tooling; this feature never reads or prints credentials.

Before signing, the real reader verifies both build/evidence GitHub runs against
fixed repository/workflow, successful completed `workflow_dispatch` on `main`,
exact run ids and revision, and same-repository head identity. It downloads the
fixed evidence artifact into a private temporary directory, checks its exact
schema and six plan facts, and uses the public kernel manifest parser to verify
canonical manifest bytes and digest. Reader failure refuses issuance.

## Evidence transactions and operational recovery

A process mutex and filesystem flock serialize whole git transactions. Existing
paths cannot change; modified/deleted history, dirty worktrees and remote
movement refuse. Desired envelope and command receipt share one commit. Push
must succeed before serving. Accepted host envelopes retain their exact canonical
bytes. Registry changes are separate immutable git events under `keys/`.

The DB receipt and kernel audit are written in one projection transaction after
git commit. A crash in between leaves git authoritative. The installed command
`dotmac-platform admin deploy-ledger-rebuild` verifies signatures, possession,
immutable key identity, public-key uniqueness, state transitions, nonce joins and
success observations before replay. Projection comparison checks stored envelope
hashes and all indexed fields, refuses divergent retained rows, and repairs
missing receipts/current registry. No SQLite parity claim is made.

A failed git push retains the local commit. If the remote did not accept it,
subsequent service reads and writes refuse `ledger_conflict`. If the remote
accepted it but the acknowledgement was lost, the failed command returns no
signed envelope; a later successful fetch must confirm equal tips before any
service read can serve it. An unavailable fetch refuses rather than trusting a
local tracking reference.

**Recovery owner: Michael and the CP deployment owner.** The bounded manual
procedure is:

1. Stop CP and preserve both histories. Acquire the existing
   `.git/deploy-agent.lock` exclusively so another writer cannot enter recovery.
2. Fetch the configured `origin`, record local `HEAD` and `origin/main`, and
   check `git merge-base --is-ancestor origin/main HEAD`. If that fails, retain
   the hold and both histories for reviewed reconciliation. Unknown remote data
   is never reset, removed or force-pushed over.
3. Validate the retained history's signatures and semantic identity/nonce/state
   rules against the pinned public keyrings, and confirm the remote's required
   branch-protection evidence. The source owner is
   `DeployAgentService.validate_history`; the fixture invokes it while the
   service is stopped. This change adds no installed recovery command. The
   deployment owner must provide a reviewed invocation for the live ceremony;
   `deploy-ledger-rebuild` itself refuses while the remote differs.
4. Retry only the ordinary `git push origin HEAD`, fetch again, and require
   exact equality of local `HEAD` and `origin/main` before restarting CP. Retry
   the original command id with the original authenticated admin: the retained
   command returns the identical envelope and repairs missing DB projection.

`tests/deploy_agent/test_ledger_recovery.py` exercises this sequence against a
local bare Git remote using real signed history: rejection before acceptance,
remote acceptance with lost acknowledgement, and an independently advanced
remote that must preserve the hold. It proves the ordinary retry adds no new
commit or rewritten evidence. It does not establish live branch protection,
credential availability, PostgreSQL projection correctness or staging acceptance.

Public verifier key rotation/history and production endpoint publication still
need deployment-specific configuration and evidence; this source makes no claim
that those live obligations are discharged.

## Gate0 machine-evidence admission

`POST /platform/deploy/gate-evidence` is the sole additional adapter. It uses the
existing kernel platform bearer guard and `GateEvidence` closed public types;
`actor_admin_id` is never accepted in the payload. The authenticated admin is
attributed in the immutable command record and existing projection audit.
`gate_admission` owns campaign authorization and evidence joins; the router
only validates and delegates. This adds no CLI authentication, deployment
executor, database, signer authority, or human signoff.

The optional `VENDOR_DEPLOY_GATE_SCOPE_FILE` names a public, regular, root-owned
file beneath canonical root-owned non-writable parent directories. Symlinks and
group/other writable files or parents refuse. The service retains its validated
canonical bytes for the process lifetime; changing a file requires an explicit
configuration/restart ceremony outside this source task. Absent configuration
keeps evidence admission disabled while preserving the existing deploy API.
`CampaignScope` is the closed configuration type: it binds the complete
`GateContext`, allowed authenticated admin UUIDs, enrolled host public-key hash,
selected complete candidate plans, the observation window, exact proof1 run and
artifact identities, exact restore source/test host and bundle/capture/inventory
hashes, the prepared-source artifact digest, the exact egress DNS/probe target,
and the required prior-run evidence digest for a next-morning campaign.
The configured observation window is at most 24 hours. This file contains public
evidence and approval references, never bearer credentials or private keys.

The owner resolves exact desired/applied/quarantine bytes from derived ledger
paths, verifies signed history and host enrollment, and binds nonce, candidate,
report classification, original submitted fixture bytes, receipt digest and
commit contents. Newly signed refusal/transition reports must belong to both
the campaign window and the actual before/after observation interval. The
original terminal receipt remains intentionally historical only for nonce replay. The same genuine applied transition must serve proofs3/4.
Independent host observations remain claims attributed to the authenticated
submitter; CP does not claim it executed those probes. DNS evidence must include
real kernel expiry bounded by the observed A/AAAA TTL, and a bounded independent
observation that all old A and AAAA destinations disappeared, rather than
merely adding different addresses. Restore evidence must bind the
protected controlled capture and source inventory, with successful cleanup.

Evidence and actor-bound command records share the existing serialized
`append_many`/push transaction under `gate0/<date>/<run>/evidence.json` and
`gate0/commands/<command>.json`. Gate0 history has the same append-only rewrite
protection as deployment evidence, including renames and file-type changes. Directory traversal and creation use
pinned no-follow descriptors; symlink ancestors refuse before any leaf write.
The receipt contains exact evidence and its digest plus its original addition
commit. A second identical authenticated POST performs authoritative readback
and returns that identical receipt, even after unrelated appends or expiry.
Changed bytes or actor under one command, or another command under one run,
refuse. A valid terminal failure can retain only the performed proof outcomes,
with a bounded failure code and no invented observations. Missing payload is
permitted only for the early `evidence_missing` or `transport_failed` stage;
all supplied signed references remain fully verified. An attempted restore
exception may retain null restored-inventory, source-parity and scratch-absence
observations; these can never satisfy PASS. Receipts explicitly carry
`verdict:PASS|FAIL`; publishing a FAIL receipt never creates Gate PASS. The
proof client must verify the identical second-POST readback before terminating
with that verdict. Push failure returns no published receipt and preserves the existing
manual non-force recovery hold. Machine evidence never supplies Michael signoff.

The 2026-10-22 measured source shipping approval permits this reviewed bounded
source through normal publication and prescribed CI within the approved ceilings.
The reviewed measurement packet and approval are referenced in
`increment2-acceptance.md`; this grants no activation, host changes or production
acceptance. Governed JWT apply, human custody, approved public fingerprints and
explicit activation approval remain required. Focused offline Git/crypto
and isolated-router tests use the available kernel a97 environment; pinned a100
assembly and migrated PostgreSQL checks remain hosted-CI gates.

The current forward transition must match the campaign's exact target revision
and tree, including a failed attempted transition with supplied signed evidence.
A successful next-morning run binds the exact published initial PASS but uses a
new revision, tree, desired nonce and target digest; its before image must equal
the initial accepted after image. Deployment, enrolled host and tool revision
remain fixed across that relationship. An unperformed transition in a truthful
partial failure does not invent a new candidate or host observation.

No additional descriptor promotion or prospective manifest regeneration is
required for this adapter: `scripts/generate_product_manifest.py:build_manifest`
records module identities, versions, planes and web enablement, all unchanged
here. `tests/architecture/test_product_manifest.py` checks those generated bytes;
`test_descriptor_promotion.py` preserves the existing immutable candidate. The
full deployment profile advances to version7; production profiles still withhold
the existing deploy_agent feature. The separate embedded profile is generated by
`deployment/profile.py:build_profile_document` from the exact source and built
wheel during image CI. These source observations do not establish architecture
checks, pinned-kernel assembly or image acceptance. Mandatory metadata remains
233 counted lines, with its existing file hashes unchanged.

Full PASS binds proof2 nonce replay to the same run's exact applied transition
nonce, report UUID and report digest shared by proofs3/4. Replay observations
follow the completed transition and remain inside the signed desired validity
window; expiration is exclusive. The producer runs forward3/4, then replay, then
the refusal fixtures from the post-forward baseline. An older prior-run receipt
cannot substitute for the current transition. Public evidence types are unchanged.
The finite refusal fixtures may leave the latest desired/report refused and
`drift=true`, while the last healthy applied baseline remains the accepted target.
Normal polling restoration and admitted proof evidence do not advance human
signoff or production authorization; the live packet reads back that final state.
