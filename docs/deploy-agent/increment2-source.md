# Increment 2 staging source contract

This source implements the staging signer, host public-key registry, signed
report ingest, git evidence authority and rebuildable PostgreSQL projection.
It is **not accepted or activated**. Michael approved the bounded source-budget
amendment on 2026-10-21; source publication may proceed through normal review and
CI. The measured limits and retained acceptance gates are recorded in
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
