# OpenBao transit custody for the a2 Control V2 identities (Gate 2, E6)

Status: SPECIFICATION AND OPERATOR TOOLING ONLY. Nothing here contacts OpenBao from CI
production paths, creates a key, mount, policy or token, or stores a credential. The
adapter is `src/vendor_cp/deployment/transit_custody.py`; the commands are in
`materials_producer`. Design: the architect's E6 transit and RLS packet; rulings:
Michael, 2026-11-15.

## Rulings this implements

- Custody is OpenBao TRANSIT. The authorization and dispatch private halves are generated
  inside transit (`type=ed25519`, `exportable=false`, `allow_plaintext_backup=false`,
  `derived=false`, never rotated) and never leave it. Supersedes mint-dossier step 1 for
  these two a2 identities only.
- The identities are for a2 only and are retired after a2 is published or disposed (the
  mount is disabled, which destroys the keys). D3 production identities are designed then.
- The G17 JWT role gates only the launcher principal. No JWT code is in CP, and that role
  must never carry the sign policy.
- Michael mints each transit token from the ceremony root and passes it on stdin.
- The route is a relay that exists only during Michael's SSH session.

## Keys and pinned identities

Dedicated mount (for example `transit-platform-cp-a2`) holding exactly two keys:
`cp-a2-deployment-authorization-v1` and `cp-a2-deployment-dispatch-v1`. CP key ids
`platform-cp-a2-authorization-v1` and `platform-cp-a2-dispatch-v1`. Version 1 for the
identity's whole life: the adapter always sends `key_version = 1` and accepts only the
`vault:v1:` prefix.

Pinning (the ceremony; nothing contacts OpenBao):

1. The ceremony reads `GET <mount>/keys/<name>` and pipes the JSON to
   `python -m vendor_cp.deployment.transit_custody identity --purpose P --key-id K`. It
   refuses anything but a non-exportable, never-rotated ed25519 key at version 1, and
   prints the closed `PlatformCpPublicVerificationIdentity.v1` document with the
   fingerprint derived by Control's own `PublicKeyFingerprintV1`.
2. Proof of possession: `transit_custody pop-challenge --purpose P` prints a
   domain-separated challenge (`dotmac.platform-cp.transit-pop.v1\0 purpose \0 nonce`; it
   starts with a non-JSON prefix, so it can never parse as a Control envelope). The admin
   signs it through transit; `transit_custody pop-verify --identity FILE --purpose P
   --nonce-hex H` (signature on stdin) checks it against the document. This proves the
   pinned key is the one transit signs with, as pure Ed25519.
3. The document is installed root-owned (mode 0644; the parent directory root-owned and not
   group/other-writable) on the CP host and on each E10 target.

## Signing

`materials_producer issue --custody transit --custody-config FILE` is the only way to issue;
there is no other mode and no default. The configuration is a closed document with no
defaults (`transit_custody print-schema`): mount, the two key names (distinct; the licensing
key and any `secret/` path are refused), `key_version: 1`, the two identity paths, the relay
socket. The adapter:

- reads ONE token from stdin (refused on a TTY, over 512 bytes, or oddly shaped); it is
  never in argv, the environment, a file, a repr, a log line or an exception text;
- talks to a unix socket only (no network client, no proxy, no redirect);
- posts exactly `{input, key_version}`: never `batch_input`, `context`, `prehashed` or an
  algorithm, and refuses a response that carries `batch_results`;
- makes at most two sign calls (authorization, then dispatch), matching a use-limit-2 token;
- parses the response strictly: duplicate JSON keys refused, 16 KiB cap, `data.signature`
  must be `vault:v1:` plus standard base64 that re-encodes identically and is exactly 64
  bytes, `data.key_version` (if present) must be 1;
- hands the raw bytes to `materials_producer`, which converts them to unpadded base64url
  and verifies them against the PINNED public identity before Control sees them. A wrong
  key, swapped keys, a rotated version or garbage all refuse (`custody_not_configured`)
  before anything is persisted as signed.

The pinned-identity check proves which key signed, not what it signed: a sign token is a
signing oracle for its two uses. Bounds: two uses, batch refused by policy, 15 minutes at
most, bound CIDR, a child of the ceremony root, human-attended, and a relay that allowlists
the two sign paths.

## Policy (rendered, never applied here)

`python -m vendor_cp.deployment.transit_custody policy --config FILE` prints it. Exact paths
only; `allowed_parameters` is load-bearing because without it one use could return many
signatures:

```hcl
path "<mount>/sign/<authorization key>" {
  capabilities       = ["update"]
  allowed_parameters = { "input" = [], "key_version" = [] }
}
path "<mount>/sign/<dispatch key>" {
  capabilities       = ["update"]
  allowed_parameters = { "input" = [], "key_version" = [] }
}
```

Token role: the image renders the exact `auth/token/roles/<name>` body, so it is not
hand-authored:

    python -m vendor_cp.deployment.transit_custody role --policy NAME --bound-cidr CIDR

`--bound-cidr` is required (the relay's source address as OpenBao sees it, a typed
parameter entered at ship time; there is no default). It must be a SINGLE address (/32 or
/128): any range, an unspecified network or a malformed value is refused. The body is `allowed_policies` the one policy, `token_no_default_policy
= true` (the default policy would add self-lookup, renew, cubbyhole and wrapping),
`renewable = false`, `token_type = service`, `token_num_uses = 2`,
`token_explicit_max_ttl` of 600 s (the hard ten minute cap; a token role has no default-ttl field), `orphan = false` (a child of the minting token, so
revoking the ceremony root revokes it even if everything else fails), and the bound CIDR.
Its output is pinned by a test, as the policy is. After writing it, the ceremony reads it back
and checks it against the render; any drift is named and exits non-zero. The read-back also
requires the fields that can only widen a token to be empty or zero (`allowed_policies_glob`,
`disallowed_policies`, `disallowed_policies_glob`, `allowed_entity_aliases`, `path_suffix`,
`token_period`, and the legacy `bound_cidrs`, `explicit_max_ttl` and `period`), and names any
field outside OpenBao 2.5.3's token-role read list, because a role update keeps fields it
does not send. Create the role fresh, and before minting a token confirm with
`bao token lookup -accessor` that it came through the role (the role's policy only, 2 uses,
ttl at most 600 s, not renewable, the bound address):

    bao read -format=json auth/token/roles/NAME | \
        python -m vendor_cp.deployment.transit_custody role-readback --policy NAME --bound-cidr CIDR

One 2-use token per issuance, minted from the ceremony root and revoked by accessor with a
lookup that must then fail. Note that the bound CIDR is the shared bridge source, so it
admits any host-local OpenBao client; it narrows, it does not authenticate.

## Route

HARD PRECONDITION for the issuance session (not built in the image): the relay is the
allowlisting forwarder of the ceremony kit, never a plain `ssh -R` pass-through. Without it
the CP host reaches the whole OpenBao HTTP API, including unauthenticated
`sys/generate-root` and `sys/rekey` endpoints, during the session that runs generate-root.
The pg_hba line (per role, this database, the target address only) and the firewall path to
the production database are host-side ceremony items, read back at E10a/E11.

A relay bounded to Michael's SSH session: his usual `ssh -L` to OpenBao plus an `ssh -R`
unix socket on the CP host (root 0700 directory, mask 0177), bind-mounted into the one-shot
issuing container, which has a route only to the CP database. A small forwarder on the
workstation passes only `POST` to the two sign paths. No firewall or WireGuard change; the
socket's absence is read back after the session.

## Operator commands (names and ids only)

    materials_producer propose        # a plan, from the existing library
    materials_producer open-approval  # an Approvals request
    materials_producer approve        # after a real Approvals decision
    <token> | materials_producer issue --custody transit --custody-config FILE ...

The authorization expiry may not exceed the 4 hour role window.

## Residuals

- S1. "Never leaves" holds at the API. An OpenBao root can still set `exportable = true`
  (irreversible) or extract keys from storage. That trust is inherent; the audit device
  records config writes and retiring the mount removes the risk afterwards.
- S2. A sign token is a signing oracle for its two uses (above).
- S3. While the session is open the CP host can reach the OpenBao HTTP API through the
  socket; the allowlisting relay cuts it to the two sign paths.
- Starter ADR-0009 needs an amendment ("remote non-exportable signing custody is not
  dereferencing"). That is a Starter docs PR, deliberately not part of this change.

## Source-only dispatch recovery

The separately named policy and token role are both `cp-a2-recovery-dispatch`.
They are rendered, never applied here:

```sh
python -m vendor_cp.deployment.transit_custody recovery-policy --config FILE
python -m vendor_cp.deployment.transit_custody recovery-role --bound-cidr CIDR
python -m vendor_cp.deployment.transit_custody recovery-role-readback --bound-cidr CIDR
```

Recovery permits update on the configured dispatch key only. The policy requires
`input` and `key_version`, restricts the latter to 1, and allows no other
parameters. The fixed role has one use and retains the normal non-orphan,
nonrenewable service, no-default-policy, single measured source address and
600-second maximum limits. The recovery custody builder refuses authorization
and a second dispatch call; its client burns its single use before upstream I/O.
The normal two-use renderer, role and builder retain their behavior.

The existing materials producer exposes `recover-dispatch --recovery-request
FILE --recovery-request-sha256 SHA256 --out-dir DIR --custody transit --custody-config FILE`. The token uses the
existing stdin transport. FILE is a bounded strict JSON projection with exactly
`original_request`, `resume_expectation`, `session_id`, `not_before`, `deadline`.
The original request carries exactly the `IssueDispatchRequest` fields; its
plan UUID and expiry are strings. The expectation uses Control's public mapping
contract and includes the exact original signed authorization. The parser
requires an absolute protected file path and the preapproved lowercase raw-byte
SHA256 digest. It opens every path component without symlinks, checks root/current
owner protection, a singly linked bounded regular file, read-to-EOF and stable
identity/metadata on the same descriptor, then compares those actual bytes to the
approved digest before JSON parsing or token reading. The digest must come from
the approved projection; hashing the current mutable file is not approval. Shape,
coordinates and the active bounded window are also checked before token reading.

The protected caller must first bind every original host, incarnation,
enrolment and controller fingerprint input, the session, and source/evidence
references to the approved external recovery manifest. A signed Control
authorization does not attest those CP host inputs. This projection is neither
that approval nor native fault provenance. No signing, provisioning or delivery
authority follows from parsing it.

`recover_dispatch_materials` verifies the original authorization, requests the
original rollout through the existing approval seam with an authorization
signer that always refuses, and commits that replay. Dispatch enters a fresh
approval hold through the existing seam and retains the same transaction until
its commit. Control owns the atomic resume preconditions and fresh checks under
its existing locks. CP's bound dispatch signer uses Control's public unsigned
statement validator and exact canonical bytes, current UTC, actual distribution
version and the session bounds before forwarding one sign. Output shares the
normal assembly and create-only writer; callers supply a fresh output directory
and retain failures without automatic retry.

The new Control API is qualified against sibling source only until a reviewed
release is adopted. Release pins are unchanged. Installed artifact/schema,
native standing/expiry/concurrency, real policy-role enforcement, audit/revocation,
exact-session signing approval and operational acceptance remain separate gates;
see `conformance/recovery_source/README.md` for the offline scope.
