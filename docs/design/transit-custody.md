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

Token role (ceremony): `allowed_policies` the one policy, `token_no_default_policy = true`,
`renewable = false`, `token_type = service`, `token_explicit_max_ttl = 15m`,
`token_bound_cidrs` the relay's source (a typed parameter), `orphan = false`. One 2-use,
10 minute token per issuance, a child of the ceremony root, revoked by accessor with a
lookup that must then fail; the root revocation at session end kills it regardless.

## Route

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
