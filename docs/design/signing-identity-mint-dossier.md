# Signing identity mint dossier — three purpose-bound Ed25519 identities

> **Status: ready to execute, nothing created yet.** Every command below is
> Michael's to paste. This repository holds **pointers only** — no key material
> is read, held, derived or logged by any code here (ADR-0009, and the seam
> that enforces it is `vendor_cp.deployment.signers`). Nothing in this document
> contains, or should ever be edited to contain, a secret value.

> **The two decisions below are recommendations with the reasoning shown, not
> settled policy.** Both are overridable at mint time and each states the exact
> one-line change if Michael decides otherwise. They are written as defaults so
> the ceremony is not blocked on a conversation.

## The four identities

One ceremony, four identities. They are not interchangeable and they do not
live in the same place — that separation is the whole point.

| # | purpose constant | pointer (OpenBao KV v2) | private half lives with | public half verified by |
|---|---|---|---|---|
| 1 | `deployment_authorization` | `secret/dotmac/platform-cp/authorization-signing/primary` | the Platform CP authorization issuer | the **target**, at `/etc/dotmac/platform-cp/authorization-verification.json` |
| 2 | `target_execution_observation` | `secret/dotmac/platform-cp/target-observation-signing/primary` | the **target host** (it signs what it applied) | Platform CP / Deployment Control |
| 3 | `deployment_dispatch` | `secret/dotmac/platform-cp/dispatch-signing/primary` | the Platform CP dispatcher (the caller injects it) | the **executor**, through `verify_dispatch_envelope` |
| 4 | `platform_release_evidence` | `secret/dotmac/platform-cp/release-evidence-signing/primary` | the release-evidence producer (Platform CP release path) | the **target**, at `/etc/dotmac/platform-cp/release-evidence-verification.json` |

Identities 1 and 2 answer two different questions — *may this happen* and *this
is what happened*. One key answering both would make the observation unable to
contradict the authorization, and an observation that cannot contradict is an
echo rather than evidence. `require_distinct_signers` refuses that pair in code;
minting them as one key would defeat the purpose before the code ever sees it.

Identity 2's private half deliberately lives **on the target**, not here. A
control plane that can sign the target's observations can manufacture the
evidence that it behaved.

### Purpose constants are not free text

Spelled exactly as the code spells them, and each read from the source that
declares it rather than from a description:

- `deployment_authorization` and `target_execution_observation` are on `main`
  today in `src/vendor_cp/deployment/signers.py`, restated from Control a10.
- `deployment_dispatch` is Control a11's `dispatch_envelope.py:45`. No
  descriptor for it exists in this repository yet.
- `platform_release_evidence` lands with the atomic cutover, which already
  consumes it in `bindings.py` through `Ed25519EvidenceVerifier`.

The two without descriptors have their pointers reserved **now**, so one
ceremony covers all four.

## Amendment — the fourth identity, and why the count moved again

`deployment_dispatch` was added on 2026-09-03, after Control **0.1.0a11**
shipped `dispatch_envelope.py`. Read from Control's own bytes rather than from a
description: `DISPATCH_PURPOSE = "deployment_dispatch"` at
`dispatch_envelope.py:45`, with `DispatchSignerIdentity` refusing any other
purpose as `dispatch_purpose_mismatch`.

It is **structurally distinct in the same way a10's pair are** — the three
signer protocols share no member name at all:

| purpose | signer members |
|---|---|
| `deployment_authorization` | `identity` / `sign` |
| `deployment_dispatch` | `dispatch_identity` / `sign_dispatch` |
| `target_execution_observation` | `execution_observation_identity` / `sign_execution_observation` |

So one cannot be passed where another is expected even by accident, and that
property now holds across three of the four rather than across a pair.

**The caller signs it.** `service.py` takes `dispatch_signer: DispatchSigner` as
a parameter, so the private half lives on the Platform CP side — the same side
as authorization — and the executor verifies. a11 is explicit: callers adopting
it must inject a dispatch-purpose signer and verify the dispatch envelope
before executing it.

**This is the second time the count has moved.** The third identity came from
reading the WIP loader; the fourth from a distribution that did not exist when
this document was written. The lesson is not "count more carefully" — it is that
the one-ceremony argument holds whatever the number, which is why it is stated
in terms of enrolment cost rather than in terms of three.

### Control already refuses one of the six collisions, by KEY not by pointer

a11 carries `SIGNER_PURPOSE_REUSED = "dispatch_signer_purpose_reused"`, raised
when `identity.public_key_fingerprint == authorized.public_key_fingerprint` —
the dispatch signer may not be the authorization signer's physical key.

Note what that compares. Control compares **fingerprints**; this product's
`require_distinct_signers` compares **pointers**. Two different pointers holding
the same key material pass the pointer check and are refused by Control's. A
pointer is a spelling; the key is the thing. The pointer check is still worth
having — it catches the mistake earlier and covers pairs Control never sees —
but it is not equivalent, and nobody should read a green pointer check as
Control's guarantee.

## Decision 1 — four identities, one ceremony (recommended)

The release-evidence purpose is not speculative. The atomic cutover's
`bindings.py` already loads its verifier on the target, and the missing signed
release-evidence producer is on the cutover path regardless.

The cost asymmetry decides it. A second ceremony means a second `CREDENTIALS.md`
enrolment and **a second opportunity to forget the renewal map** — the exact
omission that took the Prometheus scrape down in July. One ceremony has one
enrolment step and one verification pass. Two ceremonies have two of each, and
the second happens later, under more time pressure, when the first has faded.

**To override:** mint 1 and 2 only, and skip every step marked *(identity 3)*.
The reserved pointer stays unused and costs nothing.

## Decision 2 — a second OpenBao namespace, as `#133` shipped (recommended)

This product's existing live paths are all under
`secret/dotmac/vendor-control-plane/production/*` — database, runtime, deploy
SSH. Those hold the **application's own runtime material**. Signing keys are
**control-plane material the application must never reach**, so they go under
`secret/dotmac/platform-cp/`.

Different trust domains belong in different namespaces. Under one prefix, any
future policy written against `vendor-control-plane/production/*` would silently
grant signing material — and that policy would look entirely reasonable to
whoever wrote it.

`POINTER_PREFIX = "secret/dotmac/platform-cp/"` already encodes the boundary in
code, and its foreign-namespace test explicitly refuses
`secret/dotmac/vendor-control-plane/production/database`. Aligning the mint to
the shipped constant keeps that guard meaningful; aligning the constant to the
legacy paths would delete the boundary to match a naming habit.

**The honest cost:** two OpenBao namespaces for one product, when the rename
ruling deliberately kept `vendor` in the distribution, image, Compose project
and database. That is real operational surface, and someone will one day look
for these keys in the wrong place.

**To override:** change one line —
`POINTER_PREFIX` in `src/vendor_cp/deployment/signers.py` — and update this
table's three pointers to match. The change must land **before** the mint, not
after; the pointers are baked into policies, `CREDENTIALS.md` and the renewal
map, and moving them afterwards is a re-mint.

## Four constraints this ceremony must respect

These are not preferences. Each has bitten before.

1. **KV v2 policy paths are not the pointer text.** The mount is KV v2, so a
   policy grants `secret/data/<path>` for the value and `secret/metadata/<path>`
   for metadata. A policy written against the pointer string as printed above
   grants nothing and fails open-looking — it simply never matches.
2. **`-period=720h`, always.** `max_lease_ttl` is 768h on both the token backend
   and the `secret/` mount, so a non-periodic token is silently capped to ~32
   days whatever TTL is requested, and `token renew` on it is cosmetic. That is
   the 2026-06-14 expiry incident.
3. **Creation must be sudo-capable.** On OpenBao 2.5.3 a `num_uses`-limited
   token cannot create a child token, and a token role will not produce the
   periodic token the self-renewal contract needs. Supplying `-period` directly
   requires sudo-capable token creation.
4. **Enrolment precedes installation.** Append the label under `## App Tokens (`
   in `/opt/openbao/CREDENTIALS.md` **before** wiring anything to the token.
   `renew-tokens.py` reads that section automatically and needs no code change;
   a token outside that map expires silently.

**Provenance for constraint 4, stated rather than claimed:** this is recorded in
the canonical OpenBao Knowledge entries (`openbao-credentials`,
`openbao-root-usage-census-2026-08-31`). `/opt/openbao/renew-tokens.py` was
**not** inspected while writing this dossier — no host was contacted. Confirm
the `## App Tokens (` heading still reads as described before relying on the
automatic pickup; if it has changed, the enrolment step changes with it and
nothing else here does.

## Step 1 — generate the four keypairs (trusted workstation, offline)

Ed25519, 32-byte public keys, as `PublicVerificationIdentity` requires.

```sh
umask 077
mkdir -p ~/dotmac-platform-cp-mint && cd ~/dotmac-platform-cp-mint

for id in authorization dispatch target-observation release-evidence; do
  openssl genpkey -algorithm ed25519 -out "${id}.key.pem"
done
ls -l   # three files, mode 0600. Do not cat them.
```

## Step 2 — derive each PUBLIC half and its fingerprint

Public data only. Nothing here prints a private value.

```sh
python3 - <<'PY'
import base64, pathlib
from cryptography.hazmat.primitives import serialization

for name in (
        "authorization",
        "dispatch",
        "target-observation",
        "release-evidence",
    ):
    priv = serialization.load_pem_private_key(
        pathlib.Path(f"{name}.key.pem").read_bytes(), password=None
    )
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert len(raw) == 32, name
    print(name, base64.urlsafe_b64encode(raw).decode().rstrip("="))
PY
```

Then derive the canonical fingerprint with the authority that owns it —
Deployment Control, never a local reimplementation:

```sh
python3 -c "
from dotmac_deployment_control import PublicKeyFingerprintV1
print(PublicKeyFingerprintV1.from_public_key_b64('<public_key_b64url>').canonical)
"
```

`PublicVerificationIdentity.__post_init__` recomputes this and refuses a pair
where the fingerprint does not identify the key, so a transcription slip fails
at load rather than at verification time.

## Step 3 — four least-privilege policies

One policy per identity. Each grants read on its own path and **explicitly
denies** the other two and the licensing key.

An explicit `deny` is not redundant with Vault/OpenBao's implicit deny. It
survives a future broader grant: if some later policy attached to the same token
grants `secret/data/dotmac/*`, an explicit deny still wins, and an implicit one
would not. That is the failure this is defending against, not today's grants.

```hcl
# platform-cp-authorization-signing.hcl
path "secret/data/dotmac/platform-cp/authorization-signing/primary"          { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/authorization-signing/primary"      { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/dispatch-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/target-observation-signing/*"           { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/release-evidence-signing/*"             { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```hcl
# platform-cp-dispatch-signing.hcl
path "secret/data/dotmac/platform-cp/dispatch-signing/primary"               { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/dispatch-signing/primary"           { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/authorization-signing/*"                { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/target-observation-signing/*"           { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/release-evidence-signing/*"             { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```hcl
# platform-cp-target-observation-signing.hcl
path "secret/data/dotmac/platform-cp/target-observation-signing/primary"     { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/target-observation-signing/primary" { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/authorization-signing/*"                { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/dispatch-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/release-evidence-signing/*"             { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```hcl
# platform-cp-release-evidence-signing.hcl
path "secret/data/dotmac/platform-cp/release-evidence-signing/primary"       { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/release-evidence-signing/primary"   { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/authorization-signing/*"                { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/dispatch-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/target-observation-signing/*"           { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```sh
bao policy write platform-cp-authorization-signing      platform-cp-authorization-signing.hcl
bao policy write platform-cp-target-observation-signing platform-cp-target-observation-signing.hcl
bao policy write platform-cp-dispatch-signing           platform-cp-dispatch-signing.hcl
bao policy write platform-cp-release-evidence-signing   platform-cp-release-evidence-signing.hcl
```

## Step 4 — write the four records

`key=@file` reads the value from the file. Do **not** use command substitution:
that puts the private key in `argv`, where `ps` can read it.

```sh
bao kv put secret/dotmac/platform-cp/authorization-signing/primary \
  algorithm=ed25519 \
  purpose=deployment_authorization \
  key_id=platform-cp-authorization-2026-09 \
  private_key_pem=@authorization.key.pem \
  public_key_b64url='<from step 2>' \
  public_key_fingerprint='<from step 2>'

bao kv put secret/dotmac/platform-cp/target-observation-signing/primary \
  algorithm=ed25519 \
  purpose=target_execution_observation \
  key_id=platform-cp-target-observation-2026-09 \
  private_key_pem=@target-observation.key.pem \
  public_key_b64url='<from step 2>' \
  public_key_fingerprint='<from step 2>'

bao kv put secret/dotmac/platform-cp/dispatch-signing/primary \
  algorithm=ed25519 \
  purpose=deployment_dispatch \
  key_id=platform-cp-dispatch-2026-09 \
  private_key_pem=@dispatch.key.pem \
  public_key_b64url='<from step 2>' \
  public_key_fingerprint='<from step 2>'

bao kv put secret/dotmac/platform-cp/release-evidence-signing/primary \
  algorithm=ed25519 \
  purpose=platform_release_evidence \
  key_id=platform-cp-release-evidence-2026-09 \
  private_key_pem=@release-evidence.key.pem \
  public_key_b64url='<from step 2>' \
  public_key_fingerprint='<from step 2>'
```

The `purpose` field is stored beside the material so a record can be identified
without being interpreted. It carries the same string the verifiers require, so
a record filed under the wrong pointer is visible on inspection.

These paths are deliberately **outside** `production_secrets.SECRET_FIELDS`.
That module's approved set governs the three records the application itself
reads; these are never read by the running application, and adding them there
would create exactly the reach this namespace split exists to prevent.

## Step 5 — enrolment, BEFORE any token is installed anywhere

Append three lines under `## App Tokens (` in `/opt/openbao/CREDENTIALS.md`:

```
- platform-cp-authorization-signing: <token>
- platform-cp-target-observation-signing: <token>
- platform-cp-dispatch-signing: <token>
- platform-cp-release-evidence-signing: <token>
```

Then mint, periodic:

```sh
bao token create -policy=platform-cp-authorization-signing \
  -period=720h -display-name=platform-cp-authorization-signing
bao token create -policy=platform-cp-target-observation-signing \
  -period=720h -display-name=platform-cp-target-observation-signing
bao token create -policy=platform-cp-dispatch-signing \
  -period=720h -display-name=platform-cp-dispatch-signing
bao token create -policy=platform-cp-release-evidence-signing \
  -period=720h -display-name=platform-cp-release-evidence-signing
```

Enrol first, mint second, install third. Reordering these is how a token leaves
the renewal map.

After the next daily run at `17 3 * * *`, confirm all three appear in
`/opt/openbao/logs/token-renewal-status.json`. Steady state reads `degraded`
because of three pre-existing invalid labels; healthy means `degraded` **and**
`invalid` equal to exactly those three **and** `failed == []`. Three new labels
appearing under `invalid` is a failed enrolment, not the known baseline.

## Step 6 — publish the public halves to the target

Root-owned, regular files, under 16 KiB, schema
`PlatformCpPublicVerificationIdentity.v1`:

```json
{
  "schema": "PlatformCpPublicVerificationIdentity.v1",
  "key_id": "platform-cp-authorization-2026-09",
  "algorithm": "ed25519",
  "purpose": "deployment_authorization",
  "public_key_b64url": "<public>",
  "public_key_fingerprint": "<public>"
}
```

`/etc/dotmac/platform-cp/authorization-verification.json` and
`/etc/dotmac/platform-cp/release-evidence-verification.json`, `root:root`, mode
0644 (public data, but the loader requires uid 0 ownership and a regular file).

## Step 7 — verification: demonstrate, do not assert

Two layers, because they fail independently. **Every check asserts on an exit
status and discards stdout; no value is printed.**

**The arithmetic changed with the fourth identity, and not by one.** Four
identities are **twelve ordered pairs** — every identity against every purpose
that is not its own — plus four diagonal cases that must succeed. A fourth
member does not add one case, it adds six unordered pairs' worth of directions.
Nothing below is omitted as "cannot fail": all twelve are asserted, and where a
pair needs a package that may not be installed, the pair is named along with
what it needs rather than quietly skipped.

### 7a — reach: each token reads its own path and no other

Four successes and **sixteen denials** (each token against the other three
pointers and the licensing path). For each token in turn, as that token:

```sh
export BAO_TOKEN=<the authorization token>

bao kv get -field=public_key_fingerprint \
  secret/dotmac/platform-cp/authorization-signing/primary >/dev/null \
  && echo "own path: reachable (expected)"

for p in \
  secret/dotmac/platform-cp/dispatch-signing/primary \
  secret/dotmac/platform-cp/target-observation-signing/primary \
  secret/dotmac/platform-cp/release-evidence-signing/primary \
  secret/dotmac/licensing/signing-key
do
  if bao kv get -field=purpose "$p" >/dev/null 2>&1; then
    echo "REFUSE THE CEREMONY: $p is reachable and must not be"
  else
    echo "denied (expected): $p"
  fi
done
```

Repeat with each of the other three tokens, rotating which path is the permitted
one. **Count the successes: exactly four, and sixteen denials.** Twenty
successes means the policies did not attach; twenty denials means the KV v2 path
form is wrong (constraint 1) and proves nothing about isolation. Both failure
modes look like "it did not blow up", so counting is the check.

### 7b — purpose: the twelve ordered pairs

Reach proves a token cannot *fetch* another's material. It does not prove a key
cannot be *used* for the wrong job. That is the cryptographic layer, and it is
enforced in three places depending on which purpose is being misused:

| holder \ used as | authorization | dispatch | observation | release evidence |
|---|---|---|---|---|
| **authorization** | must succeed | (1) | (2) | (3) |
| **dispatch** | (4) | must succeed | (5) | (6) |
| **observation** | (7) | (8) | must succeed | (9) |
| **release evidence** | (10) | (11) | (12) | must succeed |

Each numbered cell must REFUSE. The mechanism that refuses it, and what that
mechanism needs to be present:

- **(3), (10) — the target-side loader.** `PublicVerificationIdentity.read(path,
  purpose=...)` refuses when the file's `purpose` field is not the one asked
  for. Needs the two published verification files from step 6 and the assembly's
  `bindings` module.
- **(1), (4), (5), (8), (11) — Control's own identity types.**
  `DispatchSignerIdentity` refuses a foreign purpose as
  `dispatch_purpose_mismatch`, and the authorization and observation identities
  refuse theirs the same way. Needs `dotmac-deployment-control` installed.
- **(2), (6), (7), (9), (12) — the same Control types, other direction.**

Demonstrate rather than cite. The shape for the loader pairs:

```sh
python3 - <<'PY'
from vendor_cp.deployment.bindings import PublicVerificationIdentity
from dotmac_deployment_foundation import SpecError

try:
    PublicVerificationIdentity.read(
        "/etc/dotmac/platform-cp/authorization-verification.json",
        purpose="platform_release_evidence",
    )
except SpecError as refused:
    print("authorization file refused as release evidence (expected):", refused)
else:
    raise SystemExit("REFUSE THE CEREMONY: one identity served two purposes")
PY
```

The `else: raise` is the point. A `try/except` that only prints on refusal
passes just as happily when nothing was refused.

### 7c — what this step does NOT prove

`require_distinct_signers` in `vendor_cp.deployment.signers` compares **two
pointers**. It was written for a pair and has not been widened for four, so it
does not see dispatch or release evidence at all, and it cannot see the shapes
four identities make available: three sharing one pointer, two disjoint pairs,
or two identities at different pointers holding the **same key material**.

Control refuses exactly one of those collisions, for exactly one pair, by
comparing public-key **fingerprints** (`dispatch_signer_purpose_reused`). Do not
read that as covering the rest, and do not read a green pointer check as
Control's guarantee. Widening it is a code change, deliberately not made inside
a document.

## If something goes wrong

Revoke and re-mint; do not repair in place. `bao token revoke`, delete the KV
record, remove the `CREDENTIALS.md` line, then start at step 1 with a new
`key_id` (the date suffix makes the replacement distinguishable in every log
that ever recorded the old one). A partially-completed ceremony that is
*adjusted* leaves a record whose `key_id` no longer identifies what verifies
against it.

Shred the workstation directory when the ceremony completes and the target files
verify:

```sh
cd ~ && rm -P -r ~/dotmac-platform-cp-mint   # -P overwrites before unlinking
```

## What this dossier is not

It does not authorize a deployment, name an operation, or assert that anything
was minted. Until step 5 completes, the readiness packet's `signed authorization
envelope` and `verified target signer` terms refuse by name, and that refusal is
correct rather than a defect to work around.
