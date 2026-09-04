# Signing identity mint dossier — five purpose-bound Ed25519 identities

> **Status: ready to execute, nothing created yet.** Every command below is
> Michael's to paste. This repository holds **pointers only** — no key material
> is read, held, derived or logged by any code here (ADR-0009, and the seam
> that enforces it is `vendor_cp.deployment.signers`). Nothing in this document
> contains, or should ever be edited to contain, a secret value.

> **The two decisions below are recommendations with the reasoning shown, not
> settled policy.** Both are overridable at mint time and each states the exact
> one-line change if Michael decides otherwise. They are written as defaults so
> the ceremony is not blocked on a conversation.

## The five identities

One ceremony, five identities. They are not interchangeable and they do not
live in the same place — that separation is the whole point.

The **short label** column is not decoration. The purpose-misuse matrix in
step 7b is indexed by these labels, and a matrix whose axes are spelled by hand
can drift from the identity set it claims to cover — which is how a count stays
at twelve while the document declares a fifth identity. The labels are declared
HERE, once, and the matrix is checked against them.

| # | purpose constant | short label | pointer (OpenBao KV v2) | private half lives with | public half verified by |
|---|---|---|---|---|---|
| 1 | `deployment_authorization` | authorization | `secret/dotmac/platform-cp/authorization-signing/primary` | the Platform CP authorization issuer | the **target**, at `/etc/dotmac/platform-cp/authorization-verification.json` |
| 2 | `target_execution_observation` | observation | `secret/dotmac/platform-cp/target-observation-signing/primary` | the **target host** (it signs what it applied) | Platform CP / Deployment Control |
| 3 | `deployment_dispatch` | dispatch | `secret/dotmac/platform-cp/dispatch-signing/primary` | the Platform CP dispatcher (the caller injects it) | the **executor**, through `verify_dispatch_envelope` |
| 4 | `platform_release_evidence` | release evidence | `secret/dotmac/platform-cp/release-evidence-signing/primary` | the release-evidence producer (Platform CP release path) | the **target**, at `/etc/dotmac/platform-cp/release-evidence-verification.json` |
| 5 | `deployment_recovery` | recovery | `secret/dotmac/platform-cp/recovery-signing/primary` | the Platform CP recovery-grant issuer | the **executor**, through `verify_recovery_grant` |

> **CUSTODY RULING — Michael, 2026-09-04.** *"Keep the target-observation
> private key on the target. Platform CP must not be able to manufacture target
> observations."* This approves the four-identity DESIGN; nothing is minted.
>
> **The version of this document merged as #134/#142 contradicted that rule**,
> and the contradiction was in the ceremony rather than in the table. The table
> said the observation private half lives with the target host — correct — while
> Step 1 generated it on the workstation, Step 4 wrote `private_key_pem` into
> `secret/dotmac/platform-cp/target-observation-signing/primary`, Step 3 granted
> a Platform-CP policy `read` on that exact path, and Step 5 minted a Platform CP
> token to use it. Following the document as written would have produced exactly
> the capability the ruling forbids. The steps below are corrected.

## Where each private half lives

Custody is the whole point of the separation, so it is stated per identity
rather than left to be inferred from a pointer name. **A pointer is a spelling;
the key is the thing**, and which machine holds the thing is what decides
whether a signature can be manufactured.

| purpose | private half is generated and held | can Platform CP obtain it? |
|---|---|---|
| `deployment_authorization` | Michael's workstation -> OpenBao, read by the Platform CP issuer | **yes, by design** — it issues authorizations |
| `deployment_dispatch` | Michael's workstation -> OpenBao, read by the Platform CP dispatcher | **yes, by design** — the caller injects it |
| `target_execution_observation` | **on the target, and never leaves it** | **NO — structurally** |
| `platform_release_evidence` | Michael's workstation -> OpenBao, read by the release path | **yes, by design** |
| `deployment_recovery` | Michael's workstation -> OpenBao, read by the recovery-grant issuer | **yes, by design** — it issues recovery grants |

### Identity 5 shares the namespace and is separated by POLICY SCOPE

**RULING — Michael, 2026-09-04.** *"Record the recovery signer as PRIVATE,
custodied under the dossier-declared `secret/dotmac/platform-cp/*` path. Access
is restricted to the recovery-grant issuer."*

The question this answers was raised rather than assumed away, and a reader who
sees five identities under one prefix and no explanation will conclude nobody
thought about it. They were co-located deliberately.

`deployment_authorization` and `deployment_recovery` are the authority to DEPLOY
and the authority to RESTORE. Putting them in one custody domain means one
compromise of that domain yields both. The design already refuses key REUSE —
separate purposes, each statement's fingerprint bound to its signer identity —
but **co-location is a different question from reuse**, and it is cheap to
separate at mint time and expensive afterwards.

The separation is by **policy scope, not by namespace**. All five pointers sit
under `secret/dotmac/platform-cp/`; what differs is which token may read which
path. Each policy grants read on exactly its own pointer and explicitly DENIES
every other, so compromising the dispatch or release-evidence token yields no
recovery authority, and compromising the recovery token yields no authorization
authority. The namespace is a filing decision; the policy is the boundary.

**And the recovery key alone is not sufficient to recover.** A recovery grant is
not `approval_exempt`-able, unlike a deployment authorization: `verify_recovery_grant`
accepts only a GRANTED approval decision, where `authorization.py` accepts
`granted` or `approval_exempt`. That is implemented behaviour in Control, not a
proposal — a deliberate tightening. Holding the recovery key still requires a
granted approval to exist.

### What identity 5 hands over, and what it never does

Two different things are true about one identity, and stating only one of them
is how a reader ends up believing the wrong one.

**PRIVATE, held by the issuer.** The pointer named in the identity table holds
signing material. `MaterialKind.PRIVATE`, the same as identities 1, 3 and 4, and
the opposite verdict to identity 2 — for a reason that now generalises across
the whole table: **the signer is the party making the statement.** The target
signs observations because the target asserts what it applied. The control plane
signs a recovery grant because the control plane asserts that this recovery is
authorized. `issue_recovery_grant` runs Control-side, Control is composed here,
and the executor only ever verifies.

**PUBLIC, handed to Foundation.** What crosses the boundary to the Deployment
Foundation is the public verification material and the key ID — exactly what a
verifier needs and nothing a signer needs. The private half is not among it.

**Four parties never receive the private half**, and this is a negative custody
assertion rather than an absence of mention: the **browser**, the **relay**, the
**Foundation executor** and the **deployment target**. None gets a policy
granting read on the recovery pointer, none gets a token minted for it, and no
step in this ceremony hands it over.

**Five surfaces the private half never enters:** Git, candidates, receipts, logs
and canonical documents — this document included.

Both lists are checked rather than promised, by the same fenced-block extractor
that already refuses a `bao kv put` writing private material to a public-material
pointer, a policy granting read on one, and a token minted for one. **Stated as
weaker than it sounds:** that establishes the ceremony does not CREATE the
capability. It does not establish that the capability cannot exist by some route
this document never describes.

The third row is the ruling. An observation Platform CP could produce cannot
contradict the authorization Platform CP issued, and an observation that cannot
contradict is an echo rather than evidence — which is the reason there are two
signers at all. So the key is not generated on the workstation, is never written
to this namespace, has no Platform CP policy granting read, and has no Platform
CP token. **The custody rule is made structural, not procedural:** Platform CP
cannot manufacture observations because the material was never somewhere it
could reach, not because a runbook told it not to.

What lives at `secret/dotmac/platform-cp/target-observation-signing/primary` is
the target's **public** verification identity — what Platform CP and Control need
in order to VERIFY. Control's own contract already works this way: it enrols a
target's public verification identity as PENDING and admits it only after the
caller proves possession.

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
- `deployment_recovery` is Control's `RECOVERY_PURPOSE`, at
  `src/dotmac_deployment_control/recovery_grant.py:77`, read from the merged
  commit `312e9a8227cda941f15d0e44a93c41a76332d86e` on
  `michaelayoade/dotmac_deployment_control` `main` rather than from a branch
  description. It existed nowhere at all until that merge, which is why this
  document could not name it earlier and did not guess.

**A purpose is not a document type, and one of them will not save you from the
other.** The same file declares `RECOVERY_GRANT_SCHEMA =
"dotmac.deployment_control.recovery_grant"` at line 78. That is the DOCUMENT
discriminator: `RecoveryGrantRefusalCode.SCHEMA_MISMATCH` is how a deployment
authorization is refused, and it fires BEFORE any field is compared. A verifier
matching on purpose alone would reach the field comparison with the wrong kind of
document in hand. Both belong in the ceremony's vocabulary, and they are
different things — the schema is never written into a signing record's `purpose`
field.

The three without descriptors have their pointers reserved **now**, so one
ceremony covers all five.

## Amendment — the fifth identity, and the arithmetic that moves with it

`deployment_recovery` was added on 2026-09-04 on Michael's ruling: *"The
separate recovery signer makes five unless it is already represented."* It is
not already represented. The four that existed are `deployment_authorization`,
`deployment_dispatch`, `target_execution_observation` and
`platform_release_evidence`; a recovery-grant signer is none of them, and
Control settled that in code rather than by argument:

- `RecoveryGrantSignerIdentity.__post_init__` refuses any purpose that is not
  `deployment_recovery`, so it cannot be one of the four wearing another name;
- `RecoveryGrantSigner`'s members are `recovery_identity` / `sign_recovery`,
  sharing no name with the other three signer protocols, so one cannot be passed
  where another is expected even by accident;
- `issue_recovery_grant` refuses a signer that does not implement that protocol.

**Five identities are twenty ordered pairs**, plus five diagonal cases that must
succeed. Michael's ruling names four of them to keep recovery distinct from —
authorization, target observation, release evidence and licensing — and omits
`deployment_dispatch`. That is read here as an ENUMERATION SLIP rather than an
exemption, because the same sentence requires all twenty ordered pairs and
twenty is only reachable with dispatch included: a set of four would be twelve
and five-minus-dispatch is not a set this document declares. The derived set of
five governs; a named list of four does not narrow it. Recorded rather than
silently resolved, because a reader comparing the ruling with the matrix will
notice the difference and should find it already answered.

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

## Decision 1 — five identities, one ceremony (recommended)

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
table's five pointers to match. The change must land **before** the mint, not
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

## Step 1 — generate FOUR keypairs (trusted workstation, offline)

Ed25519, 32-byte public keys, as `PublicVerificationIdentity` requires.

**Four, not five.** `target_execution_observation` is generated ON THE
TARGET in step 6 and never reaches this workstation. Generating it here —
even with the intention of copying it across and deleting it — would put the
material somewhere Platform CP's operator can reach, and "and then delete
it" is a procedure, not a property.

`deployment_recovery` IS generated here, and that is the opposite verdict for
the opposite reason: the control plane is the party that asserts a recovery is
authorized, so it is the party that must be able to sign one.

```sh
umask 077
mkdir -p ~/dotmac-platform-cp-mint && cd ~/dotmac-platform-cp-mint

for id in authorization dispatch release-evidence recovery; do
  openssl genpkey -algorithm ed25519 -out "${id}.key.pem"
done
ls -l   # four files, mode 0600. Do not cat them.
```

## Step 2 — derive each PUBLIC half and its fingerprint

Public data only. Nothing here prints a private value.

```sh
python3 - <<'PY'
import base64, pathlib
from cryptography.hazmat.primitives import serialization

for name in ("authorization", "dispatch", "release-evidence", "recovery"):
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
denies** the other three, the observation path and the licensing key.

**This is where co-location is made safe.** All five pointers share one
namespace; what separates them is that no token may read another's path. The
recovery policy is scoped to the recovery-grant issuer, so a compromised
dispatch or release-evidence token yields no recovery authority.

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
path "secret/data/dotmac/platform-cp/recovery-signing/*"                     { capabilities = ["deny"] }
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
path "secret/data/dotmac/platform-cp/recovery-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

**There is deliberately NO `platform-cp-target-observation-signing` policy.**
A policy granting read on that path would only be needed if private observation
material lived there, and none does. Minting one anyway would create the
capability the custody ruling forbids and leave a reader assuming the key is
where the policy points. The other four policies still DENY the observation
path, which now protects a public record from being written rather than a
private one from being read — cheap, and correct in both worlds.

```hcl
# platform-cp-release-evidence-signing.hcl
path "secret/data/dotmac/platform-cp/release-evidence-signing/primary"       { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/release-evidence-signing/primary"   { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/authorization-signing/*"                { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/dispatch-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/target-observation-signing/*"           { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/recovery-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```hcl
# platform-cp-recovery-signing.hcl
#
# Scoped to the recovery-grant issuer and to nothing else. The browser, the
# relay, the Foundation executor and the deployment target receive no policy
# naming this path, and none is written anywhere in this ceremony.
path "secret/data/dotmac/platform-cp/recovery-signing/primary"               { capabilities = ["read"] }
path "secret/metadata/dotmac/platform-cp/recovery-signing/primary"           { capabilities = ["read"] }
path "secret/data/dotmac/platform-cp/authorization-signing/*"                { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/dispatch-signing/*"                     { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/target-observation-signing/*"           { capabilities = ["deny"] }
path "secret/data/dotmac/platform-cp/release-evidence-signing/*"             { capabilities = ["deny"] }
path "secret/data/dotmac/licensing/*"                                        { capabilities = ["deny"] }
path "secret/metadata/dotmac/licensing/*"                                    { capabilities = ["deny"] }
```

```sh
bao policy write platform-cp-authorization-signing      platform-cp-authorization-signing.hcl
bao policy write platform-cp-dispatch-signing           platform-cp-dispatch-signing.hcl
bao policy write platform-cp-release-evidence-signing   platform-cp-release-evidence-signing.hcl
bao policy write platform-cp-recovery-signing           platform-cp-recovery-signing.hcl
```

## Step 4 — write the records (four private, one public-only)

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

# PUBLIC MATERIAL ONLY. No `private_key_pem` line, and adding one would defeat
# the custody ruling. These values come from step 6, where the key is generated
# on the target -- they do not exist yet at this point in the ceremony.
bao kv put secret/dotmac/platform-cp/target-observation-signing/primary \
  algorithm=ed25519 \
  purpose=target_execution_observation \
  key_id=platform-cp-target-observation-2026-09 \
  public_key_b64url='<from step 6, generated on the target>' \
  public_key_fingerprint='<from step 6, generated on the target>'

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

# `purpose` carries the SIGNER purpose. It never carries
# `dotmac.deployment_control.recovery_grant`, which is the DOCUMENT schema and a
# different discriminator: the schema refuses a deployment authorization before
# any field is compared, and a record filed with it in this field would name the
# wrong kind of thing.
bao kv put secret/dotmac/platform-cp/recovery-signing/primary \
  algorithm=ed25519 \
  purpose=deployment_recovery \
  key_id=platform-cp-recovery-2026-09 \
  private_key_pem=@recovery.key.pem \
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

Append four lines under `## App Tokens (` in `/opt/openbao/CREDENTIALS.md`:

```
- platform-cp-authorization-signing: <token>
- platform-cp-dispatch-signing: <token>
- platform-cp-release-evidence-signing: <token>
- platform-cp-recovery-signing: <token>
```

Then mint, periodic:

```sh
bao token create -policy=platform-cp-authorization-signing \
  -period=720h -display-name=platform-cp-authorization-signing
bao token create -policy=platform-cp-dispatch-signing \
  -period=720h -display-name=platform-cp-dispatch-signing
bao token create -policy=platform-cp-release-evidence-signing \
  -period=720h -display-name=platform-cp-release-evidence-signing
bao token create -policy=platform-cp-recovery-signing \
  -period=720h -display-name=platform-cp-recovery-signing
```

Enrol first, mint second, install third. Reordering these is how a token leaves
the renewal map.

After the next daily run at `17 3 * * *`, confirm all four appear in
`/opt/openbao/logs/token-renewal-status.json`. Steady state reads `degraded`
because of three pre-existing invalid labels; healthy means `degraded` **and**
`invalid` equal to exactly those three **and** `failed == []`. Four new labels
appearing under `invalid` is a failed enrolment, not the known baseline.

## Step 6 — generate the observation key ON the target, and publish the rest to it

**First, on the target host, generate the identity that never leaves it:**

```sh
umask 077
openssl genpkey -algorithm ed25519 -out /etc/dotmac/platform-cp/target-observation.key.pem
chown root:root /etc/dotmac/platform-cp/target-observation.key.pem
chmod 0600      /etc/dotmac/platform-cp/target-observation.key.pem
```

Export only its PUBLIC half and fingerprint — the same derivation as step 2 —
and carry those two values back for step 4's public-only record and for
Control's target-identity enrolment. **Nothing carries the private key off this
host.** If it is ever needed again it is re-generated here and re-enrolled;
a key that can be copied out is a key Platform CP can eventually hold.

## Step 6b — publish the verification files to the target

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

**The arithmetic changed again with the fifth identity, and not by one.** Five
identities are **twenty ordered pairs** — every identity against every purpose
that is not its own — plus five diagonal cases that must succeed. The fourth
member took the count from six to twelve; the fifth takes it from twelve to
twenty. A member does not add a case, it adds a row AND a column. Nothing below
is omitted as "cannot fail": all twenty are asserted, and where a pair needs a
package that may not be installed, the pair is named along with what it needs
rather than quietly skipped.

**Nothing in this section states a number that a reader has to trust.** The
identity table declares the identities and their short labels; the matrix is
checked against those labels and its cell count is derived as N*(N-1) by
`tests/architecture/test_signing_identity_dossier.py`. The count reached twelve
by hand twice and was wrong in the title for as long as it took anyone to read
both registers.

### 7a — reach: each token reads its own path and no other

**Four tokens, not five** — there is no observation token, because there is no
private observation material for one to read. Four successes and **twenty
denials**: each token against the other three private pointers, the observation
pointer, and the licensing path.

That the reach arithmetic and the purpose arithmetic both reach twenty is a
coincidence of 4x5 and 5x4, not a shared derivation. They count different
things — which tokens may FETCH which material, and which identities may be USED
for which purpose — and a change to either does not move the other.

The absent observation token is itself part of the proof. A ceremony that produced
one would have produced the capability the custody ruling forbids, so its
absence is checked rather than assumed:

```sh
bao policy read platform-cp-target-observation-signing >/dev/null 2>&1 \
  && echo "REFUSE THE CEREMONY: an observation signing policy exists" \
  || echo "no observation signing policy (expected)"
```

**The four never-receives are checked the same way**, and for the same reason:
a ceremony that quietly granted one of them looks identical to one that did not.
No policy naming the recovery path may exist for the browser, the relay, the
Foundation executor or the deployment target, and no token may be minted for
one. There is exactly one policy naming that path and exactly one token carrying
it, and counting is the check:

```sh
bao policy list | grep -c 'recovery-signing'   # expect exactly 1
```

**What that establishes:** the ceremony does not CREATE the capability. **What
it does not:** that the capability cannot exist by some route this document
never describes. A count over policies is evidence about this OpenBao instance
at this moment, not a property of the system over time.

For each of the four tokens in turn, as that token:

```sh
export BAO_TOKEN=<the authorization token>

bao kv get -field=public_key_fingerprint \
  secret/dotmac/platform-cp/authorization-signing/primary >/dev/null \
  && echo "own path: reachable (expected)"

for p in \
  secret/dotmac/platform-cp/dispatch-signing/primary \
  secret/dotmac/platform-cp/target-observation-signing/primary \
  secret/dotmac/platform-cp/release-evidence-signing/primary \
  secret/dotmac/platform-cp/recovery-signing/primary \
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
one. **Count the successes: exactly four, and twenty denials.** Twenty-four
successes means the policies did not attach; twenty-four denials means the KV v2
path form is wrong (constraint 1) and proves nothing about isolation. Both
failure modes look like "it did not blow up", so counting is the check.

### 7b — purpose: the twenty ordered pairs

Reach proves a token cannot *fetch* another's material. It does not prove a key
cannot be *used* for the wrong job. That is the cryptographic layer, and it is
enforced by the verifier for the purpose being MISUSED — which is why the cells
below are grouped by column rather than by direction.

| holder \ used as | authorization | dispatch | observation | release evidence | recovery |
|---|---|---|---|---|---|
| **authorization** | must succeed | (1) | (2) | (3) | (4) |
| **dispatch** | (5) | must succeed | (6) | (7) | (8) |
| **observation** | (9) | (10) | must succeed | (11) | (12) |
| **release evidence** | (13) | (14) | (15) | must succeed | (16) |
| **recovery** | (17) | (18) | (19) | (20) | must succeed |

**All twenty remain demonstrable in this ceremony, including the four that hold
the observation identity — and that is worth stating because it is not the
obvious answer.** These cells compare a PURPOSE DECLARATION against a verifier;
they need each identity's public half and its declared purpose, never a private
key. The ceremony has all five public halves, so keeping the observation private
key on the target costs nothing here.

Each numbered cell must REFUSE. Grouped by the verifier that refuses it — the
column, not the row — because "what refuses this" is a property of the purpose
being claimed, not of the key claiming it. Five groups of four:

- **(5), (9), (13), (17) — used as AUTHORIZATION.** Control's authorization
  identity refuses a foreign purpose, and (13) is additionally demonstrable
  through the target-side loader, because release evidence is one of the two
  identities with a published verification file. Needs
  `dotmac-deployment-control` installed.
- **(1), (10), (14), (18) — used as DISPATCH.** `DispatchSignerIdentity` refuses
  a foreign purpose as `dispatch_purpose_mismatch`.
- **(2), (6), (15), (19) — used as OBSERVATION.** Control's execution-observation
  identity refuses a foreign purpose the same way.
- **(3), (7), (11), (20) — used as RELEASE EVIDENCE.**
  `PublicVerificationIdentity.read(path, purpose=...)` refuses when the file's
  `purpose` field is not the one asked for. Needs the two published verification
  files from step 6 and the assembly's `bindings` module.
- **(4), (8), (12), (16) — used as RECOVERY.**
  `RecoveryGrantSignerIdentity.__post_init__` refuses any purpose that is not
  `deployment_recovery`. **And a second, earlier refusal applies to this column
  alone:** `RECOVERY_GRANT_SCHEMA` discriminates the DOCUMENT, so
  `RecoveryGrantRefusalCode.SCHEMA_MISMATCH` refuses a deployment authorization
  before any field is compared. Purpose and schema are different checks, and the
  schema one fires first — a verifier matching on purpose alone would reach the
  field comparison holding the wrong kind of document.

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

**Custody is proved by absence, not by comparison.** The twenty pairs establish
that no identity can be USED for another's purpose. They say nothing about who
can HOLD a key, and the custody ruling is entirely about holding. What stands in
for it is the absence checked in 7a: no observation record with private
material, no policy granting read on one, no token minted for it. Absence is a
weaker instrument than a comparison and should be read as such — it proves the
ceremony did not create the capability, not that the capability cannot exist.

**And this ceremony cannot prove the target key stayed on the target.** It can
show the key was generated there and never written to this namespace. It cannot
show that nobody copied it out afterwards, because that is a property of the
host over time and not of a ceremony performed once. That belongs to the
target's own access controls, and naming it here keeps it from being assumed
discharged by a green verification pass.

**`require_distinct_signers` compares pointers, and one identity now has no
pointer to private material.** The observation key has no OpenBao private record
at all, so a pointer comparison cannot see it — there is nothing on this side to
compare. Its distinctness from the other four is established by the fingerprint
comparison, when fingerprints are supplied, and by Control's own
`dispatch_signer_purpose_reused` at signing time. The function's ownership
boundary — ours always / ours when told / Control's / nobody's — is unchanged by
the custody ruling; what changed is that for one of the five, "ours always" now
has nothing to look at.

**One open question this document does not settle.** `ObservationSignerPointer`
in `vendor_cp.deployment.signers` is a descriptor for where the observation key
lives. Under this ruling, the path it names holds the target's PUBLIC identity
and no private material, which is a different thing from what the other four
descriptors name. That may be fine — a pointer descriptor does not assert what
kind of material sits at the end of it — or the type may want splitting. It is
a code question, deliberately not decided inside a documentation change.

