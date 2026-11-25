# CP host-gated canary and bootstrap — source preparation

Michael selected preparation of this route. No live account creation, token mint,
database deletion, team change or credential issuance has been authorized by that
choice. The proposed configuration keeps operator, execution and window references
unbound. Do not run apply until the exact final packet is explicitly approved.

The existing issuer and password-based proof retain their 77 passing mocked tests.
This separate owner introduces a database-write exception and temporary organization
authority, and requires its own source, transaction and native qualification.

Two phases use separate exclusive receipt directories:

1. Canary: require a fresh named account, create only a restricted nonadmin canary
   with no access, mint one `read:user` token, prove GET200, perform a guarded exact
   token-row deletion, reconcile metadata and prove the same token GET401.
2. Bootstrap: require an externally accepted canary receipt hash with matching
   run/source/container pins. Create only the CP nonadmin reader; its restricted
   setting requires an explicit decision. Mint one temporary `write:organization`
   token on the existing dotmac-admin UID1. Create only cp-bundle-readers with
   package-read-only grants, bind returned team ID/org/grants and original CP UID
   from fresh metadata before adding the member, and verify the exact final state.
   Revoke the new bootstrap token on success and on a failed setup when its exact
   identity is established. Require metadata restoration and same-token GET401.

The temporary organization scope is broader than these individual operations. No
`all` token, administrator password, new admin account, OpenBao access, GitHub
environment secret, CP runtime credential, deployment or application-table grant
mutation belongs to these phases. Team/user provisioning uses supported CLI/API;
SQL is restricted to the exact new token row.

The SQL owner locks the exact principal identity and binds token ID, UID, name,
scope and creation timestamp. Exactly one deleted row is required; otherwise the
transaction raises and rolls back. Protected known token IDs are refused. Mutable
permissions are checked before minting, but do not prevent cleanup of the new token
if permissions subsequently change. A renamed principal still requires explicit
reconciliation. The command marker occurs after COMMIT, but neither that marker
nor exit0 alone establishes effective revocation or absence of collateral changes.

An exclusive privileged user/team mutation window is required. Cooperative local
locks cannot constrain administrators using the UI/API. Fresh UID and grant checks
reduce check/use races but do not eliminate privileged concurrent changes. The
operator must enforce the window. Recorded reference strings do not prove authority.

The helper uses captured, hash-pinned copies of the already qualified audit/runtime,
an isolated trusted system Python (`/usr/bin/python3 -I -S -B`), root-owned source
ancestry, no local venv, core dumps disabled, exact container/image pins and a
read-only schema/PG16 probe before phase writes. HTTPS has a fixed origin, verified
TLS, no proxy, redirect, ambient authentication or retry. Generated account passwords
are discarded at the Docker client streams; token material stays in process memory
and HTTPS headers. Python cannot promise memory zeroization or exclude privileged
memory/swap capture. No raw output, response body, headers or exception text belongs
in receipts.

Every write has a durable intent. Mint/API/SQL operations are never blindly retried.
A lost mint response permits read-only reconciliation of exactly one newly bound
row, followed by the first explicitly authorized cleanup deletion. If it cannot be
bound, retain the run and reconcile; do not guess or remint. A lost DELETE reply
never permits a second DELETE automatically. Receipt I/O failure stops writes,
preserves prior intent/partial files, and may prevent a terminal status from being
persisted. Any uncertain mint, cleanup or commit holds all subsequent phases.

Cleanup ownership, operator response and exact failure scope must be in the live
packet. No successful source test closes that obligation. Canary accounts and
partially created CP resources remain retained; account/team deletion needs separate
authority. Existing users, tokens, recovery archives and unrelated resources remain
outside cleanup scope.

Hosted mocked tests exercise effect boundaries and failure rules. A separate hosted
PostgreSQL16 fixture uses an isolated Unix-only temporary cluster, metadata-only
synthetic tables and no Docker or credentials. Its transaction tests prove SQL
behavior only; they do not prove Forgejo cache invalidation, CLI behavior, deployed
schema compatibility, TLS or a working native revocation route. The native registry
canary must provide those missing operational facts before bootstrap is accepted.

Historical restricted accounts failed package-index reads. `restricted=true` must
not be assumed compatible. CP package capability and any explicit relaxation remain
separate live acceptance decisions; no automatic fallback exists. CP's
`revoke_verified` remains false until the compatible production route is accepted.
