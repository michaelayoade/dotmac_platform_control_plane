# Isolated Forgejo revocation proof — prepared source only

This helper has no live execution authority. It does not create or delete users,
teams, GitHub environments or secrets, or access OpenBao. The proposed configuration
is deliberately unbound and cannot apply. Never insert passwords or tokens in it.

The source-qualified issuer has 46 hosted mocked tests passing at CP run
45639342779, head b88cbd169c271742edadd68e3622dc6ab1850c91. Those tests do not
qualify this new helper or prove functional revocation.

An approved operator must first provision an isolated nonadmin, restricted, active
disposable principal with no organizations, teams, repositories, collaborations,
keys or tokens. Pin its exact name and UID, the full Forgejo and database container
IDs and image IDs, operator identity/profile, approved execution-packet reference,
and the final reviewed helper SHA256. Configuration strings record external
authority; they cannot themselves prove that authorization exists.

The exact live packet must reserve an exclusive user-mutation window: no other
administrator may rename, delete, recreate or modify the disposable account
during this proof. Forgejo's CLI mints by username, so the helper's fresh UID
check immediately before mint cannot eliminate a concurrent privileged write
between that check and Forgejo's lookup. A local lock would not constrain web/API
administrators; explicit operational coordination is required. Missing window
reference refuses apply, and any observed identity drift stops the run.

Forgejo v11.0.16's `admin user create --random-password` prints the password.
Any separately authorized creation must suppress stdout and stderr at that process,
use no terminal, and verify state through metadata. Use explicit nonadmin/restricted,
no forced password change and no access-token creation flags. No account creation
command is provided here because that action has not been authorized.

Before execution, qualify the final helper and audit bytes, the root-owned source
ancestry, installed system Python/OpenSSL/Docker, installed Forgejo image, TLS CA
bundle, operator password/MFA requirements, and the disposable-principal metadata.
Stage only under protected root-owned paths; prepare the empty root-owned mode700
`/root/cp-reader-revocation-receipts` parent in a separate reviewed packet. Launch
only using `/usr/bin/python3 -I -S -B` on `dotmac-s3` as root with a controlling TTY.
The operator types the password at the protected terminal, never in chat, argv,
environment, configuration, files or logs. No OTP support is implemented; an
MFA-protected account may refuse DELETE. Do not bypass policy to make it pass.

Plan mode reads local source/configuration only and contacts nothing. Apply requires
the exact configuration digest and one fresh receipt path. The live packet must
add the explicit registry-host Docker exception, an exact account/run/host binding,
approved operator session, reviewed launch hashes and execution/cleanup scope.
No apply command is supplied until those conditions are fulfilled.

The state machine records one attempt before minting one `read:user` token into
process memory. It verifies token identity from metadata, GET `/api/v1/user` status
200, exact positive decimal-ID DELETE status204, metadata absence, and the same
token's GET status401. HTTPS uses verified TLS and the system CA file directly;
no proxy, netrc authentication, redirects, body logging or automatic retry exists.
The recorded token ID/name are public recovery identifiers, never the token value.

On any failure the proof stops and retains state. There is no automatic remint,
DELETE retry, account cleanup or fallback credential. In particular a timeout may
mean a token was minted or deleted without the response being received. Inspect
the receipt and reconcile metadata through separately authorized read-only checks;
authorize exact recovery before any further write. Do not delete the receipt or
reuse the run name to bypass the one-attempt rule. A failed baseline GET can leave
a token awaiting operator revocation; that residual must be resolved explicitly.
If the receipt filesystem fails, the helper preserves the last durable intent
and any partial temporary file, emits a fixed nonsecret stop message, and does
not claim a final status was persisted. No operation follows a failed intent write.

Successful proof retains the disposable account with zero tokens; deletion is a
separate action. Source/mocked qualification does not set CP `revoke_verified` true.
Only accepted native evidence and an approved production-compatible revocation
route can close that gate. No CP issuance, acquisition, merge, image publication or
deployment follows automatically.

Token/password values stay in process memory and HTTPS headers. Python cannot
promise memory zeroization or exclude privileged memory/swap capture. Core dumps
are disabled and response bodies, exception text, captured CLI output and headers
are never included in receipts or diagnostic output.
