# Gate0 collection owner reads — source candidate

These are source implementations, not deployed endpoints or Gate0 E acceptance.
The collector, fresh controller keys and actual GitHub OIDC acquisition remain in
the genuine protected A9 job on its isolated group3 runner. CP retains its one
kernel-owned database. This API supplies detached owner evidence only.

## Closed operations

- `GET /platform/vendor/gate0/collection/windows/{window_id}/approval`
- `GET /platform/vendor/gate0/collection/windows/{window_id}/withdrawal`

Both require one `Authorization: Bearer <GitHub job JWT>` header. Withdrawal
additionally requires exactly one `X-Dotmac-Gate0-Withdrawal-Reference` header
containing the human operation's bounded external reference. This reference is
never authorization or the relay event UUID. It is deliberately outside the URL,
so ordinary URL access logs do not capture it. Neither operation accepts query
parameters or a request body. Tokens, references and raw responses must remain
private campaign evidence; any installed header logging must exclude them.

`gate0_collection_reads` is a separate feature manifest admitted through the real
assembly. Its single authentication dependency reuses the one shared fixed GitHub
RS256/JWKS verifier also used by issuer admission. It has no platform-admin or
OpenBao token owner. The signature, fixed repository/owner/workflow/ref/environment,
issuer/audience and JWT time bounds are verified before opening the projection
session. The actual Control plan then supplies the frozen window. Every frozen
GitHub claim, run/attempt, subject, workflow SHA, environment-node ID and original
window time bound must match; caller-supplied resource IDs cannot replace them.
This is continuing read scope, not authorization to consume after withdrawal.

## Protected installation input

The installed ASGI entrypoint obtains the assembly spec and its exact selected
profile together from `build_spec_with_profile()`, constructs the application,
then calls `bind_installed_collection` before serving. The binder examines the
actual two endpoint identities, paths and methods: no exposed read routes means
no file read or DB qualification; partial publication refuses boot; both routes
require one successful fixed installation load. An existing state injection or a
second binding refuses. The profile is not read from the environment again.

`load_installed_collection` reads only
`/run/dotmac-gate0-collection/installation.json`. It walks protected descriptors,
requires root ownership and no group/other write permission, opens without
following symlinks, uses nonblocking file open before checking regularity, bounds
the bytes to 512 KiB and requires canonical closed JSON. Nothing is created or
replaced. Missing or invalid configuration refuses exposed-route boot.

Exact schema `Gate0CollectionApiInstallation.v1` contains `schema`,
`source_revision`, `image_digest`, `profile_digest`, `profile_code`,
`profile_version`, `database`, `clock_anchor`, and ordered `cases`. The database
object has exactly the public `DatabaseExpectation` fields; it cannot specify a
DSN, provider, callback or a qualified boolean. Source and profile digest are
compared with the existing fixed `/app/migration_heads.json` and
`/app/application_foundation_profile.json` artifacts. The exact actual chosen
profile code/version must match. The image digest is an installation pin whose
actual measurement remains the trusted launch owner's obligation; its syntax is
not binary self-measurement.

`clock_anchor` has exactly `wall_origin`, `monotonic_origin`, and `boot_id`. The
existing trusted root installer must measure this pair once for the same host
boot, publish once without replacement and retain the campaign/packet identity.
The reader checks the current Linux boot ID, rejects future/invalid coordinates
and refuses wall/monotonic elapsed-time disagreement above two seconds. An app
worker or process restart rereads the same original anchor; it does not sample a
replacement origin. Reboot mismatch refuses. No file absence, token refresh or
request can rearm an expired case. Preserving no-replace state across operational
installation changes remains the root installer's obligation, not a parsed flag.

Each of the exactly two `cases` contains only `shared_packet_b64` and
`frozen_window_b64`: canonical original shared launch packet and frozen window
bytes. A uses consume-replay and B withdrawal-later-use. The loader derives all
selection coordinates and cross-checks packet/window digest, target, case, run,
original times and controller CA. At read time actual owner plan digest and
approval request must match the shared packet as well. A/B must have distinct
plans, windows, requests, leases, controller keys and certificates, with the same
repository/run/attempt. No additional source/image-distinctness rule is imposed.

Each case has its own inert `CollectionCaseClock`, mapped separately from the
same original anchor. Future B can parse without activation; A expiry does not
expire B's later interval. Selection checks both the selected original wall and
monotonic interval before signature/JWKS or owner I/O. The fixed shared verifier
then checks the actual JWT and every selected frozen claim before owner DB reads.
The actual frozen owner window must independently equal the configured bytes.

After validating both cases the loader obtains the existing kernel authority
runtime through `authority_database_runtime`, calls the existing measured
`qualify_authority_database(DatabaseExpectation)`, and requires that qualification
to name that same runtime. It constructs only the fixed public GitHub JWKS
transport. No database setting leaves CP. Actual CP HTTPS origin/server identity,
ingress policy, native connect/pool/watchdog bounds and trusted installed image
provenance remain unperformed operational qualification. The protected runner
still owns its original deadline, maximum sixteen withdrawal reads and the
A-cleanup-before-B launch gate; these API read clocks launch nothing.

## JWT and operation-window intersection

The JWT's whole validity interval need not fit inside the approved case window.
Fresh `iat >= not_before`, every exact claim, current signature/JWKS verification,
integer time types, current expiry, existing `iat <= nbf < exp` and
`0 < exp - iat <= 300` policy all remain. Removing only `JWT exp <= window end`
avoids making an issuer-selected 300-second JWT unusable when minted after the
start of a window of at most 300 seconds. Actual GitHub claim-time metadata has
not been measured by this source preparation; preserving that policy is not a
claim that every genuine job token satisfies it.

Every read and admission requires the original intersection: wall time before
both JWT expiry and window end, and monotonic time before the original local
bound, mapped window end and mapped JWT expiry. Mapping uses the retained original
anchor, never a later `now + lifetime`. Checks repeat after owner I/O and confirmed
cleanup before a response or typed owner denial becomes eligible.

Issuer and attester admission attach distinct request-local
`RequestAuthenticationFreshness`; the retained `window_freshness` object stays
unchanged. Proof completion, pre-mutation/pre-commit checks, receipt reads and
bounded response writes check the request cap. Attester challenge/response and
proof emission use the shorter request deadline. If expiry happens after a
confirmed commit, the result is incomplete; the system never describes a committed
mutation as rolled back. This metadata is not portable or serialized authority.
A newer real token can authenticate only within the same original interval.

## Owner evidence and transactions

Approval resolves the configured plan/target through public Control views and
matches the original frozen window and exact Approvals request/content/policy.
It obtains the existing `held_transition` hold, rechecks the owner scope while
held, and projects existing genuine approval decisions. Because the hold takes
`FOR SHARE`, this semantically read-only operation uses a bounded normal
transaction. It executes no owner mutation or commit. Its detached response is an
approved-at-read snapshot, never a transferable hold or future standing promise.

Withdrawal checks the same original owner scope and historical approval identity,
completed approval time and genuine decisions. It does not require current
standing. It uses SQL `READ ONLY` and the published Approvals getter through
`approvals.adapter.withdrawal_for_reference`. The exact immutable withdrawal UUID
selects the existing relay-event read with a hard three-row native query limit,
including event-scoped conflicts with null request/reference coordinates. Success requires one applied row
with the same request, subject, plan, event UUID and withdrawal reference, plus
exactly the one authorization in CP's bounded issuer receipt index. The collector
must independently compare that authorization to its actual issued result.
No foreign-table query, relay drain, direct revocation or human mutation occurs.

Withdrawal returns one closed state: `pending_withdrawal` (no withdrawal/relay),
`pending_relay` (matching withdrawal, no relay), or `applied` (both exact records).
Ambiguity, mismatches, other dispositions and extra authorizations refuse. Both
responses include the owner/config-derived launch/window/plan/target/request/run
binding. Approval additionally includes the exact base64 frozen window and bounded
decision/image evidence. Responses are canonical JSON bounded to 64 KiB and carry
`Cache-Control: no-store`. Rollback and close must both succeed before any response
is returned; native statement/lock limits and original wall/monotonic expiry are
checked. Cleanup failure suppresses successful and pending results alike.

## Profile and qualification boundary

Every existing profile, including `full`, explicitly withholds this new feature;
their effective route sets remain unchanged. The explicit source candidate
`production-gate0-collection-v1` version 1 derives from `production-composed-v1`
and inventories only the additional `gate0_collection_reads` surface. Its
`production_accepted=False` means production boot refuses it. A separately reviewed
source change of that exact flag and an explicit operational profile selection are
still required before publication. Neither design adoption nor adding the candidate
claims a deployed profile or permission to publish.

The new focused source tests cover claim/scope matching, original historical owner
reads after withdrawal, exact relay/receipt joins, cleanup failures, transaction
modes, shared JWT behavior, and the real assembled candidate routes/dependency
graph. They are synthetic component checks, not protected producer ancestry, A9
custody, live human approval/withdrawal or a full campaign gate. During this source
preparation only static AST/Ruff checks are authorized; these tests have not run.
The accepted deployment manifest/descriptor remain unchanged. Any prospective
composition/digest artifact must be generated from the actual pinned candidate in
its authorized hosted pipeline, rather than presented as an installed measurement.
