# Finite Gate-0 case launch owner

Source only: this proposal supplies no operational authorization, custody,
installed management channel or native qualification evidence.

Exactly two independent starts are predeclared: A `consume_replay` and B
`withdrawal_later_use`. Each immutable shared packet and approved window binds
its required `case_kind`, actual GitHub `run_id` and `run_attempt`, one plan,
controller and lease. A must finish with complete root cleanup on both hosts
before B starts. A failed or unknown start ends the sequence. Neither start
rearms, automatically creates the next approval/wrappers, or refreshes expiry.
Each independently approved window is at most 300 seconds.

Each NS3 start has exactly `SLOTS=("issue","consume")`; both proofs succeed.
The issuer's expected negative occurs at authority use: A's identical consume
replay, or B's later consume after real human withdrawal and matching committed
relay revocation. Root validates launch mechanics; the collector owns case
semantics and distinct A/B windows/plans/leases/controllers.

The digest graph is acyclic: canonical shared `Gate0RunIdentity.v1` bytes S
contain singular `capture`, `case_kind`, `run_id`, `run_attempt`, original
`not_before`/`expires_at`, issuer/attester role pins, CA and management key pins.
They contain no installation or local hashes. Installations embed hS; local
`Gate0FiniteLaunch.v1` bytes embed hS, singular capture and installation hashes.
Their separate hL is carried in context, terminal and root cleanup evidence.
Both hosts share hS; their hL, machine and network measurement differ.
Old paired capture shapes and legacy slot keys are refused.

IDP3 installation hash keys are exactly `issuer,capture_sender`; NS3 keys are
`management,issue,consume`. Issuer installation binds `plan_id`; bootstrap calls
existing owner exporter with `(plan_id,)` and requires one capture. Delivery
installation binds one `capture` selection. `Gate0CaptureInstall.v1` has exact
schema, launch_packet_digest, capture fields; capture contains only coordinates
and capture_b64. `Gate0CaptureInstalled.v1` returns singular capture coordinates
and original effective_end. Root validates decoded window case/run/attempt/CA
and expiry, then atomically publishes `captures/capture.json` and readback using
renameat2(RENAME_NOREPLACE). Actual capture digest is learned from authenticated
owner bytes, never placed into a cyclic pre-start selection. Native peer UID,
cgroup, EOF, exact readback, duplicate-publication refusal and no retry persist.

Fixed installation, wrapper, claim, status and cgroup paths use `issue` and
`consume` directly. Both wrappers must exist before management publication;
exactly one issuer and two fresh attester one-use wrappers belong to each case.
The supervisor never mints wrappers. Per host LaunchClocks starts before
bootstrap and maps original expiry once. Attester acceptance caps at 30 seconds;
management/sender transfer caps at 10 seconds, all bounded by original deadline.
Existing token/HTTP budgets and byte/frame/command limits are unchanged.

Daemon and worker status are separate. Root records a normally reaped pinned
`sshd -i` daemon status in the OS exit-code domain0..255 before the original
acceptance deadline. This neutral lifecycle domain supplies no command-success
or authority meaning: ordinary completed client disconnect can yield daemon255.
There is no daemon0/255 success allowlist. Root-observed signal termination,
wait timeout, forced cleanup and failed wait remain incomplete even if later
cleanup reaps code0. After custody/descriptors close,
the fixed issuer wrapper calls `finish_issuer(IssuerProcessResult)`. Its terminal
record declares worker3, contains the bounded transcript digest and final typed
consume owner_refused outcome, and binds hS/hL/case/window. Root reads that file
only after killing the issuer cgroup, populated0 readback and guardian reap.
Attester slots similarly need timely normal daemon reaping and a post-custody
success terminal.
The collector separately requires actual authenticated pinned SSH client3 for
issuer and client0 for each attester, complete transcript/proof and EOF from
that invocation. Worker declarations never become root-observed worker exits.
Missing/mismatched terminal, client255/5/signal/disconnect and unknown commit
state remain incomplete. Native Ubuntu OpenSSH .19 propagation is still owed.

Successful terminate_and_confirm_empty returns root-produced
BoundaryCleanupEvidence: fixed boundary, cgroup device/inode, actual kill and
populated0 readback, guardian PID/start/wait status. Failure after emptiness is
sticky: a second close cannot convert a failed guardian reap to success.
Watchdogs detach standard descriptors; workers use only their accepted stream,
not the root result stdout. Helpers/daemons must be reaped. Root close attempts
every boundary and bounded direct-child reap/descriptor close
even after an earlier failure, preserving the first closed failure reason. It
deletes fixed wrappers/context/capture files, verifies their absence and retains
supervisor-once/claims. Deletion is not physical erasure or token revocation.
The exact transient inventory also includes sender-export.json, context.next,
issuer-export.sock, management.sock, capture-commit/capture.json and its readback,
and the now-empty capture staging/active directories. Partial cleanup uses only
these fixed protected paths, never recursive or caller-selected paths.
Bounded cleanup may follow acceptance expiry and records its honest timestamp.

After the final outer close attempt, export_cleanup emits one bounded
Gate0LaunchCleanup.v1 frame on reserved stdout and creates exclusive root-owned
mode0400 status/launch-cleanup.json with identical canonical bytes. The record
binds host/case/hS/hL/window/machine/network/supervisor/original clocks, phase
completion times, daemon observations, worker terminal digests/declarations,
all fixed completed boundary measurements and exact removed/expected paths.
It records complete or incomplete with a closed CleanupReason vocabulary;
incomplete never satisfies E. The actual cleanup-completion instant is stored
when close succeeds, remains null when cleanup is unknown, and is not recomputed
at export. Complete mechanics yields supervisor0;
activation/unknown/cleanup/export failures yield5.
Broken/blocked output never reopens authority; the retained artifact is for
reconciliation, not blind republish. The record always says
delivery_status=unconfirmed; only actual protected
receipt establishes delivery. Export failure preserves the exclusive local
record for reconciliation and records a root failure without retry.

`daemon_observations` has exact keys `issuer` on IDP3 and
`management,issue,consume` on NS3. Each closed Gate0DaemonObservation.v1 records
boundary, actual child PID/start, daemon_returncode, termination, completed_at,
completed_elapsed_seconds and phase_deadline_elapsed_seconds. Elapsed values
retain the root's original monotonic origin. Worker terminal envelopes no longer
contain an invented daemon0. Normally reaped numbers remain diagnostic; exact
terminal/protocol/client and cleanup joins determine eligibility.

NS3 `management_capture` retains the exact root-committed CaptureInstallReadback
and its canonical digest only after the existing EOF/request/selection/atomic
publication/readback-send protocol. Timely normal management daemon reaping and
complete cleanup allow only local roster progression, without claiming remote
delivery. IDP3 `capture_delivery` retains matching readback/digest after its actual
capture_sender child returns exactly0. That fixed sender still waits for actual
authenticated SSH client0, exact readback and EOF. The external finalizer joins
both root records by hS/window/coordinates/end/readback bytes/digest; a lost
response or sender client255 remains incomplete and never retries publication.

The focused native component keeps the existing UID/capability/socket positive
and negative checks and adds fixed test-only exec commands0,3,5 and signal.
It records actual client status separately from outer daemon status, fixed framed
output/EOF and synthetic terminal availability/declaration. Command5/signal can
be successfully characterized while remaining ineligible authority evidence.
Every mismatch still attempts child/stream/adopted PID1 subtree teardown and
emits bounded JSON diagnostics. The existing outer60-second budget is unchanged;
no real owner, protected approval, custody, full topology or E qualification
follows from these synthetic component records.

The protected management process must actually launch the fixed supervisor and
retain its output with known host/source/packet binding. This source does not
establish that operational channel. Arbitrary uploaded JSON or local root
ownership is not portable authentication. Native cgroup, pinned SSH/shell,
stdout spoofing, blocked output, custody and management-provenance conformance
remain required on the dedicated test server. Static AST/Ruff and authored unit
regressions do not qualify E or live readiness.

## Sealed network measurement and complete peer inventory

The local network document now requires `peers`, a closed complete list of
`{public_key, allowed_ips}` records (at most 32 peers, at most 32 addresses per
peer). Keys are canonical public 32-byte base64; every address is one canonical
RFC1918 IPv4 /32. Duplicate keys or address ownership, unknown fields, empty
inventories and broader prefixes refuse. Root normalizes kernel ordering and
compares the entire actual peer/AllowedIPs inventory in both directions. The
existing `peer_public_key`/`peer_allowed_ip` fields select exactly Bao's sole /32
on that peer; they do not grant all peers to Bao. Each SSH remote source must
have exactly one inventory allocation, and local SSH listener ports are >=1024.
No gateway, source translation, wildcard or subset qualification is implied.

Before any helper or guardian, the single-thread root supervisor refuses any
existing child, checks actual capget-v3 and supported capability bounds, then
normalizes to P0=0x411e3. Ambient/inheritable sets are cleared, securebits234 are
locked and no-new-privileges is set. P0 includes the fixed continuing K=0x400e3
(CHOWN, DAC_OVERRIDE, KILL, SETGID, SETUID, SYS_CHROOT) plus temporary SETPCAP and
NET_ADMIN. Initial permitted/bounding sets must already contain P0; missing
privilege, unsupported ABI or syscall/readback failure is terminal.

After the fixed pinned public WG/ip/nft queries, all preflight descendants and
the independent guardian must be empty/reaped. Only then does root replace its
permitted/effective sets, drop every bounding bit outside K (SETPCAP last), clear
ambient and independently read back E=P=B=K, I=A=0, securebits234 and NNP1.
No listener, SSH daemon or usable protected measurement/context is published
before this final seal. Continuing watchdogs inherit K. Root-owned Unix socket
modes are set before transfer to non-root owners; no FOWNER exception is added.
UsePAM=no, no PTY/external authentication commands and the exact pinned daemon
remain qualification conditions; native failure never widens K dynamically.

The protected measurement binds original wall/monotonic coordinates, common
and local packet/machine hashes, supervisor PID/start, namespace/device/index,
complete inventory, exact Bao selection, route and nft digests. Its hash enters
the root-owned worker context without a circular dependency on that context.
Every custody request reloads and checks the concrete installed context,
measurement, original deadline and actual live namespace/interface, then performs
the actual fresh device/source bind and connected socket readbacks before any
secret bytes. The worker never runs `wg`. This is measured-at-launch plus
qualified namespace immutability, **not** fresh per-request WG netlink evidence.

After real sshd UID switching and again in Python spawn, source requires real,
effective, saved, filesystem UID equality, declared primary group without extra
groups, E=P=I=A=0, inherited B=K and NNP1; the supervisor still has exactly K.
Bounding K is a ceiling, not a worker capability grant. No NET_RAW, NET_ADMIN,
SYS_ADMIN or SETPCAP is retained; no filecap/sudo helper or mutable namespace
manager may remain in the qualified installation.
External host root is still the explicit trusted installation boundary.

`conformance/test_gate0_network_privileges.py` authors an isolated role-image
PID1 proof with synthetic certificate authentication, pinned sshd, UID10032,
Python spawn, actual cap loss/regain refusal, private namespace WG/route/nft
mutation refusal and fresh socket/device-readback positive/negative. Under the
same final K it also refuses a genuine accepted-CA certificate with a wrong
principal, proves the fixed worker never entered, and requires the authentication
monitor/privsep descendants to exit and be reaped before the positive session.
It emits
`Gate0NativeNetworkPrivilegeProof.v1` only after descendant reaping, with
`full_wireguard_installation_qualified:false` and `live_readiness:false`.
The coordinator must run it with bounded whole-container termination; it has
not been executed locally. It does not qualify the full protected WG topology,
actual transport/custody, delegated host cgroup mount, DNS/HA safety or E. Those
require their existing independently authorized installed qualification packet.

## Root startup phases and attester cross-channel identity

The source reserves supervisor stdout for five root frames per case, forwarded
by the separately adopted authenticated operational holder. On NS3 it first
emits `management_listening` after the actual management socket is bound and
listening and the original sealed network/preflight measurement is rechecked.
Only then may the holder start IDP3's fixed invocation and its single-attempt
capture sender. IDP3 emits `issuer_listening` after its actual listener bind.
NS3 emits `attester_listening_after_capture` only after actual capture commit and
readback, timely normal management-daemon reap, boundary/guardian cleanup, and
actual attester listener bind. Two existing final `Gate0LaunchCleanup.v1` frames
follow after outer close; their existing export is preserved.

`gate0_launch_phase.decode_phase` owns the full closed
`Gate0RootLaunchPhase.v1` codec. Each canonical frame is bounded to 16 KiB and
binds common/local packet hashes, case/window, machine and network measurement,
supervisor PID/start identity, original approved/root wall and monotonic clocks,
emission time/elapsed, closed phase and actual fixed listener tuple. The
post-capture phase additionally carries the exact existing management capture
readback and its digest. The root enforces its host's finite phase order, and
writes under `min(original deadline, now + 2 seconds)` without retries. Output
failure is sticky and enters existing cleanup; no replacement invocation,
worker, credential, custodian, listener or operation deadline is introduced.
The final cleanup export keeps its existing bounded tail and
`delivery_status=unconfirmed`. Only actual authenticated holder receipt and
upstream EOF/client wait can qualify delivery.

The installed attester retains the SHA256 of the exact canonical signed bundle
only after its complete response write and final freshness checks, together with
the actual signed observation `invocation_id`. After custody teardown its
`Gate0SlotTerminal.v1` worker declaration includes those two fields. The root
strictly validates and retains that terminal in its existing cleanup record.
The protected collector must compare them against its actual verified client
bundle and invocation; a worker's success word alone cannot complete that join.
Normal root sshd exit codes 0 through 255 remain neutral lifecycle measurements,
separate from the collector's actual issuer SSH client 3 and attester client 0.

The phase parser authenticates nothing. Pipes, hashes, file permissions and
process status do not manufacture holder provenance. Actual operational holder
identity, the existing A9 management receiver endpoint, immutable forced-command
installation, host/source/image/packet pins and live campaign authorization
remain unqualified. Focused codec, ordering, capture/cleanup, terminal-identity and
native framing tests are source checks; none has been executed during this
static preparation or counts as protected A9/root/E acceptance. Strategy A still
requires the separately authorized actual bounded campaign, without an extra
full synthetic campaign gate.
