# Finite Gate-0 launch owner

`gate0_launch.py` implements the root launch mechanics for the adopted protected
IDP3 issuer and NS3 attester boundary. Source installation supplies no real
packet, privileges, custody wrappers or qualification evidence. Missing inputs
refuse. No local daemon, cgroup, SSH or network operation was performed while
authoring this source.

The installation owner supplies a root-owned private tmpfs at
`/run/dotmac-gate0` and root-only cgroup v2 delegation at
`/sys/fs/cgroup/dotmac-gate0`. The protected reviewed `packet.json` must contain
the exact SSH daemon/configuration digests, installation document digests, two
capture coordinate sets, management UID and actual public network facts.
Those settings describe expectations; the root supervisor measures the actual
network before publishing worker context. Its public probes use pinned
`/usr/bin/wg` (`peers`, `allowed-ips` only), `/usr/sbin/ip` (exact route), and
`/usr/sbin/nft` (public ruleset). No WG private or preshared key is queried.
Ruleset review must establish the non-WG Bao drop. The transport independently
checks the actual connected socket before secret bytes. Network mutation after
measurement is excluded by the protected namespace/worker privilege contract;
device/source/peer loss still fails at the socket.

The `network` section has exactly `interface`, `index`, `namespace_device`,
`namespace_inode`, `bao_address`, `local_address`, `peer_public_key`,
`peer_allowed_ip`, `peers`, `route_document`, `nft_ruleset_digest`. `binary_digests` pins
the three fixed public query paths. These fields cannot allocate a new peer,
route, firewall privilege or network capability. They remain unqualified until
the installation owner provides and reviews actual values.

`run-packet.json` is the independent canonical shared run identity; its hash is
`context.packet_digest` on both hosts. `packet.json` is a separate protected
local descriptor containing `shared_run_digest`, actual `machine_id_digest`,
local network expectations and installation document digests. Context records
and rechecks that local file's distinct hash, measured `/etc/machine-id` hash,
and actual namespace. The common identity contains neither local descriptor
nor installation document hashes, so documents embedding its shared digest do
not create a circular hash dependency. Root ownership and measured launch
provenance authenticate these files; their JSON hashes do not authenticate
themselves.

The protected `ssh_endpoints` section supplies each role's exact
`local_address`, `local_port` and `remote_address`. The supervisor checks the
accepted IPv4 stream itself, including `SO_BINDTODEVICE` readback, before
starting sshd. Its local address must equal the measured local WG address.
Caller-selected listener bindings cannot bypass these checks. The fixed binary
paths must be real protected files in the pinned image; a different path or
unqualified symlink refuses and needs an explicitly reviewed image-path change.

Each host establishes its own wall/monotonic origin before bootstrap and maps
the common absolute end once. Worker contexts retain that original origin and
shorten its deadline to the phase's single established cap.
No monotonic value travels in captures. Attester slots are exactly `a_issue`,
`a_consume`, `b_issue`, `b_consume`; each is bounded by 30 seconds and the
original deadline. One accepted TCP stream is passed to the pinned `sshd -i`.
The fixed worker claims its slot using exclusive-create before opening the
fixed protected wrapper file. Sequential SSH channels therefore cannot obtain
a second wrapper, even though `MaxSessions 1` by itself would allow them.

Root switches visibility only among pre-provisioned wrapper files in
`secrets/<fixed-slot>/wrapping-token`; it never mints, refreshes or replaces one.
The root-owned files are group readable only for the active worker's group;
the installation must make every secret parent inaccessible to other groups.
Only `claims/` and the current `status/<slot>/` directory are worker writable.
Capture, installation, context, code/config and secret parents remain root
owned and non-writable. The trusted worker writes one fixed terminal result
through `finish_slot`; missing/refused/ambiguous completion is terminal.

Every worker and transport descendant joins a root-owned per-slot cgroup before
daemon exec. An independent root watchdog stays outside the boundary and kills
it on original deadline or supervisor pipe EOF. This covers native database
connect/pool stalls without inventing a kernel runtime timeout property.
`cgroup.kill` and `cgroup.events` must prove `populated 0` before any advance.
Teardown may take a bounded two-second tail; late results are never accepted.
The reviewed daemon privilege is root for user switching, with a non-root
worker. This source does not grant that operational privilege.

The management receiver connects once to the fixed local `management.sock`.
This is a stream socket with the existing four-byte framing. Parent and worker
check actual `SO_PEERCRED`; parent additionally checks the management cgroup.
It accepts only the two public staged captures, then independently observes
EOF before copying bytes into its own private files. Root atomically activates
both captures with Linux `renameat2(RENAME_NOREPLACE)`, reopens/decodes/hashes
them, and returns the exact `CaptureInstallReadback.document()`. Receiver never
gets an active-directory rename/chown capability. Any duplicate install,
trailing data, expiry or ambiguous response is terminal; no blind retry.
Root also commits that exact readback beside both captures in the same atomic
directory. `capture_coordinates()` obtains the actual capture digest only from
this protected record and compares the other five coordinates to the packet.
The management exchange can carry full coordinates with owner bytes; native
peer UID/cgroup checks authenticate the channel before parent derives that
digest. The readback effective end equals the original common launch end.

Only the supervisor removes ephemeral material after whole-boundary emptiness.
The `supervisor-once` marker prevents a restart within the same private mount.
Cross-reboot restart prevention remains the disabled restart policy and reviewed
operational launch path, not a portable capability or durable approval ledger.
Control/Approvals still own current approval and consumption.

Hosted tests in `test_gate0_finite_launch.py` target the installed wheel and
actual Linux cgroup delegation. They are authored, not executed here. Actual
pinned sshd channel, force-command, custody, WG, capture and native acquisition
proofs belong to the coordinator's integrated hosted bundle; the focused
mechanism tests do not substitute for those qualification receipts.

## Integrated sender and supervisor follow-up

The first source freeze is preserved at
`gate0-finite-launch-source-freeze-20261015`, manifest
`ec6ef8d64c381268761b52748ff233381ac57ad02362daca276a84fef18848a7`.
The follow-up implements the integration review's distinct sender, bounded
network preflight, and strict phase-deadline corrections. It has a separate
freeze and does not replace the first snapshot.

`FiniteGate0Supervisor.from_installed().run()` is the fixed installed owner.
The protected `Gate0FiniteLaunch.v1` packet selects only host role `issuer` or
`attester`. Root opens WG-bound listeners itself, verifies the actual accepted
source/local endpoint and device binding, and charges accepts to original D0.
IDP3 runs one issuer plus its finite capture sender. NS3 runs one management
connection followed by exactly the four predefined attester connections.
Every path closes its listeners and terminates its descendant boundaries.

Network preflight creates its own cgroup and independent original-D0 watchdog
before executing any pinned public tool. Parent reads stdout incrementally with
a one-MiB ceiling and discards stderr. Failure kills/reaps the complete boundary;
successful measurement also proves the boundary empty before custody starts.
Attester's 30-second cap and management/sender's 10-second cap are established
once, passed into context/watchdog/wait, and rechecked before accepting results
or advancing. A zero process exit after that cap still terminates the launch.

The IDP3 `capture_sender` account is distinct from the issuer and is the existing
management key holder explicitly designated in the operational packet. Only its
context can call `open_management_identity()`. The fixed
`management/identity` must be an existing read-only protected mount, owned by
that holder with no group/other access, matching the packet's inode/device and
protected public-key fingerprint. Missing mount, holder or delegation refuses.
The accessor returns an owned read-only FD without reading private bytes;
pinned SSH opens the same immutable fixed path. The source never copies a Mac
root key, mints a key or exposes it to issuer/attester roles.

The issuer exports exactly two owner captures through `issuer-export.sock` and
half-closes its write side. Parent checks native peer UID, PID/start and issuer
cgroup, validates framing/EOF and the packet's five fixed equality coordinates,
then passes those bounded public bytes through a private inherited socketpair
to the fixed capture sender. `open_capture_export()` checks that exact stream's
root-parent peer and inode/device and claims it once; it accepts no caller file.
Sender verifies the NS3 readback and returns that exact framed
`Gate0CaptureInstalled.v1` response on the same socket. Parent compares it,
requires successful sender exit and an empty sender boundary, then relays it
with EOF to the issuer. Only then does the issuer begin serving proof operations.
The sender CLI writes no duplicate stdout acknowledgement.

The issuer packet additionally pins `issuer_uid`, `capture_sender_uid`,
`management_identity`, `cli_digest` and `issuer_sshd_config_digest`. The attester
packet pins `attester_uid`, `management_uid`, `sshd_config_digest` and
`management_sshd_config_digest`. Both use `schema`, `host_role`, `run_end`,
`network`, `binary_digests`, `captures`, `installation_digests`, `ssh_endpoints`
`sshd_digest`, `shared_run_digest` and `machine_id_digest`; unknown top-level
fields refuse. `management_identity` has
exactly `holder_uid`, `device`, `inode`, `public_key_fingerprint`. These are real
installation expectations, not an authorization boolean or new trust root.

The closed `Gate0RunIdentity.v1` common document has `schema`, `run_id`,
`not_before`, `expires_at`, `captures` (a/b, five fixed coordinates), `roles`
(issuer/attester), `controller_ca_fingerprint`, `management_key_fingerprint`.
Each public role record contains exactly `key_id`, `public_key_b64`,
`source_revision`, `image_digest`, `profile_digest`. Before custody,
`require_run_role_terms` compares installation source/image and own/peer public
keys to those common terms. It also hashes the existing build owner's actual
`/app/application_foundation_profile.json` bytes and checks its source revision.
This is the build-time public artifact, independent of runtime installation
JSON. Actual OCI image digest measurement belongs to the external protected
launcher; no image embeds its own future layer/config digest.

## Typed projections and terminal outcomes

The typed correction preserves both preceding snapshots. Its immediate parent
is `gate0-finite-launch-integration-followup-source-freeze-20261015`, manifest
`b4d06c3cdd45ae027cdab0b7b03d92de9818f8d0ad757e7aa5d8c16b43456215`.
Closed field parsers project common run terms, local host descriptors, network
measurements, SSH endpoints, management identity, installation/binary hash maps,
context/export metadata and capture/readback frames before native calls.
Integer fields reject booleans; string, UUID, digest, fingerprint and socket
tuple fields are validated explicitly. No broad casts, `Any` records or typing
exclusions stand in for validation. AST/Ruff checks do not establish strict
mypy success; the installed hosted lane still owes that check.

Nested map keys are fixed too: IDP3 has installation hashes for `issuer` and
`capture_sender`, plus its `issuer` SSH endpoint. NS3 has installation hashes for
the four predefined slots and `management`, plus `management` and `attester`
SSH endpoints. The public tool hash map contains exactly the three fixed
WG/ip/nft paths. Only `sender-claims/` is writable to the designated sender;
the existing root-protected identity mount remains read-only.

Once any actual service worker has started, an execution failure or ambiguous
cleanup raises public `LaunchIncomplete`; the installed adapter reports fixed
status 5 and does not retry. Pre-activation refusal remains refusal. Cancellation
exceptions remain cancellation exceptions, including during failed cleanup.
Successful `sshd -i` exit alone is insufficient evidence of issuer completion:
after custody and descriptors close, the fixed issuer calls
`finish_issuer_success()`, writing one `Gate0IssuerTerminal.v1` record in its
private status directory. Parent requires that exact record alongside daemon
exit zero, then proves the whole boundary empty. Attester `finish_slot` likewise
runs only after custody cleanup. Missing success, worker exit 5 or ambiguous
daemon reporting therefore cannot be presented as a confirmed refusal.


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
