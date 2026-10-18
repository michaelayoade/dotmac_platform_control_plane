# Gate0 finite root handoff

This source implements the adopted holder-to-A9 delegation. It does not establish
an installed A9 management endpoint, install sshd, authorize host changes, or
qualify a protected campaign. Missing protected inputs refuse construction.

`FixedLaunchHolder.from_installed()` runs as Michael's existing non-root Mac
login identity holding remotely privileged credentials. Real/effective UID must
match and be positive. It derives the canonical home from `pwd`, never HOME,
and reads owner-private `~/.config/dotmac-gate0/handoff.json` through protected,
nonblocking no-follow opens. Private configuration directories are holder-owned
0700; system binaries remain root-owned. Prospective pins must be regular files
before bounded reading, so a mistaken FIFO cannot stall installation loading.
No private key bytes are opened or moved. Missing measured bindings refuse.

The canonical `Gate0HolderInstallation.v1` descriptor has exactly:

- `schema`, `campaign_digest` (SHA256), `holder_uid`, `home`;
- file pins `ssh_binary`, `ssh_add_binary`, `public_identity`, `known_hosts`,
  and `agent_qualification`;
- `public_key_fingerprint`, the exact selected public identity's OpenSSH
  SHA256 fingerprint;
- `agent`: `{path,uid,device,inode,mode,parents}`, where `parents` lists every
  canonical ancestor from `/` through the immediate directory, each exactly
  `{path,uid,device,inode,mode}`;
- `downstream`: `{host, port, user, host_key_alias}`;
- `cases`: exactly A then B, each `{kind, IDP3, NS3}`. Each host has
  `{host, port, user, host_key_alias, binding, activation}`.

The agent's immediate directory must be holder-owned 0700 and the actual socket
must match the pinned UID/device/inode/access mode. Ancestors must match their
measured metadata and be root/holder-owned and protected; the canonical
root-owned sticky `/private/tmp` ancestor is explicitly supported. Socket modes
0600, 0660 or 0666 are accepted only inside that inaccessible immediate directory
and with exact measured mode pins. Metadata establishes endpoint identity under
the trusted-holder assumption, never key lifetime.

The protected `Gate0HolderAgentQualification.v1` receipt has exactly `schema`,
`holder_uid`, `public_key_fingerprint`, `ssh_binary_digest`,
`ssh_add_binary_digest`, `native_receipt_digest`, and `custody_owner_ref`.
This records installation's accepted native custody binding; source does not
claim a receipt or qualified native agent currently exists.

Before **every** new SSH authentication the holder uses the pinned ssh-add
binary and literal pinned socket in a sanitized environment. One small budget,
`min(original case end, now + 2 seconds)`, covers bounded actual `ssh-add -L`
identity output and `ssh-add -T <public identity file>` sign/verify. It requires
exact selected identity, successful actual waits and unchanged socket metadata
before/after; timeout, loss, restart or expiry stops the campaign. Additional
unrelated agent identities are permitted, but SSH selects only the pinned public
identity. SSH keeps BatchMode, disables password/keyboard-interactive, auto-add,
auto-Keychain, certificates, forwarding, proxy and multiplex paths. It never
unlocks/reloads a key or launches the TouchID helper.

The existing presence/load owner remains responsible for human preload/unload
and native bounded-lifetime qualification. Neither a load receipt, identity list
nor successful sign test reports remaining TTL. This source never derives an
agent-expiry timestamp. The actual approved schedule must place all five new
SSH authentications inside that independently qualified bounded load. The
already-established streams remain governed by their own original deadlines.

File pins are exactly `{path, digest}`. A host `binding` has exactly
`host_role`, `case_kind`, `launch_packet_digest`, `local_packet_digest`,
`window_digest`, `machine_id_digest`, `network_measurement_digest`, `not_before`
and `expires_at`. A/B shared packets, windows and all four local packets are
distinct as appropriate; each case's two hosts share its approved interval.
An `activation` has exactly `executable_digest`, `instance_id`,
`qualification_digest`, `image_digest`, `source_revision`. Instance IDs and local
packet digests must be distinct across all four launches. Commands are derived
only as `/usr/local/libexec/dotmac-gate0/<campaign-hex>/<case>-<role>` with the
closed cases `consume-replay` / `withdrawal-later-use` and roles `issuer` /
`attester`. There is no command/path/argv slot and no bare-supervise fallback.
The root installation owner must preinstall and natively qualify four immutable,
argument-free one-shot activations attached to four isolated case/host runtimes,
including actual stdout/EOF/status, distinct protected mounts/cgroups/wrappers
and retained once guards. Source does not install them or infer native proof
from self-consistent activation JSON. A cannot be rewritten/rearmed to become B.

Supervisor PID/start and actual root start are learned from the first actual
root frame and matched across that same owned session, never predicted by a
caller. The full phase codec is `gate0_launch_phase.decode_phase`.

The holder starts NS3 once, forwards its actual `management_listening` frame,
then starts IDP3 once. It concurrently forwards the remaining fixed phases and
final cleanup records. It retains each upstream Popen, stdout EOF and actual
wait result. B requires both its own complete A final records and successful A
management waits, plus the collector's campaign-bound A-join acknowledgement
matching both exact final-byte digests. The holder waits for B's original
not-before; it never refreshes that interval. Every pending phase/use read and downstream write uses its current case's
original end, including the very first A send. A never inherits B's later end.
Only expected final cleanup/terminal/EOF delivery may use that case's fixed
two-second tail. Loss, extra input,
wrong order, timeout, signal or nonzero management exit stops the campaign.
All owned children and streams are attempted on teardown. The first failure
stays sticky while every kill, reap and close is attempted under one common
two-second teardown deadline, without resetting the budget for each child.
A's ACK is capped at A's original expiry; cleanup arriving only in the tail
cannot advance B. There is no retry/reconnect.

`InstalledHandoffReceiver.from_installed()` reads the root-protected canonical
`/run/dotmac-gate0-handoff/installation.json`. Its exact
`Gate0ReceiverInstallation.v1` fields are:

- `schema`, `campaign_digest`, `receiver_uid`;
- `collector`: exact protected `{uid, pid, start}` of the already launched
  isolated collector, using Linux `/proc` start ticks;
- file pins `sshd_binary`, `sshd_config`, `receiver_binary`, `authorized_keys`,
  and `qualification`;
- `holder_public_key` (one canonical plain Ed25519 public key), `holder_source`;
- `cases`: A then B, each exactly `{IDP3, NS3}`, holding the bindings above.

The qualification file is a protected installation receipt, not an untrusted
workflow result. `Gate0HandoffSshdQualification.v1` has exactly `schema`,
`receiver_uid`, `sshd_binary_digest`, `sshd_config_digest`,
`receiver_binary_digest`, `authorized_keys_digest`, `holder_public_key`,
`holder_source`, `source_revision` (40 hex) and `native_receipt_digest`.
It binds accepted native sshd evidence to the exact installed bytes; this
repository does not claim that receipt or installation currently exists.

Installation qualification must establish the actual immutable dedicated account
and forced command, pinned authorized public identity and source restriction,
ExposeAuthInfo, and disabled shell/PTY/subsystem/user RC/client environment and
forwarding. The receiver's plain-key ExposeAuthInfo parser has the same explicit
trusted sshd/fixed-worker assumption as the existing `SshdSessionReader`.
Login-UID-owned authinfo is not protection against compromise of that UID.
Its source is checked against actual sshd `SSH_CONNECTION`; an arbitrary workflow
pipe or JSON `authenticated` field cannot construct the installed receiver.

The receiver connects only to the preinstalled local
`/run/dotmac-gate0-handoff/collector.sock`; installation owns that listener and
protected process launch. Kernel `SO_PEERCRED` must match the exact collector
UID/PID/start binding, and the receiver UID must differ. The fixed
`/run/dotmac-gate0-handoff/receiver` directory belongs only to the receiver at
mode 0700. Its exclusive `claimed` marker persists even on failure; source
never removes or rearms it. Root installation must provision these coordinates
before collection, with no general workflow listener or arbitrary pipe fallback.

Root events preserve exact original bytes in canonical
`Gate0RootHandoff.v1` `{schema,campaign_digest,host,root_b64}` envelopes. Terminal
`Gate0RootHandoffTerminal.v1` envelopes carry
`{schema,campaign_digest,host,root_final_digest,stdout_eof,management_returncode}`
only after actual upstream EOF/wait. There are precisely five root records per
case: two NS3 phases, one IDP3 phase and two finals. Root
`delivery_status=unconfirmed` remains unchanged. A canonical
`Gate0CaseAComplete.v1` ACK has `{schema,campaign_digest,join_digest,
root_final_digests}`, in IDP3/NS3 order. The installed collector sends it only
after its actual verified A session/root join. Codec calls alone confer no
approval, root origin, join acceptance or signing authority.

Qualification follows Strategy A: focused codec/transport/provenance adapter
tests, then the separately authorized actual protected campaign. The unit tests
are source fixtures; they do not replace native sshd or protected evidence.
