# Finite Gate-0 bootstrap source

This source composes the adopted frozen Control window, existing exact Approvals
hold, role-local OpenBao custody and fixed GitHub JWT verifier. It does not install
an operational packet, issue custody material, qualify a host, open a live service
or approve a rehearsal. Missing measured launch inputs refuse.

`gate0_bootstrap` exposes closed `ActualIssuerInstallation` and
`ActualAttesterInstallation` values, plus `load_issuer_installation`,
`load_attester_installation` and `load_management_delivery_installation`. Loaders
read only the concrete `InstalledLaunchContext.open_installation()` descriptor.
Duplicate keys, unknown fields, noncanonical bytes, wrong types and coordinate
substitution refuse. Preparation validates typed public values before secret or
DB access and compares every field with the protected installed document again.
No configuration field selects a Python module, callback, authority or path.

Before DB, capture or custody access, both preparation paths call the concrete
launch context's `require_run_role_terms` with their source/image and own/peer
public keys. The launch owner compares these with the shared run and measures the
actual build-profile artifact's hash/source against that run. Shared run identity
and independently authenticated local packet/installation digests remain
separate; distinct host-local packets may participate in the same shared run.
`identity.config_digest` remains a protected local declared equality value; the
current role-term port does not compare that field with the measured build-profile
hash. Actual build-profile qualification comes from the artifact/shared-run check,
never an installation JSON self-hash.

`prepare_installed_issuer(context, installation)` qualifies the existing authority
runtime, bootstraps exactly the finite issuer custody profile, creates the actual
owner window reader and exports the two configured plans through that reader's
`read('issue', plan)` holds. `PreparedIssuer` retains the startup, exact custody,
reader, two public captures and effective deadline. It never replaces the
Foundation execution-plan digest with a capture/window hash.

`prepare_installed_attester(context, installation)` obtains actual capture
coordinates from the root-owned committed readback, compares the five preinstalled
scope coordinates and slot phase, and opens the measured protected capture.
`decode_capture` still returns an unauthenticated value; the protected root loader
is the separate authentication boundary. `PreparedAttester` retains the service,
sshd auth-info directory reader, exact custody, effective deadline, fixed phase
and plan. NS3 proves approved-at-start possession; it does not claim a current
Approvals hold. IDP3 checks current standing at point of use.

Both context managers retain custody for the entire service lifetime and close it
on every exit. Protected capture/auth-directory descriptors remain owned until
that exit. The worker opens its fixed wrapping-token file itself, reads one
bounded bare ASCII token, closes the descriptor immediately and never logs or
places the token in argv. There is no automatic renewal or rebootstrap.

Original local wall/monotonic coordinates reach `OwnerWindowReader` and attester
admission through a validated `WindowClockOrigin` before their first read/admit.
Window mappings and caches are never reset. All leaf bounds clamp to the original
trusted launch deadline; fresh service construction cannot extend an earlier
window after wall-clock correction. The finite supervisor must establish native
DB/pool/filesystem cancellation and whole-cgroup cleanup, including detached
transport children; SQL/socket timeouts alone do not establish that boundary.

## Management exchange

`CaptureSelection` pins window/plan digests and plan/target/request UUIDs. The
capture byte digest may be filled only from the authenticated owner export and
then the root-owned committed readback. A hash supplied by a runner is not a grant.

`push_capture_install(context, installation)` requires a distinct `capture_sender`
context. It accepts no caller capture bytes or file. Its sole export source is
`context.open_capture_export()`, the finite parent's authenticated stream from the
issuer's dedicated export pipe. One exact install frame followed by EOF is
validated, sent through one fixed pinned SSH client invocation, then its stdin is
closed. Exact NS3 readback and EOF are required. The sender forwards that same
readback over the retained parent stream and half-closes it. Lost responses never
retry publication.

The fixed client is `/usr/bin/ssh`. Public client configuration and known-hosts
material are under `/run/dotmac-gate0/management/`; `ssh_config` must be exactly
`Host *\n    IdentityFile none\n`, with its independently installed digest. Options
fix batch authentication, the existing selected identity, exact Ed25519 host key,
source WG address and literal destination/port/login. PTY, forwarding, proxy,
multiplexing, local/remote commands, agent/default identities and password prompts
are disabled. No remote command text is sent; recipient sshd owns its fixed forced
command. The existing management private identity remains in its protected
read-only `identity` mount, available only to the distinct sender UID. Python
retains its verified descriptor but does not read or copy key bytes. SSH opens the
fixed immutable path: [OpenSSH 9.6 client source](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/ssh.c)
closes inherited descriptors at startup, so inheriting a key FD is insufficient.

`receive_capture_install(context, channel, selections, absolute_end)` rejects a
command or PTY, requires one bounded request plus EOF before opening the fixed
root management channel, and stages only public data. Root verifies native peer
credentials and packet scope, atomically commits both captures with no-replace
semantics, reopens and verifies them, and returns the exact common-end readback.
The receiver has no active-slot rename/chown capability. Both management and sender
boundaries require the finite supervisor's original ten-second phase clamp; each
attester has its original thirty-second slot clamp and the whole run remains at
most three hundred seconds.

## Qualification still required

Actual source/image/config/SSH pins; target, policies and plans; existing management
identity holder/read-only mount; host key and recipient UID; fixed WG namespace,
peer, route and default-deny firewall facts; real DB coordinates/heads/least
privilege/native bounds; finite supervisor/cgroup/watchdog privileges; per-slot
secret files and finite custody allocations remain installation inputs. Public
JSON cannot qualify any of these facts. Same-host root compromise remains within
the adopted shared-host residual; this source does not claim to remove it.

Authored tests are synthetic hosted-only vectors for closed public values,
substitution, half-close-before-publication, absent EOF, original clocks and actual
scratch PostgreSQL refusal/rollback before secret acquisition. They are not a
measured deployment or operational approval. Local project tests, imports and
builds were not run; hosted typing/tests and independent review remain required.
