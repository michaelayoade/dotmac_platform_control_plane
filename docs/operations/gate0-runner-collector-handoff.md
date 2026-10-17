# Actual collector root handoff

`OwnedCollectorHandoff` binds/listens once as the actual isolated collector UID
at `/run/dotmac-gate0-collector/session/collector.sock`. It never accepts a
caller channel, peer identity document, join result, readiness flag or process
factory. The installer must provision the private mode0700 session directory
and launch the fixed collector under its existing once marker.

The existing root installation owner must measure that launched process's
actual PID/UID/start, confirm the staging inode, move the **same listening
socket inode** to `/run/dotmac-gate0-handoff/collector.sock`, then write the
root-protected existing receiver descriptor with that actual collector binding.
The installer must qualify receiver-only access through group membership or ACL
if the final socket uses mode0660; initial staging mode is0600. The final parent
remains root-owned and non-writable. Root never substitutes a root-created
listener or predicted/workflow-parent PID. The candidate systemd bootstrap
implements this publication sequence; it has not been installed or natively
qualified. Complete trusted provisioning remains required at execution.

The collector accepts one actual AF_UNIX receiver. Linux SO_PEERCRED, the measured
receiver UID/PID/start, the protected receiver descriptor's self/campaign/cases,
its accepted qualification digest, and the moved socket device/inode must match.
Queued extra connections, replacement, peer swaps and premature EOF refuse.
The already authenticated receiver's normal exit may race buffered B-final
records or the offline join. Once B's three startup phases are complete and its
closed final drain begins, those final reads, the offline join and last EOF read
may retain the original authenticated socket when `/proc` disappears. Kernel
UID/PID, protected descriptor/inode, living-process start checks and rejection of
extra peers remain mandatory; there is no reconnect or peer rebinding. The exact
root/terminal roster and actual final EOF are required. Missing/truncated records,
extra data and data on the final EOF read refuse. A/startup admission stays strict.
The trusted isolated UID/code boundary remains an installation obligation;
process IDs and JSON alone are not portable root authentication.

The existing handoff framing and `RootFrameSequence` owners retain the fourteen
closed root/terminal envelopes. `await_issuer_start(case)` requires NS3 management
then IDP3 issuer listening; `await_attester_start(case)` requires NS3's completed
capture/attester phase. B startup remains unavailable until the actual A join and
successful ACK transmission, and cannot precede B's original not-before.

`complete_case_a` and `complete_case_b` consume concrete owned issuer/issue/
consume sessions and the existing admission expectations. They join exact root
worker-terminal hashes, the actual issuer transcript/outcomes, all proof/bundle
hashes and the signed invocation IDs, capture readback/delivery/post-capture
phase equality, original host/PID/start bindings, exact boundary/daemon/removal
inventories, timely normal daemon exit measurements and guardian quiescence.
Daemon status0..255 is a normal lifecycle observation; it is never a client
success allowlist. Actual issuer client3/EOF and both attester client0/EOF are
separate required measurements. Every SSH/signing owner must close/reap before
the join returns. A's outcome ordinals use issue, issue, consume, consume, consume
proof identities. B's first three outcomes use the issue identity, including its
pre-withdrawal standing query. Its final exact approvals/WITHDRAWN consume refusal
preserves both-null proof/bundle digests when authenticated admission refused
before proof evaluation; an evaluated ApprovalNotHeld path must instead carry the
exact paired consume identities. Partial-null or swapped identities refuse.
The actual root transcript and terminal still bind every outcome/request identity;
no consume evaluation is invented for an early refusal. The evidence core must already have verified and registered
these exact bundles against the public proof authority; this adapter only
reauthenticates their signed observations for the terminal join and never
backdates or refreshes proof registration. Public trust is activated once at
the case's first original-clock startup barrier and retained for the join.

A ACK is generated internally from the successful join and sent before the
original A deadline; only successful send and another original-clock check
unlock B. No caller bytes or boolean can request ACK. B sends no ACK. B final
root/terminal/EOF drain alone may use the existing original B deadline+2-second
cleanup tail. Every phase/SSH completion must still precede original expiry;
no approval, token, SSH operation, signing or trust activation occurs in that
tail. Exact root bytes retain `delivery_status=unconfirmed`; the actual owned
channel supplies delivery evidence. Parsing and hosted fixtures do not establish
installed provenance, prerequisites, publication or Gate0/E acceptance.
