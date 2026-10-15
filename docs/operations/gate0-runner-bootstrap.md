# Candidate A9 systemd bootstrap

This source prepares the systemd option in the architecture recommendation. It
is a candidate format and implementation for review, not design adoption,
installed native qualification, source acceptance, campaign permission or E
acceptance. No host/service/credential installation has been performed. Existing
CLI dispatch remains coordinator integration work.

The argument-free `run_installed_bootstrap()` loads only root-protected
`/run/dotmac-gate0-collector/bootstrap.json`. Its closed
`Gate0CollectorBootstrapInstallation.v1` fields are `schema`, `campaign_digest`,
`collection_installation`, `collector_binary`, `collector_gid`,
`collector_groups`, `socket_gid`, `receiver_template`, `qualification`,
`native_receipt`, `source_revision`, `source_files`, `unit_assets`,
`manager_client`, and `manager_binary`. File pins are exactly `{path,digest}`;
all files and their ancestry must be root-owned and immutable to other users.
`manager_client` is fixed `/usr/bin/systemctl`; `manager_binary` must match the
actual PID1 executable. `source_files` contains exactly this bootstrap and the
new fixed credential adapter. `unit_assets` contains the four fixed `.in`
templates in `deploy/gate0-a9`, keyed by their exact unit names. Source revision
is a 40-character lowercase commit. Numeric groups are explicitly selected and
observed; `collector_groups` must include the exclusive socket group. An empty
systemd SupplementaryGroups assignment does not suppress NSS account groups.

The collection pin is fixed to the existing installation path; root parses only
inert launch prerequisites and original windows, never calls the collector-UID
`InstalledRunnerCollection.from_installed()` loader. The child retains that
loader's complete installation/job checks. The receiver template is the exact
existing `Gate0ReceiverInstallation.v1` shape except for `collector`; the source
publishes the actual observed UID/PID/start without changing root-frame/ACK
schemas.

`Gate0A9BootstrapQualification.v1` is a NEW candidate input format, with exactly
`schema`, `campaign_digest`, `installation_digest`, `source_revision`,
`source_files`, `unit_assets`, `manager_identity`, and `native_receipt_digest`.
The installation digest excludes only the qualification pin. Manager identity
contains the actual PID1 executable digest, manager Version, kernel release and
boot ID. Qualification must equal the computed installed pins, actual manager
measurements and exact native receipt hash. Missing or mismatched qualification
refuses before collector launch. Root-protected JSON alone does not establish
native proof: the accepted external installation packet must supply actual
qualified native evidence and its provenance. This schema is a source proposal,
not a new acceptance ledger or an accepted flag.

The system manager owns collector cgroups, descendant termination and reaping.
The only unit names are `dotmac-gate0-a9-bootstrap.service`,
`dotmac-gate0-a9-collector.service`, `dotmac-gate0-a9-deadline.timer` and
`dotmac-gate0-a9-expired.target`. The private transport enforces exact permitted
start/stop/show vectors and the one daemon-reload needed to load create-only
runtime assets. There is no generic command, unit, property, sudo or polkit
interface. Each manager request uses min(the caller's shared absolute deadline,
request-start+2 seconds, D+2). Its body reserves the final0.1 seconds within that
same bound for local client termination/reap/stream closure. A per-request cap
cannot extend the shared startup or normal D deadline. Cleanup independently
attempts wait and every retained stream even when another operation fails;
uncertainty remains refusal. An already reaped or unknown/reusable PID is never
signaled. This concerns only the owned systemctl client, not a waitpid claim for
the systemd-owned collector. The existing root service must already be installed and active; root
verifies its own MainPID, invocation, effective service properties, cgroup and
exact fragment bytes. Native scope must authorize the single manager reload on
a dedicated host with no unrelated pending unit changes.

The collector uses Type=exec, ExitType=main, Restart=no, BindsTo/After the root
bootstrap, KillMode=control-group, immediate SIGKILL forced containment,
Delegate=no, NoNewPrivileges=yes and empty capabilities. There are no stop hooks.
The root service needs its explicitly bounded capabilities, including
CAP_SYS_PTRACE for actual cross-UID `/proc` measurement; this is part of native
review, not permission granted by these files. Candidate startup and stop budgets
are two seconds. The finite root adapter also refuses a collector that is not
bound/listening within its two-second startup observation budget. That one
absolute deadline is passed through start, every show/read, process binding,
listener measurement, socket promotion and receiver publication; each step
checks before and after its work. Nested calls never refresh a two-second
startup allowance. Failure does not silently increase those values.

Root samples wall and CLOCK_MONOTONIC once and derives D from the original frozen
B expiry plus its existing two-second drain. The native one-shot timer uses
OnBootSec=D in that same boot/clock domain, WakeSystem=no, AccuracySec=1us and
RandomizedDelaySec=0. Before collector start, root requires the manager's exact
NextElapseUSecMonotonic and effective timer/expiry-target properties. The timer
remains armed and loaded on exit; fixed claims and existing assets prevent
rearm/restart. RuntimeMaxSec is not used to move D. No 900- or 600-second total
campaign/gap ceiling is invented. Manager scheduling is not hard realtime: late
observations fail. The separate proposed failure cleanup observation budget is two
seconds, capped at min(trigger+2, original B expiry+4); it authorizes no token,
proof, signing, SSH work or normal success. Normal manager/empty/readback and
receipt publication must all finish before D. A show begun before D cannot
return afterward and use the failure tail to claim normal completion.

Only the actual manager MainPID/InvocationID is observed. `/proc` must match
collector UID, start ticks, installed interpreter, exact system.slice cgroup and
qualified supplementary groups. Root proves the bound listening UNIX socket
through `/proc/<pid>/fd` and `/proc/<pid>/net/unix`, without consuming a connection.
The kernel socket inode and filesystem socket inode are separate measurements.
Same-filesystem hard-link publication creates the fixed final socket with no
overwrite, verifies its original device/inode, changes it to collector-owned
0660 with the exclusive socket group, then removes only the checked staging
name. The final root-owned directory is exactly0750 with that group. The existing
receiver descriptor is atomically published root-owned0640 with the same group,
using a private, create-only pending file and fsync. Both nonroot owners therefore
have deliberate read/traverse access. Conflicts and partial claims remain for
explicit disposition; no automatic delete/retry/rearm lifecycle exists.

Only normal collector exit0, matching original invocation, inactive/dead manager
state, MainPID0 and bounded retirement observations can write
`Gate0A9ManagerCompletion.v1`. The record distinguishes an actual held
cgroup.events populated0 observation from an explicit matching qualified manager
retirement result with empty ControlGroup. A vanished filesystem path alone is
never empty proof. Root does not waitpid a systemd child or claim a guardian
reap/cgroup.kill syscall. Forced deadline/crash/stop/incomplete cases produce no
success receipt. A private normal-observation candidate is fsynced before its
final name is linked. Publication, parent-handle closure and the final D check
form one accountable transaction. If closure fails or completes late, a fresh
protected rollback handle attempts removal only of that positively owned new
link; the private candidate/once claims remain. Conflicting or replaced files
are never removed, and cleanup uncertainty remains refusal. A failed or
uncertain producer step cannot be accepted from leftover bytes. The fixed timer
and BindsTo relation supply lifecycle containment
when root cannot run a Python cleanup handler.

The private OIDC source is fixed
`/run/dotmac-gate0-collector/oidc-request-token`, root-owned0600. Source validates
it privately but does not create it. Systemd LoadCredential supplies only
`/run/credentials/dotmac-gate0-a9-collector.service/oidc-request-token`. The
argument-free adapter reads that path, sets the existing private process field
in the actual collector process, invokes the existing owner and clears its
retained environment field. No credential enters argv, unit Environment,
manager properties, diagnostics or journald. Python clearing is not secure
memory erasure; native credential mount/isolation/teardown requires actual
qualification.

This bootstrap does NOT own A/B ephemeral controller key/certificate generation
or file removal, nor the original private OIDC source file's teardown. Manager
populated0 proves no file cleanup. A fixed outer JIT/disposable-runner lifecycle
owner and actual positively owned-inode teardown evidence remain required before
full runner-cleanup/E acceptance. No arbitrary pinned input path is deleted.

## Required native qualification scope

Use a separately approved, dedicated Linux test-server allocation; do not mutate
shared host systemd state or use the workstation/local Docker daemon. The packet
must identify exact systemd/client/kernel versions and binaries, boot ID,
cgroup-v2/PID1 ownership, installed wheel/interpreter/CLI/source/image pins, root
job lifecycle, dedicated collector/receiver UID/GID/NSS memberships, exclusive
socket group and root directory/file ownership, fixed four unit names and
rendered effective properties, protected credential delivery, two-second startup
and cleanup budgets, and retained manager result/retirement access. Absent facts
are refusal, not a skip or fabricated native receipt.

The bounded native recipe must exercise actual setsid/doublefork descendants,
collector normal exit/crash, bootstrap crash/stall, delayed activation and the
original timer/start race, manager stop failure, incomplete populated0/retirement
readback, account group/cgroup escape attempts, and credential non-disclosure in
unit text, manager properties, argv and journal. Confirm actual manager reaping,
all descendant death, no start/rearm after a retained claim, unchanged D after
delayed startup, MainPID/invocation provenance and real same-inode socket/receiver
publication. Forced cases must have no normal completion record. Check files
only where a separately approved lifecycle owner positively owns their exact
inodes; record the outer key/certificate/OIDC teardown gap otherwise. Do not
create a synthetic full Gate0 campaign, reconfigure shared host services or infer
operational acceptance from source tests.

Local verification for this candidate is restricted to AST and pinned Ruff0.6.9.
Unit tests use synthetic manager observations for source predicates and do not
establish actual systemd/kernel behavior. Native execution, CLI integration,
independent source review, design adoption and installed execution approval are
still required.
