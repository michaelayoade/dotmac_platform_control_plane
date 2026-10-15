# A9 root supervisor integration — source candidate

This source joins the finite lifecycle and collector owners. It does not qualify
a host, accept E, approve publication, attest artifact transfer or replace the
off-host allocation/registration retirement owner. The two fixed argument-free
entries are `gate0 lifecycle-run` and `gate0 lifecycle-retire-jit`; CLI wiring is
owned separately. Missing actual protected installation/native evidence refuses.
No native service, runner, key generation, signing, upload or host action was run
while preparing these sources.

## Actual manager topology

`dotmac-gate0-a9-lifecycle.service` owns the outer root coordinator. Its ExecStart
is `lifecycle-run` and fixed ExecStopPost is `lifecycle-retire-jit`.
`dotmac-gate0-a9-jit.service` and `dotmac-gate0-a9-bootstrap.service` both
BindsTo/After the lifecycle unit. The JIT unit is independent of normal bootstrap
exit, so its protected job can still encrypt/upload after collector retirement.
Bootstrap remains its own actual MainPID and retains its own unchanged original
collector deadline/timer. It is never called as a function inside the outer
process.

The installer installs the five selected fixed unit files and owns its narrowly
scoped manager reload before outer start. New source templates are under
`deploy/gate0-a9/`. They use the pinned CLI path, dedicated courier UID/GID/groups,
and the immutable original finalization time in microseconds. The bootstrap
owner alone still create-only publishes/reloads its existing collector/timer/
expired assets; the installer must not precreate those names. Outer/JIT assets
have different names. No manager reload or arbitrary unit/command capability is
exposed by the supervisor.

The outer timer uses absolute `OnBootSec` equal to original `finalization_end`,
1us accuracy, zero random delay, and conflicts with lifecycle, bootstrap and JIT.
Its actual effective properties are read back before generating secrets. There
is no new 900-second budget, reanchor, collector deadline borrowing, or normal
success during a failure tail. Every manager client request intersects its
applicable original bound with two seconds and reserves 0.1 seconds inside that
end for actual child reap. The existing bootstrap cleanup-request owner is
reused; output is capped and zero exit/EOF/wait are required.

The supervisor checks actual manager bytes/version, boot/kernel, its own
MainPID/InvocationID, UID/GID, interpreter executable, cgroup and effective
capabilities. Its exact bounding set includes CHOWN, DAC_OVERRIDE, FOWNER, KILL,
SETGID, SETUID and SYS_PTRACE, with no SYS_ADMIN or ambient capabilities.
ExecStopPost is a distinct manager ControlPID in the same lifecycle cgroup and
must have its exact fixed argv. Effective BindsTo/After relationships are checked
for both subordinates. The separately qualified bootstrap capability boundary
is retained. Actual parent-namespace immutable runner mounts must already exist:
unit-private `BindReadOnlyPaths` does not satisfy the lifecycle's pre-start mount
verification. The installer owns mounts; no arbitrary mount API is added.

## Fixed input proposal and native boundary

Root0600 `/run/dotmac-gate0-collector/supervisor-installation.json` is closed:
`schema=Gate0A9SupervisorInstallation.v1`, `lifecycle_installation_digest`,
`source_digest`, `cli`, `interpreter`, `systemctl`, `manager`, `unit_assets`,
`qualification_digest`. Executable pins use existing `{path,digest}` with a
sha256-prefixed digest and must match the actual lifecycle launcher selection.
`systemctl.path` is exactly `/usr/bin/systemctl`. `source_digest` binds the
installed `gate0_runner_supervisor.py`; lifecycle source/launcher qualification
remains independently checked by its existing owner.

`unit_assets` has exactly `lifecycle_service`, `lifecycle_timer`,
`lifecycle_expired_target`, `jit_service`, `bootstrap_service`. Each pin points to
its code-fixed basename in `/run/systemd/system`. JIT bytes also match its
existing launcher unit digest. The initial bootstrap service can be installed
before the later final campaign `bootstrap.json`; its added outer dependency
changes the bytes and requires new actual bootstrap qualification.

Fixed root0600 `supervisor-qualification.json` is a candidate closed format:
`schema=Gate0A9SupervisorQualification.v1`, `installation_digest`,
`source_digest`, `boot_id`, `kernel_release`, `systemd_version`,
`runtime_identity`, `unit_assets`, `native_receipt_digest`.
`installation_digest` hashes canonical installation excluding
`qualification_digest`, avoiding a circular pin. Runtime identity is exactly
`{uid,gid,cap_eff,executable_digest,cgroup}` and is compared with actual observed
root process facts. The receipt digest binds fixed root0600
`supervisor-native.json`, whose real native measurement/review provenance is an
external installer responsibility. Matching JSON cannot qualify itself. These
source formats/profile checks are available for review; no accepted lifecycle,
operational adoption, native receipt or qualification is generated here.

## Sequential journal and credential delivery

All three root entries that can recover/write the lifecycle journal share one
fixed `/run/dotmac-gate0-collector/lifecycle-owner.lock`. It is a create-once,
nofollow root0600 regular inode with one link. Its empty bytes are never read as
a nonempty protected document: ownership comes from actual FD metadata and
bounded nonblocking `flock`, with a same-inode pathname check after acquisition.
A PID field cannot take over the lock.

Outer holds it while it creates keys, publishes canonical public selections,
waits for the trusted installer's final delivery marker, installs certificates,
creates its own original JIT configuration and receives original job OIDC.
`lifecycle/public-keys.json` is create-only root0600 with exact schema
`Gate0A9ControllerPublicSelections.v1`, lifecycle/campaign digests and A/B keys
(`case_kind`, ASCII public key, controller fingerprint); no private bytes or
secret hash is exported.

Delivery waits only until original `provisioning_end` for root0600
`lifecycle/delivery.json`. Its exact `Gate0A9LifecycleDelivery.v1` fields are
`schema,lifecycle_binding_digest,campaign_digest,collection_installation_digest,
bootstrap_installation_digest,ca_digest,certificate_a_digest,certificate_b_digest`.
It binds actual fixed collection/bootstrap installation and CA/certificate
bytes. The trusted installer writes the inputs first and marker last. Wrong,
changed, missing or late inputs refuse; the marker is not native qualification.

Original encoded JIT configuration comes only from systemd credential
`/run/credentials/dotmac-gate0-a9-lifecycle.service/jit-config-delivery`, at most
65536 bytes. A separate literal-path reader opens the protected
`/run/credentials` root and the outer service directory/file with nofollow FDs,
allows that service directory to cross onto its actual read-only credential
filesystem, and requires a root-private directory and stable root0400 regular
file. Original provisioning-end guards apply before/after reads and closure;
ordinary lifecycle directory device restrictions are unchanged. It is loaded
from the provisioner's fixed protected
`/run/dotmac-gate0-provisioner/encoded-jit-config`. Lifecycle's existing
`_install_original_jit_config` creates/journals its own source inode. The delivery
source and its external retirement remain the actual provisioner's ownership;
no pathname adoption or arbitrary deletion is inferred. No token enters unit
Environment, argv, output or this public-key document.

The existing `receive_original_job_credential` binds/journals/listens before
starting one actual JIT unit, obtains reader-owned PROTECTED_JOB_STARTED facts,
checks the concrete peer and ACKs original OIDC. The supervisor does not start
JIT twice or reconstruct authenticated job facts.

Outer closes its lifecycle handles, discards the stale instance, and releases
the lock **before** starting bootstrap as a service. It measures the new actual
bootstrap MainPID/UID/start/executable/cgroup/InvocationID and waits for that
exact invocation to become inactive before later journal recovery. Original
JIT InvocationID comes from the concrete lifecycle owner before close. After
that invocation naturally ends, outer reacquires/reloads and performs actual
owned JIT retirement; only then can its root entry return normal. Nonzero
bootstrap/JIT exits remain failures after safe retirement.

## Same-manager file cleanup and private export

Bootstrap's normal empty/normal-exit predicate is retained. Before closing its
manager, it obtains that manager's one-shot `CollectorRetirementFact`, takes the
shared journal lock, loads a recovered lifecycle, and passes the actual manager
and identity-owned fact to `retire_owned_files`. It inspects the exact raw return:
a failure document never becomes `owned_files_retired`. Recovered handles and
lock close before final manager closure; original bootstrap cutoff still bounds
all normal actions. There is no reconstructed fact from exported JSON.

After failure, only an actually bound collector can yield a same-manager empty
retirement fact, using the existing original cleanup bound. That fact can permit
safe file cleanup/documentary failure export; it never creates a normal receipt.
The one-shot retirement attempt is tracked, including refusal, and cannot be
reissued in except/finally. If there was no bound invocation or no measurable
retirement, only a bounded failure observation may be published. Root timer and
off-host allocation fallback remain armed; no private-file removal is invented.

Separate `/run/dotmac-gate0-collector/export` is root0750 with the dedicated
courier GID. Files are create-only root0640, nofollow, bounded/fsynced and
published by same-inode hardlink with no overwrite. In-bound failed publication
can roll back only the exact owned final inode. Every rollback directory-open,
metadata/read, unlink and fsync step consumes the same original deadline. After
expiry or identity/FD uncertainty, the documentary artifact is retained and the
operation refuses; no fresh cleanup time or accepted output is inferred. FD
closure remains best-effort resource cleanup, not permission for more filesystem
work. Native timer/syscall latency remains a qualification obligation. The export
is outside the lifecycle's deletable roster. Documentary files are `collector-retirement.json` (the exact
fact observation) and `owned-files-retirement.json` (the exact lifecycle return).
After normal measured collector death and successful file retirement, the fixed
collector-owned `session/evidence/collection.json` is read stably through
nofollow FDs, at most 8 MiB, then copied unchanged as `export/collection.json`.
Pending acceptance/readiness fields are never rewritten.

`manifest.json` is LAST: `Gate0A9PrivateCollectionExport.v1`, lifecycle/campaign
digests, actual `bootstrap_invocation_id`, exact emitted three-file roster with
`{bytes,digest}`, `result=retained_bytes_exported`. Failure has separate
`failure.json` and no invented success manifest. The receiving job must check
root ownership/nonwrite modes, fixed names/lengths/hashes; these documents remain
private evidence bytes, not manager capabilities or prerequisite acceptance.

The job prepares/encrypts/uploads under its existing selected evidence owner and
then exits; it cannot wait for its own later JIT retirement. Root publishes that
later actual JIT retirement separately as root0600 `lifecycle/jit-retirement.json`.
It is not inserted into an already sealed archive or made a self-inclusive hash.
A repeated manager post-stop path must remeasure the native owned invocation;
existing bytes alone cannot authorize retirement or restore ownership. Off-host
GitHub read-back still verifies producer/run and actual encrypted Actions bytes,
and the provisioner separately observes registration removal/guest-volume
retirement. Missing transfer proof does not extend the original allocation bound.

## Verification owed

Local checks are AST parsing and exact Ruff0.6.9 only. Authored hosted tests cover
original timer readback/refusal, fixed manager vocabulary, same-manager/live-fact
ordering and failure documents, unchanged collection bytes/manifest-last, actual
lock exclusion/empty-lock semantics, no-overwrite/FIFO export refusal, expired
publication and source unit topology. Repair tests additionally use actual
credential directory/file FDs with explicit mocked separate-device/read-only
metadata, reject writable/wrong-owner/mode/symlink/FIFO/oversized/changed/late
delivery, and show failed/late delivery cannot start JIT. Publication clocks
advance during link, directory fsync and close: no rollback filesystem action
may start after the original end; positive in-bound rollback and foreign-inode
preservation remain covered. They use explicit mocks and grant no native
qualification. Bootstrap tests now exercise file handoff before manager close and
one-shot retirement under failure.

Dedicated separately authorized native qualification must prove actual systemd
properties, capability set, original timer behavior, crash/unknown-start/lock
handoff, same-manager collector/cgroup retirement, actual owned-file absence,
credential isolation, bounded EOF/reap and private export delivery on the exact
installed sources/assets. Whole-allocation teardown and external source/JIT/
custody/campaign/workflow/preparation inputs remain genuine required operations.
No source-only PASS substitutes for those observations.
