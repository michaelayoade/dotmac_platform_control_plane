# A9 raw native fixture source preparation

The installed commands `dotmac-platform gate0 native-metadata-observe` and
`dotmac-platform gate0 native-url-presence` prepare one isolated observation.
They do not qualify an installation or issue a native receipt. Source tests are
synthetic; the official GitHub runner, supplier injection, inheritance, workflow
scopes, preceding writes, hooks and shell survival still need actual external
native observation and independent review by the existing root installer owner.
There is no operational adoption or host execution authorization in this source.

The observer requires root with exactly `PATH=/usr/bin:/bin` and `LC_ALL=C`.
It reads a root:root0700 `/run/dotmac-gate0-native-fixture` and a canonical,
root:root0600 `selection.json`. It accepts no argument or override. All CP
identities use the existing `sha256:<64 lowercase hex>` grammar; administrative
artifact manifest SHA-256 values use bare hexadecimal. Existing production
selection and qualification schemas are unchanged.

The closed `Gate0A9NativeFixtureSelection.v1` fields are `schema`,
`procedure_digest`, `case`, `fixture_id`, `boot_id`, `original_bounds`,
`courier_selection`, `preliminary_inventory`, `broker_policy`, `runtime_pins`,
`listener`, `coordinates`, `github_observation`, and `negative_probe`. The case
is `metadata-positive` or `missing-url-negative`. Fixed protected pins refer to
actual installed files; there are no default origins, placeholder qualifications,
future file hashes or success assertions. Duplicate/unknown/missing JSON fields,
unprotected files, symlinks and oversized inputs refuse.

`runtime_pins` closes over `observer_module`, `cli`, `interpreter`, `bash`,
`listener`, `worker`, `runner_tree_digest`, `workflow` and `script_template`.
The Listener pin names the existing runtime binary below the intentionally
courier-owned runner directory; the unchanged read-only mount verifier joins it
to its protected `/opt/dotmac-gate0-jit` source and the measured live executable.
The observer never weakens the globally root-only protected-file reader.
The preliminary `inventory.json` is `Gate0A9NativeFixtureInventory.v1` with
`disposition=UNQUALIFIED`, actual boot/kernel/system-manager provenance, runner
tree digest, canonical runtime-pins digest and observation time. It contains no
selection digest, avoiding a cycle. Its actual bytes supply the public courier
launcher's receipt-digest field solely for the existing courier's data parser;
it must never be installed as `lifecycle-native.json` and production refuses it.

An external owner launches the separately approved actual Listener and selects
its actual PID/start independently. This source cannot launch, register, stop or
signal a runner, create a unit/cgroup, fetch a credential or contact GitHub.
The fixture cgroup is the distinct literal `/dotmac-gate0-a9-native-fixture`;
production continues to require its existing systemd JIT cgroup. Both use the
same finite read-only chain measurement predicates. Exact Listener argv remains
`Runner.Listener run --startuptype service`. Worker pipe arguments retain their
existing decimal FD grammar. Bash uses literal `/bin/bash --noprofile --norc -p
-e -o pipefail`, with a protected executable pin at `/usr/bin/bash`.

The external authenticated-read owner supplies create-once
`github-observation.json` while the courier waits. Its closed
`Gate0A9NativeFixtureGitHubObservation.v1` packet binds selected coordinates,
owner/read-provider identities, approved selected environment, in-progress job,
exact workflow bytes and protected job/review/workflow evidence pins. Coordinates
are independently present in selection, including repository/run/attempt; none
is learned from the late packet. Age is at most the selected limit, capped at
30 seconds and the original provisioning deadline. The observer holds and
rechecks the same file identity/bytes, boot and wall/monotonic bounds before
readiness. It neither refreshes a packet nor resets a clock.

The observer claims `attempt` with O_EXCL before binding the existing literal
courier socket `/run/dotmac-gate0-collector/courier/oidc.sock`. It refuses existing
attempt/output/socket, late-packet or production lifecycle/collection/bootstrap
files. These absence checks are local observations, not proof of global
isolation. No retry or rearm exists. Only the exact socket inode this attempt
created is removed; attempts and completed evidence persist for the external
owner. The observer never unlinks a preexisting or replaced socket.

Before readiness, the observer retains pidfds for courier, bash, Worker and the
independently selected Listener and remeasures current identities, argv, groups,
cgroup, executable hashes/inodes and the generated-script join. It enumerates
at most 256 bash descriptors and requires exactly one matching regular,
read-only script FD with a positive read position within a bounded 65536-byte
script. It retains that FD, uses offset-independent reads and rechecks the
actual FD, pathname identity, hash, position and process. There is no fd255
assumption, pathname-only fallback, tracer or environment-value inspection.
These measurements do not establish historical execution or resistance to an
arbitrary same-UID rewrite/restore attack; those are explicit external evidence
obligations in the adopted supplier threat model.

Exactly one metadata readiness frame is sent. The positive case receives one
canonical broker-metadata frame, checks the existing strict opaque URL parser
against independently installed finite exact HTTPS origins, and closes. The
negative case requires EOF with zero metadata. Ancillary descriptors,
truncation, early payload/EOF, extra peers, malformed metadata, expiry or changed
inputs refuse. There is no secret-readiness, ACK, token getter, HTTP or collection
phase. The existing courier therefore refuses and cleans its token variable
without reading it. Retained pidfd readiness establishes courier exit only;
its expected exit code 3 needs separate parent-wait or authenticated completion
evidence, and is not invented by this observer.

The URL-presence probe iterates environment names only. It prints exactly
`Gate0A9UrlPresence.v1 absent` and exits 0 when the literal URL name is absent;
it prints `present` and exits 3 for a present name, including an empty value;
it prints `unavailable` and exits 4 on failure. It never retrieves a URL or token
value. The negative script template allows only substitution of the measured
installed CLI path: the probe simple command is immediately followed by the
courier simple command and `builtin exit`. Under pinned bash `-e`, courier
arrival supports the explicitly labelled `pinned-errexit-control-flow` absence
inference. No child exit receipt or direct root environment observation is
fabricated. A later separately pinned negative workflow must explicitly select
`id-token: none`; this source adds no execution-repository workflow.

A completed root:root0600 `observation.json` has schema
`Gate0A9NativeFixtureObservation.v1` and completion `CASE_OBSERVED`. It records
selected/procedure/GitHub digests, finite process rows, retained script FD facts,
finite protocol events and actual courier-exit readiness. Positive URL metadata
contains only frame/path/query digests and the independently allowed origin;
raw URL/path/query and environment values are not retained or printed. Negative
output records the pinned-control-flow inference. Output is bounded at 131072
bytes, create-once, and published only after owned resource cleanup. Exit 0
means this bounded case was observed, 3 means policy/protocol refusal, and 4
means unavailable/incomplete measurement. It is never native acceptance.

The explicit hosted conformance runs the stdlib test program via stdin inside
the existing installed runtime image with `--cap-add SYS_PTRACE --network none
--user 0:0`, no host mounts and no credentials. This one disposable conformance
container needs the capability for actual cross-UID `/proc` descriptor reads;
it grants no production permission and uses neither privileged mode nor host PID
sharing. It checks installed module origins, exact courier
metadata/EOF refusal, probe empty/nonempty/absent cases and actual Linux bash
script-FD mechanics under synthetic direct lineage. Unit canaries target closed
records, selected/fresh GitHub evidence, token-value traps, descriptor mutations,
create-once writes, protocol refusals and cleanup. Existing broker-chain/public
JIT tests remain required. Tests are authored for hosted execution and were not
run locally. Source changes require refreshed installed source/runtime pins and
independent review before any separately authorized native operation.
