# Gate0 A9 collector installation inputs

`InstalledRunnerCollection.from_installed()` reads only the canonical root-owned
`/run/dotmac-gate0-collector/installation.json`. This source does not provision
that installation, qualify its real job, or authorize a protected campaign.
The loader walks held directory descriptors using `O_NOFOLLOW`, `O_DIRECTORY`
and `O_NONBLOCK`; ancestry must be root-owned and not group/other writable.
Leaves must be bounded regular files. Controller private keys must belong to the
isolated collector UID and have no group/other permissions. Every file pin is
exactly `{path,digest}`, with a `sha256:` digest. Installation must keep pinned
inputs immutable through use; pathname metadata cannot defeat compromise of the
trusted isolated UID or root installer. The disk-path pins do not independently
inspect the already loaded code objects, bytecode, or every imported module
origin. Native qualification must establish the actual immutable installed
interpreter, loaded modules and image for the dedicated launch; self-consistent
root JSON or an environment variable cannot discharge that obligation.

The closed `Gate0RunnerCollectionInstallation.v2` descriptor contains exactly
`schema`, `campaign_digest`, `collector_uid`, `receiver_uid`, `origin`, `broker`,
`job`, `source_revision`, `image_digest`, `executable`, `source_files`,
`qualification`, `holder_qualification`, `receiver_qualification`, `cases`,
`withdrawal_reference`, `output_directory`, `marker`, `prelaunch`,
`job_broker_binding`, and `binding_marker`.

Collector and receiver UIDs are positive and distinct. The actual real/effective
UID must match the collector. The executable pin must match Linux
`/proc/self/exe`. `source_files` has exactly `gate0_runner_installation`,
`gate0_runner_tokens`, `gate0_runner_ssh`, `gate0_runner_handoff`,
`gate0_runner_collector_handoff`, `gate0_runner_controller`, and
`gate0_collection`: root-protected file
pins for the corresponding installed Python source files alongside the loader. The source revision is 40 lowercase
hex; the image is a SHA256 digest. Root installation qualification binds these
installed coordinates to its accepted native receipt; source makes no claim to
observe an image registry or establish job isolation from environment variables.

`job` has exactly the frozen-window GitHub fields (`iss`, `aud`, `repository`,
`repository_id`, `repository_owner_id`, `environment`, `ref`, `workflow_ref`,
`workflow_sha`, `event_name`, `run_id`, `run_attempt`, `sub`,
`environment_node_id`) plus `runner_group_id` and `runner_name`. Both frozen
windows must match every GitHub field. The loader compares actual GitHub runtime
variables, including run/attempt/workflow SHA, repository and owner identifiers,
and actual `RUNNER_NAME` and protected-launch `RUNNER_GROUP_ID`. These variables
are restrictive comparisons under the installed dedicated job/UID/code trust
boundary; their names confer no provenance themselves.

`qualification` pins a canonical `Gate0RunnerCollectionQualification.v1`
record containing exactly `schema`, `campaign_digest`, `collector_uid`,
`receiver_uid`, `job`, `source_revision`, `image_digest`, `executable_digest`,
`installation_digest`, `holder_qualification_digest`,
`receiver_qualification_digest`, `broker`, and `native_receipt_digest`.
`installation_digest` hashes the canonical descriptor with only `qualification`
removed. `broker` is the exact origin/path/query and qualification digest.
The receipt is an input from the existing trusted installer, never a workflow
claim, acceptance boolean, or qualification performed by this loader.

There are exactly two `cases`, A then B. Each contains exactly `shared_packet`,
`frozen_window`, `command_id`, `hosts`, `ssh_binary`, `keygen`, `private_key`,
`certificate`, `known_hosts`, `issuer_trust`, and `attester_trust`. `hosts` has
exactly `IDP3` and `NS3`; each contains `binding`, `local_packet`, `endpoint`.
`binding` uses the existing `RootHostBinding` fields. The loader checks exact
shared/local/window/case/capture/machine terms. Its network measurement digest
is a protected expected binding and must later join the actual root measurement;
it is never synthesized from network configuration. `endpoint` has exactly
`host`, `port`, `source`, `user`, `host_key_alias`; IP/port/source match the
corresponding local packet SSH endpoint. Both binaries have fixed system paths.
Certificate key/CA fingerprints, digest, principal and original interval match
the frozen controller; certificate duration is at most the frozen 600s ceiling.
A/B controller keys, leases, certificates, commands, windows, plans, approvals,
shared packets and four local packets are distinct. A ends before B starts.

Each public trust term contains exactly `record`, `floor`, `source_ref`, and
`qualification`. Record/floor/qualification are root-protected pins. The exact
existing trust record contains `version`, `trusted_key_ids`, `revoked_key_ids`.
The durable floor has `key_id`, `minimum_version`, `source_ref`; the version
must meet it and the packet-pinned public key must be eligible. No role private
key is loaded. Trust-state and verifier construction are deferred to case use.
The two inert projections share one original wall/monotonic sample; their
independent not-before/deadline values never move. `case.ssh` is also deferred
until its case is open. No B token, approval, verifier, or socket opens at load.

`broker` contains exactly `origin`, `path`, `query`, `qualification`. Root's
same-job binder freezes actual supplier URL bytes after the metadata handshake;
`qualification` pins the dynamic binding and does not assert native acceptance.
The installed job URL must equal the bound origin/path/query. Root separately
pins finite exact HTTPS origins and the adopted opaque supplier provenance
method. See [the same-job contract](gate0-a9-same-job-broker.md) for the mandatory
native evidence, ancestry, schemas and acyclic joins. There are no wildcard hosts,
path-prefix grants or invented mappings to REST job IDs. Query ambiguity/audience
checks run before the request token is read. Original URL bytes are preserved.
`InstalledJobTokens.from_installed()` privately binds the actual request token.
Each `next(case.projection)` makes one owned spawned GET, appending only audience
`urn:dotmac:gate0:rehearsal-issuer`. Request/read/EOF/child completion share
`min(original case deadline, now+5s)`. The body is at most 64KiB and has exactly
`value`, a JWT of at most 32KiB. The existing projection response owner requires
status200, bounded headers, explicit framing, no redirect and actual EOF. There
is no proxy lookup, environment TLS override, secret argv, logging or retry.
Cleanup completes before IPC success; failure is sticky and clears the retained
request credential. Attempts are capped at 8 A and 23 B, including failures.
Unverified claim comparisons only restrict output; servers own signature checks.
The campaign controller must withhold every B use until its owned A join and
successfully sent ACK.

Output and marker coordinates are fixed to
`/run/dotmac-gate0-collector/session/evidence` and
`/run/dotmac-gate0-collector/session/claimed`. The existing collector/handoff
owners must exclusively create and retain the once marker, create private
0700/0600 evidence, validate the actual listener/receiver peer, preserve exact
bytes and finish both root/session joins. `withdrawal_reference` selects the
predeclared human B evidence; it does not perform withdrawal. Collection success
is not Gate0/readiness acceptance or immutable encrypted publication proof.
