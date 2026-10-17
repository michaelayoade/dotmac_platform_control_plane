# A9 same-job broker source contract

The adopted source method is `github-actions-system-vss-opaque-url.v1`, amendment
SHA256 `8517a5298e5b44de23c3fbda182008cd4889fb1c5e7e0f2efc439afae173c587`.
Supplier source is actions/runner commit
`197ca027b90de199464dee3bb9ff198a1db60967`. This source change does not assert
native qualification, an installed policy, an approved operational packet or
Gate 0 acceptance. Actual native evidence remains an operational HOLD.

The existing root installer is the authority for protected selections and
native qualification. Its protection is root custody, immutable pins and live
measurements; this is not a new signature-verification authority. Runtime never
constructs a native receipt from expected values. Missing, old or mismatched
native records refuse before secret readiness.

## Original attempt order

The fixed root prelaunch receipt and templates are delivered with original
windows, CA and certificates. The existing lifecycle installs certificates from
the collection template before JIT. No final collection/bootstrap descriptor is
needed or permitted then. The listener is bound before the one JIT start.
After accept, the existing GitHub reader authenticates the selected in-progress
job and approved reviewer state; the native owner measures the courier peer.

Root sends `Gate0A9MetadataReady.v1\n`. The fixed courier reads only
`ACTIONS_ID_TOKEN_REQUEST_URL`, then sends canonical
`{schema:"Gate0A9BrokerMetadata.v1",url:<actual bytes>}`. Root validates native
provenance and its independently selected broker policy, then the private
supervisor binder publishes final files create-once and writes the completion
marker last. Root refreshes the same job/reviewer observation and remeasures the
same peer/invocation before `Gate0A9SecretReady.v1\n`. Only then does the courier
read the token, send its original single packet and EOF. Root refreshes again
before retaining the private credential and sending the existing one-byte ACK.
Cleanup deletes the environment key directly without membership/getter reads.
No retry, second JIT, retarget, new clock or extended deadline is introduced.

## Closed records and fixed paths

Root0600 `/run/dotmac-gate0-collector/lifecycle/prelaunch.json` has
`Gate0A9PrelaunchSelection.v1` fields `schema`, `lifecycle_binding_digest`,
`campaign_digest`, `collection_template`, `bootstrap_template`, `broker_policy`,
`collection_native_qualification`, `bootstrap_native_qualification`.
Each input pin is exactly `{path,digest}`. The five input paths are fixed directly
under the collector root with underscore-to-hyphen names and `.json` suffixes.

`Gate0RunnerCollectionTemplate.v1` carries every final immutable collection
field except `broker`, `qualification`, `prelaunch`, `job_broker_binding`, and
`binding_marker`. `Gate0CollectorBootstrapTemplate.v1` carries every immutable
bootstrap field except `collection_installation`, `qualification`, `prelaunch`,
`job_broker_binding`, and `binding_marker`. These are complete actual selections,
not null fields, fabricated future qualifications or placeholder final files.

`Gate0A9BrokerPolicy.v1` has `schema`, `method`, `amendment_digest`,
`supplier_commit`, `origins`, `profile`. Origins are independently installed,
finite exact HTTPS origins; no default or learned origin exists. Profile fields
are `worker_binary`, `shell_binary`, `script_template`, `script_directory`,
`workflow_source_digest`, `worker_pipe_handle_format`. Binary/script pins use
`{path,digest}`. Worker is measured at the root-protected approved
`/opt/dotmac-gate0-jit/bin/Runner.Worker` and its inode/bytes are joined to the
fixed `/run/dotmac-gate0-jit/runner/bin/Runner.Worker` execution path through the
existing qualified read-only mount. Bash's pin is canonical `/usr/bin/bash`;
its argv retains literal `/bin/bash`. Global directory ownership checks remain
strict; job-owned runner ancestry is not passed to the root-only reader. The only supported handle profile is `unix-decimal-fd.v1`, and
actual native evidence must establish it. Worker argv is exactly its pinned
executable, `spawnclient`, two distinct decimal inherited pipe handles. Transient
FD values are measured and retained, not statically invented. Bash argv is
exactly `/bin/bash --noprofile --norc -p -e -o pipefail <actual script>`; its actual
executable and actual generated script bytes must match their protected pins.
The generated script is a `.sh` leaf in the independently selected directory
under the fixed JIT root. No arbitrary command or profile fallback exists.

`Gate0A9StaticNativeQualification.v1` has `schema`, `role`,
`lifecycle_binding_digest`, `campaign_digest`, `prelaunch_selection_digest`,
`template_digest`, `broker_policy_digest`, `runtime_identity`, `native_receipt`.
The root binder checks actual pinned native bytes and exact runtime identity.
Static selection digest is SHA256 of canonical JSON with exactly
`schema:"Gate0A9PrelaunchStaticSelection.v1"` and `selection` equal to the closed
prelaunch record excluding ONLY its two native qualification pins. This avoids
a cycle. Full prelaunch, including both pins, is independently checked and
hashed in the dynamic binding. No security field is omitted from the full join.

`Gate0A9LifecycleNative.v2` extends the existing root0600 lifecycle native owner
with fields `schema`, `boot_id`, `kernel_release`, `runner_tree_digest`,
`systemd_version`, `supplier_observation`, `supplier_review`. The latter pin fixed
root0600 `supplier-observation.json` and `supplier-review.json`. Their closed
`Gate0A9SupplierNativeObservation.v1` / `Gate0A9SupplierNativeReview.v1` fields are
`schema`, `method`, `amendment_digest`, `supplier_commit`,
`prelaunch_selection_digest`, `broker_policy_digest`, `profile_digest`,
`workflow_source_digest`, `evidence`.

Observation evidence consists of actual protected artifact pins for
`listener_clean_inheritance`, `worker_clean_inheritance`,
`all_workflow_environment_scopes`, `startup_hooks`, `preceding_writes`,
`missing_supplier_injection`, `shell_survival`, `executed_script_identity`,
`worker_pipe_handles`, `metadata_first_ipc`. Review evidence has
`supplier_observation_digest` and the exact `reviewed_evidence` digest map.
These external root-reviewed artifacts must actually establish clean inherited
environments, all workflow scopes/hooks/writes, inability to inherit an attacker
URL/token when supplier injection is missing, executed script identity and shell
survival. Assertions such as `qualified:true` are not substitutes. Source code
checks custody/pins/joins; it cannot independently interpret arbitrary native
observation artifacts as proof. Operational review must assess those artifacts.

The native peer owner checks exactly courier → bash → Worker → owned Listener,
including executable inode/bytes, argv, UID/GID/groups, JIT cgroup and stable
PID/start identities, then remeasures. Courier/bash/Worker pidfds are retained
for the one chain alongside Listener's existing owned pidfd. Refresh reuses
those handles; partial measurement failure closes only newly acquired handles.
Native close attempts every owned descriptor and retains cleanup uncertainty. These are current snapshots. They do not
prove past execution or resist same-UID rewrite/restore; the qualified launch
exclusions and executed-script evidence remain necessary.

`Gate0A9JobBrokerBinding.v1` has `schema`, `lifecycle_binding_digest`,
`campaign_digest`, `prelaunch_digest`, `broker_policy_digest`,
`static_native_qualification_digests`, `boot_id`, `jit_invocation_id`,
`selected_job_coordinates`, `github_observation_digest`, `courier_pid`,
`courier_start`, `origin`, `path`, `query`, `original_provisioning_end`. It is a
factual root binding, explicitly not native proof. Opaque supplier path/query
bytes are preserved; no supplier internal identifiers are mapped to REST IDs.
Malformed/ambiguous encoding, ports, userinfo, fragments, duplicate query names
and preexisting audience refuse. Valid opaque bytes initially supplied by the
qualified supplier are allowed; changed bytes after binding refuse.

Final collection v2/bootstrap v3 pin a readable create-once mirror
`a9-prelaunch.json`, `job-broker-binding.json`, and their derived qualifications.
`binding_marker` is the fixed path `job-broker-binding-complete.json` and is not
hashed back into a descriptor. The completion marker schema is
`Gate0A9JobBrokerBindingComplete.v1`, with `schema`, `prelaunch_digest`,
`collection_digest`, `bootstrap_digest`, `binding_digest`. It is published last.
Both final loaders check both descriptor digests, full prelaunch/static/dynamic
joins, and `Gate0A9DerivedInstallationQualification.v1` fields `schema`, `role`,
`template_digest`, `static_native_qualification_digest`,
`job_broker_binding_digest`, `installation_digest`. A derived qualification
records these joins and does not mint a native acceptance claim. Old final
schemas refuse. Final files are root-owned, readable by the isolated collector
where needed; private prelaunch/native review records remain root0600.

The original A→B gating, token counts/audience, timers, cleanup and E export
owners remain in charge. The public E JIT leaf and its schemas are independent
of this A9 handshake. Tests use explicitly synthetic native/OS/GitHub boundaries;
only hosted execution can validate the source composition, and actual native
qualification still requires the separate authorized operational process.
