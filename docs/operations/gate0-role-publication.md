# Immutable Gate0 role image publication

The existing `production-image.yml` publisher has a manual `image_target`
choice. `runtime` remains the default and retains the automatic successful-main
CI path, app acceptance script, repository and
`dotmac-candidate-release-receipt/1` receipt shape. `gate0-role` runs only for a
manual dispatch on `refs/heads/main`, through the existing `production`
environment. This document records source capability; it authorizes no dispatch,
publication, deployment, credential ceremony or host change.

The role job publishes only
`ghcr.io/michaelayoade/dotmac_vendor_control_plane_gate0_role`, from the fixed
Dockerfile `gate0-role` target. Both jobs reuse one whole-steps YAML sequence
anchor; there is one build/accept/publish engine. The existing source-revision
verifier must accept the supplied CI run against current main and every existing
required check, with `installed-sshd` and `role-image` additionally required for
Gate0. Skipped, absent and failed checks retain the verifier's existing refusal
semantics. No live operational input is supplied to the build or smoke.

Before registry authentication, the exact local role candidate must pass
`conformance/gate0_role_image_smoke.py`, mounted read-only, with network disabled,
a read-only root, dropped capabilities and only the smoke's existing
SETUID/SETGID/SYS_CHROOT exceptions. Its profile source revision must match the
independently selected revision. The smoke result must declare
`Gate0RoleImageSmoke.v1`, `passed: true`, and `live_readiness: false`.
The same candidate must also pass the bounded native capability/SSH/spawn/socket
proof through `accept_gate0_network.sh`, in its own network/PID namespace with
only the fixed preflight capabilities and an automatic whole-container deadline.
The wrapper removes only the container ID returned by its own creation and
checks cleanup before success. Its public report is retained and hash-bound
into the role receipt. This synthetic native mechanism proof explicitly does
not qualify full WireGuard installation or live readiness. These checks are
native image acceptance, not an installed IDP3/NS3 launch qualification.

For the role image, the publisher saves the candidate to a local archive and
hashes the actual config JSON bytes, reading bounded regular archive members
without extracting files. It checks the config source label and ordered diffIDs
against the selected source and measured candidate layers. After publication,
it removes local references, pulls the immutable registry reference, checks the
ordered RootFS chain and source label, and requires the manifest's config digest
to equal that accepted config hash. The app retains its existing comparison and
receipt behavior.

Role evidence uses the distinct `gate0-role-release-receipt-<source SHA>` artifact
prefix and `dotmac-gate0-role-release-receipt/1` contract. In addition to the
existing provenance fields, it carries the fixed target/repository, profile and
smoke document digests, and `live_readiness: false`; the corresponding public
profile and smoke documents are retained. It cannot be mistaken for the app's
`release-receipt-<source SHA>` artifact by its existing deploy workflow.

Operational closure still needs an independently approved immutable role-image
reference, real finite native launch qualification on IDP3 and NS3, protected
run/local packets, network and worker permissions, database qualification where
required, custody and current approvals. A successful publication receipt supplies
image provenance only. It neither supplies these inputs nor closes CP Work
Packet E, A8/A9, reverse CA or recovery requirements.

Private qualification transport is separately prepared in the existing
`gate0-sshd-conformance.yml` role job. Its optional manual packet selects only
an encrypted `gate0-role-qualification-runtime` artifact with a distinct
qualification-only receipt. Empty manual, push and PR runs retain public
observations only. The actual role image is built once, smoked and checked by
the existing native network proof, then exported once from its immutable ID;
private inventory/encryption never rebuilds or strips that export.

The closed schemas, roster/link policy, measured runtime keys, bounded cleanup
and fixed source/tool/recipient joins are documented in
[the candidate owner README](../../.github/candidate/README.md#private-role-qualification-retention).
The inner synthetic qualification fixes `live_readiness`,
`installed_native_qualified`, `operationally_accepted` and `gate0_accepted` to
false. Private transport does not satisfy this publication gate or installed
IDP3/NS3 launch guards. A genuine role-scoped GPG qualification record, exact
owner-authorized packet/recipient use and later separately authorized custody
and native qualification remain operational inputs; none are configured or
executed by preparing this source.
