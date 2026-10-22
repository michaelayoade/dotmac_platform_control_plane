# Finite Gate-0 installed service source

This is executable adapter source, with **no accepted operational startup
bindings**. Installing the wheel does not enable either service: `dotmac-platform
gate0 issuer-run` refuses `DATABASE_BINDING_UNQUALIFIED`; `dotmac-platform gate0
attester-session` refuses `TRUSTED_SSHD_BINDING_UNCONFIGURED`. No environment
variable, payload, flag or production test mode enables a provider. A qualified
trusted installation must assemble the typed inputs before invoking the owners.
The frozen CP window and dedicated trusted SSH-worker source contracts are
adopted; this is not a deployable manifest, protected readiness, qualified
session-observation evidence or authority-database qualification.

`gate0_services.assemble_issuer_startup` composes role-local issuer material,
concrete workload admission and an attester public verifier.
Trusted assembly injects the qualified `OwnerWindowReader` kernel runtime
platform session factory; production `IssuerWorker` refuses a factory with a
different identity or no binding. It assembles Control security
once and retains that composition across issue, standing and consume. Neither
payloads nor the service create a database, engine, role, table, approval, ledger,
trust root or issuer identity. The selected CP database must be the same authority
database used by the compatible management/Approvals API and existing relay;
Keycloak and PowerDNS databases are not candidates.

Each stdio frame is a four-byte unsigned network-order length followed by one
strict UTF-8 JSON object. Duplicate object keys, nonfinite numbers, nonobjects,
malformed input, EOF inside a frame and frames over 256 KiB refuse. Each direction
has at most sixteen frames and 2 MiB total payload. Input and output share one
original monotonic deadline. The issuer permits eight submissions in its one
at-most-600-second lifetime. EOF ends it; no restart/rearm exists. The attester
allows one at-most-30-second challenge exchange and requires input half-close
after its response, before proof completion. Additional input is terminal.
SIGTERM, SIGINT and the original process alarm cancel the worker. Providers must
bound their own I/O. The qualified supervisor must enforce the same terminal
deadline for native code that Python signals cannot interrupt.

The closed issuer grammar uses schema `Gate0IssuerSubmission.v1`, `operation`
(`issue`, `standing`, `consume`), and a sensitive `workload_token`. Issue adds
`plan_id`, `command_id`, `proof`. Consume adds `plan_id`, base64 `authorization`,
`proof`. Standing adds base64 `authorization`, `evidence_digest`. No actor is
accepted from the request: trusted management startup supplies its actor
reference. Human Approvals still occur through the existing kernel-authenticated
API and existing owner; neither management submission nor workload identity
fabricates a human decision.

The closed attester begin frame is `Gate0SessionBegin.v1` with `phase`, `plan_id`,
`workload_token`, `authorization` (null for issue; full base64 envelope for consume).
The worker returns `Gate0SessionChallenge.v1` with `challenge_id` and base64
`challenge`. The only response is `Gate0SessionResponse.v1` with that same
`challenge_id` and base64 `sshsig`. The certificate never comes from stdin: it is
parsed from the trusted sshd authentication file and passed to the existing
`AttesterProofProducer`. The producer independently validates certificate, CA,
principal, validity and same-key SSHSIG. A fixed proof bundle returns generated
owner evidence, companion, public transcript and signed session observation.

## Session observation semantics

`Gate0SshSessionObservation.v1` is CP-only. Its signature covers the ASCII
canonical JSON following domain
`dotmac.cp.gate0.ssh-session-observation.v1` and a NUL byte. It binds:

- Exact decoded owner canonical-byte digest and exact public transcript digest.
- Independent authenticated window-record digest and canonical
  `AdmittedOperation` digest, plus phase.
- Fresh server-generated 32-byte random invocation ID encoded as lowercase hex.
- Actual authenticated controller fingerprint, canonical certificate digest and
  CA fingerprint, checked against that operation before the challenge.
- Fixed command identity `dotmac-platform gate0 attester-session`, and UTC
  observed-from/observed-until timestamps around the completed proof exchange.

The resolver verifies current attester trust, signature, exact canonical semantic
message, owner issuance within the observed interval, an interval no longer than
30 seconds and freshness no older than 30 seconds. Existing bounded runtime
registration still independently verifies the unchanged Control evidence,
companion and public transcript. A signed extra field or changed meaning refuses.
This observes use of the key for the attester invocation; it does not observe a
deployment, target connection or later action. No new consumption ledger exists.
Live acceptance remains false until the adopted semantics are operationally qualified.

## Trusted sshd boundary still requires qualification

The metadata parser was checked against official upstream OpenSSH
[V_9_6_P1 auth2.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth2.c#L770)
and [session.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/session.c#L244).
It accepts exactly one `publickey` method followed by one canonical Ed25519
certificate and a newline; other methods, raw keys, multiple methods and trailing
metadata refuse. `SshdSessionReader` anchors lookup to a trusted directory FD,
uses `O_NOFOLLOW`, checks the exact sshd filename shape and requires one regular
0600 login-UID-owned file with stable content metadata and bounded size.

These checks do **not** authenticate code already running as the worker UID:
OpenSSH creates this file as that UID. The dedicated daemon, private temporary
mount, worker UID, executable and environment must be protected by installation.
The default standalone CLI refuses even if a caller manufactures `SSH_USER_AUTH`.
The installation must prohibit client environment overrides and user/system
startup files, require certificate-only auth, disable forwarding explicitly,
disable PTY and user RC, exclude subsystem/shell bypasses and reject nonempty
`SSH_ORIGINAL_COMMAND`. ForceCommand alone does not disable forwarding.

The observed NS3 package version supplied by the coordinator is Ubuntu
`1:9.6p1-3ubuntu13.19`. The coordinator-owned
`conformance/openssh-ubuntu-artifacts.json` now pins exact Ubuntu server/client
archives from Ubuntu snapshot `20261013T000000Z`, before their live-pool retirement.
Ubuntu USN-8721-1 and USN-8928-1 bracket this version on 3 September and
14 October 2026; hosted CI must confirm the same pinned size and SHA-256.
`.github/workflows/gate0-sshd-conformance.yml` verifies those hashes,
extracts binaries, derives binary identities and explicitly invokes this suite
with the installed wheel outside the checkout. Those source bindings require
independent review and successful hosted evidence. Patched-source format,
effective configuration, daemon privilege/worker-UID model and real hosted
acceptance remain qualification duties. No host daemon was changed.

The frozen-window/real-Approvals and approved-at-start NS3 split are now adopted
and implemented in source. Remaining live gates include actual owner-backed
window/database/bootstrap bindings and hosted consume/withdrawal evidence, exact
role-custody seed schema
and approved floors, selected CP database identity/schema/role/record inventory,
qualified same-database management/relay bindings, installed-wheel real-service
evidence, withdrawal convergence and the protected issuer E receipt. Selected
placement is issuer IDP3 / attester NS3; shared Contabo de-risking stays deferred.

## Synthetic hosted launch fixture

The real-sshd fixture uses a root-owned protected parent, root-owned
group-readable 0440 startup material, a read-only root-owned worker script, and
an isolated interpreter. It refuses writable or worker-owned configuration
before a challenge. A root-created read-only lock provides one nonblocking
fixture admission across distinct SSH connections; the lock remains held
through the fixed invocation. This is test-only launch code outside the CP
wheel, not an installed production supervisor or approval authority. The live
daemon/worker separation, private temporary mount and supervisor still require
owner qualification.

Authored cases attempt a complete valid proof exchange with PTY requested,
client environment/startup overrides, concurrent authenticated connections,
worker writes to immutable startup, and remote command execution. User RC and
profile sentinels must remain untouched, while the disposable fixture refuses
an existing system sshrc hook. A separate case deliberately fabricates an auth
file as the worker UID and demonstrates that the parser accepts it: file shape
and ownership checks cannot authenticate already-compromised same-UID code.
These are required hosted tests, not evidence that they ran locally or that
NS3's installed launch boundary is accepted. Artifact/workflow pins are owned
and reviewed separately by the coordinator.

The issuer production assembly requires `OwnerWorkloadAdmission` and exact
frozen-window bytes/digest; the installed issuer entry refuses a static or NS3
snapshot provider. NS3 assembly requires the distinct `ApprovedAtStartAdmission`
and authenticated CP management capture. Legacy unbound mechanism tests remain
explicitly synthetic. Original role/provider deadlines clamp new verifier leaves
and cannot be extended by late construction. The startup factory is still unset,
so no actual issuer/attester image is claimed deployable by these interfaces.
