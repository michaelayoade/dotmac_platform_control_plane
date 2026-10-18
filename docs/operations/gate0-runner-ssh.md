# Finite A9 controller SSH owner

`gate0_runner_ssh` owns one actual subprocess per issuer or attester invocation.
It accepts no process factory, caller descriptors, command override or signer.
The issuer exposes its own `FramedCaseCollector`; the installed collector must
reuse that instance so `finish()` inspects the actual exchanges. Finish requires
a terminal consume owner refusal, no earlier refusal/incomplete outcome, EOF and
actual client status 3. The collector still checks the exact case-specific refusal
code, ordinal, authorization, proof and complete transcript before acceptance.

The attester sends the fixed Begin frame, checks canonical challenge bytes and
all `AdmittedOperation` fields, challenge identity/nonce and the original case and
30-second expiry bounds. It invokes only `/usr/bin/ssh-keygen -Y sign -f` with the
case controller private key and namespace `dotmac-gate0-possession-v1`, sends the
response, then half-closes input. Its exact canonical bundle must bind that
challenge, certificate and actual signature. EOF and actual client status 0 are
required before bundle and invocation ID become available. After actual child
wait, both the original case and narrowed challenge channel deadline must remain
open, and the retained completion time must be strictly before that deadline. Existing public proof
and signed-observation verifiers remain mandatory: parsing is not signature trust.
Client 5/255, signals, truncation, trailing frames, output loss and timeout are
incomplete. Every signing/SSH child belongs to the same owner and cleanup budget;
no retry or new deadline is created. Close cancels process groups and reaps them
under a common maximum two-second cleanup tail.

`close_owned_sessions(*sessions)` accepts only concrete issuer/attester owners.
It closes their aggregate children under one shared cleanup end derived from the
retained installation deadlines, including every signal, wait and stream-close
attempt after a failure. Owners become closed before cleanup starts; failure is
sticky and a repeated close refuses without retrying or signalling their PIDs.
Already reaped children are never signalled. This helper accepts no process,
deadline, reset or broader process-tree authority from the controller.

SSH uses literal installed IP/source/port/user, explicit identity/certificate,
two exact pinned Ed25519 known-host aliases, strict host-key checking and a null
configuration file. The command vector ends at the fixed destination and sends
no remote command; the qualified server ForceCommand selects the service,
consistent with the session reader refusing every nonempty SSH_ORIGINAL_COMMAND.
Agent, proxy, multiplexing, forwarding, PTY, password,
interactive authentication and local command execution are disabled. Environment
is closed and credentials never enter argv except protected key/certificate paths.
No service signing material or privileged management credential is accepted.

`RunnerSshInstallation` is an inert constructor input, **not authenticated
installation evidence**. Local file hashes/ownership checks constrain bytes; they
do not prove who selected them, protected process ancestry or approval. The
separately qualified installer must bind the protected A9 job/source/image,
original clock mapping and approved A/B packets; provision fresh distinct A/B
controller keys/certificates; protect files and their containing directories from
replacement throughout invocation; verify executable build pins, exact server
keys, endpoint/source restrictions and dedicated server forced-command policy;
and establish the authenticated root-phase/final-output handoff. A9 must never
receive a management launch identity. These source adapters alone neither enable
installed collection nor establish E acceptance. Tests are hosted qualification
fixtures and do not supply installed provenance.
