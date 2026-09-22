"""CP's authenticated host-admission orchestration seam -- a LEAF module.

This section used to live inside `adapter.py`, "the ONE seam between this
assembly and `dotmac-deployment-control`". It moved out because that file is
not import-light: `adapter.py`'s other seam (the operator workflow that
reconciles a deployment target's delivery-eligibility facts) pulls in
`vendor_cp.approvals.adapter`, `vendor_cp.approvals_authority`,
`vendor_cp.identity` and
`vendor_cp.licensing.delivery_models` at module scope -- and Python executes
every one of those imports the moment anything imports `adapter` at all, this
module's own functions included. A conformance suite for the host-admission
choreography then needs the ENTIRE CP application's dependency closure just to
import five Protocols and one orchestration function, which hides the real
coupling, makes install order part of the proof, and turns what should be a
narrow adapter test into an accidental full-application test.

So this module is its own import boundary, held to it by
`tests/architecture/test_host_admission_adapter_import_boundary.py`: it may
import the standard library and SQLAlchemy, and NOTHING else -- no
`vendor_cp.*` sibling, no `dotmac_deployment_control`, no
`dotmac_deployment_foundation`. A CP-owned wheel built from just this file (and
whatever leaf dependencies it genuinely has) installs with `pip install
--no-deps` and imports cleanly with zero private-registry resolution, which is
exactly what `conformance/test_host_admission_conformance.py` needs to prove
the real choreography without pretending the whole assembly is composed there.

## Why this orchestrates THREE unreleased components with zero import coupling

Control's resolve/admit-and-consume host-admission phases and Foundation's
attestation-pair verification are none of them installable in an ordinary CP
environment today -- `pyproject.toml` pins `dotmac-deployment-control` at
`0.1.0a6`, which pre-dates every name below, and does not depend on
`dotmac-deployment-foundation` at all. Bumping either is deliberately out of
scope for this change: it happens only after a real release exists.

Every collaborator below is therefore expressed as a CP-owned `Protocol`
describing the exact shape this adapter calls, narrow enough that whatever the
real released functions eventually provide satisfies it structurally, with
zero import coupling. This is the same pattern `credential_bootstrap.py`'s
`SecretResolver` and `CredentialAuthenticator` already use, for the identical
reason: a port lets the orchestration be exercised, and its failure paths
proven, without either upstream dependency existing yet.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy.orm import Session


class HostAdmissionContextResolver(Protocol):
    """What CP needs from Control's resolve phase.

    Structurally satisfied by the real `resolve_host_admission_context` once a
    released Control depends on it -- this adapter never imports that
    function directly, only calls whatever is injected in its place.
    """

    def __call__(
        self, db: Session, *, attempt_id: UUID, presentation: object
    ) -> HostAdmissionResolvedContext: ...


class HostAdmissionResolvedContext(Protocol):
    """The narrow slice of Control's resolved context this adapter reads.

    Everything else Control's real context carries is opaque to CP: the whole
    object is passed through to `admit_and_consume` untouched. The one field
    read here is `context_digest`, because it is what binds Foundation's
    verification to the exact context Control resolved -- a verification
    performed against a stale or substituted context is not a verification of
    this admission at all.
    """

    context_digest: str


class AttestationPairVerifier(Protocol):
    """What CP needs from Foundation's verification call.

    Matches `verify_attestation_pair`'s real keyword-only signature
    structurally. A refusal is a raised exception, never a boolean or a
    sentinel value this adapter would have to interpret -- see
    `admit_and_launch_host_source` below for why that refusal propagates with
    no fallback.
    """

    def __call__(
        self,
        *,
        candidate: object,
        installed: object,
        verifier: object,
        trust_policy: object,
        expected_host_identity: str,
        expected_observation_id: str,
        expected_package: str,
        verification_context_digest: str,
        now: datetime,
    ) -> object: ...


class HostAdmissionConsumer(Protocol):
    """What CP needs from Control's admit-and-consume phase.

    Takes the resolved context and the mapped foreign evidence, and is the
    one call that may durably admit and consume the attempt. Its session is a
    SEPARATE transaction from the one `HostAdmissionContextResolver` used --
    see the ordering discussion below for why the two must never overlap.
    """

    def __call__(
        self, db: Session, *, context: object, foreign_evidence: object
    ) -> object: ...


class HostSourceLauncher(Protocol):
    """What happens after a successful, committed consumption.

    CP owns this boundary entirely -- launching a host source is never
    Control's or Foundation's concern, and it is deliberately named so it
    cannot be confused for one of their commands. `admit_and_launch_host_source`
    calls it only after `admit_session` has committed; see that function's
    docstring for why the ordering is load-bearing rather than incidental.
    """

    def __call__(self, staged: object) -> None: ...


@dataclass(frozen=True, slots=True)
class AttestationVerificationInputs:
    """Everything `admit_and_launch_host_source` hands Foundation's verifier,
    except `verification_context_digest` -- that value comes from Control's
    OWN resolved context (`HostAdmissionResolvedContext.context_digest`), not
    from the caller, so it cannot be supplied here without letting a caller
    bind verification to a digest Control never froze.
    """

    candidate: object
    installed: object
    foundation_verifier: object
    trust_policy: object
    expected_host_identity: str
    expected_observation_id: str
    expected_package: str
    now: datetime


def admit_and_launch_host_source(
    *,
    resolve_session: Session,
    admit_session: Session,
    attempt_id: UUID,
    presentation: object,
    resolve_context: HostAdmissionContextResolver,
    verify_pair: AttestationPairVerifier,
    admit_and_consume: HostAdmissionConsumer,
    launch: HostSourceLauncher,
    build_foreign_evidence: Callable[[object], object],
    verification: AttestationVerificationInputs,
) -> object:
    """CP's whole authenticated host-admission sequence.

    Own transaction lifecycle, commit-before-launch ordering, no fallback on
    a Foundation refusal. Five properties, each structural rather than
    incidental:

    1. **Two separate sessions.** `resolve_session` reads Control's context;
       `admit_session` performs the admit-and-consume write. They are never
       the same session, so a resolve-phase read can never be part of the
       same transaction as the write that consumes the attempt.
    2. **Resolve commits before verify.** `resolve_session.commit()` runs
       immediately after `resolve_context` returns, and BEFORE `verify_pair`
       is called at all. Control's own resolve function never commits --
       CP owns transaction sequencing, per this file's module docstring.
    3. **Verify runs with no open session.** By the time `verify_pair` is
       called, `resolve_session` is already committed and `admit_session` has
       not been touched. Foundation's verification is therefore never
       performed inside either transaction's lifetime -- it happens strictly
       between them.
    4. **Admit, then commit, then launch -- in that order, on success only.**
       `admit_and_consume` runs inside `admit_session`; if it raises,
       `admit_session` is left uncommitted for the CALLER's context manager
       or explicit rollback to handle -- this function does not catch, does
       not roll back, and does not launch. `launch` is called only after
       `admit_session.commit()` returns.
    5. **No fallback on a Foundation refusal.** If `verify_pair` raises, the
       exception propagates immediately and `admit_and_consume` is never
       called. There is no alternate path that reaches Control on a
       Foundation failure.

    `build_foreign_evidence` maps Foundation's verification result into
    whatever Control-owned evidence shape `admit_and_consume` expects. A real
    adapter's callable converts Foundation's actual
    `AttestationPairVerificationResultV1` into Control's
    `HostAdmissionForeignVerificationEvidenceV1`; it stays a generic callable
    here so this function keeps zero import coupling to either concrete type.
    """
    resolved = resolve_context(
        resolve_session, attempt_id=attempt_id, presentation=presentation
    )
    resolve_session.commit()

    verification_result = verify_pair(
        candidate=verification.candidate,
        installed=verification.installed,
        verifier=verification.foundation_verifier,
        trust_policy=verification.trust_policy,
        expected_host_identity=verification.expected_host_identity,
        expected_observation_id=verification.expected_observation_id,
        expected_package=verification.expected_package,
        verification_context_digest=resolved.context_digest,
        now=verification.now,
    )

    foreign_evidence = build_foreign_evidence(verification_result)
    staged = admit_and_consume(
        admit_session, context=resolved, foreign_evidence=foreign_evidence
    )
    admit_session.commit()
    launch(staged)
    return staged


__all__ = [
    "AttestationPairVerifier",
    "AttestationVerificationInputs",
    "HostAdmissionConsumer",
    "HostAdmissionContextResolver",
    "HostAdmissionResolvedContext",
    "HostSourceLauncher",
    "admit_and_launch_host_source",
]
