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

The V3 successor path below is the startup-bound
`compose_foundation_v3_providers` pair. It uses Control 0.1.0a16's public
`FoundationDispatchConsumptionV1` and sole
`admit_and_consume_host_admission` finalizer, plus Foundation b273337d's
`HostSourceAdmissionTrace`/`ControlConsumptionRequestV3` contract, through
constructors/functions installed once by the successor composition. The older
`admit_and_launch_host_source` helper remains a pre-V3 choreography reference;
the V3 providers never call it and have no alternate consume/launch path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import datetime
from typing import Any, Protocol, cast
from uuid import UUID

from sqlalchemy.orm import Session


class HostAdmissionAdapterUsageError(ValueError):
    """The caller misused `admit_and_launch_host_source` itself -- never a
    refusal from Control or Foundation. Kept distinct from either package's
    own refusal types so a caller cannot mistake a wiring mistake here for a
    security refusal upstream."""


class DispatchApprovalSubjectUnavailable(Exception):
    """Dispatch refused: the plan requires approval, and no approval barrier exists.

    C2 holds an approval FOR SHARE through every approval-dependent Control
    transition, so that a withdrawal cannot commit in the window between the
    check and the effect. A FOUNDATION_EXECUTION plan has no Approvals subject
    type yet, so there is nothing to hold at dispatch. Michael decided on
    2026-09-26 (C2-D1) that dispatch FAILS CLOSED for any plan that requires
    approval, or that cannot be found, until Gate 3 defines that subject. This
    is a refusal, not a wiring mistake, so it is deliberately not a
    `HostAdmissionAdapterUsageError`.
    """

    code = "c2_dispatch_approval_subject_unavailable"


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
    """The narrow slice of Control's resolved context this adapter reads
    directly, plus the additional slice its `build_trust_policy` caller
    needs (opaque to this Protocol -- see that parameter's own docstring).
    Everything else Control's real context carries is opaque to CP: the
    whole object is passed through to `admit_and_consume` untouched."""

    context_digest: str
    host_id: str
    attempt_id: UUID
    dispatch_id: str
    expected_foundation_package: str


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
    """Everything `admit_and_launch_host_source` hands Foundation's verifier
    that is NOT derivable from Control's resolved context -- just the two
    envelopes, the injected cryptographic verifier, and the trusted clock.
    Every value Control's resolved context already carries
    (`expected_host_identity`, `expected_observation_id`, `expected_package`,
    `verification_context_digest`, and the trust policy itself) is now
    derived by `admit_and_launch_host_source` directly from `resolved`,
    never accepted from a caller -- closing the gap an independent security
    review found: a caller could previously supply ANY value for these,
    with nothing downstream (in CP or in Control) comparing it against what
    Control actually resolved. See `build_trust_policy` below for why the
    trust policy specifically needs one more level of indirection than the
    plain string fields."""

    candidate: object
    installed: object
    foundation_verifier: object
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
    build_trust_policy: Callable[[HostAdmissionResolvedContext], object],
    verification: AttestationVerificationInputs,
) -> object:
    """CP's whole authenticated host-admission sequence.

    Own transaction lifecycle, commit-before-launch ordering, no fallback on
    a Foundation refusal. Six properties, each structural rather than
    incidental:

    1. **Two separate sessions, ENFORCED.** `resolve_session` reads Control's
       context; `admit_session` performs the admit-and-consume write. Passing
       the same object for both is refused with `HostAdmissionAdapterUsageError`
       before either is touched -- not merely a convention this function
       assumes, because the `resolve_session.commit()` in property 2 below
       would otherwise commit whatever unrelated work a shared, caller-owned
       session already had in flight.
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
    6. **Every verification expectation is derived, never caller-supplied.**
       The digest, the host identity, the observation id, the package, and
       the trust policy handed to `verify_pair` are all computed from
       `resolved` -- Control's own resolved context for this attempt -- not
       from `verification` or any other caller input. A caller therefore
       cannot bind verification to an expectation Control never actually
       resolved.

    `build_foreign_evidence` maps Foundation's verification result into
    whatever Control-owned evidence shape `admit_and_consume` expects. A real
    adapter's callable converts Foundation's actual
    `AttestationPairVerificationResultV1` into Control's
    `HostAdmissionForeignVerificationEvidenceV1`; it stays a generic callable
    here so this function keeps zero import coupling to either concrete type.

    `build_trust_policy` maps `resolved` into whatever Foundation-shaped
    trust policy object `verify_pair` expects. A real adapter's callable
    reads `resolved.candidate_root`/`resolved.installed_root`/
    `resolved.candidate_audience`/`resolved.installed_audience` -- fields on
    Control's real context object, opaque to this Protocol and to this file
    -- and builds a real `AttestationTrustPolicy`. It stays a generic
    callable here for the identical zero-import-coupling reason
    `build_foreign_evidence` does: Foundation's `AttestationTrustPolicy` is a
    Foundation type this leaf module must never import.
    """
    if resolve_session is admit_session:
        raise HostAdmissionAdapterUsageError(
            "resolve_session and admit_session must be two separate sessions -- "
            "this function commits resolve_session before Foundation "
            "verification runs, and committing a session the caller is still "
            "using for other work would commit that unrelated work too"
        )

    resolved = resolve_context(
        resolve_session, attempt_id=attempt_id, presentation=presentation
    )
    resolve_session.commit()

    verification_result = verify_pair(
        candidate=verification.candidate,
        installed=verification.installed,
        verifier=verification.foundation_verifier,
        trust_policy=build_trust_policy(resolved),
        expected_host_identity=resolved.host_id,
        expected_observation_id=resolved.dispatch_id,
        expected_package=resolved.expected_foundation_package,
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


@dataclass(frozen=True, slots=True)
class HostAdmissionObservation:
    """Current evidence from a startup-installed CP/host observer, not a request."""

    attempt_id: UUID
    presentation: object
    candidate: object
    installed: object


@dataclass(frozen=True, slots=True)
class ControlFoundationV3Bindings:
    """Control's exact public functions and DTO constructors, bound at startup.

    CP pins Control 0.1.0a16, which exports these symbols; the successor
    composition passes its public objects in. This leaf never imports a private
    Control API or selects an implementation during an execution request.
    """

    resolve_context: Callable[..., object]
    finalize: Callable[..., object]
    attest_pair: Callable[..., object]
    lookup_committed: Callable[..., object]
    #: Control's public `get_plan`. Dispatch reads the plan's approval
    #: requirement from it before finalizing (C2-D1: fail closed).
    get_plan: Callable[..., object]
    foreign_root_type: Callable[..., object]
    foreign_evidence_type: Callable[..., object]
    execution_context_type: Callable[..., object]
    consumption_request_type: Callable[..., object]


@dataclass(frozen=True, slots=True)
class FoundationHostV3Bindings:
    """Foundation's real F2 function/types, fixed once by the successor lane."""

    admit_host_source: Callable[..., tuple[object, object]]
    trust_policy_from_context: Callable[[object], object]
    verifier: object
    trace_type: type[object]
    pair_result_type: type[object]
    consumption_request_type: type[object]
    execution_context_type: type[object]


@dataclass(frozen=True, slots=True)
class FoundationV3Sources:
    """Trusted local factories/observers; none is selected by a request.

    ``sessions`` returns a fresh raw Kernel-owned platform Session each time,
    not a commit-on-exit wrapper. This adapter explicitly commits each phase
    and closes the Session with its context manager.
    """

    sessions: Callable[[], Session]
    host_admission: Callable[[], HostAdmissionObservation]
    execution_context: Callable[[], object]
    clock: Callable[[], datetime]


class _ControlReceiptAttester:
    __slots__ = ("_attest",)

    def __init__(self, attest: Callable[..., object]) -> None:
        self._attest = attest

    def attest_pair(
        self,
        *,
        authorization_material: object,
        dispatch_material: object,
    ) -> dict[str, object]:
        receipt = self._attest(
            authorization_material=authorization_material,
            dispatch_material=dispatch_material,
        )
        # Control's public FoundationSignedReceiptV2 is a frozen dataclass.
        if not is_dataclass(receipt) or isinstance(receipt, type):
            raise HostAdmissionAdapterUsageError("Control returned no typed receipt")
        return {
            "schema": "AuthorizationReceipt.v2",
            **cast(dict[str, object], asdict(cast(Any, receipt))),
        }


class _FinalizationContinuation:
    """In-process identity binding, not a serialized bearer credential."""

    __slots__ = (
        "owner",
        "context",
        "execution_facts",
        "pair",
        "trace",
        "resolution_session",
    )

    def __init__(
        self,
        owner: object,
        context: object,
        execution_facts: object,
        pair: object,
        resolution_session: Session,
    ) -> None:
        self.owner = owner
        self.context = context
        self.execution_facts = execution_facts
        self.pair = pair
        self.trace: object | None = None
        self.resolution_session = resolution_session

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("host-admission finalization is transient")


def _field(value: object, name: str) -> Any:
    """Read a member of an upstream public DTO without importing its wheel."""
    try:
        return getattr(value, name)
    except AttributeError as exc:
        raise HostAdmissionAdapterUsageError(
            f"upstream host-admission contract lacks {name}"
        ) from exc


def _foreign_evidence(pair: object, control: ControlFoundationV3Bindings) -> object:
    def root(value: object) -> object:
        return control.foreign_root_type(
            public_key_fingerprint=_field(value, "public_key_fingerprint"),
            root_version=_field(value, "trust_root_version"),
            key_id=_field(value, "key_id"),
            algorithm=_field(value, "algorithm"),
            purpose=_field(value, "purpose"),
            custody_domain=_field(value, "custody_domain"),
            issuer=_field(value, "issuer"),
        )

    return control.foreign_evidence_type(
        candidate_attestation_envelope_digest=_field(
            pair, "candidate_attestation_envelope_digest"
        ),
        installed_attestation_envelope_digest=_field(
            pair, "installed_attestation_envelope_digest"
        ),
        verification_context_digest=_field(pair, "verification_context_digest"),
        verified_host_identity=_field(pair, "expected_host_identity"),
        verified_observation_id=_field(pair, "expected_observation_id"),
        verified_package=_field(pair, "expected_package"),
        verified_candidate_audience=_field(pair, "candidate_audience"),
        verified_installed_audience=_field(pair, "installed_audience"),
        verified_candidate_root=root(_field(pair, "candidate_root")),
        verified_installed_root=root(_field(pair, "installed_root")),
    )


class _FoundationV3Provider:
    __slots__ = ("_owner", "_control", "_foundation", "_sources", "_attester")

    _CONTROL_FACTS = (
        "product_code",
        "environment",
        "target_id",
        "target_ref",
        "operation",
        "release_ref",
        "rollout_ref",
        "plan_id",
        "approval_decision_ref",
        "control_plan_digest",
        "execution_sequence",
        "attempt_no",
    )

    def __init__(
        self,
        owner: object,
        control: ControlFoundationV3Bindings,
        foundation: FoundationHostV3Bindings,
        sources: FoundationV3Sources,
    ) -> None:
        self._owner = owner
        self._control = control
        self._foundation = foundation
        self._sources = sources
        self._attester = _ControlReceiptAttester(control.attest_pair)

    @property
    def attester(self) -> _ControlReceiptAttester:
        return self._attester

    def observe(self) -> object:
        facts = self._sources.execution_context()
        if type(facts) is not self._foundation.execution_context_type:
            raise HostAdmissionAdapterUsageError(
                "actual Foundation V3 execution context required"
            )
        return facts

    def now(self) -> datetime:
        return self._sources.clock()

    def consume_dispatch(self, *, request: object) -> None:
        if type(request) is not self._foundation.consumption_request_type:
            raise HostAdmissionAdapterUsageError("exact Foundation V3 request required")
        trace = _field(request, "host_source_trace")
        continuation = _field(trace, "opaque_finalization")
        if (
            type(trace) is not self._foundation.trace_type
            or not isinstance(continuation, _FinalizationContinuation)
            or continuation.owner is not self._owner
            or continuation.trace is not trace
            or _field(trace, "pair_verification_result") is not continuation.pair
            or type(continuation.pair) is not self._foundation.pair_result_type
        ):
            raise HostAdmissionAdapterUsageError("unrecognized F2 continuation")
        resolved = continuation.context
        pair = continuation.pair
        dispatch_id = _field(resolved, "dispatch_id")
        if (
            _field(trace, "host_observation_id") != dispatch_id
            or _field(pair, "expected_observation_id") != dispatch_id
            or _field(request, "control_consumption_ref")
            != f"control-dispatch:{dispatch_id}"
        ):
            raise HostAdmissionAdapterUsageError("F2 dispatch coordinate changed")
        facts = self.observe()
        if facts != continuation.execution_facts:
            raise HostAdmissionAdapterUsageError(
                "execution observation changed since F2 resolution"
            )
        if (
            _field(facts, "target_id") != str(_field(resolved, "target_id"))
            or _field(facts, "target_ref") != _field(resolved, "target_ref")
            or _field(facts, "host_id") != _field(resolved, "host_id")
            or _field(facts, "host_incarnation")
            != _field(trace, "installed_signer_fingerprint")
            or _field(facts, "host_enrolment_ref")
            != _field(trace, "installed_trust_root_version")
        ):
            raise HostAdmissionAdapterUsageError("current target or host changed")
        expected_context = self._control.execution_context_type(
            **{
                name: _field(continuation.execution_facts, name)
                for name in self._CONTROL_FACTS
            }
        )
        execution = self._control.consumption_request_type(
            authorization_material_json=_field(request, "authorization_material_json"),
            dispatch_material_json=_field(request, "dispatch_material_json"),
            expected_context=expected_context,
            expected_execution_plan_digest=_field(
                request, "expected_execution_plan_digest"
            ),
            control_consumption_ref=_field(request, "control_consumption_ref"),
        )
        foreign = _foreign_evidence(pair, self._control)
        with self._sources.sessions() as session:
            if session is continuation.resolution_session:
                raise HostAdmissionAdapterUsageError(
                    "F2 resolution and V3 finalization require separate sessions"
                )
            self._refuse_an_approval_requiring_plan(
                session, _field(continuation.execution_facts, "plan_id")
            )
            self._control.finalize(
                session, context=resolved, foreign_evidence=foreign, execution=execution
            )
            session.commit()
        # No fallible work follows the successful Control commit.

    def _refuse_an_approval_requiring_plan(
        self, session: Session, plan_id: object
    ) -> None:
        """C2-D1: fail closed at dispatch until a Foundation plan has an
        Approvals subject that a barrier could hold.

        The plan id comes from the observed execution facts, the same value
        that becomes `expected_context.plan_id`. Control's `finalize` refuses a
        coordinate mismatch between that context and the plan it locks, so the
        plan checked here is the plan that would be consumed. A malformed id,
        a missing plan, or a plan without an explicit `requires_approval=False`
        all refuse before `finalize` is called.
        """
        try:
            parsed = UUID(str(plan_id))
        except ValueError as exc:
            raise DispatchApprovalSubjectUnavailable(
                f"dispatch plan id {plan_id!r} is not a UUID"
            ) from exc
        plan = self._control.get_plan(session, parsed)
        if plan is None:
            raise DispatchApprovalSubjectUnavailable(
                f"dispatch plan {parsed} does not exist"
            )
        if getattr(plan, "requires_approval", True) is not False:
            raise DispatchApprovalSubjectUnavailable(
                f"dispatch plan {parsed} requires approval, and FOUNDATION_EXECUTION "
                "plans have no Approvals subject for the C2 barrier to hold; "
                "dispatch fails closed until Gate 3 (C2-D1)"
            )

    def lookup_committed(self, *, control_consumption_ref: str) -> object:
        """Read Control's typed committed marker after a crash, never reconsume."""
        with self._sources.sessions() as session:
            return self._control.lookup_committed(
                session, control_consumption_ref=control_consumption_ref
            )


class _FoundationHostSourceProvider:
    __slots__ = ("_owner", "_control", "_foundation", "_sources")

    def __init__(
        self,
        owner: object,
        control: ControlFoundationV3Bindings,
        foundation: FoundationHostV3Bindings,
        sources: FoundationV3Sources,
    ) -> None:
        self._owner = owner
        self._control = control
        self._foundation = foundation
        self._sources = sources

    def admit_host_source(self) -> tuple[object, object]:
        observed = self._sources.host_admission()
        if type(observed) is not HostAdmissionObservation:
            raise HostAdmissionAdapterUsageError("typed host observation required")
        with self._sources.sessions() as session:
            resolved = self._control.resolve_context(
                session,
                attempt_id=observed.attempt_id,
                presentation=observed.presentation,
            )
            session.commit()
        # Session A has closed. Foundation reads its own installed artifact and
        # verifies the real pair with no Control transaction open.
        host_source, trace = self._foundation.admit_host_source(
            candidate=observed.candidate,
            installed=observed.installed,
            verifier=self._foundation.verifier,
            trust_policy=self._foundation.trust_policy_from_context(resolved),
            expected_host_identity=_field(resolved, "host_id"),
            expected_observation_id=_field(resolved, "dispatch_id"),
            expected_package=_field(resolved, "expected_foundation_package"),
            verification_context_digest=_field(resolved, "context_digest"),
            now=self._sources.clock(),
        )
        if type(trace) is not self._foundation.trace_type:
            raise HostAdmissionAdapterUsageError("actual Foundation F2 trace required")
        pair = _field(trace, "pair_verification_result")
        if (
            type(pair) is not self._foundation.pair_result_type
            or _field(trace, "host_observation_id") != _field(resolved, "dispatch_id")
            or _field(pair, "expected_observation_id")
            != _field(resolved, "dispatch_id")
            or _field(pair, "verification_context_digest")
            != _field(resolved, "context_digest")
        ):
            raise HostAdmissionAdapterUsageError("F2 result is not bound to Control")
        execution_facts = self._sources.execution_context()
        if type(execution_facts) is not self._foundation.execution_context_type:
            raise HostAdmissionAdapterUsageError(
                "actual Foundation V3 execution context required"
            )
        if (
            _field(execution_facts, "target_id") != str(_field(resolved, "target_id"))
            or _field(execution_facts, "target_ref") != _field(resolved, "target_ref")
            or _field(execution_facts, "host_id") != _field(resolved, "host_id")
        ):
            raise HostAdmissionAdapterUsageError(
                "execution observation disagrees with F2 resolution"
            )
        continuation = _FinalizationContinuation(
            self._owner, resolved, execution_facts, pair, session
        )
        bound_trace = replace(cast(Any, trace), opaque_finalization=continuation)
        continuation.trace = bound_trace
        return host_source, bound_trace


@dataclass(frozen=True, slots=True)
class FoundationV3ProviderPair:
    host_source: _FoundationHostSourceProvider
    execution_authority: _FoundationV3Provider


def compose_foundation_v3_providers(
    *,
    control: ControlFoundationV3Bindings,
    foundation: FoundationHostV3Bindings,
    sources: FoundationV3Sources,
) -> FoundationV3ProviderPair:
    """Bind F2 and V3 to one startup trust set and one Control finalizer."""
    if not all(
        callable(value)
        for value in (
            control.resolve_context,
            control.finalize,
            control.attest_pair,
            control.lookup_committed,
            control.get_plan,
            foundation.admit_host_source,
            foundation.trust_policy_from_context,
            sources.sessions,
            sources.host_admission,
            sources.execution_context,
            sources.clock,
        )
    ):
        raise HostAdmissionAdapterUsageError("startup composition is incomplete")
    owner = object()
    return FoundationV3ProviderPair(
        host_source=_FoundationHostSourceProvider(owner, control, foundation, sources),
        execution_authority=_FoundationV3Provider(owner, control, foundation, sources),
    )


__all__ = [
    "AttestationPairVerifier",
    "AttestationVerificationInputs",
    "DispatchApprovalSubjectUnavailable",
    "HostAdmissionAdapterUsageError",
    "HostAdmissionConsumer",
    "HostAdmissionContextResolver",
    "HostAdmissionResolvedContext",
    "HostSourceLauncher",
    "admit_and_launch_host_source",
    "HostAdmissionObservation",
    "ControlFoundationV3Bindings",
    "FoundationHostV3Bindings",
    "FoundationV3Sources",
    "FoundationV3ProviderPair",
    "compose_foundation_v3_providers",
]
