"""Startup-fixed CP F2/V3 composition: one Control finalizer, no fallback."""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from vendor_cp.deployment.host_admission_adapter import (
    ControlFoundationV3Bindings,
    FoundationHostV3Bindings,
    FoundationV3Sources,
    HostAdmissionAdapterUsageError,
    HostAdmissionObservation,
    compose_foundation_v3_providers,
)


@dataclass(frozen=True)
class _Root:
    public_key_fingerprint: str = "fingerprint"
    trust_root_version: str = "enrolment-1"
    key_id: str = "key"
    algorithm: str = "ed25519"
    purpose: str = "host"
    custody_domain: str = "host_attester"
    issuer: str = "issuer"


@dataclass(frozen=True)
class _Pair:
    candidate_attestation_envelope_digest: str = "sha256:candidate"
    installed_attestation_envelope_digest: str = "sha256:installed"
    verification_context_digest: str = "context"
    expected_host_identity: str = "host-1"
    expected_observation_id: str = ""
    expected_package: str = "foundation"
    candidate_audience: str = "candidate-audience"
    installed_audience: str = "host-1"
    candidate_root: _Root = field(default_factory=_Root)
    installed_root: _Root = field(default_factory=_Root)


@dataclass(frozen=True)
class _Trace:
    host_observation_id: str
    installed_signer_fingerprint: str = "fingerprint"
    installed_trust_root_version: str = "enrolment-1"
    pair_verification_result: _Pair | None = None
    opaque_finalization: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class _Request:
    authorization_material_json: bytes
    dispatch_material_json: bytes
    host_source_trace: _Trace
    expected_execution_plan_digest: str
    control_consumption_ref: str


@dataclass(frozen=True)
class _Receipt:
    dispatch_id: str


@dataclass(frozen=True)
class _Facts:
    product_code: str
    environment: str
    target_id: str
    target_ref: str
    operation: str
    release_ref: str
    rollout_ref: str
    plan_id: str
    approval_decision_ref: str
    control_plan_digest: str
    execution_sequence: int
    attempt_no: int
    controller_ssh_fingerprint: str
    host_id: str
    host_incarnation: str
    host_enrolment_ref: str


class _TrackedSession(Session):
    def commit(self) -> None:
        self.info["events"].append("commit")
        if self.info.get("fail_commit"):
            raise RuntimeError("commit failed")
        super().commit()

    def close(self) -> None:
        self.info["events"].append("close")
        super().close()


def _composition(
    *,
    fail_verify: bool = False,
    fail_finalizer: bool = False,
    fail_second_commit: bool = False,
    reuse_session: bool = False,
):
    events: list[str] = []
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE marker (id TEXT NOT NULL)"))
    sessions: list[_TrackedSession] = []
    attempt_id = uuid4()
    dispatch_id = str(attempt_id)
    resolved = SimpleNamespace(
        attempt_id=attempt_id,
        dispatch_id=dispatch_id,
        target_id=UUID("00000000-0000-0000-0000-000000000001"),
        target_ref="target-1",
        host_id="host-1",
        expected_foundation_package="foundation",
        context_digest="context",
    )
    facts = _Facts(
        product_code="product",
        environment="test",
        target_id=str(resolved.target_id),
        target_ref="target-1",
        operation="deploy",
        release_ref="release",
        rollout_ref="rollout",
        plan_id="plan",
        approval_decision_ref="approval",
        control_plan_digest="sha256:plan",
        execution_sequence=1,
        attempt_no=1,
        controller_ssh_fingerprint="controller",
        host_id="host-1",
        host_incarnation="fingerprint",
        host_enrolment_ref="enrolment-1",
    )
    current_facts = [facts]

    def sessions_factory() -> Session:
        if reuse_session and sessions:
            return sessions[0]
        session = _TrackedSession(bind=engine)
        session.info["events"] = events
        session.info["fail_commit"] = fail_second_commit and len(sessions) == 1
        sessions.append(session)
        return session

    def resolve(session: Session, *, attempt_id: UUID, presentation: object) -> object:
        assert attempt_id == resolved.attempt_id and presentation == "presentation"
        session.execute(text("SELECT 1"))
        events.append("resolve")
        return resolved

    def admit(**kwargs: object) -> tuple[object, object]:
        assert [item.in_transaction() for item in sessions] == [False]
        assert events[-1] == "close"
        assert kwargs["expected_observation_id"] == dispatch_id
        assert kwargs["verification_context_digest"] == "context"
        events.append("foundation")
        if fail_verify:
            raise RuntimeError("Foundation refused")
        pair = replace(_Pair(), expected_observation_id=dispatch_id)
        return "source", _Trace(
            host_observation_id=dispatch_id, pair_verification_result=pair
        )

    def finalize(
        session: Session,
        *,
        context: object,
        foreign_evidence: object,
        execution: object,
    ) -> object:
        events.append("finalize")
        assert context is resolved
        assert foreign_evidence.verified_observation_id == dispatch_id
        assert foreign_evidence.verification_context_digest == "context"
        assert foreign_evidence.verified_installed_root.root_version == "enrolment-1"
        assert execution.expected_context.target_id == str(resolved.target_id)
        assert execution.expected_execution_plan_digest == "sha256:execution"
        assert execution.control_consumption_ref == f"control-dispatch:{dispatch_id}"
        if (
            fail_finalizer
            or execution.authorization_material_json != b"auth"
            or execution.dispatch_material_json != b"dispatch"
        ):
            raise RuntimeError("Control refused")
        session.execute(text("INSERT INTO marker VALUES (:id)"), {"id": dispatch_id})
        return object()

    control = ControlFoundationV3Bindings(
        resolve_context=resolve,
        finalize=finalize,
        attest_pair=lambda **_: _Receipt(dispatch_id),
        lookup_committed=lambda _db, **_: _Receipt(dispatch_id),
        foreign_root_type=lambda **values: SimpleNamespace(**values),
        foreign_evidence_type=lambda **values: SimpleNamespace(**values),
        execution_context_type=lambda **values: SimpleNamespace(**values),
        consumption_request_type=lambda **values: SimpleNamespace(**values),
    )
    foundation = FoundationHostV3Bindings(
        admit_host_source=admit,
        trust_policy_from_context=lambda _: object(),
        verifier=object(),
        trace_type=_Trace,
        pair_result_type=_Pair,
        consumption_request_type=_Request,
        execution_context_type=_Facts,
    )
    sources = FoundationV3Sources(
        sessions=sessions_factory,
        host_admission=lambda: HostAdmissionObservation(
            attempt_id, "presentation", object(), object()
        ),
        execution_context=lambda: current_facts[0],
        clock=lambda: datetime(2026, 9, 25, tzinfo=UTC),
    )
    providers = compose_foundation_v3_providers(
        control=control, foundation=foundation, sources=sources
    )
    return providers, events, sessions, engine, resolved, current_facts


def _request(
    trace: _Trace,
    dispatch_id: str,
    *,
    auth: bytes = b"auth",
    dispatch: bytes = b"dispatch",
) -> _Request:
    return _Request(
        authorization_material_json=auth,
        dispatch_material_json=dispatch,
        host_source_trace=trace,
        expected_execution_plan_digest="sha256:execution",
        control_consumption_ref=f"control-dispatch:{dispatch_id}",
    )


def _marker_count(engine: object) -> int:
    with engine.connect() as connection:  # type: ignore[attr-defined]
        return connection.execute(text("SELECT count(*) FROM marker")).scalar_one()


def test_f2_closes_session_before_real_verification_and_v3_commits_before_return() -> (
    None
):
    providers, events, sessions, engine, resolved, _ = _composition()
    source, trace = providers.host_source.admit_host_source()
    assert source == "source"
    assert trace.pair_verification_result is not None
    assert trace.opaque_finalization is not None
    assert "opaque_finalization" not in repr(trace)
    with pytest.raises(TypeError, match="transient"):
        pickle.dumps(trace)
    assert events == ["resolve", "commit", "close", "foundation"]
    providers.execution_authority.consume_dispatch(
        request=_request(trace, resolved.dispatch_id)
    )
    assert events == [
        "resolve",
        "commit",
        "close",
        "foundation",
        "finalize",
        "commit",
        "close",
    ]
    assert sessions[0] is not sessions[1]
    assert _marker_count(engine) == 1
    assert (
        providers.execution_authority.lookup_committed(
            control_consumption_ref=f"control-dispatch:{resolved.dispatch_id}"
        ).dispatch_id
        == resolved.dispatch_id
    )
    assert providers.execution_authority.attester.attest_pair(
        authorization_material={}, dispatch_material={}
    ) == {"schema": "AuthorizationReceipt.v2", "dispatch_id": resolved.dispatch_id}


@pytest.mark.parametrize(
    "failure", ["verify", "finalizer", "commit", "auth_bytes", "dispatch_bytes"]
)
def test_refusal_or_commit_failure_never_creates_a_marker(failure: str) -> None:
    providers, events, _, engine, resolved, _ = _composition(
        fail_verify=failure == "verify",
        fail_finalizer=failure == "finalizer",
        fail_second_commit=failure == "commit",
    )
    if failure == "verify":
        with pytest.raises(RuntimeError, match="Foundation refused"):
            providers.host_source.admit_host_source()
        assert "finalize" not in events
    else:
        _, trace = providers.host_source.admit_host_source()
        with pytest.raises(RuntimeError, match="Control refused|commit failed"):
            providers.execution_authority.consume_dispatch(
                request=_request(
                    trace,
                    resolved.dispatch_id,
                    auth=b"wrong" if failure == "auth_bytes" else b"auth",
                    dispatch=b"wrong" if failure == "dispatch_bytes" else b"dispatch",
                )
            )
    assert _marker_count(engine) == 0


def test_forged_trace_and_changed_host_refuse_before_finalizer() -> None:
    providers, events, _, engine, resolved, current_facts = _composition()
    _, trace = providers.host_source.admit_host_source()
    with pytest.raises(HostAdmissionAdapterUsageError, match="unrecognized"):
        providers.execution_authority.consume_dispatch(
            request=_request(replace(trace), resolved.dispatch_id)
        )
    with pytest.raises(HostAdmissionAdapterUsageError, match="coordinate"):
        providers.execution_authority.consume_dispatch(
            request=replace(
                _request(trace, resolved.dispatch_id),
                control_consumption_ref="control-dispatch:wrong",
            )
        )
    current_facts[0] = replace(current_facts[0], host_incarnation="changed")
    with pytest.raises(HostAdmissionAdapterUsageError, match="observation changed"):
        providers.execution_authority.consume_dispatch(
            request=_request(trace, resolved.dispatch_id)
        )
    assert "finalize" not in events
    assert _marker_count(engine) == 0


def test_session_factory_cannot_reuse_the_f2_session_for_v3() -> None:
    providers, events, _, engine, resolved, _ = _composition(reuse_session=True)
    _, trace = providers.host_source.admit_host_source()
    with pytest.raises(HostAdmissionAdapterUsageError, match="separate sessions"):
        providers.execution_authority.consume_dispatch(
            request=_request(trace, resolved.dispatch_id)
        )
    assert "finalize" not in events
    assert _marker_count(engine) == 0
