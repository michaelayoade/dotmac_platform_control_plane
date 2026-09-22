"""`admit_and_launch_host_source`'s transaction ordering and no-fallback rule.

SCOPE. Every collaborator here is a fake satisfying one of
`host_admission_adapter.py`'s CP-owned host-admission Protocols -- this tier
proves the orchestration's OWN properties (session ordering,
commit-before-launch, no fallback on a Foundation refusal) against injected
fakes, never against the real
`dotmac_deployment_control`/`dotmac_deployment_foundation` functions, which
are not installable in this repository today (see
`host_admission_adapter.py`'s module docstring). A conformance suite against
the real functions is `conformance/test_host_admission_conformance.py`.

`host_admission_adapter` is a deliberate LEAF module (stdlib + SQLAlchemy
only, see its own docstring and
`tests/architecture/test_host_admission_adapter_import_boundary.py`) -- this
file imports from it directly, never through `vendor_cp.deployment.adapter`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from vendor_cp.deployment.host_admission_adapter import (
    AttestationVerificationInputs,
    HostAdmissionAdapterUsageError,
    admit_and_launch_host_source,
)

ATTEMPT_ID: UUID = uuid4()
NOW = datetime(2026, 9, 22, tzinfo=UTC)


def _make_session() -> Session:
    """A real, in-memory SQLAlchemy session -- not a mock.

    Test 5 below asserts real transaction-state properties
    (`Session.in_transaction()`), and a mock's `.commit()`/`.in_transaction()`
    would only prove that a mock was told what to return, not anything about
    actual transaction semantics.
    """
    engine = create_engine("sqlite://", future=True)
    return sessionmaker(bind=engine, future=True)()


class _SentinelFoundationFailure(Exception):
    """Stands in for whatever Foundation's real verifier raises on refusal."""


class _SentinelControlRefusal(Exception):
    """Stands in for Control's real digest-mismatch refusal."""


class _ResolvedContext:
    def __init__(self, digest: str = "context-digest") -> None:
        self.context_digest = digest


def _resolver(events: list[str] | None = None, digest: str = "context-digest"):
    def _resolve(db, *, attempt_id, presentation):
        # Actually touch the session so a real transaction opens -- otherwise
        # asserting it is later closed would be vacuous (SQLAlchemy 2.0
        # sessions are lazy and begin a transaction only on first use).
        db.execute(text("SELECT 1"))
        if events is not None:
            events.append("resolve")
        return _ResolvedContext(digest)

    return _resolve


def _capturing_resolver(digest: str = "context-digest"):
    """Like `_resolver`, but keeps the exact `_ResolvedContext` object it
    returned -- needed to assert `admit_and_consume` receives that SAME
    object as `context`, not an equal-looking copy."""
    resolved_holder: list[_ResolvedContext] = []

    def _resolve(db, *, attempt_id, presentation):
        db.execute(text("SELECT 1"))
        resolved = _ResolvedContext(digest)
        resolved_holder.append(resolved)
        return resolved

    _resolve.resolved = resolved_holder  # type: ignore[attr-defined]
    return _resolve


def _raising_verifier(exc: Exception):
    def _verify(**kwargs):
        raise exc

    return _verify


def _recording_verifier(events: list[str], result: object = "verified"):
    def _verify(**kwargs):
        events.append("verify")
        return result

    return _verify


def _capturing_verifier(result: object = "verified"):
    """Like `_recording_verifier`, but keeps the actual kwargs `verify_pair`
    was called with -- needed to assert `verification_context_digest` is
    genuinely `resolved.context_digest`, not merely that verify ran."""
    calls: list[dict[str, object]] = []

    def _verify(**kwargs):
        calls.append(kwargs)
        return result

    _verify.calls = calls  # type: ignore[attr-defined]
    return _verify


def _asserting_verifier(resolve_session: Session, admit_session: Session):
    """Asserts, from INSIDE the call, that no transaction is open on either
    session -- the resolve-phase transaction already committed and closed,
    and the admit-phase transaction has not yet begun."""

    def _verify(**kwargs):
        assert resolve_session.in_transaction() is False
        assert admit_session.in_transaction() is False
        return "verified"

    return _verify


def _admitter(events: list[str] | None = None, result: object = "staged"):
    calls: list[dict[str, object]] = []

    def _admit(db, *, context, foreign_evidence):
        calls.append({"context": context, "foreign_evidence": foreign_evidence})
        if events is not None:
            events.append("admit")
        return result

    _admit.calls = calls  # type: ignore[attr-defined]
    return _admit


def _raising_admitter(exc: Exception):
    def _admit(db, *, context, foreign_evidence):
        raise exc

    return _admit


def _launcher(events: list[str] | None = None):
    calls: list[object] = []

    def _launch(staged: object) -> None:
        calls.append(staged)
        if events is not None:
            events.append("launch")

    _launch.calls = calls  # type: ignore[attr-defined]
    return _launch


def _verification_inputs() -> AttestationVerificationInputs:
    return AttestationVerificationInputs(
        candidate=object(),
        installed=object(),
        foundation_verifier=object(),
        trust_policy=object(),
        expected_host_identity="host-1",
        expected_observation_id="obs-1",
        expected_package="package-1",
        now=NOW,
    )


class _CountingSession:
    """Wraps a real session so `.commit()` calls are countable directly.

    `Session.commit` itself has no built-in call counter, and re-deriving one
    from `in_transaction()` transitions would be indirect for what test 2/3/4
    need: a plain count of commits.
    """

    def __init__(self) -> None:
        self._session = _make_session()
        self.commit_calls = 0

    def commit(self) -> None:
        self.commit_calls += 1
        self._session.commit()

    def in_transaction(self) -> bool:
        return self._session.in_transaction()

    def __getattr__(self, name: str) -> object:
        return getattr(self._session, name)


def test_the_same_session_for_both_roles_is_refused_before_anything_runs() -> None:
    """Property 1, ENFORCED: passing one session object for both
    `resolve_session` and `admit_session` is refused immediately, before
    `resolve_context` is ever called -- not merely a documented convention.
    A shared session's `resolve_session.commit()` would otherwise commit
    whatever unrelated work the caller still had open on it."""
    shared = _make_session()
    resolve_events: list[str] = []
    resolve = _resolver(resolve_events)
    admit = _admitter()
    launch = _launcher()

    with pytest.raises(HostAdmissionAdapterUsageError):
        admit_and_launch_host_source(
            resolve_session=shared,
            admit_session=shared,
            attempt_id=ATTEMPT_ID,
            presentation=object(),
            resolve_context=resolve,
            verify_pair=_recording_verifier([]),
            admit_and_consume=admit,
            launch=launch,
            build_foreign_evidence=lambda result: result,
            verification=_verification_inputs(),
        )

    assert resolve_events == []
    assert len(admit.calls) == 0  # type: ignore[attr-defined]
    assert len(launch.calls) == 0  # type: ignore[attr-defined]


def test_a_foundation_refusal_never_reaches_control() -> None:
    """Property 1: a real-Foundation-shaped invalid-signature refusal means
    `admit_and_consume` is never invoked at all."""
    admit = _admitter()
    admit_and_launch = admit_and_launch_host_source
    with pytest.raises(_SentinelFoundationFailure):
        admit_and_launch(
            resolve_session=_make_session(),
            admit_session=_make_session(),
            attempt_id=ATTEMPT_ID,
            presentation=object(),
            resolve_context=_resolver(),
            verify_pair=_raising_verifier(_SentinelFoundationFailure("bad signature")),
            admit_and_consume=admit,
            launch=_launcher(),
            build_foreign_evidence=lambda result: result,
            verification=_verification_inputs(),
        )
    assert len(admit.calls) == 0  # type: ignore[attr-defined]


def test_a_sentinel_foundation_failure_propagates_with_no_fallback() -> None:
    """Property 2: the exact sentinel exception propagates -- not swallowed,
    not converted, not retried -- and nothing downstream ever runs."""
    admit_session = _CountingSession()
    admit = _admitter()
    launch = _launcher()

    with pytest.raises(_SentinelFoundationFailure):
        admit_and_launch_host_source(
            resolve_session=_make_session(),
            admit_session=admit_session,  # type: ignore[arg-type]
            attempt_id=ATTEMPT_ID,
            presentation=object(),
            resolve_context=_resolver(),
            verify_pair=_raising_verifier(_SentinelFoundationFailure()),
            admit_and_consume=admit,
            launch=launch,
            build_foreign_evidence=lambda result: result,
            verification=_verification_inputs(),
        )

    assert len(admit.calls) == 0  # type: ignore[attr-defined]
    assert admit_session.commit_calls == 0
    assert len(launch.calls) == 0  # type: ignore[attr-defined]


def test_a_substituted_evidence_digest_refuses_before_any_commit_or_launch() -> None:
    """Property 3: Control's own digest-mismatch refusal propagates, and
    `admit_session` never commits and `launch` never runs."""
    admit_session = _CountingSession()
    launch = _launcher()

    with pytest.raises(_SentinelControlRefusal):
        admit_and_launch_host_source(
            resolve_session=_make_session(),
            admit_session=admit_session,  # type: ignore[arg-type]
            attempt_id=ATTEMPT_ID,
            presentation=object(),
            resolve_context=_resolver(),
            verify_pair=_recording_verifier([]),
            admit_and_consume=_raising_admitter(
                _SentinelControlRefusal("digest mismatch")
            ),
            launch=launch,
            build_foreign_evidence=lambda result: result,
            verification=_verification_inputs(),
        )

    assert admit_session.commit_calls == 0
    assert len(launch.calls) == 0  # type: ignore[attr-defined]


def test_the_positive_path_commits_before_verify_and_before_launch_in_order() -> None:
    """Property 4: on a fully successful path, resolve commits before verify
    runs, admit commits before launch runs, launch receives exactly what
    admit_and_consume returned, and the function's own return value is that
    same staged object."""
    events: list[str] = []

    class _OrderedResolveSession:
        def __init__(self) -> None:
            self._session = _make_session()

        def commit(self) -> None:
            events.append("resolve_commit")
            self._session.commit()

        def __getattr__(self, name: str) -> object:
            return getattr(self._session, name)

    class _OrderedAdmitSession:
        def __init__(self) -> None:
            self._session = _make_session()

        def commit(self) -> None:
            events.append("admit_commit")
            self._session.commit()

        def __getattr__(self, name: str) -> object:
            return getattr(self._session, name)

    def _resolve(db, *, attempt_id, presentation):
        events.append("resolve")
        return _ResolvedContext()

    def _verify(**kwargs):
        events.append("verify")
        return "verification-result"

    def _admit(db, *, context, foreign_evidence):
        events.append("admit")
        return "the-staged-object"

    def _launch(staged: object) -> None:
        events.append(f"launch:{staged}")

    result = admit_and_launch_host_source(
        resolve_session=_OrderedResolveSession(),  # type: ignore[arg-type]
        admit_session=_OrderedAdmitSession(),  # type: ignore[arg-type]
        attempt_id=ATTEMPT_ID,
        presentation=object(),
        resolve_context=_resolve,
        verify_pair=_verify,
        admit_and_consume=_admit,
        launch=_launch,
        build_foreign_evidence=lambda verification_result: verification_result,
        verification=_verification_inputs(),
    )

    assert result == "the-staged-object"
    assert events == [
        "resolve",
        "resolve_commit",
        "verify",
        "admit",
        "admit_commit",
        "launch:the-staged-object",
    ]
    # (b) resolve commits strictly before verify.
    assert events.index("resolve_commit") < events.index("verify")
    # (c) admit commits strictly before launch.
    assert events.index("admit_commit") < events.index("launch:the-staged-object")


def test_verification_and_admission_bind_to_the_resolved_context_correctly() -> None:
    """No unit test before this one actually inspected what `verify_pair` and
    `admit_and_consume` were CALLED WITH, only that they ran -- an
    implementation that bound verification to a constant, `verification.now`,
    or a caller-supplied digest instead of `resolved.context_digest` would
    have passed every other test in this file. Three bindings, each load-
    bearing for the security properties this adapter exists to hold:

    1. `verify_pair` receives `verification_context_digest ==
       resolved.context_digest` -- the exact value the resolve phase froze,
       not a different one.
    2. `admit_and_consume` receives `context is resolved` -- the SAME object
       the resolve phase returned, not an equal-looking reconstruction.
    3. `admit_and_consume` receives `foreign_evidence` as EXACTLY what
       `build_foreign_evidence` returned from Foundation's verification
       result -- nothing substituted in between.
    """
    resolve = _capturing_resolver(digest="the-real-frozen-digest")
    verify = _capturing_verifier(result="foundation-verification-result")
    admit = _admitter()
    mapped_evidence = object()

    admit_and_launch_host_source(
        resolve_session=_make_session(),
        admit_session=_make_session(),
        attempt_id=ATTEMPT_ID,
        presentation=object(),
        resolve_context=resolve,
        verify_pair=verify,
        admit_and_consume=admit,
        launch=_launcher(),
        build_foreign_evidence=lambda result: mapped_evidence,
        verification=_verification_inputs(),
    )

    resolved = resolve.resolved[0]  # type: ignore[attr-defined]
    assert verify.calls[0]["verification_context_digest"] == "the-real-frozen-digest"  # type: ignore[attr-defined]
    assert admit.calls[0]["context"] is resolved  # type: ignore[attr-defined]
    assert admit.calls[0]["foreign_evidence"] is mapped_evidence  # type: ignore[attr-defined]


def test_no_open_transaction_on_either_session_during_verification() -> None:
    """Property 5: at the moment Foundation's verifier is called, the resolve
    session's transaction is already closed/committed, and the admit
    session's transaction has not yet been opened."""
    resolve_session = _make_session()
    admit_session = _make_session()

    # Touch resolve_session's transaction implicitly via the resolver, and
    # confirm neither session has an active transaction before the assertion
    # inside the verifier fires.
    admit_and_launch_host_source(
        resolve_session=resolve_session,
        admit_session=admit_session,
        attempt_id=ATTEMPT_ID,
        presentation=object(),
        resolve_context=_resolver(),
        verify_pair=_asserting_verifier(resolve_session, admit_session),
        admit_and_consume=_admitter(),
        launch=_launcher(),
        build_foreign_evidence=lambda result: result,
        verification=_verification_inputs(),
    )
