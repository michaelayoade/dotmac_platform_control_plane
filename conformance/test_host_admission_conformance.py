"""Real-wheel Control/Foundation component conformance and CP V3 refusal.

The ten component cases use a TEST-OWNED resolve/verify/finalize driver with
Control's actual FoundationDispatchConsumptionV1 signed-pair input. They do
not call CP's obsolete pre-V3 helper and do not prove CP execution adoption.
A separate case drives CP's real startup-bound V3 provider through genuine
Foundation F2 admission and proves its C2-D1 approval-subject refusal happens
before Control finalization, consumption or launch. Gate 3 remains open.

All packages are installed as exact wheels in disposable CI. The Foundation
wheel is a test-only build from a pinned source commit, not an allocated or
published successor. Required CI collects this file explicitly on real
PostgreSQL as platform_api. Missing configuration/imports fail; no skips.

Signature adapters below deliberately use deterministic SHA-256/HMAC test
doubles, as the upstream component suites do. They exercise the real package
verification logic and reject tampering, but are NOT Ed25519, signer-custody,
OIDC, live host authentication, deployment or end-to-end authorization proof.
"""

# ruff: noqa: E501  (the scoped-role and transit cases carry long literal SQL/URL tables)

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import hmac
import io
import json
import os
import secrets
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# ── Real imports -- only resolve once the real wheels are installed ────────
# Deliberately NOT wrapped in a try/except: this is a real, explicit
# conformance run (see module docstring), and an ImportError here is a real
# defect -- a missing wheel, a missing symbol, a stale API -- that must fail
# collection loudly, not be laundered into a skip that looks like "nothing to
# see here". By the time this module is even imported, conftest.py's
# pytest_configure has already confirmed CONFORMANCE_DATABASE_URL is set.
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    AuthorizationEnvelopeRefusalCode,
    AuthorizationEnvelopeRefusedError,
    AuthorizationSignature,
    AuthorizationSignerIdentity,
    BindTargetHostCommand,
    CredentialTransitionCommand,
    DesiredDeployment,
    DispatchSignature,
    DispatchSignerIdentity,
    EnrolHostAdmissionCredentialCommand,
    FoundationConsumptionRefusedError,
    FoundationDispatchConsumptionV1,
    FoundationExecutionContextV1,
    HostAdmissionForeignRootV1,
    HostAdmissionForeignVerificationEvidenceV1,
    HostAdmissionPresentationStatementV1,
    HostAdmissionPresentationV1,
    HostAdmissionRefusalCode,
    HostAdmissionRefusedError,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    SetDesiredStateCommand,
    SetTargetAdmissionPolicyCommand,
    TransitionRefusedError,
    activate_credential,
    admit_and_consume_host_admission,
    approve_plan,
    attest_foundation_execution_pair,
    bind_target_host,
    dispatch_attempt,
    enrol_host_admission_credential,
    get_plan,
    install_foundation_consumption_security,
    install_host_admission_security,
    lookup_foundation_execution_consumption,
    propose_plan,
    register_target,
    request_rollout,
    resolve_host_admission_context,
    revoke_credential,
    set_desired_state,
    set_target_admission_policy,
)
from dotmac_deployment_control import service as control_service

# `enrol_root`/`AttestationRootDescriptorTerms` are NOT re-exported at the
# top-level package -- verified directly against the installed wheel, not
# assumed. They live in the module that actually owns attestation-root
# enrolment.
from dotmac_deployment_control.attestation_trust_registry import (
    AttestationRootDescriptorTerms,
    enrol_root,
)
from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.models import (
    AttestationEnrolment,
    DeploymentPlan,
    Rollout,
    RolloutAttempt,
)
from dotmac_deployment_foundation import (
    AttestationEnvelopeV2,
    AttestationPairVerificationResultV1,
    AttestationTrustPolicy,
    AttestationTrustRootV2,
    CandidateAttestationSubjectV2,
    ControlConsumptionRequestV3,
    Digest,
    ExecutionContextV3,
    HostSourceAdmissionTrace,
    InstalledHostAttestationSubjectV2,
    PreconditionFailed,
    admit_host_source,
    attestation_envelope_digest,
    verify_attestation_pair,
)
from dotmac_deployment_foundation.host_source import read_installed_artifact

# Also not top-level -- verified against the installed wheel. Foundation's OWN
# test suite (tests/unit/test_deployment_foundation_trusted_host_source.py)
# imports it from here too.
from dotmac_deployment_foundation.trusted_host_source import candidate_subject_digest
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from conformance.openbao_support import OpenBao, UnixRelay
from vendor_cp.approvals import adapter as approvals
from vendor_cp.approvals_authority import bare_content_hash
from vendor_cp.deployment import (
    consumption_role_spec,
    consumption_scope,
    consumption_watchdog,
    materials_producer,
    transit_custody,
)
from vendor_cp.deployment import foundation_bindings as bindings_module
from vendor_cp.deployment import foundation_execution_approval as foundation_approval

# The LEAF module only -- see its own docstring and
# tests/architecture/test_host_admission_adapter_import_boundary.py. NEVER
# `vendor_cp.deployment.adapter`, which pulls in this application's entire
# approvals/identity/licensing closure and would defeat the whole point of
# the leaf split.
from vendor_cp.deployment.host_admission_adapter import (
    ControlFoundationV3Bindings,
    DispatchApprovalSubjectUnavailable,
    FoundationHostV3Bindings,
    FoundationV3Sources,
    HostAdmissionAdapterUsageError,
    HostAdmissionObservation,
    compose_foundation_v3_providers,
)
from vendor_cp.deployment.verification_identities import (
    AuthorizationEd25519Verifier,
    DispatchEd25519Verifier,
    PinnedVerificationIdentity,
)

# No pytestmark skipif here. `conformance/conftest.py`'s `pytest_configure`
# already raised a hard `pytest.UsageError` before collection ever reached
# this module if CONFORMANCE_DATABASE_URL were unset -- by the time this line
# runs, it is guaranteed set. A redundant skipif here would be dead code that
# could never actually fire, and worse, would misdescribe this suite's real
# behavior (a hard failure, not a skip) to the next reader.
CONFORMANCE_DATABASE_URL = os.environ.get("CONFORMANCE_DATABASE_URL")


# ── Deterministic signing doubles -- same convention as both repos' own test
#    suites (see module docstring). ──────────────────────────────────────────

# NOT a fixed historical constant -- REAL DEFECT found by actually running
# this suite in the afternoon after having only ever run it in the morning
# before: `activate_credential` (Control's own service.py) stamps
# `activated_at` with `_control_now()`, the REAL current wall-clock time --
# it has no injected-clock parameter this suite could override. Every test's
# injected `_AdmissionClock` must therefore start at or after real wall-clock
# time, or `resolve_host_admission_context`'s `_credential_is_active` check
# (`now < activated_at`) refuses with CREDENTIAL_NOT_ACTIVE the moment real
# time passes whatever instant this suite hardcoded. A one-hour forward
# margin comfortably covers this suite's own real Postgres round-trip time
# without weakening anything the tests check --
# every test still moves ITS OWN clock only forward from this baseline,
# relative to itself, never compared against another fixed point.
_NOW = datetime.now(UTC) + timedelta(hours=1)
_POLICY = "deployment.production"
_POLICY_VERSION = 4
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _public_key_b64(key_id: str) -> str:
    """Deterministic, non-asymmetric "public key" material -- the fingerprint
    derived from it is what Control's own stored-credential checks compare
    against; the actual cryptographic check happens in the injected verifier
    below, which never reads this value's bytes as a real key."""
    raw = hashlib.sha256(b"conformance-public-key\0" + key_id.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _AuthorizationSigner:
    """Deterministic double for `request_rollout`'s `signer=` parameter --
    faithfully reproduces Control's own real
    `tests/authorization_support.py::TestAuthorizationSigner` shape
    (`.identity`, an `AuthorizationSignerIdentity`), verified directly
    against the installed wheel: `issue_authorization_envelope` reads
    `signer.identity`, not flat attributes."""

    def __init__(self) -> None:
        self.identity = AuthorizationSignerIdentity(
            key_id="conformance-authorization-key",
            algorithm="test-sha256",
            public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
                _public_key_b64("authorization")
            ).canonical,
        )

    def sign(self, canonical_bytes: bytes) -> Any:
        identity = self.identity
        signature = hashlib.sha256(
            identity.key_id.encode() + b"\0" + canonical_bytes
        ).hexdigest()
        return AuthorizationSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=signature,
            purpose=identity.purpose,
        )


class _AuthorizationVerifier:
    def __init__(self, signer: _AuthorizationSigner) -> None:
        self._signer = signer

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        identity = self._signer.identity
        if (
            key_id != identity.key_id
            or algorithm != identity.algorithm
            or purpose != identity.purpose
            or public_key_fingerprint != identity.public_key_fingerprint
        ):
            return False
        expected = hashlib.sha256(key_id.encode() + b"\0" + canonical_bytes).hexdigest()
        return hmac.compare_digest(signature, expected)


class _DispatchSigner:
    """Deterministic double for `dispatch_attempt`'s `dispatch_signer=`
    parameter -- faithfully reproduces Control's own real
    `tests/dispatch_support.py::TestDispatchSigner` shape
    (`.dispatch_identity`, a `DispatchSignerIdentity`), verified directly:
    `issue_dispatch_envelope` reads `signer.dispatch_identity`, not flat
    attributes."""

    def __init__(self) -> None:
        self.public_key_b64 = _public_key_b64("dispatch")
        self.dispatch_identity = DispatchSignerIdentity(
            key_id="conformance-dispatch-key",
            algorithm="test-sha256",
            public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
                self.public_key_b64
            ).canonical,
        )

    def sign_dispatch(self, canonical_bytes: bytes) -> Any:
        identity = self.dispatch_identity
        signature = hashlib.sha256(
            self.public_key_b64.encode() + b"\0dispatch\0" + canonical_bytes
        ).hexdigest()
        return DispatchSignature(
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key_fingerprint=identity.public_key_fingerprint,
            signature=signature,
        )


class _DispatchVerifier:
    def __init__(self, signer: _DispatchSigner) -> None:
        self._signer = signer

    def verify_dispatch(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        identity = self._signer.dispatch_identity
        expected = self._signer.sign_dispatch(canonical_bytes).signature
        return (
            key_id == identity.key_id
            and algorithm == identity.algorithm
            and purpose == identity.purpose
            and public_key_fingerprint == identity.public_key_fingerprint
            and hmac.compare_digest(signature, expected)
        )


class _HostAdmissionPresentationVerifier:
    """Real, injected verifier for `verify_host_admission_presentation` --
    HMAC over the presentation's own canonical bytes, keyed by a per-key-id
    shared secret this test controls. A tampered signature or a signature
    produced under a different key genuinely fails `hmac.compare_digest`."""

    def __init__(self) -> None:
        self._secrets: dict[str, bytes] = {}

    def register(self, key_id: str, public_key_b64: str) -> None:
        # Deterministic "shared secret" derived from the same public-key
        # material Control stores -- this test's stand-in for a real
        # asymmetric keypair; see module docstring on why this is a
        # legitimate proof of the REAL function's own logic.
        self._secrets[key_id] = hashlib.sha256(
            b"presentation-secret\0" + public_key_b64.encode()
        ).digest()

    def sign(self, key_id: str, canonical_bytes: bytes) -> str:
        mac = hmac.new(self._secrets[key_id], canonical_bytes, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def verify_host_admission_presentation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        public_key_b64: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        secret = self._secrets.get(key_id)
        if secret is None:
            return False
        expected_mac = hmac.new(secret, canonical_bytes, hashlib.sha256).digest()
        expected_signature = (
            base64.urlsafe_b64encode(expected_mac).decode("ascii").rstrip("=")
        )
        return hmac.compare_digest(signature, expected_signature)


class _AdmissionClock:
    """A mutable, injectable clock -- `.advance()` lets test 6 (expiry
    between Foundation verification and final Control admission) move real
    time forward between the resolve and admit-and-consume phases, proving
    `admit_and_consume_host_admission`'s OWN fresh-clock check, not this
    test's simulation of one."""

    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now = self._now + delta


class _FoundationAttestationVerifier:
    """Real, injected verifier for Foundation's `verify_attestation_pair` --
    same HMAC-over-signed-bytes convention as
    `test_deployment_foundation_trusted_host_source.py`'s own `Verifier`."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, fingerprint: str, key: bytes) -> None:
        self._keys[fingerprint] = key

    def sign(self, fingerprint: str, message: bytes) -> str:
        return hmac.new(self._keys[fingerprint], message, hashlib.sha256).hexdigest()

    def verify(
        self, *, public_key: bytes, algorithm: str, message: bytes, signature: str
    ) -> bool:
        return algorithm == "ed25519" and hmac.compare_digest(
            signature, hmac.new(public_key, message, hashlib.sha256).hexdigest()
        )


# ── Database fixture ────────────────────────────────────────────────────────


@pytest.fixture()
def db() -> Any:
    """A real PostgreSQL session against the migrated `mod_deploy` schema
    named by `CONFORMANCE_DATABASE_URL`. Each test runs in its own
    transaction, rolled back on teardown -- this suite proves cross-
    transaction behavior itself (resolve commits, admit commits separately),
    so the OUTER test isolation is a rollback of whatever either phase left
    committed, not a shared open transaction wrapping both (which would
    contradict the very property under test)."""
    engine = create_engine(CONFORMANCE_DATABASE_URL, future=True)
    session = sessionmaker(bind=engine, future=True)()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


@pytest.fixture()
def admit_db() -> Any:
    """A SECOND, genuinely independent real PostgreSQL session/connection,
    for `admit_and_launch_host_source`'s `admit_session`. Property 1
    (`resolve_session is not admit_session`, now enforced by
    `HostAdmissionAdapterUsageError`) and property 3 (no open transaction on
    EITHER session during Foundation verification) are proven against real
    Postgres transaction/connection semantics only if this is a distinct
    engine and connection from `db`'s, not merely a distinct Python object
    wrapping the same connection."""
    engine = create_engine(CONFORMANCE_DATABASE_URL, future=True)
    session = sessionmaker(bind=engine, future=True)()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _clean_security_between_tests() -> Any:
    import dotmac_deployment_control.foundation_consumption as consumption
    import dotmac_deployment_control.host_admission_coordinator as admission_coordinator

    admission_coordinator._reset_host_admission_security_for_tests()
    consumption._reset_foundation_consumption_security_for_tests()
    yield
    admission_coordinator._reset_host_admission_security_for_tests()
    consumption._reset_foundation_consumption_security_for_tests()


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    """This suite builds no real `create_app()`, so nothing installs the
    process-active audit-action registry `write_platform_audit_event` needs.
    Same pattern as every one of Control's own unit tests (e.g.
    `tests/unit/test_deployment_control_intent.py`) -- verified there, not
    guessed."""
    from dotmac_approvals import module as approvals_module
    from dotmac_deployment_control import module
    from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions

    install_audit_actions(
        AuditActionRegistry.from_manifests([module, approvals_module])
    )


# ── Control-side setup: target, plan, rollout, dispatch, host-admission
#    credential, host binding, admission policy, attestation roots. One
#    function builds the complete coordinate; individual tests mutate from
#    there. ────────────────────────────────────────────────────────────────


def _register_target(db: Session) -> Any:
    return register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=f"tgt-{uuid.uuid4().hex[:8]}",
            subject_ref="conformance-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )


def _set_desired(db: Session, target_id: uuid.UUID) -> Any:
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target_id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@7.187.1",
                spec={"replicas": 2},
                licence_ref="lic-1",
                brand_profile_ref="brand-acme",
                images=[],
            ),
        ),
    )


def _approved_plan(db: Session, target_id: uuid.UUID) -> Any:
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_cmd(),
            target_id=target_id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            purpose="foundation_execution",
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_cmd(),
            plan_id=plan.id,
            evidence=ApprovalEvidence(
                policy_code=_POLICY,
                policy_version=_POLICY_VERSION,
                decision_ref=f"apr-{uuid.uuid4().hex[:8]}",
                content_digest=plan.plan_digest or "",
                decided_at=datetime.now(UTC),
                operation="deploy",
                execution_plan_digest=_EXECUTION_PLAN,
                decision_status="granted",
            ),
        ),
    )


def _genuine_approved_plan(db: Session, target_id: uuid.UUID) -> Any:
    """Real policy/request/decision, never the component fixture's apr-* proof."""
    policy = f"foundation-{uuid.uuid4().hex}"
    approvals.publish_policy_version(
        db, approvals.PublishPolicyCommand(_cmd(), policy, 1, 1, False)
    )
    db.commit()
    plan = foundation_approval.propose_foundation_plan(
        db,
        foundation_approval.ProposeFoundationPlan(
            command_id=_cmd(),
            target_id=target_id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            approval_policy_code=policy,
            approval_policy_version=1,
        ),
    )
    db.commit()  # release Control locks before entering an approval hold
    opened = foundation_approval.open_foundation_approval(
        db, command_id=_cmd(), plan_id=plan.id, requested_by=uuid.uuid4()
    )
    db.commit()
    approvals.record_decision(
        db,
        approvals.RecordDecisionCommand(
            command_id=_cmd(),
            request_id=opened.request_id,
            approver_id=uuid.uuid4(),
            content_hash=bare_content_hash(plan.plan_digest),
        ),
    )
    db.commit()
    plan = foundation_approval.approve_foundation_plan(
        db,
        command_id=_cmd(),
        plan_id=plan.id,
        approval_request_id=opened.request_id,
    )
    db.commit()
    assert plan.approval_decision_ref == str(opened.request_id)
    return plan


def _rollout(db: Session, plan_id: uuid.UUID, signer: _AuthorizationSigner) -> Any:
    return request_rollout(
        db,
        RequestRolloutCommand(
            command_id=_cmd(),
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            plan_id=plan_id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        ),
        signer=signer,
    )


class _AdmissionCoordinate:
    """Everything one host-admission conformance test needs: the attempt id,
    a valid signed presentation, the presentation verifier it must be
    checked against, the Foundation verifier/trust policy, and the real
    candidate/installed envelopes -- all built from ONE consistent Control +
    Foundation setup."""

    def __init__(
        self,
        *,
        attempt_id: uuid.UUID,
        target_id: uuid.UUID,
        presentation: HostAdmissionPresentationV1,
        presentation_verifier: _HostAdmissionPresentationVerifier,
        clock: _AdmissionClock,
        candidate_envelope: AttestationEnvelopeV2,
        installed_envelope: AttestationEnvelopeV2,
        foundation_verifier: _FoundationAttestationVerifier,
        trust_policy: AttestationTrustPolicy,
        credential_id: uuid.UUID,
        execution: FoundationDispatchConsumptionV1,
        facts: ExecutionContextV3,
    ) -> None:
        self.attempt_id = attempt_id
        self.target_id = target_id
        self.presentation = presentation
        self.presentation_verifier = presentation_verifier
        self.clock = clock
        self.candidate_envelope = candidate_envelope
        self.installed_envelope = installed_envelope
        self.foundation_verifier = foundation_verifier
        self.trust_policy = trust_policy
        self.credential_id = credential_id
        self.execution = execution
        self.facts = facts


def _build_admission_coordinate(
    db: Session,
    *,
    now: datetime,
    genuine_approval: bool = False,
    external: Any = None,
) -> _AdmissionCoordinate:
    # Every identity below is suffixed with a fresh per-call token. The
    # commands this function calls (register_target, enrol_host_admission_
    # credential, enrol_root, ...) run through `process_once_platform`, which
    # commits internally for at-most-once durability -- the outer `db`
    # fixture's rollback-on-teardown does NOT undo them. Multiple tests in one
    # process therefore each need their own key_id/host_id/custody subject,
    # or the second test to run collides with the first's already-committed
    # rows (real defect found by actually running this against Postgres,
    # not a hypothetical).
    run = uuid.uuid4().hex[:8]
    reading = read_installed_artifact()
    package = reading.distribution

    target = _register_target(db)
    _set_desired(db, target.id)
    db.commit()
    if external is not None:
        # The real operator path: propose, open, a real Approvals decision and
        # approve through the producer commands (E6 B1).
        plan = external.prepare(db, target)
    else:
        plan = (
            _genuine_approved_plan(db, target.id)
            if genuine_approval
            else _approved_plan(db, target.id)
        )
    db.commit()
    authorization_signer = _AuthorizationSigner()
    if external is not None:
        # Rollout and dispatch are issued by `materials_producer issue` with
        # transit-signed envelopes; the doubles below are not used.
        rollout = SimpleNamespace(id=external.issue(db, plan))
    elif genuine_approval:
        rollout = foundation_approval.request_foundation_rollout(
            db,
            command_id=_cmd(),
            plan_id=plan.id,
            rollout_ref=f"rol-{uuid.uuid4().hex[:8]}",
            authorization_expires_at=now + timedelta(minutes=1),
            signer=authorization_signer,
        )
    else:
        rollout = _rollout(db, plan.id, authorization_signer)
    db.commit()
    dispatch_signer = _DispatchSigner()
    dispatch_owner = (
        foundation_approval.dispatch_foundation_attempt
        if genuine_approval
        else dispatch_attempt
    )
    if external is None:
        dispatch_owner(
            db,
            command_id=_cmd(),
            rollout_id=rollout.id,
            verifier=_AuthorizationVerifier(authorization_signer),
            dispatch_signer=dispatch_signer,
        )
    db.commit()
    stored_dispatch = control_service._stored_dispatch_coordinate(
        db, _latest_attempt_id(db, rollout.id)
    )
    assert stored_dispatch is not None
    attempt_id = stored_dispatch.attempt_id

    admission_key_id = f"conformance-admission-key-{run}"
    admission_public_key_b64 = _public_key_b64(admission_key_id)
    credential_id = enrol_host_admission_credential(
        db,
        EnrolHostAdmissionCredentialCommand(
            command_id=_cmd(),
            target_id=target.id,
            key_id=admission_key_id,
            algorithm="ed25519",
            public_key_b64=admission_public_key_b64,
            enrollment_authority="conformance-test",
        ),
    )
    activate_credential(
        db, CredentialTransitionCommand(command_id=_cmd(), credential_id=credential_id)
    )
    host_id = f"conformance-host-{run}"
    bind_target_host(
        db,
        BindTargetHostCommand(
            target_id=target.id,
            host_id=host_id,
            authority="conformance-test",
        ),
    )
    candidate_subject_name = f"conformance-release-{run}"
    set_target_admission_policy(
        db,
        SetTargetAdmissionPolicyCommand(
            target_id=target.id,
            candidate_root_subject=candidate_subject_name,
            candidate_audience="foundation-candidate",
            installed_audience=host_id,
            expected_foundation_package=package,
            authority="conformance-test",
        ),
    )

    candidate_key = hashlib.sha256(
        f"conformance-candidate-root-key-{run}".encode()
    ).digest()
    host_key = hashlib.sha256(f"conformance-host-root-key-{run}".encode()).digest()
    candidate_root_b64 = (
        base64.urlsafe_b64encode(candidate_key).decode("ascii").rstrip("=")
    )
    host_root_b64 = base64.urlsafe_b64encode(host_key).decode("ascii").rstrip("=")

    for custody_domain, subject, purpose, public_key_b64 in (
        (
            "candidate_release_signer",
            candidate_subject_name,
            "dotmac.foundation.candidate-artifact.v2",
            candidate_root_b64,
        ),
        (
            "host_attester",
            host_id,
            "dotmac.foundation.installed-host.v2",
            host_root_b64,
        ),
    ):
        enrol_root(
            db,
            custody_domain=custody_domain,
            subject=subject,
            public_key_b64=public_key_b64,
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/conformance/{subject}",
            enrolment_authority="conformance-test",
            descriptor=AttestationRootDescriptorTerms(
                issuer="conformance-test",
                attestation_key_id=f"attestation-{subject}",
                evidence_purpose=purpose,
                not_after=now + timedelta(days=1),
            ),
            enrolled_at=now - timedelta(days=1),
        )

    candidate_fp = PublicKeyFingerprintV1.from_public_key_b64(
        candidate_root_b64
    ).canonical
    host_fp = PublicKeyFingerprintV1.from_public_key_b64(host_root_b64).canonical

    foundation_verifier = _FoundationAttestationVerifier()
    foundation_verifier.register(candidate_fp, candidate_key)
    foundation_verifier.register(host_fp, host_key)

    candidate_subject = CandidateAttestationSubjectV2(
        package,
        reading.version,
        reading.artifact_digest,
        "d74bf8dd8c399dd92047174365403b861f82ddd0",
        "dotmac/conformance",
        "111",
        "222",
    )
    installed_subject = InstalledHostAttestationSubjectV2(
        host_id,
        candidate_subject.package,
        candidate_subject.version,
        candidate_subject.wheel_sha256,
        candidate_subject_digest(candidate_subject),
    )
    candidate_trust_root_version = str(
        _enrolment_id_for(db, "candidate_release_signer", candidate_subject_name)
    )
    host_trust_root_version = str(_enrolment_id_for(db, "host_attester", host_id))

    candidate_envelope = _sign_envelope(
        purpose="dotmac.foundation.candidate-artifact.v2",
        fingerprint=candidate_fp,
        # Foundation's `custody_domain` field on the envelope must equal the
        # REAL custody-domain role name Control's own `_root_context` reads
        # off the enrolled row (`AttestationEnrolment.custody_domain`,
        # "candidate_release_signer"/"host_attester") -- NOT the subject.
        # Conflating the two was a real bug this suite's widened
        # verified-root comparison caught: Foundation's own internal
        # envelope/root consistency check never noticed, because both sides
        # of THAT check used the same (wrong) value consistently.
        custody_domain="candidate_release_signer",
        key_id=f"attestation-{candidate_subject_name}",
        trust_root_version=candidate_trust_root_version,
        subject=candidate_subject.canonical_document(),
        observation_id=f"conformance-candidate-observation-{run}",
        audience="foundation-candidate",
        foundation_verifier=foundation_verifier,
        now=now,
    )
    installed_envelope = _sign_envelope(
        purpose="dotmac.foundation.installed-host.v2",
        fingerprint=host_fp,
        custody_domain="host_attester",
        key_id=f"attestation-{host_id}",
        trust_root_version=host_trust_root_version,
        subject=installed_subject.canonical_document(),
        observation_id=str(attempt_id),
        audience=host_id,
        foundation_verifier=foundation_verifier,
        now=now,
    )

    presentation_verifier = _HostAdmissionPresentationVerifier()
    presentation_verifier.register(admission_key_id, admission_public_key_b64)

    candidate_digest = str(attestation_envelope_digest(candidate_envelope))
    installed_digest = str(attestation_envelope_digest(installed_envelope))

    statement = HostAdmissionPresentationStatementV1(
        presentation_id=f"presentation-{uuid.uuid4().hex[:8]}",
        key_id=admission_key_id,
        dispatch_id=stored_dispatch.dispatch_id,
        candidate_attestation_envelope_digest=candidate_digest,
        installed_attestation_envelope_digest=installed_digest,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    signature = presentation_verifier.sign(admission_key_id, statement.canonical_bytes)
    presentation = HostAdmissionPresentationV1(statement=statement, signature=signature)

    trust_policy = AttestationTrustPolicy(
        candidate_roots=(
            AttestationTrustRootV2(
                public_key_fingerprint=candidate_fp,
                public_key_base64=_to_foundation_b64(candidate_root_b64),
                purpose="dotmac.foundation.candidate-artifact.v2",
                custody_domain="candidate_release_signer",
                issuer="conformance-test",
                key_id=f"attestation-{candidate_subject_name}",
                algorithm="ed25519",
                trust_root_version=candidate_trust_root_version,
                not_before=(now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                not_after=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            ),
        ),
        installed_roots=(
            AttestationTrustRootV2(
                public_key_fingerprint=host_fp,
                public_key_base64=_to_foundation_b64(host_root_b64),
                purpose="dotmac.foundation.installed-host.v2",
                custody_domain="host_attester",
                issuer="conformance-test",
                key_id=f"attestation-{host_id}",
                algorithm="ed25519",
                trust_root_version=host_trust_root_version,
                not_before=(now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                not_after=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            ),
        ),
        candidate_audience="foundation-candidate",
        installed_audience=host_id,
    )

    clock = _AdmissionClock(now)
    install_foundation_consumption_security(
        authorization_verifier=(
            external.authorization_verifier
            if external is not None
            else _AuthorizationVerifier(authorization_signer)
        ),
        dispatch_verifier=(
            external.dispatch_verifier
            if external is not None
            else _DispatchVerifier(dispatch_signer)
        ),
        clock=clock,
    )
    # Expected business facts come from Control's owning rows, not from the
    # presented signed material. The fixture uses no privileged row edits.
    rollout_row = db.get(Rollout, rollout.id)
    attempt_row = db.get(RolloutAttempt, attempt_id)
    assert rollout_row is not None and attempt_row is not None
    assert rollout_row.authorization_envelope is not None
    assert attempt_row.dispatch_envelope is not None
    expected = FoundationExecutionContextV1(
        product_code=target.product_code,
        environment=target.environment,
        target_id=str(target.id),
        target_ref=target.target_ref,
        operation=plan.authorized_operation,
        release_ref=plan.snapshot["release_ref"],
        rollout_ref=rollout_row.rollout_ref,
        plan_id=str(plan.id),
        approval_decision_ref=plan.approval_decision_ref,
        control_plan_digest=plan.plan_digest,
        execution_sequence=rollout_row.execution_sequence,
        attempt_no=attempt_row.attempt_no,
    )
    execution = FoundationDispatchConsumptionV1(
        authorization_material_json=json.dumps(
            rollout_row.authorization_envelope, sort_keys=True, separators=(",", ":")
        ).encode(),
        dispatch_material_json=json.dumps(
            attempt_row.dispatch_envelope, sort_keys=True, separators=(",", ":")
        ).encode(),
        expected_context=expected,
        expected_execution_plan_digest=_EXECUTION_PLAN,
        control_consumption_ref=f"control-dispatch:{attempt_id}",
    )
    facts = ExecutionContextV3(
        **dataclasses.asdict(expected),
        controller_ssh_fingerprint="conformance-controller-not-custody-evidence",
        host_id=host_id,
        host_incarnation=host_fp,
        host_enrolment_ref=host_trust_root_version,
    )

    return _AdmissionCoordinate(
        attempt_id=attempt_id,
        target_id=target.id,
        presentation=presentation,
        presentation_verifier=presentation_verifier,
        clock=clock,
        candidate_envelope=candidate_envelope,
        installed_envelope=installed_envelope,
        foundation_verifier=foundation_verifier,
        trust_policy=trust_policy,
        credential_id=credential_id,
        execution=execution,
        facts=facts,
    )


def _map_foundation_result_to_control_evidence(
    result: Any,
) -> HostAdmissionForeignVerificationEvidenceV1:
    """The one piece of real "adapter glue" a production CP composition
    needs: converting Foundation's real `AttestationPairVerificationResultV1`
    into Control's real `HostAdmissionForeignVerificationEvidenceV1`. Field
    names differ deliberately (ADR-0073: the two packages never import each
    other), so this mapping is CP's, not either package's own -- including
    the one outright rename: Foundation's `trust_root_version` becomes
    Control's `root_version` on each verified-root sub-object."""
    return HostAdmissionForeignVerificationEvidenceV1(
        candidate_attestation_envelope_digest=result.candidate_attestation_envelope_digest,
        installed_attestation_envelope_digest=result.installed_attestation_envelope_digest,
        verification_context_digest=result.verification_context_digest,
        verified_host_identity=result.expected_host_identity,
        verified_observation_id=result.expected_observation_id,
        verified_package=result.expected_package,
        verified_candidate_audience=result.candidate_audience,
        verified_installed_audience=result.installed_audience,
        verified_candidate_root=HostAdmissionForeignRootV1(
            public_key_fingerprint=result.candidate_root.public_key_fingerprint,
            root_version=result.candidate_root.trust_root_version,
            key_id=result.candidate_root.key_id,
            algorithm=result.candidate_root.algorithm,
            purpose=result.candidate_root.purpose,
            custody_domain=result.candidate_root.custody_domain,
            issuer=result.candidate_root.issuer,
        ),
        verified_installed_root=HostAdmissionForeignRootV1(
            public_key_fingerprint=result.installed_root.public_key_fingerprint,
            root_version=result.installed_root.trust_root_version,
            key_id=result.installed_root.key_id,
            algorithm=result.installed_root.algorithm,
            purpose=result.installed_root.purpose,
            custody_domain=result.installed_root.custody_domain,
            issuer=result.installed_root.issuer,
        ),
    )


def _idempotency_marker_count(db: Session, attempt_id: uuid.UUID) -> int:
    rows = (
        db.execute(
            select(PlatformIdempotencyRecord).where(
                PlatformIdempotencyRecord.scope
                == control_service._SCOPE_CONSUME_DISPATCH_CHALLENGE,
                PlatformIdempotencyRecord.key == str(attempt_id),
            )
        )
        .scalars()
        .all()
    )
    committed = lookup_foundation_execution_consumption(
        db, control_consumption_ref=f"control-dispatch:{attempt_id}"
    )
    assert (committed is not None) == (len(rows) == 1)
    if committed is not None:
        assert committed.attempt_id == attempt_id
        assert committed.dispatch_id == str(attempt_id)
    return len(rows)


@dataclasses.dataclass(frozen=True)
class _VerificationInputs:
    candidate: AttestationEnvelopeV2
    installed: AttestationEnvelopeV2
    foundation_verifier: _FoundationAttestationVerifier
    now: datetime


def _verify_and_finalize_control(
    *,
    resolve_session: Session,
    admit_session: Session,
    attempt_id: uuid.UUID,
    presentation: HostAdmissionPresentationV1,
    execution: FoundationDispatchConsumptionV1,
    resolve_context: Any,
    verify_pair: Any,
    admit_and_consume: Any,
    launch: Any,
    build_foreign_evidence: Any,
    build_trust_policy: Any,
    verification: _VerificationInputs,
) -> Any:
    """Test-owned component driver, NOT CP's production composition.

    The complete signed-pair input is mandatory. No compatibility API or
    production fallback is introduced. The callback only observes a committed
    component result; this helper grants no CP execution authority.
    """
    assert resolve_session is not admit_session
    context = resolve_context(
        resolve_session, attempt_id=attempt_id, presentation=presentation
    )
    resolve_session.commit()
    assert not resolve_session.in_transaction()
    assert not admit_session.in_transaction()
    result = verify_pair(
        candidate=verification.candidate,
        installed=verification.installed,
        verifier=verification.foundation_verifier,
        trust_policy=build_trust_policy(context),
        expected_host_identity=context.host_id,
        expected_observation_id=context.dispatch_id,
        expected_package=context.expected_foundation_package,
        verification_context_digest=context.context_digest,
        now=verification.now,
    )
    staged = admit_and_consume(
        admit_session,
        context=context,
        foreign_evidence=build_foreign_evidence(result),
        execution=execution,
    )
    admit_session.commit()
    launch(staged)
    return staged


# ── Component verification properties ───────────────────────────────


def test_valid_signed_attestations_complete_the_full_flow(
    db: Session, admit_db: Session
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    launched: list[Any] = []

    result = _verify_and_finalize_control(
        resolve_session=db,
        admit_session=admit_db,
        attempt_id=coordinate.attempt_id,
        presentation=coordinate.presentation,
        execution=coordinate.execution,
        resolve_context=resolve_host_admission_context,
        verify_pair=verify_attestation_pair,
        admit_and_consume=admit_and_consume_host_admission,
        launch=lambda staged: launched.append(staged),
        build_foreign_evidence=_map_foundation_result_to_control_evidence,
        build_trust_policy=lambda resolved: coordinate.trust_policy,
        verification=_VerificationInputs(
            candidate=coordinate.candidate_envelope,
            installed=coordinate.installed_envelope,
            foundation_verifier=coordinate.foundation_verifier,
            now=coordinate.clock.now(),
        ),
    )

    assert len(launched) == 1
    assert launched[0] is result
    # Read back through `db` -- a DIFFERENT connection from `admit_db`, which
    # is where the marker was actually written and committed. Seeing it here
    # proves the write is really durable, not merely visible on the writer's
    # own connection.
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 1


def _build_trust_policy_from_resolved_context(resolved: Any) -> AttestationTrustPolicy:
    """A REAL production-shaped `build_trust_policy` -- unlike every other
    test in this file (which closes over `coordinate.trust_policy`, already
    built before any resolve happened, for setup simplicity), this derives
    the policy FRESH from Control's real resolved context, exactly the way
    any real production caller must. An independent security review found
    that no test anywhere exercised this actual derivation -- every existing
    test's `build_trust_policy` ignored `resolved` entirely -- so the historical
    component result proved Control's comparison fires, but not that the
    caller-side mapping it depends on is even possible to write correctly
    with the real fields `HostAdmissionVerificationContextV1` exposes.

    `HostAdmissionRootContextV1.public_key_base64` is ALREADY in
    Foundation's padded-standard-base64 form (`_root_context` computes it via
    Control's own `foundation_public_key_base64`) -- unlike this file's own
    fixture setup in `_build_admission_coordinate`, which must convert
    Control's stored unpadded-base64url key material via `_to_foundation_b64`
    because that setup runs BEFORE any resolve exists. A real derivation
    needs no such conversion, which is itself worth proving: it means
    `_to_foundation_b64`'s existence in this file is fixture-setup-specific,
    not something a real caller also has to reproduce.
    """

    def _root(root: Any) -> AttestationTrustRootV2:
        return AttestationTrustRootV2(
            public_key_fingerprint=root.public_key_fingerprint,
            public_key_base64=root.public_key_base64,
            purpose=root.purpose,
            custody_domain=root.custody_domain,
            issuer=root.issuer,
            key_id=root.key_id,
            algorithm=root.algorithm,
            trust_root_version=root.root_version,
            not_before=root.not_before.isoformat().replace("+00:00", "Z"),
            not_after=root.not_after.isoformat().replace("+00:00", "Z"),
            revoked=root.revoked,
        )

    return AttestationTrustPolicy(
        candidate_roots=(_root(resolved.candidate_root),),
        installed_roots=(_root(resolved.installed_root),),
        candidate_audience=resolved.candidate_audience,
        installed_audience=resolved.installed_audience,
    )


def test_a_trust_policy_genuinely_derived_from_resolved_context_completes_the_full_flow(
    db: Session, admit_db: Session
) -> None:
    """Same shape as `test_valid_signed_attestations_complete_the_full_flow`,
    with exactly one difference: `build_trust_policy` is
    `_build_trust_policy_from_resolved_context` -- a real derivation from
    `resolved`, not a closure over an already-built policy. Proves the
    mapping an independent review flagged as unexercised is both POSSIBLE
    and CORRECT with the real fields Control's resolved context exposes."""
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    launched: list[Any] = []

    result = _verify_and_finalize_control(
        resolve_session=db,
        admit_session=admit_db,
        attempt_id=coordinate.attempt_id,
        presentation=coordinate.presentation,
        execution=coordinate.execution,
        resolve_context=resolve_host_admission_context,
        verify_pair=verify_attestation_pair,
        admit_and_consume=admit_and_consume_host_admission,
        launch=lambda staged: launched.append(staged),
        build_foreign_evidence=_map_foundation_result_to_control_evidence,
        build_trust_policy=_build_trust_policy_from_resolved_context,
        verification=_VerificationInputs(
            candidate=coordinate.candidate_envelope,
            installed=coordinate.installed_envelope,
            foundation_verifier=coordinate.foundation_verifier,
            now=coordinate.clock.now(),
        ),
    )

    assert len(launched) == 1
    assert launched[0] is result
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 1


def test_an_invalid_signature_stops_inside_real_foundation_code(
    db: Session, admit_db: Session
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    # Tamper with ONE signed field of the candidate envelope's subject after
    # signing -- the signature still authenticates the ORIGINAL bytes, so
    # real Foundation code must refuse.
    mutated_subject = dict(coordinate.candidate_envelope.subject_mapping())
    mutated_subject["version"] = "9.9.9-tampered"
    tampered_candidate = dataclasses.replace(
        coordinate.candidate_envelope, subject=mutated_subject
    )
    launched: list[Any] = []

    with pytest.raises(PreconditionFailed) as excinfo:
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=tampered_candidate,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert excinfo.value.code == "trusted-host-source-signature-invalid"
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_a_sentinel_foundation_failure_has_no_fallback(
    db: Session, admit_db: Session
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    class _Sentinel(Exception):
        pass

    def _raising_verify(**kwargs: object) -> object:
        raise _Sentinel("Foundation is unreachable")

    launched: list[Any] = []
    with pytest.raises(_Sentinel):
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=_raising_verify,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_an_altered_evidence_digest_is_refused(db: Session, admit_db: Session) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    def _substituting_mapper(result: Any) -> HostAdmissionForeignVerificationEvidenceV1:
        real = _map_foundation_result_to_control_evidence(result)
        return dataclasses.replace(
            real, candidate_attestation_envelope_digest="sha256:" + "ee" * 32
        )

    launched: list[Any] = []
    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert excinfo.value.code is HostAdmissionRefusalCode.EVIDENCE_CHANGED
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_a_substituted_verified_host_identity_is_refused(
    db: Session, admit_db: Session
) -> None:
    """Mirrors `test_an_altered_evidence_digest_is_refused`'s exact shape,
    but corrupts `verified_host_identity` instead of an envelope digest --
    proving Control's widened `FOREIGN_EVIDENCE_SEMANTIC_MISMATCH` refusal
    fires when Foundation's reported host identity does not match what
    Control itself resolved, with zero launches and zero idempotency
    markers."""
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    def _substituting_mapper(result: Any) -> HostAdmissionForeignVerificationEvidenceV1:
        real = _map_foundation_result_to_control_evidence(result)
        return dataclasses.replace(
            real, verified_host_identity="a-different-host-entirely"
        )

    launched: list[Any] = []
    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert (
        excinfo.value.code
        is HostAdmissionRefusalCode.FOREIGN_EVIDENCE_SEMANTIC_MISMATCH
    )
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_a_substituted_verified_candidate_root_field_is_refused(
    db: Session, admit_db: Session
) -> None:
    """Same shape again, corrupting one field (`public_key_fingerprint`) of
    `verified_candidate_root` instead -- proving the widened refusal also
    catches a root-identity mismatch, not only a flat string field."""
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    def _substituting_mapper(result: Any) -> HostAdmissionForeignVerificationEvidenceV1:
        real = _map_foundation_result_to_control_evidence(result)
        tampered_root = dataclasses.replace(
            real.verified_candidate_root,
            public_key_fingerprint="sha256:" + "cc" * 32,
        )
        return dataclasses.replace(real, verified_candidate_root=tampered_root)

    launched: list[Any] = []
    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert (
        excinfo.value.code
        is HostAdmissionRefusalCode.FOREIGN_EVIDENCE_SEMANTIC_MISMATCH
    )
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_a_state_change_between_resolve_and_admission_consumes_nothing(
    db: Session,
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    context = resolve_host_admission_context(
        db, attempt_id=coordinate.attempt_id, presentation=coordinate.presentation
    )
    db.commit()

    # Revoke the credential between resolve and admission -- a genuine
    # concurrent-mutation scenario, not simulated.
    revoke_credential(
        db,
        CredentialTransitionCommand(
            command_id=_cmd(), credential_id=coordinate.credential_id
        ),
    )
    db.commit()

    result = verify_attestation_pair(
        candidate=coordinate.candidate_envelope,
        installed=coordinate.installed_envelope,
        verifier=coordinate.foundation_verifier,
        trust_policy=coordinate.trust_policy,
        expected_host_identity=coordinate.trust_policy.installed_audience,
        expected_observation_id=str(coordinate.attempt_id),
        expected_package=read_installed_artifact().distribution,
        verification_context_digest=context.context_digest,
        now=coordinate.clock.now(),
    )
    evidence = _map_foundation_result_to_control_evidence(result)

    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        admit_and_consume_host_admission(
            db,
            context=context,
            foreign_evidence=evidence,
            execution=coordinate.execution,
        )
    assert excinfo.value.code is HostAdmissionRefusalCode.PREPARED_STATE_CHANGED
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_expiry_between_foundation_verification_and_final_admission_is_refused(
    db: Session,
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    context = resolve_host_admission_context(
        db, attempt_id=coordinate.attempt_id, presentation=coordinate.presentation
    )
    db.commit()

    result = verify_attestation_pair(
        candidate=coordinate.candidate_envelope,
        installed=coordinate.installed_envelope,
        verifier=coordinate.foundation_verifier,
        trust_policy=coordinate.trust_policy,
        expected_host_identity=coordinate.trust_policy.installed_audience,
        expected_observation_id=str(coordinate.attempt_id),
        expected_package=read_installed_artifact().distribution,
        verification_context_digest=context.context_digest,
        now=coordinate.clock.now(),
    )
    evidence = _map_foundation_result_to_control_evidence(result)

    # Advance the REAL trusted clock past the presentation's own expires_at
    # (5 minutes after issued_at) -- proving admit_and_consume_host_admission's
    # OWN fresh-clock check, not a simulation of one.
    coordinate.clock.advance(timedelta(minutes=6))

    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        admit_and_consume_host_admission(
            db,
            context=context,
            foreign_evidence=evidence,
            execution=coordinate.execution,
        )
    assert excinfo.value.code is HostAdmissionRefusalCode.CONTEXT_EXPIRED
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_component_observer_runs_only_after_the_admission_transaction_commits(
    db: Session, admit_db: Session
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )

    events: list[str] = []
    real_resolve_commit = db.commit
    real_admit_commit = admit_db.commit

    def _recording_resolve_commit() -> None:
        events.append("resolve_commit")
        real_resolve_commit()

    def _recording_admit_commit() -> None:
        events.append("admit_commit")
        real_admit_commit()

    def _recording_launch(staged: object) -> None:
        events.append("launch")

    db.commit = _recording_resolve_commit  # type: ignore[method-assign]
    admit_db.commit = _recording_admit_commit  # type: ignore[method-assign]
    try:
        _verify_and_finalize_control(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            execution=coordinate.execution,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=_recording_launch,
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=_VerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    finally:
        db.commit = real_resolve_commit  # type: ignore[method-assign]
        admit_db.commit = real_admit_commit  # type: ignore[method-assign]

    # Distinguishable now that resolve and admit run on two real, separate
    # sessions/connections: resolve's own commit, then admit's own commit,
    # then launch -- never launch before either commit, and never admit's
    # commit before resolve's.
    assert events == ["resolve_commit", "admit_commit", "launch"]


def test_real_cp_v3_refuses_an_approval_requiring_plan_before_finalization(
    db: Session,
) -> None:
    """Current CP composition is fail-closed, not positively adopted at Gate 0.

    Real Foundation F2 first verifies both envelopes against Control-derived
    roots and reads the actual installed wheel. The real CP V3 provider then
    reads the real plan and refuses the still-unowned Approvals subject.
    No get_plan fake, row edits, compatibility consumer or alternate launch.
    """
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    db.commit()
    engine = create_engine(CONFORMANCE_DATABASE_URL, future=True)
    sessions: list[Session] = []
    finalizations: list[object] = []
    read_plans: list[object] = []

    def _session() -> Session:
        session = Session(bind=engine)
        sessions.append(session)
        return session

    def _real_f2(**kwargs: Any) -> Any:
        assert len(sessions) == 1 and not sessions[0].in_transaction()
        assert not db.in_transaction()
        return admit_host_source(**kwargs)

    def _finalize(session: Session, **kwargs: Any) -> Any:
        finalizations.append(kwargs)
        return admit_and_consume_host_admission(session, **kwargs)

    def _checked_get_plan(session: Session, plan_id: uuid.UUID) -> Any:
        assert plan_id == uuid.UUID(coordinate.facts.plan_id)
        plan = get_plan(session, plan_id)
        assert plan is not None, "the real plan read must succeed"
        assert plan.requires_approval is True
        assert plan.target_id == coordinate.target_id
        read_plans.append(plan)
        return plan

    providers = compose_foundation_v3_providers(
        control=ControlFoundationV3Bindings(
            resolve_context=resolve_host_admission_context,
            finalize=_finalize,
            attest_pair=attest_foundation_execution_pair,
            lookup_committed=lookup_foundation_execution_consumption,
            get_plan=_checked_get_plan,
            foreign_root_type=HostAdmissionForeignRootV1,
            foreign_evidence_type=HostAdmissionForeignVerificationEvidenceV1,
            execution_context_type=FoundationExecutionContextV1,
            consumption_request_type=FoundationDispatchConsumptionV1,
        ),
        foundation=FoundationHostV3Bindings(
            admit_host_source=_real_f2,
            trust_policy_from_context=_build_trust_policy_from_resolved_context,
            verifier=coordinate.foundation_verifier,
            trace_type=HostSourceAdmissionTrace,
            pair_result_type=AttestationPairVerificationResultV1,
            consumption_request_type=ControlConsumptionRequestV3,
            execution_context_type=ExecutionContextV3,
        ),
        sources=FoundationV3Sources(
            sessions=_session,
            host_admission=lambda: HostAdmissionObservation(
                coordinate.attempt_id,
                coordinate.presentation,
                coordinate.candidate_envelope,
                coordinate.installed_envelope,
            ),
            execution_context=lambda: coordinate.facts,
            clock=coordinate.clock.now,
        ),
    )
    try:
        source, trace = providers.host_source.admit_host_source()
        assert source.artifact_digest == read_installed_artifact().artifact_digest
        request = ControlConsumptionRequestV3(
            authorization_material_json=coordinate.execution.authorization_material_json,
            dispatch_material_json=coordinate.execution.dispatch_material_json,
            host_source_trace=trace,
            expected_execution_plan_digest=_EXECUTION_PLAN,
            control_consumption_ref=coordinate.execution.control_consumption_ref,
        )
        with pytest.raises(DispatchApprovalSubjectUnavailable) as refused:
            providers.execution_authority.consume_dispatch(request=request)
        assert refused.value.code == "c2_dispatch_approval_subject_unavailable"
        assert "requires approval" in str(refused.value)
        assert len(read_plans) == 1
        assert len(sessions) == 2 and sessions[0] is not sessions[1]
        assert all(not session.in_transaction() for session in sessions)
        assert finalizations == []
        assert _idempotency_marker_count(db, coordinate.attempt_id) == 0
        assert (
            lookup_foundation_execution_consumption(
                db, control_consumption_ref=coordinate.execution.control_consumption_ref
            )
            is None
        )
        # Sensitivity: a missing-plan lookup must not pass as the same typed
        # approval-subject refusal. The same checked reader must fail first.
        with pytest.MonkeyPatch.context() as plant:
            plant.setitem(globals(), "get_plan", lambda *_: None)
            with pytest.raises(AssertionError, match="real plan read must succeed"):
                _checked_get_plan(db, uuid.UUID(coordinate.facts.plan_id))
    finally:
        for session in sessions:
            session.close()
        engine.dispose()


@pytest.mark.parametrize(
    "scenario",
    [
        "positive",
        "withdrawn",
        "replay",
        "finalize_failure",
        "expired",
        "revoked",
        "changed_target",
        "changed_observation",
        "changed_host",
        "ambiguous_commit",
        "swapped_request",
        "session_reuse",
        "finalization_withdrawal",
    ],
)
def test_real_approved_cp_v3_lifecycle(db: Session, monkeypatch, scenario: str) -> None:
    """Noncandidate source composition with real Approvals, Control and F2."""
    coordinate = _build_admission_coordinate(db, now=_NOW, genuine_approval=True)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    db.commit()
    engine = create_engine(CONFORMANCE_DATABASE_URL, future=True)
    sessions: list[Session] = []
    facts = [coordinate.facts]

    class _CommitSession(Session):
        def commit(self):
            super().commit()
            if scenario == "ambiguous_commit" and len(sessions) == 2:
                raise RuntimeError("simulated lost commit acknowledgement")

    def session_factory():
        if scenario == "session_reuse" and sessions:
            return sessions[0]
        session = _CommitSession(bind=engine)
        sessions.append(session)
        return session

    providers = foundation_approval.compose_approved_foundation_v3_providers(
        foundation=FoundationHostV3Bindings(
            admit_host_source=admit_host_source,
            trust_policy_from_context=_build_trust_policy_from_resolved_context,
            verifier=coordinate.foundation_verifier,
            trace_type=HostSourceAdmissionTrace,
            pair_result_type=AttestationPairVerificationResultV1,
            consumption_request_type=ControlConsumptionRequestV3,
            execution_context_type=ExecutionContextV3,
        ),
        sources=FoundationV3Sources(
            sessions=session_factory,
            host_admission=lambda: HostAdmissionObservation(
                coordinate.attempt_id,
                coordinate.presentation,
                coordinate.candidate_envelope,
                coordinate.installed_envelope,
            ),
            execution_context=lambda: facts[0],
            clock=coordinate.clock.now,
        ),
    )
    try:
        _, trace = providers.host_source.admit_host_source()
        request = ControlConsumptionRequestV3(
            authorization_material_json=coordinate.execution.authorization_material_json,
            dispatch_material_json=coordinate.execution.dispatch_material_json,
            host_source_trace=trace,
            expected_execution_plan_digest=_EXECUTION_PLAN,
            control_consumption_ref=coordinate.execution.control_consumption_ref,
        )
        if scenario == "withdrawn":
            approvals.withdraw_request(
                db,
                approvals.WithdrawRequestCommand(
                    request_id=uuid.UUID(coordinate.facts.approval_decision_ref),
                    actor_id=uuid.uuid4(),
                    authority_ref="source-conformance",
                    reason="withdraw before finalization",
                    external_ref=_cmd(),
                ),
            )
            db.commit()
        elif scenario == "revoked":
            import dotmac_deployment_control as control

            control.revoke_plan_approval(
                db,
                control.RevokePlanApprovalCommand(
                    command_id=_cmd(),
                    plan_id=uuid.UUID(coordinate.facts.plan_id),
                    revocation_ref="source-conformance-revocation",
                ),
            )
            db.commit()
        elif scenario == "expired":
            coordinate.clock.advance(timedelta(minutes=2))
        elif scenario in {"changed_target", "changed_host", "swapped_request"}:
            field = {
                "changed_target": "target_id",
                "changed_host": "host_id",
                "swapped_request": "approval_decision_ref",
            }[scenario]
            facts[0] = dataclasses.replace(facts[0], **{field: str(uuid.uuid4())})
        elif scenario == "changed_observation":
            request = dataclasses.replace(
                request,
                host_source_trace=dataclasses.replace(
                    trace, host_observation_id=str(uuid.uuid4())
                ),
            )
        elif scenario == "finalize_failure":
            import dotmac_deployment_control as control

            real_finalize = control.admit_and_consume_host_admission

            def fail_after_preparation(*args, **kwargs):
                real_finalize(*args, **kwargs)
                raise RuntimeError("simulated finalizer failure before commit")

            monkeypatch.setattr(
                control, "admit_and_consume_host_admission", fail_after_preparation
            )
        elif scenario == "finalization_withdrawal":
            import dotmac_deployment_control as control

            real_finalize = control.admit_and_consume_host_admission
            withdrawal_results: list[object] = []

            def withdraw_while_finalization_is_held():
                with Session(engine) as peer:
                    peer.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    try:
                        approvals.withdraw_request(
                            peer,
                            approvals.WithdrawRequestCommand(
                                request_id=uuid.UUID(
                                    coordinate.facts.approval_decision_ref
                                ),
                                actor_id=uuid.uuid4(),
                                authority_ref="source-conformance",
                                reason="concurrent finalization withdrawal",
                                external_ref=_cmd(),
                            ),
                        )
                        withdrawal_results.append("unexpectedly_unblocked")
                    except OperationalError as exc:
                        withdrawal_results.append(getattr(exc.orig, "sqlstate", None))
                    finally:
                        peer.rollback()

            def finalize_with_peer_withdrawal(*args, **kwargs):
                result = real_finalize(*args, **kwargs)
                # The real finalizer has staged consumption, but its caller
                # has not committed. Approvals' FOR SHARE must still stand.
                peer = threading.Thread(target=withdraw_while_finalization_is_held)
                peer.start()
                peer.join(timeout=5)
                assert not peer.is_alive(), "withdrawal exceeded bounded wait"
                assert withdrawal_results == ["55P03"]
                return result

            monkeypatch.setattr(
                control,
                "admit_and_consume_host_admission",
                finalize_with_peer_withdrawal,
            )

        if scenario in {"positive", "replay", "finalization_withdrawal"}:
            providers.execution_authority.consume_dispatch(request=request)
        elif scenario == "expired":
            with pytest.raises(AuthorizationEnvelopeRefusedError) as refused:
                providers.execution_authority.consume_dispatch(request=request)
            assert refused.value.code is AuthorizationEnvelopeRefusalCode.EXPIRED
        else:
            # Owner exceptions vary by refusing boundary; every case below
            # independently proves the durable marker remains absent.
            with pytest.raises(
                (
                    RuntimeError,
                    approvals.ApprovalNotHeld,
                    HostAdmissionRefusedError,
                    HostAdmissionAdapterUsageError,
                    FoundationConsumptionRefusedError,
                    TransitionRefusedError,
                )
            ):
                providers.execution_authority.consume_dispatch(request=request)

        expected = scenario in {
            "positive",
            "replay",
            "ambiguous_commit",
            "finalization_withdrawal",
        }
        db.rollback()
        assert _idempotency_marker_count(db, coordinate.attempt_id) == int(expected)
        committed = providers.execution_authority.lookup_committed(
            control_consumption_ref=coordinate.execution.control_consumption_ref
        )
        assert (committed is not None) is expected
        if scenario == "finalization_withdrawal":
            # The provider's single commit released the hold. A subsequent
            # real withdrawal succeeds without erasing committed consumption.
            result = approvals.withdraw_request(
                db,
                approvals.WithdrawRequestCommand(
                    request_id=uuid.UUID(coordinate.facts.approval_decision_ref),
                    actor_id=uuid.uuid4(),
                    authority_ref="source-conformance",
                    reason="withdraw after committed consumption",
                    external_ref=_cmd(),
                ),
            )
            db.commit()
            assert result.satisfied is False
            assert _idempotency_marker_count(db, coordinate.attempt_id) == 1
        if scenario == "replay":
            with pytest.raises(
                (
                    HostAdmissionRefusedError,
                    FoundationConsumptionRefusedError,
                    TransitionRefusedError,
                )
            ):
                providers.execution_authority.consume_dispatch(request=request)
            db.rollback()
            assert _idempotency_marker_count(db, coordinate.attempt_id) == 1
        # An ambiguous commit is resolved only through committed lookup above.
        # No consume retry is issued and no workload is launched.
        assert all(not session.in_transaction() for session in sessions)
    finally:
        for session in sessions:
            session.close()
        engine.dispose()


# ── The scoped consumption role, proven against a real database ─────────────
#
# E6 review R1-R5, R11 and the transit/RLS design. The role, its limits and its
# ledger policies are created from the EXACT statements `consumption_role_spec`
# renders (the same text the grants document embeds), in this job's disposable
# database only. Control's real consumption path then runs AS that role under the
# per-run row level security, so a missing or surplus grant, or a policy that
# refuses the legitimate insert, fails here rather than in the one granted image's
# first real run.

CONFORMANCE_ADMIN_DATABASE_URL = os.environ.get("CONFORMANCE_ADMIN_DATABASE_URL")
_LEDGER_RELATION = "public.platform_idempotency_records"


def _admin_engine() -> Any:
    assert CONFORMANCE_ADMIN_DATABASE_URL, (
        "CONFORMANCE_ADMIN_DATABASE_URL is required: the scoped-role cases "
        "create a role in the disposable database. Missing is a failure, not a skip"
    )
    return create_engine(CONFORMANCE_ADMIN_DATABASE_URL, isolation_level="AUTOCOMMIT")


def _run_statements(admin: Any, statements: Any) -> None:
    """Run rendered SQL as written. A failure inside the rendered transaction is
    rolled back before it is re-raised, so the connection is never left aborted."""
    with admin.connect() as connection:
        try:
            for statement in statements:
                connection.exec_driver_sql(statement)
        except Exception:
            connection.exec_driver_sql("ROLLBACK")
            raise


def _guard_reset(admin: Any) -> None:
    """Leave the ledger exactly as Kernel ships it, whatever an earlier case did."""
    with admin.connect() as connection:
        connection.exec_driver_sql(
            f"DROP POLICY IF EXISTS {consumption_scope.GUARD_POLICY} ON {_LEDGER_RELATION}"
        )
        connection.exec_driver_sql(
            f"ALTER TABLE {_LEDGER_RELATION} DISABLE ROW LEVEL SECURITY"
        )


def _create_run_role(admin: Any, dispatch_id: str) -> tuple[str, str]:
    """Guard on, then the role: returns `(role, scram verifier)`."""
    role = f"cp_run_{uuid.uuid4().hex[:10]}"
    verifier = consumption_role_spec.scram_verifier(secrets.token_urlsafe(32))
    _run_statements(admin, consumption_role_spec.guard_enable_sql())
    _run_statements(
        admin,
        consumption_role_spec.creation_sql(
            role,
            dispatch_id=dispatch_id,
            scram_verifier=verifier,
            valid_until=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    return role, verifier


def _teardown_run_role(admin: Any, role: str) -> None:
    """Best-effort full teardown (every step attempted), then the guard off."""
    for statement in consumption_role_spec.revocation_sql(role):
        with contextlib.suppress(Exception):
            with admin.connect() as connection:
                connection.exec_driver_sql(statement)
    _guard_reset(admin)


def _role_url(role: str) -> Any:
    return make_url(CONFORMANCE_DATABASE_URL).set(username=role, password=None)


def _sqlstate(error: BaseException) -> str | None:
    return getattr(getattr(error, "orig", error), "sqlstate", None)


def _consume_as(
    db: Session, coordinate: _AdmissionCoordinate, engine: Any, sessions: list[Session]
) -> Any:
    """Control's real approved consumption, every session connected as the role."""

    def session_factory() -> Session:
        session = Session(bind=engine)
        sessions.append(session)
        return session

    providers = foundation_approval.compose_approved_foundation_v3_providers(
        foundation=FoundationHostV3Bindings(
            admit_host_source=admit_host_source,
            trust_policy_from_context=_build_trust_policy_from_resolved_context,
            verifier=coordinate.foundation_verifier,
            trace_type=HostSourceAdmissionTrace,
            pair_result_type=AttestationPairVerificationResultV1,
            consumption_request_type=ControlConsumptionRequestV3,
            execution_context_type=ExecutionContextV3,
        ),
        sources=FoundationV3Sources(
            sessions=session_factory,
            host_admission=lambda: HostAdmissionObservation(
                coordinate.attempt_id,
                coordinate.presentation,
                coordinate.candidate_envelope,
                coordinate.installed_envelope,
            ),
            execution_context=lambda: coordinate.facts,
            clock=coordinate.clock.now,
        ),
    )
    _, trace = providers.host_source.admit_host_source()
    request = ControlConsumptionRequestV3(
        authorization_material_json=coordinate.execution.authorization_material_json,
        dispatch_material_json=coordinate.execution.dispatch_material_json,
        host_source_trace=trace,
        expected_execution_plan_digest=_EXECUTION_PLAN,
        control_consumption_ref=coordinate.execution.control_consumption_ref,
    )
    providers.execution_authority.consume_dispatch(request=request)
    return providers, request


def _prove_consumed_and_out_of_scope_refused(
    db: Session,
    admin: Any,
    engine: Any,
    role: str,
    verifier: str,
    coordinate: _AdmissionCoordinate,
    sessions: list[Session],
) -> None:
    dispatch_id = str(coordinate.attempt_id)
    with admin.connect() as connection:
        stored = connection.execute(
            text("SELECT rolpassword FROM pg_authid WHERE rolname = :role"),
            {"role": role},
        ).scalar_one()
    # The server stored the client-computed verifier AS GIVEN: no plaintext ever
    # reached it, and a logged verifier cannot log in.
    assert stored == verifier and stored.startswith("SCRAM-SHA-256$")

    # The proof, as the role itself and from the ceremony's admin connection.
    consumption_scope.prove_scoped_role(
        lambda: Session(bind=engine), dispatch_id=dispatch_id
    )
    consumption_scope.prove_scoped_role(
        lambda: Session(bind=admin), role=role, dispatch_id=dispatch_id
    )
    # ... and a role bound to a DIFFERENT dispatch fails the same proof.
    with pytest.raises(consumption_scope.FoundationBindingsUnavailable):
        consumption_scope.prove_scoped_role(
            lambda: Session(bind=admin), role=role, dispatch_id=str(uuid.uuid4())
        )

    providers, request = _consume_as(db, coordinate, engine, sessions)
    db.rollback()
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 1
    assert (
        providers.execution_authority.lookup_committed(
            control_consumption_ref=coordinate.execution.control_consumption_ref
        )
        is not None
    )
    # Replay is refused under the guard.
    with pytest.raises(
        (
            HostAdmissionRefusedError,
            FoundationConsumptionRefusedError,
            TransitionRefusedError,
        )
    ):
        providers.execution_authority.consume_dispatch(request=request)
    db.rollback()
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 1
    # The legitimate path trips nothing: millisecond transactions, no advisory lock.
    with Session(bind=admin) as watcher:
        assert consumption_watchdog.tick(watcher, role) == []

    with admin.connect() as connection:
        ledger_column = connection.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND table_name = 'platform_idempotency_records' "
                "ORDER BY ordinal_position LIMIT 1"
            )
        ).scalar_one()
    refused = {
        "verification key column": "UPDATE mod_deploy.target_credentials "
        "SET public_key_b64 = public_key_b64 WHERE false",
        "lock table business column": "UPDATE mod_deploy.deployment_targets "
        "SET status = status WHERE false",
        "ledger update": "UPDATE public.platform_idempotency_records "  # noqa: S608
        f"SET {ledger_column} = {ledger_column} WHERE false",
        "ledger delete": "DELETE FROM public.platform_idempotency_records WHERE false",
        "ledger truncate": "TRUNCATE public.platform_idempotency_records",
        "rollout insert": "INSERT INTO mod_deploy.rollouts DEFAULT VALUES",
        "read-only table write": "UPDATE mod_deploy.attestation_enrolments "
        "SET updated_at = updated_at WHERE false",
        "non-contract Control table": (
            "SELECT 1 FROM mod_deploy.recovery_grants LIMIT 1"
        ),
        "schema create": "CREATE TABLE public.cp_run_scratch (a integer)",
        "role switch": "SET ROLE postgres",
        "clear the statement log": "SET log_statement = 'none'",
        "raise the temp file limit": "SET temp_file_limit = -1",
    }
    for name, statement in refused.items():
        with Session(bind=engine) as probe:
            with pytest.raises(DBAPIError) as caught:
                probe.execute(text(statement))
            assert _sqlstate(caught.value) == "42501", name
    # The grants that ARE given work: the lock column.
    with Session(bind=engine) as probe:
        probe.execute(
            text(
                "UPDATE mod_deploy.deployment_targets SET updated_at = updated_at WHERE false"
            )
        )
        probe.rollback()

    # ── the ledger guard: RLS refuses out-of-scope INSERT and hides other rows ──
    decoy = f"decoy-{uuid.uuid4().hex[:8]}"
    insert = (
        "INSERT INTO public.platform_idempotency_records "
        '(id, scope, "key", operation, status, fingerprint) '
        "VALUES (gen_random_uuid(), :scope, :key, :scope, 'executed', :fp)"
    )
    own_scope = consumption_scope.LEDGER_SCOPE
    fp = "a" * 64
    with admin.connect() as connection:
        connection.execute(
            text(insert), {"scope": "decoy.scope", "key": decoy, "fp": fp}
        )
    try:
        attempts = {
            "other scope": {"scope": "decoy.scope", "key": dispatch_id, "fp": fp},
            "other key, own scope": {"scope": own_scope, "key": decoy, "fp": fp},
            "bad fingerprint": {"scope": own_scope, "key": dispatch_id, "fp": "zz"},
        }
        for name, params in attempts.items():
            with Session(bind=engine) as probe:
                with pytest.raises(DBAPIError) as caught:
                    probe.execute(text(insert), params)
                assert _sqlstate(caught.value) == "42501", name
        with Session(bind=engine) as probe:
            with pytest.raises(DBAPIError) as caught:
                probe.execute(
                    text(
                        "INSERT INTO public.platform_idempotency_records "
                        '(id, scope, "key", operation, status, fingerprint, created_at) '
                        "VALUES (gen_random_uuid(), :scope, :key, :scope, 'executed', "
                        ":fp, now() - interval '1 day')"
                    ),
                    {"scope": own_scope, "key": dispatch_id, "fp": fp},
                )
            assert _sqlstate(caught.value) == "42501", "backdated created_at"
        # A row that satisfies the policy gets PAST it (the unique constraint,
        # not RLS, then stops it): the policy admits exactly the one coordinate.
        with Session(bind=engine) as probe:
            with pytest.raises(DBAPIError) as caught:
                probe.execute(
                    text(insert), {"scope": own_scope, "key": dispatch_id, "fp": fp}
                )
            assert _sqlstate(caught.value) == "23505", "policy-satisfying insert"
        # SELECT is bound to the run's own (scope, key).
        with Session(bind=engine) as probe:
            rows = probe.execute(
                text('SELECT scope, "key" FROM public.platform_idempotency_records')
            ).all()
            assert [tuple(row) for row in rows] == [(own_scope, dispatch_id)]
        with admin.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM public.platform_idempotency_records "
                        'WHERE "key" = :key'
                    ),
                    {"key": decoy},
                ).scalar_one()
                == 1
            )
        # COPY FROM is refused for a role RLS applies to (SQLSTATE 0A000).
        raw = engine.raw_connection()
        try:
            with pytest.raises(Exception) as copy_refused:
                with raw.cursor() as cursor:
                    with cursor.copy(
                        "COPY public.platform_idempotency_records "
                        '(id, scope, "key", operation, status) FROM STDIN'
                    ) as copy:
                        copy.write_row(
                            (str(uuid.uuid4()), own_scope, "k", "o", "executed")
                        )
            assert _sqlstate(copy_refused.value) == "0A000"
        finally:
            raw.close()
        # Inert for everyone else: platform_api still reads every row.
        with Session(bind=db.get_bind()) as peer:
            assert (
                peer.execute(
                    text(
                        "SELECT count(*) FROM public.platform_idempotency_records "
                        'WHERE "key" = :key'
                    ),
                    {"key": decoy},
                ).scalar_one()
                == 1
            )
    finally:
        with admin.connect() as connection:
            connection.execute(
                text(
                    'DELETE FROM public.platform_idempotency_records WHERE "key" = :key'
                ),
                {"key": decoy},
            )
    # The guard cannot be torn down while a restrictive policy remains.
    with pytest.raises(DBAPIError):
        _run_statements(admin, consumption_role_spec.guard_disable_sql())


def test_scoped_role_runs_real_consumption_and_refuses_out_of_scope(
    db: Session,
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW, genuine_approval=True)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    db.commit()
    admin = _admin_engine()
    _guard_reset(admin)
    role, verifier = _create_run_role(admin, str(coordinate.attempt_id))
    engine = create_engine(_role_url(role), future=True)
    sessions: list[Session] = []
    try:
        _prove_consumed_and_out_of_scope_refused(
            db, admin, engine, role, verifier, coordinate, sessions
        )
    finally:
        for session in sessions:
            session.close()
        engine.dispose()
        _teardown_run_role(admin, role)
        admin.dispose()


def test_scoped_role_revocation_leaves_nothing() -> None:
    admin = _admin_engine()
    _guard_reset(admin)
    role, _ = _create_run_role(admin, str(uuid.uuid4()))
    engine = create_engine(_role_url(role), future=True)
    try:
        live = engine.connect()
        assert live.execute(text("SELECT current_user")).scalar() == role
        with admin.connect() as connection:
            before = connection.exec_driver_sql(
                consumption_role_spec.verification_sql(role)
            ).one()
            assert tuple(before) == (1, 1, 2)
        for statement in consumption_role_spec.revocation_sql(role):
            with admin.connect() as connection:
                connection.exec_driver_sql(statement)
        with admin.connect() as connection:
            after = connection.exec_driver_sql(
                consumption_role_spec.verification_sql(role)
            ).one()
        assert tuple(after) == (0, 0, 0)
        # The pooled session the role still held was terminated, not left to
        # outlive its VALID UNTIL, and the role cannot reconnect.
        with pytest.raises(DBAPIError):
            live.execute(text("SELECT 1"))
        with pytest.raises(DBAPIError):
            create_engine(_role_url(role), future=True).connect()
        # With the policies gone the guard comes off cleanly.
        _run_statements(admin, consumption_role_spec.guard_disable_sql())
        with admin.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT relrowsecurity FROM pg_class "
                    "WHERE oid = 'public.platform_idempotency_records'::regclass"
                ).scalar_one()
                is False
            )
    finally:
        engine.dispose()
        _teardown_run_role(admin, role)
        admin.dispose()


def _watchdog_case(scenario: str) -> None:
    admin = _admin_engine()
    _guard_reset(admin)
    role, _ = _create_run_role(admin, str(uuid.uuid4()))
    engine = create_engine(_role_url(role), future=True)
    holder: Any = None
    errors: list[BaseException] = []
    try:
        if scenario == "advisory_lock":
            holder = engine.connect()
            holder.exec_driver_sql("SELECT pg_advisory_lock(424242)")
        else:

            def sleeper() -> None:
                try:
                    with engine.connect() as connection:
                        connection.exec_driver_sql("SELECT pg_sleep(25)")
                except BaseException as error:  # terminated by the watchdog
                    errors.append(error)

            threading.Thread(target=sleeper, daemon=True).start()
            time.sleep(0.5)
        output: list[str] = []
        code = consumption_watchdog.run(
            lambda: Session(bind=admin),
            role,
            deadline_seconds=40,
            interval=0.5,
            out=output.append,
        )
        assert code == consumption_watchdog.EXIT_TRIPPED, output
        assert any(scenario in line for line in output), output
        with admin.connect() as connection:
            after = connection.exec_driver_sql(
                consumption_role_spec.verification_sql(role)
            ).one()
        assert tuple(after) == (0, 0, 0)
        if holder is not None:
            with pytest.raises(DBAPIError):
                holder.exec_driver_sql("SELECT 1")
        with pytest.raises(DBAPIError):
            create_engine(_role_url(role), future=True).connect()
    finally:
        engine.dispose()
        _teardown_run_role(admin, role)
        admin.dispose()


def test_scoped_role_watchdog_revokes_on_an_advisory_lock() -> None:
    _watchdog_case("advisory_lock")


def test_scoped_role_watchdog_revokes_on_a_long_statement() -> None:
    _watchdog_case("long_statement")


# ── OpenBao transit custody, against a real OpenBao 2.5.3 dev server ────────


class _TransitKit:
    """One mount, two keys, the rendered policy and a relay, for one test."""

    def __init__(self, tmp_path: Any) -> None:
        self.bao = OpenBao.from_env()
        assert self.bao.version() == "2.5.3"
        self.kit = self.bao.provision()
        self.directory = tmp_path / "custody"
        self.directory.mkdir(mode=0o700)
        self.socket_dir = tempfile.mkdtemp(prefix="cp", dir="/tmp")
        self.relay = UnixRelay(os.path.join(self.socket_dir, "r"), self.bao.address)
        self.identity_paths: dict[str, Path] = {}
        self.uid = os.getuid()

    def identity(
        self, key_name: str, purpose: str, key_id: str, *, file: str
    ) -> PinnedVerificationIdentity:
        document = transit_custody.identity_document(
            self.kit.key_description(key_name), purpose=purpose, key_id=key_id
        )
        path = self.directory / file
        path.write_text(json.dumps(document))
        path.chmod(0o644)
        self.identity_paths[file] = path
        return PinnedVerificationIdentity.read(
            str(path), purpose=purpose, what="identity", owner_uid=self.uid
        )

    def config(
        self,
        *,
        authorization_key: str | None = None,
        dispatch_key: str | None = None,
        authorization_identity: str = "authorization.json",
        dispatch_identity: str = "dispatch.json",
        file: str = "config.json",
    ) -> str:
        document = {
            "mount": self.kit.mount,
            "authorization_key": authorization_key or self.kit.authorization_key,
            "dispatch_key": dispatch_key or self.kit.dispatch_key,
            "key_version": 1,
            "authorization_identity": str(self.identity_paths[authorization_identity]),
            "dispatch_identity": str(self.identity_paths[dispatch_identity]),
            "socket": self.relay.path,
        }
        path = self.directory / file
        path.write_text(json.dumps(document))
        return str(path)

    def pin_both(self) -> transit_custody.TransitCustodyConfig:
        self.identity(
            self.kit.authorization_key,
            "deployment_authorization",
            "platform-cp-a2-authorization-v1",
            file="authorization.json",
        )
        self.identity(
            self.kit.dispatch_key,
            "deployment_dispatch",
            "platform-cp-a2-dispatch-v1",
            file="dispatch.json",
        )
        config = transit_custody.load_config(self.config())
        self.kit.install_policy_and_role(transit_custody.render_policy(config))
        return config

    def close(self) -> None:
        self.relay.close()
        self.kit.teardown()
        if os.path.isdir(self.socket_dir):
            os.rmdir(self.socket_dir)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_transit_custody_against_real_openbao(tmp_path: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    harness = _TransitKit(tmp_path)
    kit = harness.kit
    try:
        config = harness.pin_both()
        auth_identity = PinnedVerificationIdentity.read(
            str(harness.identity_paths["authorization.json"]),
            purpose="deployment_authorization",
            what="i",
            owner_uid=harness.uid,
        )
        disp_identity = PinnedVerificationIdentity.read(
            str(harness.identity_paths["dispatch.json"]),
            purpose="deployment_dispatch",
            what="i",
            owner_uid=harness.uid,
        )
        assert (
            auth_identity.public_key_fingerprint != disp_identity.public_key_fingerprint
        )

        # Proof of possession, and pure Ed25519 (not Ed25519ph), for both keys.
        for name, identity, other, purpose in (
            (
                kit.authorization_key,
                auth_identity,
                disp_identity,
                "deployment_authorization",
            ),
            (kit.dispatch_key, disp_identity, auth_identity, "deployment_dispatch"),
        ):
            nonce = os.urandom(32)
            message = transit_custody.pop_message(purpose, nonce)
            raw = transit_custody.parse_signature(kit.root_sign(name, message))
            Ed25519PublicKey.from_public_bytes(identity.public_key).verify(raw, message)
            signature = "vault:v1:" + base64.b64encode(raw).decode()
            assert transit_custody.pop_verify(
                identity, purpose=purpose, nonce=nonce, signature=signature
            )
            assert not other.verify_signature(message, _b64url(raw))

        # The adapter end to end through the relay: strict parse, then verified
        # against the pinned identity; the single-issuance token allows two signs.
        token, accessor = kit.mint(uses=2)
        custody = transit_custody.build_custody(
            config, token.encode(), owner_uid=harness.uid
        )
        message = b"canonical bytes"
        raw = custody.authorization_sign(message)
        assert auth_identity.verify_signature(message, _b64url(raw))
        assert disp_identity.verify_signature(
            message, _b64url(custody.dispatch_sign(message))
        )
        with pytest.raises(transit_custody.FoundationBindingsUnavailable):
            custody.authorization_sign(message)
        kit.revoke_accessor(accessor)
        assert kit.accessor_is_gone(accessor)

        # Server-side use limit: the third use of a 2-use token is refused.
        limited, _ = kit.mint(uses=2)
        body = {"input": base64.b64encode(b"x").decode(), "key_version": 1}
        path = f"{kit.mount}/sign/{kit.authorization_key}"
        assert [
            harness.bao.call("POST", path, body, token=limited)[0] for _ in range(3)
        ] == [
            200,
            200,
            403,
        ]

        # Every refusal the policy exists for, with an unlimited token so a refusal
        # is the policy's and not the use limit's.
        free, _ = kit.mint(uses=0)
        b64 = base64.b64encode(b"x").decode()
        sign = f"{kit.mount}/sign/{kit.authorization_key}"
        attempts = {
            "batch_input": ("POST", sign, {"batch_input": [{"input": b64}]}),
            "batch_input beside input": ("POST", sign, {"input": b64, "batch_input": [{"input": b64}]}),
            "context": ("POST", sign, {"input": b64, "context": b64}),
            "prehashed": ("POST", sign, {"input": b64, "prehashed": True}),
            "hash_algorithm": ("POST", sign, {"input": b64, "hash_algorithm": "sha2-256"}),
            "signature_algorithm": ("POST", sign, {"input": b64, "signature_algorithm": "pss"}),
            "marshaling_algorithm": ("POST", sign, {"input": b64, "marshaling_algorithm": "jws"}),
            "hash path": ("POST", sign + "/sha2-256", {"input": b64}),
            "read key": ("GET", f"{kit.mount}/keys/{kit.authorization_key}", None),
            "export": ("GET", f"{kit.mount}/export/signing-key/{kit.authorization_key}", None),
            "rotate": ("POST", f"{kit.mount}/keys/{kit.authorization_key}/rotate", {}),
            "config": ("POST", f"{kit.mount}/keys/{kit.authorization_key}/config", {"deletion_allowed": True}),
            "another key": ("POST", f"{kit.mount}/sign/not-configured", {"input": b64}),
            "mounts": ("GET", "sys/mounts", None),
        }  # fmt: skip
        for name, (method, route, payload) in attempts.items():
            status, _ = harness.bao.call(method, route, payload, token=free)
            assert status == 403, (name, status)
        assert (
            harness.bao.call(
                "POST", sign, {"input": b64, "key_version": 1}, token=free
            )[0]
            == 200
        )

        # key_version pinning: after a root-side rotate the adapter still signs
        # with v1 and verifies; a request that omits key_version signs with v2,
        # which the pinned identity refuses.
        harness.bao.must("POST", f"{kit.mount}/keys/{kit.authorization_key}/rotate")
        rotated_token, _ = kit.mint(uses=2)
        rotated = transit_custody.build_custody(
            config, rotated_token.encode(), owner_uid=harness.uid
        )
        assert auth_identity.verify_signature(
            message, _b64url(rotated.authorization_sign(message))
        )
        v2 = transit_custody.parse_signature(
            kit.root_sign(kit.authorization_key, message), key_version=2
        )
        assert not auth_identity.verify_signature(message, _b64url(v2))
    finally:
        harness.close()


def _issue_request(plan_id: uuid.UUID, ref: str) -> Any:
    return materials_producer.IssueDispatchRequest(
        plan_id=plan_id,
        rollout_ref=ref,
        rollout_command_id=_cmd(),
        dispatch_command_id=_cmd(),
        authorization_expires_at=datetime.now(UTC) + timedelta(hours=1),
        controller_ssh_fingerprint="SHA256:conformance-launch-key",
        host_id="conformance-host-placeholder",
        host_incarnation="conformance-incarnation",
        host_enrolment_ref="conformance-enrolment",
    )


@pytest.mark.parametrize("fault", ["wrong_key", "swapped_keys"])
def test_transit_custody_refuses_wrong_and_swapped_keys_before_control_signs(
    db: Session, tmp_path: Any, fault: str
) -> None:
    harness = _TransitKit(tmp_path)
    kit = harness.kit
    try:
        harness.pin_both()
        if fault == "wrong_key":
            # The pinned authorization identity is a DIFFERENT key than the one
            # transit signs authorizations with.
            other = f"{kit.authorization_key}-other"
            harness.bao.must(
                "POST",
                f"{kit.mount}/keys/{other}",
                {"type": "ed25519", "exportable": False, "derived": False},
            )
            harness.identity(
                other,
                "deployment_authorization",
                "platform-cp-a2-authorization-v1",
                file="wrong-authorization.json",
            )
            path = harness.config(authorization_identity="wrong-authorization.json")
        else:
            path = harness.config(
                authorization_key=kit.dispatch_key, dispatch_key=kit.authorization_key
            )
        config = transit_custody.load_config(path)
        token, accessor = kit.mint(uses=2)
        custody = transit_custody.build_custody(
            config, token.encode(), owner_uid=harness.uid
        )

        target = _register_target(db)
        _set_desired(db, target.id)
        db.commit()
        plan = _genuine_approved_plan(db, target.id)
        db.commit()
        ref = f"rol-{uuid.uuid4().hex[:8]}"
        with pytest.raises(Exception) as refused:
            materials_producer.issue_dispatch_materials(
                db,
                _issue_request(plan.id, ref),
                custody=custody,
            )
        assert (
            "custody" in repr(refused.value).lower()
            or "verif" in repr(refused.value).lower()
        )
        db.rollback()
        # Nothing was persisted as signed: no rollout exists for the plan.
        assert (
            db.execute(select(Rollout.id).where(Rollout.plan_id == plan.id)).first()
            is None
        )
        kit.revoke_accessor(accessor)
        assert kit.accessor_is_gone(accessor)
    finally:
        harness.close()


class _KeepOpen:
    """The test's `db` session behind the CLI's session seam (never closed)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    def close(self) -> None:
        return None


class _TransitExternal:
    """Drives the real operator commands for `_build_admission_coordinate`."""

    def __init__(self, harness: _TransitKit, monkeypatch: Any, tmp_path: Any) -> None:
        self.harness = harness
        self.config_path = harness.config()
        self.out_dir = tmp_path / "materials"
        self.out_dir.mkdir(mode=0o700)
        self.monkeypatch = monkeypatch
        self.authorization_verifier = AuthorizationEd25519Verifier(
            PinnedVerificationIdentity.read(
                str(harness.identity_paths["authorization.json"]),
                purpose="deployment_authorization",
                what="i",
                owner_uid=harness.uid,
            )
        )
        self.dispatch_verifier = DispatchEd25519Verifier(
            PinnedVerificationIdentity.read(
                str(harness.identity_paths["dispatch.json"]),
                purpose="deployment_dispatch",
                what="i",
                owner_uid=harness.uid,
            )
        )
        self.accessor: str | None = None

    def _cli(self, db: Session, argv: list[str], stdin: bytes | None = None) -> str:
        self.monkeypatch.setattr(
            materials_producer, "_controller_session", lambda env: _KeepOpen(db)
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = materials_producer.main(
                argv,
                {},
                stdin=io.BytesIO(stdin) if stdin is not None else None,
                owner_uid=self.harness.uid,
            )
        assert code == 0, out.getvalue()
        return out.getvalue()

    def prepare(self, db: Session, target: Any) -> Any:
        policy = f"foundation-{uuid.uuid4().hex}"
        approvals.publish_policy_version(
            db, approvals.PublishPolicyCommand(_cmd(), policy, 1, 1, False)
        )
        db.commit()
        proposed = self._cli(
            db,
            [
                "propose", "--command-id", _cmd(), "--target-id", str(target.id),
                "--operation", "deploy", "--descriptor-digest", _DESCRIPTOR,
                "--execution-plan-digest", _EXECUTION_PLAN,
                "--approval-policy-code", policy, "--approval-policy-version", "1",
            ],
        )  # fmt: skip
        plan_id = uuid.UUID(proposed.strip().split(": ")[1])
        opened = self._cli(
            db,
            ["open-approval", "--command-id", _cmd(), "--plan-id", str(plan_id),
             "--requested-by", str(uuid.uuid4())],
        )  # fmt: skip
        request_id = uuid.UUID(opened.strip().split(": ")[1])
        plan = db.get(DeploymentPlan, plan_id)
        approvals.record_decision(
            db,
            approvals.RecordDecisionCommand(
                command_id=_cmd(),
                request_id=request_id,
                approver_id=uuid.uuid4(),
                content_hash=bare_content_hash(plan.plan_digest),
            ),
        )
        db.commit()
        self._cli(
            db,
            ["approve", "--command-id", _cmd(), "--plan-id", str(plan_id),
             "--approval-request-id", str(request_id)],
        )  # fmt: skip
        db.expire_all()
        return db.get(DeploymentPlan, plan_id)

    def issue(self, db: Session, plan: Any) -> uuid.UUID:
        token, self.accessor = self.harness.kit.mint(uses=2)
        self._cli(
            db,
            [
                "issue", "--plan-id", str(plan.id), "--rollout-ref",
                f"rol-{uuid.uuid4().hex[:8]}", "--rollout-command-id", _cmd(),
                "--dispatch-command-id", _cmd(), "--authorization-expires-at",
                (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "--controller-ssh-fingerprint", "SHA256:conformance-launch-key",
                "--host-id", "conformance-host-placeholder",
                "--host-incarnation", "conformance-incarnation",
                "--host-enrolment-ref", "conformance-enrolment",
                "--out-dir", str(self.out_dir), "--custody", "transit",
                "--custody-config", self.config_path,
            ],
            stdin=token.encode() + b"\n",
        )  # fmt: skip
        # Revoke the issuance token and read back that it is gone.
        self.harness.kit.revoke_accessor(self.accessor)
        assert self.harness.kit.accessor_is_gone(self.accessor)
        db.expire_all()
        return db.execute(
            select(Rollout.id).where(Rollout.plan_id == plan.id)
        ).scalar_one()


def test_end_to_end_propose_approve_issue_transit_and_consume_as_scoped_role(
    db: Session, monkeypatch: Any, tmp_path: Any
) -> None:
    harness = _TransitKit(tmp_path)
    try:
        harness.pin_both()
        external = _TransitExternal(harness, monkeypatch, tmp_path)
        coordinate = _build_admission_coordinate(
            db, now=_NOW, genuine_approval=True, external=external
        )
        install_host_admission_security(
            verifier=coordinate.presentation_verifier, clock=coordinate.clock
        )
        db.commit()

        # The target-side reader accepts the issued documents, and every Control
        # fact in them is exactly what Control stored.
        context_path = external.out_dir / materials_producer.CONTEXT_FILE
        dispatch_path = external.out_dir / materials_producer.DISPATCH_FILE
        issued = bindings_module.execution_context_source(
            str(context_path), ExecutionContextV3
        )()
        assert isinstance(issued, ExecutionContextV3)
        for name in materials_producer.CONTEXT_KEYS[:12]:
            assert getattr(issued, name) == getattr(coordinate.facts, name), name
        dispatch_document = json.loads(dispatch_path.read_text())
        assert dispatch_document["attempt_id"] == str(coordinate.attempt_id)
        assert dispatch_document["authorization_envelope"] == json.loads(
            coordinate.execution.authorization_material_json
        )
        assert dispatch_document["dispatch_envelope"] == json.loads(
            coordinate.execution.dispatch_material_json
        )
        assert (
            oct(
                (external.out_dir / materials_producer.CONTEXT_FILE).stat().st_mode
                & 0o777
            )
            == "0o600"
        )

        # Consume as the scoped role under the per-run ledger guard, with Control
        # verifying the TRANSIT-signed envelopes through CP's pinned verifiers.
        admin = _admin_engine()
        _guard_reset(admin)
        role, verifier = _create_run_role(admin, str(coordinate.attempt_id))
        engine = create_engine(_role_url(role), future=True)
        sessions: list[Session] = []
        try:
            _prove_consumed_and_out_of_scope_refused(
                db, admin, engine, role, verifier, coordinate, sessions
            )
        finally:
            for session in sessions:
                session.close()
            engine.dispose()
            _teardown_run_role(admin, role)
            admin.dispose()
    finally:
        harness.close()


# ── small helpers used above ────────────────────────────────────────────────


def _latest_attempt_id(db: Session, rollout_id: uuid.UUID) -> uuid.UUID:
    row = (
        db.execute(
            select(RolloutAttempt)
            .where(RolloutAttempt.rollout_id == rollout_id)
            .order_by(RolloutAttempt.id.desc())
        )
        .scalars()
        .first()
    )
    assert row is not None
    return row.id


def _sha256_digest(data: bytes) -> Any:
    return Digest.parse(hashlib.sha256(data).hexdigest(), where="conformance")


def _sign_envelope(
    *,
    purpose: str,
    fingerprint: str,
    custody_domain: str,
    key_id: str,
    trust_root_version: str,
    subject: dict[str, str],
    observation_id: str,
    audience: str,
    foundation_verifier: _FoundationAttestationVerifier,
    now: datetime,
) -> AttestationEnvelopeV2:
    # `issued_at`/`expires_at` are derived from `now` (the same convention
    # `enrol_root`'s `enrolled_at`/`not_after` already use below), NOT a
    # hardcoded calendar date -- a fixed literal here made this suite's own
    # evidence non-reproducible past a ~24-hour window (a real defect an
    # independent review caught): Foundation's own staleness/future checks
    # compare the envelope's issued_at/expires_at against real wall-clock
    # time, so a literal date silently expires exactly like a certificate.
    envelope = AttestationEnvelopeV2(
        "TrustedHostAttestation.v2",
        purpose,
        "conformance-test",
        key_id,
        "ed25519",
        fingerprint,
        custody_domain,
        trust_root_version,
        (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        audience,
        observation_id,
        subject,
        "placeholder",
    )
    signature = foundation_verifier.sign(fingerprint, envelope.signed_bytes())
    return dataclasses.replace(envelope, signature=signature)


def _to_foundation_b64(control_b64url: str) -> str:
    """Control stores unpadded base64url; Foundation's `AttestationTrustRootV2`
    expects padded standard base64. This is the SAME conversion Control's own
    `foundation_public_key_base64` (`host_admission.py`) performs internally
    when resolving a root context for real host admission -- reproduced
    directly here (rather than imported) because this helper builds the
    Foundation-side trust policy this test hands to `verify_attestation_pair`
    directly, a step that happens before any Control resolve call, so there
    is no stored fingerprint yet to cross-check against."""
    raw = base64.urlsafe_b64decode(control_b64url + "=" * (-len(control_b64url) % 4))
    return base64.b64encode(raw).decode("ascii")


def _enrolment_id_for(db: Session, custody_domain: str, subject: str) -> uuid.UUID:
    row = (
        db.execute(
            select(AttestationEnrolment).where(
                AttestationEnrolment.custody_domain == custody_domain,
                AttestationEnrolment.subject == subject,
            )
        )
        .scalars()
        .one()
    )
    return row.id
