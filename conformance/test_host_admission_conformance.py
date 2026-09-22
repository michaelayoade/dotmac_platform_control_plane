"""Conformance suite: `admit_and_launch_host_source` against the REAL
`dotmac_deployment_control` and `dotmac_deployment_foundation` functions.

SCOPE. `tests/unit/test_host_admission_adapter.py` proves the adapter's own
wiring (session ordering, commit-before-launch, no fallback) against injected
fakes. This suite proves those fakes were faithful: it wires the SAME
`admit_and_launch_host_source` orchestration to the real
`resolve_host_admission_context`/`admit_and_consume_host_admission`
(Control) and `verify_attestation_pair` (Foundation), built as real wheels
from the exact merge commits named in `conformance/README.md`, installed
only into a disposable environment -- never this repository's own `.venv`,
never referenced from `pyproject.toml`.

This file lives OUTSIDE `tests/` (this repository's `pyproject.toml` pins
`testpaths = ["tests"]`) specifically so a normal `pytest tests/` run in this
repository never collects it and never tries to import either real package,
neither of which is installable here today. There is NO skip anywhere in
this suite, graceful or otherwise: `conformance/conftest.py` raises a hard
`pytest.UsageError` before collection even starts if
`CONFORMANCE_DATABASE_URL` is unset, and an import error, a missing symbol,
or any other real defect below is likewise never converted into a skip. This
directory is already excluded from normal test discovery (`testpaths`) and
from CI, so an explicit `pytest conformance/` run is always a deliberate act,
and it must FAIL loudly -- never report a misleading "0 passed, N skipped"
that reads as a pass.

SIGNING CONVENTION. Every signer/verifier pair below is a deterministic,
non-asymmetric double -- SHA-256/HMAC over canonical bytes, exactly the same
convention Control's OWN test suite (`tests/authorization_support.py`,
`tests/dispatch_support.py`, `tests/execution_observation_support.py`) and
Foundation's OWN test suite
(`tests/unit/test_deployment_foundation_trusted_host_source.py`'s
`Verifier`) already use for this exact purpose. These modules are test-only
and are not packaged into either wheel, so their exact patterns are
reproduced here rather than imported. This is a legitimate "real Foundation
code" / "real Control code" proof in the sense that matters: it exercises the
REAL `verify_attestation_pair`/`resolve_host_admission_context`/
`admit_and_consume_host_admission` FUNCTION LOGIC (signature checking via an
injected verifier, purpose/audience/root/subject/digest matching, locking,
re-derivation, drift refusal) with a genuine cryptographic check that
genuinely fails on tampering -- not a stub of those functions themselves.
Using HMAC rather than asymmetric Ed25519 does not weaken any property this
suite proves, because the functions under test never inspect the verifier's
internals; they only call its `.verify(...)`/`.verify_host_admission_presentation(...)`
method and act on the boolean it returns.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import os
import uuid
from datetime import UTC, datetime, timedelta
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
    AuthorizationSignature,
    AuthorizationSignerIdentity,
    BindTargetHostCommand,
    CredentialTransitionCommand,
    DesiredDeployment,
    DispatchSignature,
    DispatchSignerIdentity,
    EnrolHostAdmissionCredentialCommand,
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
    activate_credential,
    admit_and_consume_host_admission,
    approve_plan,
    bind_target_host,
    dispatch_attempt,
    enrol_host_admission_credential,
    install_host_admission_security,
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
from dotmac_deployment_control.models import AttestationEnrolment, RolloutAttempt
from dotmac_deployment_foundation import (
    AttestationEnvelopeV2,
    AttestationTrustPolicy,
    AttestationTrustRootV2,
    CandidateAttestationSubjectV2,
    Digest,
    InstalledHostAttestationSubjectV2,
    PreconditionFailed,
    attestation_envelope_digest,
    verify_attestation_pair,
)

# Also not top-level -- verified against the installed wheel. Foundation's OWN
# test suite (tests/unit/test_deployment_foundation_trusted_host_source.py)
# imports it from here too.
from dotmac_deployment_foundation.trusted_host_source import candidate_subject_digest
from dotmac_kernel.idempotency_models import PlatformIdempotencyRecord
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

# The LEAF module only -- see its own docstring and
# tests/architecture/test_host_admission_adapter_import_boundary.py. NEVER
# `vendor_cp.deployment.adapter`, which pulls in this application's entire
# approvals/identity/licensing closure and would defeat the whole point of
# the leaf split.
from vendor_cp.deployment.host_admission_adapter import (
    AttestationVerificationInputs,
    admit_and_launch_host_source,
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
# (~5 minutes for all 9 tests) without weakening anything the tests check --
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
    import dotmac_deployment_control.host_admission_coordinator as admission_coordinator

    admission_coordinator._reset_host_admission_security_for_tests()
    yield
    admission_coordinator._reset_host_admission_security_for_tests()


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    """This suite builds no real `create_app()`, so nothing installs the
    process-active audit-action registry `write_platform_audit_event` needs.
    Same pattern as every one of Control's own unit tests (e.g.
    `tests/unit/test_deployment_control_intent.py`) -- verified there, not
    guessed."""
    from dotmac_deployment_control import module
    from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions

    install_audit_actions(AuditActionRegistry.from_manifests([module]))


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
                decided_at=_NOW,
                operation="deploy",
                execution_plan_digest=_EXECUTION_PLAN,
                decision_status="granted",
            ),
        ),
    )


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


def _build_admission_coordinate(
    db: Session,
    *,
    now: datetime,
    package: str = "dotmac-sub",
) -> _AdmissionCoordinate:
    # Every identity below is suffixed with a fresh per-call token. The
    # commands this function calls (register_target, enrol_host_admission_
    # credential, enrol_root, ...) run through `process_once_platform`, which
    # commits internally for at-most-once durability -- the outer `db`
    # fixture's rollback-on-teardown does NOT undo them. Seven tests in one
    # process therefore each need their own key_id/host_id/custody subject,
    # or the second test to run collides with the first's already-committed
    # rows (real defect found by actually running this against Postgres,
    # not a hypothetical).
    run = uuid.uuid4().hex[:8]

    target = _register_target(db)
    _set_desired(db, target.id)
    plan = _approved_plan(db, target.id)
    authorization_signer = _AuthorizationSigner()
    rollout = _rollout(db, plan.id, authorization_signer)
    dispatch_signer = _DispatchSigner()
    dispatch_attempt(
        db,
        command_id=_cmd(),
        rollout_id=rollout.id,
        verifier=_AuthorizationVerifier(authorization_signer),
        dispatch_signer=dispatch_signer,
    )
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
        "0.4.0a2",
        _sha256_digest(f"conformance-wheel-bytes-{run}".encode()),
        "b" * 40,
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
    )
    installed_envelope = _sign_envelope(
        purpose="dotmac.foundation.installed-host.v2",
        fingerprint=host_fp,
        custody_domain="host_attester",
        key_id=f"attestation-{host_id}",
        trust_root_version=host_trust_root_version,
        subject=installed_subject.canonical_document(),
        observation_id=attempt_id.hex,
        audience=host_id,
        foundation_verifier=foundation_verifier,
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
    )


# NOTE: this suite's real-wheel execution is blocked until
# `dotmac_starter_mt`#743 (Foundation's widened `AttestationPairVerificationResultV1`)
# and `dotmac_deployment_control`#59 (Control's widened
# `HostAdmissionForeignVerificationEvidenceV1`) both merge and the two pinned
# wheels this suite installs are rebuilt from those merge commits -- the
# fields this mapper reads/writes below do not exist in the wheels currently
# pinned by `conformance/README.md`. The source changes below are made and
# verified against the real, unmerged diffs directly (not guessed), so this
# file is ready the moment new wheels are available; it cannot be run
# successfully before then.
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
    return (
        db.execute(
            select(PlatformIdempotencyRecord).where(
                PlatformIdempotencyRecord.scope
                == control_service._SCOPE_CONSUME_DISPATCH_CHALLENGE,
                PlatformIdempotencyRecord.key == str(attempt_id),
            )
        )
        .scalars()
        .all()
        .__len__()
    )


# ── The seven required conformance properties ───────────────────────────────


def test_valid_signed_attestations_complete_the_full_flow(
    db: Session, admit_db: Session
) -> None:
    coordinate = _build_admission_coordinate(db, now=_NOW)
    install_host_admission_security(
        verifier=coordinate.presentation_verifier, clock=coordinate.clock
    )
    launched: list[Any] = []

    result = admit_and_launch_host_source(
        resolve_session=db,
        admit_session=admit_db,
        attempt_id=coordinate.attempt_id,
        presentation=coordinate.presentation,
        resolve_context=resolve_host_admission_context,
        verify_pair=verify_attestation_pair,
        admit_and_consume=admit_and_consume_host_admission,
        launch=lambda staged: launched.append(staged),
        build_foreign_evidence=_map_foundation_result_to_control_evidence,
        build_trust_policy=lambda resolved: coordinate.trust_policy,
        verification=AttestationVerificationInputs(
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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=_raising_verify,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
                candidate=coordinate.candidate_envelope,
                installed=coordinate.installed_envelope,
                foundation_verifier=coordinate.foundation_verifier,
                now=coordinate.clock.now(),
            ),
        )
    assert excinfo.value.code is HostAdmissionRefusalCode.EVIDENCE_CHANGED
    assert len(launched) == 0
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


# NOTE: like `_map_foundation_result_to_control_evidence` above, the two
# tests below exercise the widened `FOREIGN_EVIDENCE_SEMANTIC_MISMATCH`
# refusal added by `dotmac_deployment_control`#59 and cannot actually run
# until that PR (and `dotmac_starter_mt`#743) merge and this suite's pinned
# wheels are rebuilt from the new merge commits.


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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=lambda staged: launched.append(staged),
            build_foreign_evidence=_substituting_mapper,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
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
        expected_observation_id=coordinate.attempt_id.hex,
        expected_package="dotmac-sub",
        verification_context_digest=context.context_digest,
        now=coordinate.clock.now(),
    )
    evidence = _map_foundation_result_to_control_evidence(result)

    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        admit_and_consume_host_admission(db, context=context, foreign_evidence=evidence)
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
        expected_observation_id=coordinate.attempt_id.hex,
        expected_package="dotmac-sub",
        verification_context_digest=context.context_digest,
        now=coordinate.clock.now(),
    )
    evidence = _map_foundation_result_to_control_evidence(result)

    # Advance the REAL trusted clock past the presentation's own expires_at
    # (5 minutes after issued_at) -- proving admit_and_consume_host_admission's
    # OWN fresh-clock check, not a simulation of one.
    coordinate.clock.advance(timedelta(minutes=6))

    with pytest.raises(HostAdmissionRefusedError) as excinfo:
        admit_and_consume_host_admission(db, context=context, foreign_evidence=evidence)
    assert excinfo.value.code is HostAdmissionRefusalCode.CONTEXT_EXPIRED
    assert _idempotency_marker_count(db, coordinate.attempt_id) == 0


def test_launch_cannot_occur_before_the_admission_transaction_commits(
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
        admit_and_launch_host_source(
            resolve_session=db,
            admit_session=admit_db,
            attempt_id=coordinate.attempt_id,
            presentation=coordinate.presentation,
            resolve_context=resolve_host_admission_context,
            verify_pair=verify_attestation_pair,
            admit_and_consume=admit_and_consume_host_admission,
            launch=_recording_launch,
            build_foreign_evidence=_map_foundation_result_to_control_evidence,
            build_trust_policy=lambda resolved: coordinate.trust_policy,
            verification=AttestationVerificationInputs(
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
) -> AttestationEnvelopeV2:
    envelope = AttestationEnvelopeV2(
        "TrustedHostAttestation.v2",
        purpose,
        "conformance-test",
        key_id,
        "ed25519",
        fingerprint,
        custody_domain,
        trust_root_version,
        "2026-09-22T00:00:00Z",
        "2026-09-23T00:00:00Z",
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
