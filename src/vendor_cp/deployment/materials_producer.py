"""CP-side producer of the genuine dispatch materials (E6, review finding R8).

Only CP holds the Control database and the authorization / dispatch signing
custody, so only CP can issue a genuine Control V2 pair. The target-side
bindings CONSUME documents; this module is what makes them exist, in the one CP
image. It does three things and nothing else:

1. `issue_dispatch_materials`: through CP's own held-approval lifecycle
   (`foundation_execution_approval`) request the rollout (authorization signed)
   and dispatch the attempt (dispatch signed). Each stage commits in its own
   transaction, as that module requires. Nothing is re-implemented: Control signs
   with the signers handed in, under the approval hold.
2. It exports two documents the launcher delivers to the target:
   `dispatch-materials.json` (the attempt id and both signed envelopes, exactly
   Control's canonical JSON) and `execution-context.json` (exactly the closed key
   set `execution_context_source` reads). Every field of the Control half is read
   from the SIGNED dispatch and authorization statements, never from a caller.
3. `write_materials` writes them create-only, 0600, in an owner-only directory.

What it never does: generate, store, read or print a key. Signing goes through a
CUSTODY object whose callables hold the key where the ceremony put it; this
module sees only signatures. With no custody installed it refuses (typed,
`custody_not_configured`). Every signature is verified against the PUBLIC pinned
identity before it is returned to Control, so a custody that signs with the wrong
key, or returns garbage, cannot get a pair issued.

The host-admission document (`HOST_ADMISSION_MATERIALS`: presentation and the two
attestation envelopes) is produced by the target and Foundation, not by CP.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from importlib import import_module
from importlib.metadata import version
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    AuthorizationEd25519Verifier,
    PinnedVerificationIdentity,
)

if TYPE_CHECKING:
    from dotmac_deployment_control import DispatchResumeExpectation

__all__ = [
    "CONTEXT_FILE",
    "CONTEXT_KEYS",
    "DISPATCH_FILE",
    "Custody",
    "IssueDispatchRequest",
    "IssuedMaterials",
    "RecoverDispatchRequest",
    "recover_dispatch_materials",
    "load_recovery_request",
    "install_custody",
    "MAX_AUTHORIZATION_WINDOW",
    "main",
    "issue_dispatch_materials",
    "write_materials",
]

CONTEXT_FILE: Final = "execution-context.json"
DISPATCH_FILE: Final = "dispatch-materials.json"

#: The closed key set `foundation_bindings.execution_context_source` demands: the
#: twelve Control-owned facts plus the four host/controller facts. Pinned by test.
CONTEXT_KEYS: Final = (
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
    "controller_ssh_fingerprint",
    "host_id",
    "host_incarnation",
    "host_enrolment_ref",
)


def _refuse(message: str, code: TargetRefusal) -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(message, code=code)


@dataclass(frozen=True, slots=True)
class Custody:
    """Signing custody: PUBLIC identities plus the callables that sign.

    The callables are supplied by the custody ceremony's adapter and hold the key
    where it lives; this module never sees one. Each returns raw Ed25519
    signature bytes over exactly the bytes it is given.
    """

    authorization_identity: PinnedVerificationIdentity
    dispatch_identity: PinnedVerificationIdentity
    authorization_sign: Callable[[bytes], bytes]
    dispatch_sign: Callable[[bytes], bytes]


_LOCK = Lock()
_CUSTODY: Custody | None = None


def install_custody(custody: Custody) -> None:
    """Install the custody adapter exactly once, at process startup."""
    global _CUSTODY
    with _LOCK:
        if _CUSTODY is not None:
            raise _refuse(
                "signing custody is already installed",
                TargetRefusal.CUSTODY_NOT_CONFIGURED,
            )
        _CUSTODY = custody


def _require_custody() -> Custody:
    if _CUSTODY is None:
        raise _refuse(
            "signing custody is not configured; no pair can be issued",
            TargetRefusal.CUSTODY_NOT_CONFIGURED,
        )
    return _CUSTODY


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _signed(
    identity: PinnedVerificationIdentity, sign: Callable[[bytes], bytes], message: bytes
) -> str:
    """Custody signature, proven against the PUBLIC identity before use."""
    try:
        raw = sign(message)
    except Exception:
        raise _refuse(
            "signing custody refused to sign", TargetRefusal.CUSTODY_NOT_CONFIGURED
        ) from None
    if not isinstance(raw, bytes) or not raw:
        raise _refuse(
            "signing custody returned no signature",
            TargetRefusal.CUSTODY_NOT_CONFIGURED,
        )
    signature = _b64url(raw)
    if not identity.verify_signature(message, signature):
        raise _refuse(
            "signing custody produced a signature that does not verify against "
            "the pinned identity",
            TargetRefusal.CUSTODY_NOT_CONFIGURED,
        )
    return signature


class _AuthorizationSigner:
    """Control's `AuthorizationSigner` port over custody."""

    def __init__(self, custody: Custody) -> None:
        self._custody = custody

    @property
    def identity(self) -> Any:
        control = import_module("dotmac_deployment_control")
        pinned = self._custody.authorization_identity
        return control.AuthorizationSignerIdentity(
            pinned.key_id, pinned.algorithm, pinned.public_key_fingerprint
        )

    def sign(self, canonical_bytes: bytes) -> Any:
        control = import_module("dotmac_deployment_control")
        pinned = self._custody.authorization_identity
        return control.AuthorizationSignature(
            pinned.key_id,
            pinned.algorithm,
            pinned.public_key_fingerprint,
            _signed(pinned, self._custody.authorization_sign, canonical_bytes),
        )


class _DispatchSigner:
    """Control's `DispatchSigner` port over custody."""

    def __init__(self, custody: Custody) -> None:
        self._custody = custody

    @property
    def dispatch_identity(self) -> Any:
        control = import_module("dotmac_deployment_control")
        pinned = self._custody.dispatch_identity
        return control.DispatchSignerIdentity(
            pinned.key_id, pinned.algorithm, pinned.public_key_fingerprint
        )

    def sign_dispatch(self, canonical_bytes: bytes) -> Any:
        control = import_module("dotmac_deployment_control")
        pinned = self._custody.dispatch_identity
        return control.DispatchSignature(
            pinned.key_id,
            pinned.algorithm,
            pinned.purpose,
            pinned.public_key_fingerprint,
            _signed(pinned, self._custody.dispatch_sign, canonical_bytes),
        )


@dataclass(frozen=True, slots=True)
class IssueDispatchRequest:
    """What the operator supplies. Control's facts are NOT among it."""

    plan_id: UUID
    rollout_ref: str
    rollout_command_id: str
    dispatch_command_id: str
    authorization_expires_at: datetime
    #: The per-run launch key's fingerprint (the launcher mints one per run).
    controller_ssh_fingerprint: str
    #: The target's enrolled identity facts.
    host_id: str
    host_incarnation: str
    host_enrolment_ref: str


@dataclass(frozen=True, slots=True)
class RecoverDispatchRequest:
    """One source-qualified, purpose-bound dispatch recovery invocation.

    The caller MUST bind original_request (including host/controller facts) and
    session_id to its approved external recovery manifest. Control's signed
    authorization does not attest those CP inputs. This object is not approval,
    fault provenance, installed parity or permission to deliver the output.
    """

    original_request: IssueDispatchRequest
    expectation: DispatchResumeExpectation
    session_id: str
    not_before: datetime
    deadline: datetime


@dataclass(frozen=True, slots=True)
class IssuedMaterials:
    attempt_id: str
    dispatch_document: dict[str, Any]
    context_document: dict[str, Any]


def _text(value: object, *, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _refuse(
            f"the signed statements carry no usable {what}",
            TargetRefusal.MATERIALS_REFUSED,
        )
    return value


#: The role window; an authorization may not outlive it (hard cap, 4 hours).
MAX_AUTHORIZATION_WINDOW: Final = timedelta(hours=4)


def _check_expiry(expires_at: datetime, *, now: datetime | None = None) -> None:
    if expires_at.tzinfo is None:
        raise _refuse(
            "the authorization expiry must be timezone-aware",
            TargetRefusal.MATERIALS_REFUSED,
        )
    reference = now or datetime.now(UTC)
    if not reference < expires_at <= reference + MAX_AUTHORIZATION_WINDOW:
        raise _refuse(
            "the authorization expiry must fall within the 4 hour role window",
            TargetRefusal.MATERIALS_REFUSED,
        )


def _check_host_enrolment(request: IssueDispatchRequest) -> None:
    # Foundation's execution context demands the enrolment ref as a canonical UUID
    # (Control's enrolment id); refuse here, before anything is signed.
    try:
        if str(UUID(request.host_enrolment_ref)) != request.host_enrolment_ref:
            raise ValueError("not canonical")
    except ValueError:
        raise _refuse(
            "the host enrolment ref must be a canonical UUID",
            TargetRefusal.MATERIALS_REFUSED,
        ) from None


def issue_dispatch_materials(
    db: Any, request: IssueDispatchRequest, *, custody: Custody | None = None
) -> IssuedMaterials:
    """Issue one genuine pair under the approval hold and describe it.

    The caller owns `db`; this commits after each lifecycle stage. Refuses (typed)
    with no custody. Any Control or Approvals refusal propagates unchanged.
    """
    held_custody = custody or _require_custody()
    _check_expiry(request.authorization_expires_at)
    for name in (
        request.controller_ssh_fingerprint,
        request.host_id,
        request.host_incarnation,
        request.host_enrolment_ref,
        request.rollout_ref,
    ):
        _text(name, what="request field")
    _check_host_enrolment(request)
    approval = import_module("vendor_cp.deployment.foundation_execution_approval")
    rollout = approval.request_foundation_rollout(
        db,
        command_id=request.rollout_command_id,
        plan_id=request.plan_id,
        rollout_ref=request.rollout_ref,
        authorization_expires_at=request.authorization_expires_at,
        signer=_AuthorizationSigner(held_custody),
    )
    db.commit()
    intent = approval.dispatch_foundation_attempt(
        db,
        command_id=request.dispatch_command_id,
        rollout_id=rollout.id,
        verifier=AuthorizationEd25519Verifier(held_custody.authorization_identity),
        dispatch_signer=_DispatchSigner(held_custody),
    )
    db.commit()

    return _assemble_materials(request, intent)


def _assemble_materials(request: IssueDispatchRequest, intent: Any) -> IssuedMaterials:
    dispatch = intent.dispatch_envelope
    authorization = intent.authorization_envelope
    statement = dispatch.statement
    if authorization.statement.plan_id != statement.authorization_plan_id:
        raise _refuse(
            "the authorization and dispatch statements name different plans",
            TargetRefusal.MATERIALS_REFUSED,
        )
    context: dict[str, Any] = {
        "product_code": _text(statement.product_code, what="product"),
        "environment": _text(statement.environment, what="environment"),
        "target_id": _text(statement.target_id, what="target id"),
        "target_ref": _text(statement.target_ref, what="target ref"),
        "operation": _text(statement.operation, what="operation"),
        "release_ref": _text(statement.release_ref, what="release ref"),
        "rollout_ref": _text(statement.rollout_ref, what="rollout ref"),
        "plan_id": _text(statement.authorization_plan_id, what="plan id"),
        "approval_decision_ref": _text(
            authorization.statement.approval_decision_ref, what="approval decision"
        ),
        "control_plan_digest": _text(statement.plan_digest, what="plan digest"),
        "execution_sequence": int(statement.execution_sequence),
        "attempt_no": int(statement.attempt_no),
        "controller_ssh_fingerprint": request.controller_ssh_fingerprint,
        "host_id": request.host_id,
        "host_incarnation": request.host_incarnation,
        "host_enrolment_ref": request.host_enrolment_ref,
    }
    if tuple(context) != CONTEXT_KEYS:
        raise _refuse(
            "the execution context does not match the closed contract",
            TargetRefusal.MATERIALS_REFUSED,
        )
    attempt_id = _text(statement.dispatch_id, what="attempt id")
    return IssuedMaterials(
        attempt_id=attempt_id,
        dispatch_document={
            "attempt_id": attempt_id,
            "authorization_envelope": json.loads(authorization.canonical_bytes),
            "dispatch_envelope": json.loads(dispatch.canonical_bytes),
        },
        context_document=context,
    )


class _RefusingAuthorizationSigner(_AuthorizationSigner):
    def sign(self, canonical_bytes: bytes) -> Any:
        raise _refuse(
            "recovery cannot issue a replacement authorization",
            TargetRefusal.MATERIALS_REFUSED,
        )


def _recovery_control() -> Any:
    control = import_module("dotmac_deployment_control")
    if not all(
        callable(getattr(control, name, None))
        for name in (
            "DispatchResumeExpectation",
            "validate_recovery_dispatch_statement",
        )
    ):
        raise _refuse(
            "Control recovery API is unavailable; source qualification is required",
            TargetRefusal.MATERIALS_REFUSED,
        )
    return control


class _RecoveryDispatchSigner(_DispatchSigner):
    def __init__(self, custody: Custody, request: RecoverDispatchRequest) -> None:
        super().__init__(custody)
        self._request = request
        self._used = False

    def sign_dispatch(self, canonical_bytes: bytes) -> Any:
        if self._used:
            raise _refuse("recovery signing is spent", TargetRefusal.MATERIALS_REFUSED)
        # Burn before parsing/forwarding: a failure is never an extra signing use.
        self._used = True
        control = _recovery_control()
        from vendor_cp.deployment.transit_custody import strict_json

        statement = control.validate_recovery_dispatch_statement(
            strict_json(canonical_bytes),
            expectation=self._request.expectation,
            dispatch_identity=self.dispatch_identity,
            control_version=version("dotmac-deployment-control"),
            not_before=self._request.not_before,
            deadline=self._request.deadline,
            at=datetime.now(UTC),
        )
        if statement.canonical_bytes != canonical_bytes:
            raise _refuse(
                "noncanonical recovery signing input", TargetRefusal.MATERIALS_REFUSED
            )
        return super().sign_dispatch(canonical_bytes)


def _validate_recovery_request(request: RecoverDispatchRequest) -> datetime:
    control = _recovery_control()
    original, expected = request.original_request, request.expectation
    if not isinstance(expected, control.DispatchResumeExpectation):
        raise _refuse(
            "typed recovery expectation required", TargetRefusal.MATERIALS_REFUSED
        )
    for value in (
        request.session_id,
        original.rollout_command_id,
        original.dispatch_command_id,
        original.rollout_ref,
        original.controller_ssh_fingerprint,
        original.host_id,
        original.host_incarnation,
        original.host_enrolment_ref,
    ):
        _text(value, what="original recovery input")
    _check_host_enrolment(original)
    envelope = expected.original_authorization
    if (
        original.plan_id != expected.plan_id
        or original.rollout_ref != expected.rollout_ref
        or original.rollout_command_id != expected.rollout_command_id
        or original.dispatch_command_id != expected.dispatch_command_id
        or original.rollout_command_id == original.dispatch_command_id
        or original.authorization_expires_at != envelope.statement.expires_at
        or str(original.plan_id) != envelope.statement.plan_id
        or original.rollout_ref != envelope.statement.rollout_ref
    ):
        raise _refuse(
            "original recovery request differs", TargetRefusal.MATERIALS_REFUSED
        )
    now = datetime.now(UTC)
    bounds = (request.not_before, request.deadline, original.authorization_expires_at)
    if any(not isinstance(value, datetime) or value.tzinfo is None for value in bounds):
        raise _refuse("aware recovery bounds required", TargetRefusal.MATERIALS_REFUSED)
    if (
        not request.not_before
        <= now
        < request.deadline
        < original.authorization_expires_at
    ):
        raise _refuse("recovery window is closed", TargetRefusal.MATERIALS_REFUSED)
    return now


def _read_recovery_projection(path: str, expected_sha256: str) -> bytes:
    """Read one protected public projection FD bound to its approved raw digest."""
    if (
        not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("invalid projection digest")
    target = Path(path)
    if not target.is_absolute() or ".." in target.parts:
        raise ValueError("unsafe projection path")
    owner_uids = {0, os.geteuid()}
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors: list[int] = []
    try:
        descriptors.append(os.open("/", directory_flags))
        for component in target.parts[1:-1]:
            directory = os.fstat(descriptors[-1])
            if directory.st_uid not in owner_uids or directory.st_mode & 0o022:
                raise ValueError("unprotected projection directory")
            descriptors.append(
                os.open(component, directory_flags, dir_fd=descriptors[-1])
            )
        directory = os.fstat(descriptors[-1])
        if directory.st_uid not in owner_uids or directory.st_mode & 0o022:
            raise ValueError("unprotected projection directory")
        fd = os.open(
            target.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=descriptors[-1],
        )
        descriptors.append(fd)
        before = os.fstat(fd)
        maximum = 128 * 1024
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in owner_uids
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("unsafe projection file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(64 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise ValueError("oversized projection")
            chunks.append(chunk)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise ValueError("projection changed during read")
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError("projection digest differs")
        return raw
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def load_recovery_request(path: str, *, expected_sha256: str) -> RecoverDispatchRequest:
    """Bounded closed projection bound to the approved external manifest digest.

    The protected caller derives expected_sha256 from its preapproved projection,
    never the current mutable file. Digest agreement does not itself qualify the
    manifest's provenance, host binding or approval.
    """
    from vendor_cp.deployment.transit_custody import strict_json

    try:
        raw = _read_recovery_projection(path, expected_sha256)
        value = strict_json(raw)
        if not isinstance(value, dict) or set(value) != {
            "original_request",
            "resume_expectation",
            "session_id",
            "not_before",
            "deadline",
        }:
            raise ValueError("closed recovery projection required")
        original = value["original_request"]
        if (
            not isinstance(original, dict)
            or set(original) != {field.name for field in fields(IssueDispatchRequest)}
            or any(not isinstance(item, str) for item in original.values())
        ):
            raise ValueError("closed original request required")
        original = dict(original)
        original["plan_id"] = UUID(original["plan_id"])
        original["authorization_expires_at"] = datetime.fromisoformat(
            original["authorization_expires_at"]
        )
        control = _recovery_control()
        request = RecoverDispatchRequest(
            original_request=IssueDispatchRequest(**original),
            expectation=control.DispatchResumeExpectation.parse(
                value["resume_expectation"]
            ),
            session_id=value["session_id"],
            not_before=datetime.fromisoformat(value["not_before"]),
            deadline=datetime.fromisoformat(value["deadline"]),
        )
        _validate_recovery_request(request)
        return request
    except FoundationBindingsUnavailable:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise _refuse(
            "invalid recovery request projection", TargetRefusal.MATERIALS_REFUSED
        ) from None


def recover_dispatch_materials(
    db: Any, request: RecoverDispatchRequest, *, custody: Custody | None = None
) -> IssuedMaterials:
    """Replay original rollout, then dispatch once under a fresh approval hold.

    Each existing lifecycle seam holds its own transaction through our commit.
    No SQL, new engine, expiry extension or deployment executor lives here.
    Callers use write_materials with a fresh exclusive output directory.
    """
    held_custody = custody or _require_custody()
    now = _validate_recovery_request(request)
    control = _recovery_control()
    original, expected = request.original_request, request.expectation
    envelope = expected.original_authorization
    verifier = AuthorizationEd25519Verifier(held_custody.authorization_identity)
    control.verify_authorization_envelope(envelope, verifier=verifier, at=now)
    approval = import_module("vendor_cp.deployment.foundation_execution_approval")
    rollout = approval.request_foundation_rollout(
        db,
        command_id=original.rollout_command_id,
        plan_id=original.plan_id,
        rollout_ref=original.rollout_ref,
        authorization_expires_at=original.authorization_expires_at,
        signer=_RefusingAuthorizationSigner(held_custody),
        resume_expectation=expected,
    )
    if rollout.id != expected.rollout_id:
        raise _refuse(
            "original rollout replay differs", TargetRefusal.MATERIALS_REFUSED
        )
    db.commit()
    intent = approval.dispatch_foundation_attempt(
        db,
        command_id=original.dispatch_command_id,
        rollout_id=rollout.id,
        verifier=verifier,
        dispatch_signer=_RecoveryDispatchSigner(held_custody, request),
        resume_expectation=expected,
    )
    if intent.authorization_envelope.canonical_bytes != envelope.canonical_bytes:
        raise _refuse("original authorization changed", TargetRefusal.MATERIALS_REFUSED)
    db.commit()
    return _assemble_materials(original, intent)


def write_materials(
    directory: str | Path, issued: IssuedMaterials
) -> tuple[Path, Path]:
    """Write both documents create-only, 0600, in an owner-only directory.

    Refuses an existing file (a stale document is not overwritten into looking
    fresh), a symlinked or group/other-accessible directory, and a directory not
    owned by this process.
    """
    target = Path(directory)
    try:
        info = os.lstat(target)
    except OSError:
        raise _refuse(
            "the materials directory does not exist", TargetRefusal.MATERIALS_REFUSED
        ) from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    ):
        raise _refuse(
            "the materials directory must be an owner-only directory owned by "
            "this process",
            TargetRefusal.MATERIALS_REFUSED,
        )
    written: list[Path] = []
    for name, document in (
        (DISPATCH_FILE, issued.dispatch_document),
        (CONTEXT_FILE, issued.context_document),
    ):
        path = target / name
        try:
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError:
            raise _refuse(
                "a materials file cannot be created (it may already exist)",
                TargetRefusal.MATERIALS_REFUSED,
            ) from None
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
        written.append(path)
    return written[0], written[1]


def _controller_session(env: Mapping[str, str]) -> Any:
    """A raw CP platform session on the CONTROLLER (general credentials belong
    here, never on a target)."""
    from dotmac_kernel.session_runtime import DatabaseRuntime

    runtime = DatabaseRuntime.from_urls(
        database_url=env["DATABASE_URL"],
        platform_database_url=env["PLATFORM_DATABASE_URL"],
    )
    return runtime.platform_session_factory()


def _build_parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="Plan lifecycle and genuine dispatch materials (operator command)."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    propose = sub.add_parser("propose")
    propose.add_argument("--command-id", required=True)
    propose.add_argument("--target-id", required=True)
    propose.add_argument("--operation", required=True)
    propose.add_argument("--descriptor-digest", required=True)
    propose.add_argument("--execution-plan-digest", required=True)
    propose.add_argument("--approval-policy-code", required=True)
    propose.add_argument("--approval-policy-version", type=int, required=True)
    opened = sub.add_parser("open-approval")
    opened.add_argument("--command-id", required=True)
    opened.add_argument("--plan-id", required=True)
    opened.add_argument("--requested-by", required=True)
    approve = sub.add_parser("approve")
    approve.add_argument("--command-id", required=True)
    approve.add_argument("--plan-id", required=True)
    approve.add_argument("--approval-request-id", required=True)
    issue = sub.add_parser("issue")
    issue.add_argument("--plan-id", required=True)
    issue.add_argument("--rollout-ref", required=True)
    issue.add_argument("--rollout-command-id", required=True)
    issue.add_argument("--dispatch-command-id", required=True)
    issue.add_argument("--authorization-expires-at", required=True)
    issue.add_argument("--controller-ssh-fingerprint", required=True)
    # The host facts come from ONE source: the E10 receipt row (CP-7), or, as
    # before, all three typed. `_host_facts` refuses a mix and refuses neither.
    issue.add_argument("--e10-receipt-ref")
    issue.add_argument("--host-id")
    issue.add_argument("--host-incarnation")
    issue.add_argument("--host-enrolment-ref")
    issue.add_argument("--out-dir", required=True)
    # Required and single-valued: there is no default mode and no other custody.
    issue.add_argument("--custody", required=True, choices=("transit",))
    issue.add_argument("--custody-config", required=True)
    recovery = sub.add_parser("recover-dispatch")
    recovery.add_argument("--recovery-request", required=True)
    recovery.add_argument("--recovery-request-sha256", required=True)
    recovery.add_argument("--out-dir", required=True)
    recovery.add_argument("--custody", required=True, choices=("transit",))
    recovery.add_argument("--custody-config", required=True)
    return parser


def _host_facts(args: Any, env: Mapping[str, str]) -> tuple[str, str, str]:
    """`(host_id, host_incarnation, host_enrolment_ref)` from exactly one source.

    Either every fact is typed, or `--e10-receipt-ref` names the receipt row they
    are read from (over the owner session, `LANE3_E10_DATABASE_URL`: no runtime
    role may read `cp_lane3`). Both, or neither, is a refusal: a typed value that
    disagrees with the receipt is exactly the typo that would spend a host.
    """
    typed = (args.host_id, args.host_incarnation, args.host_enrolment_ref)
    if args.e10_receipt_ref:
        if any(value is not None for value in typed):
            raise _refuse(
                "host facts come from the receipt OR from flags, never both",
                TargetRefusal.MATERIALS_REFUSED,
            )
        from vendor_cp.deployment import lane3_e10

        try:
            db = lane3_e10.owner_session(env)
            try:
                facts = lane3_e10.receipt_host_facts(
                    db, receipt_ref=args.e10_receipt_ref
                )
            finally:
                db.close()
        except lane3_e10.E10Refused as refusal:
            raise _refuse(
                f"the E10 receipt is not usable: {refusal.code}",
                TargetRefusal.MATERIALS_REFUSED,
            ) from None
        return facts.host_id, facts.host_incarnation, facts.host_enrolment_ref
    host_id, host_incarnation, host_enrolment_ref = typed
    if host_id is None or host_incarnation is None or host_enrolment_ref is None:
        raise _refuse(
            "host facts need --e10-receipt-ref or all of --host-id, "
            "--host-incarnation and --host-enrolment-ref",
            TargetRefusal.MATERIALS_REFUSED,
        )
    return host_id, host_incarnation, host_enrolment_ref


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    stdin: Any = None,
    owner_uid: int = 0,
) -> int:
    """Operator command: names and ids only, typed refusals, no secret output.

    Runs on the CONTROLLER on CP's own database. `issue` installs transit custody
    (token on stdin) BEFORE the first database connection; without it nothing is
    signed and the database is not touched.
    """
    import sys

    parser = _build_parser()
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        try:
            from vendor_cp.audit_bootstrap import ensure_process_audit_actions

            ensure_process_audit_actions()
        except Exception:
            raise _refuse(
                "the process audit vocabulary could not be installed",
                TargetRefusal.MATERIALS_REFUSED,
            ) from None
        if args.action == "recover-dispatch":
            from vendor_cp.deployment import transit_custody

            recovery_request = load_recovery_request(
                args.recovery_request, expected_sha256=args.recovery_request_sha256
            )
            config = transit_custody.load_config(args.custody_config)
            token = transit_custody.read_token(stdin)
            recovery_custody = transit_custody.build_recovery_custody(
                config, token, owner_uid=owner_uid
            )
            session = _controller_session(env)
            try:
                issued = recover_dispatch_materials(
                    session, recovery_request, custody=recovery_custody
                )
            finally:
                session.close()
            write_materials(args.out_dir, issued)
            print("recovery materials issued")
            return 0
        if args.action == "issue":
            from vendor_cp.deployment import transit_custody

            config = transit_custody.load_config(args.custody_config)
            token = transit_custody.read_token(stdin)
            install_custody(
                transit_custody.build_custody(config, token, owner_uid=owner_uid)
            )
            host_id, host_incarnation, host_enrolment_ref = _host_facts(args, env)
            request = IssueDispatchRequest(
                plan_id=UUID(args.plan_id),
                rollout_ref=args.rollout_ref,
                rollout_command_id=args.rollout_command_id,
                dispatch_command_id=args.dispatch_command_id,
                authorization_expires_at=datetime.fromisoformat(
                    args.authorization_expires_at
                ),
                controller_ssh_fingerprint=args.controller_ssh_fingerprint,
                host_id=host_id,
                host_incarnation=host_incarnation,
                host_enrolment_ref=host_enrolment_ref,
            )
            _check_expiry(request.authorization_expires_at)
            session = _controller_session(env)
            try:
                issued = issue_dispatch_materials(session, request)
            finally:
                session.close()
            write_materials(args.out_dir, issued)
            print("materials issued")
            return 0
        approval = import_module("vendor_cp.deployment.foundation_execution_approval")
        session = _controller_session(env)
        try:
            if args.action == "propose":
                plan = approval.propose_foundation_plan(
                    session,
                    approval.ProposeFoundationPlan(
                        command_id=args.command_id,
                        target_id=UUID(args.target_id),
                        operation=args.operation,
                        descriptor_digest=args.descriptor_digest,
                        execution_plan_digest=args.execution_plan_digest,
                        approval_policy_code=args.approval_policy_code,
                        approval_policy_version=args.approval_policy_version,
                    ),
                )
                session.commit()
                print(f"plan proposed: {plan.id}")
            elif args.action == "open-approval":
                opened = approval.open_foundation_approval(
                    session,
                    command_id=args.command_id,
                    plan_id=UUID(args.plan_id),
                    requested_by=UUID(args.requested_by),
                )
                session.commit()
                print(f"approval opened: {opened.request_id}")
            else:
                plan = approval.approve_foundation_plan(
                    session,
                    command_id=args.command_id,
                    plan_id=UUID(args.plan_id),
                    approval_request_id=UUID(args.approval_request_id),
                )
                session.commit()
                print(f"plan approved: {plan.id}")
        finally:
            session.close()
    except FoundationBindingsUnavailable as refusal:
        print(f"{args.action} refused: {refusal.code}", file=sys.stderr)
        return 2
    except (KeyError, ValueError, TypeError):
        print(f"{args.action} refused: invalid request or environment", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
