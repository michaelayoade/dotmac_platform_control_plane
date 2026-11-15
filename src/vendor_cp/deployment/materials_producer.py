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
import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from pathlib import Path
from threading import Lock
from typing import Any, Final
from uuid import UUID

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    AuthorizationEd25519Verifier,
    PinnedVerificationIdentity,
)

__all__ = [
    "CONTEXT_FILE",
    "CONTEXT_KEYS",
    "DISPATCH_FILE",
    "Custody",
    "IssueDispatchRequest",
    "IssuedMaterials",
    "install_custody",
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


def issue_dispatch_materials(
    db: Any, request: IssueDispatchRequest, *, custody: Custody | None = None
) -> IssuedMaterials:
    """Issue one genuine pair under the approval hold and describe it.

    The caller owns `db`; this commits after each lifecycle stage. Refuses (typed)
    with no custody. Any Control or Approvals refusal propagates unchanged.
    """
    held_custody = custody or _require_custody()
    for name in (
        request.controller_ssh_fingerprint,
        request.host_id,
        request.host_incarnation,
        request.host_enrolment_ref,
        request.rollout_ref,
    ):
        _text(name, what="request field")
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


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    """`issue` command: controller-side, on CP's own database. Names only.

    Runs on the CONTROLLER, where the general CP database credentials belong
    (never on a target). With no custody installed in the process it refuses
    before touching the database.
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Issue genuine dispatch materials.")
    parser.add_argument("action", choices=("issue",))
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--rollout-ref", required=True)
    parser.add_argument("--rollout-command-id", required=True)
    parser.add_argument("--dispatch-command-id", required=True)
    parser.add_argument("--authorization-expires-at", required=True)
    parser.add_argument("--controller-ssh-fingerprint", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--host-incarnation", required=True)
    parser.add_argument("--host-enrolment-ref", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        custody = _require_custody()
        request = IssueDispatchRequest(
            plan_id=UUID(args.plan_id),
            rollout_ref=args.rollout_ref,
            rollout_command_id=args.rollout_command_id,
            dispatch_command_id=args.dispatch_command_id,
            authorization_expires_at=datetime.fromisoformat(
                args.authorization_expires_at
            ),
            controller_ssh_fingerprint=args.controller_ssh_fingerprint,
            host_id=args.host_id,
            host_incarnation=args.host_incarnation,
            host_enrolment_ref=args.host_enrolment_ref,
        )
        if request.authorization_expires_at.tzinfo is None:
            raise _refuse(
                "the authorization expiry must be timezone-aware",
                TargetRefusal.MATERIALS_REFUSED,
            )
        from dotmac_kernel.session_runtime import DatabaseRuntime

        runtime = DatabaseRuntime.from_urls(
            database_url=env["DATABASE_URL"],
            platform_database_url=env["PLATFORM_DATABASE_URL"],
        )
        session = runtime.platform_session_factory()
        try:
            issued = issue_dispatch_materials(session, request, custody=custody)
        finally:
            session.close()
        write_materials(args.out_dir, issued)
    except FoundationBindingsUnavailable as refusal:
        print(f"materials issue refused: {refusal.code}", file=sys.stderr)
        return 2
    except (KeyError, ValueError):
        print(
            "materials issue refused: invalid request or environment", file=sys.stderr
        )
        return 2
    print("materials issued")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
