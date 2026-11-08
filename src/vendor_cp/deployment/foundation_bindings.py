"""Foundation `execution_bindings` composition for the installed CLI.

This distribution declares ONE entry point in Foundation's
`dotmac_deployment_foundation.execution_bindings` group. Discovery loads
:func:`bindings` — a zero-argument factory — only on execute paths;
`validate` and dry runs read entry-point metadata and never import here.

Trust shape (Gate 2 ruling packet, 2026-11-07): every provider is fixed
at assembly installation from startup materials. Nothing is selected by
a request, an environment variable naming a provider, or caller-supplied
material. The Control half is bound exclusively through
:func:`foundation_execution_approval.compose_approved_foundation_v3_providers`,
so the held-approval barrier (#261) is in the execution path; this
module never calls a guarded finalizer or the private guarded composer.

The production `host_admission` and `execution_context` observers read
runner-side startup materials: `HOST_ADMISSION_MATERIALS` and
`EXECUTION_CONTEXT_MATERIALS` each name a JSON document the lane's
launcher deposits before startup (Control/Gate-0-issued evidence for
the rehearsal target and candidate). The sources re-read those
documents on every observation, parse them through Foundation's own
types, and refuse closed — naming the missing or malformed input,
never its value — so until genuine materials exist, :func:`bindings`
refuses at startup and the publication gate stays shut. That refusal
IS the gate working: discovery surfaces it loudly on execute paths
instead of admitting on partial trust.

`dotmac_deployment_foundation` is deliberately not a dependency of this
assembly (pyproject). Every Foundation import below is lazy, inside the
function that needs it, so importing this module without Foundation
installed fails only when composition is actually attempted — and then
with the sanitized refusal, not an ImportError traceback.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from sqlalchemy.orm import Session

from vendor_cp.deployment.foundation_execution_approval import (
    compose_approved_foundation_v3_providers,
)
from vendor_cp.deployment.host_admission_adapter import (
    FoundationHostV3Bindings,
    FoundationV3Sources,
    HostAdmissionObservation,
)

if TYPE_CHECKING:  # pragma: no cover - checker-only; runtime stays lazy
    from dotmac_deployment_foundation.execution_bindings import ExecutionBindings
    from dotmac_kernel.session_runtime import DatabaseRuntime

__all__ = [
    "ENTRY_POINT_NAME",
    "EXECUTION_CONTEXT_MATERIALS_ENV",
    "HOST_ADMISSION_MATERIALS_ENV",
    "Ed25519AttestationVerifier",
    "FoundationBindingsUnavailable",
    "bindings",
    "build_execution_bindings",
    "execution_context_source",
    "foundation_host_bindings",
    "host_admission_source",
    "trust_policy_from_resolved_context",
]

#: The entry-point name, which `ExecutionBindings.provider` must equal.
#: Foundation reserves `compose-host` for its in-package provider.
ENTRY_POINT_NAME: Final = "dotmac-control-plane"

#: Kernel settings materials the platform sessions are built from. The
#: kernel owns the single engine (D1): this assembly never constructs
#: one. Values are deployment facts, never echoed.
SESSION_MATERIAL_ENVS: Final = ("DATABASE_URL", "PLATFORM_DATABASE_URL")

#: Observer startup materials. Each names a JSON document the runner
#: lane's launcher deposits before startup; the values are paths to
#: deployment facts, and the documents' contents are never echoed.
HOST_ADMISSION_MATERIALS_ENV: Final = "HOST_ADMISSION_MATERIALS"
EXECUTION_CONTEXT_MATERIALS_ENV: Final = "EXECUTION_CONTEXT_MATERIALS"


class FoundationBindingsUnavailable(RuntimeError):
    """Startup composition cannot be completed. Sanitized: names only."""


class Ed25519AttestationVerifier:
    """Real `AttestationVerifier`: Ed25519 over the envelope signed bytes.

    Signature encoding is the producers' own convention (Starter
    `candidate_attestation_signer`): standard base64 of the raw
    64-byte Ed25519 signature; `public_key` is the raw 32-byte key
    decoded by Foundation from the matched trust root. Anything else —
    wrong algorithm, malformed base64, wrong-length key or signature —
    verifies False; Foundation turns a False into its own refusal.
    """

    def verify(
        self,
        *,
        public_key: bytes,
        algorithm: str,
        message: bytes,
        signature: str,
    ) -> bool:
        if algorithm != "ed25519":
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(base64.b64decode(signature, validate=True), message)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


def trust_policy_from_resolved_context(resolved: Any) -> Any:
    """Derive Foundation's `AttestationTrustPolicy` from a resolved context.

    Promoted from the conformance suite's production-shaped derivation:
    Control's resolved root contexts already carry key material in
    Foundation's padded-standard-base64 form, so a real caller needs no
    encoding conversion — only the field mapping (`root_version` ->
    `trust_root_version`, instants rendered canonical-Z).
    """
    from dotmac_deployment_foundation import (
        AttestationTrustPolicy,
        AttestationTrustRootV2,
    )

    def _root(root: Any) -> Any:
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


def foundation_host_bindings() -> FoundationHostV3Bindings:
    """Foundation's real F2 function/types from the installed facility."""
    try:
        from dotmac_deployment_foundation import (
            AttestationPairVerificationResultV1,
            ControlConsumptionRequestV3,
            ExecutionContextV3,
            HostSourceAdmissionTrace,
            admit_host_source,
        )
    except ImportError as exc:
        raise FoundationBindingsUnavailable(
            "dotmac-deployment-foundation is not installed in this "
            "environment; execution bindings cannot be composed"
        ) from exc
    return FoundationHostV3Bindings(
        admit_host_source=admit_host_source,
        trust_policy_from_context=trust_policy_from_resolved_context,
        verifier=Ed25519AttestationVerifier(),
        trace_type=HostSourceAdmissionTrace,
        pair_result_type=AttestationPairVerificationResultV1,
        consumption_request_type=ControlConsumptionRequestV3,
        execution_context_type=ExecutionContextV3,
    )


def build_execution_bindings(
    *,
    sessions: Callable[[], Session],
    host_admission: Callable[[], HostAdmissionObservation],
    execution_context: Callable[[], object],
    clock: Callable[[], datetime] | None = None,
    foundation: FoundationHostV3Bindings | None = None,
) -> ExecutionBindings:
    """Compose the approved provider pair into Foundation bindings.

    Every input is a startup-fixed source supplied by the composing
    lane; nothing here reads a request. The pair comes only from the
    approval-guarded composer, so a plan requiring approval can never
    reach dispatch around the held-approval barrier.
    """
    pair = compose_approved_foundation_v3_providers(
        foundation=foundation or foundation_host_bindings(),
        sources=FoundationV3Sources(
            sessions=sessions,
            host_admission=host_admission,
            execution_context=execution_context,
            clock=clock or (lambda: datetime.now(UTC)),
        ),
    )
    try:
        from dotmac_deployment_foundation.execution_bindings import (
            ExecutionBindings,
        )
    except ImportError as exc:
        raise FoundationBindingsUnavailable(
            "dotmac-deployment-foundation is not installed in this "
            "environment; execution bindings cannot be composed"
        ) from exc
    return ExecutionBindings(
        provider=ENTRY_POINT_NAME,
        deployment_admission_provider=pair.host_source,
        authorization_v3_provider=pair.execution_authority,
    )


#: The kernel runtime built from startup materials, held for the life of
#: the process: its engines back the session factory the adapter uses.
_RUNTIME: DatabaseRuntime | None = None


def _platform_sessions(env: Mapping[str, str]) -> Callable[[], Session]:
    """The kernel runtime's raw platform session factory (D1).

    Engines are constructed only inside `DatabaseRuntime` — vendor code
    never builds one — and the kernel's legacy db module is a retiring
    surface no new code may import. `platform_session_factory` yields the fresh
    raw Session the adapter contract requires (the adapter commits
    each phase and closes it itself — never the commit-on-exit
    `platform_session` wrapper). Engine construction is lazy; no
    connection opens here.
    """
    global _RUNTIME
    if _RUNTIME is None:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        _RUNTIME = DatabaseRuntime.from_urls(
            database_url=env["DATABASE_URL"],
            platform_database_url=env["PLATFORM_DATABASE_URL"],
        )
    return _RUNTIME.platform_session_factory


def _read_materials_document(path: str, *, what: str) -> dict[str, Any]:
    """One startup-materials JSON object, or a sanitized refusal."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise FoundationBindingsUnavailable(f"{what} materials cannot be read") from exc
    if not isinstance(document, dict):
        raise FoundationBindingsUnavailable(f"{what} materials are not an object")
    return document


def _require_closed(document: dict[str, Any], *, what: str, fields: set[str]) -> None:
    if set(document) != fields:
        raise FoundationBindingsUnavailable(
            f"{what} materials do not match the closed contract"
        )


def host_admission_source(path: str) -> Callable[[], HostAdmissionObservation]:
    """The production `host_admission` observer over startup materials.

    The document is closed: `attempt_id` (UUID), `presentation`
    (Control's own serialization, passed through untouched — Control
    validates it at resolve), and the `candidate`/`installed`
    attestation envelope documents, parsed only through Foundation's
    `AttestationEnvelopeV2.from_mapping`. Re-read on every observation
    so refreshed evidence is what admission verifies; every defect
    refuses closed without echoing a value.
    """
    what = f"host_admission observer ({HOST_ADMISSION_MATERIALS_ENV})"

    def _observe() -> HostAdmissionObservation:
        document = _read_materials_document(path, what=what)
        _require_closed(
            document,
            what=what,
            fields={"attempt_id", "presentation", "candidate", "installed"},
        )
        try:
            attempt_id = UUID(str(document["attempt_id"]))
        except Exception as exc:
            raise FoundationBindingsUnavailable(
                f"{what} materials carry no attempt id"
            ) from exc
        presentation = document["presentation"]
        if not isinstance(presentation, str) or not presentation.strip():
            raise FoundationBindingsUnavailable(
                f"{what} materials carry no presentation"
            )
        try:
            from dotmac_deployment_foundation import AttestationEnvelopeV2
        except ImportError as exc:
            raise FoundationBindingsUnavailable(
                "dotmac-deployment-foundation is not installed in this "
                "environment; execution bindings cannot be composed"
            ) from exc
        try:
            candidate = AttestationEnvelopeV2.from_mapping(document["candidate"])
            installed = AttestationEnvelopeV2.from_mapping(document["installed"])
        except Exception as exc:
            raise FoundationBindingsUnavailable(
                f"{what} materials carry an unparsable attestation envelope"
            ) from exc
        return HostAdmissionObservation(
            attempt_id=attempt_id,
            presentation=presentation,
            candidate=candidate,
            installed=installed,
        )

    return _observe


def execution_context_source(
    path: str, context_type: type[Any]
) -> Callable[[], object]:
    """The production `execution_context` observer over startup materials.

    The document's closed key set is exactly the installed Foundation
    execution-context type's fields, and the value returned is that
    exact type — the adapter refuses anything else by identity, so a
    look-alike mapping can never stand in for observed facts.
    """
    what = f"execution_context observer ({EXECUTION_CONTEXT_MATERIALS_ENV})"

    def _observe() -> object:
        document = _read_materials_document(path, what=what)
        if not dataclasses.is_dataclass(context_type):
            raise FoundationBindingsUnavailable(
                f"{what} has no typed execution context to construct"
            )
        _require_closed(
            document,
            what=what,
            fields={field.name for field in dataclasses.fields(context_type)},
        )
        try:
            return context_type(**document)
        except Exception as exc:
            raise FoundationBindingsUnavailable(
                f"{what} materials do not construct the execution context"
            ) from exc

    return _observe


def bindings(environ: Mapping[str, str] | None = None) -> ExecutionBindings:
    """The declared entry-point factory. Zero-argument by contract.

    Startup materials contract (deployment facts, values never echoed):
    kernel `DATABASE_URL`/`PLATFORM_DATABASE_URL` build the kernel's
    single runtime, whose platform session factory supplies approval/
    dispatch sessions; `HOST_ADMISSION_MATERIALS` and
    `EXECUTION_CONTEXT_MATERIALS` name the observer documents the
    runner lane deposited. Every missing input is named in one
    refusal, and supplied observer materials are exercised once here
    so a malformed document refuses at startup rather than at
    admission. That refusal IS the gate working: discovery surfaces
    it loudly on execute paths instead of admitting on partial trust.
    """
    env = os.environ if environ is None else environ
    missing: list[str] = [
        name for name in SESSION_MATERIAL_ENVS if not env.get(name, "").strip()
    ]
    sessions: Callable[[], Session] | None = None
    if not missing:
        # Building the kernel runtime proves the materials compose at
        # startup (engines are lazy; no connection is opened), so the
        # refusal below names only what is genuinely absent.
        sessions = _platform_sessions(env)
    admission_path = env.get(HOST_ADMISSION_MATERIALS_ENV, "").strip()
    if not admission_path:
        missing.append(
            f"host_admission observer ({HOST_ADMISSION_MATERIALS_ENV} unset)"
        )
    context_path = env.get(EXECUTION_CONTEXT_MATERIALS_ENV, "").strip()
    if not context_path:
        missing.append(
            f"execution_context observer ({EXECUTION_CONTEXT_MATERIALS_ENV} unset)"
        )
    if missing or sessions is None:
        raise FoundationBindingsUnavailable(
            "Foundation execution bindings cannot be composed at startup; "
            "missing: " + "; ".join(missing)
        )
    # Prove the supplied materials parse into the exact typed values at
    # startup; admission re-reads them fresh on every observation. The
    # host-admission proof runs first: its document read names the
    # missing materials input even in an environment where Foundation
    # itself is not installed yet.
    host_admission = host_admission_source(admission_path)
    host_admission()
    foundation = foundation_host_bindings()
    execution_context = execution_context_source(
        context_path, foundation.execution_context_type
    )
    execution_context()
    return build_execution_bindings(
        sessions=sessions,
        host_admission=host_admission,
        execution_context=execution_context,
        foundation=foundation,
    )
