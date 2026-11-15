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

Placement (Gate 2 a2, Michael's Q2 ruling and E3 audit): the bindings run ON
the target, with Foundation's own host effects (`target_effects`), Control's
verification security installed at startup (`control_security`), a release-
evidence trust policy (`release_evidence_policy`), CP database time as the
freshness clock (`database_clock`) and a SEPARATE scoped dispatch-consumption
credential (`consumption_scope`; grants in
`docs/design/scoped-consumption-role.md`). A host that carries a general CP
platform database credential refuses. The launcher-side materials
producer/depositor is not part of this module.

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

from vendor_cp.deployment.consumption_scope import (
    consumption_sessions,
    prove_scoped_role,
    scoped_consumption_dsn,
)
from vendor_cp.deployment.control_security import (
    AUTHORIZATION_IDENTITY_ENV,
    DISPATCH_IDENTITY_ENV,
    install_control_verification,
    load_control_identities,
)
from vendor_cp.deployment.database_clock import (
    SKEW_LIMIT_ENV,
    DatabaseClock,
    parse_skew_limit,
    require_clock_skew_within,
)
from vendor_cp.deployment.foundation_execution_approval import (
    compose_approved_foundation_v3_providers,
)
from vendor_cp.deployment.host_admission_adapter import (
    FoundationHostV3Bindings,
    FoundationV3Sources,
    HostAdmissionObservation,
)
from vendor_cp.deployment.release_evidence_policy import (
    RELEASE_EVIDENCE_IDENTITY_ENV,
    RELEASE_EVIDENCE_REPOSITORY_ENV,
    release_evidence_trust,
)
from vendor_cp.deployment.target_effects import (
    build_target_effects,
    build_target_exposure_effects,
)
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

if TYPE_CHECKING:  # pragma: no cover - checker-only; runtime stays lazy
    from dotmac_deployment_foundation.execution_bindings import ExecutionBindings

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

#: Observer startup materials. Each names a JSON document the runner
#: lane's launcher deposits before startup; the values are paths to
#: deployment facts, and the documents' contents are never echoed.
HOST_ADMISSION_MATERIALS_ENV: Final = "HOST_ADMISSION_MATERIALS"
EXECUTION_CONTEXT_MATERIALS_ENV: Final = "EXECUTION_CONTEXT_MATERIALS"


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
    build_effects: Callable[..., Any] | None = None,
    build_exposure_effects: Callable[..., Any] | None = None,
    evidence_policy: Any = None,
    evidence_verifier: Any = None,
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
        build_effects=build_effects,
        build_exposure_effects=build_exposure_effects,
        evidence_policy=evidence_policy,
        evidence_verifier=evidence_verifier,
    )


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
    (Control's own JSON mapping, parsed through its public presentation
    type before resolve), and the `candidate`/`installed`
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
        # Control resolves its own concrete presentation type. A text token or
        # stringified JSON document is not that type and cannot be forwarded as
        # if it had crossed the owner's schema boundary. Parsing is not signature
        # verification; the genuine resolver retains that responsibility.
        try:
            from dotmac_deployment_control import HostAdmissionPresentationV1
        except ImportError:
            raise FoundationBindingsUnavailable(
                "Control presentation parser is unavailable"
            ) from None
        try:
            presentation = HostAdmissionPresentationV1.parse(document["presentation"])
        except Exception:
            # Control diagnostics may include supplied private fields. Neither
            # the message nor an exception chain belongs in the startup refusal.
            raise FoundationBindingsUnavailable(
                f"{what} materials carry an unparsable presentation"
            ) from None
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

    TARGET-SIDE composition (Gate 2 a2, Michael's Q2/E3 rulings): Foundation and
    these bindings run on the host being mutated. Startup materials (values
    never echoed):

    * `DISPATCH_CONSUMPTION_DATABASE_URL`: the short-lived, scoped consumption
      role. A host carrying `DATABASE_URL` or `PLATFORM_DATABASE_URL` refuses;
    * `HOST_ADMISSION_MATERIALS` / `EXECUTION_CONTEXT_MATERIALS`: the observer
      documents the launcher deposited;
    * `AUTHORIZATION_VERIFICATION_IDENTITY` / `DISPATCH_VERIFICATION_IDENTITY`:
      the pinned public identities Control's verification is installed with;
    * `RELEASE_EVIDENCE_VERIFICATION_IDENTITY` / `RELEASE_EVIDENCE_REPOSITORY`:
      the release-evidence trust policy;
    * optional `DISPATCH_CLOCK_SKEW_LIMIT_SECONDS`.

    Every missing name is listed in one refusal. Then, in order: the role is
    PROVEN narrow by the catalogue, this host's clock is checked against CP
    database time, Control's verification security is installed on that same
    database clock, and the observers are exercised once so a malformed
    document refuses at startup rather than at admission. That refusal IS the
    gate working: discovery surfaces it loudly instead of admitting on partial
    trust.
    """
    env = os.environ if environ is None else environ
    dsn = scoped_consumption_dsn(env)
    missing: list[str] = []
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
    for name in (
        AUTHORIZATION_IDENTITY_ENV,
        DISPATCH_IDENTITY_ENV,
        RELEASE_EVIDENCE_IDENTITY_ENV,
        RELEASE_EVIDENCE_REPOSITORY_ENV,
    ):
        if not env.get(name, "").strip():
            missing.append(f"verification input ({name} unset)")
    if missing:
        raise FoundationBindingsUnavailable(
            "Foundation execution bindings cannot be composed at startup; "
            "missing: " + "; ".join(missing),
            code=TargetRefusal.UNSPECIFIED,
        )
    limit = parse_skew_limit(env.get(SKEW_LIMIT_ENV))
    # Everything that needs no connection is proved before the first one.
    evidence_policy, evidence_verifier = release_evidence_trust(env)
    control_identities = load_control_identities(env)
    host_admission = host_admission_source(admission_path)
    host_admission()
    foundation = foundation_host_bindings()
    execution_context = execution_context_source(
        context_path, foundation.execution_context_type
    )
    execution_context()

    sessions = consumption_sessions(dsn)
    prove_scoped_role(sessions)
    clock = DatabaseClock(sessions)
    require_clock_skew_within(clock, limit=limit)
    install_control_verification(env, clock=clock, identities=control_identities)
    return build_execution_bindings(
        sessions=sessions,
        host_admission=host_admission,
        execution_context=execution_context,
        clock=clock,
        foundation=foundation,
        build_effects=build_target_effects,
        build_exposure_effects=build_target_exposure_effects,
        evidence_policy=evidence_policy,
        evidence_verifier=evidence_verifier,
    )
