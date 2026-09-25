"""CP's orchestration seam for C1's protected, disposable rehearsal issuer.

`dotmac_deployment_control.rehearsal_issuer_authorization` (C1) authorizes
operating a rehearsal issuer for one bounded lease. It is PURE — it performs no
I/O and states plainly that it "cannot itself enforce that the comparison
subject was supplied by the disposable rehearsal harness rather than the
application under rehearsal", and that "callers of this contract must not
source the subject from the CP instance being rehearsed." This module is the
caller-side discharge of that obligation, made a SHAPE rather than a promise:
a `RehearsalIssuerAuthorizationSubject`-shaped object can only be built by
`issue_authorization_for_rehearsal_issuer`, and it can only be built from a
`HarnessBinding` that only `admit_harness_binding` can produce, and that
function refuses anything not attested as coming from the disposable
rehearsal harness.

## A LEAF module, deliberately

Stdlib only — no `vendor_cp.*` sibling, no `dotmac_deployment_control`, no
`dotmac_deployment_foundation`, no SQLAlchemy (this module touches no
database; `rehearsal_issuer.py` is the heavy half that does). Held to it by
`tests/architecture/test_rehearsal_issuer_adapter_import_boundary.py`, the
same discipline `host_admission_adapter.py` documents for the identical
reason: a conformance suite for this choreography should need this file's
Protocols and nothing else.

## Zero import coupling to C1 or Control

Every collaborator this module calls is expressed as a CP-owned `Protocol`
naming the exact shape this adapter calls, never the real Control/C1 types —
`dotmac-deployment-control` is pinned at `0.1.0a6`, which pre-dates C1
entirely, and bumping that pin is out of scope here. A real adapter's
`build_subject`/`issue` callables close over the genuine
`RehearsalIssuerAuthorizationSubject`/`issue_rehearsal_issuer_authorization`;
this module never imports either.

## `lease_id` binds to a Foundation `HostLease`'s existing authorization run,
never a new identity

The fleet's own rule, restated here because it decides a design choice on
this file: "the reference is the authorization, not a new identity"
(`plan_inputs.py`'s module docstring, same rule, same reasoning). Foundation's
`HostLease` carries no separate `lease_id` field; `HarnessBinding.lease_id`
is `HostLease.authorization_run_id`'s VALUE, carried across as a plain string
because this leaf module does not import the Foundation type that owns it.

## Why `RehearsalIssuerAuthorizationChecker` is declared with no caller

An issuer with no verifier declared anywhere in this codebase would mean
nothing in CP could ever check a presented rehearsal-issuer authorization —
a shape that should exist alongside the issuer even though nothing wires a
caller for it in this change.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol

__all__ = [
    "REHEARSAL_ENVIRONMENT",
    "HarnessBinding",
    "HarnessSource",
    "RehearsalIssuerAdapterUsageError",
    "RehearsalIssuerAuthorizationChecker",
    "RehearsalIssuerAuthorizationIssuer",
    "RehearsalIssuerRefusal",
    "RehearsalIssuerRefused",
    "RehearsalIssuerSubjectFactory",
    "RehearsalIssuerTerms",
    "admit_harness_binding",
    "issue_authorization_for_rehearsal_issuer",
]

#: The one environment C1's own `REHEARSAL_ONLY_ENVIRONMENT` will ever accept.
#: Pinned here too so `RehearsalIssuerTerms` refuses a non-rehearsal
#: environment structurally, on the CP side, before a subject is ever built.
REHEARSAL_ENVIRONMENT: Final = "rehearsal"

#: The five A6.4 terms every rehearsal-issuer subject must carry a provenance
#: for, matching `RehearsalIssuerTerms.provenance`'s declared keys.
_A6_KEYS: Final[frozenset[str]] = frozenset(
    {"target", "desired_state", "profile", "authorized_images", "execution_plan"}
)

_OVERRIDE_PROVENANCE: Final = "override"


class RehearsalIssuerRefusal(StrEnum):
    """Why this adapter refused, before C1 was ever asked anything."""

    #: The comparison subject was not proven to originate from the disposable
    #: rehearsal harness. Covers both a `HarnessBinding` constructed by hand
    #: and an attestation `admit_harness_binding` cannot trust.
    SUBJECT_NOT_FROM_HARNESS = "SUBJECT_NOT_FROM_HARNESS"
    #: `RehearsalIssuerTerms.environment` is not `REHEARSAL_ENVIRONMENT`.
    ENVIRONMENT_NOT_REHEARSAL = "ENVIRONMENT_NOT_REHEARSAL"
    #: One of the five A6.4 values carries no provenance entry at all — the
    #: silent shape A6.4 forbids, refused on the CP side before C1 sees it.
    PROVENANCE_ABSENT = "PROVENANCE_ABSENT"
    #: A value's provenance is `"override"` but its key is not in
    #: `declared_overrides` — an undeclared exception is a silent value with a
    #: longer paper trail.
    OVERRIDE_UNDECLARED = "OVERRIDE_UNDECLARED"


class RehearsalIssuerRefused(ValueError):
    """This adapter refused to build or issue a rehearsal-issuer
    authorization, and why. Never a refusal FROM Control or C1 — see
    `RehearsalIssuerAdapterUsageError` for a caller's own wiring mistake."""

    def __init__(self, refusal: RehearsalIssuerRefusal, message: str) -> None:
        super().__init__(message)
        self.refusal = refusal


class RehearsalIssuerAdapterUsageError(ValueError):
    """The caller misused this adapter itself -- never a refusal from Control
    or C1. Kept distinct from `RehearsalIssuerRefused` so a caller cannot
    mistake a wiring mistake here for a security refusal upstream, the same
    separation `host_admission_adapter.HostAdmissionAdapterUsageError` draws
    for the identical reason."""


class RehearsalIssuerSubjectFactory(Protocol):
    """Builds C1's comparison subject from CP-derived terms and an attested
    harness binding. A real implementation closes over C1's
    `RehearsalIssuerAuthorizationSubject`; this Protocol never imports it."""

    def __call__(self, *, terms: object, harness: object) -> object: ...


class RehearsalIssuerAuthorizationIssuer(Protocol):
    """Signs the rehearsal-issuer authorization. Matches C1's
    `issue_rehearsal_issuer_authorization`'s keyword-only shape structurally."""

    def __call__(self, *, subject: object, signer: object) -> object: ...


class RehearsalIssuerAuthorizationChecker(Protocol):
    """Verifies a presented rehearsal-issuer authorization.

    Declared for symmetry with the issuer above; CP1 wires no caller for this
    yet -- an issuer with no verifier declared anywhere would mean nothing in
    CP could ever check a presented authorization, so the shape exists now
    even though nothing calls it in this change.
    """

    def __call__(
        self, value: object, *, verifier: object, subject: object
    ) -> object: ...


class HarnessSource(StrEnum):
    """Where a harness attestation says it came from. One member today,
    because one caller is legitimate: the disposable rehearsal harness
    itself, never the application under rehearsal."""

    DISPOSABLE_REHEARSAL_HARNESS = "disposable_rehearsal_harness"


class _HarnessWitness:
    """Held only by this module. See `HarnessBinding`."""

    __slots__ = ()


_ATTESTED: Final = _HarnessWitness()


@dataclass(frozen=True, slots=True)
class HarnessBinding:
    """Proof that a comparison subject's controller/lease terms were attested
    by the disposable rehearsal harness -- structurally, not by convention.

    The witness is positional and required, and only `admit_harness_binding`
    holds one, so a caller cannot construct this from a controller fingerprint
    and a lease id it typed by hand. This is the same device
    `vendor_cp.deployment.candidate.CandidateImage` uses for the identical
    reason: "the application does not authorize itself" has to be a shape a
    caller cannot route around, not a rule somebody remembers.

    `lease_id` binds to a Foundation `HostLease`'s `authorization_run_id`
    VALUE -- there is no separate `lease_id` identity to mint. See the module
    docstring's "reference is the authorization, not a new identity" note.
    """

    _witness: _HarnessWitness
    source: HarnessSource
    controller_fingerprint: str
    lease_id: str

    def __post_init__(self) -> None:
        if self._witness is not _ATTESTED:
            raise RehearsalIssuerRefused(
                RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS,
                "a HarnessBinding may only be produced by admit_harness_binding "
                "-- an operator-constructed binding is exactly what this type "
                "exists to refuse",
            )


def _attested_text(attestation: Mapping[str, object], key: str) -> str:
    value = attestation.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RehearsalIssuerRefused(
            RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS,
            f"the harness attestation carries no usable {key!r}",
        )
    return value


def admit_harness_binding(attestation: Mapping[str, object]) -> HarnessBinding:
    """The ONLY producer of a `HarnessBinding`.

    Refuses `SUBJECT_NOT_FROM_HARNESS` unless `attestation["source"]` equals
    `HarnessSource.DISPOSABLE_REHEARSAL_HARNESS.value`, and the same refusal
    for a malformed `controller_fingerprint`/`lease_id` -- an attestation this
    function cannot trust the shape of is not one it can say came from the
    harness either.
    """
    source = attestation.get("source")
    if source != HarnessSource.DISPOSABLE_REHEARSAL_HARNESS.value:
        raise RehearsalIssuerRefused(
            RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS,
            f"attestation source {source!r} is not "
            f"{HarnessSource.DISPOSABLE_REHEARSAL_HARNESS.value!r}; a "
            "rehearsal-issuer comparison subject may only be built from the "
            "disposable rehearsal harness's own attestation, never from the "
            "application under rehearsal",
        )
    controller_fingerprint = _attested_text(attestation, "controller_fingerprint")
    lease_id = _attested_text(attestation, "lease_id")
    return HarnessBinding(
        _ATTESTED,
        HarnessSource.DISPOSABLE_REHEARSAL_HARNESS,
        controller_fingerprint,
        lease_id,
    )


@dataclass(frozen=True, slots=True)
class RehearsalIssuerTerms:
    """CP's own derived A6.4 terms for one rehearsal-issuer lease, with a
    provenance record for every one of the five values C1's subject compares.

    Field names match `rehearsal_issuer.derive_rehearsal_issuer_terms`'s
    output exactly. `provenance` carries the five keys named by `_A6_KEYS`
    (`target`, `desired_state`, `profile`, `authorized_images`,
    `execution_plan`), each mapped to `"derived"` or `"override"`.
    """

    immutable_reference: str
    target_id: str
    target_ref: str
    desired_state_digest: str
    profile_digest: str
    authorized_image_digests: tuple[str, ...]
    execution_plan_digest: str
    environment: str = REHEARSAL_ENVIRONMENT
    provenance: Mapping[str, str] = field(default_factory=dict)
    declared_overrides: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        # Environment first, structurally, before any other field is read --
        # the same discipline C1's own statement type uses for the identical
        # reason (see its module docstring's "Why `environment` is pinned").
        if self.environment != REHEARSAL_ENVIRONMENT:
            raise RehearsalIssuerRefused(
                RehearsalIssuerRefusal.ENVIRONMENT_NOT_REHEARSAL,
                f"environment must be {REHEARSAL_ENVIRONMENT!r}, not "
                f"{self.environment!r}",
            )
        missing = sorted(_A6_KEYS - set(self.provenance))
        if missing:
            raise RehearsalIssuerRefused(
                RehearsalIssuerRefusal.PROVENANCE_ABSENT,
                f"provenance carries no entry for {missing}; every one of the "
                "five A6.4 values must carry a provenance before a subject is "
                "built",
            )
        undeclared = sorted(
            key
            for key in _A6_KEYS
            if self.provenance[key] == _OVERRIDE_PROVENANCE
            and key not in self.declared_overrides
        )
        if undeclared:
            raise RehearsalIssuerRefused(
                RehearsalIssuerRefusal.OVERRIDE_UNDECLARED,
                f"{undeclared} carry provenance 'override' but are not in "
                "declared_overrides; an override with no declaration is a "
                "silent value with a longer paper trail",
            )


def issue_authorization_for_rehearsal_issuer(
    *,
    terms: RehearsalIssuerTerms,
    harness: HarnessBinding,
    build_subject: RehearsalIssuerSubjectFactory,
    issue: RehearsalIssuerAuthorizationIssuer,
    signer: object,
) -> object:
    """CP's whole rehearsal-issuer authorization orchestration.

    No I/O, no key material held or touched -- `signer` is passed through to
    `issue` untouched, never inspected or dereferenced here. Controller and
    lease identity reach the built subject ONLY through `harness`, never as
    separate caller-suppliable arguments, so a caller cannot bind a
    comparison subject to a controller/lease the harness never attested.

    No fallback: if `issue` raises, the exception propagates unchanged --
    there is no alternate path that reaches C1 on a refusal.
    """
    subject = build_subject(terms=terms, harness=harness)
    return issue(subject=subject, signer=signer)
