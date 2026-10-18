"""`rehearsal_issuer_adapter`'s harness-attestation witness and A6.4-provenance
guard, proved against fakes -- this module is a LEAF and never imports
Control or C1 real types (see its own docstring and
`tests/architecture/test_rehearsal_issuer_adapter_import_boundary.py`).
"""

from __future__ import annotations

import pytest

from vendor_cp.deployment.rehearsal_issuer_adapter import (
    _ATTESTED,  # noqa: PLC2701 - white-box test of the witness device itself
    REHEARSAL_ENVIRONMENT,
    HarnessBinding,
    HarnessSource,
    RehearsalIssuerRefusal,
    RehearsalIssuerRefused,
    RehearsalIssuerTerms,
    _HarnessWitness,  # noqa: PLC2701
    admit_harness_binding,
    issue_authorization_for_rehearsal_issuer,
)

_FULL_PROVENANCE = {
    "target": "derived",
    "desired_state": "derived",
    "profile": "override",
    "authorized_images": "derived",
    "execution_plan": "override",
}
_DECLARED_OVERRIDES = frozenset({"profile", "execution_plan"})


def _terms(**overrides: object) -> RehearsalIssuerTerms:
    kwargs: dict[str, object] = {
        "immutable_reference": "authorization-ref",
        "target_id": "target-id",
        "target_ref": "target-ref",
        "desired_state_digest": "desired-state-digest",
        "profile_digest": "profile-digest",
        "authorized_image_digests": ("image-digest",),
        "execution_plan_digest": "execution-plan-digest",
        "environment": REHEARSAL_ENVIRONMENT,
        "provenance": dict(_FULL_PROVENANCE),
        "declared_overrides": _DECLARED_OVERRIDES,
    }
    kwargs.update(overrides)
    return RehearsalIssuerTerms(**kwargs)  # type: ignore[arg-type]


def _attestation(**overrides: object) -> dict[str, object]:
    attestation: dict[str, object] = {
        "source": HarnessSource.DISPOSABLE_REHEARSAL_HARNESS.value,
        "controller_fingerprint": "controller-1",
        "lease_id": "lease-1",
    }
    attestation.update(overrides)
    return attestation


# ── the harness-attestation witness ──────────────────────────────────────────


def test_a_hand_built_harness_binding_is_refused() -> None:
    """The witness device itself: only `admit_harness_binding` holds `_ATTESTED`,
    so a caller constructing `HarnessBinding` directly cannot produce one."""
    with pytest.raises(RehearsalIssuerRefused) as refused:
        HarnessBinding(
            _HarnessWitness(),
            HarnessSource.DISPOSABLE_REHEARSAL_HARNESS,
            "controller-1",
            "lease-1",
        )
    assert refused.value.refusal is RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS


def test_admit_harness_binding_accepts_the_real_witness() -> None:
    """SENSITIVITY, the other direction: the real witness must be accepted, or
    the rule above would refuse the ceremony it is part of."""
    binding = HarnessBinding(
        _ATTESTED,
        HarnessSource.DISPOSABLE_REHEARSAL_HARNESS,
        "controller-1",
        "lease-1",
    )
    assert binding.controller_fingerprint == "controller-1"


def test_admit_harness_binding_refuses_a_non_harness_source() -> None:
    with pytest.raises(RehearsalIssuerRefused) as refused:
        admit_harness_binding(_attestation(source="the-application-under-rehearsal"))
    assert refused.value.refusal is RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS


def test_admit_harness_binding_refuses_a_missing_controller_fingerprint() -> None:
    with pytest.raises(RehearsalIssuerRefused) as refused:
        admit_harness_binding(_attestation(controller_fingerprint=""))
    assert refused.value.refusal is RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS


def test_admit_harness_binding_refuses_a_missing_lease_id() -> None:
    with pytest.raises(RehearsalIssuerRefused) as refused:
        admit_harness_binding(_attestation(lease_id=None))
    assert refused.value.refusal is RehearsalIssuerRefusal.SUBJECT_NOT_FROM_HARNESS


def test_admit_harness_binding_succeeds_for_the_disposable_harness() -> None:
    binding = admit_harness_binding(_attestation())
    assert binding.source is HarnessSource.DISPOSABLE_REHEARSAL_HARNESS
    assert binding.controller_fingerprint == "controller-1"
    assert binding.lease_id == "lease-1"


# ── RehearsalIssuerTerms' own guard ──────────────────────────────────────────


def test_terms_refuses_a_non_rehearsal_environment() -> None:
    with pytest.raises(RehearsalIssuerRefused) as refused:
        _terms(environment="production")
    assert refused.value.refusal is RehearsalIssuerRefusal.ENVIRONMENT_NOT_REHEARSAL


def test_terms_accepts_the_rehearsal_environment() -> None:
    """SENSITIVITY, the other direction: the one value that must be accepted."""
    terms = _terms()
    assert terms.environment == REHEARSAL_ENVIRONMENT


@pytest.mark.parametrize(
    "missing",
    ["target", "desired_state", "profile", "authorized_images", "execution_plan"],
)
def test_terms_refuses_a_missing_provenance_entry(missing: str) -> None:
    """Each of the five A6.4 values independently: removing any one of them
    from `provenance` must refuse, naming PROVENANCE_ABSENT."""
    provenance = dict(_FULL_PROVENANCE)
    del provenance[missing]
    with pytest.raises(RehearsalIssuerRefused) as refused:
        _terms(provenance=provenance)
    assert refused.value.refusal is RehearsalIssuerRefusal.PROVENANCE_ABSENT


def test_terms_refuses_an_undeclared_override() -> None:
    """`execution_plan`'s provenance is `"override"` but is not declared."""
    with pytest.raises(RehearsalIssuerRefused) as refused:
        _terms(declared_overrides=frozenset({"profile"}))
    assert refused.value.refusal is RehearsalIssuerRefusal.OVERRIDE_UNDECLARED


def test_terms_accepts_a_fully_declared_override_set() -> None:
    """SENSITIVITY, the other direction: declaring both overrides must pass."""
    terms = _terms()
    assert terms.declared_overrides == _DECLARED_OVERRIDES


# ── the orchestration entry point ───────────────────────────────────────────


def test_issue_authorization_hands_the_built_subject_and_signer_to_issue() -> None:
    """A subject IS produced from `terms`/`harness`, and `issue` receives
    exactly that subject alongside the caller's own `signer` -- nothing
    substituted in between."""
    terms = _terms()
    binding = admit_harness_binding(_attestation())

    built_calls: list[dict[str, object]] = []

    def _build_subject(*, terms: object, harness: object) -> object:
        subject = object()
        built_calls.append({"subject": subject, "terms": terms, "harness": harness})
        return subject

    issue_calls: list[dict[str, object]] = []

    def _issue(*, subject: object, signer: object) -> object:
        issue_calls.append({"subject": subject, "signer": signer})
        return "the-authorization"

    signer = object()
    result = issue_authorization_for_rehearsal_issuer(
        terms=terms,
        harness=binding,
        build_subject=_build_subject,
        issue=_issue,
        signer=signer,
    )

    assert result == "the-authorization"
    assert len(built_calls) == 1
    assert built_calls[0]["terms"] is terms
    assert built_calls[0]["harness"] is binding
    assert issue_calls == [{"subject": built_calls[0]["subject"], "signer": signer}]


def test_issue_authorization_propagates_a_refusal_from_issue_with_no_fallback() -> None:
    """No fallback: if `issue` raises, the exception propagates unchanged."""
    terms = _terms()
    binding = admit_harness_binding(_attestation())

    class _SentinelRefusal(Exception):
        pass

    def _build_subject(*, terms: object, harness: object) -> object:
        return object()

    def _raising_issue(*, subject: object, signer: object) -> object:
        raise _SentinelRefusal("refused")

    with pytest.raises(_SentinelRefusal):
        issue_authorization_for_rehearsal_issuer(
            terms=terms,
            harness=binding,
            build_subject=_build_subject,
            issue=_raising_issue,
            signer=object(),
        )
