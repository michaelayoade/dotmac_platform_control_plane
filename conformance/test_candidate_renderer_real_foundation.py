"""Installed-artifact render conformance; synthetic profiles are NOT admission.

Invoke only in the hosted exact-Foundation wheel lane, with the conformance
PostgreSQL precondition retained. No source-path imports or optional skips.
"""

from __future__ import annotations

import dataclasses
import json
import sysconfig
import tomllib
from pathlib import Path

import pytest
from dotmac_deployment_foundation.application_profile import (
    ApplicationFoundationProfile,
    ConcernBinding,
    FoundationConcern,
    profile_digest,
)
from dotmac_deployment_foundation.document import build_canonical_document
from dotmac_deployment_foundation.engine.plan import build_plan
from dotmac_deployment_foundation.errors import SpecError
from dotmac_deployment_foundation.execution_plan import (
    HostPrestateV1,
    render_execution_plan,
)
from dotmac_deployment_foundation.spec import ProductDeploymentSpec

from vendor_cp.deployment.candidate import (
    CandidateImage,
    CandidateRefused,
    RegistryObservation,
    ReleaseReceiptV1,
    admit_candidate_image,
    render_candidate,
)

SYNTHETIC_DESCRIPTOR = Path(__file__).parent / "fixtures/renderer-component.toml"
PRODUCTION_DESCRIPTOR = Path(__file__).resolve().parents[1] / "deploy/product.toml"


@pytest.fixture
def image() -> CandidateImage:
    digest = "sha256:" + "c" * 64
    receipt = ReleaseReceiptV1.from_document(
        {
            "contract": "dotmac-candidate-release-receipt/1",
            "source_revision": "a" * 40,
            "registry_digest": digest,
            "reference": "registry.example/candidate@" + digest,
            "config_digest": "sha256:" + "d" * 64,
            "registry_config_digest": "sha256:" + "d" * 64,
            "rootfs_chain": "sha256:" + "e" * 64,
            "ci_run_id": "synthetic-ci",
            "release_run_id": "synthetic-release",
        }
    )
    return admit_candidate_image(
        receipt, RegistryObservation(digest, receipt.source_revision)
    )


def _profile_coordinate(version: str = "1.0.0") -> str:
    # A canonical V1 document is enough to exercise digest transport. These
    # synthetic declarations carry no observed contributions/admission receipt.
    binding = ConcernBinding(
        implementation="synthetic-render-conformance",
        version=version,
        coordinates="synthetic@sha256:" + "b" * 64,
    )
    profile = ApplicationFoundationProfile(
        application="render-conformance",
        slots=dict.fromkeys(FoundationConcern, binding),
    )
    return profile_digest(profile.as_document())


def test_synthetic_installed_renderer_preserves_exact_two_field_derivation(
    image: CandidateImage,
) -> None:
    for value in (HostPrestateV1, ProductDeploymentSpec, render_candidate):
        module = __import__(value.__module__, fromlist=[value.__name__])
        origin = Path(module.__file__).resolve()
        assert any(
            origin.is_relative_to(Path(sysconfig.get_path(kind)).resolve())
            for kind in ("purelib", "platlib")
        ), origin
    before = SYNTHETIC_DESCRIPTOR.read_bytes()
    synthetic_spec = ProductDeploymentSpec.load(str(SYNTHETIC_DESCRIPTOR))
    expected = dataclasses.replace(
        synthetic_spec, image=image.reference, source_revision=image.source_revision
    )
    for field in dataclasses.fields(synthetic_spec):
        if field.name not in {"image", "source_revision"}:
            assert getattr(expected, field.name) == getattr(synthetic_spec, field.name)
    document = build_canonical_document(expected)
    prestate = HostPrestateV1((("app", "sha256:" + "f" * 64),))
    coordinate = _profile_coordinate()
    rendered = render_candidate(
        str(SYNTHETIC_DESCRIPTOR),
        image,
        target="qualified-test-target",
        operation="deploy",
        prestate=prestate,
        application_profile_digest=coordinate,
    )
    independent = render_execution_plan(
        expected,
        build_plan(expected),
        target="qualified-test-target",
        operation="deploy",
        descriptor_digest=document.sha256_digest(),
        prestate=prestate,
        application_profile_digest=coordinate,
    )
    assert rendered.canonical_descriptor_bytes == document.canonical_bytes()
    assert rendered.descriptor_digest == document.sha256_digest()
    assert rendered.canonical_plan_bytes == independent.canonical_bytes()
    assert rendered.execution_plan_digest == independent.digest()
    assert rendered.prestate is prestate
    assert rendered.application_profile_digest == coordinate
    assert SYNTHETIC_DESCRIPTOR.read_bytes() == before
    plan = json.loads(rendered.canonical_plan_bytes)
    assert plan["image_reference"] == image.reference
    assert plan["source_revision"] == image.source_revision


@pytest.mark.parametrize("changed", ["prestate", "profile"])
def test_synthetic_frozen_coordinates_change_real_foundation_plan(
    image: CandidateImage,
    changed: str,
) -> None:
    prestate = HostPrestateV1((("app", "sha256:" + "f" * 64),))
    coordinate = _profile_coordinate()
    baseline = render_candidate(
        str(SYNTHETIC_DESCRIPTOR),
        image,
        target="qualified-test-target",
        operation="deploy",
        prestate=prestate,
        application_profile_digest=coordinate,
    )
    altered = render_candidate(
        str(SYNTHETIC_DESCRIPTOR),
        image,
        target="qualified-test-target",
        operation="deploy",
        prestate=(
            HostPrestateV1((("app", "sha256:" + "0" * 64),))
            if changed == "prestate"
            else prestate
        ),
        application_profile_digest=(
            _profile_coordinate("2.0.0") if changed == "profile" else coordinate
        ),
    )
    assert altered.descriptor_digest == baseline.descriptor_digest
    assert altered.canonical_descriptor_bytes == baseline.canonical_descriptor_bytes
    assert altered.execution_plan_digest != baseline.execution_plan_digest
    assert altered.canonical_plan_bytes != baseline.canonical_plan_bytes


def test_dictionary_prestate_cannot_substitute_for_foundation_value(
    image: CandidateImage,
) -> None:
    with pytest.raises(CandidateRefused, match="candidate_prestate_unavailable"):
        render_candidate(
            str(SYNTHETIC_DESCRIPTOR),
            image,
            target="qualified-test-target",
            operation="deploy",
            prestate={"roles": []},  # type: ignore[arg-type]
            application_profile_digest=_profile_coordinate(),
        )


def test_actual_production_descriptor_row_counts_without_executor_is_refused() -> None:
    """The real production promise remains unsupported by this exact owner.

    This is required refusal evidence, not positive production compatibility.
    No parser input is stripped, rewritten or replaced by the synthetic fixture.
    """
    before = PRODUCTION_DESCRIPTOR.read_bytes()
    declared = tomllib.loads(before.decode("utf-8"))
    dataset = declared["backup"]["datasets"][0]
    assert "row_counts" in dataset["verify"]
    assert "external_executor" not in dataset
    try:
        with pytest.raises(SpecError) as refused:
            ProductDeploymentSpec.load(str(PRODUCTION_DESCRIPTOR))
        assert refused.value.code == "backup.verification.unperformable"
        assert refused.value.where == "backup.datasets[0]"
    finally:
        assert PRODUCTION_DESCRIPTOR.read_bytes() == before
