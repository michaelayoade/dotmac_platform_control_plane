"""Required explicit D16 conformance against the pinned, real Foundation source.

No optional skip: direct invocation without D16_FOUNDATION_CHECKOUT is an error.
The synthetic dump/evidence exercise the adapter's wiring, not the future CP
producer's operational full-decompression proof.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import sys
import types
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from vendor_cp.deployment import d16_source_verifier as subject
from vendor_cp.deployment.d16_source_verifier import (
    FOUNDATION_COMMIT,
    D16SourceInputs,
    D16SourceRefusal,
    VerifiedDumpEvidence,
    verify_d16_transition,
)


@pytest.fixture(scope="module")
def checkout() -> Path:
    value = os.environ.get("D16_FOUNDATION_CHECKOUT")
    if not value:
        raise pytest.UsageError(
            "D16_FOUNDATION_CHECKOUT must name a clean Foundation checkout at "
            + FOUNDATION_COMMIT
        )
    path = Path(value)
    if not path.is_dir():
        raise pytest.UsageError("D16_FOUNDATION_CHECKOUT is not a directory")
    return path


@pytest.fixture(scope="module")
def real_foundation(checkout: Path) -> dict[str, Any]:
    package_src = checkout / "packages/dotmac-deployment-foundation/src"
    original_path = sys.path[:]
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.path.insert(0, str(package_src))
        sys.dont_write_bytecode = True
        return {
            name: importlib.import_module(f"dotmac_deployment_foundation.{name}")
            for name in ("recovery", "spec", "transition_receipt")
        }
    finally:
        sys.path[:] = original_path
        sys.dont_write_bytecode = original_bytecode


@pytest.fixture
def real_inputs(
    checkout: Path, real_foundation: dict[str, Any], tmp_path: Path
) -> D16SourceInputs:
    recovery = real_foundation["recovery"]
    spec_module = real_foundation["spec"]
    transition = real_foundation["transition_receipt"]
    descriptor_toml = (checkout / "deploy/product.toml").read_text(encoding="utf-8")
    spec = spec_module.ProductDeploymentSpec.loads(descriptor_toml)
    assert spec.product == "dotmac_starter_mt"
    assert spec.migration.expected_heads == ("a003",)

    dump_bytes = b"synthetic archive bytes: wiring proof only"
    dump = tmp_path / "database.dump"
    dump.write_bytes(dump_bytes)
    digest = hashlib.sha256(dump_bytes).hexdigest()
    component_digests = {
        component.value: "sha256:" + "a" * 64
        for component in recovery.REQUIRED_COMPONENTS
    }
    component_digests[recovery.BundleComponent.DATABASE_DUMP.value] = "sha256:" + digest
    manifest = recovery.build_manifest(
        product=spec.product,
        environment=spec.environment,
        postgres_major=16,
        source_revision="c" * 40,
        captured_at_epoch=1_800_000_000,
        evidence=recovery.CatalogEvidence(migration_heads=("a002",)),
        component_digests=component_digests,
    )
    manifest_path = tmp_path / "bundle-manifest.json"
    manifest_path.write_bytes(manifest.canonical_bytes())

    source = transition.TransitionSide(
        descriptor_sha256="sha256:" + "1" * 64,
        migration_heads=("a002",),
    )
    receipt = transition.TransitionReceiptV1(
        product=spec.product,
        environment=spec.environment,
        target="test-host",
        run_id="test-run-1",
        source=source,
        target_side=transition.TargetSide(
            descriptor_sha256=spec.to_canonical_document().sha256_digest(),
            migration_heads=tuple(spec.migration.expected_heads),
            image_digest=spec.image_digest,
            image_source_revision=spec.source_revision,
        ),
        backup=transition.TransitionBackup(
            bundle_digest=digest,
            checksum_algorithm="sha256",
            size_bytes=len(dump_bytes),
            bundle_id=str(dump),
            manifest_digest=manifest.sha256_digest(),
        ),
    )
    return D16SourceInputs(
        foundation_checkout=checkout,
        descriptor_toml=descriptor_toml,
        receipt_document=receipt.as_mapping(),
        previous_receipt_document=None,
        genesis_source_document=source.as_document(),
        manifest_path=manifest_path,
        dump_path=dump,
        verified_dump_evidence=VerifiedDumpEvidence(
            write_time_sha256="sha256:" + digest,
            size_bytes=len(dump_bytes),
            magic_verified=True,
            full_decompression_verified=True,
            completed_at_epoch=1_800_000_000,
            evidence_id="synthetic-conformance-only",
        ),
        dataset_code="primary",
        observed_target_heads=tuple(spec.migration.expected_heads),
        observed_image_digest=spec.image_digest,
        expected_run_id="test-run-1",
        expected_target="test-host",
    )


def test_real_foundation_accepts_consistent_transition(
    real_inputs: D16SourceInputs,
) -> None:
    result = verify_d16_transition(real_inputs)
    assert result.verified, (result.refusal, result.foundation_findings)
    assert result.refusal is None
    assert result.provenance is not None
    assert result.provenance.commit == FOUNDATION_COMMIT
    assert result.provenance.import_origins
    assert all(
        "dotmac_deployment_foundation" in Path(origin).parts
        and any(part.startswith("d16-foundation-") for part in Path(origin).parts)
        for _, origin in result.provenance.import_origins
    )


def test_real_foundation_refuses_mutated_observation(
    real_inputs: D16SourceInputs,
) -> None:
    result = verify_d16_transition(
        replace(real_inputs, observed_target_heads=("wrong_head",))
    )
    assert result.refusal is D16SourceRefusal.FOUNDATION_REFUSED
    assert "target_heads_declared_vs_observed" in result.foundation_findings


def test_real_foundation_refuses_mutated_dump(real_inputs: D16SourceInputs) -> None:
    real_inputs.dump_path.write_bytes(b"different bytes with the same length!!")
    result = verify_d16_transition(real_inputs)
    assert result.refusal is D16SourceRefusal.BACKUP_PROOF_MISMATCH


def test_real_foundation_refuses_mutated_manifest(real_inputs: D16SourceInputs) -> None:
    real_inputs.manifest_path.write_bytes(b"{}")
    result = verify_d16_transition(real_inputs)
    assert result.refusal is D16SourceRefusal.MANIFEST_INVALID


def test_forged_preloaded_module_with_checkout_origin_cannot_run(
    real_inputs: D16SourceInputs, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = types.ModuleType("dotmac_deployment_foundation.transition_receipt")
    fake.__file__ = str(
        real_inputs.foundation_checkout
        / "packages/dotmac-deployment-foundation/src"
        / "dotmac_deployment_foundation/transition_receipt.py"
    )
    fake.verify_transition_receipt = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("forged module executed")
    )
    monkeypatch.setitem(sys.modules, fake.__name__, fake)
    assert verify_d16_transition(real_inputs).verified


def test_checkout_swap_after_snapshot_does_not_execute(
    real_inputs: D16SourceInputs, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (
        real_inputs.foundation_checkout
        / "packages/dotmac-deployment-foundation/src"
        / "dotmac_deployment_foundation/transition_receipt.py"
    )
    original = source.read_bytes()
    materialize = subject._snapshot_source

    def swap_after_snapshot(checkout: Path, snapshot: Path) -> None:
        materialize(checkout, snapshot)
        source.write_text("raise RuntimeError('mutable checkout executed')\n")

    monkeypatch.setattr(subject, "_snapshot_source", swap_after_snapshot)
    try:
        assert verify_d16_transition(real_inputs).verified
    finally:
        source.write_bytes(original)


def test_required_ci_workflow_pins_the_same_source_commit() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    checkout_step = re.search(
        r"- name: Fetch exact Foundation transition verifier source\n"
        r"(?:[^\n]*\n){0,8}?\s+ref: (?P<ref>[0-9a-f]{40})\n",
        workflow,
    )
    assert checkout_step is not None
    assert checkout_step.group("ref") == FOUNDATION_COMMIT
    assert (
        "D16_FOUNDATION_CHECKOUT: ${{ github.workspace }}/.d16-foundation-source"
        in workflow
    )
    assert (
        "poetry run pytest -q conformance/test_d16_source_verifier_real_foundation.py"
        in workflow
    )


# ── P-CP1 5a: Foundation a2's REAL pin rewrite (build-once generic deploy) ──
#
# Appended here, not a new file, because the D16 source-verifier invocation is
# the one database-free conformance run (`conftest.py`) and already holds the
# pinned, immutable Foundation checkout. The unit golden copy of this function
# lives in `tests/unit/test_deploy_unit_effects.py`.

_PIN_APP_IMAGE = "127.0.0.1:5000/team/app@sha256:" + "1" * 64
_PIN_RENDER = f"APP_IMAGE={_PIN_APP_IMAGE}\nWORKERS=2\nZED=z\n".encode()


@pytest.fixture(scope="module")
def compose_host(checkout: Path) -> Any:
    package_src = checkout / "packages/dotmac-deployment-foundation/src"
    original_path = sys.path[:]
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.path.insert(0, str(package_src))
        sys.dont_write_bytecode = True
        return importlib.import_module(
            "dotmac_deployment_foundation.providers.compose_host"
        )
    finally:
        sys.path[:] = original_path
        sys.dont_write_bytecode = original_bytecode


def _effects_for(module: Any, env_file: Path) -> Any:
    # The property under test is one method, so build the instance without its
    # constructor and give it only the attribute that method reads.
    effects = module.ComposeHostEffects.__new__(module.ComposeHostEffects)
    effects._env_file = env_file
    return effects


def test_real_pin_rewrite_is_byte_identical_and_only_the_mode_changes(
    compose_host: Any, tmp_path: Path
) -> None:
    target = tmp_path / "params.env"
    target.write_bytes(_PIN_RENDER)
    target.chmod(0o400)
    _effects_for(compose_host, target)._write_env_value("APP_IMAGE", _PIN_APP_IMAGE)
    assert target.read_bytes() == _PIN_RENDER
    assert target.stat().st_mode & 0o777 == 0o600


def test_real_pin_rewrite_changes_a_different_pin(
    compose_host: Any, tmp_path: Path
) -> None:
    """SENSITIVITY: the rewrite does write, so byte-identity is not vacuous."""
    target = tmp_path / "params.env"
    target.write_bytes(_PIN_RENDER)
    other = "127.0.0.1:5000/team/app@sha256:" + "2" * 64
    _effects_for(compose_host, target)._write_env_value("APP_IMAGE", other)
    assert target.read_bytes() == _PIN_RENDER.replace(
        _PIN_APP_IMAGE.encode(), other.encode()
    )
