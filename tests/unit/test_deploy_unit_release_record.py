"""Release record: `deploy_unit` attestation, CP holding, and Control's source port.

Ruling 2026-11-22: the record is the catalogue's container-image artifact plus a
`deploy_unit` attestation over the exact descriptor bytes; CP holds the bytes
and Control reads them through `ReleaseDescriptorSource`, recomputing the digest
itself. Documentation-range values only; the digests are of fixture bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import nullcontext
from pathlib import Path

import pytest
from dotmac_deployment_control import (
    ReleaseDescriptorUnavailableError,
)
from dotmac_deployment_control.release_descriptor import verify_release_descriptor
from dotmac_kernel import PlatformAuditEvent
from dotmac_kernel.testing import create_test_engine, isolated_session
from dotmac_release_catalog import (
    ArtifactAttestation,
    AttestationKind,
    ReleaseArtifact,
)
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from vendor_cp.deployment.release_descriptor_source import (
    CatalogueReleaseDescriptorSource,
    parse_release_ref,
)
from vendor_cp.release_evidence.deploy_unit import (
    AUDIT_ACTION,
    COMPANION_DESCRIPTOR_PATH,
    PRIMARY_DESCRIPTOR_PATH,
    DeployUnitEvidenceCommand,
    DirectoryDeployUnitStore,
    HeldDocuments,
    record_deploy_unit_evidence,
    verify_held_documents,
)
from vendor_cp.release_evidence.service import (
    ReleaseEvidenceConflict,
    ReleaseEvidenceError,
)

_PRODUCT = "dotmac-integrator"
_VERSION = "0.4.2"
_IMAGE_DIGEST = f"sha256:{'b' * 64}"
_REPOSITORY = "registry.example.test/team/integrator"
_ARTIFACT_REF = f"{_REPOSITORY}@{_IMAGE_DIGEST}"
_REVISION = "c" * 40
_COMPANION = (
    b'schema = "dotmac.deploy_unit/1"\n'
    b'product = "dotmac-integrator-companion"\n'
    b'spec = "deploy/companion/product.toml"\n'
    b'secrets_namespace = "erp-integrator"\n'
)
_PRIMARY = (
    b'schema = "dotmac.deploy_unit/1"\n'
    b'product = "erp_v2"\n'
    b'spec = "deploy/product.toml"\n'
    b'secrets_namespace = "erp"\n'
)


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_test_engine()
    try:
        yield engine
    finally:
        engine.dispose()


def _command(
    payload: bytes = _COMPANION,
    *,
    command_id: str = "integrator-build-1",
    path: str = COMPANION_DESCRIPTOR_PATH,
    **overrides: object,
) -> DeployUnitEvidenceCommand:
    values: dict[str, object] = {
        "command_id": command_id,
        "product_code": _PRODUCT,
        "product_version": _VERSION,
        "artifact_digest": _IMAGE_DIGEST,
        "artifact_ref": _ARTIFACT_REF,
        "source_revision": _REVISION,
        "descriptor_path": path,
        "deploy_unit_digest": _digest(payload),
        "deploy_unit": payload,
        "actor_admin_id": None,
        "operator_ref": "github-actions:1",
    }
    values.update(overrides)
    return DeployUnitEvidenceCommand(**values)  # type: ignore[arg-type]


def test_record_holds_bytes_and_attests_one_audited_deploy_unit(
    engine: Engine, tmp_path: Path
) -> None:
    command = _command()
    with isolated_session(engine) as db:
        result = record_deploy_unit_evidence(
            db, command, held=HeldDocuments.under(tmp_path)
        )
        artifact = db.get(ReleaseArtifact, result.artifact_id)
        attestation = db.get(ArtifactAttestation, result.attestation_id)
        events = list(db.scalars(select(PlatformAuditEvent)))
    assert not result.replayed
    assert artifact is not None and attestation is not None
    assert (artifact.product_code, artifact.version) == (_PRODUCT, _VERSION)
    assert artifact.artifact_ref == _ARTIFACT_REF
    assert artifact.source_revision == _REVISION
    assert attestation.attestation_kind == AttestationKind.DEPLOY_UNIT.value
    assert attestation.digest == command.deploy_unit_digest
    assert attestation.uri == result.deploy_unit_uri
    assert attestation.uri.endswith("#" + COMPANION_DESCRIPTOR_PATH)
    held = attestation.uri.split("#", 1)[0].removeprefix("file://")
    assert Path(held).read_bytes() == _COMPANION
    assert [e.action for e in events] == [AUDIT_ACTION]
    assert events[0].details["deploy_unit_digest"] == command.deploy_unit_digest


def test_record_needs_no_kernel_product_manifest(
    engine: Engine, tmp_path: Path
) -> None:
    """ERP v2 and Integrator emit none: no PRODUCT_MANIFEST row is implied."""
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=HeldDocuments.under(tmp_path))
        kinds = list(db.scalars(select(ArtifactAttestation.attestation_kind)))
    assert kinds == [AttestationKind.DEPLOY_UNIT.value]


def test_semantic_replay_does_not_reaudit_and_every_delivery_is_recorded(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        first = record_deploy_unit_evidence(db, _command(), held=store)
        same = record_deploy_unit_evidence(db, _command(), held=store)
        other = record_deploy_unit_evidence(
            db, _command(command_id="integrator-build-2"), held=store
        )
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 1
        assert db.scalar(select(func.count()).select_from(ArtifactAttestation)) == 1
        assert db.scalar(select(func.count()).select_from(PlatformAuditEvent)) == 1
    assert not first.replayed and same.replayed and other.replayed
    assert first.attestation_id == same.attestation_id == other.attestation_id


def test_a_different_descriptor_on_the_same_artifact_is_a_conflict(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    changed = _COMPANION + b"# changed\n"
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=store)
        with pytest.raises(ReleaseEvidenceConflict):
            record_deploy_unit_evidence(
                db,
                _command(changed, command_id="integrator-build-2"),
                held=store,
            )


def test_a_different_image_for_the_same_release_is_a_conflict(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    other_digest = f"sha256:{'d' * 64}"
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=store)
        with pytest.raises(ReleaseEvidenceConflict):
            record_deploy_unit_evidence(
                db,
                _command(
                    command_id="integrator-build-2",
                    artifact_digest=other_digest,
                    artifact_ref=f"{_REPOSITORY}@{other_digest}",
                ),
                held=store,
            )


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"deploy_unit_digest": _digest(b"other")}, id="digest-mismatch"),
        pytest.param({"deploy_unit_digest": "sha256:xyz"}, id="digest-malformed"),
        pytest.param(
            {"deploy_unit": b"not = [toml", "deploy_unit_digest": None}, id="not-toml"
        ),
        pytest.param({"deploy_unit": b"", "deploy_unit_digest": None}, id="empty"),
        pytest.param(
            {"deploy_unit": b"\xff\xfe", "deploy_unit_digest": None}, id="binary"
        ),
        pytest.param(
            {"deploy_unit": b'schema = "other/1"\n', "deploy_unit_digest": None},
            id="wrong-schema",
        ),
        pytest.param(
            {"deploy_unit": b"#" * 262_145, "deploy_unit_digest": None}, id="oversize"
        ),
    ],
)
def test_malformed_descriptor_evidence_is_refused_before_anything_is_written(
    engine: Engine, tmp_path: Path, overrides: dict[str, object]
) -> None:
    if overrides.get("deploy_unit_digest", "") is None:
        overrides["deploy_unit_digest"] = _digest(overrides["deploy_unit"])  # type: ignore[arg-type]
    with isolated_session(engine) as db:
        with pytest.raises(ReleaseEvidenceError):
            record_deploy_unit_evidence(
                db,
                _command(**overrides),
                held=HeldDocuments.under(tmp_path),
            )
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 0
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "overrides",
    [
        {"path": "deploy/other.toml"},
        {"path": "../deploy/deploy-unit.toml"},
        {"source_revision": "abc"},
        {"source_revision": "C" * 40},
        {"operator_ref": " padded"},
        {"operator_ref": ""},
    ],
)
def test_command_refuses_a_bad_path_revision_or_operator(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ReleaseEvidenceError):
        _command(**overrides)


def test_store_refuses_to_serve_or_keep_bytes_that_do_not_match(
    tmp_path: Path,
) -> None:
    store = DirectoryDeployUnitStore(tmp_path / "held")
    with pytest.raises(ReleaseEvidenceError):
        store.hold(b"x", digest=_digest(b"y"))
    store.hold(_COMPANION, digest=_digest(_COMPANION))
    target = next((tmp_path / "held").iterdir())
    target.chmod(0o600)
    target.write_bytes(b"tampered")
    with pytest.raises(ReleaseEvidenceError):
        store.read(digest=_digest(_COMPANION))
    with pytest.raises(ReleaseEvidenceError):
        store.hold(_COMPANION, digest=_digest(_COMPANION))


def test_held_store_is_private_and_write_once(tmp_path: Path) -> None:
    root = tmp_path / "held" / "deploy-units"
    store = DirectoryDeployUnitStore(root)
    uri = store.hold(_COMPANION, digest=_digest(_COMPANION))
    assert root.stat().st_mode & 0o777 == 0o700
    held = Path(uri.removeprefix("file://"))
    assert held.stat().st_mode & 0o777 == 0o600
    # An identical re-hold is a replay; the address is never rewritten.
    assert store.hold(_COMPANION, digest=_digest(_COMPANION)) == uri
    assert held.read_bytes() == _COMPANION


def test_the_held_documents_default_is_durable_and_never_under_run() -> None:
    from vendor_cp.config import VendorSettings

    default = VendorSettings(provider_mode="fake").held_documents_directory
    assert str(default).startswith("/var/lib/dotmac/vendor-control-plane/")
    assert not str(default).startswith(("/run", "/tmp", "/dev/shm"))  # noqa: S108


# ── the ReleaseDescriptorSource adapter, and Control's own verification ──────


def _source(db: Session, store: HeldDocuments) -> CatalogueReleaseDescriptorSource:
    return CatalogueReleaseDescriptorSource(
        session_scope=lambda: nullcontext(db), store=lambda: store
    )


def test_source_returns_evidence_that_controls_own_verification_accepts(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=store)
        verified = verify_release_descriptor(
            _source(db, store),
            release_ref=f"{_PRODUCT}@{_VERSION}",
            product_code="dotmac-integrator-companion",
            descriptor_path=COMPANION_DESCRIPTOR_PATH,
            legacy_allowed=False,
        )
    evidence = verified.evidence
    assert evidence.image_repository == _REPOSITORY
    assert evidence.image_digest == _IMAGE_DIGEST
    assert evidence.source_revision == _REVISION
    assert evidence.deploy_unit_bytes == _COMPANION
    assert verified.digest == evidence.attested_digest == _digest(_COMPANION)


_SPEC = b'product = "erp_v2"\n'
_HAS_SPEC_KIND = any(k.value == "product_spec" for k in AttestationKind)
needs_spec_kind = pytest.mark.skipif(
    not _HAS_SPEC_KIND,
    reason="PRODUCT_SPEC is not in the PROVISIONAL catalogue pin yet (#1145)",
)


def _primary(**overrides: object) -> DeployUnitEvidenceCommand:
    values: dict[str, object] = {
        "product_code": "erp_v2",
        "product_version": "2.1.0",
        "artifact_ref": f"{_REPOSITORY}@{_IMAGE_DIGEST}",
        "product_spec": _SPEC,
        "product_spec_digest": _digest(_SPEC),
    }
    values.update(overrides)
    return _command(_PRIMARY, path=PRIMARY_DESCRIPTOR_PATH, **values)


def test_a_primary_release_cannot_be_recorded_without_its_product_toml(
    engine: Engine, tmp_path: Path
) -> None:
    with isolated_session(engine) as db:
        with pytest.raises(ReleaseEvidenceError):
            record_deploy_unit_evidence(
                db,
                _primary(product_spec=None, product_spec_digest=None),
                held=HeldDocuments.under(tmp_path),
            )
        assert db.scalar(select(func.count()).select_from(ReleaseArtifact)) == 0


def test_the_product_toml_and_digest_come_together_and_must_match(
    engine: Engine, tmp_path: Path
) -> None:
    held = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        for bad in (
            {"product_spec_digest": None},
            {"product_spec": None},
            {"product_spec_digest": _digest(b"other")},
            {
                "product_spec": b"not = [toml",
                "product_spec_digest": _digest(b"not = [toml"),
            },
        ):
            with pytest.raises(ReleaseEvidenceError):
                record_deploy_unit_evidence(db, _primary(**bad), held=held)


@needs_spec_kind
def test_a_primary_records_both_documents_in_one_transaction_and_resolves(
    engine: Engine, tmp_path: Path
) -> None:
    held = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        result = record_deploy_unit_evidence(db, _primary(), held=held)
        assert result.product_spec_attestation_id is not None
        assert result.product_spec_uri is not None
        assert result.product_spec_uri.endswith("#deploy/product.toml")
        kinds = sorted(db.scalars(select(ArtifactAttestation.attestation_kind)))
        assert kinds == ["deploy_unit", "product_spec"]
        verified = verify_release_descriptor(
            _source(db, held),
            release_ref="erp_v2@2.1.0",
            product_code="erp_v2",
            descriptor_path=PRIMARY_DESCRIPTOR_PATH,
            legacy_allowed=False,
        )
        assert verified.product_toml_sha256 == _digest(_SPEC)
        assert verified.evidence.product_toml_path == "deploy/product.toml"
        assert verify_held_documents(db, held) == ()


@needs_spec_kind
def test_a_primary_resolves_only_from_the_artifact_of_its_own_product(
    engine: Engine, tmp_path: Path
) -> None:
    held = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(
            db, _primary(product_code="some-other-product"), held=held
        )
        with pytest.raises(ReleaseDescriptorUnavailableError, match="own"):
            _source(db, held).resolve(
                "some-other-product@2.1.0",
                product_code="erp_v2",
                descriptor_path=PRIMARY_DESCRIPTOR_PATH,
            )


@needs_spec_kind
def test_a_primary_with_no_product_spec_attestation_is_refused(
    engine: Engine, tmp_path: Path
) -> None:
    from dotmac_release_catalog import (
        ArtifactKind,
        Digest,
        attest_artifact,
        publish_artifact,
    )

    held = HeldDocuments.under(tmp_path)
    uri = held.deploy_units.hold(_PRIMARY, digest=_digest(_PRIMARY))
    with isolated_session(engine) as db:
        artifact = publish_artifact(
            db,
            product_code="erp_v2",
            version="2.1.0",
            artifact_kind=ArtifactKind.CONTAINER_IMAGE,
            digest=Digest.parse(_IMAGE_DIGEST),
            artifact_ref=_ARTIFACT_REF,
            source_revision=_REVISION,
        )
        attest_artifact(
            db,
            artifact_id=artifact.id,
            attestation_kind=AttestationKind.DEPLOY_UNIT,
            uri=f"{uri}#{PRIMARY_DESCRIPTOR_PATH}",
            digest=_digest(_PRIMARY),
        )
        with pytest.raises(ReleaseDescriptorUnavailableError, match="product_spec"):
            _source(db, held).resolve(
                "erp_v2@2.1.0",
                product_code="erp_v2",
                descriptor_path=PRIMARY_DESCRIPTOR_PATH,
            )


@needs_spec_kind
def test_two_product_spec_attestations_for_one_path_are_ambiguous(
    engine: Engine, tmp_path: Path
) -> None:
    from dotmac_release_catalog import attest_artifact

    held = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        result = record_deploy_unit_evidence(db, _primary(), held=held)
        attest_artifact(
            db,
            artifact_id=result.artifact_id,
            attestation_kind=AttestationKind("product_spec"),
            uri="file:///elsewhere#deploy/product.toml",
            digest=_digest(b"second"),
        )
        with pytest.raises(ReleaseDescriptorUnavailableError, match="ambiguous"):
            _source(db, held).resolve(
                "erp_v2@2.1.0",
                product_code="erp_v2",
                descriptor_path=PRIMARY_DESCRIPTOR_PATH,
            )


def test_restore_read_back_names_every_attestation_whose_bytes_are_missing(
    engine: Engine, tmp_path: Path
) -> None:
    held = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=held)
        assert verify_held_documents(db, held) == ()
        next((tmp_path / "deploy-units").iterdir()).unlink()
        problems = verify_held_documents(db, held)
    assert len(problems) == 1 and "missing or do not match" in problems[0]
    assert str(tmp_path) not in problems[0]  # value-free


def test_source_refuses_when_the_held_bytes_are_gone_or_changed(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=store)
        held = next((tmp_path / "deploy-units").iterdir())
        held.chmod(0o600)
        held.write_bytes(_COMPANION + b"#x\n")
        with pytest.raises(ReleaseDescriptorUnavailableError):
            _source(db, store).resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="dotmac-integrator-companion",
                descriptor_path=COMPANION_DESCRIPTOR_PATH,
            )
        held.unlink()
        with pytest.raises(ReleaseDescriptorUnavailableError):
            _source(db, store).resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="dotmac-integrator-companion",
                descriptor_path=COMPANION_DESCRIPTOR_PATH,
            )


def test_source_refuses_a_descriptor_attested_for_another_path(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        record_deploy_unit_evidence(db, _command(), held=store)
        with pytest.raises(ReleaseDescriptorUnavailableError):
            _source(db, store).resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="erp_v2",
                descriptor_path=PRIMARY_DESCRIPTOR_PATH,
            )


def test_source_refuses_an_unknown_release_a_missing_attestation_and_bad_refs(
    engine: Engine, tmp_path: Path
) -> None:
    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        source = _source(db, store)
        for ref in ("nope@1.0.0", f"{_PRODUCT}", "UPPER@1", f"{_PRODUCT}@", "a@b@c"):
            with pytest.raises(ReleaseDescriptorUnavailableError):
                source.resolve(
                    ref,
                    product_code="x",
                    descriptor_path=COMPANION_DESCRIPTOR_PATH,
                )
        with pytest.raises(ReleaseDescriptorUnavailableError):
            source.resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="x",
                descriptor_path="deploy/elsewhere.toml",
            )
    assert parse_release_ref(f"{_PRODUCT}@{_VERSION}") == (_PRODUCT, _VERSION)


def test_source_refuses_an_artifact_with_no_deploy_unit_attestation(
    engine: Engine, tmp_path: Path
) -> None:
    from dotmac_release_catalog import ArtifactKind, Digest, publish_artifact

    with isolated_session(engine) as db:
        publish_artifact(
            db,
            product_code=_PRODUCT,
            version=_VERSION,
            artifact_kind=ArtifactKind.CONTAINER_IMAGE,
            digest=Digest.parse(_IMAGE_DIGEST),
            artifact_ref=_ARTIFACT_REF,
            source_revision=_REVISION,
        )
        with pytest.raises(ReleaseDescriptorUnavailableError):
            _source(db, HeldDocuments.under(tmp_path)).resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="x",
                descriptor_path=COMPANION_DESCRIPTOR_PATH,
            )


def test_source_refuses_two_deploy_unit_attestations_as_ambiguous(
    engine: Engine, tmp_path: Path
) -> None:
    from dotmac_release_catalog import attest_artifact

    store = HeldDocuments.under(tmp_path)
    with isolated_session(engine) as db:
        result = record_deploy_unit_evidence(db, _command(), held=store)
        attest_artifact(
            db,
            artifact_id=result.artifact_id,
            attestation_kind=AttestationKind.DEPLOY_UNIT,
            uri="file:///elsewhere#" + COMPANION_DESCRIPTOR_PATH,
            digest=_digest(b"second"),
        )
        with pytest.raises(ReleaseDescriptorUnavailableError, match="ambiguous"):
            _source(db, store).resolve(
                f"{_PRODUCT}@{_VERSION}",
                product_code="x",
                descriptor_path=COMPANION_DESCRIPTOR_PATH,
            )


def test_the_adapter_is_read_only_and_control_never_imports_the_catalogue() -> None:
    import re

    import dotmac_deployment_control

    from vendor_cp.deployment import release_descriptor_source

    adapter = Path(release_descriptor_source.__file__).read_text()
    for forbidden in ("attest_artifact", "publish_artifact", "db.add", "urlopen"):
        assert forbidden not in adapter
    # SENSITIVITY: the pattern below does match a real import statement.
    pattern = re.compile(r"^\s*(import|from)\s+dotmac_release_catalog", re.MULTILINE)
    assert pattern.search("from dotmac_release_catalog import x")
    control_root = Path(dotmac_deployment_control.__file__).parent
    assert [
        p.name for p in control_root.rglob("*.py") if pattern.search(p.read_text())
    ] == []
