"""Inert composition fixtures; no new campaign, native crypto or acceptance.

The archive test seam returns explicit fixture ciphertext. It tests byte joins,
not GPG qualification; production exposes no injected callback or DTO shortcut.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_preparation as prep
from vendor_cp.deployment.gate0_e_archive import (
    ARCHIVE_NAMES,
    ArchiveRefused,
    EncryptedArchive,
    GpgArchiveProfile,
)
from vendor_cp.deployment.gate0_e_finalization import RetainedEvidenceRefused
from vendor_cp.deployment.gate0_framing import canonical, strict_object


@pytest.fixture
def inputs(complete_retained_collection):  # noqa: F811
    raw, selected = complete_retained_collection
    claims = selected.cases[0].window.document["github"]
    selected = replace(
        selected,
        source=replace(selected.source, workflow_revision=claims["workflow_sha"]),
    )
    producer = prep.EProducerCoordinates(
        int(claims["repository_id"]),
        int(claims["repository_owner_id"]),
        19,
        int(claims["run_id"]),
        1,
        20,
        claims["workflow_sha"],
    )
    profile = GpgArchiveProfile(
        Path("/usr/bin/gpg"),
        "0" * 64,
        "gpg (GnuPG) 2.4.7",
        b"private-test-profile",
        "0" * 64,
        "A" * 40,
        "A" * 40,
    )
    return {
        "raw_collection": raw,
        "selection": selected,
        "producer": producer,
        "source_bundle_digest": "sha256:" + "9" * 64,
        "prerequisite_bytes": b"opaque-owner-evidence\x00\xffPRIVATE-PREREQUISITE",
        "profile": profile,
        "deadline": time.monotonic() + 180,
    }


@pytest.fixture
def archive_seam(monkeypatch):
    """Declared composition seam, never a synthetic cryptographic success claim."""
    calls = []

    def package(manifest, files, profile, *, deadline):
        calls.append((manifest, dict(files), profile, deadline))
        return EncryptedArchive(
            b"fixture-ciphertext",
            prep._sha(b"fixture-ciphertext"),
            "1" * 64,
            prep._sha(manifest),
        )

    monkeypatch.setattr(prep, "package_private_collection", package)
    return calls


def test_exact_verify_payload_manifest_and_projection_chain(
    inputs, archive_seam, monkeypatch
):
    calls = []
    actual_verify = prep.verify_retained_collection

    def verify(raw, selection):
        result = actual_verify(raw, selection)
        calls.append((raw, selection, result))
        return result

    monkeypatch.setattr(prep, "verify_retained_collection", verify)
    result = prep.prepare_encrypted_e(**inputs)
    assert len(calls) == len(archive_seam) == 1
    raw, selection, verified = calls[0]
    assert raw is inputs["raw_collection"] and selection is inputs["selection"]
    manifest, files, profile, deadline = archive_seam[0]
    assert profile is inputs["profile"] and deadline == inputs["deadline"]
    assert set(files) == set(ARCHIVE_NAMES)
    assert files["collection.json"] is verified.collection_bytes
    assert files["collection.json"] == inputs["raw_collection"]
    assert files["prerequisites.json"] is inputs["prerequisite_bytes"]
    manifest_doc = strict_object(manifest)
    assert manifest == canonical(manifest_doc)
    assert manifest_doc == {
        "schema": "Gate0EArchiveManifest.v1",
        "files": {
            name: {"length": len(value), "sha256": prep._sha(value)}
            for name, value in files.items()
        },
    }
    producer_doc = strict_object(files["producer.json"])
    assert producer_doc == {
        "schema": "Gate0EProducerSelection.v1",
        "producer": inputs["producer"].document(),
        "source_bundle_digest": inputs["source_bundle_digest"],
    }
    receipt = strict_object(files["receipt.json"])
    assert receipt == {
        "schema": "Gate0ERetainedCollectionReceipt.v1",
        "policy_digest": verified.policy_digest,
        "collection_digest": verified.collection_digest,
        "bundle_digests": list(verified.bundle_digests),
        "root_record_digests": list(verified.root_record_digests),
        "join_digests": list(verified.join_digests),
        "result": "retained_bytes_verified",
    }
    assert files["producer.json"] == canonical(producer_doc)
    assert files["receipt.json"] == canonical(receipt)
    public = prep.validate_encrypted_e_projection(result.projection)
    assert result.projection == canonical(public)
    assert public == {
        "schema": "Gate0EncryptedEvidenceProjection.v1",
        "policy_digest": selection.policy_digest,
        "campaign_digest": selection.campaign_digest,
        "source_bundle_digest": inputs["source_bundle_digest"],
        "collection_digest": verified.collection_digest,
        "plaintext_archive_digest": "sha256:" + "1" * 64,
        "inner_manifest_digest": "sha256:" + prep._sha(manifest),
        "ciphertext_digest": "sha256:" + prep._sha(result.ciphertext),
        "ciphertext_bytes": len(result.ciphertext),
        "producer": inputs["producer"].document(),
        "result": "encrypted_evidence",
    }
    assert public["source_bundle_digest"] != selection.source.module_bundle_digest
    assert public["producer"]["source_revision"] == selection.source.workflow_revision
    assert all(
        value.startswith("sha256:") and len(value) == 71
        for key, value in public.items()
        if key.endswith("_digest")
    )
    for secret in (
        inputs["raw_collection"],
        inputs["prerequisite_bytes"],
        inputs["profile"].public_key,
        files["receipt.json"],
    ):
        assert secret not in result.projection and secret.decode(
            "utf-8", errors="ignore"
        ) not in repr(result)
    assert "readiness_accepted" not in public and "acceptance" not in receipt


def test_tampered_retained_bytes_refuse_before_encryption(inputs, archive_seam):
    doc = strict_object(inputs["raw_collection"])
    doc["readiness_accepted"] = True
    inputs["raw_collection"] = canonical(doc)
    with pytest.raises(RetainedEvidenceRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


@pytest.mark.parametrize(
    "field", ["repository_id", "owner_id", "run_id", "source_revision"]
)
def test_producer_splice_refuses_before_archive(inputs, archive_seam, field):
    producer = inputs["producer"]
    inputs["producer"] = replace(
        producer,
        **{
            field: "f" * 40
            if field == "source_revision"
            else getattr(producer, field) + 1
        },
    )
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


def test_independent_workflow_pin_must_match_both_selected_windows(
    inputs, archive_seam
):
    selected = inputs["selection"]
    inputs["selection"] = replace(
        selected, source=replace(selected.source, workflow_revision="f" * 40)
    )
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


@pytest.mark.parametrize(
    "field", ["repository_id", "owner_id", "workflow_id", "run_id", "attempt", "job_id"]
)
@pytest.mark.parametrize("bad", [True, False, 0, -1, "1", 1.0])
def test_coordinates_require_positive_exact_integers(field, bad):
    coordinates = dict(
        repository_id=1,
        owner_id=2,
        workflow_id=3,
        run_id=4,
        attempt=1,
        job_id=5,
        source_revision="a" * 40,
    )
    coordinates[field] = bad
    with pytest.raises(prep.EPreparationRefused):
        prep.EProducerCoordinates(**coordinates)


def test_attempt_one_only(inputs):
    with pytest.raises(prep.EPreparationRefused):
        replace(inputs["producer"], attempt=2)


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 64,
        "sha256:" + "A" * 64,
        "sha256:sha256:" + "a" * 64,
        b"sha256:" + b"a" * 64,
    ],
)
def test_explicit_source_bundle_pin_is_prefixed_and_typed(inputs, archive_seam, bad):
    inputs["source_bundle_digest"] = bad
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


@pytest.mark.parametrize(
    ("key", "bad"),
    [
        ("prerequisite_bytes", b""),
        ("prerequisite_bytes", "private"),
        ("prerequisite_bytes", b"x" * prep.MAX_PRIVATE_BYTES),
        ("raw_collection", b"x" * (8 * 1024 * 1024 + 1)),
        ("raw_collection", {}),
        ("deadline", float("inf")),
        ("deadline", float("nan")),
        ("deadline", True),
        ("deadline", 0),
    ],
    ids=[
        "empty-prerequisites",
        "text-prerequisites",
        "oversized-prerequisites",
        "oversized-collection",
        "object-collection",
        "infinite-deadline",
        "nan-deadline",
        "boolean-deadline",
        "zero-deadline",
    ],
)
def test_input_types_bounds_and_original_deadline(inputs, archive_seam, key, bad):
    inputs[key] = bad
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


@pytest.mark.parametrize(
    "mutation",
    [
        "ciphertext_hash",
        "manifest_hash",
        "plaintext_hash",
        "ciphertext_size",
        "ciphertext_type",
        "double_prefix",
    ],
)
def test_concrete_archive_return_bound_to_actual_bytes(inputs, monkeypatch, mutation):
    def package(manifest, files, profile, *, deadline):
        values = dict(
            ciphertext=b"fixture",
            ciphertext_sha256=prep._sha(b"fixture"),
            plaintext_sha256="1" * 64,
            inner_manifest_sha256=prep._sha(manifest),
        )
        if mutation == "ciphertext_hash":
            values["ciphertext_sha256"] = "2" * 64
        elif mutation == "manifest_hash":
            values["inner_manifest_sha256"] = "2" * 64
        elif mutation == "plaintext_hash":
            values["plaintext_sha256"] = None
        elif mutation == "ciphertext_size":
            values["ciphertext"] = b"x" * (prep.MAX_CIPHERTEXT_BYTES + 1)
        elif mutation == "ciphertext_type":
            values["ciphertext"] = "fixture"
        else:
            values["ciphertext_sha256"] = "sha256:" + values["ciphertext_sha256"]
        return EncryptedArchive(**values)

    monkeypatch.setattr(prep, "package_private_collection", package)
    with pytest.raises(prep.EPreparationRefused, match="^gate0_e_preparation_refused$"):
        prep.prepare_encrypted_e(**inputs)


def test_no_caller_verified_or_encrypted_dto_shortcut(inputs, archive_seam):
    verified = prep.verify_retained_collection(
        inputs["raw_collection"], inputs["selection"]
    )
    inputs["raw_collection"] = verified
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


def test_archive_refusal_category_preserved_and_other_error_closed(inputs, monkeypatch):
    def refused(*args, **kwargs):
        raise ArchiveRefused("archive_deadline")

    monkeypatch.setattr(prep, "package_private_collection", refused)
    with pytest.raises(ArchiveRefused, match="^archive_deadline$"):
        prep.prepare_encrypted_e(**inputs)

    def private_error(*args, **kwargs):
        raise ValueError("PRIVATE-PREREQUISITE path token")

    monkeypatch.setattr(prep, "package_private_collection", private_error)
    with pytest.raises(prep.EPreparationRefused, match="^gate0_e_preparation_refused$"):
        prep.prepare_encrypted_e(**inputs)


def test_deadline_never_reset_after_verification(inputs, archive_seam, monkeypatch):
    actual = prep.verify_retained_collection

    def verify(*args):
        result = actual(*args)
        monkeypatch.setattr(prep.time, "monotonic", lambda: inputs["deadline"])
        return result

    monkeypatch.setattr(prep, "verify_retained_collection", verify)
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


def test_projection_closed_against_private_disclosure_and_digest_splice(
    inputs, archive_seam
):
    result = prep.prepare_encrypted_e(**inputs)
    doc = strict_object(result.projection)
    for field, value in (
        ("private_receipt", "secret"),
        ("ciphertext_digest", "a" * 64),
        ("ciphertext_bytes", True),
    ):
        changed = doc | {field: value}
        with pytest.raises(prep.EPreparationRefused):
            prep.validate_encrypted_e_projection(canonical(changed))


def test_caller_encrypted_archive_is_not_a_profile_or_authenticity_token(
    inputs, archive_seam
):
    inputs["profile"] = EncryptedArchive(b"cipher", "a" * 64, "b" * 64, "c" * 64)
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


def test_combined_payload_budget_refuses_before_archive(inputs, archive_seam):
    inputs["prerequisite_bytes"] = b"x" * (
        prep.MAX_PRIVATE_BYTES - 65536 - len(inputs["raw_collection"])
    )
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert archive_seam == []


def test_deadline_expiring_during_archive_never_returns_a_projection(
    inputs, monkeypatch
):
    calls = []

    def package(manifest, files, profile, *, deadline):
        calls.append(deadline)
        monkeypatch.setattr(prep.time, "monotonic", lambda: deadline)
        return EncryptedArchive(
            b"cipher", prep._sha(b"cipher"), "1" * 64, prep._sha(manifest)
        )

    monkeypatch.setattr(prep, "package_private_collection", package)
    with pytest.raises(prep.EPreparationRefused):
        prep.prepare_encrypted_e(**inputs)
    assert calls == [inputs["deadline"]]
