"""Hosted-only joins; fixture ciphertext claims no native GPG qualification."""

from __future__ import annotations

import base64
import copy
import hashlib
import sys
import time
from asyncio import CancelledError
from collections.abc import Mapping
from dataclasses import asdict, fields, is_dataclass, replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_e_github import _TRANSPORT_GET
from test_gate0_e_github import producer as github_producer  # noqa: F401
from test_gate0_e_preparation import inputs  # noqa: F401
from test_gate0_e_source_references import install_public_metadata
from test_gate0_e_source_references import (
    installed as historical_installed,  # noqa: F401
)
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_archive as archive
from vendor_cp.deployment import gate0_e_preparation as preparation
from vendor_cp.deployment import gate0_e_writer as writer
from vendor_cp.deployment.gate0_framing import canonical, strict_object

_PRIVATE_MARKER = b"WRITER-PRIVATE-PAYLOAD-RETENTION-MARKER"


@pytest.fixture
def private_e(inputs, monkeypatch):  # noqa: F811
    plaintext = []

    def encrypt(manifest, files, profile, *, deadline):
        raw = archive._pack(manifest, files)
        plaintext.append(raw)
        ciphertext = b"HOSTED-FIXTURE-CIPHERTEXT"
        return archive.EncryptedArchive(
            ciphertext,
            writer._sha(ciphertext)[7:],
            writer._sha(raw)[7:],
            writer._sha(manifest)[7:],
        )

    monkeypatch.setattr(preparation, "package_private_collection", encrypt)
    historical = canonical(
        dict(
            schema="Gate0EHistoricalSourceReferences.v1",
            selection=dict(
                policy_digest=inputs["selection"].policy_digest,
                repositories={},
                decisions={},
                packets=[],
            ),
            qualification={},
            retained=[],
            observations=[],
        )
    )
    prerequisites = canonical(
        dict(
            schema="Gate0EPrivatePrerequisites.v1",
            policy_digest=inputs["selection"].policy_digest,
            campaign_digest=inputs["selection"].campaign_digest,
            source_bundle_digest=inputs["source_bundle_digest"],
            historical_reference=base64.b64encode(historical).decode("ascii"),
            historical_reference_digest=writer._sha(historical),
            evidence=dict(
                fixture=dict(
                    digest=writer._sha(_PRIVATE_MARKER),
                    bytes_base64=base64.b64encode(_PRIVATE_MARKER).decode("ascii"),
                )
            ),
            coverage={requirement: ["fixture"] for requirement in writer.REQUIREMENTS},
            a9={
                "collection.json": base64.b64encode(inputs["raw_collection"]).decode(
                    "ascii"
                )
            },
        )
    )
    values = {**inputs, "prerequisite_bytes": prerequisites}
    transfer = preparation.prepare_encrypted_e(**values)
    selected = writer.EPrivateInputs(
        values["producer"],
        values["source_bundle_digest"],
        values["prerequisite_bytes"],
        transfer.projection,
        plaintext[0],
        transfer.ciphertext,
    )
    return archive.unpack_private_archive(plaintext[0]), values["selection"], selected


def test_private_archive_recomputes_actual_bytes_and_preserves_nonacceptance(private_e):
    packaged, selection, private_inputs = private_e
    result = writer.verify_private_e(packaged, selection, private_inputs)
    assert result.result == "private_archive_and_proofs_verified"
    assert result.receipt_digest == writer._sha(packaged.proof_files["receipt.json"])
    assert result.prerequisite_digest == writer._sha(private_inputs.prerequisite_bytes)
    assert result.plaintext_digest == writer._sha(private_inputs.plaintext)
    assert not hasattr(result, "readiness_accepted")


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_bundle_digest", "sha256:" + "a" * 64),
        ("prerequisite_bytes", b'{"fixture":"foreign"}'),
        ("plaintext", b"not-an-archive"),
        ("ciphertext", b"changed-ciphertext"),
    ],
)
def test_private_independent_pin_or_actual_byte_tamper_refuses(private_e, field, value):
    packaged, selection, private_inputs = private_e
    with pytest.raises(writer.EWriterRefused):
        writer.verify_private_e(
            packaged, selection, replace(private_inputs, **{field: value})
        )


def test_caller_private_archive_dto_does_not_replace_actual_plaintext(private_e):
    packaged, selection, private_inputs = private_e
    files = dict(packaged.proof_files)
    files["receipt.json"] = b'{"result":"forged"}'
    forged = archive.PrivateArchive(packaged.inner_manifest, MappingProxyType(files))
    with pytest.raises(writer.EWriterRefused):
        writer.verify_private_e(forged, selection, private_inputs)


def test_coherent_repack_of_false_inner_receipt_is_recomputed(private_e):
    packaged, selection, private_inputs = private_e
    files = dict(packaged.proof_files)
    receipt = strict_object(files["receipt.json"])
    receipt["collection_digest"] = "sha256:" + "a" * 64
    files["receipt.json"] = canonical(receipt)
    manifest = canonical(
        dict(
            schema="Gate0EArchiveManifest.v1",
            files={
                name: dict(length=len(raw), sha256=writer._sha(raw)[7:])
                for name, raw in files.items()
            },
        )
    )
    plaintext = archive._pack(manifest, files)
    projection = strict_object(private_inputs.projection)
    projection["plaintext_archive_digest"] = writer._sha(plaintext)
    projection["inner_manifest_digest"] = writer._sha(manifest)
    with pytest.raises(writer.EWriterRefused):
        writer.verify_private_e(
            archive.unpack_private_archive(plaintext),
            selection,
            replace(
                private_inputs, plaintext=plaintext, projection=canonical(projection)
            ),
        )


def test_spoofed_producer_dto_cannot_pass_live_reader_identity(private_e):
    _, selection, private_inputs = private_e
    installed = writer.InstalledEWriter(
        writer._SEAL, {"producer": private_inputs.producer.document()}, {}, selection
    )

    class FakeReads:
        def owns_facts(self, facts):
            return True

    with pytest.raises(writer.EWriterRefused):
        installed._producer_join(
            FakeReads(), object(), writer.ProducerStage.COLLECTION_SNAPSHOT
        )


def test_publication_and_acceptance_refuse_unowned_dtos_before_receipt(private_e):
    _, selection, private_inputs = private_e
    installed = writer.InstalledEWriter(
        writer._SEAL,
        {"producer": private_inputs.producer.document(), "operation": "publish"},
        {},
        selection,
    )
    with pytest.raises(writer.EWriterRefused):
        installed.construct_receipt(
            object(), object(), object(), object(), deadline=time.monotonic() + 180
        )
    assert installed._used


def test_installed_loader_refuses_missing_independent_root_binding(monkeypatch):
    reads = []

    def protected(path, maximum, **kwargs):
        reads.append(path)
        raise FileNotFoundError

    monkeypatch.setattr(writer, "_protected", protected)
    with pytest.raises(writer.EWriterRefused, match="gate0_e_writer_refused"):
        writer.InstalledEWriter.from_installed()
    assert reads == [writer._INSTALLATION]


@pytest.fixture
def a9_export():
    campaign, lifecycle, qualification = ("sha256:" + letter * 64 for letter in "abc")
    invocation = "1" * 32
    process = canonical(
        dict(
            schema="Gate0A9CollectorRetirementObservation.v1",
            campaign_digest=campaign,
            invocation_id="2" * 32,
            original_pid=42,
            original_start=1234,
            original_cgroup="/original",
            normal=True,
            manager=dict(
                Result="success",
                ExecMainCode="1",
                ExecMainStatus="0",
                ActiveState="inactive",
                ControlGroup="",
                InvocationID="2" * 32,
            ),
            retirement="manager_retired_control_group",
        )
    )
    owned = canonical(
        dict(
            schema="Gate0A9OwnedFilesRetirement.v1",
            lifecycle_binding_digest=lifecycle,
            campaign_digest=campaign,
            boot_id="fixture-boot",
            original_deadline_microseconds=1234,
            process_retirement_observation_digest=writer._sha(process),
            files=[
                dict(
                    slot="controller-key",
                    device=1,
                    inode=2,
                    read_before_unlink=True,
                    unlinked=True,
                    absent_after_unlink=True,
                )
            ],
            result="owned_files_retired",
        )
    )
    files = {
        "collection.json": b"private-original-collection",
        "collector-retirement.json": process,
        "owned-files-retirement.json": owned,
    }
    manifest = canonical(
        dict(
            schema="Gate0A9PrivateCollectionExport.v1",
            lifecycle_binding_digest=lifecycle,
            campaign_digest=campaign,
            bootstrap_invocation_id=invocation,
            files={
                name: dict(bytes=len(raw), digest=writer._sha(raw))
                for name, raw in files.items()
            },
            result="retained_bytes_exported",
        )
    )
    completion = canonical(
        dict(
            schema="Gate0A9ManagerCompletion.v1",
            campaign_digest=campaign,
            qualification_digest=qualification,
            bootstrap_manager_observation=dict(bootstrap=dict(InvocationID=invocation)),
            timer={},
            socket_binding={},
            manager_observations=[
                dict(InvocationID="2" * 32, MainPID="42"),
                dict(
                    InvocationID="2" * 32,
                    MainPID="0",
                    ActiveState="inactive",
                    SubState="dead",
                    Result="success",
                    ExecMainCode="1",
                    ExecMainStatus="0",
                ),
            ],
            retirement="manager_retired_control_group",
            original_cutoff_microseconds=1234,
            result="normal_collector_retired",
        )
    )
    return dict(
        manifest_bytes=manifest,
        files=files,
        completion_bytes=completion,
        campaign=campaign,
        lifecycle_binding=lifecycle,
        bootstrap_invocation=invocation,
        qualification_digest=qualification,
        owned_slots=("controller-key",),
    )


def test_actual_a9_export_byte_binding_and_original_manager_identity(a9_export):
    assert writer.verify_a9_export(**a9_export) == b"private-original-collection"
    a9_export["bootstrap_invocation"] = "3" * 32
    with pytest.raises(writer.EWriterRefused):
        writer.verify_a9_export(**a9_export)


@pytest.mark.parametrize(
    "target",
    ["collection.json", "collector-retirement.json", "owned-files-retirement.json"],
)
def test_a9_export_tamper_refuses(a9_export, target):
    a9_export["files"][target] += b"tamper"
    with pytest.raises(writer.EWriterRefused):
        writer.verify_a9_export(**a9_export)


def test_coherent_export_hashes_cannot_hide_failed_owned_file_retirement(a9_export):
    files = a9_export["files"]
    owned = strict_object(files["owned-files-retirement.json"])
    owned["files"][0]["absent_after_unlink"] = False
    files["owned-files-retirement.json"] = canonical(owned)
    manifest = strict_object(a9_export["manifest_bytes"])
    manifest["files"]["owned-files-retirement.json"] = dict(
        bytes=len(files["owned-files-retirement.json"]),
        digest=writer._sha(files["owned-files-retirement.json"]),
    )
    a9_export["manifest_bytes"] = canonical(manifest)
    with pytest.raises(writer.EWriterRefused):
        writer.verify_a9_export(**a9_export)


@pytest.mark.parametrize(
    "change",
    ["contract_digest", "decision_digest", "reviewer_id", "native_receipt_digest"],
)
def test_foreign_or_unqualified_adoption_provenance_cannot_authorize_receipt(
    private_e, change
):
    packaged, selection, private_inputs = private_e
    contract = canonical(
        dict(
            schema="Gate0EPublicationReviewContract.v2",
            meaning=writer._PUBLIC_REVIEW_MEANING,
            proposal_digest=writer._PUBLIC_PROPOSAL,
            adoption_digest=writer._PUBLIC_ADOPTION,
        )
    )
    decision = b"opaque-exact-human-decision-fixture-not-an-adoption"
    native_digest = "sha256:" + "5" * 64
    provenance = dict(
        schema="Gate0EPublicationDecisionProvenance.v1",
        contract_digest=writer._sha(contract),
        decision_digest=writer._sha(decision),
        reviewer_id=7,
        native_receipt_digest=native_digest,
    )
    provenance[change] = 9 if change == "reviewer_id" else "sha256:" + "6" * 64
    summary = canonical(
        dict(
            schema="Gate0EBArchiveVerification.v2",
            repository_id=private_inputs.producer.repository_id,
            release_id=1,
            ciphertext_asset_id=2,
            projection_asset_id=3,
            producer=private_inputs.producer.document(),
            ciphertext_digest=writer._sha(private_inputs.ciphertext),
            plaintext_digest=writer._sha(private_inputs.plaintext),
            manifest_digest=writer._sha(packaged.inner_manifest),
            private_receipt_digest=writer._sha(packaged.proof_files["receipt.json"]),
            projection_digest=writer._sha(private_inputs.projection),
            policy_digest=selection.policy_digest,
            private_verification_record_digest="sha256:" + "1" * 64,
            holder_source_digest="sha256:" + "2" * 64,
            holder_profile_digest="sha256:" + "3" * 64,
            private_prerequisite_digest="sha256:" + "a" * 64,
            source_reference_digest="sha256:" + "b" * 64,
            operational_evidence_digest="sha256:" + "c" * 64,
            result="private_archive_and_proofs_verified",
        )
    )
    records = {
        "summary": summary,
        "contract": contract,
        "decision": decision,
        "provenance": canonical(provenance),
        "qualification": canonical(dict(native_receipt=dict(digest=native_digest))),
    }
    retained = {"/fixture/" + name: raw for name, raw in records.items()}
    pins = {
        name: dict(path="/fixture/" + name, digest=writer._sha(raw))
        for name, raw in records.items()
    }
    document = dict(
        producer=private_inputs.producer.document(),
        qualification=pins["qualification"],
        publication={**pins, "reviewer_id": 7},
        holder_source_digest="sha256:" + "2" * 64,
        holder_profile_digest="sha256:" + "3" * 64,
    )
    installed = writer.InstalledEWriter(
        writer._SEAL,
        document,
        retained,
        writer.EPublicSelection(
            selection.policy_digest,
            selection.campaign_digest,
            selection.source,
            selection.environment,
        ),
    )
    # Failure must precede use of any publication DTO or release evidence.
    with pytest.raises(writer.EWriterRefused):
        installed._receipt_document(None, None, deadline=time.monotonic() + 180)


def test_historical_coordinates_ignore_only_host_retained_paths():
    import copy

    reference = dict(
        schema="Gate0EHistoricalSourceReferences.v1",
        selection=dict(
            policy_digest="sha256:" + "a" * 64,
            repositories={"cp": {"repository_id": 10}},
            decisions={
                "a7": {
                    "revision": "b" * 40,
                    "retained_pin": {"path": "/host-a/decision", "sha256": "c" * 64},
                }
            },
            packets=[
                {
                    "id": "b",
                    "pr": 200,
                    "merge_sha": "d" * 40,
                    "sources": [
                        {
                            "revision": "d" * 40,
                            "path": "docs/adr/0013.md",
                            "blob_sha": "e" * 40,
                            "sha256": "f" * 64,
                            "retained_pin": {
                                "path": "/host-a/source",
                                "sha256": "f" * 64,
                            },
                        }
                    ],
                    "runs": [{"run_id": 123, "attempt": 1}],
                }
            ],
        ),
        qualification={"host": "a"},
        retained=[],
        observations=[],
    )
    other = copy.deepcopy(reference)
    other["selection"]["decisions"]["a7"]["retained_pin"]["path"] = "/host-b/decision"
    other["selection"]["packets"][0]["sources"][0]["retained_pin"]["path"] = (
        "/host-b/source"
    )
    other["qualification"] = {"host": "b"}
    expected = writer._source_coordinates(canonical(reference))
    assert writer._source_coordinates(canonical(other)) == expected
    for field, changed in (
        ("path", "docs/adr/other.md"),
        ("sha256", "0" * 64),
        ("blob_sha", "1" * 40),
        ("revision", "2" * 40),
    ):
        tampered = copy.deepcopy(other)
        tampered["selection"]["packets"][0]["sources"][0][field] = changed
        assert writer._source_coordinates(canonical(tampered)) != expected
    other["selection"]["packets"][0]["sources"][0]["retained_pin"]["sha256"] = "3" * 64
    assert writer._source_coordinates(canonical(other)) != expected


@pytest.fixture
def installed_composition(
    inputs,  # noqa: F811
    a9_export,
    github_producer,  # noqa: F811
    historical_installed,  # noqa: F811
    monkeypatch,
):
    """Installed source-unit composition; no native crypto or adoption claim.

    Protected file/HTTP/encryption/staging seams are fixture boundaries. Actual
    installed loaders, live fact issuance and all writer joins run unchanged.
    """
    gh = writer.github_owner
    historical = writer.historical_owner
    _, blueprint = github_producer
    workflow_bytes = base64.b64decode(blueprint[gh.EndpointCode.SOURCE]["content"])
    selection = replace(
        inputs["selection"],
        source=replace(
            inputs["selection"].source, workflow_digest=writer._sha(workflow_bytes)
        ),
    )
    producer = inputs["producer"]
    files, gh_files, wire, staged, packages = {}, {}, {}, [], []
    reader_digests = {}

    def pin(name, raw):
        path = writer._RETAINED + name
        files[path] = raw
        return {"path": path, "digest": writer._sha(raw)}

    native_raw = canonical(
        dict(
            schema="Gate0ENativeReviewReceipt.v1",
            qualification_measurements_digest="1" * 64,
            runtime_identity_digest="2" * 64,
            reviewer_record_digest="3" * 64,
        )
    )
    native = pin("native.json", native_raw)
    provenance_pin = pin(
        "owner-dossier", b"SOURCE-UNIT-ONLY not an actual human adoption"
    )
    owners = {
        "writer": writer,
        "proof": writer.proof_owner,
        "archive": writer.archive_owner,
        "preparation": writer.preparation_owner,
        "historical": historical,
        "github": gh,
        "release": writer.release_owner,
        "handoff": writer.handoff_owner,
        "framing": writer.framing_owner,
    }
    owner_digests = {}
    for name, module in owners.items():
        raw = Path(module.__file__).read_bytes()
        files[str(Path(module.__file__).absolute())] = raw
        owner_digests[name] = writer._sha(raw)

    # Rebind the existing complete finite historical fixture to this selected
    # policy, without replacing its loader, transport joins or owns_facts.
    h_selection, h_files, _, _, _ = historical_installed
    h_selection["policy_digest"] = selection.policy_digest[7:]
    h_qual = historical._json(h_files[historical._QUALIFICATION])
    h_qual["policy_digest"] = h_selection["policy_digest"]
    h_qual["selection_sha256"] = historical._digest(
        canonical({k: v for k, v in h_selection.items() if k != "qualification"})
    )
    h_files[historical._QUALIFICATION] = canonical(h_qual)
    h_selection["qualification"]["sha256"] = historical._digest(
        h_files[historical._QUALIFICATION]
    )
    h_files[historical._INSTALLATION] = canonical(h_selection)
    h_binding = historical._json(h_files[historical._BINDING])
    h_binding["installation_sha256"] = historical._digest(
        h_files[historical._INSTALLATION]
    )
    h_binding["qualification_sha256"] = historical._digest(
        h_files[historical._QUALIFICATION]
    )
    for module, name in (
        (historical, "reader_source_sha256"),
        (gh, "github_mechanics_sha256"),
    ):
        h_files[module.__file__] = Path(module.__file__).read_bytes()
        h_binding[name] = historical._digest(h_files[module.__file__])
    h_files[historical._BINDING] = canonical(h_binding)
    h_owner = historical.InstalledHistoricalSourceReads.from_installed()
    h_facts = h_owner.verify(deadline=time.monotonic() + 180)
    assert h_owner.owns_facts(h_facts)
    historical_pin = pin("historical.json", h_facts.reference_bytes)
    public_coordinates = install_public_metadata(h_selection, h_files)
    assert canonical(
        {k: v for k, v in public_coordinates.items() if k != "schema"}
    ) == writer._source_coordinates(h_facts.reference_bytes)

    export = copy.deepcopy(a9_export)
    export["campaign"] = selection.campaign_digest
    export["files"]["collection.json"] = inputs["raw_collection"]
    for name in ("collector-retirement.json", "owned-files-retirement.json"):
        value = strict_object(export["files"][name])
        value["campaign_digest"] = selection.campaign_digest
        if name == "owned-files-retirement.json":
            value["process_retirement_observation_digest"] = writer._sha(
                export["files"]["collector-retirement.json"]
            )
        export["files"][name] = canonical(value)
    completion = strict_object(export["completion_bytes"])
    completion["campaign_digest"] = selection.campaign_digest
    export["completion_bytes"] = canonical(completion)
    manifest = strict_object(export["manifest_bytes"])
    manifest["campaign_digest"] = selection.campaign_digest
    manifest["files"] = {
        name: {"bytes": len(raw), "digest": writer._sha(raw)}
        for name, raw in export["files"].items()
    }
    export["manifest_bytes"] = canonical(manifest)
    for name, raw in {
        **export["files"],
        "manifest.json": export["manifest_bytes"],
    }.items():
        files[writer._EXPORT + name] = raw
    a9 = dict(
        manifest={
            "path": writer._EXPORT + "manifest.json",
            "digest": writer._sha(export["manifest_bytes"]),
        },
        files={
            name: {"path": writer._EXPORT + name, "digest": writer._sha(raw)}
            for name, raw in export["files"].items()
        },
        completion=pin("completion.json", export["completion_bytes"]),
        lifecycle_binding_digest=export["lifecycle_binding"],
        bootstrap_invocation_id=export["bootstrap_invocation"],
        qualification_digest=export["qualification_digest"],
        owned_slots=list(export["owned_slots"]),
    )

    def trust(name, value):
        return dict(
            key_id=value.key_id,
            public_key=pin(name + "-public", value.public_key),
            record=pin(name + "-trust", value.record),
            minimum_version=value.minimum_version,
            source_ref=value.source_ref,
            qualification_digest=value.qualification_digest,
        )

    cases = []
    for index, case in enumerate(selection.cases):
        cases.append(
            dict(
                shared_packet=pin(f"case-{index}-shared", case.shared_packet),
                frozen_window=pin(f"case-{index}-window", case.frozen_window),
                command_id=case.command_id,
                roots=[
                    pin(f"case-{index}-root-{n}", root.document)
                    for n, root in enumerate(case.roots)
                ],
                issuer_trust=trust(f"issuer-{index}", case.issuer_trust),
                attester_trust=trust(f"attester-{index}", case.attester_trust),
            )
        )
    evidence = {"operational": pin("operational", _PRIVATE_MARKER)}
    profile = asdict(inputs["profile"])
    profile["executable"] = str(profile["executable"])
    profile["public_key"] = pin("gpg-public", inputs["profile"].public_key)
    document = dict(
        schema="Gate0EWriterInstallation.v1",
        operation="prepare",
        policy_digest=selection.policy_digest,
        campaign_digest=selection.campaign_digest,
        source_bundle_digest=inputs["source_bundle_digest"],
        source=asdict(selection.source),
        cases=cases,
        withdrawal_reference=selection.withdrawal_reference,
        environment=selection.environment,
        producer=producer.document(),
        historical_reference=historical_pin,
        evidence=evidence,
        coverage={key: ["operational"] for key in writer.REQUIREMENTS},
        a9=a9,
        gpg=profile,
        publication=None,
    )

    def load_writer(operation="prepare", publication=None):
        if operation != "prepare":
            # Public installation has no private selection, archive pins or root
            # bindings. Native boundaries remain synthetic source-unit evidence.
            public_owners = {
                key: owner_digests[key]
                for key in (
                    "writer",
                    "proof",
                    "archive",
                    "handoff",
                    "historical",
                    "github",
                    "release",
                    "preparation",
                    "framing",
                )
            }
            slots = dict(
                release="sha256:"
                + reader_digests["draft" if operation == "publish" else "published"],
                publication=publication["reader_selection_digest"],
                producer="sha256:" + reader_digests["producer"],
            )
            public_native = pin(
                "public/native.json",
                canonical(
                    dict(
                        schema="Gate0EPublicWriterNativeReview.v1",
                        method_scope=writer._PUBLIC_SCOPE,
                        owner_digests=public_owners,
                        reader_slots=slots,
                        qualification_measurements_digest="1" * 64,
                        runtime_identity_digest="2" * 64,
                        reviewer_record_digest="3" * 64,
                    )
                ),
            )
            public_pins = copy.deepcopy(publication)
            for key in ("summary", "contract", "decision", "provenance", "projection"):
                raw = files[publication[key]["path"]]
                if key == "provenance":
                    provenance = strict_object(raw)
                    provenance["native_receipt_digest"] = public_native["digest"]
                    raw = canonical(provenance)
                public_pins[key] = pin("public/" + key + ".json", raw)
            public_doc = dict(
                schema="Gate0EPublicWriterInstallation.v1",
                operation=operation,
                **{
                    key: document[key]
                    for key in (
                        "policy_digest",
                        "campaign_digest",
                        "source_bundle_digest",
                        "source",
                        "environment",
                        "producer",
                    )
                },
                historical_reference=pin(
                    "public/historical.json", canonical(public_coordinates)
                ),
                holder_source_digest="sha256:" + "5" * 64,
                holder_profile_digest="sha256:" + "6" * 64,
                reader_slots=slots,
                publication=public_pins,
            )
            qualification = dict(
                schema="Gate0EPublicWriterQualification.v1",
                method_scope=writer._PUBLIC_SCOPE,
                selection_digest=writer._sha(canonical(public_doc)),
                policy_digest=selection.policy_digest,
                runtime_uid=123,
                owner_digests=public_owners,
                native_receipt=public_native,
                decision_provenance=public_pins["provenance"],
                reader_slots=slots,
            )
            public_doc["qualification"] = pin(
                "public/qualification.json", canonical(qualification)
            )
            raw = canonical(public_doc)
            files[writer._INSTALLATION] = raw
            files[writer._BINDING] = canonical(
                dict(
                    schema="Gate0EPublicWriterBinding.v1",
                    installation_digest=writer._sha(raw),
                    qualification_digest=public_doc["qualification"]["digest"],
                    runtime_uid=123,
                    owners=public_owners,
                    native_receipt=public_native,
                )
            )
            return writer.InstalledEWriter.from_installed()
        document["operation"], document["publication"] = operation, publication
        qualified = {
            key: value for key, value in document.items() if key != "qualification"
        }
        qualification = dict(
            schema="Gate0EWriterQualification.v1",
            selection_digest=writer._sha(canonical(qualified)),
            policy_digest=selection.policy_digest,
            runtime_uid=123,
            owner_digests=owner_digests,
            native_receipt=native,
            decision_provenance=provenance_pin,
        )
        document["qualification"] = pin("qualification.json", canonical(qualification))
        raw = canonical(document)
        files[writer._INSTALLATION] = raw
        files[writer._BINDING] = canonical(
            dict(
                schema="Gate0EWriterBinding.v1",
                installation_digest=writer._sha(raw),
                qualification_digest=document["qualification"]["digest"],
                runtime_uid=123,
                owners=owner_digests,
                native_receipt=native,
            )
        )
        return writer.InstalledEWriter.from_installed()

    def gpin(name, value):
        raw = value if isinstance(value, bytes) else canonical(value)
        path = "/etc/dotmac-gate0-e/" + name
        gh_files[path] = raw
        return {"path": path, "digest": gh._digest(raw)}

    def reader(
        phase,
        *,
        run_id=None,
        workflow_id=None,
        head=None,
        job_id=None,
        raw_workflow=None,
        release_files=None,
        title=None,
        summary_digest=None,
        snapshot_stage=None,
    ):
        publication = phase in ("publication", "publication_complete")
        run_id = (
            run_id
            if run_id is not None
            else producer.run_id + (100 if publication else 0)
        )
        workflow_id = (
            workflow_id
            if workflow_id is not None
            else producer.workflow_id + (1 if publication else 0)
        )
        head = (
            head
            if head is not None
            else ("c" * 40 if publication else producer.source_revision)
        )
        job_id = (
            job_id
            if job_id is not None
            else producer.job_id + (100 if publication else 0)
        )
        raw_workflow = raw_workflow if raw_workflow is not None else workflow_bytes
        blob = hashlib.sha1(
            b"blob " + str(len(raw_workflow)).encode() + b"\0" + raw_workflow,
            usedforsecurity=False,
        ).hexdigest()
        steps = [
            {"number": 1, "name": "Collect", "required_stage": "COLLECTION_SNAPSHOT"},
            {
                "number": 2,
                "name": "Wait transfer",
                "required_stage": "PRODUCER_JOB_COMPLETE",
            },
            {"number": 3, "name": "Upload", "required_stage": "PRODUCER_JOB_COMPLETE"},
        ]
        policy = dict(
            schema="Gate0EGitHubSourcePolicy.v1",
            workflow_sha256=gh._digest(raw_workflow),
            workflow_blob_sha=blob,
            job_key="e",
            job_name="E job",
            environment_id=13,
            environment_name=selection.environment,
            required_steps=steps,
            action_source_pins=["actions/checkout@" + "b" * 40],
            mandatory_jobs=["E job", "Support"],
            sole_artifact_step=3,
            publication_title=title,
            selected_summary_digest=summary_digest,
            projection_sha256=None,
            ciphertext_sha256=None,
            branch_policies=[],
            environment_rules=[],
            policy_digest=selection.policy_digest,
            campaign_digest=selection.campaign_digest,
            source_bundle_digest=inputs["source_bundle_digest"],
        )
        source_pin = gpin(f"github-read-source-policy-{run_id}.json", policy)
        workflow = dict(
            id=workflow_id,
            path=".github/workflows/e.yml",
            commit=head,
            blob_sha=blob,
            sha256=gh._digest(raw_workflow),
            job_key="e",
            job_name="E job",
            environment_id=13,
            environment_name=selection.environment,
            reviewer_id=14,
            runner_group_id=15,
            runner_id=16,
            runner_name="dedicated",
            required_steps=steps,
            action_source_pins=policy["action_source_pins"],
            source_policy_pin=source_pin,
        )
        repository = dict(
            owner="dotmac",
            name="selected",
            repository_id=producer.repository_id,
            owner_id=producer.owner_id,
        )
        run = dict(
            repository=repository,
            workflow=workflow,
            run_id=run_id,
            attempt=1,
            head_sha=head,
            branch="main",
            event="workflow_dispatch",
            actor_id=14,
            triggering_actor_id=14,
        )
        release_pin = None
        if release_files is not None:
            release_pin = dict(
                release_id=22,
                tag="gate0-unit",
                commit=producer.source_revision,
                assets=[
                    dict(id=30 + i, name=name, size=len(raw), sha256=gh._digest(raw))
                    for i, (name, raw) in enumerate(release_files.items())
                ],
            )
        installation = dict(
            schema="Gate0EGitHubReadInstallation.v1",
            policy_digest=selection.policy_digest[7:],
            phase=phase,
            repository=repository,
            producer=None if publication else run,
            publication=run if publication else None,
            transfer=None,
            release=release_pin,
            download_origins=["download.example.com"],
            credential=gh._CREDENTIAL,
        )
        native_pin = gpin(f"github-read-{phase}-native.json", native_raw)
        action = dict(
            run_id=run_id,
            head_sha=head,
            runner_id=16,
            runner_group_id=15,
            job_name="E job",
            environment_id=13,
            qualified_at="2026-10-15T10:00:00Z",
            protection_rules_sha256=gh._digest(b"[]"),
            branch_policies_sha256=gh._digest(b"[]"),
            source_policy_digest=source_pin["digest"],
            native_record_digest="d" * 64,
        )
        qualification = dict(
            schema="Gate0EGitHubNativeQualification.v1",
            installation_policy_digest=selection.policy_digest[7:],
            native_receipt_pin=native_pin,
            api_version=gh._API_VERSION,
            runtime_uid=123,
            credential_uid=0,
            permissions=dict(
                metadata="read",
                actions="read",
                contents="read",
                repository_id=producer.repository_id,
            ),
            action_time={str(run_id): action},
            source_policy_digests=[source_pin["digest"]],
            transfer_profile="flat-two-stored-or-deflate-no-extra.v1",
            immutable_setting=dict(
                repository_id=producer.repository_id,
                state="enabled",
                response_sha256="7" * 64,
                native_record_digest="8" * 64,
                observed_at="2026-10-15T10:00:00Z",
            )
            if phase == "published"
            else None,
        )
        installation["qualification"] = gpin(
            f"github-read-{phase}-qualification.json", qualification
        )
        raw = canonical(installation)
        gh_files[gh._INSTALLATION] = raw
        gh_files[gh._ROOT_BINDING] = canonical(
            dict(
                schema="Gate0EGitHubRootBinding.v1",
                installation_sha256=gh._digest(raw),
                qualification_sha256=installation["qualification"]["digest"],
                source_sha256=gh._digest(gh_files[str(Path(gh.__file__).absolute())]),
                native_receipt_pin=native_pin,
                runtime_uid=123,
            )
        )
        result = gh.InstalledGate0GitHubReads.from_installed()
        responses = copy.deepcopy(blueprint)
        responses[gh.EndpointCode.REPOSITORY].update(
            id=producer.repository_id, owner={"id": producer.owner_id}
        )
        for code in (gh.EndpointCode.RUN, gh.EndpointCode.ATTEMPT):
            responses[code].update(
                id=run_id,
                workflow_id=workflow_id,
                head_sha=head,
                path=workflow["path"],
                repository={
                    "id": producer.repository_id,
                    "owner": {"id": producer.owner_id},
                },
                head_repository={"id": producer.repository_id},
                display_title=title or "E unit producer",
            )
        responses[gh.EndpointCode.WORKFLOW] = dict(
            id=workflow_id, path=workflow["path"]
        )
        responses[gh.EndpointCode.SOURCE].update(
            path=workflow["path"],
            sha=blob,
            size=len(raw_workflow),
            content=base64.b64encode(raw_workflow).decode(),
        )
        job = responses[gh.EndpointCode.JOBS]["jobs"][0]
        job.update(id=job_id, run_id=run_id, head_sha=head)
        upload = copy.deepcopy(job["steps"][1])
        job["steps"][1]["name"] = "Wait transfer"
        upload.update(number=3, name="Upload")
        job["steps"].append(upload)
        if phase == "publication" or snapshot_stage == "collection":
            for code in (gh.EndpointCode.RUN, gh.EndpointCode.ATTEMPT):
                responses[code].update(status="in_progress", conclusion=None)
            job.update(status="in_progress", conclusion=None, completed_at=None)
            job["steps"][1].update(
                status="in_progress", conclusion=None, completed_at=None
            )
            job["steps"][2].update(
                status="queued", conclusion=None, started_at=None, completed_at=None
            )
        support = copy.deepcopy(job)
        support.update(id=job_id + 1, name="Support")
        responses[gh.EndpointCode.JOBS] = dict(total_count=2, jobs=[job, support])
        responses[gh.EndpointCode.REVIEWS][0]["environments"][0]["name"] = (
            selection.environment
        )
        responses[gh.EndpointCode.ENVIRONMENT]["name"] = selection.environment
        for code, value in responses.items():
            page = 1 if code in (gh.EndpointCode.JOBS, gh.EndpointCode.BRANCHES) else 0
            wire[
                (
                    result._path(
                        code,
                        result._publication if publication else result._producer,
                        None,
                        page,
                    ),
                    False,
                )
            ] = value
        if release_files is not None:
            published = phase == "published"
            wire[(result._path(gh.EndpointCode.RELEASE, None, 22, 0), False)] = dict(
                id=22,
                tag_name="gate0-unit",
                draft=not published,
                immutable=published,
                created_at="2026-10-15T10:06:00Z",
                published_at="2026-10-15T10:07:00Z" if published else None,
                target_commitish=producer.source_revision,
            )
            asset_roster = []
            for i, (name, value) in enumerate(release_files.items()):
                item = dict(
                    id=30 + i,
                    name=name,
                    state="uploaded",
                    size=len(value),
                    digest="sha256:" + gh._digest(value),
                    content_type="application/octet-stream",
                    uploader={"id": 14},
                    created_at="2026-10-15T10:06:00Z",
                    updated_at="2026-10-15T10:06:00Z",
                )
                asset_roster.append(item)
                path = result._path(gh.EndpointCode.ASSET, None, 30 + i, 0)
                wire[(path, False)], wire[(path, True)] = item, value
            wire[(result._path(gh.EndpointCode.ASSETS, None, 22, 1), False)] = (
                asset_roster
            )
            if published:
                wire[
                    (
                        result._path(gh.EndpointCode.TAG_REF, None, "gate0-unit", 0),
                        False,
                    )
                ] = dict(
                    ref="refs/tags/gate0-unit", object=dict(type="tag", sha="b" * 40)
                )
                wire[(result._path(gh.EndpointCode.TAG, None, "b" * 40, 0), False)] = (
                    dict(
                        sha="b" * 40,
                        object=dict(type="commit", sha=producer.source_revision),
                    )
                )
        reader_digests[phase] = result.installed_selection_digest
        if phase == "producer":
            gh_files[gh._PRODUCER_COMPLETION_INSTALLATION] = gh_files[gh._INSTALLATION]
            gh_files[gh._PRODUCER_COMPLETION_ROOT_BINDING] = gh_files[gh._ROOT_BINDING]
        return result

    def protected(path, maximum, *args, **kwargs):
        raw = files[path]
        assert 0 < len(raw) <= maximum
        return raw

    def gh_protected(path, maximum, *args, **kwargs):
        raw = gh_files[path]
        assert 0 < len(raw) <= maximum
        return raw

    def spawn(path, token, binary, maximum, origins, deadline, page):
        assert token == b"unit-only-credential" and time.monotonic() < deadline
        value = wire[(path, binary)]
        raw = value if binary else canonical(value)
        assert len(raw) <= maximum
        return 200, 0, 0, raw

    def package(manifest, payloads, profile, *, deadline):
        plaintext = archive._pack(manifest, payloads)
        ciphertext = b"SOURCE-UNIT-CIPHERTEXT"
        packages.append((manifest, dict(payloads), profile, deadline, plaintext))
        return archive.EncryptedArchive(
            ciphertext,
            writer._sha(ciphertext)[7:],
            writer._sha(plaintext)[7:],
            writer._sha(manifest)[7:],
        )

    gh_files[str(Path(gh.__file__).absolute())] = files[
        str(Path(gh.__file__).absolute())
    ]
    gh_files[gh._CREDENTIAL] = b"unit-only-credential"
    monkeypatch.setattr(gh.InstalledGate0GitHubReads, "_get", _TRANSPORT_GET)
    monkeypatch.setattr(gh, "_protected", gh_protected)
    monkeypatch.setattr(gh, "_spawn_get", spawn)
    monkeypatch.setattr(writer, "_protected", protected)
    monkeypatch.setattr(preparation, "package_private_collection", package)
    monkeypatch.setattr(writer, "_stage", lambda value, **kwargs: staged.append(value))
    return SimpleNamespace(
        selection=selection,
        producer=producer,
        document=document,
        files=files,
        pin=pin,
        load=load_writer,
        reader=reader,
        staged=staged,
        packages=packages,
        provenance_pin=provenance_pin,
        native=native,
        historical_reference=h_facts.reference_bytes,
        public_coordinates=public_coordinates,
        historical_files=h_files,
        gh_files=gh_files,
        wire=wire,
        reader_digests=reader_digests,
    )


def test_positive_installed_loader_prepare_encrypts_and_stages_exact_bytes(
    installed_composition,
):
    c = installed_composition
    c.reader(
        "producer", snapshot_stage="collection"
    )  # Install real protected reader selection and wire responses.
    installed = c.load()
    deadline = time.monotonic() + 180
    installed.prepare(deadline=deadline)
    assert len(c.packages) == len(c.staged) == 1
    manifest, payloads, profile, actual_deadline, plaintext = c.packages[0]
    assert actual_deadline == deadline and profile.public_key == b"private-test-profile"
    assert payloads["collection.json"] == c.files[writer._EXPORT + "collection.json"]
    assert archive.unpack_private_archive(plaintext).inner_manifest == manifest
    prerequisites = strict_object(payloads["prerequisites.json"])
    assert (
        base64.b64decode(prerequisites["historical_reference"])
        == c.historical_reference
    )
    assert prerequisites["coverage"] == c.document["coverage"]
    assert set(c.staged[0]) == {"gate0-evidence.pgp", "gate0-evidence-public.json"}
    public = preparation.validate_encrypted_e_projection(
        c.staged[0]["gate0-evidence-public.json"]
    )
    assert public["ciphertext_digest"] == writer._sha(c.staged[0]["gate0-evidence.pgp"])
    assert public["plaintext_archive_digest"] == writer._sha(plaintext)
    assert public["producer"] == c.producer.document()
    assert _PRIVATE_MARKER not in c.staged[0]["gate0-evidence-public.json"]
    with pytest.raises(writer.EWriterRefused):
        installed.prepare(deadline=deadline)


@pytest.mark.parametrize("change", ["workflow", "other_job"])
def test_prepare_joins_independent_workflow_and_exact_selected_job(
    installed_composition, change
):
    c = installed_composition
    c.reader("producer", snapshot_stage="collection")
    if change == "workflow":
        c.document["source"]["workflow_digest"] = writer._sha(
            b"independent other workflow"
        )
    else:
        c.document["producer"]["job_id"] += 1  # A genuine green Support roster job.
    installed = c.load()
    with pytest.raises(writer.EWriterRefused):
        installed.prepare(deadline=time.monotonic() + 180)
    assert not c.staged and not c.packages


@pytest.fixture
def receipt_composition(installed_composition):
    c = installed_composition
    c.reader("producer", snapshot_stage="collection")
    c.load().prepare(deadline=time.monotonic() + 180)
    manifest, payloads, _, _, plaintext = c.packages[0]
    c.reader("producer")
    summary = canonical(
        dict(
            schema="Gate0EBArchiveVerification.v2",
            repository_id=c.producer.repository_id,
            release_id=22,
            ciphertext_asset_id=30,
            projection_asset_id=31,
            producer=c.producer.document(),
            ciphertext_digest=writer._sha(c.staged[0]["gate0-evidence.pgp"]),
            plaintext_digest=writer._sha(plaintext),
            manifest_digest=writer._sha(manifest),
            private_receipt_digest=writer._sha(payloads["receipt.json"]),
            projection_digest=writer._sha(c.staged[0]["gate0-evidence-public.json"]),
            policy_digest=c.selection.policy_digest,
            private_verification_record_digest="sha256:" + "4" * 64,
            holder_source_digest="sha256:" + "5" * 64,
            holder_profile_digest="sha256:" + "6" * 64,
            private_prerequisite_digest=writer._sha(payloads["prerequisites.json"]),
            source_reference_digest=strict_object(payloads["prerequisites.json"])[
                "historical_reference_digest"
            ],
            operational_evidence_digest=writer._sha(
                canonical(
                    {
                        name: item["digest"]
                        for name, item in strict_object(payloads["prerequisites.json"])[
                            "evidence"
                        ].items()
                    }
                )
            ),
            result="private_archive_and_proofs_verified",
        )
    )
    contract = canonical(
        dict(
            schema="Gate0EPublicationReviewContract.v2",
            meaning=writer._PUBLIC_REVIEW_MEANING,
            proposal_digest=writer._PUBLIC_PROPOSAL,
            adoption_digest=writer._PUBLIC_ADOPTION,
        )
    )
    decision = b"SOURCE-UNIT-ONLY decision bytes; not operational adoption"
    provenance = canonical(
        dict(
            schema="Gate0EPublicationDecisionProvenance.v1",
            contract_digest=writer._sha(contract),
            decision_digest=writer._sha(decision),
            reviewer_id=14,
            native_receipt_digest=c.native["digest"],
        )
    )
    c.files[c.provenance_pin["path"]] = provenance
    c.provenance_pin["digest"] = writer._sha(provenance)
    title = (
        f"Gate0 E publication summary {writer._sha(summary)[7:]} "
        f"draft 22 producer {c.producer.run_id}"
    )

    def publication(phase="publication", **overrides):
        reads = c.reader(
            phase, title=title, summary_digest=writer._sha(summary)[7:], **overrides
        )
        facts = (
            reads.publication_snapshot()
            if phase == "publication"
            else reads.publication_complete_snapshot()
        )
        assert reads.owns_facts(facts)
        return reads, facts

    pub_reads, pub_facts = publication()
    pins = dict(
        summary=c.pin("summary.json", summary),
        contract=c.pin("contract.json", contract),
        decision=c.pin("decision", decision),
        provenance=c.provenance_pin,
        reviewer_id=14,
        environment_id=13,
        display_title=title,
        projection=c.pin("projection.json", c.staged[0]["gate0-evidence-public.json"]),
        run=dict(
            repository_id=pub_facts.run.repository_id,
            owner_id=pub_facts.run.owner_id,
            workflow_id=pub_facts.run.workflow_id,
            run_id=pub_facts.run.run_id,
            attempt=pub_facts.run.attempt,
            job_id=pub_reads.selected_job(pub_facts).id,
            source_revision=pub_facts.run.head_sha,
            workflow_digest=writer._sha(pub_facts.run.workflow_source.raw_bytes),
        ),
        reader_selection_digest="sha256:" + pub_reads.installed_selection_digest,
    )
    draft_reads = c.reader("draft", release_files=c.staged[0])
    draft = draft_reads.draft_snapshot()
    assert draft_reads.owns_facts(draft)
    c.publication, c.pub_reads, c.pub_facts = publication, pub_reads, pub_facts
    c.pins, c.draft_reads, c.draft, c.summary = pins, draft_reads, draft, summary
    return c


def test_live_installed_receipt_composition_and_exact_private_archive(
    receipt_composition,
):
    c = receipt_composition
    installed = c.load("publish", c.pins)
    raw = installed.construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    receipt = strict_object(raw)
    assert receipt["private_prerequisite_digest"] == writer._sha(
        c.packages[0][1]["prerequisites.json"]
    )
    assert receipt["b_summary_digest"] == writer._sha(c.summary)
    assert receipt["publication"]["run_id"] == c.pins["run"]["run_id"]
    assert receipt["draft"]["target_commit"] == c.producer.source_revision
    assert "receipt_digest" not in receipt and "receipt_asset_id" not in receipt
    assert receipt["result"] == "candidate_independent_readiness_verified"


@pytest.mark.parametrize(
    "change", ["run", "workflow", "source", "workflow_bytes", "job", "reader_digest"]
)
def test_foreign_live_publication_selection_refuses(receipt_composition, change):
    c = receipt_composition
    overrides = {
        "run": {"run_id": c.pins["run"]["run_id"] + 1},
        "workflow": {"workflow_id": c.pins["run"]["workflow_id"] + 1},
        "source": {"head": "d" * 40},
        "workflow_bytes": {
            "raw_workflow": b"name: independently qualified other publication\n"
        },
        "job": {"job_id": c.pins["run"]["job_id"] + 2},
        "reader_digest": {},
    }[change]
    actual_reads, actual = c.publication(**overrides)
    pins = copy.deepcopy(c.pins)
    pins["reader_selection_digest"] = (
        "sha256:" + actual_reads.installed_selection_digest
    )
    if change == "reader_digest":
        pins["reader_selection_digest"] = "sha256:" + "0" * 64
    installed = c.load("publish", pins)
    with pytest.raises(writer.EWriterRefused):
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            actual_reads,
            actual,
            deadline=time.monotonic() + 180,
        )


@pytest.mark.parametrize("fail_official", [False, True])
def test_completed_live_publication_producer_release_and_direct_official_boundary(
    receipt_composition, monkeypatch, fail_official
):
    c = receipt_composition
    receipt = c.load("publish", c.pins).construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    pub_reads, publication = c.publication("publication_complete")
    producer_reads = c.reader("producer")
    producer = producer_reads.producer_snapshot(
        writer.ProducerStage.PRODUCER_RUN_COMPLETE
    )
    release_files = {**c.staged[0], "gate0-readiness-receipt.json": receipt}
    release_reads = c.reader("published", release_files=release_files)
    release = release_reads.published_snapshot()
    assert all(
        owner.owns_facts(facts)
        for owner, facts in (
            (pub_reads, publication),
            (producer_reads, producer),
            (release_reads, release),
        )
    )
    pins = copy.deepcopy(c.pins)
    pins["reader_selection_digest"] = "sha256:" + pub_reads.installed_selection_digest
    installed = c.load("verify_published", pins)
    calls = []
    official = writer.release_owner
    assertion = official.VerifiedReleaseAssertion(
        release.repository_id,
        release.owner_id,
        release.release_id,
        release.tag,
        release.raw_tag_sha,
        release.peeled_commit,
        tuple(
            (asset.id, asset.name, asset.size, asset.sha256) for asset in release.assets
        ),
        "7" * 64,
        "8" * 64,
        (
            official.ReleaseCommandEvidence(
                "unit-native-process-boundary", None, "9" * 64, b"SOURCE-UNIT-ONLY"
            ),
        ),
    )

    class OfficialUnitBoundary:
        def verify_published(self, reads, facts):
            calls.append((reads, facts))
            assert (
                reads is release_reads and facts is release and reads.owns_facts(facts)
            )
            if fail_official:
                raise writer.github_owner.AttestationTransportUnqualified()
            return assertion

    loads = []

    def load_official(cls):
        loads.append(True)
        return OfficialUnitBoundary()

    monkeypatch.setattr(
        writer.InstalledGhReleaseVerifier, "from_installed", classmethod(load_official)
    )
    if fail_official:
        with pytest.raises(writer.EWriterRefused) as error:
            installed.verify_published(
                release_reads, release, pub_reads, publication, producer_reads, producer
            )
        _assert_writer_exception_clean(error.value, installed)
    else:
        result = installed.verify_published(
            release_reads, release, pub_reads, publication, producer_reads, producer
        )
        assert (
            result.receipt_digest == writer._sha(receipt)
            and result.receipt_asset_id == 32
        )
        assert (
            result.producer_run_id == c.producer.run_id
            and result.publication_run_id == publication.run.run_id
        )
        assert (
            result.gh_digest == assertion.gh_sha256
            and result.gh_command_digests == ("9" * 64,)
        )
    assert loads == [True] and calls == [(release_reads, release)]


@pytest.mark.parametrize("change", ["host_paths", "source_hash", "repository_path"])
def test_prepare_normalizes_only_local_historical_names(installed_composition, change):
    c = installed_composition
    selected = strict_object(c.historical_reference)
    for decision in selected["selection"]["decisions"].values():
        decision["retained_pin"]["path"] = (
            "/independent-host/" + decision["retained_pin"]["sha256"]
        )
    for packet in selected["selection"]["packets"]:
        for source in packet["sources"]:
            source["retained_pin"]["path"] = (
                "/independent-host/" + source["retained_pin"]["sha256"]
            )
    source = selected["selection"]["packets"][0]["sources"][0]
    if change == "source_hash":
        source["sha256"] = "0" * 64
    elif change == "repository_path":
        source["path"] = "src/foreign_contract.py"
    c.document["historical_reference"] = c.pin(
        "other-host-historical.json", canonical(selected)
    )
    c.reader("producer", snapshot_stage="collection")
    installed = c.load()
    if change == "host_paths":
        installed.prepare(deadline=time.monotonic() + 180)
        actual = strict_object(c.packages[0][1]["prerequisites.json"])
        assert (
            base64.b64decode(actual["historical_reference"]) == c.historical_reference
        )
        assert c.staged
    else:
        with pytest.raises(writer.EWriterRefused):
            installed.prepare(deadline=time.monotonic() + 180)
        assert not c.packages and not c.staged


@pytest.mark.parametrize("changed", ["source", "qualification", "native"])
def test_installed_positive_fixture_still_refuses_changed_protected_pins(
    installed_composition, changed
):
    c = installed_composition
    c.load()
    path = {
        "source": str(Path(writer.__file__).absolute()),
        "qualification": c.document["qualification"]["path"],
        "native": c.native["path"],
    }[changed]
    c.files[path] += b"changed-protected-input"
    with pytest.raises(writer.EWriterRefused):
        writer.InstalledEWriter.from_installed()


def _assert_writer_exception_clean(error, owner=None):
    """Inspect retained values, not just the exception's printable diagnostic."""
    tokens = (_PRIVATE_MARKER, base64.b64encode(_PRIVATE_MARKER))
    seen = set()

    def private_reachable(value):
        if id(value) in seen:
            return False
        seen.add(id(value))
        if isinstance(value, bytes):
            return any(token in value for token in tokens)
        if isinstance(value, str):
            return any(token.decode() in value for token in tokens)
        if isinstance(value, Mapping):
            return any(
                private_reachable(k) or private_reachable(v) for k, v in value.items()
            )
        if isinstance(value, tuple | list | set | frozenset):
            return any(private_reachable(item) for item in value)
        if isinstance(value, type) or callable(value):
            return False  # Global code/classes are not captured private payloads.
        if is_dataclass(value):
            return any(
                private_reachable(getattr(value, item.name)) for item in fields(value)
            )
        if hasattr(value, "__dict__"):
            return private_reachable(vars(value))
        return False

    assert error.__context__ is None and error.__cause__ is None
    assert not private_reachable(error.args)
    trace = error.__traceback__
    names = []
    while trace is not None:
        frame = trace.tb_frame
        if frame.f_code.co_filename == writer.__file__:
            names.append(frame.f_code.co_name)
            assert not private_reachable(dict(frame.f_locals))
        trace = trace.tb_next
    assert "_receipt_document" not in names
    assert not any(name.endswith(("_checked", "_work")) for name in names)
    if owner is not None:
        assert owner.__dict__ == {"_used": True}
        assert not private_reachable(owner)


def test_pure_private_verifier_late_failure_detaches_materialized_archive(
    private_e, monkeypatch
):
    packaged, selection, selected = private_e
    reached = []
    private_frames = []
    actual = writer.validate_encrypted_e_projection

    def late_projection(raw):
        private_frames.append(sys._getframe(1))
        result = actual(raw)
        reached.append(True)  # All unpack/proof/receipt/manifest checks preceded this.
        result["plaintext_archive_digest"] = "sha256:" + "0" * 64
        return result

    assert base64.b64encode(_PRIVATE_MARKER) in selected.plaintext
    monkeypatch.setattr(writer, "validate_encrypted_e_projection", late_projection)
    with pytest.raises(writer.EWriterRefused) as error:
        writer.verify_private_e(packaged, selection, selected)
    assert reached == [True]
    _assert_writer_exception_clean(error.value)
    assert private_frames and all(frame.f_locals == {} for frame in private_frames)
    # Inputs belong to this caller; the boundary cannot erase caller ownership.
    assert base64.b64encode(_PRIVATE_MARKER) in selected.plaintext


def test_receipt_late_projection_failure_discards_owner_and_frames(
    receipt_composition, monkeypatch
):
    c = receipt_composition
    pins = copy.deepcopy(c.pins)
    pins["projection"] = c.pin("wrong-projection.json", b"changed-public-projection")
    installed = c.load("publish", pins)
    with pytest.raises(writer.EWriterRefused) as error:
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )
    _assert_writer_exception_clean(error.value, installed)


def test_prepare_private_staging_failure_detaches_owner_and_nested_causes(
    installed_composition, monkeypatch
):
    c = installed_composition
    c.reader("producer", snapshot_stage="collection")
    installed = c.load()
    reached = []
    private_frames = []

    def stage(files, *, deadline):
        private_frames.append(sys._getframe(1))
        reached.append(set(files))
        try:
            raise RuntimeError(_PRIVATE_MARKER)
        except RuntimeError as cause:
            raise ValueError(_PRIVATE_MARKER) from cause

    monkeypatch.setattr(writer, "_stage", stage)
    with pytest.raises(writer.EWriterRefused) as error:
        installed.prepare(deadline=time.monotonic() + 180)
    assert len(c.packages) == 1 and reached == [
        {"gate0-evidence.pgp", "gate0-evidence-public.json"}
    ]
    _assert_writer_exception_clean(error.value, installed)
    assert private_frames and all(frame.f_locals == {} for frame in private_frames)


def test_installed_loader_late_private_pin_failure_has_clean_traceback(
    installed_composition,
):
    c = installed_composition
    c.load()
    c.files[c.document["gpg"]["public_key"]["path"]] += b"wrong-late-key-pin"
    with pytest.raises(writer.EWriterRefused) as error:
        writer.InstalledEWriter.from_installed()
    _assert_writer_exception_clean(error.value)


@pytest.mark.parametrize(
    "kind", [KeyboardInterrupt, CancelledError, GeneratorExit, SystemExit]
)
def test_cancellation_during_public_projection_stops_and_scrubs(
    receipt_composition, monkeypatch, kind
):
    c = receipt_composition
    installed = c.load("publish", c.pins)
    actual_validate = writer.validate_encrypted_e_projection
    reached = []

    def interrupt(raw):
        result = actual_validate(raw)
        assert result["result"] == "encrypted_evidence"
        reached.append(True)
        if kind is SystemExit:
            raise SystemExit(7)
        raise kind(_PRIVATE_MARKER)

    monkeypatch.setattr(writer, "validate_encrypted_e_projection", interrupt)
    with pytest.raises(kind) as error:
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )
    assert reached == [True]
    if kind is SystemExit:
        assert error.value.code == 7
    else:
        assert not error.value.args
    _assert_writer_exception_clean(error.value, installed)


def test_private_exit_payload_is_not_retained_by_public_stop(private_e, monkeypatch):
    packaged, selection, selected = private_e

    def stop_after_materialization(raw):
        raise SystemExit(_PRIVATE_MARKER)

    monkeypatch.setattr(
        writer, "validate_encrypted_e_projection", stop_after_materialization
    )
    with pytest.raises(SystemExit) as error:
        writer.verify_private_e(packaged, selection, selected)
    assert error.value.code == 1
    _assert_writer_exception_clean(error.value)


def test_successful_receipt_boundary_releases_consumed_private_selection(
    receipt_composition,  # noqa: F811
):
    c = receipt_composition
    owner = c.load("publish", c.pins)
    public_workflow_digest = owner.selection.source.workflow_digest
    retained_files = dict(c.files)
    receipt = owner.construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    assert strict_object(receipt)["b_summary_digest"] == writer._sha(c.summary)
    assert canonical(strict_object(receipt)) == receipt
    assert public_workflow_digest == c.selection.source.workflow_digest
    assert owner.__dict__ == {"_used": True}
    # Only the selected owner's references were detached. Actual retained fixture
    # evidence at the external native boundary is unchanged and remains usable.
    assert c.files == retained_files
    with pytest.raises(writer.EWriterRefused) as raised:
        owner.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )
    _assert_writer_exception_clean(raised.value, owner)


@pytest.mark.parametrize("operation", ["publish", "verify_published"])
def test_public_installed_loader_and_receipt_never_open_private_inputs(
    receipt_composition, monkeypatch, operation
):
    c = receipt_composition
    if operation == "verify_published":
        c.reader("published", release_files=c.staged[0])
    protected = writer._protected
    reads = []
    source_paths = {
        str(Path(module.__file__).absolute())
        for module in (
            writer,
            writer.proof_owner,
            writer.archive_owner,
            writer.handoff_owner,
            writer.historical_owner,
            writer.github_owner,
            writer.release_owner,
            writer.preparation_owner,
            writer.framing_owner,
        )
    }
    allowed = (
        {writer._INSTALLATION, writer._BINDING}
        | source_paths
        | {
            writer._RETAINED + "public/" + name + ".json"
            for name in (
                "qualification",
                "native",
                "historical",
                "summary",
                "contract",
                "decision",
                "provenance",
                "projection",
            )
        }
    )

    def public_only(path, *args, **kwargs):
        assert path in allowed, "publication attempted a private input read"
        reads.append(path)
        return protected(path, *args, **kwargs)

    def private_forbidden(*args, **kwargs):
        pytest.fail("public execution invoked a private proof owner")

    monkeypatch.setattr(writer, "_protected", public_only)
    monkeypatch.setattr(writer, "ESelection", private_forbidden)
    monkeypatch.setattr(writer, "RootHostBinding", private_forbidden)
    monkeypatch.setattr(writer, "verify_private_e", private_forbidden)
    monkeypatch.setattr(writer, "verify_retained_collection", private_forbidden)
    installed = c.load(operation, c.pins)
    assert type(installed.selection) is writer.EPublicSelection
    assert set(installed._document).isdisjoint(
        {"cases", "a9", "gpg", "evidence", "coverage"}
    )
    assert set(installed._document["publication"]).isdisjoint(
        {"private_collection", "private_prerequisites"}
    )
    # The same public receipt builder is used by whole-run final readback.
    raw = (
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )
        if operation == "publish"
        else installed._receipt_document(
            c.draft, c.pub_facts, deadline=time.monotonic() + 180
        )
    )
    receipt = strict_object(raw)
    archived = strict_object(c.packages[0][1]["prerequisites.json"])
    assert receipt["private_prerequisite_digest"] == writer._sha(
        c.packages[0][1]["prerequisites.json"]
    )
    assert receipt["source_reference_digest"] == archived["historical_reference_digest"]
    assert receipt["operational_evidence_digest"] == writer._sha(
        canonical({name: item["digest"] for name, item in archived["evidence"].items()})
    )
    assert reads and all(path in allowed for path in reads)


@pytest.mark.parametrize(
    "change",
    [
        "v1",
        "extra",
        "missing",
        "bad_digest",
        "bad_type",
        "holder_source",
        "holder_profile",
        "producer",
        "policy",
        "asset",
        "private_prerequisite_missing",
        "source_reference_missing",
        "operational_evidence_missing",
    ],
)
def test_public_receipt_requires_exact_authenticated_b_v2(receipt_composition, change):
    c = receipt_composition
    summary = strict_object(c.summary)
    if change == "v1":
        summary["schema"] = "Gate0EBArchiveVerification.v1"
    elif change == "extra":
        summary["unreviewed"] = True
    elif change == "missing":
        del summary["private_receipt_digest"]
    elif change.endswith("_missing"):
        del summary[change.removesuffix("_missing") + "_digest"]
    elif change == "bad_digest":
        summary["operational_evidence_digest"] = "a" * 64
    elif change == "bad_type":
        summary["source_reference_digest"] = 42
    elif change == "producer":
        summary["producer"]["job_id"] += 1
    elif change == "asset":
        summary["ciphertext_asset_id"] += 1
    else:
        summary[change + "_digest"] = "sha256:" + "0" * 64
    pins = copy.deepcopy(c.pins)
    pins["summary"] = c.pin("changed-summary.json", canonical(summary))
    installed = c.load("publish", pins)
    with pytest.raises(writer.EWriterRefused):
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )


@pytest.mark.parametrize(
    "change", ["legacy_contract", "meaning", "proposal", "adoption", "decision"]
)
def test_public_review_requires_adopted_exact_contract_and_native_decision(
    receipt_composition, change
):
    c = receipt_composition
    pins = copy.deepcopy(c.pins)
    if change == "decision":
        pins["decision"] = c.pin("foreign-decision.json", b"different decision")
    else:
        contract = strict_object(c.files[pins["contract"]["path"]])
        if change == "legacy_contract":
            contract = dict(
                schema="Gate0EPublicationReviewContract.v1",
                meaning="digest_bound_b_verification_publication_review",
            )
        elif change == "meaning":
            contract["meaning"] = "ordinary Environment approval"
        else:
            contract[change + "_digest"] = "sha256:" + "0" * 64
        raw = canonical(contract)
        pins["contract"] = c.pin("foreign-contract.json", raw)
        # Even coherently authenticated source-unit provenance cannot turn a
        # foreign meaning into the adopted trust contract.
        provenance = strict_object(c.files[pins["provenance"]["path"]])
        provenance["contract_digest"] = writer._sha(raw)
        pins["provenance"] = c.pin("foreign-provenance.json", canonical(provenance))
    installed = c.load("publish", pins)
    with pytest.raises(writer.EWriterRefused):
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )


def test_public_readback_refuses_before_whole_publication_completes(
    receipt_composition, monkeypatch
):
    c = receipt_composition
    receipt = c.load("publish", c.pins).construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    producer_reads = c.reader("producer")
    producer = producer_reads.producer_snapshot(
        writer.ProducerStage.PRODUCER_RUN_COMPLETE
    )
    release_reads = c.reader(
        "published",
        release_files={**c.staged[0], "gate0-readiness-receipt.json": receipt},
    )
    release = release_reads.published_snapshot()
    installed = c.load("verify_published", c.pins)

    def official_forbidden(*args, **kwargs):
        pytest.fail("official verifier reached before publication completion")

    monkeypatch.setattr(
        writer.InstalledGhReleaseVerifier, "from_installed", official_forbidden
    )
    with pytest.raises(writer.EWriterRefused):
        installed.verify_published(
            release_reads, release, c.pub_reads, c.pub_facts, producer_reads, producer
        )


@pytest.mark.parametrize(
    "change",
    [
        "private_top_level",
        "private_publication",
        "private_path",
        "legacy_schema",
        "native_scope",
        "native_digest",
        "qualification",
        "runtime_uid",
        "source_bytes",
    ],
)
def test_public_installed_selection_cannot_expand_private_or_native_scope(
    receipt_composition, monkeypatch, change
):
    c = receipt_composition
    c.load("publish", c.pins)
    doc = strict_object(c.files[writer._INSTALLATION])
    binding = strict_object(c.files[writer._BINDING])
    if change == "private_top_level":
        doc["cases"] = c.document["cases"]
    elif change == "private_publication":
        doc["publication"]["private_collection"] = c.pin(
            "forbidden-collection", b"must not open"
        )
    elif change == "private_path":
        doc["publication"]["summary"] = c.pin("forbidden-private-summary", c.summary)
    elif change == "legacy_schema":
        doc = copy.deepcopy(c.document)
        doc["operation"] = "publish"
    elif change == "native_scope":
        pin = binding["native_receipt"]
        native = strict_object(c.files[pin["path"]])
        native["method_scope"] = "private-preparation"
        c.files[pin["path"]] = canonical(native)
    elif change == "native_digest":
        binding["native_receipt"]["digest"] = "sha256:" + "0" * 64
    elif change == "qualification":
        c.files[doc["qualification"]["path"]] += b" "
    elif change == "runtime_uid":
        binding["runtime_uid"] += 1
    else:
        c.files[str(Path(writer.historical_owner.__file__).absolute())] += (
            b"changed owner"
        )
    raw = canonical(doc)
    c.files[writer._INSTALLATION] = raw
    binding["installation_digest"] = writer._sha(raw)
    c.files[writer._BINDING] = canonical(binding)
    protected = writer._protected
    opened = []

    def no_private(path, *args, **kwargs):
        assert "forbidden-" not in path
        opened.append(path)
        return protected(path, *args, **kwargs)

    monkeypatch.setattr(writer, "_protected", no_private)
    with pytest.raises(writer.EWriterRefused):
        writer.InstalledEWriter.from_installed()
    assert opened and not any("forbidden-" in path for path in opened)


@pytest.mark.parametrize(
    "change",
    [
        "campaign_digest",
        "source_bundle_digest",
        "policy_digest",
        "producer_job",
        "workflow_bytes",
    ],
)
def test_public_projection_and_completed_producer_match_independent_selection(
    receipt_composition, change
):
    c = receipt_composition
    if change == "producer_job":
        c.document["producer"]["job_id"] += 1
    elif change == "workflow_bytes":
        c.document["source"]["workflow_digest"] = "sha256:" + "0" * 64
    else:
        c.document[change] = "sha256:" + "0" * 64
    with pytest.raises(writer.EWriterRefused):
        installed = c.load("publish", c.pins)
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() + 180,
        )


def test_public_receipt_digest_matches_full_private_verified_digest_projection(
    receipt_composition,
):
    c = receipt_composition
    manifest, payloads, _, _, plaintext = c.packages[0]
    selected = writer.EPrivateInputs(
        c.producer,
        c.document["source_bundle_digest"],
        payloads["prerequisites.json"],
        c.staged[0]["gate0-evidence-public.json"],
        plaintext,
        c.staged[0]["gate0-evidence.pgp"],
    )
    private = writer.verify_private_e(
        archive.unpack_private_archive(plaintext), c.selection, selected
    )
    raw = c.load("publish", c.pins).construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    receipt = strict_object(raw)
    assert set(receipt) == {
        "schema",
        "policy_digest",
        "campaign_digest",
        "source_bundle_digest",
        "collection_digest",
        "private_prerequisite_digest",
        "producer",
        "source_reference_digest",
        "operational_evidence_digest",
        "b_summary_digest",
        "b_holder_profile_digest",
        "b_verification_record_digest",
        "publication",
        "draft",
        "result",
    }
    prerequisites = strict_object(payloads["prerequisites.json"])
    expected = {
        **receipt,
        "private_prerequisite_digest": private.prerequisite_digest,
        "source_reference_digest": writer._sha(
            base64.b64decode(prerequisites["historical_reference"], validate=True)
        ),
        "operational_evidence_digest": writer._sha(
            canonical(
                {
                    name: item["digest"]
                    for name, item in prerequisites["evidence"].items()
                }
            )
        ),
    }
    assert writer._sha(raw) == writer._sha(canonical(expected))
    assert private.manifest_digest == writer._sha(manifest)


@pytest.mark.parametrize("operation", ["prepare", "publish"])
def test_writer_public_dispatch_preserves_private_prepare_reread(
    receipt_composition, monkeypatch, operation
):
    c = receipt_composition
    protected = writer._protected
    calls = []

    def classified(path, *args, **kwargs):
        private = kwargs.get("private", True)
        calls.append((path, private))
        if operation == "publish" and (
            path in (writer._INSTALLATION, writer._BINDING)
            or path.startswith(writer._RETAINED + "public/")
        ):
            assert private is False
        return protected(path, *args, **kwargs)

    monkeypatch.setattr(writer, "_protected", classified)
    c.load(operation, c.pins if operation == "publish" else None)
    installation_reads = [
        private for path, private in calls if path == writer._INSTALLATION
    ]
    assert installation_reads == ([False, True] if operation == "prepare" else [False])
    if operation == "prepare":
        assert (writer._BINDING, True) in calls
        assert any(
            path.startswith(writer._RETAINED) and private for path, private in calls
        )


def test_readable_private_prepare_configuration_still_refuses(
    installed_composition, monkeypatch
):
    c = installed_composition
    c.load()
    protected = writer._protected
    calls = []

    def private_leaf_policy(path, *args, **kwargs):
        private = kwargs.get("private", True)
        calls.append((path, private))
        if path == writer._INSTALLATION and private:
            raise writer.EWriterRefused()
        return protected(path, *args, **kwargs)

    monkeypatch.setattr(writer, "_protected", private_leaf_policy)
    with pytest.raises(writer.EWriterRefused):
        writer.InstalledEWriter.from_installed()
    assert calls == [(writer._INSTALLATION, False), (writer._INSTALLATION, True)]


def test_writer_public_historical_mode_uses_only_closed_public_slots(
    receipt_composition, monkeypatch
):
    c = receipt_composition
    historical = writer.historical_owner
    native = historical._protected
    allowed = {
        historical._PUBLIC_INSTALLATION,
        historical._PUBLIC_BINDING,
        historical._PUBLIC_QUALIFICATION,
        historical._PUBLIC_NATIVE,
        historical._CREDENTIAL,
        historical.__file__,
        historical._mechanics.__file__,
    }
    opened = []

    def public_only(path, *args, **kwargs):
        assert path in allowed, "writer attempted private historical access"
        opened.append(path)
        return native(path, *args, **kwargs)

    monkeypatch.setattr(historical, "_protected", public_only)
    raw = c.load("publish", c.pins).construct_receipt(
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        deadline=time.monotonic() + 180,
    )
    receipt = strict_object(raw)
    summary = strict_object(c.summary)
    assert receipt["source_reference_digest"] == summary["source_reference_digest"]
    assert receipt["source_reference_digest"] != writer._sha(
        canonical(c.public_coordinates)
    )
    assert (
        historical._PUBLIC_INSTALLATION in opened and historical._CREDENTIAL in opened
    )
    assert (
        historical._INSTALLATION not in opened
        and historical._QUALIFICATION not in opened
    )


@pytest.mark.parametrize(
    "change", ["full_wrapper", "retained_pin", "body", "observations"]
)
def test_public_writer_historical_slot_rejects_private_forms_before_use(
    receipt_composition, change
):
    c = receipt_composition
    if change == "full_wrapper":
        value = strict_object(c.historical_reference)
        c.public_coordinates.clear()
        c.public_coordinates.update(value)
    elif change == "retained_pin":
        c.public_coordinates["decisions"]["rulings"]["retained_pin"] = {
            "path": "/private/dossier",
            "sha256": "a" * 64,
        }
    else:
        c.public_coordinates[change] = _PRIVATE_MARKER.decode()
    with pytest.raises(writer.EWriterRefused):
        c.load("publish", c.pins)


def test_installed_three_asset_draft_loader_is_reachable(installed_composition):
    from vendor_cp.deployment import gate0_e_github as gh

    c = installed_composition
    c.reader("producer", snapshot_stage="collection")
    c.load().prepare(deadline=time.monotonic() + 180)
    release_files = {
        **c.staged[0],
        "gate0-readiness-receipt.json": b"{}",
    }
    reads = c.reader("draft_with_receipt", release_files=release_files)
    facts = reads.draft_with_receipt_snapshot()
    assert type(facts) is gh.DraftReleaseFacts and reads.owns_facts(facts)
    assert reads._installation["phase"] == "draft_with_receipt"
    assert facts.draft and len(facts.assets) == 3
    assert {asset.name for asset in facts.assets} == set(release_files)


@pytest.mark.parametrize("phase", ["draft_with_receipt ", "unknown"])
def test_installed_draft_phase_is_not_normalized_or_generalized(
    installed_composition, phase
):
    from vendor_cp.deployment import gate0_e_github as gh

    with pytest.raises(gh.GitHubReadRefused):
        installed_composition.reader(phase, release_files={})


def test_expired_receipt_deadline_refuses_before_producer_or_historical_read(
    receipt_composition, monkeypatch
):
    c = receipt_composition
    installed = c.load("publish", c.pins)
    reads = []

    def unexpected_read(*args, **kwargs):
        reads.append(True)
        pytest.fail("expired receipt attempted a read")

    monkeypatch.setattr(
        writer.InstalledGate0GitHubReads,
        "from_installed_producer_completion",
        unexpected_read,
    )
    monkeypatch.setattr(
        writer.InstalledHistoricalSourceReads, "from_installed_public", unexpected_read
    )
    with pytest.raises(writer.EWriterRefused):
        installed.construct_receipt(
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            deadline=time.monotonic() - 1,
        )
    assert not reads
    assert installed.__dict__ == {"_used": True}


def test_receipt_document_expired_deadline_refuses_before_retained_read(
    receipt_composition, monkeypatch
):
    c = receipt_composition
    installed = c.load("publish", c.pins)

    def unexpected_read(*args):
        pytest.fail("expired receipt read retained content")

    monkeypatch.setattr(writer.InstalledEWriter, "_selected", unexpected_read)
    with pytest.raises(writer.EWriterRefused):
        installed._receipt_document(c.draft, c.pub_facts, deadline=time.monotonic() - 1)
