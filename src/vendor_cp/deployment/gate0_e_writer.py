"""Sole CP E composition owner; preparation never asserts readiness.

Installation qualification authenticates retained observations. Byte verification
cannot recreate historical kernel observations or Michael's human decision.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import time
import traceback
from asyncio import CancelledError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn, cast

from vendor_cp.deployment import gate0_e_archive as archive_owner
from vendor_cp.deployment import gate0_e_finalization as proof_owner
from vendor_cp.deployment import gate0_e_github as github_owner
from vendor_cp.deployment import gate0_e_preparation as preparation_owner
from vendor_cp.deployment import gate0_e_release_verification as release_owner
from vendor_cp.deployment import gate0_e_source_references as historical_owner
from vendor_cp.deployment import gate0_framing as framing_owner
from vendor_cp.deployment import gate0_runner_handoff as handoff_owner
from vendor_cp.deployment.gate0_e_archive import (
    ARCHIVE_NAMES,
    GpgArchiveProfile,
    PrivateArchive,
)
from vendor_cp.deployment.gate0_e_finalization import (
    EPublicTrust,
    ERetainedCase,
    ESelection,
    ESourcePins,
    verify_retained_collection,
)
from vendor_cp.deployment.gate0_e_github import (
    DownloadedReleaseFacts,
    DraftReleaseFacts,
    InstalledGate0GitHubReads,
    ProducerFacts,
    ProducerStage,
    PublicationFacts,
    _protected,
)
from vendor_cp.deployment.gate0_e_preparation import (
    EProducerCoordinates,
    prepare_encrypted_e,
    validate_encrypted_e_projection,
)
from vendor_cp.deployment.gate0_e_release_verification import InstalledGhReleaseVerifier
from vendor_cp.deployment.gate0_e_source_references import (
    InstalledHistoricalSourceReads,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_handoff import RootHostBinding

_INSTALLATION = "/run/dotmac-gate0-e/writer.json"
_BINDING = "/etc/dotmac-gate0-e/writer-binding.json"
_RETAINED = "/etc/dotmac-gate0-e/writer/"
_STAGING = "/run/dotmac-gate0-e/staging"
_EXPORT = "/run/dotmac-gate0-collector/export/"
_CAP = 8 * 1024 * 1024
_SEAL = object()
# A7.7/D7/D11 predicates, with real artifact references, never state flags.
REQUIREMENTS = (
    "no_rollout_approval",
    "execution_grant_separation",
    "withdrawal_relay",
    "protected_scheduler_negative_before_positive",
    "oidc_claim_audience_ttl_role_refusals",
    "signer_read_denial",
    "independent_role_custody_controller",
    "missing_wrong_approval_custody_controller",
    "proof_integrity_purpose_lease_uniqueness",
    "trust_startup_floor_rollback_revoked_wins_refresh",
    "trust_pre_post_refresh_cache",
    "two_version_overlap_retirement",
    "expired_revoked_lease",
    "per_run_key_ephemerality_cleanup",
)


class EWriterRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_e_writer_refused")


@dataclass(frozen=True, slots=True)
class _PrivateFailure:
    """Bounded control outcome, never an exception or proof/acceptance result."""

    category: str = "refused"
    exit_code: int = 1


def _private_failure(error: BaseException) -> _PrivateFailure:
    """Detach completed private frames/chains before returning a safe outcome."""
    category = "refused"
    exit_code = 1
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, KeyboardInterrupt):
            category = "interrupt"
        elif isinstance(current, SystemExit) and category == "refused":
            category = "exit"
            if type(current.code) is int and 0 <= current.code <= 255:
                exit_code = current.code
        elif isinstance(current, CancelledError) and category == "refused":
            category = "cancelled"
        elif isinstance(current, GeneratorExit) and category == "refused":
            category = "generator"
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        for nested in (current.__cause__, current.__context__):
            if nested is not None:
                pending.append(nested)
        # Executing boundary frames cannot be cleared here; their own public
        # wrappers explicitly delete private arguments before a fresh raise.
        traceback.clear_frames(current.__traceback__)
        current.__traceback__ = None
        current.__cause__ = None
        current.__context__ = None
    return _PrivateFailure(category, exit_code)


def _raise_private_failure(failure: _PrivateFailure) -> NoReturn:
    if failure.category == "interrupt":
        raise KeyboardInterrupt
    if failure.category == "exit":
        raise SystemExit(failure.exit_code)
    if failure.category == "cancelled":
        raise CancelledError
    if failure.category == "generator":
        raise GeneratorExit
    raise EWriterRefused()


def _require(condition: bool) -> None:
    if not condition:
        raise EWriterRefused()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )
    return cast(str, value)


def _object(raw: bytes, names: str | None = None) -> dict[str, Any]:
    value = strict_object(raw, _CAP)
    _require(canonical(value) == raw)
    if names is not None:
        _require(set(value) == set(names.split()))
    return value


def _fields(value: object, names: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(names.split()))
    return cast(dict[str, Any], value)


def _decode(value: object) -> bytes:
    _require(type(value) is str)
    return base64.b64decode(cast(str, value), validate=True)


def _source_coordinates(raw: bytes) -> bytes:
    """Compare selected accepted facts, excluding per-host qualification wrappers."""
    value = _object(raw, "schema selection qualification retained observations")
    _require(value["schema"] == "Gate0EHistoricalSourceReferences.v1")
    selection = value["selection"]
    decisions = {}
    for name, decision in selection["decisions"].items():
        decisions[name] = {
            key: val for key, val in decision.items() if key != "retained_pin"
        }
        decisions[name]["retained_sha256"] = decision["retained_pin"]["sha256"]
    packets = []
    for packet in selection["packets"]:
        sources = []
        for source in packet["sources"]:
            selected = {
                key: val for key, val in source.items() if key != "retained_pin"
            }
            selected["retained_sha256"] = source["retained_pin"]["sha256"]
            sources.append(selected)
        packets.append({**packet, "sources": sources})
    return canonical(
        dict(
            policy_digest=selection["policy_digest"],
            repositories=selection["repositories"],
            decisions=decisions,
            packets=packets,
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class EPrivateInputs:
    """Independent original selection plus actual B-downloaded/decrypted bytes.

    No member confers provenance; installed owners authenticate these inputs.
    ``prerequisite_bytes`` is the exact independently selected evidence container.
    """

    producer: EProducerCoordinates
    source_bundle_digest: str
    prerequisite_bytes: bytes = field(repr=False)
    projection: bytes = field(repr=False)
    plaintext: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class PrivateEVerification:
    collection_digest: str
    prerequisite_digest: str
    producer_digest: str
    receipt_digest: str
    manifest_digest: str
    plaintext_digest: str
    ciphertext_digest: str
    projection_digest: str
    result: str = field(default="private_archive_and_proofs_verified", init=False)


def _verify_private_e_checked(
    archive: PrivateArchive, selection: ESelection, selected_inputs: EPrivateInputs
) -> PrivateEVerification | _PrivateFailure:
    try:
        return _verify_private_e_work(archive, selection, selected_inputs)
    except BaseException as error:
        return _private_failure(error)
    finally:
        del archive, selection, selected_inputs


def verify_private_e(
    archive: PrivateArchive, selection: ESelection, selected_inputs: EPrivateInputs
) -> PrivateEVerification:
    """Pure byte verification with a clean refusal boundary, never readiness."""
    result = _verify_private_e_checked(archive, selection, selected_inputs)
    del archive, selection, selected_inputs
    if isinstance(result, _PrivateFailure):
        _raise_private_failure(result)
    return result


def _verify_private_e_work(
    archive: PrivateArchive,
    selection: ESelection,
    selected_inputs: EPrivateInputs,
) -> PrivateEVerification:
    """Recheck exact actual archive/projection, proof, producer and dossier joins.

    Byte-only; B can reuse this without importing a publication owner. It neither
    refreshes historical trust nor creates readiness or opens an issuer window.
    """
    _require(type(archive) is PrivateArchive and type(selection) is ESelection)
    _require(type(selected_inputs) is EPrivateInputs)
    inputs = selected_inputs
    preparation_owner._join_selection(selection, inputs.producer)
    _hash(inputs.source_bundle_digest)
    actual = archive_owner.unpack_private_archive(inputs.plaintext)
    _require(actual.inner_manifest == archive.inner_manifest)
    _require(dict(actual.proof_files) == dict(archive.proof_files))
    files = archive.proof_files
    _require(set(files) == set(ARCHIVE_NAMES))
    _require(files["prerequisites.json"] == inputs.prerequisite_bytes)
    prerequisites = _object(
        inputs.prerequisite_bytes,
        "schema policy_digest campaign_digest source_bundle_digest "
        "historical_reference "
        "historical_reference_digest evidence coverage a9",
    )
    _require(prerequisites["schema"] == "Gate0EPrivatePrerequisites.v1")
    for key, expected in dict(
        policy_digest=selection.policy_digest,
        campaign_digest=selection.campaign_digest,
        source_bundle_digest=inputs.source_bundle_digest,
    ).items():
        _require(prerequisites[key] == expected)
    historical = _decode(prerequisites["historical_reference"])
    _require(_sha(historical) == prerequisites["historical_reference_digest"])
    _source_coordinates(historical)
    _require(set(prerequisites["coverage"]) == set(REQUIREMENTS))
    for record in prerequisites["evidence"].values():
        item = _fields(record, "digest bytes_base64")
        _require(_sha(_decode(item["bytes_base64"])) == item["digest"])
    for references in prerequisites["coverage"].values():
        _require(type(references) is list and len(references) > 0)
        _require(len(set(references)) == len(references))
        _require(all(ref in prerequisites["evidence"] for ref in references))
    _require(
        _decode(prerequisites["a9"]["collection.json"]) == files["collection.json"]
    )
    verified = verify_retained_collection(files["collection.json"], selection)
    _require(not verified.readiness_accepted)
    producer = canonical(
        dict(
            schema="Gate0EProducerSelection.v1",
            producer=inputs.producer.document(),
            source_bundle_digest=inputs.source_bundle_digest,
        )
    )
    receipt = canonical(
        dict(
            schema="Gate0ERetainedCollectionReceipt.v1",
            policy_digest=verified.policy_digest,
            collection_digest=verified.collection_digest,
            bundle_digests=list(verified.bundle_digests),
            root_record_digests=list(verified.root_record_digests),
            join_digests=list(verified.join_digests),
            result="retained_bytes_verified",
        )
    )
    _require(files["producer.json"] == producer and files["receipt.json"] == receipt)
    expected_manifest = canonical(
        dict(
            schema="Gate0EArchiveManifest.v1",
            files={
                name: dict(length=len(files[name]), sha256=_sha(files[name])[7:])
                for name in ARCHIVE_NAMES
            },
        )
    )
    _require(archive.inner_manifest == expected_manifest)
    projection = validate_encrypted_e_projection(inputs.projection)
    for key, projection_expected in dict(
        policy_digest=selection.policy_digest,
        campaign_digest=selection.campaign_digest,
        source_bundle_digest=inputs.source_bundle_digest,
        collection_digest=verified.collection_digest,
        plaintext_archive_digest=_sha(inputs.plaintext),
        inner_manifest_digest=_sha(archive.inner_manifest),
        ciphertext_digest=_sha(inputs.ciphertext),
        ciphertext_bytes=len(inputs.ciphertext),
        producer=inputs.producer.document(),
    ).items():
        _require(projection[key] == projection_expected)
    return PrivateEVerification(
        verified.collection_digest,
        _sha(inputs.prerequisite_bytes),
        _sha(producer),
        _sha(receipt),
        _sha(archive.inner_manifest),
        _sha(inputs.plaintext),
        _sha(inputs.ciphertext),
        _sha(inputs.projection),
    )


def _verify_a9_export_checked(
    manifest_bytes: bytes,
    files: dict[str, bytes],
    completion_bytes: bytes,
    *,
    campaign: str,
    lifecycle_binding: str,
    bootstrap_invocation: str,
    qualification_digest: str,
    owned_slots: tuple[str, ...],
) -> bytes | _PrivateFailure:
    try:
        return _verify_a9_export_work(
            manifest_bytes,
            files,
            completion_bytes,
            campaign=campaign,
            lifecycle_binding=lifecycle_binding,
            bootstrap_invocation=bootstrap_invocation,
            qualification_digest=qualification_digest,
            owned_slots=owned_slots,
        )
    except BaseException as error:
        return _private_failure(error)
    finally:
        del manifest_bytes, files, completion_bytes
        del (
            campaign,
            lifecycle_binding,
            bootstrap_invocation,
            qualification_digest,
            owned_slots,
        )


def verify_a9_export(
    manifest_bytes: bytes,
    files: dict[str, bytes],
    completion_bytes: bytes,
    *,
    campaign: str,
    lifecycle_binding: str,
    bootstrap_invocation: str,
    qualification_digest: str,
    owned_slots: tuple[str, ...],
) -> bytes:
    result = _verify_a9_export_checked(
        manifest_bytes,
        files,
        completion_bytes,
        campaign=campaign,
        lifecycle_binding=lifecycle_binding,
        bootstrap_invocation=bootstrap_invocation,
        qualification_digest=qualification_digest,
        owned_slots=owned_slots,
    )
    del manifest_bytes, files, completion_bytes
    del (
        campaign,
        lifecycle_binding,
        bootstrap_invocation,
        qualification_digest,
        owned_slots,
    )
    if isinstance(result, _PrivateFailure):
        _raise_private_failure(result)
    return result


def _verify_a9_export_work(
    manifest_bytes: bytes,
    files: dict[str, bytes],
    completion_bytes: bytes,
    *,
    campaign: str,
    lifecycle_binding: str,
    bootstrap_invocation: str,
    qualification_digest: str,
    owned_slots: tuple[str, ...],
) -> bytes:
    """Interpret the actual export schemas; authentication belongs to installation."""
    manifest = _object(
        manifest_bytes,
        "schema lifecycle_binding_digest campaign_digest bootstrap_invocation_id "
        "files result",
    )
    _require(manifest["schema"] == "Gate0A9PrivateCollectionExport.v1")
    _require(manifest["result"] == "retained_bytes_exported")
    _require(manifest["campaign_digest"] == campaign)
    _require(manifest["lifecycle_binding_digest"] == lifecycle_binding)
    _require(manifest["bootstrap_invocation_id"] == bootstrap_invocation)
    _require(
        set(files)
        == {
            "collection.json",
            "collector-retirement.json",
            "owned-files-retirement.json",
        }
    )
    _require(set(manifest["files"]) == set(files))
    for name, raw in files.items():
        _require(manifest["files"][name] == dict(bytes=len(raw), digest=_sha(raw)))
    process = _object(
        files["collector-retirement.json"],
        "schema campaign_digest invocation_id original_pid original_start "
        "original_cgroup manager retirement normal",
    )
    _require(process["schema"] == "Gate0A9CollectorRetirementObservation.v1")
    _require(process["campaign_digest"] == campaign and process["normal"] is True)
    for key in ("original_pid", "original_start"):
        _require(type(process[key]) is int and process[key] > 0)
    _require(
        type(process["invocation_id"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", process["invocation_id"]) is not None
    )
    manager = process["manager"]
    for key, expected in dict(
        Result="success", ExecMainCode="1", ExecMainStatus="0", ActiveState="inactive"
    ).items():
        _require(manager[key] == expected)
    _require(
        process["retirement"]
        in ("observed_populated_zero", "manager_retired_control_group")
    )
    if process["retirement"] == "manager_retired_control_group":
        _require(manager["ControlGroup"] == "")
    _require(manager["InvocationID"] == process["invocation_id"])
    owned = _object(
        files["owned-files-retirement.json"],
        "schema lifecycle_binding_digest campaign_digest boot_id "
        "original_deadline_microseconds process_retirement_observation_digest files "
        "result",
    )
    _require(
        owned["schema"] == "Gate0A9OwnedFilesRetirement.v1"
        and owned["result"] == "owned_files_retired"
    )
    _require(
        owned["campaign_digest"] == campaign
        and owned["lifecycle_binding_digest"] == lifecycle_binding
    )
    _require(
        owned["process_retirement_observation_digest"]
        == _sha(files["collector-retirement.json"])
    )
    records = owned["files"]
    _require(
        type(records) is list
        and len(records) == len(owned_slots)
        and len(set(owned_slots)) == len(owned_slots)
    )
    _require(sorted(record["slot"] for record in records) == sorted(owned_slots))
    for record in records:
        item = _fields(
            record, "slot device inode read_before_unlink unlinked absent_after_unlink"
        )
        _require(
            all(
                item[key] is True
                for key in ("read_before_unlink", "unlinked", "absent_after_unlink")
            )
        )
        _require(type(item["inode"]) is int and item["inode"] > 0)
        _require(type(item["device"]) is int and item["device"] >= 0)
    completion = _object(
        completion_bytes,
        "schema campaign_digest qualification_digest bootstrap_manager_observation "
        "timer socket_binding manager_observations retirement "
        "original_cutoff_microseconds result",
    )
    _require(completion["schema"] == "Gate0A9ManagerCompletion.v1")
    _require(
        completion["campaign_digest"] == campaign
        and completion["qualification_digest"] == qualification_digest
    )
    _require(completion["result"] == "normal_collector_retired")
    observations = completion["manager_observations"]
    _require(type(observations) is list and len(observations) == 2)
    _require(
        all(item["InvocationID"] == process["invocation_id"] for item in observations)
    )
    _require(observations[0]["MainPID"] == str(process["original_pid"]))
    for key, expected in dict(
        ActiveState="inactive",
        SubState="dead",
        MainPID="0",
        Result="success",
        ExecMainCode="1",
        ExecMainStatus="0",
    ).items():
        _require(observations[1][key] == expected)
    _require(
        completion["retirement"]
        in ("observed_populated_zero", "manager_retired_control_group")
    )
    # Exact bootstrap identity lives in the qualified bootstrap observation.
    _require(
        completion["bootstrap_manager_observation"]["bootstrap"]["InvocationID"]
        == bootstrap_invocation
    )
    return files["collection.json"]


class InstalledEWriter:
    """Fixed protected installation. There is no caller-selected loader path."""

    def __init__(
        self,
        seal: object,
        document: dict[str, Any],
        retained: dict[str, bytes],
        selection: ESelection,
    ) -> None:
        _require(seal is _SEAL)
        self._document, self._retained, self.selection = document, retained, selection
        self.producer = EProducerCoordinates(**document["producer"])
        self._used = False

    @classmethod
    def from_installed(cls) -> InstalledEWriter:
        result = cls._from_installed_checked()
        if isinstance(result, _PrivateFailure):
            _raise_private_failure(result)
        return result

    @classmethod
    def _from_installed_checked(cls) -> InstalledEWriter | _PrivateFailure:
        try:
            return cls._from_installed_work()
        except BaseException as error:
            return _private_failure(error)

    @classmethod
    def _from_installed_work(cls) -> InstalledEWriter:
        raw = _protected(_INSTALLATION, _CAP)
        doc = _object(
            raw,
            "schema operation policy_digest campaign_digest "
            "source_bundle_digest source cases withdrawal_reference environment "
            "producer historical_reference evidence coverage a9 gpg "
            "qualification publication",
        )
        _require(doc["schema"] == "Gate0EWriterInstallation.v1")
        _require(doc["operation"] in ("prepare", "publish", "verify_published"))
        binding = _object(
            _protected(_BINDING, 65536),
            "schema installation_digest qualification_digest runtime_uid owners "
            "native_receipt",
        )
        _require(
            binding["schema"] == "Gate0EWriterBinding.v1"
            and binding["installation_digest"] == _sha(raw)
        )
        _require(
            type(binding["runtime_uid"]) is int
            and os.getuid() == os.geteuid() == binding["runtime_uid"]
        )
        owners = {
            "writer": __file__,
            "proof": proof_owner.__file__,
            "archive": archive_owner.__file__,
            "preparation": preparation_owner.__file__,
            "historical": historical_owner.__file__,
            "github": github_owner.__file__,
            "release": release_owner.__file__,
            "handoff": handoff_owner.__file__,
            "framing": framing_owner.__file__,
        }
        _require(set(binding["owners"]) == set(owners))
        for key, path in owners.items():
            _require(
                binding["owners"][key]
                == _sha(_protected(os.path.abspath(path), _CAP, private=False))
            )
        retained: dict[str, bytes] = {}

        def pin(value: object) -> bytes:
            item = _fields(value, "path digest")
            path = item["path"]
            _require(type(path) is str and path.startswith(_RETAINED))
            _require(all(part not in ("", ".", "..") for part in path[1:].split("/")))
            if path not in retained:
                retained[path] = _protected(path, _CAP)
            _require(_sha(retained[path]) == _hash(item["digest"]))
            _require(sum(map(len, retained.values())) <= 4 * _CAP)
            return retained[path]

        qual_raw = pin(doc["qualification"])
        _require(_sha(qual_raw) == binding["qualification_digest"])
        qual = _object(
            qual_raw,
            "schema selection_digest policy_digest runtime_uid owner_digests "
            "native_receipt decision_provenance",
        )
        _require(qual["schema"] == "Gate0EWriterQualification.v1")
        _require(
            qual["selection_digest"]
            == _sha(
                canonical(
                    {key: value for key, value in doc.items() if key != "qualification"}
                )
            )
        )
        _require(
            qual["policy_digest"] == doc["policy_digest"]
            and qual["runtime_uid"] == binding["runtime_uid"]
        )
        _require(
            qual["owner_digests"] == binding["owners"]
            and qual["native_receipt"] == binding["native_receipt"]
        )
        native = _object(
            pin(binding["native_receipt"]),
            "schema qualification_measurements_digest runtime_identity_digest "
            "reviewer_record_digest",
        )
        _require(native["schema"] == "Gate0ENativeReviewReceipt.v1")
        for key in (
            "qualification_measurements_digest",
            "runtime_identity_digest",
            "reviewer_record_digest",
        ):
            _require(
                type(native[key]) is str
                and re.fullmatch(r"[0-9a-f]{64}", native[key]) is not None
            )
        pin(qual["decision_provenance"])

        def trust(value: object) -> EPublicTrust:
            item = _fields(
                value,
                "key_id public_key record minimum_version source_ref "
                "qualification_digest",
            )
            return EPublicTrust(
                item["key_id"],
                pin(item["public_key"]),
                pin(item["record"]),
                item["minimum_version"],
                item["source_ref"],
                item["qualification_digest"],
            )

        _require(type(doc["cases"]) is list and len(doc["cases"]) == 2)
        cases = []
        for value in doc["cases"]:
            case = _fields(
                value,
                "shared_packet frozen_window command_id roots issuer_trust "
                "attester_trust",
            )
            _require(type(case["roots"]) is list and len(case["roots"]) == 2)
            roots = tuple(RootHostBinding(pin(root)) for root in case["roots"])
            cases.append(
                ERetainedCase(
                    pin(case["shared_packet"]),
                    pin(case["frozen_window"]),
                    case["command_id"],
                    cast(tuple[RootHostBinding, RootHostBinding], roots),
                    trust(case["issuer_trust"]),
                    trust(case["attester_trust"]),
                )
            )
        selection = ESelection(
            doc["policy_digest"],
            doc["campaign_digest"],
            ESourcePins(**doc["source"]),
            cast(tuple[ERetainedCase, ERetainedCase], tuple(cases)),
            doc["withdrawal_reference"],
            doc["environment"],
        )
        _hash(doc["source_bundle_digest"])
        preparation_owner._join_selection(
            selection, EProducerCoordinates(**doc["producer"])
        )
        pin(doc["historical_reference"])
        _require(set(doc["coverage"]) == set(REQUIREMENTS))
        _require(type(doc["evidence"]) is dict and 0 < len(doc["evidence"]) <= 64)
        for value in doc["evidence"].values():
            pin(value)
        for references in doc["coverage"].values():
            _require(type(references) is list and 0 < len(references) <= 64)
            _require(
                len(references) == len(set(references))
                and all(ref in doc["evidence"] for ref in references)
            )
        a9 = _fields(
            doc["a9"],
            "manifest files completion lifecycle_binding_digest "
            "bootstrap_invocation_id qualification_digest owned_slots",
        )
        _require(
            set(a9["files"])
            == {
                "collection.json",
                "collector-retirement.json",
                "owned-files-retirement.json",
            }
        )
        for name, value in a9["files"].items():
            _require(value["path"] == _EXPORT + name)
        _require(a9["manifest"]["path"] == _EXPORT + "manifest.json")
        _hash(a9["lifecycle_binding_digest"])
        _hash(a9["qualification_digest"])
        _require(
            re.fullmatch(r"[0-9a-f]{32}", a9["bootstrap_invocation_id"]) is not None
        )
        _require(type(a9["owned_slots"]) is list and len(a9["owned_slots"]) > 0)
        pin(a9["completion"])
        gpg = _fields(
            doc["gpg"],
            "executable executable_sha256 version_line public_key "
            "public_key_sha256 primary_fingerprint encryption_fingerprint",
        )
        pin(gpg["public_key"])
        if doc["operation"] == "prepare":
            _require(doc["publication"] is None)
        else:
            publication = _fields(
                doc["publication"],
                "summary contract decision provenance reviewer_id "
                "environment_id display_title projection "
                "private_prerequisites private_collection "
                "run reader_selection_digest",
            )
            for key in (
                "summary",
                "contract",
                "decision",
                "provenance",
                "projection",
                "private_prerequisites",
                "private_collection",
            ):
                pin(publication[key])
            selected_run = _fields(
                publication["run"],
                "repository_id owner_id workflow_id run_id attempt job_id "
                "source_revision workflow_digest",
            )
            EProducerCoordinates(
                **{
                    key: value
                    for key, value in selected_run.items()
                    if key != "workflow_digest"
                }
            )
            _hash(selected_run["workflow_digest"])
            _hash(publication["reader_selection_digest"])
            _require(publication["provenance"] == qual["decision_provenance"])
            for key in ("reviewer_id", "environment_id"):
                _require(type(publication[key]) is int and publication[key] > 0)
            # These exact bytes are selected by actual native qualification;
            # neither this document nor an accepted boolean authenticates them.
        return cls(_SEAL, doc, retained, selection)

    def _discard_private_state(self) -> None:
        """Invalidate this consumed owner and detach all private installed inputs."""
        self.__dict__.clear()
        self._used = True

    def _selected(self, pin: dict[str, Any]) -> bytes:
        raw = self._retained[pin["path"]]
        _require(_sha(raw) == pin["digest"])
        return raw

    def _producer_join(
        self,
        reads: InstalledGate0GitHubReads,
        facts: ProducerFacts,
        stage: ProducerStage,
    ) -> None:
        _require(
            type(reads) is InstalledGate0GitHubReads
            and type(facts) is ProducerFacts
            and reads.owns_facts(facts)
        )
        _require(facts.stage == stage)
        for key, expected in self.producer.document().items():
            if key == "job_id":
                _require(reads.selected_job(facts).id == expected)
            else:
                _require(
                    getattr(facts, "head_sha" if key == "source_revision" else key)
                    == expected
                )

        _require(
            "sha256:" + facts.workflow_source.bytes_sha256
            == self.selection.source.workflow_digest
            and _sha(facts.workflow_source.raw_bytes)
            == self.selection.source.workflow_digest
            and facts.workflow_source.commit == self.selection.source.workflow_revision
        )

    def _publication_join(
        self, reads: InstalledGate0GitHubReads, facts: PublicationFacts
    ) -> None:
        _require(
            type(reads) is InstalledGate0GitHubReads
            and type(facts) is PublicationFacts
            and reads.owns_facts(facts)
        )
        pins = self._document["publication"]
        _require(pins is not None)
        expected = pins["run"]
        _require(
            "sha256:" + reads.installed_selection_digest
            == pins["reader_selection_digest"]
        )
        _require(
            facts.run.workflow_source.commit == expected["source_revision"]
            and _sha(facts.run.workflow_source.raw_bytes) == expected["workflow_digest"]
        )
        actual: object
        for key, value in expected.items():
            if key == "job_id":
                actual = reads.selected_job(facts).id
            elif key == "source_revision":
                actual = facts.run.head_sha
            elif key == "workflow_digest":
                actual = "sha256:" + facts.run.workflow_source.bytes_sha256
            else:
                actual = getattr(facts.run, key)
            _require(type(actual) is type(value) and actual == value)

    def prepare(self, *, deadline: float) -> None:
        result = self._prepare_checked(deadline=deadline)
        del self, deadline
        if isinstance(result, _PrivateFailure):
            _raise_private_failure(result)

    def _prepare_checked(self, *, deadline: float) -> None | _PrivateFailure:
        try:
            self._prepare_work(deadline=deadline)
            return None
        except BaseException as error:
            self._discard_private_state()
            return _private_failure(error)
        finally:
            del self, deadline

    def _prepare_work(self, *, deadline: float) -> None:
        _require(not self._used and self._document["operation"] == "prepare")
        self._used = True
        _require(time.monotonic() < deadline)
        doc, a9 = self._document, self._document["a9"]

        def export_pin(value: dict[str, Any]) -> bytes:
            raw = _protected(value["path"], _CAP, private=False)
            _require(_sha(raw) == value["digest"])
            return raw

        manifest = export_pin(a9["manifest"])
        files = {name: export_pin(value) for name, value in a9["files"].items()}
        completion = self._selected(a9["completion"])
        collection = verify_a9_export(
            manifest,
            files,
            completion,
            campaign=self.selection.campaign_digest,
            lifecycle_binding=a9["lifecycle_binding_digest"],
            bootstrap_invocation=a9["bootstrap_invocation_id"],
            qualification_digest=a9["qualification_digest"],
            owned_slots=tuple(a9["owned_slots"]),
        )
        historical = InstalledHistoricalSourceReads.from_installed()
        facts = historical.verify(deadline=deadline)
        _require(historical.owns_facts(facts))
        _require("sha256:" + facts.source_policy_digest == doc["policy_digest"])
        _require(
            _source_coordinates(facts.reference_bytes)
            == _source_coordinates(self._selected(doc["historical_reference"]))
        )
        reads = InstalledGate0GitHubReads.from_installed()
        producer = reads.producer_snapshot(ProducerStage.COLLECTION_SNAPSHOT)
        self._producer_join(reads, producer, ProducerStage.COLLECTION_SNAPSHOT)
        prerequisites = canonical(
            dict(
                schema="Gate0EPrivatePrerequisites.v1",
                policy_digest=doc["policy_digest"],
                campaign_digest=doc["campaign_digest"],
                source_bundle_digest=doc["source_bundle_digest"],
                historical_reference=base64.b64encode(facts.reference_bytes).decode(
                    "ascii"
                ),
                historical_reference_digest=_sha(facts.reference_bytes),
                evidence={
                    name: dict(
                        digest=_sha(self._selected(pin)),
                        bytes_base64=base64.b64encode(self._selected(pin)).decode(
                            "ascii"
                        ),
                    )
                    for name, pin in doc["evidence"].items()
                },
                coverage=doc["coverage"],
                a9={
                    name: base64.b64encode(raw).decode("ascii")
                    for name, raw in {
                        **files,
                        "manifest.json": manifest,
                        "manager-completion.json": completion,
                    }.items()
                },
            )
        )
        profile = dict(doc["gpg"])
        profile["public_key"] = self._selected(profile["public_key"])
        profile["executable"] = Path(profile["executable"])
        encrypted = prepare_encrypted_e(
            collection,
            self.selection,
            self.producer,
            doc["source_bundle_digest"],
            prerequisites,
            GpgArchiveProfile(**profile),
            deadline=deadline,
        )
        _require(time.monotonic() < deadline)
        _stage(
            {
                "gate0-evidence.pgp": encrypted.ciphertext,
                "gate0-evidence-public.json": encrypted.projection,
            }
        )

    def _receipt_document(
        self,
        release: DraftReleaseFacts | DownloadedReleaseFacts,
        publication: PublicationFacts,
    ) -> bytes:
        """Private implementation shared by prepublication and final readback."""
        doc, pins = self._document, self._document["publication"]
        _require(pins is not None)
        summary_raw = self._selected(pins["summary"])
        summary = _object(
            summary_raw,
            "schema repository_id release_id ciphertext_asset_id "
            "projection_asset_id producer "
            "ciphertext_digest plaintext_digest manifest_digest private_receipt_digest "
            "projection_digest policy_digest private_verification_record_digest "
            "holder_source_digest holder_profile_digest result",
        )
        _require(summary["schema"] == "Gate0EBArchiveVerification.v1")
        _require(summary["result"] == "private_archive_and_proofs_verified")
        _require(type(summary["producer"]) is dict)
        EProducerCoordinates(**summary["producer"])
        for key in (
            "repository_id",
            "release_id",
            "ciphertext_asset_id",
            "projection_asset_id",
        ):
            _require(type(summary[key]) is int and summary[key] > 0)
        _require(summary["ciphertext_asset_id"] != summary["projection_asset_id"])
        _require(summary["producer"] == self.producer.document())
        _require(summary["policy_digest"] == self.selection.policy_digest)
        for key in (
            "ciphertext_digest",
            "plaintext_digest",
            "manifest_digest",
            "private_receipt_digest",
            "projection_digest",
            "policy_digest",
            "private_verification_record_digest",
            "holder_source_digest",
            "holder_profile_digest",
        ):
            _hash(summary[key])
        provenance = _object(
            self._selected(pins["provenance"]),
            "schema contract_digest decision_digest reviewer_id native_receipt_digest",
        )
        _require(provenance["schema"] == "Gate0EPublicationDecisionProvenance.v1")
        _require(
            provenance["contract_digest"] == _sha(self._selected(pins["contract"]))
        )
        _require(
            provenance["decision_digest"] == _sha(self._selected(pins["decision"]))
        )
        _require(type(provenance["reviewer_id"]) is int)
        _require(provenance["reviewer_id"] == pins["reviewer_id"])
        _hash(provenance["native_receipt_digest"])
        qualification = _object(self._selected(doc["qualification"]))
        _require(
            provenance["native_receipt_digest"]
            == qualification["native_receipt"]["digest"]
        )
        contract = _object(self._selected(pins["contract"]), "schema meaning")
        _require(
            contract
            == dict(
                schema="Gate0EPublicationReviewContract.v1",
                meaning="digest_bound_b_verification_publication_review",
            )
        )
        # These bytes only describe a source candidate. Actual provenance is
        # supplied by the independent root/native qualification checked at load.
        review = publication.run.review
        _require(
            review.reviewer_id == pins["reviewer_id"] and review.state == "approved"
        )
        _require(review.environment_ids == (pins["environment_id"],))
        _require(review.environment_names == (self.selection.environment,))
        _require(publication.display_title == pins["display_title"])
        expected_title = (
            f"Gate0 E publication summary {_sha(summary_raw)[7:]} "
            f"draft {release.release_id} producer {self.producer.run_id}"
        )
        _require(publication.display_title == expected_title)
        _require(
            publication.selected_summary_digest
            in (_sha(summary_raw), _sha(summary_raw)[7:])
        )
        _require(publication.review_response_digest == review.observation_sha256)
        _require(
            publication.run.run_id != self.producer.run_id
            and publication.run.attempt == 1
        )
        _require(publication.run.repository_id == self.producer.repository_id)
        _require(publication.run.owner_id == self.producer.owner_id)
        _require(release.repository_id == self.producer.repository_id)
        _require(release.owner_id == self.producer.owner_id)
        _require(
            summary["repository_id"] == release.repository_id
            and summary["release_id"] == release.release_id
        )
        assets = {asset.name: asset for asset in release.assets}
        _require(len(assets) == len(release.assets))
        for name, id_key, digest_key in (
            ("gate0-evidence.pgp", "ciphertext_asset_id", "ciphertext_digest"),
            ("gate0-evidence-public.json", "projection_asset_id", "projection_digest"),
        ):
            asset = assets[name]
            _require(
                asset.id == summary[id_key]
                and _sha(asset.raw_bytes) == summary[digest_key]
            )
            _require(
                asset.size == len(asset.raw_bytes)
                and asset.sha256 == _sha(asset.raw_bytes)[7:]
            )
        projection_raw = self._selected(pins["projection"])
        _require(projection_raw == assets["gate0-evidence-public.json"].raw_bytes)
        projection = validate_encrypted_e_projection(projection_raw)
        for key, expected in dict(
            policy_digest=self.selection.policy_digest,
            campaign_digest=self.selection.campaign_digest,
            source_bundle_digest=doc["source_bundle_digest"],
            producer=self.producer.document(),
            ciphertext_digest=summary["ciphertext_digest"],
            plaintext_archive_digest=summary["plaintext_digest"],
            inner_manifest_digest=summary["manifest_digest"],
        ).items():
            _require(projection[key] == expected)
        prerequisites_raw = self._selected(pins["private_prerequisites"])
        prerequisites = _object(
            prerequisites_raw,
            "schema policy_digest campaign_digest source_bundle_digest "
            "historical_reference historical_reference_digest evidence coverage a9",
        )
        _require(prerequisites["schema"] == "Gate0EPrivatePrerequisites.v1")
        _require(prerequisites["coverage"] == doc["coverage"])
        _require(set(prerequisites["evidence"]) == set(doc["evidence"]))
        for name, pin in doc["evidence"].items():
            actual = self._selected(pin)
            _require(
                prerequisites["evidence"][name]
                == dict(
                    digest=_sha(actual),
                    bytes_base64=base64.b64encode(actual).decode("ascii"),
                )
            )
        historical_raw = _decode(prerequisites["historical_reference"])
        _require(prerequisites["historical_reference_digest"] == _sha(historical_raw))
        _require(
            _source_coordinates(historical_raw)
            == _source_coordinates(self._selected(doc["historical_reference"]))
        )
        for key in ("policy_digest", "campaign_digest", "source_bundle_digest"):
            _require(prerequisites[key] == doc[key])
        collection_raw = self._selected(pins["private_collection"])
        verified = verify_retained_collection(collection_raw, self.selection)
        producer_raw = canonical(
            dict(
                schema="Gate0EProducerSelection.v1",
                producer=self.producer.document(),
                source_bundle_digest=doc["source_bundle_digest"],
            )
        )
        inner_receipt = canonical(
            dict(
                schema="Gate0ERetainedCollectionReceipt.v1",
                policy_digest=verified.policy_digest,
                collection_digest=verified.collection_digest,
                bundle_digests=list(verified.bundle_digests),
                root_record_digests=list(verified.root_record_digests),
                join_digests=list(verified.join_digests),
                result="retained_bytes_verified",
            )
        )
        payloads = {
            "collection.json": collection_raw,
            "producer.json": producer_raw,
            "prerequisites.json": prerequisites_raw,
            "receipt.json": inner_receipt,
        }
        manifest = canonical(
            dict(
                schema="Gate0EArchiveManifest.v1",
                files={
                    name: dict(
                        length=len(payloads[name]), sha256=_sha(payloads[name])[7:]
                    )
                    for name in ARCHIVE_NAMES
                },
            )
        )
        # Deterministic existing archive owner, no alternate tar/envelope.
        plaintext = archive_owner._pack(manifest, payloads)
        private_result = verify_private_e(
            archive_owner.unpack_private_archive(plaintext),
            self.selection,
            EPrivateInputs(
                self.producer,
                doc["source_bundle_digest"],
                prerequisites_raw,
                projection_raw,
                plaintext,
                assets["gate0-evidence.pgp"].raw_bytes,
            ),
        )
        _require(private_result.receipt_digest == summary["private_receipt_digest"])
        _require(private_result.manifest_digest == summary["manifest_digest"])
        _require(private_result.plaintext_digest == summary["plaintext_digest"])
        target = (
            release.target_commitish
            if type(release) is DraftReleaseFacts
            else cast(DownloadedReleaseFacts, release).peeled_commit
        )
        _require(target == self.producer.source_revision)
        return canonical(
            dict(
                schema="Gate0ReadinessReceipt.v1",
                policy_digest=self.selection.policy_digest,
                campaign_digest=self.selection.campaign_digest,
                source_bundle_digest=doc["source_bundle_digest"],
                collection_digest=projection["collection_digest"],
                private_prerequisite_digest=_sha(prerequisites_raw),
                producer=self.producer.document(),
                source_reference_digest=_sha(historical_raw),
                operational_evidence_digest=_sha(
                    canonical(
                        {name: pin["digest"] for name, pin in doc["evidence"].items()}
                    )
                ),
                b_summary_digest=_sha(summary_raw),
                b_holder_profile_digest=summary["holder_profile_digest"],
                b_verification_record_digest=summary[
                    "private_verification_record_digest"
                ],
                publication=dict(
                    repository_id=publication.run.repository_id,
                    run_id=publication.run.run_id,
                    attempt=publication.run.attempt,
                    workflow_id=publication.run.workflow_id,
                    source_revision=publication.run.head_sha,
                    workflow_digest=publication.run.workflow_source.bytes_sha256,
                    reviewer_id=review.reviewer_id,
                    environment_id=pins["environment_id"],
                    review_response_digest=publication.review_response_digest,
                ),
                draft=dict(
                    repository_id=release.repository_id,
                    release_id=release.release_id,
                    tag=release.tag,
                    target_commit=target,
                    assets=[
                        dict(
                            id=assets[name].id,
                            name=name,
                            digest=_sha(assets[name].raw_bytes),
                        )
                        for name in ("gate0-evidence.pgp", "gate0-evidence-public.json")
                    ],
                ),
                result="candidate_independent_readiness_verified",
            )
        )

    def construct_receipt(
        self,
        draft_reads: InstalledGate0GitHubReads,
        draft: DraftReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
    ) -> bytes:
        result = self._construct_receipt_checked(
            draft_reads, draft, publication_reads, publication
        )
        del self, draft_reads, draft, publication_reads, publication
        if isinstance(result, _PrivateFailure):
            _raise_private_failure(result)
        return result

    def _construct_receipt_checked(
        self,
        draft_reads: InstalledGate0GitHubReads,
        draft: DraftReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
    ) -> bytes | _PrivateFailure:
        try:
            return self._construct_receipt_work(
                draft_reads, draft, publication_reads, publication
            )
        except BaseException as error:
            self._discard_private_state()
            return _private_failure(error)
        finally:
            del self, draft_reads, draft, publication_reads, publication

    def _construct_receipt_work(
        self,
        draft_reads: InstalledGate0GitHubReads,
        draft: DraftReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
    ) -> bytes:
        """Sole receipt constructor; returns bytes for the separate mutation owner."""
        _require(not self._used and self._document["operation"] == "publish")
        self._used = True
        _require(
            type(draft_reads) is InstalledGate0GitHubReads
            and type(draft) is DraftReleaseFacts
        )
        _require(draft_reads.owns_facts(draft) and draft.draft is True)
        _require(len(draft.assets) == 2)
        _require(
            type(publication_reads) is InstalledGate0GitHubReads
            and type(publication) is PublicationFacts
        )
        self._publication_join(publication_reads, publication)
        _require(publication.run.stage == ProducerStage.COLLECTION_SNAPSHOT)
        return self._receipt_document(draft, publication)

    def verify_published(
        self,
        release_reads: InstalledGate0GitHubReads,
        release: DownloadedReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
        producer_reads: InstalledGate0GitHubReads,
        producer: ProducerFacts,
    ) -> PublishedEVerification:
        result = self._verify_published_checked(
            release_reads,
            release,
            publication_reads,
            publication,
            producer_reads,
            producer,
        )
        del (
            self,
            release_reads,
            release,
            publication_reads,
            publication,
            producer_reads,
            producer,
        )
        if isinstance(result, _PrivateFailure):
            _raise_private_failure(result)
        return result

    def _verify_published_checked(
        self,
        release_reads: InstalledGate0GitHubReads,
        release: DownloadedReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
        producer_reads: InstalledGate0GitHubReads,
        producer: ProducerFacts,
    ) -> PublishedEVerification | _PrivateFailure:
        try:
            return self._verify_published_work(
                release_reads,
                release,
                publication_reads,
                publication,
                producer_reads,
                producer,
            )
        except BaseException as error:
            self._discard_private_state()
            return _private_failure(error)
        finally:
            del (
                self,
                release_reads,
                release,
                publication_reads,
                publication,
                producer_reads,
                producer,
            )

    def _verify_published_work(
        self,
        release_reads: InstalledGate0GitHubReads,
        release: DownloadedReleaseFacts,
        publication_reads: InstalledGate0GitHubReads,
        publication: PublicationFacts,
        producer_reads: InstalledGate0GitHubReads,
        producer: ProducerFacts,
    ) -> PublishedEVerification:
        """After completed publication; invoke the official verifier here directly."""
        _require(not self._used and self._document["operation"] == "verify_published")
        self._used = True
        _require(
            type(release_reads) is InstalledGate0GitHubReads
            and type(release) is DownloadedReleaseFacts
        )
        _require(
            release_reads.owns_facts(release)
            and release.draft is False
            and release.immutable is True
        )
        _require(
            type(publication_reads) is InstalledGate0GitHubReads
            and type(publication) is PublicationFacts
        )
        self._publication_join(publication_reads, publication)
        _require(publication.run.stage == ProducerStage.PRODUCER_RUN_COMPLETE)
        _require(
            publication.run.status == "completed"
            and publication.run.conclusion == "success"
        )
        self._producer_join(
            producer_reads, producer, ProducerStage.PRODUCER_RUN_COMPLETE
        )
        _require(producer.status == "completed" and producer.conclusion == "success")
        expected = self._receipt_document(release, publication)
        assets = {asset.name: asset for asset in release.assets}
        _require(
            set(assets)
            == {
                "gate0-evidence.pgp",
                "gate0-evidence-public.json",
                "gate0-readiness-receipt.json",
            }
        )
        _require(
            len(release.assets) == 3
            and len({asset.id for asset in release.assets}) == 3
        )
        receipt = assets["gate0-readiness-receipt.json"]
        _require(receipt.raw_bytes == expected)
        assertion = InstalledGhReleaseVerifier.from_installed().verify_published(
            release_reads, release
        )
        return PublishedEVerification(
            _sha(expected),
            receipt.id,
            release.repository_id,
            release.release_id,
            release.tag,
            release.raw_tag_sha,
            release.peeled_commit,
            tuple(
                (asset.id, asset.name, _sha(asset.raw_bytes))
                for asset in release.assets
            ),
            _sha(self._selected(self._document["publication"]["summary"])),
            producer.run_id,
            publication.run.run_id,
            publication.review_response_digest,
            assertion.gh_sha256,
            assertion.qualification_sha256,
            tuple(command.sha256 for command in assertion.commands),
        )


@dataclass(frozen=True, slots=True)
class PublishedEVerification:
    receipt_digest: str
    receipt_asset_id: int
    repository_id: int
    release_id: int
    tag: str
    raw_tag_sha: str
    peeled_commit: str
    assets: tuple[tuple[int, str, str], ...]
    summary_digest: str
    producer_run_id: int
    publication_run_id: int
    review_response_digest: str
    gh_digest: str
    gh_qualification_digest: str
    gh_command_digests: tuple[str, ...]


def _stage(files: dict[str, bytes]) -> None:
    """Create-only fixed private outputs; retain partial attempt on any failure."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in _STAGING.strip("/").split("/"):
            new = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = new
            info = os.fstat(descriptor)
            _require(info.st_uid == 0 and not info.st_mode & 0o022)
        _require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o700)
        _require(not os.listdir(descriptor))
        for name, raw in files.items():
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    _require(written > 0)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_installed_prepare_e() -> int:
    try:
        InstalledEWriter.from_installed().prepare(deadline=time.monotonic() + 180)
        print("E_FINALIZATION_COMPLETE")
        return 0
    except Exception:
        return 3
