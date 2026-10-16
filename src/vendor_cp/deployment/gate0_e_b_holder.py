"""Concrete Mac B custody verification; no acceptance or publication authority."""

from __future__ import annotations

import hashlib
import math
import os
import pwd
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from vendor_cp.deployment import gate0_e_archive as archive
from vendor_cp.deployment import gate0_e_finalization as proof
from vendor_cp.deployment import gate0_e_github as github
from vendor_cp.deployment import gate0_e_preparation as preparation
from vendor_cp.deployment import gate0_e_source_references as historical
from vendor_cp.deployment import gate0_e_writer as writer
from vendor_cp.deployment import gate0_framing as framing
from vendor_cp.deployment import gate0_runner_handoff as handoff
from vendor_cp.deployment.gate0_e_finalization import (
    EPublicTrust,
    ERetainedCase,
    ESelection,
    ESourcePins,
)
from vendor_cp.deployment.gate0_e_preparation import (
    EProducerCoordinates,
    validate_encrypted_e_projection,
)
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_handoff import RootHostBinding

_INSTALLATION = "/Library/Application Support/Dotmac/Gate0E/B/installation.json"
_BINDING = "/Library/Preferences/io.dotmac.gate0-e-b-binding.json"
_RECORD_ROOT = "/Library/Application Support/Dotmac/Gate0E/B/"
_SEAL = object()
_CAP = 16 * 1024 * 1024


class BHolderRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_e_b_holder_refused")


def _require(condition: bool) -> None:
    if not condition:
        raise BHolderRefused()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(raw: bytes, names: str | None = None) -> dict[str, Any]:
    value = strict_object(raw, _CAP)
    _require(canonical(value) == raw)
    if names is not None:
        _require(set(value) == set(names.split()))
    return value


def _fields(value: object, names: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == set(names.split()))
    return cast(dict[str, Any], value)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def _walk(
    path: str,
    uid: int,
    user_boundary: str | None,
    *,
    kind: str = "file",
    private: bool = False,
    read: bool = False,
    maximum: int = _CAP,
) -> tuple[tuple[int, int, int, int], bytes]:
    """Mac-compatible nofollow walk, root prefix and exact private-user boundary.

    Socket/keyring observations are metadata only. No /proc or secret-key read.
    """
    _require(
        path.startswith("/")
        and all(part not in ("", ".", "..") for part in path[1:].split("/"))
    )
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path[1:].split("/")
        current = ""
        for index, part in enumerate(parts):
            current += "/" + part
            expected_uid = (
                uid
                if user_boundary
                and (
                    current == user_boundary or current.startswith(user_boundary + "/")
                )
                else 0
            )
            info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            _require(
                not stat.S_ISLNK(info.st_mode)
                and info.st_uid == expected_uid
                and not info.st_mode & 0o022
            )
            if index == len(parts) - 1:
                _require(
                    (kind == "file" and stat.S_ISREG(info.st_mode))
                    or (kind == "directory" and stat.S_ISDIR(info.st_mode))
                    or (kind == "socket" and stat.S_ISSOCK(info.st_mode))
                )
                if private:
                    _require(
                        stat.S_IMODE(info.st_mode)
                        == (0o600 if kind == "file" else 0o700)
                    )
                data = b""
                if read:
                    _require(kind == "file" and 0 < info.st_size <= maximum)
                    leaf = os.open(
                        part,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=descriptor,
                    )
                    try:
                        _require(_identity(os.fstat(leaf)) == _identity(info))
                        chunks = []
                        size = 0
                        while True:
                            chunk = os.read(leaf, min(65536, maximum + 1 - size))
                            if not chunk:
                                break
                            size += len(chunk)
                            _require(size <= maximum)
                            chunks.append(chunk)
                        _require(
                            size == info.st_size
                            and _identity(os.fstat(leaf)) == _identity(info)
                        )
                        data = b"".join(chunks)
                    finally:
                        os.close(leaf)
                return _identity(info), data
            new = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            parent = descriptor
            descriptor = new
            try:
                _require(_identity(os.fstat(new)) == _identity(info))
            finally:
                os.close(parent)
        raise BHolderRefused()
    finally:
        os.close(descriptor)


def _root_read(path: str) -> bytes:
    return _walk(path, 0, None, read=True)[1]


def _instant(value: object) -> datetime:
    _require(type(value) is str)
    result = datetime.fromisoformat(cast(str, value).replace("Z", "+00:00"))
    _require(result.tzinfo is not None and result.utcoffset() == UTC.utcoffset(result))
    return result


@dataclass(frozen=True, slots=True, repr=False)
class BArchiveVerification:
    """Public hash summary only; actual private record remains at this boundary."""

    summary: bytes = field(repr=False)
    summary_digest: str
    private_record_digest: str


class InstalledBArchiveVerifier:
    def __init__(
        self,
        seal: object,
        document: dict[str, Any],
        selected: dict[str, bytes],
        selection: ESelection,
        producer: EProducerCoordinates,
        profile: archive.GpgHolderProfile,
        profile_digest: str,
        identities: dict[str, tuple[int, int, int, int]],
    ) -> None:
        _require(seal is _SEAL)
        self._document, self._selected = document, selected
        self._selection: ESelection | None = selection
        self._producer = producer
        self._profile: archive.GpgHolderProfile | None = profile
        self._profile_digest = profile_digest
        self._identities, self._used = identities, False

    @classmethod
    def _from_installed_checked(
        cls,
    ) -> InstalledBArchiveVerifier | archive._PrivateFailure:
        built: InstalledBArchiveVerifier | None = None
        selection: ESelection | None = None
        profile: archive.GpgHolderProfile | None = None
        selected: dict[str, bytes] = {}
        try:
            _require(sys.platform == "darwin")
            raw = _root_read(_INSTALLATION)
            doc = _object(
                raw,
                "schema policy_digest campaign_digest source_bundle_digest source "
                "cases "
                "withdrawal_reference environment producer prerequisite "
                "historical_reference "
                "github_installation historical_installation custody qualification",
            )
            _require(doc["schema"] == "Gate0EBHolderInstallation.v1")
            binding = _object(
                _root_read(_BINDING),
                "schema installation_digest qualification_digest "
                "runtime_uid runtime_home source_digests native_receipt",
            )
            _require(
                binding["schema"] == "Gate0EBHolderBinding.v1"
                and binding["installation_digest"] == _sha(raw)
            )
            uid = binding["runtime_uid"]
            _require(
                type(uid) is int and uid > 0 and os.getuid() == os.geteuid() == uid
            )
            home = binding["runtime_home"]
            _require(home == pwd.getpwuid(uid).pw_dir)
            _walk(home, uid, home, kind="directory")
            private_root = home + "/.config/dotmac-gate0-e-b/records"
            _walk(private_root, uid, home, kind="directory", private=True)

            def pin(value: object, *, root: bool = False) -> bytes:
                item = _fields(value, "path digest")
                path = item["path"]
                _require(
                    type(path) is str
                    and path.startswith(_RECORD_ROOT if root else private_root + "/")
                )
                if path not in selected:
                    selected[path] = (
                        _root_read(path)
                        if root
                        else _walk(path, uid, home, private=True, read=True)[1]
                    )
                _require(writer._hash(item["digest"]) == _sha(selected[path]))
                _require(sum(map(len, selected.values())) <= 4 * _CAP)
                return selected[path]

            qualification_raw = pin(doc["qualification"], root=True)
            _require(_sha(qualification_raw) == binding["qualification_digest"])
            qualification = _object(
                qualification_raw,
                "schema platform selection_digest runtime_uid runtime_home "
                "source_digests native_receipt custody_profile_digest "
                "github_installation_digest historical_installation_digest",
            )
            _require(
                qualification["schema"] == "Gate0EBHolderNativeQualification.v1"
                and qualification["platform"] == "darwin"
            )
            _require(
                qualification["selection_digest"]
                == _sha(
                    canonical(
                        {
                            key: value
                            for key, value in doc.items()
                            if key != "qualification"
                        }
                    )
                )
            )
            for key in (
                "runtime_uid",
                "runtime_home",
                "source_digests",
                "native_receipt",
            ):
                _require(qualification[key] == binding[key])
            modules = {
                "holder": __file__,
                "archive": archive.__file__,
                "writer": writer.__file__,
                "github": github.__file__,
                "historical": historical.__file__,
                "preparation": preparation.__file__,
                "proof": proof.__file__,
                "handoff": handoff.__file__,
                "framing": framing.__file__,
            }
            _require(set(binding["source_digests"]) == set(modules))
            for key, path in modules.items():
                _require(
                    _sha(_root_read(os.path.abspath(path)))
                    == binding["source_digests"][key]
                )
            native = _object(
                pin(binding["native_receipt"], root=True),
                "schema qualification_measurements_digest runtime_identity_digest "
                "reviewer_record_digest",
            )
            _require(native["schema"] == "Gate0ENativeReviewReceipt.v1")
            for key in (
                "qualification_measurements_digest",
                "runtime_identity_digest",
                "reviewer_record_digest",
            ):
                github._hex(native[key])
            custody_raw = pin(doc["custody"], root=True)
            _require(_sha(custody_raw) == qualification["custody_profile_digest"])
            custody = _object(
                custody_raw,
                "schema platform runtime_uid runtime_home homedir agent_boundary "
                "agent_root agent_socket "
                "keyring private_key_directory nodes public_profile gpgconf "
                "qualified_at not_after native_receipt_digest",
            )
            _require(
                custody["schema"] == "Gate0EBExistingCustodyProfile.v1"
                and custody["platform"] == "darwin"
            )
            _require(custody["runtime_uid"] == uid and custody["runtime_home"] == home)
            _require(
                custody["native_receipt_digest"]
                == _sha(pin(binding["native_receipt"], root=True))
            )
            _require(
                _instant(custody["qualified_at"])
                <= datetime.now(UTC)
                < _instant(custody["not_after"])
            )
            _require(
                type(custody["homedir"]) is str
                and custody["homedir"].startswith(home + "/")
            )
            _require(
                type(custody["agent_root"]) is str
                and custody["agent_socket"].startswith(custody["agent_root"] + "/")
            )
            _require(
                custody["agent_root"] == custody["agent_boundary"]
                or custody["agent_root"].startswith(custody["agent_boundary"] + "/")
            )
            _require(
                custody["private_key_directory"]
                == custody["homedir"] + "/private-keys-v1.d"
            )
            for key in ("keyring", "private_key_directory"):
                _require(custody[key].startswith(custody["homedir"] + "/"))
            _require(
                set(custody["nodes"])
                == {
                    "homedir",
                    "agent_root",
                    "agent_socket",
                    "keyring",
                    "private_key_directory",
                }
            )
            identities = {}
            for key in custody["nodes"]:
                node = _fields(custody["nodes"][key], "device inode uid mode")
                _require(
                    all(
                        type(node[field]) is int and node[field] >= 0
                        for field in ("device", "inode", "uid", "mode")
                    )
                )
                kind = (
                    "socket"
                    if key == "agent_socket"
                    else "file"
                    if key == "keyring"
                    else "directory"
                )
                boundary = (
                    (
                        home
                        if custody["agent_root"].startswith(home + "/")
                        else custody["agent_boundary"]
                    )
                    if key in ("agent_root", "agent_socket")
                    else home
                )
                identity, _ = _walk(
                    custody[key], uid, boundary, kind=kind, private=key != "keyring"
                )
                _require(
                    identity
                    == (node["device"], node["inode"], node["uid"], node["mode"])
                )
                identities[key] = identity
            public = dict(
                _fields(
                    custody["public_profile"],
                    "executable executable_sha256 version_line public_key "
                    "public_key_sha256 primary_fingerprint encryption_fingerprint",
                )
            )
            public["public_key"] = pin(public["public_key"])
            public["executable"] = Path(public["executable"])
            conf = _fields(
                custody["gpgconf"], "executable executable_sha256 version_line"
            )
            conf_pins = archive.GnuPgToolPins(
                Path(conf["executable"]),
                conf["executable_sha256"],
                conf["version_line"],
            )
            profile = archive.GpgHolderProfile(
                archive.GpgArchiveProfile(**public),
                Path(custody["homedir"]),
                Path(home),
                conf_pins,
                Path(custody["agent_socket"]),
                Path(custody["keyring"]),
            )
            producer = EProducerCoordinates(**doc["producer"])

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
                item = _fields(
                    value,
                    "shared_packet frozen_window command_id roots issuer_trust "
                    "attester_trust",
                )
                _require(type(item["roots"]) is list and len(item["roots"]) == 2)
                roots = tuple(RootHostBinding(pin(root)) for root in item["roots"])
                cases.append(
                    ERetainedCase(
                        pin(item["shared_packet"]),
                        pin(item["frozen_window"]),
                        item["command_id"],
                        cast(tuple[RootHostBinding, RootHostBinding], roots),
                        trust(item["issuer_trust"]),
                        trust(item["attester_trust"]),
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
            preparation._join_selection(selection, producer)
            writer._hash(doc["source_bundle_digest"])
            for key in ("prerequisite", "historical_reference"):
                pin(doc[key])
            for key in ("github_installation", "historical_installation"):
                reader_pin = _fields(doc[key], "path digest")
                fixed = (
                    github._INSTALLATION
                    if key == "github_installation"
                    else historical._INSTALLATION
                )
                _require(reader_pin["path"] == fixed)
                actual = _root_read(fixed)
                _require(
                    _sha(actual)
                    == reader_pin["digest"]
                    == qualification[key + "_digest"]
                )
            # The existing readers retain fixed /run paths. Those installations
            # must themselves have real Mac qualification; no Linux receipt is
            # imported as a substitute and their private seals are never used.
            selected["custody-profile"] = custody_raw
            built = cls(
                _SEAL,
                doc,
                selected,
                selection,
                producer,
                profile,
                _sha(custody_raw),
                identities,
            )
            return built
        except BaseException as error:
            return archive._private_failure(error)
        finally:
            raw = qualification_raw = custody_raw = b""
            if built is None:
                selected.clear()
            doc = binding = qualification = custody = public = {}
            selection = profile = None

    @classmethod
    def from_installed(cls) -> InstalledBArchiveVerifier:
        result = cls._from_installed_checked()
        if isinstance(result, archive._PrivateFailure):
            if result.category == "interrupt":
                raise KeyboardInterrupt
            if result.category == "exit":
                raise SystemExit(result.exit_code)
            raise BHolderRefused()
        return result

    def _pin(self, name: str) -> bytes:
        pin = self._document[name]
        raw = self._selected[pin["path"]]
        _require(_sha(raw) == pin["digest"])
        return raw

    def _custody_identity(self) -> None:
        custody = _object(self._selected["custody-profile"])
        uid, home = custody["runtime_uid"], custody["runtime_home"]
        _require(
            os.getuid() == os.geteuid() == uid and pwd.getpwuid(uid).pw_dir == home
        )
        _require(
            _instant(custody["qualified_at"])
            <= datetime.now(UTC)
            < _instant(custody["not_after"])
        )
        for key, expected in self._identities.items():
            kind = (
                "socket"
                if key == "agent_socket"
                else "file"
                if key == "keyring"
                else "directory"
            )
            boundary = (
                (
                    home
                    if custody["agent_root"].startswith(home + "/")
                    else custody["agent_boundary"]
                )
                if key in ("agent_root", "agent_socket")
                else home
            )
            actual, _ = _walk(
                custody[key], uid, boundary, kind=kind, private=key != "keyring"
            )
            _require(actual == expected)

    def _verify_draft_private(
        self,
        reads: github.InstalledGate0GitHubReads,
        draft_facts: github.DraftReleaseFacts,
        *,
        deadline: float,
    ) -> BArchiveVerification | archive._PrivateFailure:
        decrypted: archive.DecryptedArchive | None = None
        private: archive.PrivateArchive | None = None
        result: writer.PrivateEVerification | None = None
        source_facts: historical.HistoricalSourceFacts | None = None
        historical_reads: historical.InstalledHistoricalSourceReads | None = None
        try:
            _require(not self._used)
            self._used = True
            selection, profile = self._selection, self._profile
            if selection is None or profile is None:
                raise BHolderRefused()
            _require(
                type(deadline) in (float, int)
                and math.isfinite(deadline)
                and time.monotonic() < deadline
            )
            _require(
                type(reads) is github.InstalledGate0GitHubReads
                and type(draft_facts) is github.DraftReleaseFacts
            )
            _require(reads.owns_facts(draft_facts) and draft_facts.draft is True)
            _require(
                "sha256:" + reads.installed_selection_digest
                == self._document["github_installation"]["digest"]
            )
            run = reads._producer
            if run is None:
                raise BHolderRefused()
            _require(
                run.run_id == self._producer.run_id
                and run.attempt == self._producer.attempt
            )
            _require(
                run.workflow.id == self._producer.workflow_id
                and run.head_sha == self._producer.source_revision
            )
            _require(
                "sha256:" + run.workflow.sha256 == selection.source.workflow_digest
            )
            selected_jobs: list[Any] = []
            for observation in draft_facts.observations:
                if observation.endpoint == github.EndpointCode.JOBS:
                    selected_jobs.extend(
                        job
                        for job in _object(observation.body)["jobs"]
                        if job["name"] == run.workflow.job_name
                    )
            _require(len(selected_jobs) > 0)
            for job in selected_jobs:
                _require(type(job["id"]) is int and job["id"] == self._producer.job_id)
                _require(
                    job["run_id"] == self._producer.run_id
                    and job["head_sha"] == self._producer.source_revision
                )
                _require(
                    job["status"] == "completed" and job["conclusion"] == "success"
                )
            _require(
                draft_facts.repository_id == self._producer.repository_id
                and draft_facts.owner_id == self._producer.owner_id
            )
            _require(draft_facts.target_commitish == self._producer.source_revision)
            assets = {asset.name: asset for asset in draft_facts.assets}
            _require(
                len(draft_facts.assets) == 2
                and set(assets) == {"gate0-evidence.pgp", "gate0-evidence-public.json"}
            )
            _require(len({asset.id for asset in draft_facts.assets}) == 2)
            for asset in draft_facts.assets:
                _require(
                    asset.state == "uploaded" and asset.size == len(asset.raw_bytes)
                )
                _require(_sha(asset.raw_bytes)[7:] == asset.sha256)
            ciphertext = assets["gate0-evidence.pgp"].raw_bytes
            projection = assets["gate0-evidence-public.json"].raw_bytes
            public = validate_encrypted_e_projection(projection)
            _require(public["producer"] == self._producer.document())
            _require(public["policy_digest"] == selection.policy_digest)
            _require(public["campaign_digest"] == selection.campaign_digest)
            _require(public["ciphertext_digest"] == _sha(ciphertext))
            # Pin the concrete read installation again at action time. The live
            # reader already verifies completed original producer source/steps.
            _require(
                _sha(_root_read(github._INSTALLATION))
                == self._document["github_installation"]["digest"]
            )
            self._custody_identity()
            decrypted = archive.decrypt_private_collection(
                ciphertext, profile, deadline=deadline
            )
            self._custody_identity()
            _require(type(decrypted) is archive.DecryptedArchive)
            _require(_sha(decrypted.plaintext)[7:] == decrypted.plaintext_sha256)
            private = archive.unpack_private_archive(decrypted.plaintext)
            result = writer.verify_private_e(
                private,
                selection,
                writer.EPrivateInputs(
                    self._producer,
                    self._document["source_bundle_digest"],
                    self._pin("prerequisite"),
                    projection,
                    decrypted.plaintext,
                    ciphertext,
                ),
            )
            historical_reads = (
                historical.InstalledHistoricalSourceReads.from_installed()
            )
            source_facts = historical_reads.verify(deadline=deadline)
            _require(historical_reads.owns_facts(source_facts))
            _require(
                _sha(canonical(historical_reads._installation))
                == self._document["historical_installation"]["digest"]
            )
            _require(
                "sha256:" + source_facts.source_policy_digest == selection.policy_digest
            )
            _require(
                writer._source_coordinates(source_facts.reference_bytes)
                == writer._source_coordinates(self._pin("historical_reference"))
            )
            prerequisites_raw = private.proof_files["prerequisites.json"]
            _require(_sha(prerequisites_raw) == result.prerequisite_digest)
            prerequisites = _object(prerequisites_raw)
            archived_reference = writer._decode(prerequisites["historical_reference"])
            _require(
                writer._source_coordinates(archived_reference)
                == writer._source_coordinates(source_facts.reference_bytes)
            )
            _require(
                _sha(_root_read(historical._INSTALLATION))
                == self._document["historical_installation"]["digest"]
            )
            _require(time.monotonic() < deadline and reads.owns_facts(draft_facts))
            private_prerequisite_digest = _sha(prerequisites_raw)
            source_reference_digest = _sha(archived_reference)
            operational_evidence_digest = _sha(
                canonical(
                    {
                        name: evidence["digest"]
                        for name, evidence in prerequisites["evidence"].items()
                    }
                )
            )
            record = canonical(
                dict(
                    schema="Gate0EBPrivateArchiveVerification.v1",
                    repository_id=draft_facts.repository_id,
                    release_id=draft_facts.release_id,
                    tag=draft_facts.tag,
                    target_commit=draft_facts.target_commitish,
                    producer=self._producer.document(),
                    assets=[
                        dict(id=asset.id, name=asset.name, digest=_sha(asset.raw_bytes))
                        for asset in draft_facts.assets
                    ],
                    recipient_primary_fingerprint=profile.public.primary_fingerprint,
                    recipient_encryption_fingerprint=profile.public.encryption_fingerprint,
                    qualification_digest=self._document["qualification"]["digest"],
                    ciphertext_digest=result.ciphertext_digest,
                    plaintext_digest=result.plaintext_digest,
                    manifest_digest=result.manifest_digest,
                    private_receipt_digest=result.receipt_digest,
                    prerequisite_digest=result.prerequisite_digest,
                    private_prerequisite_digest=private_prerequisite_digest,
                    source_reference_digest=source_reference_digest,
                    operational_evidence_digest=operational_evidence_digest,
                    projection_digest=result.projection_digest,
                    collection_digest=result.collection_digest,
                    holder_source_digest=_sha(_root_read(os.path.abspath(__file__))),
                    holder_profile_digest=self._profile_digest,
                    status_digest="sha256:" + decrypted.status_sha256,
                    historical_reference_digest=_sha(source_facts.reference_bytes),
                    verified_at=datetime.now(UTC).isoformat(),
                    result="private_archive_and_proofs_verified",
                )
            )
            record_digest = _sha(record)
            self._custody_identity()
            _require(time.monotonic() < deadline)
            self._retain(record, record_digest)
            _require(time.monotonic() < deadline)
            summary = canonical(
                dict(
                    schema="Gate0EBArchiveVerification.v2",
                    repository_id=draft_facts.repository_id,
                    release_id=draft_facts.release_id,
                    ciphertext_asset_id=assets["gate0-evidence.pgp"].id,
                    projection_asset_id=assets["gate0-evidence-public.json"].id,
                    producer=self._producer.document(),
                    ciphertext_digest=result.ciphertext_digest,
                    plaintext_digest=result.plaintext_digest,
                    manifest_digest=result.manifest_digest,
                    private_receipt_digest=result.receipt_digest,
                    projection_digest=result.projection_digest,
                    policy_digest=selection.policy_digest,
                    private_prerequisite_digest=private_prerequisite_digest,
                    source_reference_digest=source_reference_digest,
                    operational_evidence_digest=operational_evidence_digest,
                    private_verification_record_digest=record_digest,
                    holder_source_digest=_sha(_root_read(os.path.abspath(__file__))),
                    holder_profile_digest=self._profile_digest,
                    result="private_archive_and_proofs_verified",
                )
            )
            return BArchiveVerification(summary, _sha(summary), record_digest)
        except BaseException as error:
            return archive._private_failure(error)
        finally:
            decrypted = private = result = source_facts = historical_reads = None
            record = summary = archived_reference = ciphertext = projection = b""
            prerequisites_raw = b""
            prerequisites = public = {}
            assets = {}
            selection = profile = None
            self._selection = None
            self._profile = None
            self._selected.clear()

    def verify_draft(
        self,
        reads: github.InstalledGate0GitHubReads,
        draft_facts: github.DraftReleaseFacts,
        *,
        deadline: float,
    ) -> BArchiveVerification:
        result = self._verify_draft_private(reads, draft_facts, deadline=deadline)
        del self, reads, draft_facts
        if isinstance(result, archive._PrivateFailure):
            if result.category == "interrupt":
                raise KeyboardInterrupt
            if result.category == "exit":
                raise SystemExit(result.exit_code)
            raise BHolderRefused()
        return result

    def _retain(self, record: bytes, digest: str) -> None:
        """Create-only private record on existing holder boundary; no plaintext file."""
        custody = _object(self._selected["custody-profile"])
        home, uid = custody["runtime_home"], custody["runtime_uid"]
        directory = home + "/.config/dotmac-gate0-e-b/verified"
        expected, _ = _walk(directory, uid, home, kind="directory", private=True)
        descriptor = _open_directory(directory)
        try:
            _require(_identity(os.fstat(descriptor)) == expected)
            name = digest[7:] + ".json"
            leaf = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            try:
                os.fchmod(leaf, 0o600)
                _require(os.fstat(leaf).st_uid == uid)
                view = memoryview(record)
                while view:
                    count = os.write(leaf, view)
                    _require(count > 0)
                    view = view[count:]
                os.fsync(leaf)
            finally:
                os.close(leaf)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _open_directory(path: str) -> int:
    """Hold the create parent through a second complete no-follow traversal."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path[1:].split("/"):
            new = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = new
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def run_installed_verify_e_b_archive() -> int:
    try:
        installed = InstalledBArchiveVerifier.from_installed()
        reads = github.InstalledGate0GitHubReads.from_installed()
        facts = reads.draft_snapshot()
        result = installed.verify_draft(reads, facts, deadline=time.monotonic() + 180)
        sys.stdout.buffer.write(result.summary)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 3
