"""Root-installed adapter composing the existing finite CP transition owners.

Configuration contains public installation facts only. It neither installs nor
activates host trust and never accepts serialized code or connection secrets.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, NotRequired, TypedDict, cast

from vendor_cp.deploy_agent.contracts import (
    ContractError,
    Digest,
    Identifier,
    Revision,
    _shape,
    read_json,
    require,
)
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_request as producer
from vendor_cp.deployment.effects import (
    BUNDLE_COMPONENTS,
    PlatformBackupResult,
    PlatformCpRecoveryBundle,
)

if TYPE_CHECKING:
    from vendor_cp.deployment.cp_transition_host import (
        CpTransitionHostConfig,
        HeldFenceContinuation,
    )


class IdentityV1(TypedDict):
    host: Identifier
    database: Identifier
    cluster_system_identifier: str
    database_oid: int


class TrustV1(TypedDict):
    repository: str
    repository_id: str
    repository_owner_id: str
    workflow_path: str
    workflow_revision: Revision
    predicate_type: str
    gh_binary: str
    gh_binary_digest: Digest
    gh_config_directory: str
    environment_protection_proof: str
    environment_protection_digest: Digest


class HostV1(TypedDict):
    repository_root: str
    deploy_directory: str
    target_descriptor: str
    source_image: str
    target_image: str
    postgres_image: str
    maintenance_helper: str
    maintenance_helper_digest: Digest
    external_ready_url: str
    candidate_port: int
    host_id_file: str
    docker_binary: str
    docker_binary_digest: Digest
    git_binary: str
    git_binary_digest: Digest
    backup_directory: str
    compose_file: str
    compose_env_file: str
    runtime_compose_overlay: str | None
    candidate_env_file: str | None
    candidate_runtime_environment: str | None
    licence_key_host_file: str
    ready_host: str
    app_port: int
    timeout_seconds: int
    session_wait_seconds: int


class HeldFencePinsV1(TypedDict):
    path: str
    digest: Digest
    proof_digest: Digest
    fence_id: Annotated[str, r"[0-9a-f]{64}"]


class HeldFenceContextV1(TypedDict):
    schema: Literal["dotmac.cp_transition_held_fence_context/1"]
    prior_artifact_directory: str
    request: cp.CpTransitionRequestV1
    reservation_digest: Digest
    failure_digest: Digest
    failed_stage: Literal["source-restore-comparison"]


class InstallationV1(TypedDict):
    schema: Literal["dotmac.cp_transition_installation/1"]
    identity: IdentityV1
    trust: TrustV1
    host: HostV1
    artifact_directory: str
    historical_context_files: list[str]
    held_fence_context: NotRequired[HeldFencePinsV1]


class BackupMetadataV1(TypedDict):
    dataset: Literal["primary"]
    path: str
    size_bytes: int
    checksum: Annotated[str, r"[0-9a-f]{64}"]
    checksum_algorithm: Literal["sha256"]
    manifest_size_bytes: int
    database_dump_sha256: Digest
    database_dump_size_bytes: int
    globals_sha256: Digest
    globals_size_bytes: int


class IncumbentV1(TypedDict):
    role: Identifier
    image_digest: Digest


class HistoricalContextV1(TypedDict):
    schema: Literal["dotmac.cp_transition_recovery_context/1"]
    receipt_digest: Digest
    request: cp.CpTransitionRequestV1
    incumbent_roles: list[IncumbentV1]
    backup: BackupMetadataV1


@dataclass(frozen=True, slots=True)
class Installation:
    policy: cp.CpTransitionTrustPolicy
    host: CpTransitionHostConfig
    store: cp.ArtifactStore
    historical_context_files: tuple[Path, ...]
    held_fence_context: HeldFencePinsV1 | None = None


class TransitionOperatorRefused(Exception):
    """Fixed, redacted operator boundary; host compensation remains core-owned."""


def _path(value: str) -> Path:
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and "\x00" not in value)
    return path


def _directory(path: Path) -> None:
    descriptor = cp._open_directory(path)
    os.close(descriptor)


def _file(path: Path) -> None:
    """Check protected file metadata without retrieving credential contents."""
    directory = cp._open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            cp._protected(os.fstat(descriptor), directory=False)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def _host_config(value: HostV1) -> CpTransitionHostConfig:
    path_fields = (
        "repository_root",
        "deploy_directory",
        "target_descriptor",
        "maintenance_helper",
        "host_id_file",
        "docker_binary",
        "git_binary",
        "backup_directory",
        "compose_file",
        "compose_env_file",
        "licence_key_host_file",
    )
    for name in path_fields:
        _path(cast(dict[str, str], value)[name])
    require(
        (value["candidate_env_file"] is None)
        != (value["candidate_runtime_environment"] is None)
    )
    for path in (value["candidate_env_file"], value["candidate_runtime_environment"]):
        if path is not None:
            _path(path)
    for name in ("source_image", "target_image", "postgres_image"):
        require(
            re.fullmatch(
                r"[^\s@]+@sha256:[0-9a-f]{64}", cast(dict[str, str], value)[name]
            )
            is not None
        )
    for name in ("source_image", "target_image"):
        require(
            cast(dict[str, str], value)[name].split("@", 1)[0]
            == "ghcr.io/michaelayoade/dotmac_vendor_control_plane"
        )
    require(value["source_image"] != value["target_image"])
    require(1 <= value["candidate_port"] <= 65535 and 1 <= value["app_port"] <= 65535)
    require(value["candidate_port"] != value["app_port"])
    require(1 <= value["timeout_seconds"] <= 3600)
    require(1 <= value["session_wait_seconds"] <= 3600)
    require(re.fullmatch(r"[A-Za-z0-9.-]+", value["ready_host"]) is not None)
    require(
        re.fullmatch(
            r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_~.-]*",
            value["external_ready_url"],
        )
        is not None
    )
    if value["runtime_compose_overlay"] is not None:
        _file(_path(value["runtime_compose_overlay"]))
    from vendor_cp.deployment.cp_transition_host import CpTransitionHostConfig

    return CpTransitionHostConfig(
        repository_root=_path(value["repository_root"]),
        deploy_directory=_path(value["deploy_directory"]),
        target_descriptor=_path(value["target_descriptor"]),
        source_image=value["source_image"],
        target_image=value["target_image"],
        postgres_image=value["postgres_image"],
        maintenance_helper=_path(value["maintenance_helper"]),
        maintenance_helper_digest=value["maintenance_helper_digest"],
        external_ready_url=value["external_ready_url"],
        candidate_port=value["candidate_port"],
        host_id_file=_path(value["host_id_file"]),
        docker_binary=_path(value["docker_binary"]),
        docker_binary_digest=value["docker_binary_digest"],
        git_binary=_path(value["git_binary"]),
        git_binary_digest=value["git_binary_digest"],
        backup_directory=_path(value["backup_directory"]),
        compose_file=_path(value["compose_file"]),
        compose_env_file=_path(value["compose_env_file"]),
        runtime_compose_overlay=_path(value["runtime_compose_overlay"])
        if value["runtime_compose_overlay"] is not None
        else None,
        candidate_env_file=_path(value["candidate_env_file"])
        if value["candidate_env_file"] is not None
        else None,
        candidate_runtime_environment=_path(value["candidate_runtime_environment"])
        if value["candidate_runtime_environment"] is not None
        else None,
        licence_key_host_file=_path(value["licence_key_host_file"]),
        ready_host=value["ready_host"],
        app_port=value["app_port"],
        timeout_seconds=value["timeout_seconds"],
        session_wait_seconds=float(value["session_wait_seconds"]),
    )


def load_installation(path: Path) -> Installation:
    """Read an exact public policy through the core's protected-path owner."""
    require(
        sys.platform == "linux" and os.geteuid() == 0, "root_linux_operator_required"
    )
    document = read_json(cp._read_protected(path))
    _shape(document, InstallationV1)
    value = cast(InstallationV1, document)
    identity = cp.CpTransitionIdentity(**value["identity"])
    trust = value["trust"]
    require(
        trust["repository"] == producer.REPOSITORY
        and trust["repository_id"] == producer.REPOSITORY_ID
        and trust["repository_owner_id"] == producer.REPOSITORY_OWNER_ID
        and trust["workflow_path"] == producer.WORKFLOW_PATH
        and trust["predicate_type"] == producer.PREDICATE_TYPE,
        "installation_trust_mismatch",
    )
    policy = cp.CpTransitionTrustPolicy(
        identity=identity,
        repository=trust["repository"],
        repository_id=trust["repository_id"],
        repository_owner_id=trust["repository_owner_id"],
        workflow_path=trust["workflow_path"],
        workflow_revision=trust["workflow_revision"],
        predicate_type=trust["predicate_type"],
        gh_binary=_path(trust["gh_binary"]),
        gh_binary_digest=trust["gh_binary_digest"],
        gh_config_directory=_path(trust["gh_config_directory"]),
        environment_protection_proof=_path(trust["environment_protection_proof"]),
        environment_protection_digest=trust["environment_protection_digest"],
    )
    store = cp.ArtifactStore(_path(value["artifact_directory"]))
    _directory(store.root)
    paths = tuple(_path(item) for item in value["historical_context_files"])
    require(len(paths) == len(set(paths)) and len(paths) <= 32)
    return Installation(
        policy,
        _host_config(value["host"]),
        store,
        paths,
        value.get("held_fence_context"),
    )


def _load_held_fence(
    installation: Installation,
    request: cp.CpTransitionRequestV1,
) -> HeldFenceContinuation | None:
    """Receive failed-prefix facts through independently installed root pins.

    Neither a request nor a serialized proof supplies its own expected digest
    or fence ID. This context is evidence only: normal new authorization,
    reservation, inspection and migration gates all still run.
    """
    pins = installation.held_fence_context
    if pins is None:
        return None
    raw = cp._read_protected(_path(pins["path"]))
    require(cp.raw_digest(raw) == pins["digest"], "held_fence_context_digest_mismatch")
    document = read_json(raw)
    _shape(document, HeldFenceContextV1)
    context = cast(HeldFenceContextV1, document)
    prior = context["request"]
    require(
        prior["plan_digest"] == cp.transition_plan_digest(prior),
        "held_fence_prior_plan_mismatch",
    )
    prior_store = cp.ArtifactStore(_path(context["prior_artifact_directory"]))
    _directory(prior_store.root)
    # The root pin asserts the reviewed failed prefix. Also refuse a retained
    # checkpoint that contradicts that assertion; absence alone proves no stage.
    after_restore = (
        (cp.PRE_ACL_EVIDENCE - cp.PRE_MIGRATION_EVIDENCE)
        | cp.RUNTIME_EVIDENCE
        | cp.ROUTING_EVIDENCE
        | {"recovery-restored", "fence-source-rechecked"}
    )
    directory = cp._open_directory(prior_store.root)
    try:
        for name in os.listdir(directory):
            match = re.fullmatch(r"[0-9a-f]{64}\.(evidence|receipt)\.json", name)
            if match is None:
                continue
            kind = match.group(1)
            retained_raw = prior_store.read("sha256:" + name[:64], kind=kind)
            try:
                retained = read_json(retained_raw)
            except ContractError:
                require(kind == "evidence", "held_fence_receipt_invalid")
                # The content-addressed store also retains raw TOML/image
                # descriptors; those are not transition checkpoint documents.
                continue
            if (
                retained.get("request_digest") == cp.request_digest(prior)
                and retained.get("host_nonce") == pins["fence_id"]
            ):
                require(
                    kind != "receipt" and retained.get("kind") not in after_restore,
                    "held_fence_prefix_after_restore",
                )
    finally:
        os.close(directory)
    identity = installation.policy.identity
    require(
        all(
            prior[key] == getattr(identity, key)
            for key in (
                "host",
                "database",
                "cluster_system_identifier",
                "database_oid",
            )
        ),
        "held_fence_identity_mismatch",
    )
    reservation_raw = prior_store.read(cp.request_digest(prior), kind="reservation")
    require(
        cp.raw_digest(reservation_raw) == context["reservation_digest"],
        "held_fence_reservation_digest_mismatch",
    )
    reservation = read_json(reservation_raw)
    _shape(reservation.get("verification_digest"), Digest)
    require(
        set(reservation)
        == {
            "schema",
            "verification_digest",
            "request_digest",
            "host_nonce",
            "authorization_run_id",
            "authorization_run_attempt",
        },
        "held_fence_reservation_mismatch",
    )
    require(
        reservation["schema"] == "dotmac.cp_transition_attempt/2"
        and reservation["request_digest"] == cp.request_digest(prior)
        and reservation["host_nonce"] == pins["fence_id"]
        and reservation["authorization_run_id"] == prior["authorization_run_id"]
        and reservation["authorization_run_attempt"]
        == prior["authorization_run_attempt"],
        "held_fence_reservation_mismatch",
    )
    failure = read_json(prior_store.read(context["failure_digest"]))
    require(
        failure
        == {
            "schema": "dotmac.cp_transition_evidence/2",
            "request_digest": cp.request_digest(prior),
            "host_nonce": pins["fence_id"],
            "kind": "failure",
            "result": {
                "external_status": 503,
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        },
        "held_fence_failure_mismatch",
    )
    from vendor_cp.deployment import transition_fence
    from vendor_cp.deployment.cp_transition_host import HeldFenceContinuation

    proof_document = read_json(prior_store.read(pins["proof_digest"]))
    require(
        proof_document.get("fence_id") == pins["fence_id"], "held_fence_proof_mismatch"
    )
    proof = transition_fence.FenceProof.from_document(
        proof_document,
        expected_digest=pins["proof_digest"],
    )
    require(
        proof.fence_id == pins["fence_id"] and proof.database == prior["database"],
        "held_fence_proof_mismatch",
    )
    result = HeldFenceContinuation(prior, proof)
    result.bind(request)
    return result


def _load_recovery(
    installation: Installation,
) -> dict[str, tuple[PlatformCpRecoveryBundle, PlatformBackupResult]]:
    """Rebuild only independently root-installed historical recovery bindings."""
    recovery: dict[str, tuple[PlatformCpRecoveryBundle, PlatformBackupResult]] = {}
    historical = []
    for path in installation.historical_context_files:
        document = read_json(cp._read_protected(path))
        _shape(document, HistoricalContextV1)
        entry = cast(HistoricalContextV1, document)
        request = entry["request"]
        identity = installation.policy.identity
        require(
            all(
                cast(dict[str, object], request)[key] == getattr(identity, key)
                for key in (
                    "host",
                    "database",
                    "cluster_system_identifier",
                    "database_oid",
                )
            ),
            "historical_identity_mismatch",
        )
        key = cp.request_digest(request)
        require(key not in recovery)
        source = installation.store.read(request["source"]["raw_descriptor_digest"])
        target = installation.store.read(request["target"]["raw_descriptor_digest"])
        raw = installation.store.read(entry["receipt_digest"], kind="receipt")
        receipt_value = read_json(raw)
        _shape(receipt_value, cp.CpMigrationTransitionReceiptV1)
        receipt = cast(cp.CpMigrationTransitionReceiptV1, receipt_value)
        require(receipt["request"] == request and receipt["phase"] == "complete")
        metadata = entry["backup"]
        require(
            all(
                cast(dict[str, int], metadata)[name] > 0
                for name in (
                    "size_bytes",
                    "manifest_size_bytes",
                    "database_dump_size_bytes",
                    "globals_size_bytes",
                )
            )
        )
        root = _path(metadata["path"])
        require(root.parent == installation.host.backup_directory)
        directory = cp._open_directory(root)
        try:
            for name in BUNDLE_COMPONENTS:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    cp._protected(os.fstat(descriptor), directory=False)
                finally:
                    os.close(descriptor)
        finally:
            os.close(directory)
        owner = PlatformCpRecoveryBundle.for_transition(
            installation.host.deploy_directory,
            source_descriptor=source,
            target_descriptor=target,
            source_image=f"ghcr.io/michaelayoade/dotmac_vendor_control_plane@{request['source']['image_digest']}",
            source_revision=request["source"]["revision"],
            target_image=f"ghcr.io/michaelayoade/dotmac_vendor_control_plane@{request['target']['image_digest']}",
            target_source_revision=request["target"]["revision"],
            expected_source_heads=tuple(request["source"]["heads"]),
            target=identity.host,
            incumbent_roles=[
                (role["role"], role["image_digest"])
                for role in entry["incumbent_roles"]
            ],
            host_id_file=installation.host.host_id_file,
            compose_file=installation.host.compose_file,
            env_file=installation.host.compose_env_file,
            backup_dir=installation.host.backup_directory,
            docker_bin=str(installation.host.docker_binary),
        )
        backup = PlatformBackupResult(**metadata)
        require(owner.verify(backup), "historical_recovery_refused")
        recovery[key] = (owner, backup)
        historical.append((raw, request, receipt["host_nonce"]))
    for raw, request, nonce in historical:
        cp.verify_receipt(
            raw,
            store=installation.store,
            request=request,
            host_nonce=nonce,
            recovery=recovery,
        )
    return recovery


def run_transition(
    *, config_file: Path, request_file: Path, bundle_file: Path | None = None
) -> str:
    """Return a receipt digest only; installation and live approval are external."""
    try:
        installation = load_installation(config_file)
        raw = cp._read_protected(request_file)
        request = cp.load_request(
            raw, identity=installation.policy.identity, now=datetime.now(UTC)
        )
        if bundle_file is not None:
            cp._read_protected(bundle_file)
        recovery = _load_recovery(installation)
        held_fence = _load_held_fence(installation, request)
        previous = request["previous_receipt_digest"]
        if previous is not None:
            prior_raw = installation.store.read(previous, kind="receipt")
            prior_value = read_json(prior_raw)
            _shape(prior_value, cp.CpMigrationTransitionReceiptV1)
            prior = cast(cp.CpMigrationTransitionReceiptV1, prior_value)
            require(
                cp.request_digest(prior["request"]) in recovery,
                "historical_recovery_missing",
            )
            require(prior["phase"] == "complete", "incomplete_previous_receipt")
            cp.verify_receipt(
                prior_raw,
                store=installation.store,
                request=prior["request"],
                host_nonce=prior["host_nonce"],
                recovery=recovery,
            )
        from vendor_cp.deployment.cp_transition_host import ExistingCpTransitionHost

        host = ExistingCpTransitionHost(
            installation.host,
            store=installation.store,
            recovery=recovery,
            **({"held_fence": held_fence} if held_fence is not None else {}),
        )
        return cp.execute_transition(
            raw,
            request_path=request_file,
            bundle_path=bundle_file,
            verifier=cp.GhAttestationVerifier(installation.policy),
            host=host,
            store=installation.store,
            recovery=recovery,
            clock=lambda: datetime.now(UTC),
        )
    except Exception:
        # Executor owns post-reservation compensation; never leak child output,
        # database diagnostics, configuration contents or exception strings.
        raise TransitionOperatorRefused("CP_TRANSITION_REFUSED") from None
