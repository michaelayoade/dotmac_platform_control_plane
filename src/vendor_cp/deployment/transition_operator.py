"""Root-installed adapter composing the existing finite CP transition owners.

Configuration contains public installation facts only. It neither installs nor
activates host trust and never accepts serialized code or connection secrets.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, replace
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


class CommittedMigrationPinsV1(TypedDict):
    path: str
    digest: Digest


class InstallationV1(TypedDict):
    schema: Literal["dotmac.cp_transition_installation/1"]
    identity: IdentityV1
    trust: TrustV1
    host: HostV1
    artifact_directory: str
    historical_context_files: list[str]
    held_fence_context: NotRequired[HeldFencePinsV1]
    committed_migration_context: NotRequired[CommittedMigrationPinsV1]
    operator_revision: NotRequired[Revision]


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


class CommittedMigrationContextV1(TypedDict):
    schema: Literal["dotmac.cp_committed_migration_context/1"]
    prior_artifact_directory: str
    request: cp.CpTransitionRequestV1
    host_nonce: Annotated[str, r"[0-9a-f]{64}"]
    reservation_digest: Digest
    authorization_verification_digest: Digest
    authorization_context_digest: Digest
    original_fence_digest: Digest
    current_fence_digest: Digest
    current_fence_id: Annotated[str, r"[0-9a-f]{64}"]
    evidence: dict[Identifier, Digest]
    migration_claim_digest: Digest
    migration_tree_digest: Digest
    quiescence_digest: Digest
    incumbent_roles: list[IncumbentV1]
    backup: BackupMetadataV1


class HistoricalAuthorizationContextV1(TypedDict):
    schema: Literal["dotmac.cp_historical_authorization_context/1"]
    trust: TrustV1
    request_name: str
    invocation_file: str
    invocation_digest: Digest
    result_file: str
    result_digest: Digest


class OriginalInvocationV1(TypedDict):
    status: Literal["ONE_ATTEMPT_STARTED"]
    run_id: int
    started_unix: int
    request_sha256: Annotated[str, r"[0-9a-f]{64}"]
    bundle_sha256: Annotated[str, r"[0-9a-f]{64}"]


class OriginalResultV1(TypedDict):
    status: Literal["OWNER_RETURNED"]
    exit: Literal[3]
    stdout_bytes: int
    stderr_bytes: int
    work: str
    completed_unix: int


class HistoricalCommittedContextV1(TypedDict):
    schema: Literal["dotmac.cp_committed_recovery_context/1"]
    receipt_digest: Digest
    committed_context: CommittedMigrationPinsV1


@dataclass(frozen=True, slots=True)
class Installation:
    policy: cp.CpTransitionTrustPolicy
    host: CpTransitionHostConfig
    store: cp.ArtifactStore
    historical_context_files: tuple[Path, ...]
    held_fence_context: HeldFencePinsV1 | None = None
    committed_migration_context: CommittedMigrationPinsV1 | None = None
    operator_revision: str | None = None


class _HostContinuationArguments(TypedDict, total=False):
    held_fence: HeldFenceContinuation
    committed_context: cp.CommittedMigrationContext
    committed_contexts: dict[str, cp.CommittedMigrationContext]


class _ExecutionContexts(TypedDict, total=False):
    committed_contexts: dict[str, cp.CommittedMigrationContext]


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


def _trust_policy(
    identity: cp.CpTransitionIdentity, trust: TrustV1
) -> cp.CpTransitionTrustPolicy:
    require(
        trust["repository"] == producer.REPOSITORY
        and trust["repository_id"] == producer.REPOSITORY_ID
        and trust["repository_owner_id"] == producer.REPOSITORY_OWNER_ID
        and trust["workflow_path"] == producer.WORKFLOW_PATH
        and trust["predicate_type"] == producer.PREDICATE_TYPE,
        "installation_trust_mismatch",
    )
    return cp.CpTransitionTrustPolicy(
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


def load_installation(path: Path) -> Installation:
    """Read an exact public policy through the core's protected-path owner."""
    require(
        sys.platform == "linux" and os.geteuid() == 0, "root_linux_operator_required"
    )
    document = read_json(cp._read_protected(path))
    _shape(document, InstallationV1)
    value = cast(InstallationV1, document)
    identity = cp.CpTransitionIdentity(**value["identity"])
    policy = _trust_policy(identity, value["trust"])
    committed = value.get("committed_migration_context")
    require(
        committed is None or value.get("held_fence_context") is None,
        "continuation_contexts_conflict",
    )
    require(
        committed is None or value.get("operator_revision") is not None,
        "committed_operator_revision_required",
    )
    store = cp.ArtifactStore(_path(value["artifact_directory"]))
    _directory(store.root)
    paths = tuple(_path(item) for item in value["historical_context_files"])
    require(len(paths) == len(set(paths)) and len(paths) <= 32)
    return Installation(
        policy,
        replace(
            _host_config(value["host"]),
            operator_revision=value.get("operator_revision"),
        ),
        store,
        paths,
        value.get("held_fence_context"),
        committed,
        value.get("operator_revision"),
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
            cast(dict[str, object], prior)[key] == getattr(identity, key)
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


def _recovery_binding(
    installation: Installation,
    store: cp.ArtifactStore,
    request: cp.CpTransitionRequestV1,
    metadata: BackupMetadataV1,
    incumbent_roles: list[IncumbentV1],
) -> tuple[PlatformCpRecoveryBundle, PlatformBackupResult]:
    """Reconstruct the existing recovery owner; never recapture or restore."""
    identity = installation.policy.identity
    source = store.read(request["source"]["raw_descriptor_digest"])
    target = store.read(request["target"]["raw_descriptor_digest"])
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
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
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
            (role["role"], role["image_digest"]) for role in incumbent_roles
        ],
        host_id_file=installation.host.host_id_file,
        compose_file=installation.host.compose_file,
        env_file=installation.host.compose_env_file,
        backup_dir=installation.host.backup_directory,
        docker_bin=str(installation.host.docker_binary),
    )
    backup = PlatformBackupResult(**metadata)
    require(owner.verify(backup), "historical_recovery_refused")
    return owner, backup


def _load_historical_authorization(
    installation: Installation,
    store: cp.ArtifactStore,
    context: CommittedMigrationContextV1,
) -> cp.HistoricalAuthorization:
    document = read_json(store.read(context["authorization_context_digest"]))
    _shape(document, HistoricalAuthorizationContextV1)
    value = cast(HistoricalAuthorizationContextV1, document)
    require(value["request_name"] == "request.json", "historical_subject_mismatch")
    invocation_path = _path(value["invocation_file"])
    result_path = _path(value["result_file"])
    require(
        invocation_path.name == "invocation.json"
        and result_path.name == "result.json"
        and invocation_path.parent == result_path.parent,
        "historical_execution_records_mismatch",
    )
    invocation_raw = cp._read_protected(invocation_path)
    result_raw = cp._read_protected(result_path)
    require(
        cp.raw_digest(invocation_raw) == value["invocation_digest"]
        and cp.raw_digest(result_raw) == value["result_digest"],
        "historical_execution_records_mismatch",
    )
    invocation_document = read_json(invocation_raw)
    result_document = read_json(result_raw)
    _shape(invocation_document, OriginalInvocationV1)
    _shape(result_document, OriginalResultV1)
    invocation = cast(OriginalInvocationV1, invocation_document)
    result = cast(OriginalResultV1, result_document)
    prior = context["request"]
    require(
        invocation["run_id"] == prior["authorization_run_id"]
        and invocation["request_sha256"] == cp.request_digest(prior)[7:]
        and result["work"] == str(invocation_path.parent)
        and 0 < invocation["started_unix"] <= result["completed_unix"]
        and result["stdout_bytes"] >= 0
        and result["stderr_bytes"] >= 0,
        "historical_execution_records_mismatch",
    )
    policy = _trust_policy(installation.policy.identity, value["trust"])
    historical = cp.HistoricalAuthorization(
        policy=policy,
        verification_bytes=store.read(context["authorization_verification_digest"]),
        execution_window_start=datetime.fromtimestamp(invocation["started_unix"], UTC),
        execution_window_end=datetime.fromtimestamp(result["completed_unix"], UTC),
        request_name=value["request_name"],
        protection_bytes=cp._read_protected(policy.environment_protection_proof),
        context_digest=context["authorization_context_digest"],
    )
    historical.verify(prior)
    return historical


def _load_committed_context(
    installation: Installation,
    pins: CommittedMigrationPinsV1 | None = None,
) -> cp.CommittedMigrationContext | None:
    """Load protected historical facts; fresh admission remains core-owned."""
    pins = pins if pins is not None else installation.committed_migration_context
    if pins is None:
        return None
    raw = cp._read_protected(_path(pins["path"]))
    require(cp.raw_digest(raw) == pins["digest"], "committed_context_digest_mismatch")
    document = read_json(raw)
    _shape(document, CommittedMigrationContextV1)
    value = cast(CommittedMigrationContextV1, document)
    prior = value["request"]
    require(
        all(
            cast(dict[str, object], prior)[key]
            == getattr(installation.policy.identity, key)
            for key in ("host", "database", "cluster_system_identifier", "database_oid")
        ),
        "historical_identity_mismatch",
    )
    store = cp.ArtifactStore(_path(value["prior_artifact_directory"]))
    _directory(store.root)
    require(
        cp.raw_digest(store.read(cp.request_digest(prior), kind="reservation"))
        == value["reservation_digest"],
        "committed_reservation_digest_mismatch",
    )
    historical = _load_historical_authorization(installation, store, value)
    owner, backup = _recovery_binding(
        installation, store, prior, value["backup"], value["incumbent_roles"]
    )
    from vendor_cp.deployment.transition_fence import FenceProof

    proofs = [
        FenceProof.from_document(
            read_json(store.read(checksum)), expected_digest=checksum
        )
        for checksum in (value["original_fence_digest"], value["current_fence_digest"])
    ]
    require(
        proofs[1].fence_id == value["current_fence_id"],
        "committed_fence_id_mismatch",
    )
    return cp.CommittedMigrationContext(
        prior_store=store,
        request=prior,
        host_nonce=value["host_nonce"],
        evidence=value["evidence"],
        historical_authorization=historical,
        recovery={cp.request_digest(prior): (owner, backup)},
        original_proof=proofs[0],
        proof=proofs[1],
        context_digest=pins["digest"],
        migration_claim_digest=value["migration_claim_digest"],
        migration_tree_digest=value["migration_tree_digest"],
        quiescence_digest=value["quiescence_digest"],
    )


def _load_recovery(
    installation: Installation,
    *,
    committed_contexts: dict[str, cp.CommittedMigrationContext] | None = None,
) -> dict[str, tuple[PlatformCpRecoveryBundle, PlatformBackupResult]]:
    """Rebuild only independently root-installed historical recovery bindings."""
    recovery: dict[str, tuple[PlatformCpRecoveryBundle, PlatformBackupResult]] = {}
    contexts = committed_contexts if committed_contexts is not None else {}
    historical = []
    committed_receipts = []
    for path in installation.historical_context_files:
        document = read_json(cp._read_protected(path))
        if document.get("schema") == "dotmac.cp_committed_recovery_context/1":
            _shape(document, HistoricalCommittedContextV1)
            committed_entry = cast(HistoricalCommittedContextV1, document)
            context = _load_committed_context(
                installation, committed_entry["committed_context"]
            )
            require(context is not None, "historical_committed_context_missing")
            assert context is not None  # noqa: S101 - narrowed by require
            require(
                context.context_digest not in contexts,
                "duplicate_historical_committed_context",
            )
            contexts[context.context_digest] = context
            for key, binding in context.recovery.items():
                require(key not in recovery, "duplicate_historical_recovery")
                recovery[key] = binding
            raw = installation.store.read(
                committed_entry["receipt_digest"], kind="receipt"
            )
            value = read_json(raw)
            _shape(value, cp.CpCommittedMigrationReceiptV1)
            receipt = cast(cp.CpCommittedMigrationReceiptV1, value)
            require(
                receipt["phase"] == "complete"
                and receipt["historical_context_digest"] == context.context_digest,
                "historical_committed_receipt_mismatch",
            )
            committed_receipts.append((raw, receipt, context))
            continue
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
        raw = installation.store.read(entry["receipt_digest"], kind="receipt")
        receipt_value = read_json(raw)
        _shape(receipt_value, cp.CpMigrationTransitionReceiptV1)
        old_receipt = cast(cp.CpMigrationTransitionReceiptV1, receipt_value)
        require(
            old_receipt["request"] == request and old_receipt["phase"] == "complete"
        )
        owner, backup = _recovery_binding(
            installation,
            installation.store,
            request,
            entry["backup"],
            entry["incumbent_roles"],
        )
        recovery[key] = (owner, backup)
        historical.append((raw, request, old_receipt["host_nonce"]))
    verification_contexts: _ExecutionContexts = {}
    if contexts:
        verification_contexts["committed_contexts"] = contexts
    for raw, request, nonce in historical:
        cp.verify_receipt(
            raw,
            store=installation.store,
            request=request,
            host_nonce=nonce,
            recovery=recovery,
            **verification_contexts,
        )
    for raw, receipt, context in committed_receipts:
        cp.verify_committed_receipt(
            raw,
            store=installation.store,
            request=receipt["request"],
            host_nonce=receipt["host_nonce"],
            recovery=recovery,
            context=context,
            committed_contexts=contexts,
            routing_gate=True,
        )
    return recovery


def run_transition(
    *, config_file: Path, request_file: Path, bundle_file: Path | None = None
) -> str:
    """Return a receipt digest only; installation and live approval are external."""
    try:
        installation = load_installation(config_file)
        raw = cp._read_protected(request_file)
        schema = read_json(raw).get("schema")
        request: cp.TransitionRequest
        if schema == "dotmac.cp_transition_request/1":
            request = cp.load_request(
                raw, identity=installation.policy.identity, now=datetime.now(UTC)
            )
        else:
            require(
                schema == "dotmac.cp_committed_migration_request/1",
                "unknown_transition_request",
            )
            request = cp.load_committed_request(
                raw, identity=installation.policy.identity, now=datetime.now(UTC)
            )
        if bundle_file is not None:
            cp._read_protected(bundle_file)
        contexts: dict[str, cp.CommittedMigrationContext] = {}
        recovery = _load_recovery(installation, committed_contexts=contexts)
        context = None
        held_fence = None
        if request["schema"] == "dotmac.cp_committed_migration_request/1":
            require(
                request["operator_revision"] == installation.operator_revision,
                "committed_operator_revision_mismatch",
            )
            context = _load_committed_context(installation)
            require(context is not None, "committed_context_missing")
            assert context is not None  # noqa: S101 - narrowed by require
            contexts[context.context_digest] = context
            for key, binding in context.recovery.items():
                require(key not in recovery, "duplicate_historical_recovery")
                recovery[key] = binding
        else:
            held_fence = _load_held_fence(installation, request)
        previous = request["previous_receipt_digest"]
        if previous is not None:
            prior_raw = installation.store.read(previous, kind="receipt")
            prior_value = read_json(prior_raw)
            prior: cp.CpMigrationTransitionReceiptV1 | cp.CpCommittedMigrationReceiptV1
            if prior_value.get("schema") == "dotmac.cp_committed_migration_receipt/1":
                _shape(prior_value, cp.CpCommittedMigrationReceiptV1)
                prior = cast(cp.CpCommittedMigrationReceiptV1, prior_value)
                require(
                    prior["historical_context_digest"] in contexts,
                    "historical_recovery_missing",
                )
            else:
                _shape(prior_value, cp.CpMigrationTransitionReceiptV1)
                prior = cast(cp.CpMigrationTransitionReceiptV1, prior_value)
                require(
                    cp.request_digest(prior["request"]) in recovery,
                    "historical_recovery_missing",
                )
            require(prior["phase"] == "complete", "incomplete_previous_receipt")
            cp.verify_any_receipt(
                prior_raw,
                store=installation.store,
                request=prior["request"],
                host_nonce=prior["host_nonce"],
                recovery=recovery,
                committed_contexts=contexts,
                routing_gate=True,
            )
        from vendor_cp.deployment.cp_transition_host import ExistingCpTransitionHost

        options: _HostContinuationArguments = {}
        if held_fence is not None:
            options["held_fence"] = held_fence
        if context is not None:
            options["committed_context"] = context
        if contexts:
            options["committed_contexts"] = contexts
        host = ExistingCpTransitionHost(
            installation.host, store=installation.store, recovery=recovery, **options
        )
        execution_contexts: _ExecutionContexts = {}
        if contexts:
            execution_contexts["committed_contexts"] = contexts
        if context is not None:
            return cp.execute_committed_continuation(
                raw,
                request_path=request_file,
                bundle_path=bundle_file,
                verifier=cp.GhAttestationVerifier(installation.policy),
                host=host,
                store=installation.store,
                recovery=recovery,
                context=context,
                clock=lambda: datetime.now(UTC),
                **execution_contexts,
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
            **execution_contexts,
        )
    except Exception:
        # Executor owns post-reservation compensation; never leak child output,
        # database diagnostics, configuration contents or exception strings.
        raise TransitionOperatorRefused("CP_TRANSITION_REFUSED") from None
