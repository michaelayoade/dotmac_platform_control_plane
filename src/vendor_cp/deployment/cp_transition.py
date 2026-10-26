"""CP-local transition request, immutable evidence store and execution checkpoints.

This source-only implementation composes one finite CP host transition. It
requires separately reviewed host installation policy. Digests identify CP
JSON/bytes; none is a Foundation descriptor digest.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, TypedDict, cast

from vendor_cp.deploy_agent.contracts import (
    Digest,
    Identifier,
    Revision,
    _shape,
    canonical_json,
    digest,
    read_json,
    require,
    sha,
    timestamp,
)
from vendor_cp.deployment.descriptor_binding import (
    SourceDescriptorDeclarations,
    source_descriptor_declarations,
)
from vendor_cp.deployment.effects import (
    REQUIRED_ROLES,
    PlatformBackupResult,
    PlatformCpRecoveryBundle,
)

if TYPE_CHECKING:
    from vendor_cp.deployment.transition_fence import FenceProof

RecoveryContexts = Mapping[str, tuple[PlatformCpRecoveryBundle, PlatformBackupResult]]


class TransitionSideV1(TypedDict):
    image_digest: Digest
    revision: Revision
    raw_descriptor_digest: Digest
    heads: list[Identifier]


class CpTransitionRequestV1(TypedDict):
    schema: Literal["dotmac.cp_transition_request/1"]
    product: Literal["dotmac_vendor_control_plane"]
    environment: Literal["production"]
    host: Identifier
    database: Identifier
    cluster_system_identifier: str
    database_oid: int
    source: TransitionSideV1
    target: TransitionSideV1
    plan_digest: Digest
    authorization_run_id: int
    authorization_run_attempt: int
    trusted_actor: Identifier
    expires_at: str
    previous_receipt_digest: Digest | None


Nonce = Annotated[str, r"[0-9a-f]{64}"]


class CommittedMigrationBasisV1(TypedDict):
    context_digest: Digest
    prior_request_digest: Digest
    prior_host_nonce: Nonce
    prior_reservation_digest: Digest
    prior_authorization_digest: Digest
    original_fence_digest: Digest
    current_fence_digest: Digest
    current_fence_id: Nonce
    frontier_measurement_digest: Digest


class CpCommittedMigrationRequestV1(TypedDict):
    schema: Literal["dotmac.cp_committed_migration_request/1"]
    product: Literal["dotmac_vendor_control_plane"]
    environment: Literal["production"]
    host: Identifier
    database: Identifier
    cluster_system_identifier: str
    database_oid: int
    source: TransitionSideV1
    target: TransitionSideV1
    previous_receipt_digest: Digest | None
    operator_revision: Revision
    basis: CommittedMigrationBasisV1
    plan_digest: Digest
    authorization_run_id: int
    authorization_run_attempt: int
    trusted_actor: Identifier
    expires_at: str


TransitionRequest = CpTransitionRequestV1 | CpCommittedMigrationRequestV1


@dataclass(frozen=True, slots=True)
class CpTransitionIdentity:
    """Explicit host-installed policy, never populated from request inputs."""

    host: str
    database: str
    cluster_system_identifier: str
    database_oid: int

    def __post_init__(self) -> None:
        _shape(self.host, Identifier)
        _shape(self.database, Identifier)
        require(
            self.cluster_system_identifier.isascii()
            and self.cluster_system_identifier.isdecimal()
            and int(self.cluster_system_identifier) > 0
        )
        require(type(self.database_oid) is int and self.database_oid > 0)


def validate_request(
    value: object, *, identity: CpTransitionIdentity, now: datetime
) -> CpTransitionRequestV1:
    _shape(value, CpTransitionRequestV1)
    request = cast(CpTransitionRequestV1, value)
    require(
        all(
            cast(dict[str, object], request)[key] == getattr(identity, key)
            for key in ("host", "database", "cluster_system_identifier", "database_oid")
        ),
        "host_mismatch",
    )
    require(
        request["authorization_run_id"] > 0 and request["authorization_run_attempt"] > 0
    )
    require(
        now < timestamp(request["expires_at"]) <= now + timedelta(hours=24), "expired"
    )
    require(
        request["plan_digest"] == transition_plan_digest(request),
        "plan_digest_mismatch",
    )
    for side in (request["source"], request["target"]):
        heads = side["heads"]
        require(bool(heads) and len(heads) == len(set(heads)))
        require(heads == sorted(heads))
    require(request["source"]["image_digest"] != request["target"]["image_digest"])
    return request


def load_request(
    raw: bytes, *, identity: CpTransitionIdentity, now: datetime
) -> CpTransitionRequestV1:
    return validate_request(read_json(raw), identity=identity, now=now)


PLAN_FIELDS = (
    "product",
    "environment",
    "host",
    "database",
    "cluster_system_identifier",
    "database_oid",
    "source",
    "target",
    "previous_receipt_digest",
)


COMMITTED_PLAN_FIELDS = (*PLAN_FIELDS, "operator_revision", "basis")


def transition_plan_digest(request: TransitionRequest) -> str:
    committed = request.get("schema") == "dotmac.cp_committed_migration_request/1"
    fields = COMMITTED_PLAN_FIELDS if committed else PLAN_FIELDS
    payload = {key: cast(dict[str, object], request)[key] for key in fields}
    if committed:
        payload["schema"] = "dotmac.cp_committed_migration_plan/1"
    return digest(payload)


def request_digest(request: TransitionRequest) -> str:
    """Digest of the exact closed CP JSON representation (not a signature)."""
    return digest(request)


def _protected(info: os.stat_result, *, directory: bool) -> None:
    require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "unsafe_artifact_path")
    require(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
        "unsafe_artifact_path",
    )
    if not directory:
        require(info.st_nlink == 1, "unsafe_artifact_path")


def _open_directory(path: Path) -> int:
    """Walk from / using directory descriptors; never follow a symlink."""
    require(path.is_absolute() and ".." not in path.parts, "unsafe_artifact_path")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _protected(os.fstat(current), directory=True)
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = child
            _protected(os.fstat(current), directory=True)
        return current
    except BaseException:
        os.close(current)
        raise


class ArtifactStore:
    """Root-owned retained artifacts; call reserve under the canonical CP lock.

    Creation is exclusive. A partial write or a crashed attempt consumes the
    name permanently. There is deliberately no deletion, replacement or retry.
    The owner supplies a pre-created root-protected directory; this class never
    repairs permissions or creates parent directories.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def _name(checksum: str, kind: str) -> str:
        sha(checksum)
        require(kind in {"reservation", "evidence", "receipt"})
        return f"{checksum[7:]}.{kind}.json"

    def _create(self, name: str, raw: bytes) -> None:
        directory = _open_directory(self.root)
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            try:
                _protected(os.fstat(descriptor), directory=False)
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    require(written > 0, "artifact_write_failed")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
                # Even a failed write leaves a durably consumed reservation.
                os.fsync(directory)
        finally:
            os.close(directory)

    def read(self, checksum: str, *, kind: str = "evidence") -> bytes:
        directory = _open_directory(self.root)
        try:
            descriptor = os.open(
                self._name(checksum, kind),
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            try:
                _protected(os.fstat(descriptor), directory=False)
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = stream.read(16 * 1024 * 1024 + 1)
                require(len(raw) <= 16 * 1024 * 1024, "artifact_too_large")
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        if kind != "reservation":
            require(raw_digest(raw) == checksum, "artifact_digest_mismatch")
        return raw

    def put(self, raw: bytes, *, kind: str = "evidence") -> str:
        require(kind in {"evidence", "receipt"} and bool(raw))
        checksum = raw_digest(raw)
        self._create(self._name(checksum, kind), raw)
        require(self.read(checksum, kind=kind) == raw, "artifact_readback_mismatch")
        return checksum

    def reserve(
        self, request: TransitionRequest, authorization: VerifiedAuthorization
    ) -> str:
        """Durably consume request digest and generate a distinct host nonce."""
        verify_authorization(request, authorization)
        checksum = request_digest(request)
        nonce = secrets.token_hex(32)
        raw = canonical_json(
            {
                "schema": "dotmac.cp_transition_attempt/2",
                "verification_digest": raw_digest(authorization.verification_bytes),
                "request_digest": checksum,
                "host_nonce": nonce,
                "authorization_run_id": request["authorization_run_id"],
                "authorization_run_attempt": request["authorization_run_attempt"],
            }
        )
        self._create(self._name(checksum, "reservation"), raw)
        require(self.read(checksum, kind="reservation") == raw)
        return nonce

    def reserve_committed_frontier(
        self,
        context: CommittedMigrationContext,
        request: CpCommittedMigrationRequestV1,
        *,
        host_nonce: str,
        fresh_reservation_digest: str,
    ) -> bytes:
        """Consume the independently pinned prior attempt, under the CP lock.

        This key excludes the fresh store and context, so sibling proposals
        contend. Failed and partial writes are permanently consumed.
        """
        require(self.root == context.prior_store.root, "committed_prior_store_mismatch")
        raw = canonical_json(
            _frontier_claim(context, request, host_nonce, fresh_reservation_digest)
        )
        key = committed_frontier_key(context)
        self._create(self._name(key, "reservation"), raw)
        require(self.read(key, kind="reservation") == raw, "artifact_readback_mismatch")
        return raw


def raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class SingleUserManualV2(TypedDict):
    """Owner dispatch plus manual production approval; administrator bypass off."""

    schema: Literal["dotmac.cp_transition_environment_protection/2"]
    repository_id: str
    repository_owner_id: str
    workflow_revision: Revision
    environment: Literal["production"]
    protected_main: Literal[True]
    approval_model: Literal["single-user-manual"]
    prevent_self_review: Literal[False]
    can_admins_bypass: Literal[False]
    required_reviewer_ids: list[int]
    expires_at: str


@dataclass(frozen=True, slots=True)
class CpTransitionTrustPolicy:
    """Reviewed installation inputs. There are no production fallback values."""

    identity: CpTransitionIdentity
    gh_binary: Path
    gh_binary_digest: str
    gh_config_directory: Path
    repository: str
    repository_id: str
    repository_owner_id: str
    workflow_path: str
    workflow_revision: str
    predicate_type: str
    environment_protection_proof: Path
    environment_protection_digest: str

    def __post_init__(self) -> None:
        import re

        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository)
            is not None
        )
        require(
            re.fullmatch(
                r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", self.workflow_path
            )
            is not None
        )
        require(
            all(
                value.isascii() and value.isdecimal() and int(value) > 0
                for value in (self.repository_id, self.repository_owner_id)
            )
        )
        sha(self.workflow_revision, prefix=False)
        sha(self.gh_binary_digest)
        sha(self.environment_protection_digest)
        require(
            self.predicate_type.startswith("https://")
            and len(self.predicate_type) < 512
        )


def _read_protected(path: Path) -> bytes:
    directory = _open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            _protected(os.fstat(descriptor), directory=False)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def _protected_executable_digest(path: Path) -> str:
    """Hash a regular root-protected executable without loading it in memory."""
    directory = _open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            _protected(info, directory=False)
            require(info.st_mode & 0o111 != 0, "executable_required")
            checksum = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while chunk := stream.read(1024 * 1024):
                    checksum.update(chunk)
            return "sha256:" + checksum.hexdigest()
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


GLOBALS_BOOTSTRAP_STATEMENT = "CREATE ROLE postgres;\n"


def globals_replay_fingerprint(path: Path) -> tuple[str, int]:
    """Reconstruct the supported initdb adaptation from protected original bytes."""
    directory = _open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            _protected(os.fstat(descriptor), directory=False)
            checksum, size, removed = hashlib.sha256(), 0, 0
            beginning = True
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while part := stream.readline(1024 * 1024):
                    if beginning and part == GLOBALS_BOOTSTRAP_STATEMENT.encode():
                        removed += 1
                    else:
                        checksum.update(part)
                        size += len(part)
                    beginning = part.endswith(b"\n")
            require(removed == 1 and size > 0, "globals_bootstrap_statement_count")
            return "sha256:" + checksum.hexdigest(), size
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


_VERIFIED = object()


@dataclass(frozen=True, slots=True)
class VerifiedAuthorization:
    request_digest: str
    authorization_run_id: int
    authorization_run_attempt: int
    trusted_actor: str
    verification_bytes: bytes
    _witness: object = None


def verify_authorization(
    request: TransitionRequest, authorization: VerifiedAuthorization
) -> None:
    """Require the exact in-process authorization issued by the gh owner."""
    require(
        authorization._witness
        == (
            _VERIFIED,
            request_digest(request),
            request["authorization_run_id"],
            request["authorization_run_attempt"],
            request["trusted_actor"],
            raw_digest(authorization.verification_bytes),
        )
        and authorization.request_digest == request_digest(request)
        and authorization.authorization_run_id == request["authorization_run_id"]
        and authorization.authorization_run_attempt
        == request["authorization_run_attempt"]
        and authorization.trusted_actor == request["trusted_actor"],
        "unverified_authorization",
    )


class GhAttestationVerifier:
    """Execute the published gh verifier, then restrict verified certificate facts.

    JSON is read only from this process's successful stdout. There is no public
    API accepting a caller's claim to have verified an attestation. Certificate
    field spellings follow sigstore-go/docs/verification.md; gh's wrapper follows
    https://cli.github.com/manual/gh_attestation_verify.
    """

    def __init__(self, policy: CpTransitionTrustPolicy) -> None:
        self.policy = policy

    def verify(
        self,
        request: TransitionRequest,
        *,
        request_path: Path,
        bundle_path: Path | None,
        now: datetime,
    ) -> VerifiedAuthorization:
        import subprocess  # noqa: S404 - pinned absolute binary, fixed argv/env

        policy = self.policy
        validate_any_request(request, identity=policy.identity, now=now)
        raw = _read_protected(request_path)
        require(raw == canonical_json(request), "request_bytes_mismatch")
        require(
            _protected_executable_digest(policy.gh_binary) == policy.gh_binary_digest,
            "verifier_binary_mismatch",
        )
        directory = _open_directory(policy.gh_config_directory)
        os.close(directory)
        proof_bytes = _read_protected(policy.environment_protection_proof)
        require(
            raw_digest(proof_bytes) == policy.environment_protection_digest,
            "environment_protection_mismatch",
        )
        proof = read_json(proof_bytes)
        _shape(proof, SingleUserManualV2)
        require(
            proof["repository_id"] == policy.repository_id
            and proof["repository_owner_id"] == policy.repository_owner_id
            and proof["workflow_revision"] == policy.workflow_revision
            and proof["required_reviewer_ids"] == [int(policy.repository_owner_id)]
            and request["trusted_actor"] == policy.repository.split("/", 1)[0]
            and timestamp(cast(str, proof["expires_at"])) > now,
            "environment_protection_mismatch",
        )
        workflow = f"{policy.repository}/{policy.workflow_path}"
        argv = [
            str(policy.gh_binary),
            "attestation",
            "verify",
            str(request_path),
            "--repo",
            policy.repository,
            "--signer-workflow",
            workflow,
            "--signer-digest",
            policy.workflow_revision,
            "--source-digest",
            policy.workflow_revision,
            "--source-ref",
            "refs/heads/main",
            "--deny-self-hosted-runners",
            "--format",
            "json",
            "--predicate-type",
            policy.predicate_type,
        ]
        if bundle_path is not None:
            _read_protected(bundle_path)
            argv += ["--bundle", str(bundle_path)]
        completed = subprocess.run(  # noqa: S603 - root-protected hash-pinned gh
            argv,
            env={
                "GH_CONFIG_DIR": str(policy.gh_config_directory),
                "PATH": "/usr/bin:/bin",
                "HOME": "/nonexistent",
            },
            capture_output=True,
            timeout=120,
            check=False,
        )
        require(completed.returncode == 0, "attestation_verification_failed")
        require(
            len(completed.stdout) <= 16 * 1024 * 1024, "verification_output_too_large"
        )
        run, attempt = _verify_authorization_report(
            request,
            policy=policy,
            verification_bytes=completed.stdout,
            request_name=request_path.name,
            now=now,
        )
        return VerifiedAuthorization(
            request_digest(request),
            run,
            attempt,
            request["trusted_actor"],
            completed.stdout,
            (
                _VERIFIED,
                request_digest(request),
                run,
                attempt,
                request["trusted_actor"],
                raw_digest(completed.stdout),
            ),
        )


def _verify_authorization_report(
    request: TransitionRequest,
    *,
    policy: CpTransitionTrustPolicy,
    verification_bytes: bytes,
    request_name: str,
    now: datetime,
) -> tuple[int, int]:
    """Restrict a successful verifier report; never mint execution authority."""
    import re

    wrapped = read_json(b'{"results":' + verification_bytes + b"}")
    results = wrapped["results"]
    require(isinstance(results, list) and len(results) == 1, "ambiguous_attestation")
    result = cast(dict[str, object], cast(list[object], results)[0])
    require(
        isinstance(result, dict) and isinstance(result.get("verificationResult"), dict)
    )
    verified = cast(dict[str, object], result["verificationResult"])
    signature = cast(dict[str, object], verified.get("signature"))
    require(
        isinstance(signature, dict) and isinstance(signature.get("certificate"), dict)
    )
    cert = cast(dict[str, object], signature["certificate"])
    repository_uri = f"https://github.com/{policy.repository}"
    signer_uri = f"{repository_uri}/{policy.workflow_path}@refs/heads/main"
    expected: dict[str, object] = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": signer_uri,
        "buildSignerURI": signer_uri,
        "buildSignerDigest": policy.workflow_revision,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": repository_uri,
        "sourceRepositoryDigest": policy.workflow_revision,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": policy.repository_id,
        "sourceRepositoryOwnerIdentifier": policy.repository_owner_id,
        "buildConfigURI": signer_uri,
        "buildConfigDigest": policy.workflow_revision,
    }
    require(
        all(cert.get(key) == value for key, value in expected.items()),
        "authorization_identity_mismatch",
    )
    match = re.fullmatch(
        re.escape(repository_uri)
        + r"/actions/runs/([1-9][0-9]*)/attempts/([1-9][0-9]*)",
        str(cert.get("runInvocationURI")),
    )
    require(match is not None, "authorization_run_mismatch")
    assert match is not None  # noqa: S101 - narrowed by require
    run, attempt = map(int, match.groups())
    require(
        (run, attempt)
        == (request["authorization_run_id"], request["authorization_run_attempt"]),
        "authorization_run_mismatch",
    )
    observed_times = verified.get("verifiedTimestamps")
    require(
        isinstance(observed_times, list) and bool(observed_times),
        "missing_verified_timestamp",
    )
    for item in cast(list[dict[str, object]], observed_times):
        require(
            isinstance(item, dict)
            and item.get("type") in {"Tlog", "TimestampAuthority"}
        )
        observed = datetime.fromisoformat(
            str(item.get("timestamp")).replace("Z", "+00:00")
        )
        require(
            observed.tzinfo is not None
            and observed <= now
            and timestamp(request["expires_at"]) - timedelta(hours=24) <= observed
            and observed < timestamp(request["expires_at"]),
            "invalid_verified_timestamp",
        )
    statement = verified.get("statement")
    require(isinstance(statement, dict))
    statement = cast(dict[str, object], statement)
    require(statement.get("predicateType") == policy.predicate_type)
    require(
        statement.get("subject")
        == [
            {
                "name": request_name,
                "digest": {"sha256": raw_digest(canonical_json(request))[7:]},
            }
        ],
        "authorization_subject_mismatch",
    )
    # Actor is populated from github.actor by this exact reviewed producer,
    # never from dispatch inputs. Run identity above is independently certified.
    require(
        statement.get("predicate")
        == {
            "request_digest": request_digest(request),
            "trusted_actor": request["trusted_actor"],
            "environment": "production",
        },
        "authorization_predicate_mismatch",
    )
    return run, attempt


class SourceObservation(TypedDict):
    side: TransitionSideV1
    descriptor_declarations: SourceDescriptorDeclarations
    database_owner: Identifier
    roles: list[Identifier]
    catalogue_digest: Digest


class BootstrapIdentityV1(TypedDict):
    role: Literal["postgres"]
    oid: Literal[10]
    superuser: Literal[True]


class GlobalsReplayProofV1(TypedDict):
    schema: Literal["dotmac.cp_globals_replay/1"]
    request_digest: Digest
    host_nonce: str
    original_digest: Digest
    original_size: int
    replay_digest: Digest
    replay_size: int
    omitted_statement: Literal["CREATE ROLE postgres;\n"]
    source_bootstrap: BootstrapIdentityV1
    fresh_bootstrap: BootstrapIdentityV1


class RestoreObservation(TypedDict):
    source: SourceObservation
    restored_source: SourceObservation
    restore_evidence_digest: Digest
    manifest_digest: Digest
    manifest_size: int
    dump_digest: Digest
    globals_digest: Digest
    dump_size: int
    globals_size: int
    restored_dump_digest: Digest
    restored_globals_digest: Digest
    globals_replay_digest: Digest
    catalogue_comparison_digest: Digest


class CandidateQuiescenceProofV1(TypedDict):
    schema: Literal["dotmac.cp_candidate_quiescence/1"]
    request_digest: Digest
    host_nonce: str
    before_digest: Digest
    after_digest: Digest


class CandidateMeasurementV1(TypedDict):
    track_counts: Literal[True]
    stats_reset: str | None
    server_start: str
    relations: list[list[str | int]]
    sequences: list[list[str | int | None]]
    catalogue_digest: Digest


class CandidateSnapshotV1(TypedDict):
    schema: Literal["dotmac.cp_candidate_quiescence_snapshot/1"]
    request_digest: Digest
    host_nonce: str
    measurement: CandidateMeasurementV1


class CandidateClosureV1(TypedDict):
    candidate_sessions: Literal[0]
    candidate_roles: list[Identifier]
    writer_sessions: Literal[0]
    reconnect_denial: Literal["database_acl"]
    quiescence_digest: Digest


def _validate_evidence(
    value: dict[str, object],
    *,
    request: TransitionRequest,
    nonce: str,
    kind: str,
    store: ArtifactStore,
    evidence: dict[str, str],
    recovery: RecoveryContexts,
) -> None:
    """Closed draft stage records; never accept arbitrary facts as measurements.

    Records must be produced by the existing measured owners in the future
    host adapter. This verifier establishes bindings, not host provenance.
    """
    require(set(value) == {"schema", "request_digest", "host_nonce", "kind", "result"})
    require(value["schema"] == "dotmac.cp_transition_evidence/2")
    require(value["request_digest"] == request_digest(request))
    require(value["host_nonce"] == nonce and value["kind"] == kind)
    result = value["result"]
    source, target = request["source"], request["target"]
    expected: dict[str, object] = {
        "inspection": {"source": source, "target": target},
        "authorization": {
            "verification_digest": read_json(
                store.read(request_digest(request), kind="reservation")
            )["verification_digest"],
            "run_id": request["authorization_run_id"],
            "run_attempt": request["authorization_run_attempt"],
            "trusted_actor": request["trusted_actor"],
        },
        "maintenance": {
            "external_status": 503,
            "active_http": 0,
            "active_websockets": 0,
        },
        "strict-fence-reconnect": {
            "database": request["database"],
            "writer_sessions": 0,
            "reconnect_denial": "database_acl",
        },
        "writers-stopped": {"running_writers": [], "restart_enabled": []},
        "fence-source-rechecked": {
            "source": source,
            "writer_sessions": 0,
            "reconnect_denial": "database_acl",
        },
        "migrate": {
            "heads": target["heads"],
            "restore_digest": evidence.get("recovery-restored"),
            "fence_digest": evidence.get("fence-source-rechecked"),
        },
        "migrated-target-heads": target,
        "candidate-ready": {"side": target, "status": 200, "writer_sessions": 0},
        "acl-restored": {"database": request["database"], "acl_difference": []},
        "full-ready": {"side": target, "status": 200},
        "routing-restored": {"side": target, "external_status": 200},
        "pre-routing-verified": {"receipt_digest": evidence.get("pre-routing-receipt")},
        "failure": {
            "external_status": 503,
            "writer_sessions": 0,
            "reconnect_denial": "database_acl",
        },
    }
    if kind == "source-genesis":
        _shape(result, SourceObservation)
        observed = cast(SourceObservation, result)
        require(observed["side"] == source and bool(observed["roles"]))
        require(observed["roles"] == sorted(set(observed["roles"])))
        require(observed["database_owner"] == "app_admin")
        require(set(REQUIRED_ROLES) <= set(observed["roles"]))
        store.read(observed["catalogue_digest"])
        descriptor = store.read(source["raw_descriptor_digest"])
        require(
            raw_digest(descriptor) == source["raw_descriptor_digest"]
            and observed["descriptor_declarations"]
            == source_descriptor_declarations(descriptor),
            "source_descriptor_observation_mismatch",
        )
    elif kind == "recovery-restored":
        # The public authorization producer imports this module with only its
        # portable crypto dependencies. Database verification is execution-only.
        from vendor_cp.deployment.cp_catalogue import verify_restore_comparison

        _shape(result, RestoreObservation)
        restored = cast(RestoreObservation, result)
        genesis_document = read_json(store.read(evidence["source-genesis"]))["result"]
        _shape(genesis_document, SourceObservation)
        genesis = cast(SourceObservation, genesis_document)
        require(restored["source"] == genesis, "restore_source_mismatch")
        require(
            {key: value for key, value in genesis.items() if key != "catalogue_digest"}
            == {
                key: value
                for key, value in restored["restored_source"].items()
                if key != "catalogue_digest"
            },
            "restore_source_mismatch",
        )
        comparison_bytes = store.read(restored["catalogue_comparison_digest"])
        verify_restore_comparison(
            comparison_bytes,
            store.read(genesis["catalogue_digest"]),
            store.read(restored["restored_source"]["catalogue_digest"]),
            request_digest=request_digest(request),
            host_nonce=nonce,
            expected_source_cluster=request["cluster_system_identifier"],
            expected_source_database=request["database"],
        )
        comparison = read_json(comparison_bytes)
        parser = cast(dict[str, object], comparison["parser"])
        require(
            parser["cluster_system_identifier"] != request["cluster_system_identifier"],
            "scratch_is_source_cluster",
        )
        restored_bytes = store.read(restored["restore_evidence_digest"])
        require(read_json(restored_bytes) == restored["restored_source"])
        manifest_bytes = store.read(restored["manifest_digest"])
        require(len(manifest_bytes) == restored["manifest_size"] > 0)
        manifest = read_json(manifest_bytes)
        require(
            manifest.get("database_name") == request["database"]
            and manifest.get("cluster_system_identifier")
            == request["cluster_system_identifier"],
            "recovery_database_mismatch",
        )
        owner, backup = recovery[request_digest(request)]
        require(
            owner.matches_transition(
                product=request["product"],
                environment=request["environment"],
                target=request["host"],
                source_image_digest=source["image_digest"],
                source_revision=source["revision"],
                source_descriptor_raw_sha256=source["raw_descriptor_digest"],
                source_heads=source["heads"],
                target_image_digest=target["image_digest"],
                target_source_revision=target["revision"],
                target_descriptor_raw_sha256=target["raw_descriptor_digest"],
            ),
            "recovery_context_mismatch",
        )
        require(owner.verify(backup), "recovery_owner_refused")
        require(
            restored["manifest_digest"] == "sha256:" + backup.checksum
            and restored["manifest_size"] == backup.manifest_size_bytes
            and restored["dump_digest"]
            == restored["restored_dump_digest"]
            == backup.database_dump_sha256
            and restored["globals_digest"] == backup.globals_sha256
            and restored["dump_size"] == backup.database_dump_size_bytes
            and restored["globals_size"] == backup.globals_size_bytes,
            "recovery_result_mismatch",
        )
        proof_document = read_json(store.read(restored["globals_replay_digest"]))
        _shape(proof_document, GlobalsReplayProofV1)
        replay = cast(GlobalsReplayProofV1, proof_document)
        replay_digest, replay_size = globals_replay_fingerprint(
            Path(backup.path) / "globals.sql"
        )
        require(
            replay["request_digest"] == request_digest(request)
            and replay["host_nonce"] == nonce
            and replay["original_digest"] == backup.globals_sha256
            and type(replay["original_size"]) is int
            and replay["original_size"] == backup.globals_size_bytes
            and replay["replay_digest"]
            == replay_digest
            == restored["restored_globals_digest"]
            and type(replay["replay_size"]) is int
            and replay["replay_size"] == replay_size
            and replay_size
            == backup.globals_size_bytes - len(GLOBALS_BOOTSTRAP_STATEMENT.encode()),
            "globals_replay_binding_mismatch",
        )
        for identity in (replay["source_bootstrap"], replay["fresh_bootstrap"]):
            require(
                identity["role"] == "postgres"
                and type(identity["oid"]) is int
                and identity["oid"] == 10
                and identity["superuser"] is True,
                "globals_bootstrap_identity_mismatch",
            )
        for observation in (genesis, restored["restored_source"]):
            catalogue = read_json(store.read(observation["catalogue_digest"]))
            bootstrap = catalogue.get("bootstrap")
            require(
                bootstrap == [["postgres", 10, True]]
                and type(bootstrap[0][1]) is int
                and bootstrap[0][2] is True,
                "globals_bootstrap_identity_mismatch",
            )
    elif kind == "candidate-removed-fenced":
        _shape(result, CandidateClosureV1)
        closed = cast(CandidateClosureV1, result)
        require(
            canonical_json(closed)
            == canonical_json(
                {
                    "candidate_sessions": 0,
                    "candidate_roles": [],
                    "writer_sessions": 0,
                    "reconnect_denial": "database_acl",
                    "quiescence_digest": closed["quiescence_digest"],
                }
            ),
            "candidate_cleanup_unproved",
        )
        _verify_candidate_quiescence(
            closed["quiescence_digest"], request=request, nonce=nonce, store=store
        )

    else:
        require(
            kind in expected
            and canonical_json(result) == canonical_json(expected[kind]),
            "stage_result_mismatch",
        )
        if kind == "authorization":
            store.read(cast(dict[str, str], result)["verification_digest"])


def _verify_candidate_quiescence(
    proof_digest: str, *, request: TransitionRequest, nonce: str, store: ArtifactStore
) -> None:
    proof = read_json(store.read(proof_digest))
    _shape(proof, CandidateQuiescenceProofV1)
    require(
        proof["request_digest"] == request_digest(request)
        and proof["host_nonce"] == nonce
        and proof["before_digest"] == proof["after_digest"],
        "candidate_mutation_observed",
    )
    before = store.read(cast(str, proof["before_digest"]))
    require(before == store.read(cast(str, proof["after_digest"])))
    document = read_json(before)
    _shape(document, CandidateSnapshotV1)
    snapshot = cast(CandidateSnapshotV1, document)
    require(
        snapshot["request_digest"] == request_digest(request)
        and snapshot["host_nonce"] == nonce,
        "candidate_snapshot_mismatch",
    )
    measured = snapshot["measurement"]
    require(measured["track_counts"] is True and bool(measured["relations"]))
    for row in measured["relations"]:
        require(
            len(row) == 7
            and all(isinstance(item, str) and bool(item) for item in row[:2])
            and all(type(item) is int and item >= 0 for item in row[2:])
        )
    for sequence in measured["sequences"]:
        require(
            len(sequence) == 3
            and all(isinstance(item, str) and bool(item) for item in sequence[:2])
            and (sequence[2] is None or type(sequence[2]) is int)
        )
    store.read(measured["catalogue_digest"])


class CpMigrationTransitionReceiptV1(TypedDict):
    schema: Literal["dotmac.cp_migration_transition_receipt/1"]
    request: CpTransitionRequestV1
    request_digest: Digest
    host_nonce: str
    phase: Literal["pre-routing", "complete"]
    genesis_digest: Digest | None
    previous_receipt_digest: Digest | None
    evidence: dict[Identifier, Digest]


PRE_MIGRATION_EVIDENCE = {
    "inspection",
    "authorization",
    "maintenance",
    "strict-fence-reconnect",
    "writers-stopped",
    "source-genesis",
    "recovery-restored",
    "fence-source-rechecked",
}
PRE_ACL_EVIDENCE = PRE_MIGRATION_EVIDENCE | {
    "migrate",
    "migrated-target-heads",
    "candidate-ready",
    "candidate-removed-fenced",
}
RUNTIME_EVIDENCE = {"acl-restored", "full-ready"}
ROUTING_EVIDENCE = {"pre-routing-verified", "routing-restored"}


def verify_transition_prefix(
    request: CpTransitionRequestV1,
    *,
    authorization: VerifiedAuthorization,
    store: ArtifactStore,
    host_nonce: str,
    evidence: Mapping[str, str],
    recovery: RecoveryContexts,
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> None:
    """Join retained pre-DDL facts to the single authenticated host attempt.

    The concrete host and migration owners must still measure their respective
    live observations. Retained bytes cannot replace those independent reads.
    """
    verify_authorization(request, authorization)
    verify_predecessor(
        request, store=store, recovery=recovery, committed_contexts=committed_contexts
    )
    reservation = read_json(store.read(request_digest(request), kind="reservation"))
    require(
        reservation
        == {
            "schema": "dotmac.cp_transition_attempt/2",
            "request_digest": request_digest(request),
            "host_nonce": host_nonce,
            "authorization_run_id": request["authorization_run_id"],
            "authorization_run_attempt": request["authorization_run_attempt"],
            "verification_digest": raw_digest(authorization.verification_bytes),
        },
        "reservation_mismatch",
    )
    require(set(evidence) == PRE_MIGRATION_EVIDENCE, "pre_migration_evidence_mismatch")
    require(
        store.read(raw_digest(authorization.verification_bytes))
        == authorization.verification_bytes,
        "authorization_bytes_mismatch",
    )
    retained = dict(evidence)
    for kind, checksum in retained.items():
        _validate_evidence(
            read_json(store.read(checksum)),
            request=request,
            nonce=host_nonce,
            kind=kind,
            store=store,
            evidence=retained,
            recovery=recovery,
        )


def verify_predecessor(
    request: CpTransitionRequestV1,
    *,
    store: ArtifactStore,
    recovery: RecoveryContexts,
    depth: int = 0,
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> None:
    """Verify the complete independent chain anchor before host mutation or DDL."""
    require(depth < 32, "receipt_chain_too_deep")
    checksum = request["previous_receipt_digest"]
    if checksum is None:
        return
    raw = store.read(checksum, kind="receipt")
    prior = read_json(raw)
    if prior.get("schema") == "dotmac.cp_committed_migration_receipt/1":
        _shape(prior, CpCommittedMigrationReceiptV1)
    else:
        _shape(prior, CpMigrationTransitionReceiptV1)
    previous = cast(
        CpMigrationTransitionReceiptV1 | CpCommittedMigrationReceiptV1, prior
    )
    require(
        previous["phase"] == "complete"
        and previous["request"]["target"] == request["source"],
        "predecessor_transition_mismatch",
    )
    require(
        all(
            cast(dict[str, object], previous["request"])[key]
            == cast(dict[str, object], request)[key]
            for key in (
                "product",
                "environment",
                "host",
                "database",
                "cluster_system_identifier",
                "database_oid",
            )
        ),
        "predecessor_identity_mismatch",
    )
    verify_any_receipt(
        raw,
        store=store,
        request=previous["request"],
        host_nonce=previous["host_nonce"],
        routing_gate=True,
        _depth=depth + 1,
        recovery=recovery,
        committed_contexts=committed_contexts,
    )


def verify_receipt(
    raw: bytes,
    *,
    store: ArtifactStore,
    request: CpTransitionRequestV1,
    host_nonce: str,
    recovery: RecoveryContexts,
    routing_gate: bool = False,
    _depth: int = 0,
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> CpMigrationTransitionReceiptV1:
    require(_depth < 32, "receipt_chain_too_deep")
    reservation = read_json(store.read(request_digest(request), kind="reservation"))
    require(
        reservation
        == {
            "schema": "dotmac.cp_transition_attempt/2",
            "request_digest": request_digest(request),
            "host_nonce": host_nonce,
            "authorization_run_id": request["authorization_run_id"],
            "authorization_run_attempt": request["authorization_run_attempt"],
            "verification_digest": reservation.get("verification_digest"),
        },
        "reservation_mismatch",
    )
    sha(reservation["verification_digest"])
    receipt = read_json(raw)
    _shape(receipt, CpMigrationTransitionReceiptV1)
    value = cast(CpMigrationTransitionReceiptV1, receipt)
    require(
        value["request"] == request
        and value["request_digest"] == request_digest(request)
    )
    require(value["host_nonce"] == host_nonce)
    require(value["previous_receipt_digest"] == request["previous_receipt_digest"])
    require(
        (value["genesis_digest"] is None) != (value["previous_receipt_digest"] is None)
    )
    required = PRE_ACL_EVIDENCE | (RUNTIME_EVIDENCE if routing_gate else set())
    allowed = PRE_ACL_EVIDENCE | RUNTIME_EVIDENCE
    if value["phase"] == "complete":
        required |= RUNTIME_EVIDENCE | ROUTING_EVIDENCE
        allowed |= ROUTING_EVIDENCE
    require(required <= set(value["evidence"]) <= allowed, "receipt_phase_mismatch")
    require(
        value["genesis_digest"] is None
        or value["genesis_digest"] == value["evidence"]["source-genesis"]
    )
    validation_evidence = dict(value["evidence"])
    if "pre-routing-verified" in validation_evidence:
        pre_routing = dict(value)
        pre_routing["phase"] = "pre-routing"
        pre_routing["evidence"] = {
            key: checksum
            for key, checksum in value["evidence"].items()
            if key not in ROUTING_EVIDENCE
        }
        validation_evidence["pre-routing-receipt"] = raw_digest(
            canonical_json(pre_routing)
        )
        store.read(validation_evidence["pre-routing-receipt"], kind="receipt")
    for kind, checksum in value["evidence"].items():
        evidence = read_json(store.read(checksum))
        _validate_evidence(
            evidence,
            request=request,
            nonce=host_nonce,
            kind=kind,
            store=store,
            evidence=validation_evidence,
            recovery=recovery,
        )
    verify_predecessor(
        request,
        store=store,
        recovery=recovery,
        depth=_depth,
        committed_contexts=committed_contexts,
    )
    return value


class CpTransitionHost(Protocol):
    def lock(self) -> AbstractContextManager[None]: ...
    def inspect(self, request: CpTransitionRequestV1) -> bytes: ...
    def maintenance(self, request: CpTransitionRequestV1, nonce: str) -> bytes: ...
    def fence_and_negative_reconnect(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes: ...
    def stop_and_drain_writers(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes: ...
    def source_genesis(self, request: CpTransitionRequestV1, nonce: str) -> bytes: ...
    def capture_and_restore(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes: ...
    def recheck_fence_source(
        self, request: CpTransitionRequestV1, nonce: str
    ) -> bytes: ...
    def migrate(
        self,
        request: CpTransitionRequestV1,
        nonce: str,
        *,
        authorization: VerifiedAuthorization,
        reservation_digest: str,
        genesis_digest: str,
        restore_digest: str,
        fence_digest: str,
        evidence: Mapping[str, str],
    ) -> bytes: ...
    def target_heads(self, request: TransitionRequest, nonce: str) -> bytes: ...
    def candidate_ready(self, request: TransitionRequest, nonce: str) -> bytes: ...
    def close_candidate_and_refence(
        self, request: TransitionRequest, nonce: str
    ) -> bytes: ...
    def restore_acl(self, request: TransitionRequest, nonce: str) -> bytes: ...
    def full_ready(self, request: TransitionRequest, nonce: str) -> bytes: ...
    def verify_pre_routing(self, receipt_bytes: bytes) -> bytes: ...
    def restore_routing(self, request: TransitionRequest, nonce: str) -> bytes: ...
    def fail_closed(
        self, request: TransitionRequest, nonce: str, *, acl_may_be_restored: bool
    ) -> bytes: ...


def execute_transition(
    raw_request: bytes,
    *,
    request_path: Path,
    bundle_path: Path | None,
    verifier: GhAttestationVerifier,
    host: CpTransitionHost,
    store: ArtifactStore,
    recovery: RecoveryContexts,
    clock: Callable[[], datetime],
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> str:
    """Single-use CP owner. Failure never retries or restores public routing."""
    with host.lock():
        now = clock()
        request = load_request(raw_request, identity=verifier.policy.identity, now=now)
        authorization = verifier.verify(
            request, request_path=request_path, bundle_path=bundle_path, now=now
        )
        verify_predecessor(
            request,
            store=store,
            recovery=recovery,
            committed_contexts=committed_contexts,
        )
        inspection = host.inspect(request)
        validate_request(request, identity=verifier.policy.identity, now=clock())
        nonce = store.reserve(request, authorization)
        evidence: dict[str, str] = {}
        acl_may_be_restored = False

        def retain(kind: str, raw: bytes) -> str:
            value = read_json(raw)
            _validate_evidence(
                value,
                request=request,
                nonce=nonce,
                kind=kind,
                store=store,
                evidence=evidence,
                recovery=recovery,
            )
            checksum = store.put(raw)
            evidence[kind] = checksum
            return checksum

        def local(kind: str, facts: dict[str, object]) -> bytes:
            return canonical_json(
                {
                    "schema": "dotmac.cp_transition_evidence/2",
                    "request_digest": request_digest(request),
                    "host_nonce": nonce,
                    "kind": kind,
                    "result": facts,
                }
            )

        def receipt(
            phase: Literal["pre-routing", "complete"], *, routing_gate: bool
        ) -> bytes:
            value: CpMigrationTransitionReceiptV1 = {
                "schema": "dotmac.cp_migration_transition_receipt/1",
                "request": request,
                "request_digest": request_digest(request),
                "host_nonce": nonce,
                "phase": phase,
                "genesis_digest": evidence["source-genesis"]
                if request["previous_receipt_digest"] is None
                else None,
                "previous_receipt_digest": request["previous_receipt_digest"],
                "evidence": dict(evidence),
            }
            raw = canonical_json(value)
            verify_receipt(
                raw,
                store=store,
                request=request,
                host_nonce=nonce,
                routing_gate=routing_gate,
                recovery=recovery,
                committed_contexts=committed_contexts,
            )
            checksum = store.put(raw, kind="receipt")
            return store.read(checksum, kind="receipt")

        try:
            # Pre-reservation inspection has no host nonce; owner binds its exact bytes.
            retain(
                "inspection",
                local("inspection", read_json(inspection)),
            )
            auth_digest = store.put(authorization.verification_bytes)
            retain(
                "authorization",
                local(
                    "authorization",
                    {
                        "verification_digest": auth_digest,
                        "run_id": authorization.authorization_run_id,
                        "run_attempt": authorization.authorization_run_attempt,
                        "trusted_actor": authorization.trusted_actor,
                    },
                ),
            )
            for kind, action in (
                ("maintenance", host.maintenance),
                ("strict-fence-reconnect", host.fence_and_negative_reconnect),
                ("writers-stopped", host.stop_and_drain_writers),
                ("source-genesis", host.source_genesis),
                ("recovery-restored", host.capture_and_restore),
                ("fence-source-rechecked", host.recheck_fence_source),
            ):
                retain(kind, action(request, nonce))
            verify_transition_prefix(
                request,
                authorization=authorization,
                store=store,
                host_nonce=nonce,
                evidence=evidence,
                recovery=recovery,
                committed_contexts=committed_contexts,
            )
            retain(
                "migrate",
                host.migrate(
                    request,
                    nonce,
                    authorization=authorization,
                    reservation_digest=request_digest(request),
                    genesis_digest=evidence["source-genesis"],
                    restore_digest=evidence["recovery-restored"],
                    fence_digest=evidence["fence-source-rechecked"],
                    evidence=dict(evidence),
                ),
            )
            retain("migrated-target-heads", host.target_heads(request, nonce))

            def mark_acl() -> None:
                nonlocal acl_may_be_restored
                acl_may_be_restored = True

            return _execute_common_suffix(
                request,
                nonce=nonce,
                host=host,
                store=store,
                evidence=evidence,
                retain=retain,
                receipt=receipt,
                mark_acl=mark_acl,
            )

        except BaseException as original:
            try:
                failure = host.fail_closed(
                    request, nonce, acl_may_be_restored=acl_may_be_restored
                )
                retain("failure", failure)
            except BaseException as compensation:
                original.add_note(
                    f"Fail-closed compensation failed: {type(compensation).__name__}"
                )
            raise


def validate_committed_request(
    value: object, *, identity: CpTransitionIdentity, now: datetime
) -> CpCommittedMigrationRequestV1:
    _shape(value, CpCommittedMigrationRequestV1)
    request = cast(CpCommittedMigrationRequestV1, value)
    require(now.tzinfo is not None)
    require(
        all(
            cast(dict[str, object], request)[key] == getattr(identity, key)
            for key in ("host", "database", "cluster_system_identifier", "database_oid")
        ),
        "host_mismatch",
    )
    require(
        request["authorization_run_id"] > 0 and request["authorization_run_attempt"] > 0
    )
    require(
        now < timestamp(request["expires_at"]) <= now + timedelta(hours=24), "expired"
    )
    require(
        request["plan_digest"] == transition_plan_digest(request),
        "plan_digest_mismatch",
    )
    for side in (request["source"], request["target"]):
        require(bool(side["heads"]) and side["heads"] == sorted(set(side["heads"])))
    require(request["source"]["image_digest"] != request["target"]["image_digest"])
    return request


def load_committed_request(
    raw: bytes, *, identity: CpTransitionIdentity, now: datetime
) -> CpCommittedMigrationRequestV1:
    return validate_committed_request(read_json(raw), identity=identity, now=now)


def validate_any_request(
    value: TransitionRequest, *, identity: CpTransitionIdentity, now: datetime
) -> TransitionRequest:
    if value["schema"] == "dotmac.cp_committed_migration_request/1":
        return validate_committed_request(value, identity=identity, now=now)
    return validate_request(value, identity=identity, now=now)


@dataclass(frozen=True, slots=True)
class HistoricalAuthorization:
    """Protected original verifier output and independently bounded execution time.

    This evidence never carries the fresh gh execution witness.
    """

    policy: CpTransitionTrustPolicy
    verification_bytes: bytes
    execution_window_start: datetime
    execution_window_end: datetime
    request_name: str
    protection_bytes: bytes
    context_digest: str

    def verify(self, request: CpTransitionRequestV1) -> None:
        require(
            self.execution_window_start.tzinfo is not None
            and self.execution_window_end.tzinfo is not None
        )
        require(
            self.execution_window_start <= self.execution_window_end,
            "historical_execution_window_invalid",
        )
        sha(self.context_digest)
        require(
            raw_digest(self.protection_bytes)
            == self.policy.environment_protection_digest,
            "environment_protection_mismatch",
        )
        proof_document = read_json(self.protection_bytes)
        _shape(proof_document, SingleUserManualV2)
        proof = cast(SingleUserManualV2, proof_document)
        require(
            proof["repository_id"] == self.policy.repository_id
            and proof["repository_owner_id"] == self.policy.repository_owner_id
            and proof["workflow_revision"] == self.policy.workflow_revision
            and proof["required_reviewer_ids"] == [int(self.policy.repository_owner_id)]
            and request["trusted_actor"] == self.policy.repository.split("/", 1)[0]
            and timestamp(proof["expires_at"]) > self.execution_window_end,
            "environment_protection_mismatch",
        )
        for bound in (self.execution_window_start, self.execution_window_end):
            validate_request(request, identity=self.policy.identity, now=bound)
        _verify_authorization_report(
            request,
            policy=self.policy,
            verification_bytes=self.verification_bytes,
            request_name=self.request_name,
            now=self.execution_window_start,
        )


@dataclass(frozen=True, slots=True)
class CommittedMigrationContext:
    prior_store: ArtifactStore
    request: CpTransitionRequestV1
    host_nonce: str
    evidence: Mapping[str, str]
    historical_authorization: HistoricalAuthorization
    recovery: RecoveryContexts
    original_proof: FenceProof
    proof: FenceProof
    context_digest: str
    migration_claim_digest: str
    migration_tree_digest: str
    quiescence_digest: str

    @property
    def measurement(self) -> CandidateMeasurementV1:
        proof_document = read_json(self.prior_store.read(self.quiescence_digest))
        _shape(proof_document, CandidateQuiescenceProofV1)
        proof = cast(CandidateQuiescenceProofV1, proof_document)
        snapshot = read_json(self.prior_store.read(proof["after_digest"]))
        _shape(snapshot, CandidateSnapshotV1)
        return cast(CandidateSnapshotV1, snapshot)["measurement"]

    def recovery_context(self) -> RecoveryContexts:
        return self.recovery


def committed_frontier_key(context: CommittedMigrationContext) -> str:
    return digest(
        {
            "schema": "dotmac.cp_committed_frontier_key/1",
            "prior_request_digest": request_digest(context.request),
            "prior_host_nonce": context.host_nonce,
        }
    )


def _frontier_claim(
    context: CommittedMigrationContext,
    request: CpCommittedMigrationRequestV1,
    nonce: str,
    fresh_reservation_digest: str,
) -> dict[str, object]:
    return {
        "schema": "dotmac.cp_committed_frontier_reservation/1",
        "frontier_key": committed_frontier_key(context),
        "prior_request_digest": request_digest(context.request),
        "prior_host_nonce": context.host_nonce,
        "current_fence_digest": request["basis"]["current_fence_digest"],
        "current_fence_id": request["basis"]["current_fence_id"],
        "context_digest": context.context_digest,
        "request_digest": request_digest(request),
        "host_nonce": nonce,
        "fresh_reservation_digest": fresh_reservation_digest,
    }


def verify_committed_frontier(
    context: CommittedMigrationContext,
    request: CpCommittedMigrationRequestV1,
    *,
    owned_frontier_claim: bytes | None = None,
) -> None:
    """Verify the exact original committed failure, never a relabelled prefix."""
    import re

    from vendor_cp.deployment.transition_fence import FenceProof

    prior, store = context.request, context.prior_store
    _shape(request, CpCommittedMigrationRequestV1)
    context.historical_authorization.verify(prior)
    reservation_raw = store.read(request_digest(prior), kind="reservation")
    authorization_raw = context.historical_authorization.verification_bytes
    require(
        store.read(raw_digest(authorization_raw)) == authorization_raw,
        "authorization_bytes_mismatch",
    )
    reservation = read_json(reservation_raw)
    require(
        reservation
        == {
            "schema": "dotmac.cp_transition_attempt/2",
            "request_digest": request_digest(prior),
            "host_nonce": context.host_nonce,
            "authorization_run_id": prior["authorization_run_id"],
            "authorization_run_attempt": prior["authorization_run_attempt"],
            "verification_digest": raw_digest(authorization_raw),
        },
        "reservation_mismatch",
    )
    for name in (
        "product",
        "environment",
        "host",
        "database",
        "cluster_system_identifier",
        "database_oid",
        "source",
        "target",
        "previous_receipt_digest",
    ):
        require(
            cast(dict[str, object], request)[name]
            == cast(dict[str, object], prior)[name],
            "committed_target_or_identity_mismatch",
        )
    require(
        (request["authorization_run_id"], request["authorization_run_attempt"])
        != (prior["authorization_run_id"], prior["authorization_run_attempt"]),
        "committed_authorization_reused",
    )
    for proof in (context.original_proof, context.proof):
        FenceProof.from_document(
            read_json(store.read(proof.digest())), expected_digest=proof.digest()
        )
        require(proof.database == prior["database"], "committed_fence_mismatch")
    require(
        context.original_proof.fence_id == context.host_nonce
        and context.original_proof.prior_acl == context.proof.prior_acl
        and context.original_proof.prior_grants == context.proof.prior_grants
        and context.original_proof.member_roles == context.proof.member_roles
        and context.original_proof.fenced_roles == context.proof.fenced_roles
        and context.original_proof.absent_roles == context.proof.absent_roles,
        "committed_fence_lineage_mismatch",
    )
    expected_basis = {
        "context_digest": context.context_digest,
        "prior_request_digest": request_digest(prior),
        "prior_host_nonce": context.host_nonce,
        "prior_reservation_digest": raw_digest(reservation_raw),
        "prior_authorization_digest": raw_digest(authorization_raw),
        "original_fence_digest": context.original_proof.digest(),
        "current_fence_digest": context.proof.digest(),
        "current_fence_id": context.proof.fence_id,
        "frontier_measurement_digest": digest(context.measurement),
    }
    require(request["basis"] == expected_basis, "committed_basis_mismatch")
    required = PRE_MIGRATION_EVIDENCE | {
        "migrate",
        "migrated-target-heads",
        "failure",
    }
    require(set(context.evidence) == required, "committed_frontier_evidence_mismatch")
    retained = dict(context.evidence)
    for kind, checksum in retained.items():
        _validate_evidence(
            read_json(store.read(checksum)),
            request=prior,
            nonce=context.host_nonce,
            kind=kind,
            store=store,
            evidence=retained,
            recovery=context.recovery,
        )
    _verify_candidate_quiescence(
        context.quiescence_digest, request=prior, nonce=context.host_nonce, store=store
    )
    claim = read_json(store.read(context.migration_claim_digest))
    require(
        claim
        == {
            "schema": "dotmac.cp_transition_migration_claim/1",
            "request_digest": request_digest(prior),
            "host_nonce": context.host_nonce,
            "migration_tree_digest": context.migration_tree_digest,
        },
        "committed_migration_claim_mismatch",
    )
    tree = read_json(store.read(context.migration_tree_digest))
    require(
        set(tree) == {"schema", "revision", "files"}
        and tree["schema"] == "dotmac.cp_transition_migration_tree/1"
        and tree["revision"] == prior["target"]["revision"]
        and isinstance(tree["files"], dict)
        and bool(tree["files"]),
        "committed_migration_tree_mismatch",
    )
    for path, checksum in cast(dict[str, str], tree["files"]).items():
        require(
            isinstance(path, str)
            and not path.startswith("/")
            and ".." not in Path(path).parts
        )
        sha(checksum)
    verify_predecessor(prior, store=store, recovery=context.recovery)
    # Scan all retained attempts, not merely the caller-selected evidence map.
    directory = _open_directory(store.root)
    try:
        for name in os.listdir(directory):
            match = re.fullmatch(
                r"([0-9a-f]{64})\.(evidence|receipt|reservation)\.json", name
            )
            if match is None:
                continue
            raw = store.read("sha256:" + match[1], kind=match[2])
            if match[2] == "reservation":
                # This root-pinned directory belongs to one original attempt.
                # History uses separate stores; unknown/partial reservations deny.
                if "sha256:" + match[1] == request_digest(prior):
                    require(
                        raw == reservation_raw, "committed_reservation_contradiction"
                    )
                else:
                    require(
                        "sha256:" + match[1] == committed_frontier_key(context)
                        and owned_frontier_claim is not None
                        and raw == owned_frontier_claim,
                        "committed_frontier_consumed",
                    )
                continue
            try:
                item = read_json(raw)
            except ValueError:
                continue
            if item.get("request_digest") == request_digest(prior):
                require(
                    item.get("host_nonce") == context.host_nonce,
                    "committed_later_attempt",
                )
                require(match[2] != "receipt", "committed_frontier_already_ready")
                retained_kind = item.get("kind")
                if retained_kind is not None:
                    require(
                        isinstance(retained_kind, str)
                        and retained_kind in required
                        and retained.get(retained_kind) == raw_digest(raw),
                        "committed_frontier_contradiction",
                    )
            embedded = item.get("request")
            if (
                isinstance(embedded, dict)
                and embedded != prior
                and embedded.get("host") == prior["host"]
                and embedded.get("database") == prior["database"]
            ):
                require(False, "committed_later_attempt")
    finally:
        os.close(directory)
    if owned_frontier_claim is not None:
        owned = read_json(owned_frontier_claim)
        _shape(owned.get("host_nonce"), Nonce)
        _shape(owned.get("fresh_reservation_digest"), Digest)
        require(owned["host_nonce"] != context.host_nonce, "committed_nonce_reused")
        require(
            owned
            == _frontier_claim(
                context,
                request,
                cast(str, owned["host_nonce"]),
                cast(str, owned["fresh_reservation_digest"]),
            ),
            "committed_frontier_owner_mismatch",
        )
    key = committed_frontier_key(context)
    try:
        existing = store.read(key, kind="reservation")
    except FileNotFoundError:
        require(owned_frontier_claim is None, "committed_frontier_claim_missing")
    else:
        require(
            owned_frontier_claim is not None and existing == owned_frontier_claim,
            "committed_frontier_consumed",
        )


class CpCommittedMigrationReceiptV1(TypedDict):
    schema: Literal["dotmac.cp_committed_migration_receipt/1"]
    request: CpCommittedMigrationRequestV1
    request_digest: Digest
    host_nonce: str
    phase: Literal["pre-routing", "complete"]
    historical_context_digest: Digest
    frontier_reservation_digest: Digest
    evidence: dict[Identifier, Digest]


def _execute_common_suffix(
    request: TransitionRequest,
    *,
    nonce: str,
    host: CpTransitionHost,
    store: ArtifactStore,
    evidence: dict[str, str],
    retain: Callable[[str, bytes], str],
    receipt: Callable[..., bytes],
    mark_acl: Callable[[], None],
) -> str:
    """One candidate/ACL/readiness/routing owner for both request variants."""
    retain("candidate-ready", host.candidate_ready(request, nonce))
    retain("candidate-removed-fenced", host.close_candidate_and_refence(request, nonce))
    receipt("pre-routing", routing_gate=False)
    mark_acl()
    retain("acl-restored", host.restore_acl(request, nonce))
    retain("full-ready", host.full_ready(request, nonce))
    pre_routing = receipt("pre-routing", routing_gate=True)
    evidence["pre-routing-receipt"] = raw_digest(pre_routing)
    retain("pre-routing-verified", host.verify_pre_routing(pre_routing))
    del evidence["pre-routing-receipt"]
    store.read(evidence["pre-routing-verified"])
    retain("routing-restored", host.restore_routing(request, nonce))
    return raw_digest(receipt("complete", routing_gate=True))


COMMITTED_PRE_ACL_EVIDENCE = {
    "inspection",
    "authorization",
    "committed-rebound",
    "migrated-target-heads",
    "candidate-ready",
    "candidate-removed-fenced",
}


def _validate_committed_evidence(
    value: dict[str, object],
    *,
    request: CpCommittedMigrationRequestV1,
    nonce: str,
    kind: str,
    store: ArtifactStore,
    evidence: dict[str, str],
    recovery: RecoveryContexts,
) -> None:
    if kind != "committed-rebound":
        _validate_evidence(
            value,
            request=request,
            nonce=nonce,
            kind=kind,
            store=store,
            evidence=evidence,
            recovery=recovery,
        )
        return
    require(
        value
        == {
            "schema": "dotmac.cp_transition_evidence/2",
            "request_digest": request_digest(request),
            "host_nonce": nonce,
            "kind": kind,
            "result": {
                "prior_fence_id": request["basis"]["current_fence_id"],
                "fence_id": nonce,
                "original_fence_digest": request["basis"]["original_fence_digest"],
                "current_fence_digest": request["basis"]["current_fence_digest"],
            },
        },
        "committed_rebind_mismatch",
    )


def verify_committed_receipt(
    raw: bytes,
    *,
    store: ArtifactStore,
    request: CpCommittedMigrationRequestV1,
    host_nonce: str,
    recovery: RecoveryContexts,
    context: CommittedMigrationContext,
    routing_gate: bool = False,
    _depth: int = 0,
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> CpCommittedMigrationReceiptV1:
    require(_depth < 32, "receipt_chain_too_deep")
    reservation_raw = store.read(request_digest(request), kind="reservation")
    reservation = read_json(reservation_raw)
    require(
        reservation
        == {
            "schema": "dotmac.cp_transition_attempt/2",
            "request_digest": request_digest(request),
            "host_nonce": host_nonce,
            "authorization_run_id": request["authorization_run_id"],
            "authorization_run_attempt": request["authorization_run_attempt"],
            "verification_digest": reservation.get("verification_digest"),
        },
        "reservation_mismatch",
    )
    sha(reservation["verification_digest"])
    claim = canonical_json(
        _frontier_claim(context, request, host_nonce, raw_digest(reservation_raw))
    )
    verify_committed_frontier(context, request, owned_frontier_claim=claim)
    document = read_json(raw)
    _shape(document, CpCommittedMigrationReceiptV1)
    value = cast(CpCommittedMigrationReceiptV1, document)
    require(
        value["request"] == request
        and value["request_digest"] == request_digest(request)
        and value["host_nonce"] == host_nonce
        and value["historical_context_digest"] == context.context_digest
        and value["frontier_reservation_digest"] == raw_digest(claim),
        "committed_receipt_mismatch",
    )
    required = COMMITTED_PRE_ACL_EVIDENCE | (
        RUNTIME_EVIDENCE if routing_gate else set()
    )
    allowed = COMMITTED_PRE_ACL_EVIDENCE | RUNTIME_EVIDENCE
    if value["phase"] == "complete":
        required |= RUNTIME_EVIDENCE | ROUTING_EVIDENCE
        allowed |= ROUTING_EVIDENCE
    require(required <= set(value["evidence"]) <= allowed, "receipt_phase_mismatch")
    retained = dict(value["evidence"])
    if "pre-routing-verified" in retained:
        pre_routing = dict(value)
        pre_routing["phase"] = "pre-routing"
        pre_routing["evidence"] = {
            key: checksum
            for key, checksum in retained.items()
            if key not in ROUTING_EVIDENCE
        }
        retained["pre-routing-receipt"] = raw_digest(canonical_json(pre_routing))
        store.read(retained["pre-routing-receipt"], kind="receipt")
    for kind, checksum in value["evidence"].items():
        _validate_committed_evidence(
            read_json(store.read(checksum)),
            request=request,
            nonce=host_nonce,
            kind=kind,
            store=store,
            evidence=retained,
            recovery=recovery,
        )
    return value


def verify_any_receipt(
    raw: bytes,
    *,
    store: ArtifactStore,
    request: TransitionRequest,
    host_nonce: str,
    recovery: RecoveryContexts,
    routing_gate: bool = False,
    _depth: int = 0,
    context: CommittedMigrationContext | None = None,
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> CpMigrationTransitionReceiptV1 | CpCommittedMigrationReceiptV1:
    if request["schema"] == "dotmac.cp_committed_migration_request/1":
        context = context or (committed_contexts or {}).get(
            request["basis"]["context_digest"]
        )
        require(context is not None, "committed_context_missing")
        assert context is not None  # noqa: S101 - narrowed by require
        return verify_committed_receipt(
            raw,
            store=store,
            request=request,
            host_nonce=host_nonce,
            recovery=recovery,
            routing_gate=routing_gate,
            _depth=_depth,
            context=context,
            committed_contexts=committed_contexts,
        )
    return verify_receipt(
        raw,
        store=store,
        request=request,
        host_nonce=host_nonce,
        recovery=recovery,
        routing_gate=routing_gate,
        _depth=_depth,
        committed_contexts=committed_contexts,
    )


class CpCommittedTransitionHost(CpTransitionHost, Protocol):
    def inspect_committed(
        self, request: CpCommittedMigrationRequestV1, context: CommittedMigrationContext
    ) -> bytes: ...
    def rebind_committed(
        self,
        request: CpCommittedMigrationRequestV1,
        nonce: str,
        context: CommittedMigrationContext,
    ) -> bytes: ...


def execute_committed_continuation(
    raw_request: bytes,
    *,
    request_path: Path,
    bundle_path: Path | None,
    verifier: GhAttestationVerifier,
    host: CpCommittedTransitionHost,
    store: ArtifactStore,
    recovery: RecoveryContexts,
    context: CommittedMigrationContext,
    clock: Callable[[], datetime],
    committed_contexts: Mapping[str, CommittedMigrationContext] | None = None,
) -> str:
    with host.lock():
        now = clock()
        request = load_committed_request(
            raw_request, identity=verifier.policy.identity, now=now
        )
        authorization = verifier.verify(
            request, request_path=request_path, bundle_path=bundle_path, now=now
        )
        verify_committed_frontier(context, request)
        inspection = host.inspect_committed(request, context)
        validate_committed_request(
            request, identity=verifier.policy.identity, now=clock()
        )
        nonce = store.reserve(request, authorization)
        reservation_raw = store.read(request_digest(request), kind="reservation")
        claim = context.prior_store.reserve_committed_frontier(
            context,
            request,
            host_nonce=nonce,
            fresh_reservation_digest=raw_digest(reservation_raw),
        )
        verify_committed_frontier(context, request, owned_frontier_claim=claim)
        evidence: dict[str, str] = {}
        acl_may_be_restored = False

        def retain(kind: str, raw: bytes) -> str:
            _validate_committed_evidence(
                read_json(raw),
                request=request,
                nonce=nonce,
                kind=kind,
                store=store,
                evidence=evidence,
                recovery=recovery,
            )
            checksum = store.put(raw)
            evidence[kind] = checksum
            return checksum

        def local(kind: str, facts: object) -> bytes:
            return canonical_json(
                {
                    "schema": "dotmac.cp_transition_evidence/2",
                    "request_digest": request_digest(request),
                    "host_nonce": nonce,
                    "kind": kind,
                    "result": facts,
                }
            )

        def receipt(
            phase: Literal["pre-routing", "complete"], *, routing_gate: bool
        ) -> bytes:
            value: CpCommittedMigrationReceiptV1 = {
                "schema": "dotmac.cp_committed_migration_receipt/1",
                "request": request,
                "request_digest": request_digest(request),
                "host_nonce": nonce,
                "phase": phase,
                "historical_context_digest": context.context_digest,
                "frontier_reservation_digest": raw_digest(claim),
                "evidence": dict(evidence),
            }
            raw = canonical_json(value)
            verify_committed_receipt(
                raw,
                store=store,
                request=request,
                host_nonce=nonce,
                recovery=recovery,
                routing_gate=routing_gate,
                context=context,
                committed_contexts=committed_contexts,
            )
            return store.read(store.put(raw, kind="receipt"), kind="receipt")

        try:
            retain("inspection", local("inspection", read_json(inspection)))
            auth_digest = store.put(authorization.verification_bytes)
            retain(
                "authorization",
                local(
                    "authorization",
                    {
                        "verification_digest": auth_digest,
                        "run_id": authorization.authorization_run_id,
                        "run_attempt": authorization.authorization_run_attempt,
                        "trusted_actor": authorization.trusted_actor,
                    },
                ),
            )
            retain("committed-rebound", host.rebind_committed(request, nonce, context))
            retain("migrated-target-heads", host.target_heads(request, nonce))

            def mark_acl() -> None:
                nonlocal acl_may_be_restored
                acl_may_be_restored = True

            return _execute_common_suffix(
                request,
                nonce=nonce,
                host=host,
                store=store,
                evidence=evidence,
                retain=retain,
                receipt=receipt,
                mark_acl=mark_acl,
            )
        except BaseException as original:
            try:
                retain(
                    "failure",
                    host.fail_closed(
                        request, nonce, acl_may_be_restored=acl_may_be_restored
                    ),
                )
            except BaseException as compensation:
                original.add_note(
                    f"Fail-closed compensation failed: {type(compensation).__name__}"
                )
            raise
