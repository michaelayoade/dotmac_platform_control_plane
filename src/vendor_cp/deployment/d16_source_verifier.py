"""Read-only D16 transition check against an exact Foundation source revision.

This is a temporary source adapter.  The CP evidence producer must establish
the write-time backup proof and independently collect every deployment fact.
This module neither creates those facts nor authorizes a transition.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

FOUNDATION_COMMIT = "d74bf8dd8c399dd92047174365403b861f82ddd0"
_PACKAGE_RELATIVE = Path(
    "packages/dotmac-deployment-foundation/src/dotmac_deployment_foundation"
)
_CANONICAL_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_DUMP_BYTES = 1024 * 1024 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_CHILD_CODE = r"""
import base64
import importlib
import importlib.metadata
import json
import pathlib
import sys

snapshot = pathlib.Path(sys.argv[1]).resolve()
package = snapshot / "dotmac_deployment_foundation"
response = {
    "refusal": "source_import_mismatch", "findings": [],
    "origins": [], "versions": [],
}
try:
    # An isolated interpreter must start without Foundation already loaded.
    if any(name == "dotmac_deployment_foundation" or
           name.startswith("dotmac_deployment_foundation.") for name in sys.modules):
        raise RuntimeError("preloaded Foundation module")
    sys.path.insert(0, str(snapshot))
    prefix = "dotmac_deployment_foundation"
    names = ("backup", "errors", "recovery", "spec", "transition_receipt")
    modules = {name: importlib.import_module(prefix + "." + name)
               for name in names}
    origins = []
    for name, module in tuple(sys.modules.items()):
        if name == prefix or name.startswith(prefix + "."):
            origin = getattr(module, "__file__", None)
            if (not isinstance(origin, str) or
                    not pathlib.Path(origin).resolve().is_relative_to(package)):
                raise RuntimeError("Foundation import escaped snapshot")
            origins.append((name, str(pathlib.Path(origin).resolve())))
    versions = [("python", sys.version.split()[0])]
    for name in ("dotmac-deployment-foundation", "dotmac-kernel",
                 "sqlalchemy", "psycopg"):
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = "not-visible-with-no-site"
        versions.append((name, version))
    response.update(origins=sorted(origins), versions=versions)
    payload = json.load(sys.stdin)
    backup, errors, recovery, spec_module, transition = (modules[name] for name in
        ("backup", "errors", "recovery", "spec", "transition_receipt"))
    try:
        manifest_bytes = base64.b64decode(payload["manifest_b64"], validate=True)
        manifest = recovery.load_manifest(manifest_bytes)
        manifest_dump = manifest.component_digest(
            recovery.BundleComponent.DATABASE_DUMP)
    except (errors.SpecError, ValueError, TypeError, RecursionError, UnicodeError):
        response["refusal"] = "manifest_invalid"
    else:
        if manifest_dump.hex != payload["dump_digest"]:
            response["refusal"] = "dump_manifest_mismatch"
        else:
            try:
                spec = spec_module.ProductDeploymentSpec.loads(
                    payload["descriptor_toml"])
                receipt = transition.TransitionReceiptV1.parse(
                    payload["receipt_document"])
                previous = (
                    transition.TransitionReceiptV1.parse(
                        payload["previous_receipt_document"])
                    if payload["previous_receipt_document"] is not None else None)
                genesis = (transition.TransitionSide.from_document(
                    payload["genesis_source_document"], where="genesis_source")
                    if payload["genesis_source_document"] is not None else None)
            except (errors.SpecError, ValueError, TypeError,
                    RecursionError, UnicodeError):
                response["refusal"] = "input_malformed"
            else:
                record = backup.BackupRecord(
                    dataset=payload["dataset_code"], path=payload["dump_identity"],
                    size_bytes=payload["dump_size"], checksum=payload["dump_digest"],
                    checksum_algorithm="sha256",
                    completed_at_epoch=payload["completed_at_epoch"],
                    assurance=backup.Assurance.VERIFIED,
                    artefact_class=backup.ArtefactClass.RECOVERY_BUNDLE,
                    evidence_origin=backup.BackupEvidenceOrigin.LOCAL_ARTEFACT,
                )
                verdict = transition.verify_transition_receipt(
                    receipt, spec=spec,
                    observed_target_heads=tuple(payload["observed_target_heads"]),
                    previous_receipt=previous, genesis_source=genesis,
                    backup_record=record,
                    bundle_manifest=manifest_bytes,
                    observed_image_digest=payload["observed_image_digest"],
                    expected_run_id=payload["expected_run_id"],
                    expected_target=payload["expected_target"],
                )
                response["refusal"] = None if verdict.verified else "foundation_refused"
                response["findings"] = [item.value for item in verdict.findings]
except Exception:
    # Do not leak untrusted document contents or a traceback across this seam.
    pass
print(json.dumps(response, separators=(",", ":")))
"""


class D16SourceRefusal(StrEnum):
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_REVISION = "source_revision_mismatch"
    SOURCE_DIRTY = "source_dirty"
    SOURCE_IMPORT = "source_import_mismatch"
    INPUT_MALFORMED = "input_malformed"
    BACKUP_PROOF_MISSING = "backup_proof_missing"
    BACKUP_PROOF_MISMATCH = "backup_proof_mismatch"
    LOCAL_FILE_UNSAFE = "local_file_unsafe"
    LOCAL_FILE_CHANGED = "local_file_changed"
    MANIFEST_INVALID = "manifest_invalid"
    DUMP_MANIFEST_MISMATCH = "dump_manifest_mismatch"
    FOUNDATION_REFUSED = "foundation_refused"


@dataclass(frozen=True, slots=True)
class VerifiedDumpEvidence:
    """Trusted CP producer's write-time and readability proof.

    These are assertions received across a separate trust boundary.  The
    source adapter checks their shape and later byte match, not their author.
    The producer must prove the archive magic and full decompression itself.
    """

    write_time_sha256: str
    size_bytes: int
    magic_verified: bool
    full_decompression_verified: bool
    completed_at_epoch: int
    evidence_id: str


@dataclass(frozen=True, slots=True)
class D16SourceInputs:
    foundation_checkout: Path
    descriptor_toml: str
    receipt_document: Mapping[str, object]
    previous_receipt_document: Mapping[str, object] | None
    genesis_source_document: Mapping[str, object] | None
    manifest_path: Path
    dump_path: Path
    verified_dump_evidence: VerifiedDumpEvidence | None
    dataset_code: str
    observed_target_heads: tuple[str, ...]
    observed_image_digest: str
    expected_run_id: str
    expected_target: str


@dataclass(frozen=True, slots=True)
class FoundationSourceProvenance:
    commit: str
    source_tree: str
    import_origins: tuple[tuple[str, str], ...]
    installed_versions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class D16SourceResult:
    verified: bool
    refusal: D16SourceRefusal | None
    foundation_findings: tuple[str, ...] = ()
    provenance: FoundationSourceProvenance | None = None
    dump_sha256: str | None = None
    manifest_bytes_sha256: str | None = None
    backup_evidence_id: str | None = None


class _Refused(Exception):
    def __init__(self, code: D16SourceRefusal) -> None:
        self.code = code
        super().__init__(code.value)


def _git(checkout: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_TERMINAL_PROMPT="0",
    )
    try:
        result = subprocess.run(  # noqa: S603 - fixed Git command, no shell
            [
                executable,
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.ignorestat=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-C",
                str(checkout),
                *arguments,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE) from exc
    return result.stdout


def _checked_source(checkout: Path) -> tuple[Path, str]:
    try:
        root = checkout.resolve(strict=True)
    except OSError as exc:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE) from exc
    if (
        not root.is_dir()
        or Path(os.fsdecode(_git(root, "rev-parse", "--show-toplevel")).strip()) != root
    ):
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    if os.fsdecode(_git(root, "rev-parse", "HEAD")).strip() != FOUNDATION_COMMIT:
        raise _Refused(D16SourceRefusal.SOURCE_REVISION)
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise _Refused(D16SourceRefusal.SOURCE_DIRTY)
    package = root / _PACKAGE_RELATIVE
    if not package.is_dir() or package.is_symlink():
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    tree = os.fsdecode(
        _git(root, "rev-parse", f"HEAD:{_PACKAGE_RELATIVE.as_posix()}")
    ).strip()

    # Git's status/index flags can suppress an assumed-unchanged file.  Verify
    # each package blob against the commit and reject ignored importable files.
    algorithm = os.fsdecode(_git(root, "rev-parse", "--show-object-format")).strip()
    if algorithm not in {"sha1", "sha256"}:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    rows = _git(root, "ls-files", "-s", "-z", "--", _PACKAGE_RELATIVE.as_posix())
    tracked: set[Path] = set()
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, separator, encoded_path = row.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or fields[0] not in {b"100644", b"100755"}:
            raise _Refused(D16SourceRefusal.SOURCE_DIRTY)
        path = root / os.fsdecode(encoded_path)
        tracked.add(path)
        try:
            if path.is_symlink() or not path.is_file():
                raise _Refused(D16SourceRefusal.SOURCE_DIRTY)
            data = path.read_bytes()
        except OSError as exc:
            raise _Refused(D16SourceRefusal.SOURCE_DIRTY) from exc
        blob = hashlib.new(algorithm, b"blob " + str(len(data)).encode() + b"\0" + data)
        if blob.hexdigest().encode() != fields[1]:
            raise _Refused(D16SourceRefusal.SOURCE_DIRTY)
    if not tracked:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    for path in package.rglob("*"):
        if (path.is_file() or path.is_symlink()) and path not in tracked:
            raise _Refused(D16SourceRefusal.SOURCE_DIRTY)
    return package, tree


def _snapshot_source(checkout: Path, snapshot: Path) -> None:
    """Materialize only commit blobs, rejecting unsafe tree entries and paths."""
    prefix = _PACKAGE_RELATIVE.as_posix() + "/"
    rows = _git(checkout, "ls-tree", "-rz", FOUNDATION_COMMIT, "--", prefix[:-1])
    count = 0
    algorithm = os.fsdecode(_git(checkout, "rev-parse", "--show-object-format")).strip()
    if algorithm not in {"sha1", "sha256"}:
        raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE)
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, separator, encoded = row.partition(b"\t")
        fields = metadata.split()
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
        ):
            raise _Refused(D16SourceRefusal.SOURCE_IMPORT)
        name = os.fsdecode(encoded)
        if not name.startswith(prefix):
            raise _Refused(D16SourceRefusal.SOURCE_IMPORT)
        relative = Path(name.removeprefix(prefix))
        if not relative.parts or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise _Refused(D16SourceRefusal.SOURCE_IMPORT)
        blob = _git(checkout, "cat-file", "blob", os.fsdecode(fields[2]))
        actual = hashlib.new(
            algorithm, b"blob " + str(len(blob)).encode() + b"\0" + blob
        )
        if actual.hexdigest().encode() != fields[2]:
            raise _Refused(D16SourceRefusal.SOURCE_IMPORT)
        destination = snapshot / "dotmac_deployment_foundation" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(blob)
        destination.chmod(0o400)
        count += 1
    if (
        not count
        or not (snapshot / "dotmac_deployment_foundation" / "__init__.py").is_file()
    ):
        raise _Refused(D16SourceRefusal.SOURCE_IMPORT)


def _run_isolated(
    snapshot: Path, payload: dict[str, object], tree: str
) -> tuple[D16SourceRefusal | None, tuple[str, ...], FoundationSourceProvenance]:
    try:
        encoded = json.dumps(payload, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _Refused(D16SourceRefusal.INPUT_MALFORMED) from exc
    try:
        result = subprocess.run(  # noqa: S603 - current interpreter, fixed script, no shell
            [sys.executable, "-I", "-S", "-B", "-c", _CHILD_CODE, str(snapshot)],
            input=encoded,
            text=True,
            capture_output=True,
            timeout=30,
            env={
                key: value
                for key, value in os.environ.items()
                if not key.startswith("PYTHON")
            },
            check=True,
        )
        answer = json.loads(result.stdout)
        refusal = answer["refusal"]
        origins = tuple((str(name), str(origin)) for name, origin in answer["origins"])
        if not origins or any(
            not Path(origin).is_relative_to(snapshot) for _, origin in origins
        ):
            raise ValueError("invalid child origins")
        provenance = FoundationSourceProvenance(
            commit=FOUNDATION_COMMIT,
            source_tree=tree,
            import_origins=origins,
            installed_versions=tuple(
                (str(name), str(version)) for name, version in answer["versions"]
            ),
        )
        return (
            D16SourceRefusal(refusal) if refusal else None,
            tuple(str(value) for value in answer["findings"]),
            provenance,
        )
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        raise _Refused(D16SourceRefusal.SOURCE_IMPORT) from exc


def _read_local(
    path: Path, *, maximum: int, keep_bytes: bool
) -> tuple[str, int, bytes | None]:
    """Open every path component without following a symlink; hash one fd."""
    if not path.is_absolute() or ".." in path.parts:
        raise _Refused(D16SourceRefusal.LOCAL_FILE_UNSAFE)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    descriptors: list[int] = []
    try:
        descriptors.append(os.open("/", directory_flags))
        for part in path.parts[1:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        fd = os.open(path.name, file_flags, dir_fd=descriptors[-1])
        descriptors.append(fd)
        initial = os.fstat(fd)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_size < 1
            or initial.st_size > maximum
        ):
            raise _Refused(D16SourceRefusal.LOCAL_FILE_UNSAFE)
        digest = hashlib.sha256()
        total = 0
        chunks: list[bytes] = []
        while chunk := os.read(fd, _CHUNK_BYTES):
            total += len(chunk)
            if total > maximum:
                raise _Refused(D16SourceRefusal.LOCAL_FILE_UNSAFE)
            digest.update(chunk)
            if keep_bytes:
                chunks.append(chunk)
        final = os.fstat(fd)
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != initial.st_size or any(
            getattr(initial, field) != getattr(final, field) for field in identity
        ):
            raise _Refused(D16SourceRefusal.LOCAL_FILE_CHANGED)
        return digest.hexdigest(), total, b"".join(chunks) if keep_bytes else None
    except (OSError, ValueError) as exc:
        raise _Refused(D16SourceRefusal.LOCAL_FILE_UNSAFE) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validated_proof(proof: VerifiedDumpEvidence | None) -> VerifiedDumpEvidence:
    if proof is None:
        raise _Refused(D16SourceRefusal.BACKUP_PROOF_MISSING)
    if (
        type(proof) is not VerifiedDumpEvidence
        or not isinstance(proof.write_time_sha256, str)
        or _CANONICAL_SHA256.fullmatch(proof.write_time_sha256) is None
        or type(proof.size_bytes) is not int
        or proof.size_bytes < 1
        or type(proof.completed_at_epoch) is not int
        or proof.completed_at_epoch < 1
        or type(proof.magic_verified) is not bool
        or type(proof.full_decompression_verified) is not bool
        or not proof.magic_verified
        or not proof.full_decompression_verified
        or not isinstance(proof.evidence_id, str)
        or not proof.evidence_id.strip()
        or proof.evidence_id != proof.evidence_id.strip()
    ):
        raise _Refused(D16SourceRefusal.BACKUP_PROOF_MISSING)
    return proof


def verify_d16_transition(inputs: D16SourceInputs) -> D16SourceResult:
    """Check local bytes and delegate policy to the exact Foundation verifier.

    A true result remains conditional on the separate CP producer's identity,
    write-time backup proof, and independently observed deployment facts.
    """
    provenance: FoundationSourceProvenance | None = None
    dump_digest: str | None = None
    manifest_digest: str | None = None
    proof_id: str | None = None
    try:
        if not isinstance(inputs.foundation_checkout, Path):
            raise _Refused(D16SourceRefusal.INPUT_MALFORMED)
        _, tree = _checked_source(inputs.foundation_checkout)
        proof = _validated_proof(inputs.verified_dump_evidence)
        proof_id = proof.evidence_id
        if (
            not isinstance(inputs.descriptor_toml, str)
            or not isinstance(inputs.receipt_document, Mapping)
            or not isinstance(inputs.dump_path, Path)
            or not isinstance(inputs.manifest_path, Path)
            or not isinstance(inputs.dataset_code, str)
            or not inputs.dataset_code
            or not isinstance(inputs.observed_target_heads, tuple)
            or any(not isinstance(head, str) for head in inputs.observed_target_heads)
            or not all(
                isinstance(value, str) and value
                for value in (
                    inputs.observed_image_digest,
                    inputs.expected_run_id,
                    inputs.expected_target,
                )
            )
        ):
            raise _Refused(D16SourceRefusal.INPUT_MALFORMED)
        dump_digest, dump_size, _ = _read_local(
            inputs.dump_path, maximum=_MAX_DUMP_BYTES, keep_bytes=False
        )
        if (
            proof.write_time_sha256 != f"sha256:{dump_digest}"
            or proof.size_bytes != dump_size
        ):
            raise _Refused(D16SourceRefusal.BACKUP_PROOF_MISMATCH)
        manifest_digest, _, manifest_bytes = _read_local(
            inputs.manifest_path, maximum=_MAX_MANIFEST_BYTES, keep_bytes=True
        )
        if manifest_bytes is None:
            raise _Refused(D16SourceRefusal.MANIFEST_INVALID)

        payload: dict[str, object] = {
            "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
            "dump_digest": dump_digest,
            "dump_size": dump_size,
            # Foundation treats this as an artefact identifier; the child only
            # receives a string and never opens the mutable local path.
            "dump_identity": str(inputs.dump_path),
            "completed_at_epoch": proof.completed_at_epoch,
            "descriptor_toml": inputs.descriptor_toml,
            "receipt_document": inputs.receipt_document,
            "previous_receipt_document": inputs.previous_receipt_document,
            "genesis_source_document": inputs.genesis_source_document,
            "dataset_code": inputs.dataset_code,
            "observed_target_heads": inputs.observed_target_heads,
            "observed_image_digest": inputs.observed_image_digest,
            "expected_run_id": inputs.expected_run_id,
            "expected_target": inputs.expected_target,
        }
        try:
            with tempfile.TemporaryDirectory(prefix="d16-foundation-") as temporary:
                snapshot = Path(temporary).resolve()
                _snapshot_source(inputs.foundation_checkout, snapshot)
                refusal, findings, provenance = _run_isolated(snapshot, payload, tree)
        except OSError as exc:
            raise _Refused(D16SourceRefusal.SOURCE_UNAVAILABLE) from exc
        if refusal is not None:
            return D16SourceResult(
                verified=False,
                refusal=refusal,
                foundation_findings=findings,
                provenance=provenance,
                dump_sha256=f"sha256:{dump_digest}",
                manifest_bytes_sha256=f"sha256:{manifest_digest}",
                backup_evidence_id=proof_id,
            )
        return D16SourceResult(
            verified=True,
            refusal=None,
            provenance=provenance,
            dump_sha256=f"sha256:{dump_digest}",
            manifest_bytes_sha256=f"sha256:{manifest_digest}",
            backup_evidence_id=proof_id,
        )
    except _Refused as refusal:
        return D16SourceResult(
            verified=False,
            refusal=refusal.code,
            provenance=provenance,
            dump_sha256=f"sha256:{dump_digest}" if dump_digest else None,
            manifest_bytes_sha256=f"sha256:{manifest_digest}"
            if manifest_digest
            else None,
            backup_evidence_id=proof_id,
        )
