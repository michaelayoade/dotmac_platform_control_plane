"""Platform CP's product-specific adapter over the Foundation host effects.

The Foundation owns the deployment state machine and the general Docker Compose
implementation.  This assembly owns one narrower fact the general provider
cannot know: a usable Platform CP backup is an atomic four-file recovery bundle,
not one compressed database dump.  ``PlatformCpComposeHostEffects`` delegates
every general effect and replaces only ``backup`` / ``verify_backup``.

The a4 Foundation CLI cannot construct this adapter: its only provider branch
constructs ``ComposeHostEffects`` directly, and its parser exposes no effects
factory.  The class below is therefore the typed integration seam for the
assembly executor that Control a10 must make reachable.  It deliberately does
not invent that unpublished authorization or target-observation API.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404 - argv lists, shell=False throughout
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

EXPECTED_PRODUCT = "dotmac_vendor_control_plane"
EXPECTED_ENVIRONMENT = "production"
EXPECTED_DATASET = "primary"
BUNDLE_SCHEMA = "PlatformCpRecoveryBundle.v1"
BUNDLE_COMPONENTS = ("database.dump", "globals.sql", "manifest.json", "SHA256SUMS")
HASHED_COMPONENTS = ("database.dump", "globals.sql")
REQUIRED_ROLES = (
    "app_admin",
    "app_user",
    "platform_api",
    "outbox_dispatcher",
    "platform_outbox_dispatcher",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_PASSWORD_VERIFIER = re.compile(r"SCRAM-SHA-256\$|PASSWORD '(?:md5|SCRAM)")
_IMAGE_REFERENCE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")


class PlatformRecoveryError(RuntimeError):
    """The product-specific recovery bundle cannot be produced or verified."""


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True, slots=True)
class PlatformBackupResult:
    """Structural equivalent of Foundation's ``BackupResult``.

    The production result factory returns Foundation's own type.  This local
    value keeps the product bundle testable without making the unpublished
    Foundation candidate an application dependency.
    """

    dataset: str
    path: str
    size_bytes: int
    checksum: str
    checksum_algorithm: str


class ProductSpec(Protocol):
    product: str
    environment: str
    image: str
    source_revision: str


class BackupResultLike(Protocol):
    """The public structural fields Foundation reads from a backup result."""

    dataset: str
    path: str
    size_bytes: int
    checksum: str
    checksum_algorithm: str


class ProcessExecutor(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult: ...

    def capture_stdout(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> ProcessResult: ...


class SubprocessExecutor:
    """The single argv-list subprocess seam used by the bundle producer."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult:
        try:
            stdin = stdin_path.open("rb") if stdin_path is not None else None
            try:
                completed = subprocess.run(  # noqa: S603 - argv list, no shell
                    list(argv),
                    shell=False,
                    check=False,
                    timeout=timeout_seconds,
                    env=dict(env),
                    stdin=stdin,
                    capture_output=True,
                    text=False,
                )
            finally:
                if stdin is not None:
                    stdin.close()
        except subprocess.TimeoutExpired as error:
            return ProcessResult(
                124, stderr=f"timed out after {timeout_seconds}s: {error}"
            )
        except OSError as error:
            return ProcessResult(127, stderr=str(error))
        return ProcessResult(
            completed.returncode,
            completed.stdout.decode("utf-8", "replace"),
            completed.stderr.decode("utf-8", "replace"),
        )

    def capture_stdout(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> ProcessResult:
        try:
            with destination.open("wb") as output:
                completed = subprocess.run(  # noqa: S603 - argv list, no shell
                    list(argv),
                    shell=False,
                    check=False,
                    timeout=timeout_seconds,
                    env=dict(env),
                    stdout=output,
                    stderr=subprocess.PIPE,
                )
        except subprocess.TimeoutExpired as error:
            destination.unlink(missing_ok=True)
            return ProcessResult(
                124, stderr=f"timed out after {timeout_seconds}s: {error}"
            )
        except OSError as error:
            destination.unlink(missing_ok=True)
            return ProcessResult(127, stderr=str(error))
        return ProcessResult(
            completed.returncode,
            stderr=completed.stderr.decode("utf-8", "replace"),
        )


ResultFactory = Callable[[str, str, int, str, str], BackupResultLike]
ErrorFactory = Callable[[str, str], Exception]


def _foundation_result(
    dataset: str,
    path: str,
    size_bytes: int,
    checksum: str,
    checksum_algorithm: str,
) -> BackupResultLike:
    # ``engine`` exports this type in its public ``__all__``.  Do not reach
    # through to ``engine.run``: the provider plugin must survive an internal
    # Foundation module move.
    from dotmac_deployment_foundation.engine import BackupResult  # noqa: PLC0415

    return cast(
        BackupResultLike,
        BackupResult(dataset, path, size_bytes, checksum, checksum_algorithm),
    )


def _foundation_error(step: str, message: str) -> Exception:
    from dotmac_deployment_foundation import StepFailed  # noqa: PLC0415

    return cast(Exception, StepFailed(step, message))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class PlatformCpRecoveryBundle:
    """Create and re-verify one product-owned atomic recovery bundle."""

    def __init__(
        self,
        spec: ProductSpec,
        deploy_dir: Path | str,
        *,
        target: str,
        host_id_file: Path | str = "/etc/dotmac-host-id",
        compose_file: Path | str | None = None,
        env_file: Path | str | None = None,
        descriptor_file: Path | str | None = None,
        backup_dir: Path | str = "/opt/backups/dotmac-vendor-control-plane",
        docker_bin: str = "/usr/bin/docker",
        process: ProcessExecutor | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        result_factory: ResultFactory = _foundation_result,
        error_factory: ErrorFactory = _foundation_error,
    ) -> None:
        if spec.product != EXPECTED_PRODUCT or spec.environment != EXPECTED_ENVIRONMENT:
            raise ValueError(
                "PlatformCpRecoveryBundle only serves Platform CP production"
            )
        docker = Path(docker_bin)
        if not docker.is_absolute():
            raise ValueError("docker_bin must be absolute")
        self._spec = spec
        self._deploy_dir = Path(deploy_dir)
        self._target = target
        self._host_id_file = Path(host_id_file)
        self._compose_file = Path(
            compose_file or self._deploy_dir / "docker-compose.production.yml"
        )
        self._env_file = Path(env_file or self._deploy_dir / ".env")
        self._descriptor_file = Path(
            descriptor_file or self._deploy_dir / "deploy/product.toml"
        )
        self._backup_dir = Path(backup_dir)
        self._docker_bin = str(docker)
        self._process = process or SubprocessExecutor()
        self._clock = clock
        self._result_factory = result_factory
        self._error_factory = error_factory

    @property
    def _compose(self) -> tuple[str, ...]:
        return (
            self._docker_bin,
            "compose",
            "--project-name",
            self._spec.product,
            "--project-directory",
            str(self._deploy_dir),
            "--env-file",
            str(self._env_file),
            "-f",
            str(self._compose_file),
        )

    def _environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        environment["VENDOR_APP_IMAGE"] = self._spec.image
        # Parse-time only for an existing cluster.  Never persisted or printed.
        environment["VENDOR_DB_BOOTSTRAP_PASSWORD"] = secrets.token_urlsafe(48)
        return environment

    def _error(self, step: str, message: str) -> Exception:
        return self._error_factory(step, message)

    def _require_host(self) -> None:
        try:
            observed = self._host_id_file.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise self._error(
                "backup", f"host identity is unreadable: {error}"
            ) from error
        if observed != self._target:
            raise self._error(
                "backup",
                f"host identity {observed!r} does not match authorized target "
                f"{self._target!r}",
            )

    def _checked(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
        stdin_path: Path | None = None,
    ) -> str:
        result = self._process.run(
            argv,
            timeout_seconds=timeout_seconds,
            env=env,
            stdin_path=stdin_path,
        )
        if not result.ok:
            detail = (result.stderr or result.stdout).strip()
            raise self._error(
                "backup", f"command failed with {result.exit_code}: {detail}"
            )
        return result.stdout.strip()

    def _capture(
        self,
        argv: Sequence[str],
        destination: Path,
        *,
        timeout_seconds: int,
        env: Mapping[str, str],
    ) -> None:
        result = self._process.capture_stdout(
            argv,
            destination,
            timeout_seconds=timeout_seconds,
            env=env,
        )
        if not result.ok:
            destination.unlink(missing_ok=True)
            detail = (result.stderr or result.stdout).strip()
            raise self._error(
                "backup", f"capture failed with {result.exit_code}: {detail}"
            )

    def capture(self, dataset: str, *, timeout_seconds: int) -> BackupResultLike:
        if dataset != EXPECTED_DATASET:
            raise self._error("backup", f"no Platform CP recovery dataset {dataset!r}")
        self._require_host()
        now = self._clock().astimezone(UTC)
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        published = self._backup_dir / f"bundle-{stamp}"
        if published.exists():
            raise self._error("backup", f"recovery bundle {published} already exists")
        temporary = Path(
            tempfile.mkdtemp(dir=self._backup_dir, prefix=f".bundle-{stamp}.")
        )
        temporary.chmod(0o700)
        env = self._environment()
        try:
            globals_file = temporary / "globals.sql"
            database_file = temporary / "database.dump"
            self._capture(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "--user",
                    "postgres",
                    "db",
                    "pg_dumpall",
                    "--username",
                    "postgres",
                    "--globals-only",
                    "--no-role-passwords",
                ),
                globals_file,
                timeout_seconds=timeout_seconds,
                env=env,
            )
            self._capture(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "db",
                    "sh",
                    "-c",
                    "exec pg_dump --username app_admin "
                    '--dbname "$POSTGRES_DB" --format custom',
                ),
                database_file,
                timeout_seconds=timeout_seconds,
                env=env,
            )
            if not globals_file.stat().st_size or not database_file.stat().st_size:
                raise self._error(
                    "backup", "the recovery bundle contains an empty capture"
                )
            self._checked(
                (*self._compose, "exec", "-T", "db", "pg_restore", "--list"),
                timeout_seconds=timeout_seconds,
                env=env,
                stdin_path=database_file,
            )
            globals_text = globals_file.read_text(encoding="utf-8")
            for role in REQUIRED_ROLES:
                if not re.search(
                    rf'^CREATE ROLE "?{re.escape(role)}"?;$', globals_text, re.M
                ):
                    raise self._error(
                        "backup", f"cluster globals do not create role {role}"
                    )
            if _PASSWORD_VERIFIER.search(globals_text):
                raise self._error(
                    "backup", "cluster globals contain a password verifier"
                )

            pg_version = self._checked(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "db",
                    "sh",
                    "-c",
                    "psql --username app_admin "
                    '--dbname "$POSTGRES_DB" -tAc "SHOW server_version_num"',
                ),
                timeout_seconds=timeout_seconds,
                env=env,
            )
            cluster_id = self._checked(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "--user",
                    "postgres",
                    "db",
                    "psql",
                    "--username",
                    "postgres",
                    "-tAc",
                    "SELECT system_identifier FROM pg_control_system()",
                ),
                timeout_seconds=timeout_seconds,
                env=env,
            )
            database_name = self._checked(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "db",
                    "sh",
                    "-c",
                    'printf %s "$POSTGRES_DB"',
                ),
                timeout_seconds=timeout_seconds,
                env=env,
            )
            heads = self._checked(
                (
                    *self._compose,
                    "exec",
                    "-T",
                    "db",
                    "sh",
                    "-c",
                    'psql --username app_admin --dbname "$POSTGRES_DB" -tAc '
                    '"SELECT version_num FROM alembic_version '
                    'ORDER BY version_num"',
                ),
                timeout_seconds=timeout_seconds,
                env=env,
            )
            revision = self._checked(
                (
                    self._docker_bin,
                    "image",
                    "inspect",
                    "--format",
                    '{{index .Config.Labels "org.opencontainers.image.revision"}}',
                    self._spec.image,
                ),
                timeout_seconds=timeout_seconds,
                env=env,
            )
            if (
                not pg_version.isdigit()
                or not cluster_id.isdigit()
                or not database_name
            ):
                raise self._error("backup", "recovery identity is incomplete")
            if (
                not _REVISION.fullmatch(revision)
                or revision != self._spec.source_revision
            ):
                raise self._error(
                    "backup", "image revision does not match the descriptor"
                )
            if not heads:
                raise self._error("backup", "the database reports no migration heads")
            try:
                descriptor_digest = f"sha256:{_sha256(self._descriptor_file)}"
            except OSError as error:
                raise self._error(
                    "backup", f"accepted descriptor is unreadable: {error}"
                ) from error
            image_digest = self._spec.image.rsplit("@", 1)[-1]
            if not _DIGEST.fullmatch(image_digest):
                raise self._error("backup", "the descriptor image is not digest-pinned")

            file_digests = {
                name: f"sha256:{_sha256(temporary / name)}"
                for name in HASHED_COMPONENTS
            }
            sums = "".join(
                f"{file_digests[name].removeprefix('sha256:')}  {name}\n"
                for name in HASHED_COMPONENTS
            )
            (temporary / "SHA256SUMS").write_text(sums, encoding="ascii")
            manifest = {
                "schema": BUNDLE_SCHEMA,
                "product": self._spec.product,
                "environment": self._spec.environment,
                "target": self._target,
                "postgres_major": int(pg_version) // 10000,
                "cluster_system_identifier": cluster_id,
                "database_name": database_name,
                "image_digest": image_digest,
                "image_source_revision": revision,
                "descriptor_sha256": descriptor_digest,
                "migration_heads": sorted(
                    line for line in heads.splitlines() if line.strip()
                ),
                "files": file_digests,
                "created_at": stamp,
                "restore_order": ["globals.sql", "database.dump"],
            }
            canonical = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            (temporary / "manifest.json").write_text(canonical + "\n", encoding="ascii")
            bundle_digest = hashlib.sha256(canonical.encode("ascii")).hexdigest()
            os.replace(temporary, published)
            result = self._result_factory(
                dataset,
                str(published),
                sum((published / name).stat().st_size for name in BUNDLE_COMPONENTS),
                bundle_digest,
                "sha256",
            )
            if not self.verify(result):
                raise self._error(
                    "verify_backup", "the published recovery bundle does not verify"
                )
            return result
        except BaseException:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    def verify(self, result: BackupResultLike) -> bool:
        try:
            dataset = str(result.dataset)
            root = Path(str(result.path))
            size = int(result.size_bytes)
            checksum = str(result.checksum)
            algorithm = str(result.checksum_algorithm)
        except (AttributeError, TypeError, ValueError):
            return False
        if dataset != EXPECTED_DATASET or algorithm != "sha256" or not root.is_dir():
            return False
        try:
            if root.parent.resolve() != self._backup_dir.resolve() or root.is_symlink():
                return False
            if any(
                not (root / name).is_file() or (root / name).is_symlink()
                for name in BUNDLE_COMPONENTS
            ):
                return False
            expected_size = sum(
                (root / name).stat().st_size for name in BUNDLE_COMPONENTS
            )
            if expected_size != size:
                return False
            sums = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            expected_lines = [
                f"{_sha256(root / name)}  {name}" for name in HASHED_COMPONENTS
            ]
            if sums != expected_lines:
                return False
            manifest = json.loads((root / "manifest.json").read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        expected_files = {
            name: f"sha256:{_sha256(root / name)}" for name in HASHED_COMPONENTS
        }
        required = {
            "schema": BUNDLE_SCHEMA,
            "product": self._spec.product,
            "environment": self._spec.environment,
            "target": self._target,
            "image_digest": self._spec.image.rsplit("@", 1)[-1],
            "image_source_revision": self._spec.source_revision,
            "descriptor_sha256": f"sha256:{_sha256(self._descriptor_file)}",
            "files": expected_files,
            "restore_order": ["globals.sql", "database.dump"],
        }
        if any(manifest.get(key) != value for key, value in required.items()):
            return False
        if not manifest.get("migration_heads") or not manifest.get("database_name"):
            return False
        canonical = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(canonical.encode("ascii")).hexdigest() == checksum


class PlatformCpComposeHostEffects:
    """Delegate general effects; override only Platform CP backup semantics."""

    def __init__(
        self,
        delegate: object,
        recovery: PlatformCpRecoveryBundle,
        *,
        compose_file: Path | str,
        env_file: Path | str,
        image_env_var: str = "VENDOR_APP_IMAGE",
        error_factory: ErrorFactory = _foundation_error,
    ) -> None:
        self._delegate = delegate
        self._recovery = recovery
        self._compose_file = Path(compose_file)
        self._env_file = Path(env_file)
        self._image_env_var = image_env_var
        self._error_factory = error_factory

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)

    def _delegate_call(self, name: str, *args: object, **kwargs: object) -> object:
        method = getattr(self._delegate, name, None)
        if not callable(method):
            raise TypeError(f"the delegated Effects has no callable {name}")
        return method(*args, **kwargs)

    # Explicit methods, rather than relying only on ``__getattr__``. Python
    # 3.12+ runtime Protocol checks use static attribute lookup, so a dynamic
    # proxy has every method when called and still fails ``isinstance(Effects)``.
    # The runtime-binding loader needs to reject an incomplete provider before
    # any gate or mutation, so the complete general surface stays visible.
    def image_present(self, reference: str) -> bool:
        return bool(self._delegate_call("image_present", reference))

    def image_labels(self, reference: str) -> Mapping[str, str]:
        return cast(Mapping[str, str], self._delegate_call("image_labels", reference))

    def release_evidence(self, revision: str) -> Mapping[str, object]:
        return cast(
            Mapping[str, object], self._delegate_call("release_evidence", revision)
        )

    def manifest_digest(self, manifest_path: str) -> str:
        return str(self._delegate_call("manifest_digest", manifest_path))

    def observe_roles(self) -> Sequence[object]:
        return cast(Sequence[object], self._delegate_call("observe_roles"))

    def working_tree_dirty(self) -> bool:
        return bool(self._delegate_call("working_tree_dirty"))

    def untracked_compose_overrides(self) -> Sequence[str]:
        return cast(Sequence[str], self._delegate_call("untracked_compose_overrides"))

    def resolved_materials(self) -> Sequence[str]:
        return cast(Sequence[str], self._delegate_call("resolved_materials"))

    def run_command(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: int,
        materials: Sequence[str] = (),
    ) -> object:
        return self._delegate_call(
            "run_command",
            command,
            timeout_seconds=timeout_seconds,
            materials=materials,
        )

    def backup(self, dataset_code: str, *, timeout_seconds: int) -> BackupResultLike:
        return self._recovery.capture(dataset_code, timeout_seconds=timeout_seconds)

    def verify_backup(self, result: BackupResultLike) -> bool:
        return self._recovery.verify(result)

    def migration_heads(self) -> Sequence[str]:
        return cast(Sequence[str], self._delegate_call("migration_heads"))

    def stop_roles(self, roles: Sequence[str], *, timeout_seconds: int) -> None:
        self._delegate_call("stop_roles", roles, timeout_seconds=timeout_seconds)

    def start_candidate(self, role: str, *, timeout_seconds: int) -> str:
        return str(
            self._delegate_call(
                "start_candidate", role, timeout_seconds=timeout_seconds
            )
        )

    def candidate_ready(self, role: str) -> bool:
        return bool(self._delegate_call("candidate_ready", role))

    def switch(self, *, timeout_seconds: int, image: str) -> None:
        """Repoint only the image value; the product Compose is immutable input.

        The Foundation provider is constructed with ``manage_compose_file=False``
        below.  These checks make that product boundary observable and reject
        ambiguous legacy state before the delegate can recreate anything.
        """
        if not _IMAGE_REFERENCE.fullmatch(image):
            raise self._error_factory(
                "switch", "the desired VENDOR_APP_IMAGE is not digest-pinned"
            )
        try:
            compose_before = self._compose_file.read_bytes()
            env_before = self._env_file.read_text(encoding="utf-8")
        except OSError as error:
            raise self._error_factory(
                "switch", f"Platform CP deployment input is unreadable: {error}"
            ) from error
        # Foundation's atomic writer preserves every line but normalises the
        # final newline. Refuse an input outside that shape before mutation so
        # a switch cannot silently make an unrelated byte change.
        lines = env_before.splitlines()
        if env_before != ("\n".join(lines) + ("\n" if lines else "")):
            raise self._error_factory(
                "switch", "the Platform CP .env is not canonical LF text"
            )
        prefix = f"{self._image_env_var}="
        matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
        if len(matches) != 1:
            raise self._error_factory(
                "switch",
                f"the Platform CP .env contains {len(matches)} {self._image_env_var} "
                "assignments; exactly one is required",
            )
        prior = lines[matches[0]][len(prefix) :]
        if not _IMAGE_REFERENCE.fullmatch(prior):
            raise self._error_factory(
                "switch", "the existing VENDOR_APP_IMAGE is not digest-pinned"
            )
        expected_lines = list(lines)
        expected_lines[matches[0]] = f"{prefix}{image}"
        expected_env = "\n".join(expected_lines) + "\n"

        switch = getattr(self._delegate, "switch", None)
        if not callable(switch):
            raise self._error_factory("switch", "the delegated Effects has no switch")
        switch(timeout_seconds=timeout_seconds, image=image)

        if self._compose_file.read_bytes() != compose_before:
            raise self._error_factory(
                "switch", "the Foundation provider changed Platform CP's Compose file"
            )
        if self._env_file.read_text(encoding="utf-8") != expected_env:
            raise self._error_factory(
                "switch",
                "the Foundation provider changed more than VENDOR_APP_IMAGE in .env",
            )

    def worker_responds(self, role: str) -> bool:
        return bool(self._delegate_call("worker_responds", role))

    def scheduler_last_tick_age_seconds(self, role: str) -> int | None:
        value = self._delegate_call("scheduler_last_tick_age_seconds", role)
        return None if value is None else int(cast(int, value))

    def write_evidence(self, evidence: Mapping[str, object]) -> str:
        return str(self._delegate_call("write_evidence", evidence))

    def prune_images(self, *, retain: int) -> None:
        self._delegate_call("prune_images", retain=retain)

    def emit_annotation(self, annotation: Mapping[str, str]) -> None:
        self._delegate_call("emit_annotation", annotation)


ComposeEffectsFactory = Callable[..., object]


def build_platform_cp_effects(
    spec: ProductSpec,
    deploy_dir: Path | str,
    *,
    target: str,
    docker_bin: str = "/usr/bin/docker",
    git_bin: str = "/usr/bin/git",
    compose_effects_factory: ComposeEffectsFactory | None = None,
) -> PlatformCpComposeHostEffects:
    """Build the product decorator from Foundation's published provider API.

    This is not wired into a launcher.  Foundation a4 has no runtime-binding
    factory, so nothing can reach this function from the published CLI yet.
    """
    if compose_effects_factory is None:
        from dotmac_deployment_foundation.providers import (  # noqa: PLC0415
            ComposeHostEffects,
        )

        compose_effects_factory = ComposeHostEffects
    root = Path(deploy_dir)
    compose_file = root / "docker-compose.production.yml"
    env_file = root / ".env"
    base = compose_effects_factory(
        spec,
        root,
        compose_file=compose_file,
        env_file=env_file,
        docker_bin=docker_bin,
        git_bin=git_bin,
        db_service="db",
        migration_service="ops",
        image_env_var="VENDOR_APP_IMAGE",
        # Load-bearing: the product Compose also owns db, manifest-init, ops,
        # volumes and networks that are not derivable from the descriptor.
        manage_compose_file=False,
        backup_dir="/opt/backups",
    )
    recovery = PlatformCpRecoveryBundle(
        spec,
        root,
        target=target,
        compose_file=compose_file,
        env_file=env_file,
        docker_bin=docker_bin,
    )
    return PlatformCpComposeHostEffects(
        base,
        recovery,
        compose_file=compose_file,
        env_file=env_file,
    )


__all__ = [
    "BUNDLE_COMPONENTS",
    "PlatformBackupResult",
    "PlatformCpComposeHostEffects",
    "PlatformCpRecoveryBundle",
    "PlatformRecoveryError",
    "ProcessResult",
    "build_platform_cp_effects",
]
