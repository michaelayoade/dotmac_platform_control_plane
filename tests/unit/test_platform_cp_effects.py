from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vendor_cp.deployment.effects import (
    BUNDLE_COMPONENTS,
    PlatformBackupResult,
    PlatformCpComposeHostEffects,
    PlatformCpRecoveryBundle,
    PlatformRecoveryError,
    ProcessResult,
    build_platform_cp_effects,
)


@dataclass(frozen=True)
class _Spec:
    product: str = "dotmac_vendor_control_plane"
    environment: str = "production"
    image: str = "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "a" * 64
    source_revision: str = "b" * 40


class _Process:
    def __init__(self, *, omit_role: str = "", leak_verifier: bool = False) -> None:
        self.argv: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.omit_role = omit_role
        self.leak_verifier = leak_verifier

    def capture_stdout(
        self,
        argv: list[str] | tuple[str, ...],
        destination: Path,
        *,
        timeout_seconds: int,
        env: dict[str, str],
    ) -> ProcessResult:
        self.argv.append(tuple(argv))
        self.environments.append(dict(env))
        if "pg_dumpall" in argv:
            roles = (
                "app_admin",
                "app_user",
                "platform_api",
                "outbox_dispatcher",
                "platform_outbox_dispatcher",
            )
            text = "".join(
                f"CREATE ROLE {role};\n" for role in roles if role != self.omit_role
            )
            if self.leak_verifier:
                text += "ALTER ROLE app_user PASSWORD 'SCRAM-SHA-256$unsafe';\n"
            destination.write_text(text, encoding="utf-8")
        else:
            destination.write_bytes(b"PGDMP\x00complete-custom-dump")
        return ProcessResult(0)

    def run(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        timeout_seconds: int,
        env: dict[str, str],
        stdin_path: Path | None = None,
    ) -> ProcessResult:
        self.argv.append(tuple(argv))
        self.environments.append(dict(env))
        joined = " ".join(argv)
        if "pg_restore --list" in joined:
            assert stdin_path is not None and stdin_path.read_bytes().startswith(
                b"PGDMP"
            )
            return ProcessResult(0)
        if "SHOW server_version_num" in joined:
            return ProcessResult(0, "160010\n")
        if "pg_control_system" in joined:
            return ProcessResult(0, "7396401848165731488\n")
        if 'printf %s "$POSTGRES_DB"' in joined:
            return ProcessResult(0, "vendor_control_plane")
        if "SELECT version_num FROM alembic_version" in joined:
            return ProcessResult(
                0, "0028_machine_attribution\ndc_0004_approval_standing\n"
            )
        if "image inspect" in joined:
            return ProcessResult(0, "b" * 40 + "\n")
        raise AssertionError(argv)


def _error(step: str, message: str) -> Exception:
    return PlatformRecoveryError(f"{step}: {message}")


def _result(
    dataset: str, path: str, size: int, checksum: str, algorithm: str
) -> object:
    return PlatformBackupResult(dataset, path, size, checksum, algorithm)


def _bundle(tmp_path: Path, process: _Process) -> PlatformCpRecoveryBundle:
    deploy = tmp_path / "deploy-root"
    (deploy / "deploy").mkdir(parents=True)
    (deploy / "docker-compose.production.yml").write_text("name: x\n")
    (deploy / ".env").write_text("APP_ENV=production\n")
    (deploy / "deploy/product.toml").write_text("schema = 'ProductDeploymentSpec.v1'\n")
    host = tmp_path / "host-id"
    host.write_text("vendor-cp-prod\n")
    return PlatformCpRecoveryBundle(
        _Spec(),
        deploy,
        target="vendor-cp-prod",
        host_id_file=host,
        backup_dir=tmp_path / "backups",
        docker_bin="/usr/bin/docker",
        process=process,
        clock=lambda: datetime(2026, 9, 3, 8, 30, tzinfo=UTC),
        result_factory=_result,
        error_factory=_error,
    )


def test_the_bundle_is_atomic_complete_and_reverified(tmp_path: Path) -> None:
    process = _Process()
    bundle = _bundle(tmp_path, process)

    result = bundle.capture("primary", timeout_seconds=300)

    root = Path(result.path)
    assert root.name == "bundle-20260903T083000Z"
    assert set(path.name for path in root.iterdir()) == set(BUNDLE_COMPONENTS)
    assert not list(root.parent.glob(".bundle-*"))
    assert bundle.verify(result)

    globals_argv = next(argv for argv in process.argv if "pg_dumpall" in argv)
    database_argv = next(
        argv
        for argv in process.argv
        if "pg_dump" in " ".join(argv) and "pg_dumpall" not in argv
    )
    assert globals_argv[globals_argv.index("--user") + 1] == "postgres"
    assert "--no-role-passwords" in globals_argv
    assert "--user" not in database_argv
    assert "--username app_admin" in " ".join(database_argv)
    assert all(result.path not in " ".join(argv) for argv in process.argv)


def test_a_missing_role_refuses_without_publishing_a_bundle(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, _Process(omit_role="platform_api"))

    with pytest.raises(PlatformRecoveryError, match="do not create role platform_api"):
        bundle.capture("primary", timeout_seconds=300)

    assert not list((tmp_path / "backups").glob("bundle-*"))
    assert not list((tmp_path / "backups").glob(".bundle-*"))


def test_a_password_verifier_is_refused_and_never_published(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, _Process(leak_verifier=True))

    with pytest.raises(PlatformRecoveryError, match="contain a password verifier"):
        bundle.capture("primary", timeout_seconds=300)

    assert not list((tmp_path / "backups").glob("bundle-*"))


def test_each_component_and_the_descriptor_binding_are_live(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, _Process())
    result = bundle.capture("primary", timeout_seconds=300)
    root = Path(result.path)

    for name in BUNDLE_COMPONENTS:
        original = (root / name).read_bytes()
        (root / name).write_bytes(original + b"x")
        assert not bundle.verify(result), name
        (root / name).write_bytes(original)
        assert bundle.verify(result), name

    descriptor = tmp_path / "deploy-root/deploy/product.toml"
    descriptor.write_text("schema = 'changed'\n")
    assert not bundle.verify(result)


def test_host_and_dataset_must_match_before_a_capture(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path, _Process())
    (tmp_path / "host-id").write_text("somewhere-else\n")

    with pytest.raises(PlatformRecoveryError, match="does not match authorized target"):
        bundle.capture("primary", timeout_seconds=300)

    (tmp_path / "host-id").write_text("vendor-cp-prod\n")
    with pytest.raises(PlatformRecoveryError, match="no Platform CP recovery dataset"):
        bundle.capture("other", timeout_seconds=300)


def test_the_adapter_delegates_every_non_backup_effect(tmp_path: Path) -> None:
    class Delegate:
        def image_present(self, reference: str) -> bool:
            return reference == "image"

        def backup(self, dataset_code: str, *, timeout_seconds: int) -> object:
            raise AssertionError("the generic single-file backup must not run")

    recovery = _bundle(tmp_path, _Process())
    compose = tmp_path / "deploy-root/docker-compose.production.yml"
    env = tmp_path / "deploy-root/.env"
    effects = PlatformCpComposeHostEffects(
        Delegate(),
        recovery,
        compose_file=compose,
        env_file=env,
        error_factory=_error,
    )

    assert effects.image_present("image")  # type: ignore[attr-defined]
    result = effects.backup("primary", timeout_seconds=300)
    assert effects.verify_backup(result)


class _SwitchDelegate:
    def __init__(
        self,
        env_file: Path,
        compose_file: Path,
        *,
        mutate_compose: bool = False,
    ) -> None:
        self.env_file = env_file
        self.compose_file = compose_file
        self.mutate_compose = mutate_compose
        self.calls: list[tuple[int, str]] = []

    def switch(self, *, timeout_seconds: int, image: str) -> None:
        self.calls.append((timeout_seconds, image))
        lines = self.env_file.read_text(encoding="utf-8").splitlines()
        rewritten = [
            f"VENDOR_APP_IMAGE={image}"
            if line.startswith("VENDOR_APP_IMAGE=")
            else line
            for line in lines
        ]
        self.env_file.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        if self.mutate_compose:
            self.compose_file.write_text("services: {}\n", encoding="utf-8")


def _switch_effects(
    tmp_path: Path,
    env_text: str,
    *,
    mutate_compose: bool = False,
) -> tuple[PlatformCpComposeHostEffects, _SwitchDelegate, Path, Path]:
    recovery = _bundle(tmp_path, _Process())
    compose = tmp_path / "deploy-root/docker-compose.production.yml"
    compose.write_text(
        "services:\n  app: {}\n  db: {}\n  manifest-init: {}\n  ops: {}\n"
        "volumes:\n  postgres_data: {}\nnetworks:\n  default: {}\n",
        encoding="utf-8",
    )
    env = tmp_path / "deploy-root/.env"
    env.write_text(env_text, encoding="utf-8")
    delegate = _SwitchDelegate(env, compose, mutate_compose=mutate_compose)
    return (
        PlatformCpComposeHostEffects(
            delegate,
            recovery,
            compose_file=compose,
            env_file=env,
            error_factory=_error,
        ),
        delegate,
        compose,
        env,
    )


def test_switch_preserves_the_full_compose_and_only_repoints_the_image(
    tmp_path: Path,
) -> None:
    old = "repo/image@sha256:" + "1" * 64
    new = "repo/image@sha256:" + "2" * 64
    effects, delegate, compose, env = _switch_effects(
        tmp_path,
        f"# retained comment\nUNRELATED=retained\nVENDOR_APP_IMAGE={old}\n",
    )
    compose_before = compose.read_bytes()

    effects.switch(timeout_seconds=900, image=new)

    assert delegate.calls == [(900, new)]
    assert compose.read_bytes() == compose_before
    assert env.read_text(encoding="utf-8") == (
        f"# retained comment\nUNRELATED=retained\nVENDOR_APP_IMAGE={new}\n"
    )


@pytest.mark.parametrize(
    "env_text, message",
    [
        ("UNRELATED=value\n", "contains 0 VENDOR_APP_IMAGE"),
        (
            "VENDOR_APP_IMAGE=repo/image@sha256:"
            + "1" * 64
            + "\nVENDOR_APP_IMAGE=repo/image@sha256:"
            + "2" * 64
            + "\n",
            "contains 2 VENDOR_APP_IMAGE",
        ),
        ("VENDOR_APP_IMAGE=repo/image:mutable\n", "existing VENDOR_APP_IMAGE"),
    ],
)
def test_switch_refuses_an_ambiguous_or_mutable_prior_image(
    tmp_path: Path, env_text: str, message: str
) -> None:
    effects, delegate, compose, env = _switch_effects(tmp_path, env_text)
    compose_before = compose.read_bytes()
    env_before = env.read_bytes()

    with pytest.raises(PlatformRecoveryError, match=message):
        effects.switch(
            timeout_seconds=900,
            image="repo/image@sha256:" + "3" * 64,
        )

    assert delegate.calls == []
    assert compose.read_bytes() == compose_before
    assert env.read_bytes() == env_before


def test_factory_constructs_the_public_provider_without_compose_ownership(
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    class Delegate:
        pass

    def factory(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return Delegate()

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    build_platform_cp_effects(
        _Spec(),
        deploy,
        target="vendor-cp-prod",
        compose_effects_factory=factory,
    )

    assert captured["kwargs"] == {
        "compose_file": deploy / "docker-compose.production.yml",
        "env_file": deploy / ".env",
        "docker_bin": "/usr/bin/docker",
        "git_bin": "/usr/bin/git",
        "db_service": "db",
        "migration_service": "ops",
        "image_env_var": "VENDOR_APP_IMAGE",
        "manage_compose_file": False,
        "backup_dir": "/opt/backups",
    }


def test_generated_parse_time_material_never_enters_an_argv(tmp_path: Path) -> None:
    process = _Process()
    _bundle(tmp_path, process).capture("primary", timeout_seconds=300)

    generated = {env["VENDOR_DB_BOOTSTRAP_PASSWORD"] for env in process.environments}
    assert len(generated) == 1
    material = generated.pop()
    assert material
    assert all(material not in " ".join(argv) for argv in process.argv)
