from __future__ import annotations

import json
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
class _CanonicalDocument:
    digest: str

    def sha256_digest(self) -> str:
        return self.digest


@dataclass(frozen=True)
class _Spec:
    product: str = "dotmac_vendor_control_plane"
    environment: str = "production"
    image: str = "ghcr.io/michaelayoade/dotmac_vendor_control_plane@sha256:" + "a" * 64
    source_revision: str = "b" * 40
    descriptor_digest: str = "sha256:" + "c" * 64

    def to_canonical_document(self) -> _CanonicalDocument:
        return _CanonicalDocument(self.descriptor_digest)


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


#: The incumbent this target is running when a backup is taken: the PREVIOUS
#: release, whose bytes the bundle actually holds. Deliberately a different
#: digest from `_Spec.image`'s -- if the two matched, every assertion below
#: would pass whichever identity the manifest recorded, which is exactly how
#: the confusion went unnoticed.
INCUMBENT = (("app", "sha256:" + "e" * 64),)


def _bundle(
    tmp_path: Path,
    process: _Process,
    *,
    spec: _Spec | None = None,
    incumbent: tuple[tuple[str, str], ...] = INCUMBENT,
) -> PlatformCpRecoveryBundle:
    deploy = tmp_path / "deploy-root"
    (deploy / "deploy").mkdir(parents=True, exist_ok=True)
    (deploy / "docker-compose.production.yml").write_text("name: x\n")
    (deploy / ".env").write_text("APP_ENV=production\n")
    (deploy / "deploy/product.toml").write_text("schema = 'ProductDeploymentSpec.v1'\n")
    host = tmp_path / "host-id"
    host.write_text("vendor-cp-prod\n")
    return PlatformCpRecoveryBundle(
        spec or _Spec(),
        deploy,
        target="vendor-cp-prod",
        incumbent_roles=incumbent,
        host_id_file=host,
        backup_dir=tmp_path / "backups",
        docker_bin="/usr/bin/docker",
        process=process,
        clock=lambda: datetime(2026, 9, 3, 8, 30, tzinfo=UTC),
        result_factory=_result,
        error_factory=_error,
    )


def _unbound_bundle(
    tmp_path: Path,
    process: _Process,
    *,
    spec: _Spec | None = None,
) -> PlatformCpRecoveryBundle:
    """A bundle built the way the facility builds one: no authorized facts yet.

    Same fixture as `_bundle`, minus `target` and `incumbent_roles` — the two
    the execution plan freezes and stage two supplies.
    """
    deploy = tmp_path / "deploy-root"
    (deploy / "deploy").mkdir(parents=True, exist_ok=True)
    (deploy / "docker-compose.production.yml").write_text("name: x\n")
    (deploy / ".env").write_text("APP_ENV=production\n")
    (deploy / "deploy/product.toml").write_text("schema = 'ProductDeploymentSpec.v1'\n")
    host = tmp_path / "host-id"
    host.write_text("vendor-cp-prod\n")
    return PlatformCpRecoveryBundle(
        spec or _Spec(),
        deploy,
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

    different_spec = _Spec(descriptor_digest="sha256:" + "d" * 64)
    verifier = _bundle(tmp_path, _Process(), spec=different_spec)
    assert not verifier.verify(result)


def test_bundle_binds_the_executed_spec_not_the_accepted_descriptor_file(
    tmp_path: Path,
) -> None:
    first = _Spec(descriptor_digest="sha256:" + "1" * 64)
    second = _Spec(descriptor_digest="sha256:" + "2" * 64)
    result = _bundle(tmp_path, _Process(), spec=first).capture(
        "primary", timeout_seconds=300
    )

    # Same deploy directory and image, different canonical descriptor. If the
    # bundle reopened deploy/product.toml both verifiers would accept it.
    assert _bundle(tmp_path, _Process(), spec=first).verify(result)
    assert not _bundle(tmp_path, _Process(), spec=second).verify(result)


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
        incumbent_roles=INCUMBENT,
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


# ── the bundle holds the incumbent's data, and says so ──────────────────────


def _manifest(result: object) -> dict[str, object]:
    path = Path(result.path) / "manifest.json"  # type: ignore[attr-defined]
    return json.loads(path.read_text(encoding="ascii"))


def test_pre_migration_data_carries_the_incumbent_identity(tmp_path: Path) -> None:
    """The whole point, and the assertion the previous shape could not pass.

    The bytes in this bundle are the PREVIOUS release's database, captured
    before the candidate's migration runs. Labelling them with the candidate's
    digest is a claim that only becomes visible during a restore.

    Before the fix the manifest carried `image_digest` and
    `image_source_revision` taken from `spec` — the candidate — so there was no
    field that could hold `INCUMBENT`'s digest at all, and this test could not
    be written, let alone pass.
    """
    result = _bundle(tmp_path, _Process()).capture("primary", timeout_seconds=300)
    manifest = _manifest(result)

    assert manifest["incumbent_roles"] == [
        {"role": "app", "image_digest": "sha256:" + "e" * 64}
    ]
    assert manifest["first_deployment"] is False

    # And the candidate identity is recorded as what it is: what the backup was
    # taken FOR, never what it came from.
    assert manifest["taken_for_image_digest"] == "sha256:" + "a" * 64
    assert manifest["taken_for_source_revision"] == "b" * 40

    # The two identities are genuinely different values, so neither field can
    # be standing in for the other by coincidence.
    assert (
        manifest["incumbent_roles"][0]["image_digest"]
        != (  # type: ignore[index]
            manifest["taken_for_image_digest"]
        )
    )


def test_no_incumbent_is_a_first_deployment_claim_not_a_missing_field(
    tmp_path: Path,
) -> None:
    """An empty prestate SAYS something: this target had no role containers.

    Recorded as a claim rather than left to a reader who finds an empty list
    and cannot tell it from a field nobody filled in.
    """
    result = _bundle(tmp_path, _Process(), incumbent=()).capture(
        "primary", timeout_seconds=300
    )
    manifest = _manifest(result)

    assert manifest["first_deployment"] is True
    assert manifest["incumbent_roles"] == []
    assert "first_deployment" in manifest


def test_a_bundle_verifies_against_an_incumbent_that_has_since_moved(
    tmp_path: Path,
) -> None:
    """SENSITIVITY for the shape-only rule in `verify`.

    A bundle records the host as it was. Re-deriving the incumbent expectation
    the way every candidate-side field is re-derived would reject every bundle
    except the newest — so the useful ones, taken before the last few
    deployments, would all fail. Capture with one incumbent, verify through an
    instance that believes in another, and it must still hold.
    """
    process = _Process()
    result = _bundle(tmp_path, process).capture("primary", timeout_seconds=300)

    moved_on = _bundle(tmp_path, process, incumbent=(("app", "sha256:" + "f" * 64),))
    assert moved_on.verify(result)


def test_verify_refuses_a_manifest_whose_incumbent_claim_is_incoherent(
    tmp_path: Path,
) -> None:
    """POSITIVE CONTROL for the test above: shape-only is not no-check.

    `first_deployment` and `incumbent_roles` must agree. A bundle claiming a
    first deployment while naming a role it came from is describing two
    different hosts.
    """
    bundle = _bundle(tmp_path, _Process())
    result = bundle.capture("primary", timeout_seconds=300)
    assert bundle.verify(result)

    path = Path(result.path) / "manifest.json"
    manifest = json.loads(path.read_text(encoding="ascii"))
    manifest["first_deployment"] = True
    path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    assert not bundle.verify(result)


def test_an_unsorted_or_repeated_incumbent_is_refused(tmp_path: Path) -> None:
    """Same rule as the prestate it mirrors: one host state records one way.

    The order is refused rather than repaired — silently sorting would hide a
    caller that had observed the host twice.
    """
    with pytest.raises(ValueError, match="sorted by role code"):
        _bundle(
            tmp_path,
            _Process(),
            incumbent=(("web", "sha256:" + "e" * 64), ("app", "sha256:" + "e" * 64)),
        )
    with pytest.raises(ValueError, match="names a role twice"):
        _bundle(
            tmp_path,
            _Process(),
            incumbent=(("app", "sha256:" + "e" * 64), ("app", "sha256:" + "f" * 64)),
        )
    with pytest.raises(ValueError, match="not pinned to a sha256 digest"):
        _bundle(tmp_path, _Process(), incumbent=(("app", "latest"),))


# ── stage one / stage two ───────────────────────────────────────────────────
#
# Foundation's published binding contract is
# `build_effects(spec, deploy_dir) -> Effects` — two positional arguments and no
# keywords (`dotmac_deployment_foundation.execution_bindings.ExecutionBindings`,
# whose `build_effects` field documents that shape, and `cli._build_effects`,
# which calls `bindings.build_effects(spec, Path(args.deploy_dir))`).
#
# While `target` and `incumbent_roles` were REQUIRED keyword-only arguments of
# the factory, that call could not be made at all: it raised `TypeError: missing
# a required keyword-only argument: 'target'` before any deployment logic ran.
# Every test in this file passed throughout, because every one of them called
# the factory the way the factory wanted to be called instead of the way the
# facility actually calls it.


def _unbound_effects(tmp_path: Path) -> object:
    """Effects built exactly as the facility builds them: two positionals."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()

    class Delegate:
        pass

    return build_platform_cp_effects(
        _Spec(), deploy, compose_effects_factory=lambda *a, **k: Delegate()
    )


def test_the_factory_is_callable_through_the_published_binding_contract(
    tmp_path: Path,
) -> None:
    """The regression for the defect above, driven as the real caller drives it.

    `signature().bind` is the contract check — it fails on exactly the argument
    shape the facility uses — and the construction that follows proves the call
    is not merely well-formed but actually builds the provider.
    """
    import inspect

    inspect.signature(build_platform_cp_effects).bind(_Spec(), tmp_path)
    assert _unbound_effects(tmp_path) is not None


def test_capture_refuses_until_the_authorized_execution_is_bound(
    tmp_path: Path,
) -> None:
    """Refusing is the whole design. The two alternatives are both corruptions:
    observing the host here would be a second authority over a fact the plan
    froze, and defaulting the incumbent to empty would label the previous
    release's bytes a first deployment."""
    bundle = _unbound_bundle(tmp_path, _Process())

    with pytest.raises(PlatformRecoveryError, match="never bound"):
        bundle.capture("primary", timeout_seconds=300)

    assert not list((tmp_path / "backups").glob("bundle-*"))
    assert not list((tmp_path / "backups").glob(".bundle-*"))


def test_unbound_is_not_the_first_deployment_claim(tmp_path: Path) -> None:
    """The reason "not yet supplied" has its own type instead of being `()`.

    An empty incumbent already MEANS something: a positive claim that the target
    had no role containers. If unbound collapsed into it, a bundle captured
    before binding would record the incumbent's own data as a first deployment —
    a lie that only surfaces during a restore.
    """
    with pytest.raises(PlatformRecoveryError, match="never bound"):
        _unbound_bundle(tmp_path, _Process()).capture("primary", timeout_seconds=300)

    # SENSITIVITY: a bundle BOUND to an empty incumbent does make that claim, so
    # the refusal above is about boundness and not about emptiness.
    bound = _unbound_bundle(tmp_path, _Process())
    bound.bind_authorized_execution(target="vendor-cp-prod", incumbent_roles=())
    result = bound.capture("primary", timeout_seconds=300)
    manifest = json.loads((Path(result.path) / "manifest.json").read_text())
    assert manifest["first_deployment"] is True
    assert manifest["incumbent_roles"] == []


def test_binding_records_the_prestate_the_plan_froze(tmp_path: Path) -> None:
    """Stage two supplies the frozen facts, and they reach the manifest."""
    bundle = _unbound_bundle(tmp_path, _Process())
    bundle.bind_authorized_execution(target="vendor-cp-prod", incumbent_roles=INCUMBENT)
    result = bundle.capture("primary", timeout_seconds=300)

    manifest = json.loads((Path(result.path) / "manifest.json").read_text())
    assert manifest["target"] == "vendor-cp-prod"
    assert manifest["incumbent_roles"] == [
        {"role": "app", "image_digest": "sha256:" + "e" * 64}
    ]
    assert manifest["first_deployment"] is False


def test_rebinding_the_same_facts_is_accepted_and_different_facts_refused(
    tmp_path: Path,
) -> None:
    """A retry inside one authorized run is not a contradiction; two different
    answers to one frozen fact is exactly the drift the plan exists to catch."""
    bundle = _unbound_bundle(tmp_path, _Process())
    bundle.bind_authorized_execution(target="vendor-cp-prod", incumbent_roles=INCUMBENT)
    bundle.bind_authorized_execution(target="vendor-cp-prod", incumbent_roles=INCUMBENT)

    with pytest.raises(ValueError, match="already bound to a different"):
        bundle.bind_authorized_execution(
            target="vendor-cp-prod", incumbent_roles=(("app", "sha256:" + "f" * 64),)
        )
    with pytest.raises(ValueError, match="already bound to a different"):
        bundle.bind_authorized_execution(
            target="somewhere-else", incumbent_roles=INCUMBENT
        )


def test_bind_validates_the_prestate_it_is_handed(tmp_path: Path) -> None:
    """The same shape rules the constructor applied; a later supply is not a
    quieter one."""
    bundle = _unbound_bundle(tmp_path, _Process())

    with pytest.raises(ValueError, match="sorted by role code"):
        bundle.bind_authorized_execution(
            target="vendor-cp-prod",
            incumbent_roles=(
                ("web", "sha256:" + "e" * 64),
                ("app", "sha256:" + "e" * 64),
            ),
        )
    with pytest.raises(ValueError, match="not pinned to a sha256 digest"):
        bundle.bind_authorized_execution(
            target="vendor-cp-prod", incumbent_roles=(("app", "latest"),)
        )
    with pytest.raises(ValueError, match="target is empty"):
        bundle.bind_authorized_execution(target="", incumbent_roles=INCUMBENT)
