"""Build-once generic deploy: the bindings' params / legacy / pull-flag checks.

Documentation-range values only (RFC 5737 / `example.test`); no estate address,
secret value or real digest appears here. Foundation is not a CP dependency, so
its effects class is stubbed at the import boundary and the stub records the
constructor arguments; Foundation's own `_write_env_value` is exercised for real
by the `test_real_pin_rewrite_*` tests in
`conformance/test_d16_source_verifier_real_foundation.py`, against the pinned
source.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from vendor_cp.deployment import deploy_unit_effects as subject
from vendor_cp.deployment.deploy_unit_effects import (
    DeployEffectsInputs,
    build_deploy_unit_effects,
    deploy_unit_effects_factory,
)
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

APP_IMAGE = "127.0.0.1:5000/team/app@sha256:" + "1" * 64
RENDER = f"APP_IMAGE={APP_IMAGE}\nWORKERS=2\n".encode()
LEGACY = b"API_SECRET=placeholder\n"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _install_foundation(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    class ComposeHostEffects:
        def __init__(self, spec: Any, deploy_dir: Path, **kwargs: Any) -> None:
            seen["effects"] = (spec, deploy_dir, kwargs)

    def resolve_tool(configured: str, *, what: str, expected_sha256: str = "") -> str:
        return configured

    modules = {
        "dotmac_deployment_foundation": ModuleType("dotmac_deployment_foundation"),
        "dotmac_deployment_foundation.providers": ModuleType("p"),
        "dotmac_deployment_foundation.providers.compose_host": ModuleType("c"),
        "dotmac_deployment_foundation.toolchain": ModuleType("t"),
    }
    modules[
        "dotmac_deployment_foundation.providers.compose_host"
    ].ComposeHostEffects = ComposeHostEffects  # type: ignore[attr-defined]
    toolchain = modules["dotmac_deployment_foundation.toolchain"]
    toolchain.DEFAULT_TOOLS = {"docker": "/usr/bin/docker", "git": "/usr/bin/git"}  # type: ignore[attr-defined]
    toolchain.resolve_tool = resolve_tool  # type: ignore[attr-defined]
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    seen["type"] = ComposeHostEffects
    return seen


def _write(path: Path, data: bytes, mode: int = 0o400) -> Path:
    path.unlink(missing_ok=True)  # a 0400 file cannot be rewritten in place
    path.write_bytes(data)
    path.chmod(mode)
    return path


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    return {"deploy": deploy, "run": run}


def _inputs(layout: dict[str, Path], **overrides: Any) -> DeployEffectsInputs:
    params = _write(layout["run"] / "params.env", RENDER)
    values: dict[str, Any] = {
        "params_env": params,
        "params_env_digest": _digest(RENDER),
        "app_image": APP_IMAGE,
        "image_source": "transfer",
    }
    values.update(overrides)
    return DeployEffectsInputs(**values)


def _code(caught: pytest.ExceptionInfo[FoundationBindingsUnavailable]) -> TargetRefusal:
    return caught.value.code


def test_effects_construct_over_the_bound_params_env(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    inputs = _inputs(layout)
    spec = object()
    effects = build_deploy_unit_effects(spec, layout["deploy"], inputs)
    assert type(effects) is seen["type"]
    given_spec, deploy_dir, kwargs = seen["effects"]
    assert given_spec is spec and deploy_dir == layout["deploy"]
    assert kwargs == {
        "env_file": inputs.params_env,
        "extra_env_files": (),
        "docker_bin": "/usr/bin/docker",
        "git_bin": "/usr/bin/git",
        "pull_missing_images": False,
        "check_registry_for_missing_images": False,
    }


def test_factory_has_foundations_build_effects_shape(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    factory = deploy_unit_effects_factory(_inputs(layout))
    assert type(factory(object(), layout["deploy"])) is seen["type"]


def test_effects_refuse_params_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    inputs = _inputs(layout)
    _write(inputs.params_env, RENDER + b"EXTRA=1\n", mode=0o600)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_DIGEST_MISMATCH
    assert "effects" not in seen  # Foundation never saw the file


def test_effects_refuse_unplanned_app_image(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    other = b"APP_IMAGE=127.0.0.1:5000/team/app@sha256:" + b"2" * 64 + b"\n"
    inputs = _inputs(
        layout,
        params_env=_write(layout["run"] / "other.env", other),
        params_env_digest=_digest(other),
    )
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_MALFORMED


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(b"", id="empty"),
        pytest.param(RENDER.rstrip(b"\n"), id="no-final-LF"),
        pytest.param(RENDER + b"\n", id="blank-line"),
        pytest.param(RENDER + b"WORKERS=3\n", id="duplicate-key"),
        pytest.param(RENDER + b"lower=1\n", id="lowercase-key"),
        pytest.param(RENDER + b"A=1\r\n", id="CRLF"),
        pytest.param(RENDER + b"A=\x00\n", id="NUL"),
        pytest.param(b"\xff\xfe\n", id="not-utf8"),
    ],
)
def test_effects_refuse_malformed_params_env(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path], bad: bytes
) -> None:
    _install_foundation(monkeypatch)
    inputs = _inputs(
        layout,
        params_env=_write(layout["run"] / "bad.env", bad),
        params_env_digest=_digest(bad),
    )
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_MALFORMED


def test_effects_refuse_params_env_that_is_not_private(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    inputs = _inputs(layout)
    inputs.params_env.chmod(0o620)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_MALFORMED


def test_effects_refuse_params_env_symlink(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    real = _write(layout["run"] / "real.env", RENDER)
    link = layout["run"] / "link.env"
    link.symlink_to(real)
    inputs = _inputs(layout, params_env=link)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_MALFORMED


def test_effects_refuse_dotenv(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    (layout["deploy"] / ".env").write_text("PLANTED=1\n")
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], _inputs(layout))
    assert _code(caught) is TargetRefusal.DOTENV_PRESENT
    assert "effects" not in seen


def test_effects_refuse_dangling_dotenv_symlink(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    (layout["deploy"] / ".env").symlink_to(layout["run"] / "absent")
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], _inputs(layout))
    assert _code(caught) is TargetRefusal.DOTENV_PRESENT


@pytest.mark.parametrize("name", subject._COMPOSE_OVERRIDES)
def test_effects_refuse_compose_override(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path], name: str
) -> None:
    _install_foundation(monkeypatch)
    (layout["deploy"] / name).write_text("services: {}\n")
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], _inputs(layout))
    assert _code(caught) is TargetRefusal.COMPOSE_OVERRIDE_PRESENT


def test_legacy_file_is_an_extra_env_file_when_the_sha_matches(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    legacy = _write(layout["run"] / "legacy.env", LEGACY)
    inputs = _inputs(layout, legacy_env=legacy, legacy_sha256=_digest(LEGACY))
    build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert seen["effects"][2]["extra_env_files"] == (legacy,)


def test_effects_refuse_legacy_sha(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    seen = _install_foundation(monkeypatch)
    legacy = _write(layout["run"] / "legacy.env", LEGACY + b"EDITED=1\n")
    inputs = _inputs(layout, legacy_env=legacy, legacy_sha256=_digest(LEGACY))
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.LEGACY_ENV_SHA_MISMATCH
    assert "effects" not in seen


def test_effects_refuse_legacy_file_missing(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    inputs = _inputs(
        layout,
        legacy_env=layout["run"] / "absent.env",
        legacy_sha256=_digest(LEGACY),
    )
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    assert _code(caught) is TargetRefusal.LEGACY_ENV_MISSING


def test_effects_refuse_a_legacy_path_without_a_policy_sha(
    layout: dict[str, Path],
) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        _inputs(layout, legacy_env=layout["run"] / "legacy.env")
    assert _code(caught) is TargetRefusal.LEGACY_ENV_NOT_BOUND


@pytest.mark.parametrize(("source", "pulls"), [("transfer", False), ("pull", True)])
def test_pull_flags_come_from_the_plans_image_source(
    monkeypatch: pytest.MonkeyPatch,
    layout: dict[str, Path],
    source: str,
    pulls: bool,
) -> None:
    seen = _install_foundation(monkeypatch)
    build_deploy_unit_effects(
        object(), layout["deploy"], _inputs(layout, image_source=source)
    )
    kwargs = seen["effects"][2]
    assert kwargs["pull_missing_images"] is pulls
    assert kwargs["check_registry_for_missing_images"] is pulls


@pytest.mark.parametrize("bad", ["", "Transfer", "registry", "TRANSFER"])
def test_effects_refuse_an_unknown_image_source(
    layout: dict[str, Path], bad: str
) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        _inputs(layout, image_source=bad)
    assert _code(caught) is TargetRefusal.IMAGE_SOURCE_INVALID


@pytest.mark.parametrize(
    "digest", ["", "abc", "sha256:" + "A" * 64, "sha256:" + "1" * 63]
)
def test_inputs_refuse_a_non_canonical_digest(
    layout: dict[str, Path], digest: str
) -> None:
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        _inputs(layout, params_env_digest=digest)
    assert _code(caught) is TargetRefusal.PARAMS_ENV_MALFORMED


def test_refusals_without_foundation_installed_are_typed_after_every_check(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    for name in (
        "dotmac_deployment_foundation",
        "dotmac_deployment_foundation.providers.compose_host",
        "dotmac_deployment_foundation.toolchain",
    ):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], _inputs(layout))
    assert _code(caught) is TargetRefusal.FOUNDATION_MISSING
    assert caught.value.__cause__ is None
    # A bad file still refuses on ITS code, not on the missing facility.
    (layout["deploy"] / ".env").write_text("X=1\n")
    with pytest.raises(FoundationBindingsUnavailable) as caught2:
        build_deploy_unit_effects(object(), layout["deploy"], _inputs(layout))
    assert _code(caught2) is TargetRefusal.DOTENV_PRESENT


def test_refusal_messages_never_carry_a_value_or_path(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Path]
) -> None:
    _install_foundation(monkeypatch)
    inputs = _inputs(layout)
    _write(inputs.params_env, RENDER + b"SECRET_LOOKING=hunter2\n", mode=0o600)
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        build_deploy_unit_effects(object(), layout["deploy"], inputs)
    text = str(caught.value)
    assert "hunter2" not in text and str(layout["run"]) not in text
    assert "sha256:" not in text


# ── from_materials, against Control's own published contract vectors ───────


def _contract() -> dict[str, Any]:
    path = resources.files("dotmac_deployment_control") / "contract/target_api_v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_from_materials_reads_the_bound_facts_from_control_vectors(
    layout: dict[str, Path],
) -> None:
    materials = _contract()["materials"]["ok"]
    binding = materials["plan_snapshot"]["deploy_binding"]
    inputs = DeployEffectsInputs.from_materials(
        materials,
        params_env=layout["run"] / "params.env",
        legacy_env=layout["run"] / "legacy.env",
    )
    assert inputs.params_env_digest == binding["params_env_digest"]
    assert inputs.app_image == materials["app_image"]
    assert inputs.image_source == binding["images"][0]["source"] == "transfer"
    assert inputs.legacy_sha256 == binding["legacy"]["sha256"]


def test_from_materials_refuses_a_legacy_path_the_plan_does_not_bind(
    layout: dict[str, Path],
) -> None:
    materials = json.loads(json.dumps(_contract()["materials"]["ok"]))
    materials["plan_snapshot"]["deploy_binding"]["legacy"] = None
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DeployEffectsInputs.from_materials(
            materials,
            params_env=layout["run"] / "params.env",
            legacy_env=layout["run"] / "legacy.env",
        )
    assert _code(caught) is TargetRefusal.LEGACY_ENV_NOT_BOUND


def test_from_materials_refuses_a_bound_legacy_policy_with_no_file(
    layout: dict[str, Path],
) -> None:
    materials = _contract()["materials"]["ok"]
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DeployEffectsInputs.from_materials(
            materials, params_env=layout["run"] / "params.env"
        )
    assert _code(caught) is TargetRefusal.LEGACY_ENV_MISSING


@pytest.mark.parametrize("drop", ["plan_snapshot", "app_image"])
def test_from_materials_refuses_an_incomplete_document(
    layout: dict[str, Path], drop: str
) -> None:
    materials = dict(_contract()["materials"]["ok"])
    del materials[drop]
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DeployEffectsInputs.from_materials(
            materials, params_env=layout["run"] / "params.env"
        )
    assert _code(caught) is TargetRefusal.MATERIALS_REFUSED


def test_from_materials_refuses_mixed_image_sources(layout: dict[str, Path]) -> None:
    materials = json.loads(json.dumps(_contract()["materials"]["ok"]))
    images = materials["plan_snapshot"]["deploy_binding"]["images"]
    images.append({**images[0], "source": "pull"})
    materials["plan_snapshot"]["deploy_binding"]["legacy"] = None
    with pytest.raises(FoundationBindingsUnavailable) as caught:
        DeployEffectsInputs.from_materials(
            materials, params_env=layout["run"] / "params.env"
        )
    assert _code(caught) is TargetRefusal.IMAGE_SOURCE_INVALID


# ── the canonical render and Foundation's pin rewrite ────────────────────────


def _golden_write_env_value(env_file: Path, key: str, value: str) -> None:
    """Verbatim port of Foundation a2 `ComposeHostEffects._write_env_value`.

    Source: Starter `packages/dotmac-deployment-foundation/src/
    dotmac_deployment_foundation/providers/compose_host.py` as pinned by CI
    (`d74bf8dd`, identical at `daa576f`). The real function is exercised by
    the `test_real_pin_rewrite_*` conformance tests; this copy keeps the
    golden property in the ordinary suite, where a stub cannot drift silently.
    """
    lines = (
        env_file.read_text(encoding="utf-8").splitlines() if env_file.is_file() else []
    )
    pattern = re.compile(rf"^{re.escape(key)}=")
    replaced = False
    new_lines: list[str] = []
    for line in lines:
        if pattern.match(line):
            new_lines.append(f"{key}={value}")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"{key}={value}")
    env_file.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(env_file.parent), prefix=f".{env_file.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(new_lines))
            if new_lines:
                fh.write("\n")
        os.replace(tmp_path, env_file)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def test_pin_rewrite_byte_identical(tmp_path: Path) -> None:
    """Rewriting the planned pin into the canonical render changes no byte.

    Replayed over every one of Control's published render vectors, so the
    property holds for the exact bytes Control digests and binds.
    """
    vectors = _contract()["render_vectors"]
    assert vectors  # SENSITIVITY: an empty vector set would pass vacuously
    for index, vector in enumerate(vectors):
        render = vector["render_utf8"].encode("utf-8")
        assert _digest(render) == vector["digest"]
        target = tmp_path / f"params-{index}.env"
        target.write_bytes(render)
        target.chmod(0o400)
        _golden_write_env_value(target, "APP_IMAGE", vector["app_image"])
        assert target.read_bytes() == render, vector["name"]
        # Only the mode changes: the replace creates a 0600 file (mkstemp).
        assert target.stat().st_mode & 0o777 == 0o600


def test_pin_rewrite_changes_only_the_pin_line(tmp_path: Path) -> None:
    """SENSITIVITY: the property is not 'the rewrite never changes anything'."""
    target = tmp_path / "params.env"
    target.write_bytes(RENDER)
    other = "127.0.0.1:5000/team/app@sha256:" + "2" * 64
    _golden_write_env_value(target, "APP_IMAGE", other)
    assert target.read_bytes() == f"APP_IMAGE={other}\nWORKERS=2\n".encode()
    assert _digest(target.read_bytes()) != _digest(RENDER)
