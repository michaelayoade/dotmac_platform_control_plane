"""Foundation effects for a build-once generic deploy (P-CP1 lane 5a).

The generic agent renders `params.env` from the plan and hands the bindings the
path; this module is the in-process check between the two and Foundation's own
`ComposeHostEffects`. It never decides a value: every fact it compares comes
from the VERIFIED dispatch materials (`plan_snapshot.deploy_binding`, which
Control derives and signs), never from a file, an environment variable or an
observation.

What it refuses, each with a named, value-free `TargetRefusal`:

* the `params.env` bytes hash to anything but the plan's `params_env_digest`
  (`params_env_digest_mismatch`), or are not one `APP_IMAGE=` line for exactly
  the planned image reference (`params_env_malformed`);
* a `<deploy_dir>/.env` (`dotenv_present`) or a Compose override
  (`compose_override_present`) exists, because either would silently add values
  the plan never bound;
* the plan binds a `[legacy_env_file]` and the file's whole-file sha256 differs
  from the policy sha (`legacy_env_sha_mismatch`), the file is absent
  (`legacy_env_missing`), or a legacy file is offered that no policy binds
  (`legacy_env_not_bound`).

Pull flags come from the plan's image source, not from a default: `transfer`
(the fleet default, D-1) constructs the effects with
`pull_missing_images = check_registry_for_missing_images = False`, so a
transferred image can never trigger a registry reach from the host.

Foundation's pin rewrite (`APP_IMAGE=`) then produces byte-identical content for
a file that already carries that line, and only the mode changes
(`tests/unit/test_deploy_unit_effects.py::test_pin_rewrite_byte_identical`).

Placement: this is the factory a caller binds to Foundation's `build_effects`
(`deploy_unit_effects_factory`). Wiring it into `foundation_bindings.bindings()`
needs the consumed materials, which arrive with the consumption client (lane
5b); the Gate 2 `target_effects.build_target_effects` is unchanged until then.
Foundation is not a dependency of this assembly, so its imports are lazy.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

__all__ = [
    "DeployEffectsInputs",
    "build_deploy_unit_effects",
    "deploy_unit_effects_factory",
]

IMAGE_SOURCES: Final = frozenset({"transfer", "pull"})
APP_IMAGE_KEY: Final = "APP_IMAGE"
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_LINE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,127}=[^\x00\r\n]*")
_COMPOSE_OVERRIDES: Final = (
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
    "compose.override.yml",
    "compose.override.yaml",
)
_MAX_ENV_BYTES: Final = 256 * 1024


def _refuse(code: TargetRefusal, message: str) -> FoundationBindingsUnavailable:
    """Names only: no value, path or digest is ever placed in a message."""
    return FoundationBindingsUnavailable(message, code=code)


@dataclass(frozen=True, slots=True)
class DeployEffectsInputs:
    """The facts the effects are constructed from; all from verified materials."""

    params_env: Path
    params_env_digest: str
    app_image: str
    image_source: str
    legacy_env: Path | None = None
    legacy_sha256: str | None = None

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.params_env_digest):
            raise _refuse(
                TargetRefusal.PARAMS_ENV_MALFORMED,
                "params_env_digest is not canonical sha256:<64 hex>",
            )
        if not self.app_image or any(c in self.app_image for c in "\x00\r\n"):
            raise _refuse(
                TargetRefusal.PARAMS_ENV_MALFORMED,
                "the planned app image is empty or not a single line",
            )
        if self.image_source not in IMAGE_SOURCES:
            raise _refuse(
                TargetRefusal.IMAGE_SOURCE_INVALID,
                "the plan's image source is neither transfer nor pull",
            )
        if (self.legacy_env is None) != (self.legacy_sha256 is None):
            raise _refuse(
                TargetRefusal.LEGACY_ENV_NOT_BOUND,
                "a legacy env path and its policy sha come together",
            )
        if self.legacy_sha256 is not None and not _DIGEST.fullmatch(self.legacy_sha256):
            raise _refuse(
                TargetRefusal.LEGACY_ENV_SHA_MISMATCH,
                "the legacy policy sha is not canonical sha256:<64 hex>",
            )

    @classmethod
    def from_materials(
        cls,
        materials: Mapping[str, Any],
        *,
        params_env: Path | str,
        legacy_env: Path | str | None = None,
    ) -> DeployEffectsInputs:
        """Read the bound facts from verified `dotmac.deploy_target_materials/1`.

        `legacy_env` is the path the agent copied the legacy file to (or None).
        The plan decides whether a legacy file is expected: a path with no bound
        policy, or a bound policy with no path, both refuse.
        """
        try:
            binding = materials["plan_snapshot"]["deploy_binding"]
            images = binding["images"]
            sources = {image["source"] for image in images}
            digest = binding["params_env_digest"]
            app_image = materials["app_image"]
            legacy = binding.get("legacy")
        except (KeyError, TypeError):
            raise _refuse(
                TargetRefusal.MATERIALS_REFUSED,
                "the dispatch materials carry no deploy binding",
            ) from None
        if not images or len(sources) != 1:
            raise _refuse(
                TargetRefusal.IMAGE_SOURCE_INVALID,
                "the plan must carry one image source",
            )
        legacy_sha: str | None = None
        if legacy is not None:
            try:
                legacy_sha = legacy["sha256"]
            except (KeyError, TypeError):
                raise _refuse(
                    TargetRefusal.MATERIALS_REFUSED,
                    "the plan's legacy binding carries no sha",
                ) from None
            if legacy_env is None:
                raise _refuse(
                    TargetRefusal.LEGACY_ENV_MISSING,
                    "the plan binds a legacy env file and none was supplied",
                )
        elif legacy_env is not None:
            raise _refuse(
                TargetRefusal.LEGACY_ENV_NOT_BOUND,
                "a legacy env file was supplied and the plan binds none",
            )
        return cls(
            params_env=Path(params_env),
            params_env_digest=digest,
            app_image=app_image,
            image_source=next(iter(sources)),
            legacy_env=None if legacy_env is None else Path(legacy_env),
            legacy_sha256=legacy_sha,
        )


def _read_private_file(path: Path, *, code: TargetRefusal, what: str) -> bytes:
    """Bytes of a regular, non-symlink, not group/world-writable file."""
    try:
        before = os.lstat(path)
    except OSError:
        raise _refuse(code, f"{what} cannot be read") from None
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022:
        raise _refuse(code, f"{what} is not a private regular file")
    if before.st_size > _MAX_ENV_BYTES:
        raise _refuse(code, f"{what} exceeds the size limit")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(_MAX_ENV_BYTES + 1)
    except OSError:
        raise _refuse(code, f"{what} cannot be read") from None
    if len(data) > _MAX_ENV_BYTES:
        raise _refuse(code, f"{what} exceeds the size limit")
    return data


def _check_params_env(inputs: DeployEffectsInputs) -> None:
    data = _read_private_file(
        inputs.params_env,
        code=TargetRefusal.PARAMS_ENV_MALFORMED,
        what="params.env",
    )
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, inputs.params_env_digest):
        raise _refuse(
            TargetRefusal.PARAMS_ENV_DIGEST_MISMATCH,
            "params.env does not hash to the plan's params_env_digest",
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _refuse(
            TargetRefusal.PARAMS_ENV_MALFORMED, "params.env is not UTF-8"
        ) from None
    lines = text.split("\n")
    if not text.endswith("\n") or lines.pop() != "":
        raise _refuse(
            TargetRefusal.PARAMS_ENV_MALFORMED, "params.env is not LF-terminated"
        )
    keys = [line.split("=", 1)[0] for line in lines]
    if any(_LINE.fullmatch(line) is None for line in lines) or len(set(keys)) != len(
        keys
    ):
        raise _refuse(
            TargetRefusal.PARAMS_ENV_MALFORMED,
            "params.env is not unique KEY=value lines",
        )
    if f"{APP_IMAGE_KEY}={inputs.app_image}" not in lines:
        raise _refuse(
            TargetRefusal.PARAMS_ENV_MALFORMED,
            "params.env does not carry the planned APP_IMAGE",
        )


def _check_deploy_dir(deploy_dir: Path) -> None:
    if os.path.lexists(deploy_dir / ".env"):
        raise _refuse(
            TargetRefusal.DOTENV_PRESENT,
            "a .env exists in the deploy directory; the plan binds params.env only",
        )
    for name in _COMPOSE_OVERRIDES:
        if os.path.lexists(deploy_dir / name):
            raise _refuse(
                TargetRefusal.COMPOSE_OVERRIDE_PRESENT,
                "a Compose override exists in the deploy directory",
            )


def _check_legacy(inputs: DeployEffectsInputs) -> None:
    if inputs.legacy_env is None or inputs.legacy_sha256 is None:
        return
    data = _read_private_file(
        inputs.legacy_env,
        code=TargetRefusal.LEGACY_ENV_MISSING,
        what="the legacy env file",
    )
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, inputs.legacy_sha256):
        raise _refuse(
            TargetRefusal.LEGACY_ENV_SHA_MISMATCH,
            "the legacy env file does not hash to the policy sha",
        )


def build_deploy_unit_effects(
    spec: Any, deploy_dir: Path | str, inputs: DeployEffectsInputs
) -> Any:
    """Foundation's `ComposeHostEffects` over the plan-bound params.env.

    Every check runs BEFORE Foundation is imported, so a refusal never depends
    on Foundation being installed, and Foundation never sees a file the plan
    did not bind.
    """
    root = Path(deploy_dir)
    _check_deploy_dir(root)
    _check_params_env(inputs)
    _check_legacy(inputs)
    try:
        from dotmac_deployment_foundation.providers.compose_host import (
            ComposeHostEffects,
        )
        from dotmac_deployment_foundation.toolchain import (
            DEFAULT_TOOLS,
            resolve_tool,
        )
    except ImportError:
        raise _refuse(
            TargetRefusal.FOUNDATION_MISSING,
            "dotmac-deployment-foundation is not installed in this environment; "
            "target-side effects cannot be composed",
        ) from None
    tools = {
        name: resolve_tool(default, what=f"{name}_bin")
        for name, default in DEFAULT_TOOLS.items()
    }
    pulls = inputs.image_source == "pull"
    return ComposeHostEffects(
        spec,
        root,
        env_file=inputs.params_env,
        extra_env_files=() if inputs.legacy_env is None else (inputs.legacy_env,),
        docker_bin=tools["docker"],
        git_bin=tools["git"],
        pull_missing_images=pulls,
        check_registry_for_missing_images=pulls,
    )


def deploy_unit_effects_factory(
    inputs: DeployEffectsInputs,
) -> Callable[[Any, Path | str], Any]:
    """Bind the inputs; the result has Foundation's `build_effects` shape."""

    def build_effects(spec: Any, deploy_dir: Path | str) -> Any:
        return build_deploy_unit_effects(spec, deploy_dir, inputs)

    return build_effects
