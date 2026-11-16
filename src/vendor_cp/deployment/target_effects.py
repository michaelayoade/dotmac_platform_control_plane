"""Thin target-side effects factories (E6, scope (a)).

Gate 2 a2 executes ON the target (Michael's Q2 ruling): Foundation and these
bindings run on the host being mutated, the controller only launches. The
effects the Executor needs are therefore Foundation's OWN
`ComposeHostEffects` / `ComposeHostExposureEffects`, constructed exactly as the
in-package `compose-host` provider constructs them (the same pinned
`docker`/`git` resolution, the same local subprocess runner), and nothing else.

What this module deliberately is not:

* not a second deployment engine: no host effect is implemented here, so none
  can drift from Foundation's;
* not an SSH effects option: the CP-owned remote option was rejected, and no
  runner here reaches another machine;
* not a relaxation of `require_build_effects`: Foundation's refusal for any
  other placement is untouched. These factories are only ever reachable through
  bindings that compose at all on a target, because `bindings()` requires the
  scoped dispatch-consumption credential and refuses a host carrying a general
  CP database credential (see `consumption_scope`).

Foundation is not a dependency of this assembly (pyproject), so every import is
lazy and a missing install refuses with the sanitized, typed refusal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

__all__ = ["build_target_effects", "build_target_exposure_effects"]


def _foundation_missing() -> FoundationBindingsUnavailable:
    return FoundationBindingsUnavailable(
        "dotmac-deployment-foundation is not installed in this environment; "
        "target-side effects cannot be composed",
        code=TargetRefusal.FOUNDATION_MISSING,
    )


def build_target_effects(spec: Any, deploy_dir: Path | str) -> Any:
    """Foundation's `ComposeHostEffects` with its local runner, on this host.

    Tools are resolved through Foundation's own pinned-toolchain check
    (absolute path, executable, not replaceable by anyone but its owner), the
    same call the in-package provider makes, so selecting this provider never
    weakens tool pinning.
    """
    try:
        from dotmac_deployment_foundation.providers.compose_host import (
            ComposeHostEffects,
        )
        from dotmac_deployment_foundation.toolchain import (
            DEFAULT_TOOLS,
            resolve_tool,
        )
    except ImportError:
        raise _foundation_missing() from None
    tools = {
        name: resolve_tool(default, what=f"{name}_bin")
        for name, default in DEFAULT_TOOLS.items()
    }
    return ComposeHostEffects(
        spec,
        Path(deploy_dir),
        docker_bin=tools["docker"],
        git_bin=tools["git"],
    )


def build_target_exposure_effects(spec: Any, deploy_dir: Path | str) -> Any:
    """Foundation's `ComposeHostExposureEffects` over its local runner.

    `_default_runner` is Foundation's own local subprocess runner; its CLI
    imports it by this name for the same construction, and Foundation exposes
    no public alias. A rename refuses here rather than substituting a runner.
    """
    try:
        from dotmac_deployment_foundation.providers.compose_host import (
            _default_runner,
        )
        from dotmac_deployment_foundation.providers.exposure_host import (
            ComposeHostExposureEffects,
        )
    except ImportError:
        raise _foundation_missing() from None
    return ComposeHostExposureEffects(
        spec, deploy_dir=Path(deploy_dir), runner=_default_runner
    )
