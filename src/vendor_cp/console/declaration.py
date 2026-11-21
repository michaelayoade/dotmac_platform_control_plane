"""Pure console feature declaration, without route bindings."""

from __future__ import annotations

from dotmac_kernel import ModuleManifest

declaration = ModuleManifest(
    code="console",
    version="0.1.0",
    contract_version=2,
    core=False,
    enabled_by_default=True,
)
