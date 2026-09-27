"""The `withdrawal_conflicts` manifest: the one platform-admin resolve route.

Separate from `relay_health`'s CLI-only surface (`vendor_cp.cli`) because a
CLI command has no authenticated-admin seam to draw an actor from (see
`vendor_cp.cli.commands.withdrawal_conflicts_list`'s own docstring); the JSON
route does, through `require_platform_admin`, exactly as
`vendor_cp.contracts.router` establishes its actor.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.relay.withdrawal_router import router

feature = FeatureManifest(
    name="withdrawal_conflicts",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
