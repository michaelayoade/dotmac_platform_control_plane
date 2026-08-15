"""The vendor-local approval feature — versioned approval policy + records.

This is the ONLY approval owner in this assembly. It writes
`public.approval_policies` and `public.approval_records`, and every approval
decision the control plane makes goes through it.

## Why it is named `vendor_approvals`

`dotmac-approvals` is composed here — in SHADOW, and read-only — and it holds
the module code `approvals`. A module registry has one owner per code, so this
package cannot also be called that.

Shadow composition is a bounded authority-migration phase with exactly one
authoritative writer, and this package is that writer. The module's tables are
empty, `platform_api` may only read them (vendor `v012`), and the authority moves
only in the sealed cutover transaction of ADR-0004 § 3.1.

The rename is therefore proactive, not consequential. A module registry holds one
owner per code and `FeatureManifest.name` becomes that code, so a manifest still
called `approvals` would collide with the module on the cutover's first line of
composition. Renaming now takes that off the cutover's path instead of leaving it
as the cutover's first surprise.

The HTTP surface is unchanged: routes still live under
`/platform/vendor/approvals`. A manifest name is a composition identifier, not a
URL.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from vendor_cp.approvals.router import router

feature = FeatureManifest(
    name="vendor_approvals",
    routers=[router],
    core=True,
    enabled_by_default=True,
)
