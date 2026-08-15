"""The vendor-local approval feature — versioned approval policy + records.

This is the ONLY approval owner in this assembly. It writes
`public.approval_policies` and `public.approval_records`, and every approval
decision the control plane makes goes through it.

## Why it is named `vendor_approvals`

`dotmac-approvals` exists as a published module and RESERVES the module code
`approvals`. It is **not composed here** — not its manifest, not its lineage,
not a plane selection. Shadow composition is a bounded authority-migration phase
with exactly one authoritative writer, so it may land only behind a cutover
contract naming the old and new authority, the identity mapping, open-request
handling, parity measurement, the watermark, the rollback boundary and the
retirement gate.

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
