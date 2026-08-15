"""The vendor-local approval feature — versioned approval policy + records.

Named `vendor_approvals`, not `approvals`. The installed `dotmac-approvals`
module now composes into this assembly under the code `approvals`, and a module
registry has exactly one owner per code, so both cannot carry that name.

The rename says which one this is rather than which one arrived first. This
package is the vendor-local writer that still owns every approval decision in
production; the installed module is composed in SHADOW — manifest, lineage and
PLATFORM plane only — exactly as `dotmac-entitlement-allocation` was. When a
cutover is designed the authority moves and this package retires; the name is
not the thing that has to change then.

The HTTP surface is unchanged: routes still live under
`/platform/vendor/approvals`. A manifest name is a composition identifier, not
a URL.
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
