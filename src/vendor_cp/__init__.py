"""DotMac Vendor Control Plane.

A vendor/product-lifecycle ASSEMBLY composed from the pinned `dotmac-kernel`. It
is NOT a product data plane: it owns vendor-side accounts, provisioning
contracts, and (later) deployment lifecycle — never a product's tenants,
subscribers, or customer data. See `docs/ARCHITECTURE.md`.

There is deliberately no `__version__` literal here. It used to say `"0.1.0"`
and nothing read it, which is the only reason it never disagreed with
`pyproject.toml` — the same shape in `dotmac-deployment-control` shipped a
wheel that reported itself two alphas behind what it was. The installed
version lives in `vendor_cp.identity`, which reads what the installer
recorded rather than what a source file remembers.
"""
