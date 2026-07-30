"""DotMac Vendor Control Plane.

A vendor/product-lifecycle ASSEMBLY composed from the pinned `dotmac-kernel`. It
is NOT a product data plane: it owns vendor-side accounts, provisioning
contracts, and (later) deployment lifecycle — never a product's tenants,
subscribers, or customer data. See `docs/ARCHITECTURE.md`.
"""

__version__ = "0.1.0"
