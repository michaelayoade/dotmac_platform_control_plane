"""ASGI entrypoint — the vendor control plane is `create_app(build_spec())`.

`uvicorn vendor_cp.main:app`. All composition lives in `assembly.build_spec()`;
this module is the thinnest possible adapter, exactly as the kernel intends.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from vendor_cp.assembly import build_spec

app = create_app(build_spec())
