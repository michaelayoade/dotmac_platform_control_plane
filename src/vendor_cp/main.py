"""ASGI entrypoint — all composition lives in `assembly.build_spec()`.

Kernel a100 consumes the assembly's typed API-documentation policy while it
constructs FastAPI. This adapter therefore has no post-construction route
deletion and no second policy owner.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from vendor_cp.assembly import build_spec

app = create_app(build_spec())
