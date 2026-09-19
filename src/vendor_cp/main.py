"""ASGI entrypoint — the vendor control plane is `create_app(build_spec())`.

`uvicorn vendor_cp.main:app`. All composition, including the declared API
documentation policy, lives in `assembly.build_spec()`; the kernel applies it
at FastAPI construction (ADR-0016). This module remains a thin adapter.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from vendor_cp.assembly import build_spec

app = create_app(build_spec())
