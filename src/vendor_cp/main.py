"""ASGI entrypoint — the vendor control plane is `create_app(build_spec())`.

`uvicorn vendor_cp.main:app`. All composition, including the declared API
documentation policy, lives in `assembly.build_spec()`; the kernel applies it
at FastAPI construction (ADR-0016). This module remains a thin adapter.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from vendor_cp.assembly import build_spec
from vendor_cp.deployment.release_descriptor_source import (
    CatalogueReleaseDescriptorSource,
)

app = create_app(build_spec())

# Deployment Control's operator surface reads its release-descriptor source from
# `app.state` (Control a18, `web.release_descriptor_source`) and refuses when it
# is absent, rather than accepting descriptor text from a browser. The source is
# read-only and does no I/O until a request resolves a release; the M4 profile
# is what decides whether the surface is mounted at all.
app.state.deployment_control_release_source = CatalogueReleaseDescriptorSource()
