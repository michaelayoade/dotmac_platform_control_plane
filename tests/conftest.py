"""Test bootstrap.

The kernel constructs its SQLAlchemy engine from `DATABASE_URL` at import time,
so it must be present in the real environment BEFORE any test module imports
`vendor_cp` (→ `dotmac_kernel`). A well-formed but unreachable Postgres URL is
enough — engine construction never connects; DB-backed tests use the kernel's
in-memory testing kit (`create_test_engine`), not this URL.
"""

from __future__ import annotations

import os

_DUMMY = "postgresql+psycopg://x:x@127.0.0.1:5432/vendor_control_plane_test"
os.environ.setdefault("DATABASE_URL", _DUMMY)
os.environ.setdefault("PLATFORM_DATABASE_URL", _DUMMY)
