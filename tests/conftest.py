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

import pytest  # noqa: E402
from dotmac_kernel.audit_actions import (  # noqa: E402
    AuditActionRegistry,
    install_audit_actions,
)

from vendor_cp.assembly import build_spec  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _install_declared_audit_actions() -> None:
    """Unit services consume the same closed audit vocabulary as the app."""
    install_audit_actions(AuditActionRegistry.from_manifests(build_spec().modules))
