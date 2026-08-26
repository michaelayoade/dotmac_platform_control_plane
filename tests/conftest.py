"""Test bootstrap.

The kernel constructs its SQLAlchemy engine from `DATABASE_URL` at import time,
so it must be present in the real environment BEFORE any test module imports
`vendor_cp` (→ `dotmac_kernel`). A well-formed but unreachable Postgres URL is
enough — engine construction never connects; DB-backed tests use the kernel's
in-memory testing kit (`create_test_engine`), not this URL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

_DUMMY = "postgresql+psycopg://x:x@127.0.0.1:5432/vendor_control_plane_test"
os.environ.setdefault("DATABASE_URL", _DUMMY)
os.environ.setdefault("PLATFORM_DATABASE_URL", _DUMMY)

import pytest  # noqa: E402  # environment must precede kernel import
from dotmac_kernel.audit_actions import (  # noqa: E402
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)

from vendor_cp.assembly import STATEFUL_MODULES, VENDOR_SURFACES  # noqa: E402


@pytest.fixture(autouse=True)
def _complete_assembly_audit_registry() -> Iterator[None]:
    """Give each test the declarations production installs at assembly boot.

    The kernel registry is process-global.  A test that boots a restricted
    profile legitimately replaces it, but that profile must not become an
    undeclared, order-dependent precondition for the next service test.
    """

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(
        AuditActionRegistry.from_manifests((*STATEFUL_MODULES, *VENDOR_SURFACES))
    )
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)
