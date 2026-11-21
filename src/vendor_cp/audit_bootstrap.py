"""Ensure a non-web process has its caller-owned audit vocabulary installed."""

from __future__ import annotations

from dotmac_kernel import AuditActionsNotInstalledError
from dotmac_kernel.audit_actions import active_audit_actions


def ensure_process_audit_actions() -> None:
    """Supply CP declarations only when the caller installed no registry.

    An existing registry belongs to the process's composition owner. Preserve it
    unchanged, including an explicitly empty or partial vocabulary. Only the
    kernel's distinct not-installed state permits this CP fallback.
    """
    try:
        active_audit_actions()
    except AuditActionsNotInstalledError:
        from vendor_cp.composition import install_process_audit_actions

        install_process_audit_actions()


__all__ = ["ensure_process_audit_actions"]
