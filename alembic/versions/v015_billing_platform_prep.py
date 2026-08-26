"""Prepare Vendor CP's platform-plane relationship to Billing.

This migration composes no tenant Billing state and moves no money. It creates
only Vendor-owned links from platform Billing accounts to the local vendor
account and commercial contract subjects. Billing's public platform helper
owns the foreign-key target and exact app-role revoke shape.

Revision ID: v015_billing_platform_prep
Revises: v014_allocations_authority
Create Date: 2026-08-17
"""

from __future__ import annotations

from dotmac_billing import (
    drop_billing_account_link,
    link_platform_billing_account,
)

revision = "v015_billing_platform_prep"
down_revision = "v014_allocations_authority"
branch_labels = None
depends_on = "bi_0001_billing"

VENDOR_ACCOUNT_LINK = "billing_vendor_account_links"
CONTRACT_LINK = "billing_contract_links"


def upgrade() -> None:
    link_platform_billing_account(
        table_name=VENDOR_ACCOUNT_LINK,
        subject_table="vendor_accounts",
        subject_column="vendor_account_id",
        on_delete_subject="RESTRICT",
        on_delete_billing_account="RESTRICT",
    )
    link_platform_billing_account(
        table_name=CONTRACT_LINK,
        subject_table="contracts",
        subject_column="contract_id",
        on_delete_subject="RESTRICT",
        on_delete_billing_account="RESTRICT",
    )


def downgrade() -> None:
    drop_billing_account_link(table_name=CONTRACT_LINK)
    drop_billing_account_link(table_name=VENDOR_ACCOUNT_LINK)
