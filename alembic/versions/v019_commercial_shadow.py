"""Compose Billing and Subscriptions PLATFORM storage as read-only shadows.

The shared modules grant their online platform role normal DML because a
greenfield assembly may make them authoritative immediately. Vendor has not.
This assembly is only installing the two platform schemas so it can prove the
shape and prepare a measured cutover; no runtime adapter, commercial-authority
binding, backfill, dual-write or writer switch lands here.

``depends_on`` orders this assembly-owned restriction after both released
module heads. Vendor's Alembic environment runs the complete composed upgrade
in one transaction and its deploy entrypoint accepts only ``heads``, so neither
module's transient DML grant can become a committed deployment state.

Revision ID: v019_commercial_shadow
Revises: v018_licence_delivery_intents
Create Date: 2026-08-25
"""

from __future__ import annotations

from alembic import op

revision = "v019_commercial_shadow"
down_revision = "v018_licence_delivery_intents"
branch_labels = None
depends_on = ("bi_0001_billing", "su_0003_billing_treatments")

ONLINE_PLATFORM_ROLE = "platform_api"
TENANT_ROLE = "app_user"

# Snapshots of the immutable released platform planes this revision seals.
# A migration must not import today's model list and silently change its own
# historical meaning when a later module release adds a table.
PLATFORM_TABLES = {
    "mod_billing": (
        "platform_billing_accounts",
        "platform_rated_obligations",
        "platform_documents",
        "platform_document_lines",
        "platform_document_events",
        "platform_confirmed_settlements",
        "platform_posting_groups",
        "platform_posting_effects",
        "platform_allocation_effects",
        "platform_applied_tax_snapshots",
        "platform_applied_fx_snapshots",
        "platform_party_tax_identity_snapshots",
        "platform_invoice_document_facts",
        "platform_document_artifacts",
        "platform_accounting_facts",
        "platform_receivable_position_facts",
        "platform_receivable_exposure_facts",
    ),
    "mod_subscriptions": (
        "platform_offers",
        "platform_offer_versions",
        "platform_offer_version_prices",
        "platform_subscription_contracts",
        "platform_subscription_contract_versions",
        "platform_subscription_contract_lines",
        "platform_recurring_charge_occurrences",
        "platform_subscription_billing_arrangements",
        "platform_subscription_billing_grants",
    ),
}

# SELECT stays: a shadow that cannot be inspected cannot establish parity.
REVOKED = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_GRANTABLE = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


def upgrade() -> None:
    for schema, tables in PLATFORM_TABLES.items():
        for table in tables:
            qualified = f"{schema}.{table}"
            op.execute(
                f"REVOKE {', '.join(REVOKED)} ON {qualified} "
                f"FROM {ONLINE_PLATFORM_ROLE};"
            )
            op.execute(f"REVOKE ALL ON {qualified} FROM {TENANT_ROLE};")

    # Billing a1 deliberately grants this one column-level privilege in
    # addition to its table grants. A table-level REVOKE does not remove it.
    op.execute(
        "REVOKE UPDATE (id) ON mod_billing.platform_billing_accounts "
        f"FROM {ONLINE_PLATFORM_ROLE};"
    )

    _verify_effective_privileges()


def downgrade() -> None:
    """Refuse to recreate writable module planes before authority moves."""
    raise RuntimeError(
        "v019_commercial_shadow cannot be downgraded: restoring Billing or "
        "Subscriptions DML before the sealed authority cutover would create "
        "an unapproved writer. Grants move only in the future cutover revision."
    )


def _verify_effective_privileges() -> None:
    """Assert effective table and column privileges before commit."""
    connection = op.get_bind()
    failures: list[str] = []

    for schema, tables in PLATFORM_TABLES.items():
        for table in tables:
            qualified = f"{schema}.{table}"
            for privilege in REVOKED:
                if _holds(connection, ONLINE_PLATFORM_ROLE, qualified, privilege):
                    failures.append(
                        f"{ONLINE_PLATFORM_ROLE} still holds {privilege} on "
                        f"{qualified}"
                    )
            if not _holds(connection, ONLINE_PLATFORM_ROLE, qualified, "SELECT"):
                failures.append(
                    f"{ONLINE_PLATFORM_ROLE} cannot SELECT {qualified}; shadow "
                    "comparison requires read access"
                )
            for privilege in ("SELECT", *REVOKED):
                if _holds(connection, TENANT_ROLE, qualified, privilege):
                    failures.append(
                        f"{TENANT_ROLE} still holds {privilege} on {qualified}"
                    )

    if failures:
        raise RuntimeError(
            "commercial shadow restriction did not take effect: " + "; ".join(failures)
        )


def _holds(connection: object, role: str, qualified: str, privilege: str) -> bool:
    """Whether a role effectively holds a table or column privilege."""
    from sqlalchemy import text

    statement = "SELECT has_table_privilege(:role, :rel, :priv)"
    if privilege in COLUMN_GRANTABLE:
        statement += " OR has_any_column_privilege(:role, :rel, :priv)"
    return bool(
        connection.execute(  # type: ignore[attr-defined]
            text(statement),
            {"role": role, "rel": qualified, "priv": privilege},
        ).scalar()
    )
