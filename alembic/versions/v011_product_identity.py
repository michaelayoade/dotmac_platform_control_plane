"""Expand commercial state with explicit, product-qualified identity.

Adds ``product_code`` to immutable offer versions and contracts without guessing
the product for historical rows. The columns are nullable only so the migration
can preserve those rows. ``NOT VALID`` checks tolerate the existing ambiguity but
reject every new or updated row without a non-blank product identity.

Offer identity becomes ``(product_code, offer_code, version)``. A partial unique
index keeps unclassified historical offer identities unique while operators map
them; product-qualified offers may use the same commercial code independently.

Revision ID: v011_product_identity
Revises: v010_delivery_hardening
Create Date: 2026-08-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "v011_product_identity"
down_revision = "v010_delivery_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "offer_versions",
        sa.Column("product_code", sa.String(length=120), nullable=True),
    )
    op.execute(
        """
        ALTER TABLE offer_versions
          ADD CONSTRAINT ck_offer_versions_product_identity
          CHECK (
            product_code IS NOT NULL
            AND length(product_code) > 0
            AND product_code = btrim(product_code)
          ) NOT VALID;
        """
    )
    op.drop_constraint("uq_offer_versions_code_ver", "offer_versions", type_="unique")
    op.create_unique_constraint(
        "uq_offer_versions_product_code_ver",
        "offer_versions",
        ["product_code", "offer_code", "version"],
    )
    op.create_index(
        "uq_offer_versions_unclassified_code_ver",
        "offer_versions",
        ["offer_code", "version"],
        unique=True,
        postgresql_where=sa.text("product_code IS NULL"),
    )

    op.add_column(
        "contracts",
        sa.Column("product_code", sa.String(length=120), nullable=True),
    )
    op.execute(
        """
        ALTER TABLE contracts
          ADD CONSTRAINT ck_contracts_product_identity
          CHECK (
            product_code IS NOT NULL
            AND length(product_code) > 0
            AND product_code = btrim(product_code)
          ) NOT VALID;
        """
    )
    op.create_index("ix_contracts_product_code", "contracts", ["product_code"])


def downgrade() -> None:
    # The old global identity cannot represent two product-qualified offers with
    # the same code/version. Refuse rather than delete or merge commercial facts.
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
              FROM offer_versions
             GROUP BY offer_code, version
            HAVING count(*) > 1
          ) THEN
            RAISE EXCEPTION
              'cannot downgrade v011: product-qualified offer identities collide';
          END IF;
        END $$;
        """
    )
    op.drop_index("ix_contracts_product_code", table_name="contracts")
    op.execute("ALTER TABLE contracts DROP CONSTRAINT ck_contracts_product_identity;")
    op.drop_column("contracts", "product_code")

    op.drop_index(
        "uq_offer_versions_unclassified_code_ver", table_name="offer_versions"
    )
    op.drop_constraint(
        "uq_offer_versions_product_code_ver", "offer_versions", type_="unique"
    )
    op.create_unique_constraint(
        "uq_offer_versions_code_ver",
        "offer_versions",
        ["offer_code", "version"],
    )
    op.execute(
        "ALTER TABLE offer_versions "
        "DROP CONSTRAINT ck_offer_versions_product_identity;"
    )
    op.drop_column("offer_versions", "product_code")
