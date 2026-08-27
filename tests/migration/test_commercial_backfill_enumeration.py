"""PostgreSQL enforces the agreement walk's read-only consistent snapshot."""

from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from vendor_cp.commercial_backfill import walk_agreement_lines


def test_agreement_walk_starts_repeatable_read_read_only(postgres_url: str) -> None:
    engine = create_engine(postgres_url)
    try:
        with Session(engine) as db:
            walked = walk_agreement_lines(db, page_size=1, max_pages=1)
            assert walked.complete is True
            assert db.execute(text("SHOW transaction_read_only")).scalar_one() == "on"
            assert (
                db.execute(text("SHOW transaction_isolation")).scalar_one()
                == "repeatable read"
            )
    finally:
        engine.dispose()
