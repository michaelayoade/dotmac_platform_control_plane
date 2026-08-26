"""The commercial readiness report is aggregate-only and non-authoritative."""

from __future__ import annotations

import ast
import inspect
from dataclasses import fields
from pathlib import Path

from dotmac_billing import module as billing_module
from dotmac_subscriptions import module as subscriptions_module

import vendor_cp.commercial_shadow_readiness as readiness_module
from vendor_cp.commercial_shadow_readiness import (
    BILLING_PLATFORM_TABLES,
    SUBSCRIPTIONS_PLATFORM_TABLES,
    CommercialShadowReadinessReport,
    SourceCompleteness,
    SourceMapping,
    TargetPopulation,
)
from vendor_cp.cutover_readiness import VENDOR_OWNED_TABLES

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "src/vendor_cp/commercial_shadow_readiness.py"


def test_observed_tables_match_the_exact_pinned_module_manifests() -> None:
    assert BILLING_PLATFORM_TABLES == tuple(billing_module.platform_tables)
    assert SUBSCRIPTIONS_PLATFORM_TABLES == tuple(subscriptions_module.platform_tables)


def test_report_contract_can_serialize_only_aggregate_counts() -> None:
    integer_only = {
        SourceCompleteness,
        SourceMapping,
        TargetPopulation,
        CommercialShadowReadinessReport,
    }
    for record in integer_only:
        assert {field.type for field in fields(record)} <= {
            "int",
            "SourceCompleteness",
            "SourceMapping",
            "TargetPopulation",
        }

    report = CommercialShadowReadinessReport(
        schema_version=1,
        source_completeness=SourceCompleteness(1, 2, 3, 4, 5),
        source_mapping=SourceMapping(6, 7),
        billing_target=TargetPopulation(17, 17, 0, 0),
        subscriptions_target=TargetPopulation(9, 9, 0, 0),
    )
    payload = report.to_dict()
    assert payload == {
        "schema_version": 1,
        "source_completeness": {
            "offer_versions": 1,
            "offers_missing_product_identity": 2,
            "agreement_headers": 3,
            "agreement_lines": 4,
            "non_draft_agreements_without_frozen_content": 5,
        },
        "source_mapping": {
            "agreement_lines_without_resolved_offer": 6,
            "agreement_lines_with_frozen_offer_mismatch": 7,
        },
        "billing_target": {
            "expected_tables": 17,
            "present_tables": 17,
            "populated_tables": 0,
            "rows": 0,
        },
        "subscriptions_target": {
            "expected_tables": 9,
            "present_tables": 9,
            "populated_tables": 0,
            "rows": 0,
        },
    }


def test_every_literal_statement_is_read_only() -> None:
    tree = ast.parse(SERVICE.read_text())
    text_statements = [
        call.args[0].value.strip().upper()
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "text"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ]
    count_statements = [
        call.args[1].value.strip().upper()
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_count"
        and len(call.args) >= 2
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    ]
    statements = text_statements + count_statements
    assert statements
    assert all(
        statement.startswith(("SELECT", "SET TRANSACTION")) for statement in statements
    )
    assert text_statements[0].startswith(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    )


def test_incumbent_writer_inventory_does_not_infer_billing_readiness() -> None:
    offer_service = (ROOT / "src/vendor_cp/offers/service.py").read_text()
    offer_router = (ROOT / "src/vendor_cp/offers/router.py").read_text()
    assert offer_service.count("OfferVersion(") == 1
    assert offer_router.count("service.publish_offer_version(") == 1

    # Vendor's ratcheted owned-table inventory has one local priced-offer
    # source, but no invoice, receivable, settlement, recurrence or cadence
    # table.  This is a writer inventory fact only; the report deliberately has
    # no `ready` verdict derived from it.
    commercial_markers = (
        "billing",
        "invoice",
        "receivable",
        "settlement",
        "recurrence",
        "cadence",
    )
    assert not {
        table
        for table in VENDOR_OWNED_TABLES
        if any(marker in table for marker in commercial_markers)
    }
    assert "ready" not in {
        field.name for field in fields(CommercialShadowReadinessReport)
    }


def test_service_imports_no_commercial_runtime_owner() -> None:
    source = inspect.getsource(readiness_module)
    assert "dotmac_billing" not in source
    assert "dotmac_subscriptions" not in source
