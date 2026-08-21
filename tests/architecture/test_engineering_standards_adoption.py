"""Vendor Control Plane's side of the Governance standards adoption.

The detector remains Governance-owned. These tests guard this repository's
immutable pin and declared review record without copying the classifier.
"""

from __future__ import annotations

import importlib.util
import json
import re
import types
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / ".dotmac" / "standards-profile.json"
EVIDENCE = REPO / "docs" / "external-connector-surface.md"
CATEGORIES = {
    "outbound_transport",
    "webhook_surface",
    "provider_credential",
    "connector_task",
    "sync_checkpoint",
    "delivery_retry",
}
ACCEPTED_GOVERNANCE_SHA = "a19259b10568d29dc0a9617347498fea7f1e7a97"
_EVIDENCE_ROW = re.compile(r"^\|\s*`(\w+)`\s*\|\s*(\d+)\s*\|", re.MULTILINE)


def _profile() -> dict:
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def _pin_checker() -> types.ModuleType:
    path = REPO / "scripts" / "check_governance_pin.py"
    spec = importlib.util.spec_from_file_location("check_governance_pin", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_profile_declares_the_accepted_schema_nine_surface() -> None:
    profile = _profile()
    assert profile["schema_version"] == 9
    assert profile["enforcement_mode"] == "required"
    surface = profile["external_connector_surface"]
    assert set(surface) == {"baselines", "conserved_exclusions"}
    assert set(surface["baselines"]) == CATEGORIES
    assert all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in surface["baselines"].values()
    )


def test_the_profile_tracks_the_remaining_vendor_licensing_boundary() -> None:
    profile = _profile()
    assert profile["authorities"] == [
        {
            "authority_id": "licence-signing-custody",
            "subject": (
                "Vendor-held private signing-key custody and runtime signer "
                "selection supplied to the Licensing module."
            ),
            "protected_resources": [
                "licence-signing-private-key-custody",
                "licence-runtime-signer-selection",
            ],
            "owner_component": "licence-signing-adapter",
            "owner_implementation": "src/vendor_cp/licensing/signing_adapter.py",
            "decision_interface": (
                "vendor_cp.licensing.signing_adapter.runtime_licence_signers"
            ),
            "canonical_writer_paths": ["src/vendor_cp/licensing/signing_adapter.py"],
            "adapter_paths": ["src/vendor_cp/licensing/adapter.py"],
            "drift_test_paths": [
                "tests/architecture/test_licensing_authority.py",
                "tests/unit/test_licence_key_rotation.py",
            ],
        }
    ]
    assert profile["typed_contract_surfaces"] == [
        {
            "surface_id": "licensing-module-adapter-contract",
            "paths": ["src/vendor_cp/licensing/adapter.py"],
            "require_public_annotations": True,
            "forbid_any": True,
            "require_immutable_records": True,
        }
    ]


def test_the_review_record_equals_the_declared_baseline() -> None:
    declared = _profile()["external_connector_surface"]["baselines"]
    rows = _EVIDENCE_ROW.findall(EVIDENCE.read_text(encoding="utf-8"))
    recorded = {category: int(count) for category, count in rows}
    assert set(recorded) == CATEGORIES, rows
    assert recorded == declared


def test_the_governance_pin_is_coherent_and_accepted() -> None:
    checker = _pin_checker()
    pins = checker.read_pins(REPO)
    assert all(pins), "a missing pin would make three empty values look coherent"
    assert pins == (ACCEPTED_GOVERNANCE_SHA,) * 3
    assert checker.problems(*pins) == []


def test_the_pin_rule_rejects_each_failure_shape() -> None:
    checker = _pin_checker()
    armed = "0" * 39 + "a"
    other = "1" * 39 + "b"
    assert checker.problems(armed, armed, armed) == []
    for bad in ("PENDING-APPROVAL", "main", "v1", armed[:7], armed.upper()):
        assert checker.problems(bad, bad, bad)
    for pins in (
        (other, armed, armed),
        (armed, other, armed),
        (armed, armed, other),
        (armed, armed, ""),
    ):
        assert "disagree" in checker.problems(*pins)[0]


def test_the_profile_names_the_accepted_governance_source() -> None:
    model = _profile()["governance_model"]
    assert model == {
        "kind": "pinned",
        "canonical_url": "https://github.com/michaelayoade/dotmac_governance",
        "revision": ACCEPTED_GOVERNANCE_SHA,
        "source": "docs/adr/0006-cross-repository-engineering-conformance.md",
        "status": "accepted",
    }
