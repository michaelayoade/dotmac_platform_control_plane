"""Desired operation instances follow exact held owner schemas."""

from __future__ import annotations

import pytest
from dotmac_kernel import CAPABILITY_SCHEMA_DIALECT, CapabilitySchemaDocument

from vendor_cp.managed_profiles.operation_inputs import (
    DesiredOperationInputError,
    validate_desired_operation_input,
)


def _schema() -> CapabilitySchemaDocument:
    return CapabilitySchemaDocument.from_mapping(
        {
            "$id": "schema:owner/service/apply/input@v1",
            "$schema": CAPABILITY_SCHEMA_DIALECT,
            "additionalProperties": False,
            "properties": {
                "desired_ref": {"type": "string"},
                "issuer_url": {"format": "uri", "type": "string"},
                "notification_email": {"format": "email", "type": "string"},
            },
            "required": ["desired_ref", "issuer_url"],
            "type": "object",
        }
    )


def test_only_approved_composition_target_may_be_missing() -> None:
    assert validate_desired_operation_input(
        {"desired_ref": "deployment-1"},
        schema=_schema(),
        composition_target_pointers=("/issuer_url",),
    ) == {"desired_ref": "deployment-1"}

    with pytest.raises(DesiredOperationInputError, match="required"):
        validate_desired_operation_input(
            {}, schema=_schema(), composition_target_pointers=("/issuer_url",)
        )


def test_caller_cannot_override_a_composition_owned_target() -> None:
    with pytest.raises(DesiredOperationInputError, match="must not be caller"):
        validate_desired_operation_input(
            {
                "desired_ref": "deployment-1",
                "issuer_url": "https://id.example.test/realms/customer",
            },
            schema=_schema(),
            composition_target_pointers=("/issuer_url",),
        )


def test_undeclared_input_field_is_refused() -> None:
    with pytest.raises(DesiredOperationInputError, match="Additional properties"):
        validate_desired_operation_input(
            {"desired_ref": "deployment-1", "provider": "keycloak"},
            schema=_schema(),
            composition_target_pointers=("/issuer_url",),
        )


def test_format_is_enforced_before_vendor_can_approve_the_document() -> None:
    with pytest.raises(DesiredOperationInputError, match="not a 'email'"):
        validate_desired_operation_input(
            {
                "desired_ref": "deployment-1",
                "notification_email": "not-an-email",
            },
            schema=_schema(),
            composition_target_pointers=("/issuer_url",),
        )


def test_new_required_owner_field_flows_through_without_vendor_source_change() -> None:
    schema_mapping = _schema().to_mapping()
    properties = schema_mapping["properties"]
    assert isinstance(properties, dict)
    properties["owner_added_required"] = {
        "minimum": 1,
        "type": "integer",
    }
    required = schema_mapping["required"]
    assert isinstance(required, list)
    required.append("owner_added_required")
    changed = CapabilitySchemaDocument.from_mapping(schema_mapping)

    with pytest.raises(DesiredOperationInputError, match="owner_added_required"):
        validate_desired_operation_input(
            {"desired_ref": "deployment-1"},
            schema=changed,
            composition_target_pointers=("/issuer_url",),
        )
    assert validate_desired_operation_input(
        {"desired_ref": "deployment-1", "owner_added_required": 1},
        schema=changed,
        composition_target_pointers=("/issuer_url",),
    )["owner_added_required"] == 1
