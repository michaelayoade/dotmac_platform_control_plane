"""Validation for immutable product-owned desired-operation documents."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

from dotmac_kernel import CapabilitySchemaDocument
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError


class DesiredOperationInputError(ValueError):
    """A desired-operation document does not satisfy its held owner schema."""


def validate_desired_operation_input(
    document: Mapping[str, object],
    *,
    schema: CapabilitySchemaDocument,
    composition_target_pointers: Sequence[str] = (),
) -> dict[str, object]:
    """Return a detached canonical document after exact schema validation.

    A product-owned composition may fill an approved target pointer only after
    the prerequisite operation has produced signed public evidence.  Such a
    value is therefore required by the final APPLY schema but must be absent
    from Vendor intent.  Every other constraint is enforced before the desired
    state and its plan can be approved.
    """

    canonical = _canonical_mapping(document)
    targets = tuple(sorted(set(composition_target_pointers)))
    for pointer in targets:
        schema.require_instance_pointer(pointer)
        if _pointer_present(canonical, pointer):
            raise DesiredOperationInputError(
                f"composition-owned target {pointer!r} must not be caller supplied"
            )
    schema_mapping = schema.to_mapping()
    try:
        Draft202012Validator.check_schema(schema_mapping)
        errors = tuple(
            sorted(
                Draft202012Validator(
                    schema_mapping,
                    format_checker=FormatChecker(),
                ).iter_errors(canonical),
                key=lambda error: tuple(str(item) for item in error.absolute_path),
            )
        )
    except SchemaError as exc:
        raise DesiredOperationInputError(
            "held capability input schema is not valid JSON Schema 2020-12"
        ) from exc
    refused = tuple(
        error for error in errors if not _is_approved_missing_target(error, targets)
    )
    if refused:
        first = refused[0]
        location = _instance_pointer(tuple(first.absolute_path)) or "/"
        raise DesiredOperationInputError(
            f"desired operation input violates its held schema at {location}: "
            f"{first.message}"
        )
    return canonical


def _canonical_mapping(document: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(document, Mapping) or not all(
        isinstance(key, str) for key in document
    ):
        raise DesiredOperationInputError(
            "desired operation input must be a JSON object with string keys"
        )
    try:
        payload = json.dumps(
            dict(document),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        parsed: object = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise DesiredOperationInputError(
            "desired operation input must contain only finite JSON values"
        ) from exc
    if not isinstance(parsed, dict):  # pragma: no cover - guarded by Mapping
        raise DesiredOperationInputError("desired operation input must be an object")
    return cast(dict[str, object], parsed)


def _is_approved_missing_target(
    error: ValidationError, targets: tuple[str, ...]
) -> bool:
    if error.validator != "required" or not isinstance(error.instance, Mapping):
        return False
    required = error.validator_value
    if not isinstance(required, list) or not all(
        isinstance(item, str) for item in required
    ):
        return False
    missing = tuple(item for item in required if item not in error.instance)
    if not missing:
        return False
    parent = _instance_pointer(tuple(error.absolute_path))
    for field in missing:
        pointer = f"{parent}/{_escape_pointer_token(field)}"
        if not any(
            target == pointer or target.startswith(f"{pointer}/") for target in targets
        ):
            return False
    return True


def _pointer_present(document: Mapping[str, object], pointer: str) -> bool:
    current: object = document
    for token in _pointer_tokens(pointer):
        if not isinstance(current, Mapping) or token not in current:
            return False
        current = current[token]
    return True


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise DesiredOperationInputError(
            "composition target must be a non-root RFC 6901 pointer"
        )
    return tuple(
        token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")
    )


def _instance_pointer(path: tuple[object, ...]) -> str:
    if not path:
        return ""
    return "/" + "/".join(_escape_pointer_token(str(item)) for item in path)


def _escape_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


__all__ = ["DesiredOperationInputError", "validate_desired_operation_input"]
