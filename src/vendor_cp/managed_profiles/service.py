"""Owner of immutable, content-addressed managed-service profile versions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import cast
from uuid import UUID

from dotmac_kernel import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    write_platform_audit_event,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.managed_profiles import catalogues
from vendor_cp.managed_profiles.catalogues import ConfigurationFieldSpec
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion

_CONTENT_SCHEMA = "vendor.managed-service-profile@v1"
_UPDATE_AUTHORITIES = frozenset({"vendor_automatic", "customer_approved", "offline"})
_CODE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,118}[a-z0-9])?$")
_CONTENT_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")

JsonScalar = str | int | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class CompatiblePredecessor:
    commercial_product_code: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class EndpointContract:
    endpoint_code: str
    version: int


@dataclass(frozen=True, slots=True)
class CapabilityContract:
    capability_code: str
    version: int
    endpoints: tuple[EndpointContract, ...]


@dataclass(frozen=True, slots=True)
class ComponentContract:
    component_code: str
    required: bool
    depends_on: tuple[str, ...]
    capabilities: tuple[CapabilityContract, ...]


@dataclass(frozen=True, slots=True)
class VerificationCheckContract:
    check_code: str
    version: int
    gate: str
    component_code: str | None


@dataclass(frozen=True, slots=True)
class PublishProfileVersionCommand:
    commercial_product_code: str
    profile_code: str
    version: int
    schema_version: int
    update_authority: str
    compatible_predecessors: tuple[CompatiblePredecessor, ...] = ()
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class BuiltProfileVersion:
    commercial_product_code: str
    profile_code: str
    version: int
    schema_version: int
    content_hash: str
    update_authority: str
    allowed_optional_components: tuple[str, ...]
    components: tuple[ComponentContract, ...]
    configuration_fields: tuple[ConfigurationFieldSpec, ...]
    verification_checks: tuple[VerificationCheckContract, ...]
    compatible_predecessors: tuple[CompatiblePredecessor, ...]
    document: dict[str, JsonValue]

    @property
    def component_codes(self) -> tuple[str, ...]:
        return tuple(component.component_code for component in self.components)


@dataclass(frozen=True, slots=True)
class ManagedServiceProfileVersionView:
    id: UUID
    commercial_product_code: str
    profile_code: str
    version: int
    schema_version: int
    content_hash: str
    update_authority: str
    allowed_optional_components: tuple[str, ...]
    components: tuple[ComponentContract, ...]
    configuration_fields: tuple[ConfigurationFieldSpec, ...]
    verification_checks: tuple[VerificationCheckContract, ...]
    compatible_predecessors: tuple[CompatiblePredecessor, ...]
    document: dict[str, JsonValue]

    @property
    def component_codes(self) -> tuple[str, ...]:
        return tuple(component.component_code for component in self.components)


def build_profile_version(command: PublishProfileVersionCommand) -> BuiltProfileVersion:
    """Validate and canonicalise one prospective immutable profile version."""

    _validate_identity(command)
    product = _product(command.commercial_product_code)
    required_component_codes = catalogues.resolve_components(
        commercial_product_code=command.commercial_product_code,
        selected_optional_components=(),
    )
    allowed_optional = tuple(sorted(product.optional_component_codes))
    component_codes = catalogues.resolve_components(
        commercial_product_code=command.commercial_product_code,
        selected_optional_components=allowed_optional,
    )
    components = tuple(
        _component_contract(
            component_code=component_code,
            required=component_code in required_component_codes,
        )
        for component_code in component_codes
    )
    # The explicit own-product check is intentionally repeated at the document
    # boundary: a future catalogue refactor must not make a non-suite profile
    # publishable without its commercial product's component.
    if command.commercial_product_code != "managed-suite" and not set(
        product.required_component_codes
    ).issubset(component_codes):
        raise BadRequestError(
            f"{command.commercial_product_code!r} profile lacks its own component"
        )

    configuration_fields = catalogues.selected_configuration_fields(
        component_codes=component_codes
    )
    checks = tuple(
        VerificationCheckContract(
            check_code=check.check_code,
            version=check.version,
            gate=check.gate,
            component_code=check.component_code,
        )
        for check in catalogues.selected_verification_checks(
            component_codes=component_codes
        )
    )
    predecessors = _canonical_predecessors(command.compatible_predecessors)
    document = _document(
        command=command,
        allowed_optional=allowed_optional,
        components=components,
        configuration_fields=configuration_fields,
        checks=checks,
        predecessors=predecessors,
    )
    content_hash = "sha256:" + hashlib.sha256(_canonical(document)).hexdigest()
    return BuiltProfileVersion(
        commercial_product_code=command.commercial_product_code,
        profile_code=command.profile_code,
        version=command.version,
        schema_version=command.schema_version,
        content_hash=content_hash,
        update_authority=command.update_authority,
        allowed_optional_components=allowed_optional,
        components=components,
        configuration_fields=configuration_fields,
        verification_checks=checks,
        compatible_predecessors=predecessors,
        document=document,
    )


def publish_profile_version(
    db: Session, command: PublishProfileVersionCommand
) -> ManagedServiceProfileVersionView:
    """Publish once; versions and their content are never edited or deleted."""

    built = build_profile_version(command)
    existing = get_profile_version(
        db,
        commercial_product_code=built.commercial_product_code,
        profile_code=built.profile_code,
        version=built.version,
    )
    if existing is not None:
        raise ConflictError(
            f"managed profile {built.commercial_product_code!r}/"
            f"{built.profile_code!r} v{built.version} already exists"
        )
    _verify_predecessors(db, built.compatible_predecessors)
    row = ManagedServiceProfileVersion(
        commercial_product_code=built.commercial_product_code,
        profile_code=built.profile_code,
        version=built.version,
        schema_version=built.schema_version,
        content_hash=built.content_hash,
        document=cast(dict[str, object], built.document),
    )
    # Keep the nested-transaction import local: importing dotmac_kernel.db at
    # package import time constructs its configured engine, which would make a
    # wheel import require a DATABASE_URL.
    from dotmac_kernel.db import conflict_savepoint

    try:
        with conflict_savepoint(db):
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise ConflictError(
            "managed profile version or content hash was published concurrently"
        ) from exc
    write_platform_audit_event(
        db,
        actor_admin_id=command.actor_admin_id,
        action="vendor.managed_profile.published",
        entity_type="managed_service_profile_version",
        entity_id=str(row.id),
        details={
            "commercial_product_code": row.commercial_product_code,
            "profile_code": row.profile_code,
            "version": row.version,
            "content_hash": row.content_hash,
        },
    )
    return _view(row)


def get_profile_version(
    db: Session,
    *,
    commercial_product_code: str,
    profile_code: str,
    version: int,
) -> ManagedServiceProfileVersionView | None:
    row = db.execute(
        select(ManagedServiceProfileVersion).where(
            ManagedServiceProfileVersion.commercial_product_code
            == commercial_product_code,
            ManagedServiceProfileVersion.profile_code == profile_code,
            ManagedServiceProfileVersion.version == version,
        )
    ).scalar_one_or_none()
    return _view(row) if row is not None else None


def require_profile_content_hash(
    db: Session, *, commercial_product_code: str, content_hash: str
) -> ManagedServiceProfileVersionView:
    """Resolve an exact product/hash pair; never treat a hash alone as identity."""

    row = db.execute(
        select(ManagedServiceProfileVersion).where(
            ManagedServiceProfileVersion.commercial_product_code
            == commercial_product_code,
            ManagedServiceProfileVersion.content_hash == content_hash,
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(
            "no exact predecessor managed profile exists for "
            f"{commercial_product_code!r}/{content_hash!r}"
        )
    return _view(row)


def _validate_identity(command: PublishProfileVersionCommand) -> None:
    if _CODE.fullmatch(command.profile_code) is None:
        raise BadRequestError("profile code must be a canonical lower-case code")
    if command.version < 1:
        raise BadRequestError("profile version must be positive")
    if command.schema_version < 1:
        raise BadRequestError("profile schema version must be positive")
    if command.update_authority not in _UPDATE_AUTHORITIES:
        raise BadRequestError(
            "update authority must be vendor_automatic, customer_approved, or offline"
        )


def _product(commercial_product_code: str) -> catalogues.ProductSpec:
    try:
        return catalogues.require_product(commercial_product_code)
    except KeyError as exc:
        raise BadRequestError(str(exc)) from None


def _component_contract(*, component_code: str, required: bool) -> ComponentContract:
    component = catalogues.require_component(component_code)
    capabilities = tuple(
        CapabilityContract(
            capability_code=capability.capability_code,
            version=capability.version,
            endpoints=tuple(
                EndpointContract(endpoint.endpoint_code, endpoint.version)
                for endpoint in capability.endpoints
            ),
        )
        for capability in (
            catalogues.require_capability(code) for code in component.capabilities
        )
    )
    return ComponentContract(
        component_code=component_code,
        required=required,
        depends_on=component.depends_on,
        capabilities=capabilities,
    )


def _canonical_predecessors(
    predecessors: tuple[CompatiblePredecessor, ...],
) -> tuple[CompatiblePredecessor, ...]:
    seen: set[tuple[str, str]] = set()
    result: list[CompatiblePredecessor] = []
    for predecessor in sorted(
        predecessors,
        key=lambda item: (item.commercial_product_code, item.content_hash),
    ):
        _product(predecessor.commercial_product_code)
        if _CONTENT_HASH.fullmatch(predecessor.content_hash) is None:
            raise BadRequestError("compatible predecessor has an invalid content hash")
        identity = (
            predecessor.commercial_product_code,
            predecessor.content_hash,
        )
        if identity in seen:
            raise BadRequestError("compatible predecessor was supplied twice")
        seen.add(identity)
        result.append(predecessor)
    return tuple(result)


def _verify_predecessors(
    db: Session, predecessors: tuple[CompatiblePredecessor, ...]
) -> None:
    for predecessor in predecessors:
        require_profile_content_hash(
            db,
            commercial_product_code=predecessor.commercial_product_code,
            content_hash=predecessor.content_hash,
        )


def _document(
    *,
    command: PublishProfileVersionCommand,
    allowed_optional: tuple[str, ...],
    components: tuple[ComponentContract, ...],
    configuration_fields: tuple[ConfigurationFieldSpec, ...],
    checks: tuple[VerificationCheckContract, ...],
    predecessors: tuple[CompatiblePredecessor, ...],
) -> dict[str, JsonValue]:
    return {
        "content_schema": _CONTENT_SCHEMA,
        "schema_version": command.schema_version,
        "commercial_product_code": command.commercial_product_code,
        "profile_code": command.profile_code,
        "version": command.version,
        "update_authority": command.update_authority,
        "allowed_optional_components": list(allowed_optional),
        "components": [
            {
                "component_code": component.component_code,
                "required": component.required,
                "depends_on": list(component.depends_on),
                "capabilities": [
                    {
                        "capability_code": capability.capability_code,
                        "version": capability.version,
                        "endpoints": [
                            {
                                "endpoint_code": endpoint.endpoint_code,
                                "version": endpoint.version,
                            }
                            for endpoint in capability.endpoints
                        ],
                    }
                    for capability in component.capabilities
                ],
            }
            for component in components
        ],
        "configuration_fields": [
            {
                "field_code": field.field_code,
                "value_type": field.value_type,
                "required": field.required,
                "component_code": field.component_code,
                "capability_code": field.capability_code,
            }
            for field in configuration_fields
        ],
        "verification_checks": [
            {
                "check_code": check.check_code,
                "version": check.version,
                "gate": check.gate,
                "component_code": check.component_code,
            }
            for check in checks
        ],
        "compatible_predecessors": [
            {
                "commercial_product_code": predecessor.commercial_product_code,
                "content_hash": predecessor.content_hash,
            }
            for predecessor in predecessors
        ],
    }


def _canonical(document: dict[str, JsonValue]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _view(row: ManagedServiceProfileVersion) -> ManagedServiceProfileVersionView:
    document = cast(dict[str, JsonValue], row.document)
    try:
        update_authority = cast(str, document["update_authority"])
        allowed_optional = tuple(
            cast(list[str], document["allowed_optional_components"])
        )
        components = _components_from_document(
            cast(list[dict[str, JsonValue]], document["components"])
        )
        fields = _fields_from_document(
            cast(list[dict[str, JsonValue]], document["configuration_fields"])
        )
        checks = _checks_from_document(
            cast(list[dict[str, JsonValue]], document["verification_checks"])
        )
        predecessors = _predecessors_from_document(
            cast(list[dict[str, JsonValue]], document["compatible_predecessors"])
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConflictError(
            f"managed profile {row.id} contains an invalid immutable document"
        ) from exc
    if "sha256:" + hashlib.sha256(_canonical(document)).hexdigest() != row.content_hash:
        raise ConflictError(f"managed profile {row.id} content hash does not match")
    return ManagedServiceProfileVersionView(
        id=row.id,
        commercial_product_code=row.commercial_product_code,
        profile_code=row.profile_code,
        version=row.version,
        schema_version=row.schema_version,
        content_hash=row.content_hash,
        update_authority=update_authority,
        allowed_optional_components=allowed_optional,
        components=components,
        configuration_fields=fields,
        verification_checks=checks,
        compatible_predecessors=predecessors,
        document=document,
    )


def _components_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[ComponentContract, ...]:
    return tuple(
        ComponentContract(
            component_code=cast(str, item["component_code"]),
            required=cast(bool, item["required"]),
            depends_on=tuple(cast(list[str], item["depends_on"])),
            capabilities=tuple(
                CapabilityContract(
                    capability_code=cast(str, capability["capability_code"]),
                    version=cast(int, capability["version"]),
                    endpoints=tuple(
                        EndpointContract(
                            endpoint_code=cast(str, endpoint["endpoint_code"]),
                            version=cast(int, endpoint["version"]),
                        )
                        for endpoint in cast(
                            list[dict[str, JsonValue]], capability["endpoints"]
                        )
                    ),
                )
                for capability in cast(list[dict[str, JsonValue]], item["capabilities"])
            ),
        )
        for item in items
    )


def _fields_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[ConfigurationFieldSpec, ...]:
    return tuple(
        ConfigurationFieldSpec(
            field_code=cast(str, item["field_code"]),
            value_type=cast(catalogues.ConfigurationValueType, item["value_type"]),
            required=cast(bool, item["required"]),
            component_code=cast(str | None, item["component_code"]),
            capability_code=cast(str | None, item["capability_code"]),
        )
        for item in items
    )


def _checks_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[VerificationCheckContract, ...]:
    return tuple(
        VerificationCheckContract(
            check_code=cast(str, item["check_code"]),
            version=cast(int, item["version"]),
            gate=cast(str, item["gate"]),
            component_code=cast(str | None, item["component_code"]),
        )
        for item in items
    )


def _predecessors_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[CompatiblePredecessor, ...]:
    return tuple(
        CompatiblePredecessor(
            commercial_product_code=cast(str, item["commercial_product_code"]),
            content_hash=cast(str, item["content_hash"]),
        )
        for item in items
    )


__all__ = [
    "BuiltProfileVersion",
    "CapabilityContract",
    "CompatiblePredecessor",
    "ComponentContract",
    "EndpointContract",
    "ManagedServiceProfileVersionView",
    "PublishProfileVersionCommand",
    "VerificationCheckContract",
    "build_profile_version",
    "get_profile_version",
    "publish_profile_version",
    "require_profile_content_hash",
]
