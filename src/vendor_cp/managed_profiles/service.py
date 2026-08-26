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
    CapabilityCheck,
    CapabilityConfigField,
    CapabilityContractError,
    CapabilityContractSnapshot,
    CapabilityEndpointRequirement,
    CapabilityEvidenceBinding,
    CapabilityOperation,
    CapabilitySchemaDocument,
    ConflictError,
    NotFoundError,
    write_platform_audit_event,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.managed_profiles import catalogues
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractEvidence,
    CapabilityContractRegistry,
)
from vendor_cp.managed_profiles.composition_contracts import (
    CapabilityCompositionEvidence,
    CapabilityCompositionRegistry,
)
from vendor_cp.managed_profiles.instance_refs import is_capability_instance_ref
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
class CapabilityContract:
    capability_instance_ref: str
    capability_id: str
    artifact_id: UUID
    artifact_digest: str
    product_manifest_attestation_id: UUID
    product_manifest_digest: str
    contract_attestation_id: UUID
    contract_attestation_digest: str
    contract_ref: str
    snapshot: CapabilityContractSnapshot
    schemas: tuple[CapabilitySchemaContract, ...]

    @property
    def owner_code(self) -> str:
        return self.snapshot.owner_code

    @property
    def capability_code(self) -> str:
        return self.snapshot.capability_code

    @property
    def schema_version(self) -> int:
        return self.snapshot.schema_version

    @property
    def content_hash(self) -> str:
        return self.contract_attestation_digest

    @property
    def operations(self) -> tuple[CapabilityOperation, ...]:
        return self.snapshot.operations

    @property
    def config_fields(self) -> tuple[CapabilityConfigField, ...]:
        return self.snapshot.config_fields

    @property
    def endpoint_requirements(self) -> tuple[CapabilityEndpointRequirement, ...]:
        return self.snapshot.endpoint_requirements

    @property
    def checks(self) -> tuple[CapabilityCheck, ...]:
        return self.snapshot.checks


@dataclass(frozen=True, slots=True)
class ComponentContract:
    component_code: str
    required: bool
    depends_on: tuple[str, ...]
    capabilities: tuple[CapabilityContract, ...]


@dataclass(frozen=True, slots=True)
class CapabilitySchemaContract:
    schema_ref: str
    schema_digest: str
    attestation_id: UUID
    document_ref: str
    document: CapabilitySchemaDocument


@dataclass(frozen=True, slots=True)
class ConfigurationFieldContract:
    capability_instance_ref: str
    capability_id: str
    field_code: str
    value_type: str
    value_format: str
    required: bool


@dataclass(frozen=True, slots=True)
class VerificationCheckContract:
    capability_instance_ref: str
    capability_id: str
    check_code: str
    stage: str
    evidence_type: str
    required: bool


@dataclass(frozen=True, slots=True)
class PrerequisiteEvidenceBindingContract:
    binding_code: str
    source_capability_id: str
    source_pointer: str
    source_schema_ref: str
    source_schema_digest: str
    target_capability_id: str
    target_pointer: str
    target_schema_ref: str
    target_schema_digest: str
    source_selector_pointer: str | None
    source_selector_value: str | None
    target_selector_pointer: str | None
    target_selector_value: str | None
    coverage: str
    required: bool
    composition_contract_ref: str
    composition_contract_digest: str
    composition_contract_attestation_id: UUID


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
    configuration_fields: tuple[ConfigurationFieldContract, ...]
    verification_checks: tuple[VerificationCheckContract, ...]
    prerequisite_evidence_bindings: tuple[PrerequisiteEvidenceBindingContract, ...]
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
    configuration_fields: tuple[ConfigurationFieldContract, ...]
    verification_checks: tuple[VerificationCheckContract, ...]
    prerequisite_evidence_bindings: tuple[PrerequisiteEvidenceBindingContract, ...]
    compatible_predecessors: tuple[CompatiblePredecessor, ...]
    document: dict[str, JsonValue]

    @property
    def component_codes(self) -> tuple[str, ...]:
        return tuple(component.component_code for component in self.components)


def build_profile_version(
    command: PublishProfileVersionCommand,
    *,
    capability_registry: CapabilityContractRegistry,
    composition_registry: CapabilityCompositionRegistry,
) -> BuiltProfileVersion:
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
            capability_registry=capability_registry,
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

    capability_contracts = _unique_capability_contracts(components)
    configuration_fields = _configuration_fields(capability_contracts)
    checks = _verification_checks(capability_contracts)
    evidence_bindings = _composition_bindings(
        commercial_product_code=command.commercial_product_code,
        components=components,
        contracts=capability_contracts,
        composition_registry=composition_registry,
    )
    predecessors = _canonical_predecessors(command.compatible_predecessors)
    document = _document(
        command=command,
        allowed_optional=allowed_optional,
        components=components,
        configuration_fields=configuration_fields,
        checks=checks,
        evidence_bindings=evidence_bindings,
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
        prerequisite_evidence_bindings=evidence_bindings,
        compatible_predecessors=predecessors,
        document=document,
    )


def publish_profile_version(
    db: Session,
    command: PublishProfileVersionCommand,
    *,
    capability_registry: CapabilityContractRegistry,
    composition_registry: CapabilityCompositionRegistry,
) -> ManagedServiceProfileVersionView:
    """Publish once; versions and their content are never edited or deleted."""

    built = build_profile_version(
        command,
        capability_registry=capability_registry,
        composition_registry=composition_registry,
    )
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


def _component_contract(
    *,
    component_code: str,
    required: bool,
    capability_registry: CapabilityContractRegistry,
) -> ComponentContract:
    component = catalogues.require_component(component_code)
    requirements = component.capability_requirements
    evidence = tuple(
        capability_registry.require(requirement.capability_id)
        for requirement in requirements
    )
    for requirement, item in zip(requirements, evidence, strict=True):
        if item.capability_id != requirement.capability_id:
            raise BadRequestError(
                "capability registry returned evidence for a different capability"
            )
    capabilities = tuple(
        _capability_contract(
            item, capability_instance_ref=requirement.capability_instance_ref
        )
        for requirement, item in zip(requirements, evidence, strict=True)
    )
    return ComponentContract(
        component_code=component_code,
        required=required,
        depends_on=component.depends_on,
        capabilities=capabilities,
    )


def _capability_contract(
    evidence: CapabilityContractEvidence, *, capability_instance_ref: str
) -> CapabilityContract:
    if not is_capability_instance_ref(capability_instance_ref):
        raise BadRequestError("capability instance reference is not canonical")
    try:
        return CapabilityContract(
            capability_instance_ref=capability_instance_ref,
            capability_id=evidence.capability_id,
            artifact_id=evidence.artifact_id,
            artifact_digest=evidence.artifact_digest,
            product_manifest_attestation_id=(evidence.product_manifest_attestation_id),
            product_manifest_digest=evidence.product_manifest_digest,
            contract_attestation_id=evidence.contract_attestation_id,
            contract_attestation_digest=evidence.contract_attestation_digest,
            contract_ref=evidence.contract_ref,
            snapshot=evidence.snapshot,
            schemas=tuple(
                CapabilitySchemaContract(
                    schema_ref=schema.schema_ref,
                    schema_digest=schema.schema_digest,
                    attestation_id=schema.attestation_id,
                    document_ref=schema.document_ref,
                    document=schema.document,
                )
                for schema in evidence.schemas
            ),
        )
    except (ValueError, CapabilityContractError) as exc:
        raise BadRequestError("capability registry returned invalid evidence") from exc


def _unique_capability_contracts(
    components: tuple[ComponentContract, ...],
) -> tuple[CapabilityContract, ...]:
    contracts: dict[str, CapabilityContract] = {}
    for component in components:
        for capability in component.capabilities:
            prior = contracts.get(capability.capability_instance_ref)
            if prior is not None and prior != capability:
                raise BadRequestError(
                    "capability instance "
                    f"{capability.capability_instance_ref!r} has conflicting evidence"
                )
            contracts[capability.capability_instance_ref] = capability
    return tuple(contracts[instance_ref] for instance_ref in sorted(contracts))


def _configuration_fields(
    contracts: tuple[CapabilityContract, ...],
) -> tuple[ConfigurationFieldContract, ...]:
    fields: dict[tuple[str, str], ConfigurationFieldContract] = {}
    for contract in contracts:
        for field in contract.config_fields:
            identity = (contract.capability_instance_ref, field.field_code)
            fields[identity] = ConfigurationFieldContract(
                capability_instance_ref=contract.capability_instance_ref,
                capability_id=contract.capability_id,
                field_code=field.field_code,
                value_type=field.value_type.value,
                value_format=field.value_format.value,
                required=field.required,
            )
    return tuple(fields[identity] for identity in sorted(fields))


def _verification_checks(
    contracts: tuple[CapabilityContract, ...],
) -> tuple[VerificationCheckContract, ...]:
    checks: dict[tuple[str, str], VerificationCheckContract] = {}
    for contract in contracts:
        for check in contract.checks:
            identity = (contract.capability_instance_ref, check.check_code)
            checks[identity] = VerificationCheckContract(
                capability_instance_ref=contract.capability_instance_ref,
                capability_id=contract.capability_id,
                check_code=check.check_code,
                stage=check.stage.value,
                evidence_type=check.evidence_type.value,
                required=check.required,
            )
    return tuple(checks[identity] for identity in sorted(checks))


def _composition_bindings(
    *,
    commercial_product_code: str,
    components: tuple[ComponentContract, ...],
    contracts: tuple[CapabilityContract, ...],
    composition_registry: CapabilityCompositionRegistry,
) -> tuple[PrerequisiteEvidenceBindingContract, ...]:
    dependency_edges = {
        (dependency, component.component_code)
        for component in components
        for dependency in component.depends_on
    }
    contracts_by_id: dict[str, list[CapabilityContract]] = {}
    components_by_capability_id: dict[str, set[str]] = {}
    for component in components:
        for contract in component.capabilities:
            contracts_by_id.setdefault(contract.capability_id, []).append(contract)
            components_by_capability_id.setdefault(contract.capability_id, set()).add(
                component.component_code
            )
    evidences = composition_registry.require(
        commercial_product_code=commercial_product_code,
        capability_ids=tuple(sorted(contracts_by_id)),
    )
    resolved_items: list[PrerequisiteEvidenceBindingContract] = []
    for evidence in evidences:
        for definition in evidence.snapshot.evidence_bindings:
            source_id = _composition_capability_id(
                definition.source_capability_code,
                definition.source_capability_schema_version,
            )
            target_id = _composition_capability_id(
                definition.target_capability_code,
                definition.target_capability_schema_version,
            )
            sources = contracts_by_id.get(source_id, [])
            targets = contracts_by_id.get(target_id, [])
            if not sources or not targets:
                continue
            resolved_items.append(
                _resolve_composition_binding(
                    definition,
                    evidence=evidence,
                    source=sources[0],
                    target=targets[0],
                )
            )
    resolved = tuple(sorted(resolved_items, key=_evidence_binding_key))
    if len(set(resolved)) != len(resolved):
        raise BadRequestError(
            "composition contract contains duplicate evidence mappings"
        )
    if resolved != tuple(sorted(resolved, key=_evidence_binding_key)):
        raise BadRequestError("composition evidence mappings are not canonical")
    mapped_edges = {
        (source_component, target_component)
        for item in resolved
        for source_component in components_by_capability_id[item.source_capability_id]
        for target_component in components_by_capability_id[item.target_capability_id]
        if source_component == target_component
        or (source_component, target_component) in dependency_edges
    }
    missing_edges = dependency_edges - mapped_edges
    if missing_edges:
        raise BadRequestError(
            "composition evidence does not cover component dependency edges: "
            + ", ".join(
                f"{source}->{target}" for source, target in sorted(missing_edges)
            )
        )
    return resolved


def _resolve_composition_binding(
    definition: CapabilityEvidenceBinding,
    *,
    evidence: CapabilityCompositionEvidence,
    source: CapabilityContract,
    target: CapabilityContract,
) -> PrerequisiteEvidenceBindingContract:
    source_id = _composition_capability_id(
        definition.source_capability_code,
        definition.source_capability_schema_version,
    )
    target_id = _composition_capability_id(
        definition.target_capability_code,
        definition.target_capability_schema_version,
    )
    if source.capability_id != source_id or target.capability_id != target_id:
        raise BadRequestError(
            "composition mapping names a capability outside the profile"
        )
    if source.owner_code != definition.source_owner_code or target.owner_code != (
        definition.target_owner_code
    ):
        raise BadRequestError("composition mapping owner differs from held contract")
    try:
        source_operation = source.snapshot.require_operation(
            definition.source_operation_code
        )
        target_operation = target.snapshot.require_operation(
            definition.target_operation_code
        )
    except CapabilityContractError as exc:
        raise BadRequestError(
            "composition mapping names an undeclared operation"
        ) from exc
    if (
        source_operation.output_schema_ref != definition.source_output_schema_ref
        or source_operation.output_schema_digest
        != definition.source_output_schema_digest
        or target_operation.input_schema_ref != definition.target_input_schema_ref
        or target_operation.input_schema_digest != definition.target_input_schema_digest
    ):
        raise BadRequestError("composition schema pins differ from held operations")
    source_schema = _profile_schema(
        source,
        schema_ref=definition.source_output_schema_ref,
        schema_digest=definition.source_output_schema_digest,
    )
    target_schema = _profile_schema(
        target,
        schema_ref=definition.target_input_schema_ref,
        schema_digest=definition.target_input_schema_digest,
    )
    try:
        source_shape = source_schema.document.require_public_non_secret_pointer(
            definition.source_pointer
        )
        # Only facts LEAVING the source capability must be explicitly public and
        # non-secret.  The target is desired input, not exported evidence; it only
        # has to be an exact declared path in the held apply-input schema.
        target_shape = target_schema.document.require_instance_pointer(
            definition.target_pointer
        )
    except CapabilityContractError as exc:
        raise BadRequestError(
            "composition source is not public evidence or a mapped path is absent"
        ) from exc
    if source_shape.get("type") != target_shape.get("type") or source_shape.get(
        "format"
    ) != target_shape.get("format"):
        raise BadRequestError("composition source and target schema shapes differ")
    return PrerequisiteEvidenceBindingContract(
        binding_code=definition.binding_code,
        source_capability_id=source_id,
        source_pointer=definition.source_pointer,
        source_schema_ref=definition.source_output_schema_ref,
        source_schema_digest=definition.source_output_schema_digest,
        target_capability_id=target_id,
        target_pointer=definition.target_pointer,
        target_schema_ref=definition.target_input_schema_ref,
        target_schema_digest=definition.target_input_schema_digest,
        source_selector_pointer=definition.source_selector_pointer,
        source_selector_value=definition.source_selector_value,
        target_selector_pointer=definition.target_selector_pointer,
        target_selector_value=definition.target_selector_value,
        coverage=definition.coverage,
        required=definition.required,
        composition_contract_ref=evidence.contract_ref,
        composition_contract_digest=evidence.contract_digest,
        composition_contract_attestation_id=evidence.contract_attestation_id,
    )


def _composition_capability_id(capability_code: str, schema_version: int) -> str:
    return f"{capability_code}.v{schema_version}"


def _profile_schema(
    contract: CapabilityContract, *, schema_ref: str, schema_digest: str
) -> CapabilitySchemaContract:
    matches = tuple(
        item
        for item in contract.schemas
        if item.schema_ref == schema_ref and item.schema_digest == schema_digest
    )
    if len(matches) != 1:
        raise BadRequestError(
            "composition schema lacks exact held attestation evidence"
        )
    return matches[0]


def _evidence_binding_key(
    item: PrerequisiteEvidenceBindingContract,
) -> tuple[object, ...]:
    return (
        item.composition_contract_digest,
        item.binding_code,
        item.target_capability_id,
        item.target_pointer,
        item.source_capability_id,
        item.source_pointer,
        item.required,
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
    configuration_fields: tuple[ConfigurationFieldContract, ...],
    checks: tuple[VerificationCheckContract, ...],
    evidence_bindings: tuple[PrerequisiteEvidenceBindingContract, ...],
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
                        "capability_instance_ref": (capability.capability_instance_ref),
                        "capability_id": capability.capability_id,
                        "artifact_id": str(capability.artifact_id),
                        "artifact_digest": capability.artifact_digest,
                        "product_manifest_attestation_id": str(
                            capability.product_manifest_attestation_id
                        ),
                        "product_manifest_digest": (capability.product_manifest_digest),
                        "contract_attestation_id": str(
                            capability.contract_attestation_id
                        ),
                        "contract_attestation_digest": (
                            capability.contract_attestation_digest
                        ),
                        "contract_ref": capability.contract_ref,
                        "contract": cast(
                            dict[str, JsonValue],
                            json.loads(capability.snapshot.to_json_bytes()),
                        ),
                        "schemas": [
                            {
                                "schema_ref": schema.schema_ref,
                                "schema_digest": schema.schema_digest,
                                "attestation_id": str(schema.attestation_id),
                                "document_ref": schema.document_ref,
                                "document": cast(
                                    dict[str, JsonValue],
                                    json.loads(schema.document.to_json_bytes()),
                                ),
                            }
                            for schema in capability.schemas
                        ],
                    }
                    for capability in component.capabilities
                ],
            }
            for component in components
        ],
        "configuration_fields": [
            {
                "capability_instance_ref": field.capability_instance_ref,
                "field_code": field.field_code,
                "value_type": field.value_type,
                "value_format": field.value_format,
                "required": field.required,
                "capability_id": field.capability_id,
            }
            for field in configuration_fields
        ],
        "verification_checks": [
            {
                "capability_instance_ref": check.capability_instance_ref,
                "capability_id": check.capability_id,
                "check_code": check.check_code,
                "stage": check.stage,
                "evidence_type": check.evidence_type,
                "required": check.required,
            }
            for check in checks
        ],
        "prerequisite_evidence_bindings": [
            {
                "binding_code": item.binding_code,
                "source_capability_id": item.source_capability_id,
                "source_pointer": item.source_pointer,
                "source_schema_ref": item.source_schema_ref,
                "source_schema_digest": item.source_schema_digest,
                "target_capability_id": item.target_capability_id,
                "target_pointer": item.target_pointer,
                "target_schema_ref": item.target_schema_ref,
                "target_schema_digest": item.target_schema_digest,
                "source_selector_pointer": item.source_selector_pointer,
                "source_selector_value": item.source_selector_value,
                "target_selector_pointer": item.target_selector_pointer,
                "target_selector_value": item.target_selector_value,
                "coverage": item.coverage,
                "required": item.required,
                "composition_contract_ref": item.composition_contract_ref,
                "composition_contract_digest": item.composition_contract_digest,
                "composition_contract_attestation_id": str(
                    item.composition_contract_attestation_id
                ),
            }
            for item in evidence_bindings
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
        evidence_bindings = _evidence_bindings_from_document(
            cast(
                list[dict[str, JsonValue]],
                document["prerequisite_evidence_bindings"],
            )
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
        prerequisite_evidence_bindings=evidence_bindings,
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
                _capability_from_document(capability)
                for capability in cast(list[dict[str, JsonValue]], item["capabilities"])
            ),
        )
        for item in items
    )


def _capability_from_document(
    item: dict[str, JsonValue],
) -> CapabilityContract:
    capability_instance_ref = cast(str, item["capability_instance_ref"])
    if not is_capability_instance_ref(capability_instance_ref):
        raise BadRequestError("capability instance reference is not canonical")
    contract_document = cast(dict[str, JsonValue], item["contract"])
    contract_digest = cast(str, item["contract_attestation_digest"])
    payload = json.dumps(
        contract_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    snapshot = CapabilityContractSnapshot.from_json_bytes(
        payload, expected_digest=contract_digest
    )
    schemas = tuple(
        _schema_from_document(schema)
        for schema in cast(list[dict[str, JsonValue]], item["schemas"])
    )
    return CapabilityContract(
        capability_instance_ref=capability_instance_ref,
        capability_id=cast(str, item["capability_id"]),
        artifact_id=UUID(cast(str, item["artifact_id"])),
        artifact_digest=cast(str, item["artifact_digest"]),
        product_manifest_attestation_id=UUID(
            cast(str, item["product_manifest_attestation_id"])
        ),
        product_manifest_digest=cast(str, item["product_manifest_digest"]),
        contract_attestation_id=UUID(cast(str, item["contract_attestation_id"])),
        contract_attestation_digest=contract_digest,
        contract_ref=cast(str, item["contract_ref"]),
        snapshot=snapshot,
        schemas=schemas,
    )


def _schema_from_document(item: dict[str, JsonValue]) -> CapabilitySchemaContract:
    schema_document = cast(dict[str, object], item["document"])
    payload = json.dumps(
        schema_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    schema_ref = cast(str, item["schema_ref"])
    schema_digest = cast(str, item["schema_digest"])
    document = CapabilitySchemaDocument.from_json_bytes(
        payload,
        expected_ref=schema_ref,
        expected_digest=schema_digest,
    )
    return CapabilitySchemaContract(
        schema_ref=schema_ref,
        schema_digest=schema_digest,
        attestation_id=UUID(cast(str, item["attestation_id"])),
        document_ref=cast(str, item["document_ref"]),
        document=document,
    )


def _fields_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[ConfigurationFieldContract, ...]:
    return tuple(
        ConfigurationFieldContract(
            capability_instance_ref=cast(str, item["capability_instance_ref"]),
            capability_id=cast(str, item["capability_id"]),
            field_code=cast(str, item["field_code"]),
            value_type=cast(str, item["value_type"]),
            value_format=cast(str, item["value_format"]),
            required=cast(bool, item["required"]),
        )
        for item in items
    )


def _checks_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[VerificationCheckContract, ...]:
    return tuple(
        VerificationCheckContract(
            capability_instance_ref=cast(str, item["capability_instance_ref"]),
            capability_id=cast(str, item["capability_id"]),
            check_code=cast(str, item["check_code"]),
            stage=cast(str, item["stage"]),
            evidence_type=cast(str, item["evidence_type"]),
            required=cast(bool, item["required"]),
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


def _evidence_bindings_from_document(
    items: list[dict[str, JsonValue]],
) -> tuple[PrerequisiteEvidenceBindingContract, ...]:
    return tuple(
        PrerequisiteEvidenceBindingContract(
            binding_code=cast(str, item["binding_code"]),
            source_capability_id=cast(str, item["source_capability_id"]),
            source_pointer=cast(str, item["source_pointer"]),
            source_schema_ref=cast(str, item["source_schema_ref"]),
            source_schema_digest=cast(str, item["source_schema_digest"]),
            target_capability_id=cast(str, item["target_capability_id"]),
            target_pointer=cast(str, item["target_pointer"]),
            target_schema_ref=cast(str, item["target_schema_ref"]),
            target_schema_digest=cast(str, item["target_schema_digest"]),
            source_selector_pointer=cast(str | None, item["source_selector_pointer"]),
            source_selector_value=cast(str | None, item["source_selector_value"]),
            target_selector_pointer=cast(str | None, item["target_selector_pointer"]),
            target_selector_value=cast(str | None, item["target_selector_value"]),
            coverage=cast(str, item["coverage"]),
            required=cast(bool, item["required"]),
            composition_contract_ref=cast(str, item["composition_contract_ref"]),
            composition_contract_digest=cast(str, item["composition_contract_digest"]),
            composition_contract_attestation_id=UUID(
                cast(str, item["composition_contract_attestation_id"])
            ),
        )
        for item in items
    )


__all__ = [
    "BuiltProfileVersion",
    "CapabilityContract",
    "CapabilitySchemaContract",
    "ConfigurationFieldContract",
    "CompatiblePredecessor",
    "ComponentContract",
    "ManagedServiceProfileVersionView",
    "PublishProfileVersionCommand",
    "VerificationCheckContract",
    "build_profile_version",
    "get_profile_version",
    "publish_profile_version",
    "require_profile_content_hash",
]
