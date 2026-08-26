"""In-memory product-owned a69 contract evidence for Vendor tests only."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from uuid import NAMESPACE_URL, uuid5

from dotmac_kernel import (
    CAPABILITY_SCHEMA_DIALECT,
    CapabilityCheck,
    CapabilityCheckStage,
    CapabilityCompositionSnapshot,
    CapabilityConfigField,
    CapabilityConfigValueFormat,
    CapabilityConfigValueType,
    CapabilityContractSnapshot,
    CapabilityEndpointRequirement,
    CapabilityEndpointType,
    CapabilityEvidenceBinding,
    CapabilityEvidenceType,
    CapabilityOperation,
    CapabilitySchemaDocument,
    ConflictError,
)

from vendor_cp.managed_profiles import catalogues
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractEvidence,
    CapabilitySchemaEvidence,
)
from vendor_cp.managed_profiles.composition_contracts import (
    CapabilityCompositionEvidence,
)

HASH = "sha256:" + "a" * 64


def _owner(capability_id: str) -> str:
    return {
        "dns": "dotmac-domains",
        "host": "dotmac-hosting",
        "identity": "dotmac-kernel-identity",
        "business": "dotmac-erp",
        "email": "mail-service-owner",
        "collaboration": "collaboration-service-owner",
        "academy": "dotmac-academy",
        "workspace": "dotmac-workspace",
    }[capability_id.split(".", 1)[0]]


def _schema(owner: str, capability: str, operation: str, direction: str) -> str:
    path = f"{owner}/{capability.replace('.', '/')}/{operation}/{direction}"
    return f"schema:{path}@v1"


def _operation_material(
    owner: str, capability: str
) -> tuple[tuple[CapabilityOperation, ...], tuple[CapabilitySchemaEvidence, ...]]:
    operations: list[CapabilityOperation] = []
    schemas: list[CapabilitySchemaEvidence] = []
    for operation in ("apply", "cancel", "observe", "plan"):
        input_ref = _schema(owner, capability, operation, "input")
        output_ref = _schema(owner, capability, operation, "output")
        input_schema = _schema_document(input_ref)
        output_schema = _schema_document(output_ref)
        operations.append(
            CapabilityOperation(
                operation_code=operation,
                input_schema_ref=input_ref,
                input_schema_digest=input_schema.digest,
                output_schema_ref=output_ref,
                output_schema_digest=output_schema.digest,
            )
        )
        for schema in (input_schema, output_schema):
            schemas.append(
                CapabilitySchemaEvidence(
                    schema_ref=schema.schema_ref,
                    schema_digest=schema.digest,
                    attestation_id=uuid5(
                        NAMESPACE_URL, f"schema:{owner}:{schema.schema_ref}"
                    ),
                    document_ref=f"file:///held/{schema.digest[7:]}.json",
                    document=schema,
                )
            )
    return tuple(operations), tuple(sorted(schemas, key=lambda item: item.schema_ref))


def _schema_document(schema_ref: str) -> CapabilitySchemaDocument:
    is_output = "/output@" in schema_ref
    property_schema: dict[str, object] = {"type": "string"}
    if is_output:
        # A source value crosses the capability boundary as evidence and must be
        # explicitly public/non-secret.  A target input is declared desired state,
        # so classification is neither required nor inferred.
        property_schema["x-dotmac-data-classification"] = "public_non_secret"
    properties: dict[str, object] = {
        ("public_value" if is_output else "upstream_value"): property_schema
    }
    if not is_output and "/email/lifecycle/apply/input@" in schema_ref:
        properties["resource_kind"] = {
            "type": "string",
            "enum": [
                "alias",
                "app_password",
                "application",
                "delivery",
                "dkim",
                "domain",
                "mailbox",
                "quota",
            ],
        }
    return CapabilitySchemaDocument.from_mapping(
        {
            "$id": schema_ref,
            "$schema": CAPABILITY_SCHEMA_DIALECT,
            "additionalProperties": False,
            "properties": properties,
            "type": "object",
        }
    )


def _field(
    code: str,
    value_type: CapabilityConfigValueType,
    value_format: CapabilityConfigValueFormat = CapabilityConfigValueFormat.NONE,
) -> CapabilityConfigField:
    return CapabilityConfigField(code, value_type, value_format)


def _config(capability_id: str) -> tuple[CapabilityConfigField, ...]:
    fields: list[CapabilityConfigField] = []
    if capability_id == "dns.authoritative.v1":
        fields.append(
            _field(
                "customer_domain",
                CapabilityConfigValueType.STRING,
                CapabilityConfigValueFormat.FQDN,
            )
        )
    mapping = {
        "identity.realm.lifecycle.v1": "identity",
        "business.application.lifecycle.v1": "business",
        "email.lifecycle.v1": "email",
        "collaboration.application.lifecycle.v1": "collaboration",
        "academy.application.lifecycle.v1": "academy",
        "workspace.application.lifecycle.v1": "workspace",
    }
    prefix = mapping.get(capability_id)
    if prefix is not None:
        fields.extend(
            (
                _field(
                    f"{prefix}_endpoint",
                    CapabilityConfigValueType.STRING,
                    CapabilityConfigValueFormat.HTTPS_URL,
                ),
                _field(
                    f"{prefix}_admin_secret_ref",
                    CapabilityConfigValueType.SECRET_REFERENCE,
                ),
            )
        )
        if prefix != "workspace":
            fields.append(
                _field(
                    f"{prefix}_backup_policy_ref",
                    CapabilityConfigValueType.REFERENCE,
                )
            )
    if capability_id == "identity.realm.lifecycle.v1":
        fields.append(
            _field("identity_policy_ref", CapabilityConfigValueType.REFERENCE)
        )
    if capability_id == "email.lifecycle.v1":
        fields.append(
            _field(
                "email_domains",
                CapabilityConfigValueType.STRING_LIST,
                CapabilityConfigValueFormat.FQDN_LIST,
            )
        )
    return tuple(sorted(fields, key=lambda item: item.field_code))


def _checks(capability_id: str) -> tuple[CapabilityCheck, ...]:
    domain = capability_id.removesuffix(".v1").replace(".lifecycle", "")
    return (
        CapabilityCheck(
            check_code=f"{domain}.ready",
            stage=CapabilityCheckStage.ACTIVATION,
            evidence_type=CapabilityEvidenceType.BOOLEAN,
        ),
        CapabilityCheck(
            check_code=f"{domain}.evidence",
            stage=CapabilityCheckStage.EVIDENCE,
            evidence_type=CapabilityEvidenceType.DOCUMENT,
        ),
    )


def _evidence(capability_id: str) -> CapabilityContractEvidence:
    owner = _owner(capability_id)
    capability_code = capability_id.removesuffix(".v1")
    operations, schemas = _operation_material(owner, capability_code)
    snapshot = CapabilityContractSnapshot(
        owner_code=owner,
        capability_code=capability_code,
        schema_version=1,
        operations=operations,
        config_fields=_config(capability_id),
        endpoint_requirements=(
            CapabilityEndpointRequirement(
                endpoint_code="service_endpoint",
                endpoint_type=CapabilityEndpointType.HTTPS_URL,
                operation_codes=("apply", "cancel", "observe", "plan"),
            ),
        ),
        checks=_checks(capability_id),
    )
    artifact_id = uuid5(NAMESPACE_URL, f"artifact:{owner}")
    manifest_id = uuid5(NAMESPACE_URL, f"manifest:{owner}")
    contract_id = uuid5(NAMESPACE_URL, f"contract:{capability_id}")
    return CapabilityContractEvidence(
        capability_id=capability_id,
        artifact_id=artifact_id,
        artifact_digest="sha256:" + "b" * 64,
        product_manifest_attestation_id=manifest_id,
        product_manifest_digest="sha256:" + "c" * 64,
        contract_attestation_id=contract_id,
        contract_attestation_digest=snapshot.digest,
        contract_ref=f"file:///held/{snapshot.digest.removeprefix('sha256:')}.json",
        snapshot=snapshot,
        schemas=schemas,
    )


@dataclass(frozen=True, slots=True)
class InMemoryCapabilityContractRegistry:
    evidence: dict[str, CapabilityContractEvidence]

    @property
    def snapshots(self) -> dict[str, CapabilityContractEvidence]:
        """Compatibility name for tests while callers migrate to evidence."""

        return self.evidence

    def require(self, capability_id: str) -> CapabilityContractEvidence:
        try:
            return self.evidence[capability_id]
        except KeyError:
            raise ConflictError(
                f"no product owner published capability contract {capability_id!r}"
            ) from None


@dataclass(frozen=True, slots=True)
class InMemoryCapabilityCompositionRegistry:
    evidence: CapabilityCompositionEvidence

    def require(
        self,
        *,
        commercial_product_code: str,
        capability_ids: tuple[str, ...],
    ) -> tuple[CapabilityCompositionEvidence, ...]:
        del commercial_product_code, capability_ids
        return (self.evidence,)


def build_capability_contract_registry() -> InMemoryCapabilityContractRegistry:
    capability_ids = {
        capability_id
        for component in catalogues.COMPONENT_CATALOGUE.values()
        for capability_id in component.capabilities
    }
    return InMemoryCapabilityContractRegistry(
        dict(
            MappingProxyType(
                {
                    capability_id: _evidence(capability_id)
                    for capability_id in sorted(capability_ids)
                }
            )
        )
    )


def build_capability_composition_registry() -> InMemoryCapabilityCompositionRegistry:
    registry = build_capability_contract_registry()
    realm = registry.require("identity.realm.lifecycle.v1")
    identity_user = registry.require("identity.user.lifecycle.v1")
    oidc = registry.require("identity.oidc-client.lifecycle.v1")

    def binding(
        binding_code: str,
        source: CapabilityContractEvidence,
        target: CapabilityContractEvidence,
        *,
        source_selector: str | None = None,
        target_selector: str | None = None,
    ) -> CapabilityEvidenceBinding:
        source_apply = source.snapshot.require_operation("apply")
        target_apply = target.snapshot.require_operation("apply")
        return CapabilityEvidenceBinding(
            binding_code=binding_code,
            source_owner_code=source.snapshot.owner_code,
            source_capability_code=source.snapshot.capability_code,
            source_capability_schema_version=source.snapshot.schema_version,
            source_operation_code="apply",
            source_output_schema_ref=source_apply.output_schema_ref,
            source_output_schema_digest=source_apply.output_schema_digest,
            source_pointer="/public_value",
            source_selector_pointer=(
                "/resource_kind" if source_selector is not None else None
            ),
            source_selector_value=source_selector,
            target_owner_code=target.snapshot.owner_code,
            target_capability_code=target.snapshot.capability_code,
            target_capability_schema_version=target.snapshot.schema_version,
            target_operation_code="apply",
            target_input_schema_ref=target_apply.input_schema_ref,
            target_input_schema_digest=target_apply.input_schema_digest,
            target_pointer="/upstream_value",
            target_selector_pointer=(
                "/resource_kind" if target_selector is not None else None
            ),
            target_selector_value=target_selector,
            coverage="each_target_exactly_one",
            required=True,
        )

    bindings = tuple(
        sorted(
            (
                binding("realm-to-oidc-clients", realm, oidc),
                binding("realm-to-identity-users", realm, identity_user),
                *(
                    binding(
                        f"oidc-client-to-{target.split('.', 1)[0]}",
                        oidc,
                        registry.require(target),
                        target_selector=(
                            "application" if target == "email.lifecycle.v1" else None
                        ),
                    )
                    for target in (
                        "academy.application.lifecycle.v1",
                        "business.application.lifecycle.v1",
                        "collaboration.user-oidc.configuration.lifecycle.v1",
                        "email.lifecycle.v1",
                        "workspace.application.lifecycle.v1",
                    )
                ),
                binding(
                    "email-application-to-domain",
                    registry.require("email.lifecycle.v1"),
                    registry.require("email.lifecycle.v1"),
                    source_selector="application",
                    target_selector="domain",
                ),
                binding(
                    "email-application-to-mailbox",
                    registry.require("email.lifecycle.v1"),
                    registry.require("email.lifecycle.v1"),
                    source_selector="application",
                    target_selector="mailbox",
                ),
                binding(
                    "identity-user-to-collaboration-user",
                    identity_user,
                    registry.require("collaboration.user-group-quota.lifecycle.v1"),
                ),
            ),
            key=lambda item: item.binding_code,
        )
    )
    snapshot = CapabilityCompositionSnapshot(
        owner_code="dotmac-managed-suite",
        composition_code="managed-suite.dependencies",
        schema_version=1,
        evidence_bindings=bindings,
    )
    snapshot.require_compatible_with(
        contracts=tuple(item.snapshot for item in registry.evidence.values()),
        schemas=tuple(
            {
                (schema.schema_ref, schema.schema_digest): schema.document
                for item in registry.evidence.values()
                for schema in item.schemas
            }.values()
        ),
    )
    return InMemoryCapabilityCompositionRegistry(
        CapabilityCompositionEvidence(
            artifact_id=uuid5(NAMESPACE_URL, "managed-suite-composition-artifact"),
            artifact_digest="sha256:" + "d" * 64,
            product_manifest_attestation_id=uuid5(
                NAMESPACE_URL, "managed-suite-composition-manifest"
            ),
            product_manifest_digest="sha256:" + "e" * 64,
            contract_ref="file:///held/managed-suite-composition.json",
            contract_digest=snapshot.digest,
            contract_attestation_id=uuid5(
                NAMESPACE_URL, "managed-suite-composition-v1"
            ),
            snapshot=snapshot,
        )
    )


def build_desired_operation_documents(
    commercial_product_code: str,
    *,
    selected_optional_components: tuple[str, ...] = (),
) -> tuple[tuple[str, str, str, dict[str, object]], ...]:
    """Exact-cover desired APPLY inputs for the synthetic owner contracts."""

    components = catalogues.resolve_components(
        commercial_product_code=commercial_product_code,
        selected_optional_components=selected_optional_components,
    )
    requirements = {
        requirement.capability_instance_ref: (component_code, requirement.capability_id)
        for component_code in components
        for requirement in catalogues.require_component(
            component_code
        ).capability_requirements
    }
    return tuple(
        (
            instance_ref,
            *requirements[instance_ref],
            (
                {"resource_kind": "application"}
                if requirements[instance_ref][1] == "email.lifecycle.v1"
                else {}
            ),
        )
        for instance_ref in sorted(requirements)
    )


def build_composition_selections(
    commercial_product_code: str,
    *,
    selected_optional_components: tuple[str, ...] = (),
    desired_operation_documents: tuple[tuple[str, str, str, dict[str, object]], ...]
    | None = None,
) -> tuple[object, ...]:
    """Explicit synthetic instance edges; production never infers these names."""

    from vendor_cp.fleet.service import CapabilityCompositionSelection

    documents = desired_operation_documents or build_desired_operation_documents(
        commercial_product_code,
        selected_optional_components=selected_optional_components,
    )
    instances_by_capability: dict[str, list[tuple[str, str]]] = {}
    for instance_ref, component_code, capability_id, _document in documents:
        instances_by_capability.setdefault(capability_id, []).append(
            (instance_ref, component_code)
        )
    evidence = build_capability_composition_registry().evidence
    selections: list[CapabilityCompositionSelection] = []
    for binding in evidence.snapshot.evidence_bindings:
        source_id = (
            f"{binding.source_capability_code}.v"
            f"{binding.source_capability_schema_version}"
        )
        target_id = (
            f"{binding.target_capability_code}.v"
            f"{binding.target_capability_schema_version}"
        )
        sources = [
            (instance_ref, component_code)
            for instance_ref, component_code in instances_by_capability.get(
                source_id, []
            )
            if binding.source_selector_pointer is None
            or next(
                document
                for candidate, _component, _capability, document in documents
                if candidate == instance_ref
            ).get(binding.source_selector_pointer.removeprefix("/"))
            == binding.source_selector_value
        ]
        targets = [
            (instance_ref, component_code)
            for instance_ref, component_code in instances_by_capability.get(
                target_id, []
            )
            if binding.target_selector_pointer is None
            or next(
                document
                for candidate, _component, _capability, document in documents
                if candidate == instance_ref
            ).get(binding.target_selector_pointer.removeprefix("/"))
            == binding.target_selector_value
        ]
        for target_ref, target_component in targets:
            matching_sources = [
                source_ref
                for source_ref, source_component in sources
                if source_component == target_component
            ]
            if not matching_sources and len(sources) == 1:
                matching_sources = [source_ref for source_ref, _component in sources]
            if len(matching_sources) != 1:
                continue
            selections.append(
                CapabilityCompositionSelection(
                    composition_contract_digest=evidence.contract_digest,
                    binding_code=binding.binding_code,
                    source_capability_instance_ref=matching_sources[0],
                    target_capability_instance_ref=target_ref,
                )
            )
    return tuple(selections)


__all__ = [
    "InMemoryCapabilityContractRegistry",
    "InMemoryCapabilityCompositionRegistry",
    "build_capability_contract_registry",
    "build_capability_composition_registry",
    "build_desired_operation_documents",
    "build_composition_selections",
]
