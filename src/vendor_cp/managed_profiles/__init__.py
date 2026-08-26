"""Provider-neutral managed-service profile catalogue and immutable versions."""

from vendor_cp.managed_profiles import catalogues, service
from vendor_cp.managed_profiles.capability_contracts import (
    CapabilityContractEvidence,
    CapabilityContractRegistry,
    CataloguedCapabilityContractRegistry,
    DirectoryCapabilityContractDocumentReader,
)
from vendor_cp.managed_profiles.composition_contracts import (
    CapabilityCompositionEvidence,
    CapabilityCompositionEvidenceError,
    CapabilityCompositionRegistry,
    CataloguedCapabilityCompositionRegistry,
)
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion
from vendor_cp.managed_profiles.service import (
    BuiltProfileVersion,
    CapabilityContract,
    CapabilitySchemaContract,
    CompatiblePredecessor,
    ComponentContract,
    ConfigurationFieldContract,
    ManagedServiceProfileVersionView,
    PrerequisiteEvidenceBindingContract,
    PublishProfileVersionCommand,
    build_profile_version,
    get_profile_version,
    publish_profile_version,
    require_profile_content_hash,
)

__all__ = [
    "BuiltProfileVersion",
    "CapabilityContractEvidence",
    "CapabilityContractRegistry",
    "CapabilityCompositionEvidence",
    "CapabilityCompositionEvidenceError",
    "CapabilityCompositionRegistry",
    "CataloguedCapabilityCompositionRegistry",
    "CataloguedCapabilityContractRegistry",
    "CapabilityContract",
    "CapabilitySchemaContract",
    "CompatiblePredecessor",
    "ComponentContract",
    "ConfigurationFieldContract",
    "DirectoryCapabilityContractDocumentReader",
    "ManagedServiceProfileVersion",
    "ManagedServiceProfileVersionView",
    "PublishProfileVersionCommand",
    "PrerequisiteEvidenceBindingContract",
    "build_profile_version",
    "catalogues",
    "get_profile_version",
    "publish_profile_version",
    "require_profile_content_hash",
    "service",
]
