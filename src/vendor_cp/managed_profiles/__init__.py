"""Provider-neutral managed-service profile catalogue and immutable versions."""

from vendor_cp.managed_profiles import catalogues, service
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion
from vendor_cp.managed_profiles.service import (
    BuiltProfileVersion,
    CapabilityContract,
    CompatiblePredecessor,
    ComponentContract,
    EndpointContract,
    ManagedServiceProfileVersionView,
    PublishProfileVersionCommand,
    VerificationCheckContract,
    build_profile_version,
    get_profile_version,
    publish_profile_version,
    require_profile_content_hash,
)

__all__ = [
    "BuiltProfileVersion",
    "CapabilityContract",
    "CompatiblePredecessor",
    "ComponentContract",
    "EndpointContract",
    "ManagedServiceProfileVersion",
    "ManagedServiceProfileVersionView",
    "PublishProfileVersionCommand",
    "VerificationCheckContract",
    "build_profile_version",
    "catalogues",
    "get_profile_version",
    "publish_profile_version",
    "require_profile_content_hash",
    "service",
]
