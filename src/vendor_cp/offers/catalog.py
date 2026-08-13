"""Product-scoped access to target applications' capability catalogues.

The vendor control plane does not own capability codes. It receives a
manifest-derived snapshot for each named product and exposes only a fail-closed
``require_declared`` port to commercial services. A code declared by one product
is not evidence that another product declares it.

The environment adapter is an assembly concern, not the authority. Its
``VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON`` input is deliberately recorded as
temporary shadow configuration: it is neither signed nor bound to exact release
bytes. The typed port lets the release-bound, digest-verified product-manifest
adapter replace it without changing offer or contract policy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Self

from dotmac_entitlement_allocation import (
    AllocationError,
    UndeclaredCapabilityError,
    UnknownProductError,
)
from dotmac_kernel import (
    BadRequestError,
    CapabilityCatalogue,
    DomainError,
    FeatureManifest,
    NotFoundError,
)
from dotmac_kernel import UndeclaredCapabilityError as KernelUndeclaredCapabilityError

from vendor_cp.config import vendor_settings


@dataclass(frozen=True, slots=True)
class ProductCapabilityCatalogues:
    """Immutable in-process adapter over product-qualified kernel catalogues."""

    _catalogues: Mapping[str, CapabilityCatalogue]

    @classmethod
    def from_capabilities(
        cls, capabilities_by_product: Mapping[str, Iterable[str]]
    ) -> Self:
        catalogues: dict[str, CapabilityCatalogue] = {}
        for product_code, codes in capabilities_by_product.items():
            if not product_code or product_code != product_code.strip():
                raise ValueError("product catalogue keys must be non-blank and trimmed")
            catalogues[product_code] = CapabilityCatalogue.from_manifests(
                [
                    FeatureManifest(
                        name=f"product:{product_code}", capabilities=tuple(codes)
                    )
                ]
            )
        return cls(MappingProxyType(catalogues))

    def require_declared(self, *, product_code: str, capability_code: str) -> None:
        catalogue = self._catalogues.get(product_code)
        if catalogue is None:
            raise UnknownProductError(
                f"product {product_code!r} has no supplied manifest catalogue"
            )
        try:
            catalogue.require(capability_code)
        except KernelUndeclaredCapabilityError as exc:
            # The published module owns this port and its stable error
            # vocabulary. The kernel catalogue is the backing mechanism; its
            # KeyError-shaped exception must not leak across the module seam.
            raise UndeclaredCapabilityError(product_code, (capability_code,)) from exc


def catalogue_domain_error(error: AllocationError) -> DomainError:
    """Translate the module-owned validation vocabulary at the HTTP boundary."""

    if isinstance(error, UnknownProductError):
        return NotFoundError(str(error))
    return BadRequestError(str(error))


def configured_product_capability_catalogues() -> ProductCapabilityCatalogues:
    """Build the process adapter from the configured manifest snapshots."""

    return ProductCapabilityCatalogues.from_capabilities(
        dict(vendor_settings.product_manifest_capabilities)
    )


__all__ = [
    "ProductCapabilityCatalogues",
    "catalogue_domain_error",
    "configured_product_capability_catalogues",
]
