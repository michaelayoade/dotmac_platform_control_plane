"""Product-scoped access to target applications' capability catalogues.

The vendor control plane does not own capability codes. It receives a
manifest-derived snapshot for each named product and exposes only a fail-closed
``require_declared`` port to commercial services. A code declared by one product
is not evidence that another product declares it.

The environment adapter is an assembly concern, not the authority: deployments
materialise ``VENDOR_PRODUCT_MANIFEST_CAPABILITIES_JSON`` from the target product
manifests. The typed port lets that adapter be replaced by a published
product-catalogue client without changing offer or contract policy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol, Self

from dotmac_kernel import CapabilityCatalogue, FeatureManifest, NotFoundError

from vendor_cp.config import vendor_settings


class UnknownProductError(NotFoundError):
    """No manifest-derived catalogue was supplied for this product."""


class ProductCapabilityCatalogueReader(Protocol):
    """The narrow product-qualified catalogue seam commercial policy consumes."""

    def require_declared(self, *, product_code: str, capability_code: str) -> None: ...


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
        catalogue.require(capability_code)


def configured_product_capability_catalogues() -> ProductCapabilityCatalogues:
    """Build the process adapter from the configured manifest snapshots."""

    return ProductCapabilityCatalogues.from_capabilities(
        dict(vendor_settings.product_manifest_capabilities)
    )


__all__ = [
    "UnknownProductError",
    "ProductCapabilityCatalogueReader",
    "ProductCapabilityCatalogues",
    "configured_product_capability_catalogues",
]
