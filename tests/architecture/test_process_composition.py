"""Web surfaces enrich the same installed declarations non-web processes use."""

from __future__ import annotations

from dataclasses import fields

from vendor_cp import assembly, composition

_ROUTE_FIELDS = frozenset(
    {"routers", "web_routers", "nav", "api_routers", "web_surfaces"}
)


def test_surface_binding_preserves_installed_order_and_every_non_route_field() -> None:
    assert assembly.STATEFUL_MODULES is composition.STATEFUL_MODULES
    assert tuple(manifest.name for manifest in assembly.VENDOR_SURFACES) == tuple(
        manifest.name for manifest in composition.VENDOR_DECLARATIONS
    )
    assert assembly.COMPOSED_MANIFESTS == (
        *composition.STATEFUL_MODULES,
        *assembly.VENDOR_SURFACES,
    )
    assert composition.COMPOSED_DECLARATIONS == (
        *composition.STATEFUL_MODULES,
        *composition.VENDOR_DECLARATIONS,
    )
    for declaration, surface in zip(
        composition.VENDOR_DECLARATIONS, assembly.VENDOR_SURFACES, strict=True
    ):
        assert type(declaration) is type(surface)
        for field in fields(declaration):
            if field.name in _ROUTE_FIELDS:
                assert not getattr(declaration, field.name), (
                    declaration.name,
                    field.name,
                )
            else:
                assert getattr(surface, field.name) == getattr(
                    declaration, field.name
                ), (
                    declaration.name,
                    field.name,
                )
