"""Vendor-owned commercial product/component composition.

The graph may select exact externally owned capability identities.  It does not
define a capability operation, endpoint, configuration field or evidence check;
those semantics arrive only in immutable owner contract snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from dotmac_kernel import BadRequestError

from vendor_cp.managed_profiles.instance_refs import is_capability_instance_ref


@dataclass(frozen=True, slots=True)
class CapabilityRequirementSpec:
    """One stable deployment node selecting a reusable owner capability."""

    capability_instance_ref: str
    capability_id: str

    def __post_init__(self) -> None:
        if not is_capability_instance_ref(self.capability_instance_ref):
            raise ValueError("capability instance reference is not canonical")


@dataclass(frozen=True, slots=True)
class ComponentSpec:
    component_code: str
    depends_on: tuple[str, ...]
    capability_requirements: tuple[CapabilityRequirementSpec, ...]

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Compatibility read for callers interested only in contract ids."""

        return tuple(item.capability_id for item in self.capability_requirements)


@dataclass(frozen=True, slots=True)
class ProductSpec:
    commercial_product_code: str
    required_component_codes: tuple[str, ...]
    optional_component_codes: tuple[str, ...] = ()


_COMPONENTS = (
    ComponentSpec(
        "identity",
        (),
        (
            CapabilityRequirementSpec("identity.realm", "identity.realm.lifecycle.v1"),
            CapabilityRequirementSpec("identity.user", "identity.user.lifecycle.v1"),
            CapabilityRequirementSpec("identity.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "identity.host.deployment", "host.deployment-bundle.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "identity.host.backup", "host.backup-restore.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "identity.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
    ComponentSpec(
        "email",
        ("identity",),
        (
            CapabilityRequirementSpec("email.application", "email.lifecycle.v1"),
            CapabilityRequirementSpec(
                "email.oidc-client", "identity.oidc-client.lifecycle.v1"
            ),
            CapabilityRequirementSpec("email.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "email.host.deployment", "host.deployment-bundle.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "email.host.backup", "host.backup-restore.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "email.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
    ComponentSpec(
        "collaboration",
        ("identity",),
        (
            CapabilityRequirementSpec(
                "collaboration.application",
                "collaboration.application.lifecycle.v1",
            ),
            CapabilityRequirementSpec(
                "collaboration.file-roundtrip",
                "collaboration.file-roundtrip.lifecycle.v1",
            ),
            CapabilityRequirementSpec(
                "collaboration.user-group-quota",
                "collaboration.user-group-quota.lifecycle.v1",
            ),
            CapabilityRequirementSpec(
                "collaboration.user-oidc",
                "collaboration.user-oidc.configuration.lifecycle.v1",
            ),
            CapabilityRequirementSpec(
                "collaboration.oidc-client", "identity.oidc-client.lifecycle.v1"
            ),
            CapabilityRequirementSpec("collaboration.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "collaboration.host.deployment",
                "host.deployment-bundle.lifecycle.v1",
            ),
            CapabilityRequirementSpec(
                "collaboration.host.backup", "host.backup-restore.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "collaboration.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
    ComponentSpec(
        "business",
        ("identity",),
        (
            CapabilityRequirementSpec(
                "business.application", "business.application.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "business.oidc-client", "identity.oidc-client.lifecycle.v1"
            ),
            CapabilityRequirementSpec("business.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "business.host.deployment", "host.deployment-bundle.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "business.host.backup", "host.backup-restore.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "business.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
    ComponentSpec(
        "academy",
        ("identity",),
        (
            CapabilityRequirementSpec(
                "academy.application", "academy.application.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "academy.oidc-client", "identity.oidc-client.lifecycle.v1"
            ),
            CapabilityRequirementSpec("academy.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "academy.host.deployment", "host.deployment-bundle.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "academy.host.backup", "host.backup-restore.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "academy.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
    ComponentSpec(
        "workspace",
        ("identity",),
        (
            CapabilityRequirementSpec(
                "workspace.application", "workspace.application.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "workspace.oidc-client", "identity.oidc-client.lifecycle.v1"
            ),
            CapabilityRequirementSpec("workspace.dns", "dns.authoritative.v1"),
            CapabilityRequirementSpec(
                "workspace.host.deployment", "host.deployment-bundle.lifecycle.v1"
            ),
            CapabilityRequirementSpec(
                "workspace.host.health", "host.health-probe.lifecycle.v1"
            ),
        ),
    ),
)
COMPONENT_CATALOGUE = MappingProxyType(
    {spec.component_code: spec for spec in _COMPONENTS}
)

_PRODUCTS = (
    ProductSpec("managed-email", ("email",)),
    ProductSpec("managed-collaboration", ("collaboration",)),
    ProductSpec("managed-business", ("business",)),
    ProductSpec("managed-sso", ("identity",)),
    ProductSpec(
        "managed-suite",
        ("identity", "business", "email", "collaboration", "academy"),
        ("workspace",),
    ),
    ProductSpec("managed-academy", ("academy",)),
)
PRODUCT_CATALOGUE = MappingProxyType(
    {spec.commercial_product_code: spec for spec in _PRODUCTS}
)


def require_product(commercial_product_code: str) -> ProductSpec:
    try:
        return PRODUCT_CATALOGUE[commercial_product_code]
    except KeyError:
        raise KeyError(
            f"undeclared managed product {commercial_product_code!r}"
        ) from None


def require_component(component_code: str) -> ComponentSpec:
    try:
        return COMPONENT_CATALOGUE[component_code]
    except KeyError:
        raise KeyError(f"undeclared managed component {component_code!r}") from None


def resolve_components(
    *,
    commercial_product_code: str,
    selected_optional_components: tuple[str, ...],
) -> tuple[str, ...]:
    try:
        product = require_product(commercial_product_code)
    except KeyError as exc:
        raise BadRequestError(str(exc)) from None
    duplicates = _duplicates(selected_optional_components)
    if duplicates:
        raise BadRequestError(
            f"optional components contain duplicates: {', '.join(duplicates)}"
        )
    unsupported = set(selected_optional_components) - set(
        product.optional_component_codes
    )
    if unsupported:
        raise BadRequestError(
            f"components are not optional for {commercial_product_code!r}: "
            f"{', '.join(sorted(unsupported))}"
        )

    selected = set(product.required_component_codes) | set(selected_optional_components)
    pending = list(selected)
    while pending:
        component = require_component(pending.pop())
        for dependency in component.depends_on:
            if dependency not in selected:
                selected.add(dependency)
                pending.append(dependency)
    resolved = tuple(sorted(selected))
    validate_component_selection(
        commercial_product_code=commercial_product_code,
        component_codes=resolved,
    )
    return resolved


def validate_component_selection(
    *, commercial_product_code: str, component_codes: tuple[str, ...]
) -> None:
    try:
        product = require_product(commercial_product_code)
    except KeyError as exc:
        raise BadRequestError(str(exc)) from None
    selected = set(component_codes)
    for code in component_codes:
        try:
            require_component(code)
        except KeyError as exc:
            raise BadRequestError(str(exc)) from None
    missing_own = set(product.required_component_codes) - selected
    if missing_own:
        raise BadRequestError(
            f"{commercial_product_code!r} must retain its own component(s): "
            f"{', '.join(sorted(missing_own))}"
        )
    for code in sorted(selected):
        missing = set(require_component(code).depends_on) - selected
        if missing:
            raise BadRequestError(
                f"component {code!r} is missing dependency: "
                f"{', '.join(sorted(missing))}"
            )


def selected_capabilities(component_codes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                capability_id
                for component_code in component_codes
                for capability_id in require_component(component_code).capabilities
            }
        )
    )


def selected_capability_requirements(
    component_codes: tuple[str, ...],
) -> tuple[CapabilityRequirementSpec, ...]:
    requirements = tuple(
        requirement
        for component_code in component_codes
        for requirement in require_component(component_code).capability_requirements
    )
    refs = [item.capability_instance_ref for item in requirements]
    if len(refs) != len(set(refs)):
        raise BadRequestError("capability instance reference is not globally unique")
    return tuple(sorted(requirements, key=lambda item: item.capability_instance_ref))


def _duplicates(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if values.count(value) > 1}))


__all__ = [
    "COMPONENT_CATALOGUE",
    "PRODUCT_CATALOGUE",
    "CapabilityRequirementSpec",
    "ComponentSpec",
    "ProductSpec",
    "require_component",
    "require_product",
    "resolve_components",
    "selected_capabilities",
    "selected_capability_requirements",
    "validate_component_selection",
]
