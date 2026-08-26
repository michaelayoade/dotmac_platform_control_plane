"""Closed, provider-neutral catalogues for managed-service profile versions.

These declarations describe *what* a managed product needs.  They never select
an implementation plugin, provider account, host, or secret value.  Integrator
bindings select implementations later, against the exact versioned connector
capabilities and endpoints snapshotted into a published profile version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

from dotmac_kernel import BadRequestError

type ConfigurationValueType = Literal[
    "dns_name",
    "dns_name_list",
    "https_endpoint",
    "reference",
    "secret_reference",
]
type VerificationGate = Literal[
    "pre_activate",
    "activate",
    "upgrade",
    "suspend",
    "restore",
    "retire",
]

CONFIGURATION_VALUE_TYPES = MappingProxyType(
    {
        "dns_name": "one canonical fully-qualified DNS name",
        "dns_name_list": "a non-empty set of canonical fully-qualified DNS names",
        "https_endpoint": "an HTTPS endpoint with a canonical DNS host",
        "reference": "a named, versioned non-secret policy or resource reference",
        "secret_reference": (
            "a named, versioned secret reference; never secret material"
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ConnectorEndpointSpec:
    endpoint_code: str
    version: int


@dataclass(frozen=True, slots=True)
class ConnectorCapabilitySpec:
    capability_code: str
    version: int
    endpoints: tuple[ConnectorEndpointSpec, ...]


@dataclass(frozen=True, slots=True)
class ComponentSpec:
    component_code: str
    depends_on: tuple[str, ...]
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProductSpec:
    commercial_product_code: str
    required_component_codes: tuple[str, ...]
    optional_component_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConfigurationFieldSpec:
    field_code: str
    value_type: ConfigurationValueType
    required: bool
    component_code: str | None = None
    capability_code: str | None = None

    def __post_init__(self) -> None:
        if (self.component_code is None) == (self.capability_code is None):
            raise ValueError(
                "a configuration field has exactly one component or capability owner"
            )


@dataclass(frozen=True, slots=True)
class VerificationCheckSpec:
    check_code: str
    version: int
    gate: VerificationGate
    component_code: str | None = None


def _endpoint(code: str, version: int = 1) -> ConnectorEndpointSpec:
    return ConnectorEndpointSpec(endpoint_code=code, version=version)


_CAPABILITIES = (
    ConnectorCapabilitySpec(
        "dns.records.lifecycle",
        1,
        (_endpoint("dns.record_set.apply"), _endpoint("dns.record_set.verify")),
    ),
    ConnectorCapabilitySpec(
        "health.probe.lifecycle",
        1,
        (_endpoint("health.probe.verify"),),
    ),
    ConnectorCapabilitySpec(
        "backup.restore.lifecycle",
        1,
        (_endpoint("backup.snapshot.verify"), _endpoint("backup.restore.verify")),
    ),
    ConnectorCapabilitySpec(
        "identity.realm.lifecycle",
        1,
        (_endpoint("identity.realm.ensure"), _endpoint("identity.realm.disable")),
    ),
    ConnectorCapabilitySpec(
        "identity.oidc-client.lifecycle",
        1,
        (
            _endpoint("identity.oidc-client.ensure"),
            _endpoint("identity.oidc-client.rotate"),
        ),
    ),
    ConnectorCapabilitySpec(
        "identity.session-provenance.lifecycle",
        1,
        (_endpoint("identity.binding.disable-and-revoke"),),
    ),
    ConnectorCapabilitySpec(
        "business.application.lifecycle",
        1,
        (_endpoint("business.application.ensure"),),
    ),
    ConnectorCapabilitySpec(
        "email.application.lifecycle",
        1,
        (
            _endpoint("email.application.ensure"),
            _endpoint("email.domain.ensure"),
            _endpoint("email.delivery.verify"),
        ),
    ),
    ConnectorCapabilitySpec(
        "collaboration.application.lifecycle",
        1,
        (_endpoint("collaboration.application.ensure"),),
    ),
    ConnectorCapabilitySpec(
        "academy.application.lifecycle",
        1,
        (_endpoint("academy.application.ensure"),),
    ),
    ConnectorCapabilitySpec(
        "workspace.application.lifecycle",
        1,
        (_endpoint("workspace.application.ensure"),),
    ),
)
CAPABILITY_CATALOGUE = MappingProxyType(
    {spec.capability_code: spec for spec in _CAPABILITIES}
)

_COMPONENTS = (
    ComponentSpec(
        component_code="identity",
        depends_on=(),
        capabilities=(
            "identity.realm.lifecycle",
            "identity.oidc-client.lifecycle",
            "identity.session-provenance.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
            "backup.restore.lifecycle",
        ),
    ),
    ComponentSpec(
        component_code="email",
        depends_on=("identity",),
        capabilities=(
            "email.application.lifecycle",
            "identity.oidc-client.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
            "backup.restore.lifecycle",
        ),
    ),
    ComponentSpec(
        component_code="collaboration",
        depends_on=("identity",),
        capabilities=(
            "collaboration.application.lifecycle",
            "identity.oidc-client.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
            "backup.restore.lifecycle",
        ),
    ),
    ComponentSpec(
        component_code="business",
        depends_on=("identity",),
        capabilities=(
            "business.application.lifecycle",
            "identity.oidc-client.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
            "backup.restore.lifecycle",
        ),
    ),
    ComponentSpec(
        component_code="academy",
        depends_on=("identity",),
        capabilities=(
            "academy.application.lifecycle",
            "identity.oidc-client.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
            "backup.restore.lifecycle",
        ),
    ),
    ComponentSpec(
        component_code="workspace",
        depends_on=("identity",),
        capabilities=(
            "workspace.application.lifecycle",
            "identity.oidc-client.lifecycle",
            "dns.records.lifecycle",
            "health.probe.lifecycle",
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

_CONFIGURATION_FIELDS = (
    ConfigurationFieldSpec(
        "customer_domain", "dns_name", True, capability_code="dns.records.lifecycle"
    ),
    ConfigurationFieldSpec(
        "identity_endpoint", "https_endpoint", True, component_code="identity"
    ),
    ConfigurationFieldSpec(
        "identity_admin_secret_ref",
        "secret_reference",
        True,
        component_code="identity",
    ),
    ConfigurationFieldSpec(
        "identity_policy_ref", "reference", True, component_code="identity"
    ),
    ConfigurationFieldSpec(
        "identity_backup_policy_ref", "reference", True, component_code="identity"
    ),
    ConfigurationFieldSpec(
        "business_endpoint", "https_endpoint", True, component_code="business"
    ),
    ConfigurationFieldSpec(
        "business_admin_secret_ref",
        "secret_reference",
        True,
        component_code="business",
    ),
    ConfigurationFieldSpec(
        "business_backup_policy_ref", "reference", True, component_code="business"
    ),
    ConfigurationFieldSpec(
        "email_endpoint", "https_endpoint", True, component_code="email"
    ),
    ConfigurationFieldSpec(
        "email_admin_secret_ref",
        "secret_reference",
        True,
        component_code="email",
    ),
    ConfigurationFieldSpec(
        "email_domains", "dns_name_list", True, component_code="email"
    ),
    ConfigurationFieldSpec(
        "email_backup_policy_ref", "reference", True, component_code="email"
    ),
    ConfigurationFieldSpec(
        "collaboration_endpoint",
        "https_endpoint",
        True,
        component_code="collaboration",
    ),
    ConfigurationFieldSpec(
        "collaboration_admin_secret_ref",
        "secret_reference",
        True,
        component_code="collaboration",
    ),
    ConfigurationFieldSpec(
        "collaboration_backup_policy_ref",
        "reference",
        True,
        component_code="collaboration",
    ),
    ConfigurationFieldSpec(
        "academy_endpoint", "https_endpoint", True, component_code="academy"
    ),
    ConfigurationFieldSpec(
        "academy_admin_secret_ref",
        "secret_reference",
        True,
        component_code="academy",
    ),
    ConfigurationFieldSpec(
        "academy_backup_policy_ref", "reference", True, component_code="academy"
    ),
    ConfigurationFieldSpec(
        "workspace_endpoint", "https_endpoint", True, component_code="workspace"
    ),
    ConfigurationFieldSpec(
        "workspace_admin_secret_ref",
        "secret_reference",
        True,
        component_code="workspace",
    ),
)
CONFIGURATION_FIELD_CATALOGUE = MappingProxyType(
    {spec.field_code: spec for spec in _CONFIGURATION_FIELDS}
)


def _check(
    code: str,
    gate: VerificationGate,
    component: str | None = None,
    version: int = 1,
) -> VerificationCheckSpec:
    return VerificationCheckSpec(code, version, gate, component)


_VERIFICATION_CHECKS = (
    _check("deployment.plan_hash_bound", "pre_activate"),
    _check("deployment.health.ready", "activate"),
    _check("deployment.update.verified", "upgrade"),
    _check("deployment.suspension.verified", "suspend"),
    _check("deployment.backup.restore", "restore"),
    _check("deployment.retirement.verified", "retire"),
    _check("identity.discovery.issuer", "activate", "identity"),
    _check("identity.jwks.rs256", "activate", "identity"),
    _check("identity.oidc.pkce_s256", "activate", "identity"),
    _check("identity.oidc.aud_azp", "activate", "identity"),
    _check("identity.binding.immutable", "activate", "identity"),
    _check("identity.binding.takeover_refused", "activate", "identity"),
    _check("identity.session.provenance_revocation", "suspend", "identity"),
    _check("identity.backup.restore", "restore", "identity"),
    _check("business.oidc.login", "activate", "business"),
    _check("business.authorization", "activate", "business"),
    _check("business.backup.restore", "restore", "business"),
    _check("email.dns.mx", "pre_activate", "email"),
    _check("email.dns.spf", "pre_activate", "email"),
    _check("email.dns.dkim", "pre_activate", "email"),
    _check("email.dns.dmarc", "pre_activate", "email"),
    _check("email.delivery.inbound", "activate", "email"),
    _check("email.delivery.outbound", "activate", "email"),
    _check("email.app_password", "activate", "email"),
    _check("email.backup.restore", "restore", "email"),
    _check("collaboration.oidc.login", "activate", "collaboration"),
    _check("collaboration.files.roundtrip", "activate", "collaboration"),
    _check("collaboration.backup.restore", "restore", "collaboration"),
    _check("academy.oidc.login", "activate", "academy"),
    _check("academy.course.access", "activate", "academy"),
    _check("academy.backup.restore", "restore", "academy"),
    _check("workspace.oidc.login", "activate", "workspace"),
    _check("workspace.launcher.authorization", "activate", "workspace"),
)
VERIFICATION_CHECK_CATALOGUE = MappingProxyType(
    {spec.check_code: spec for spec in _VERIFICATION_CHECKS}
)

_FQDN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_REFERENCE = re.compile(r"^reference:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")
_SECRET_REFERENCE = re.compile(r"^secret:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")


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


def require_capability(capability_code: str) -> ConnectorCapabilitySpec:
    try:
        return CAPABILITY_CATALOGUE[capability_code]
    except KeyError:
        raise KeyError(f"undeclared connector capability {capability_code!r}") from None


def require_configuration_field(field_code: str) -> ConfigurationFieldSpec:
    try:
        return CONFIGURATION_FIELD_CATALOGUE[field_code]
    except KeyError:
        raise BadRequestError(
            f"undeclared configuration field {field_code!r}"
        ) from None


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


def selected_capabilities(
    component_codes: tuple[str, ...],
) -> tuple[ConnectorCapabilitySpec, ...]:
    codes = {
        capability_code
        for component_code in component_codes
        for capability_code in require_component(component_code).capabilities
    }
    return tuple(require_capability(code) for code in sorted(codes))


def required_configuration_fields(
    *, component_codes: tuple[str, ...]
) -> tuple[str, ...]:
    capabilities = {
        capability.capability_code
        for capability in selected_capabilities(component_codes)
    }
    return tuple(
        sorted(
            field.field_code
            for field in CONFIGURATION_FIELD_CATALOGUE.values()
            if field.required
            and (
                field.component_code in component_codes
                or field.capability_code in capabilities
            )
        )
    )


def selected_configuration_fields(
    *, component_codes: tuple[str, ...]
) -> tuple[ConfigurationFieldSpec, ...]:
    capabilities = {
        capability.capability_code
        for capability in selected_capabilities(component_codes)
    }
    return tuple(
        field
        for field in CONFIGURATION_FIELD_CATALOGUE.values()
        if field.component_code in component_codes
        or field.capability_code in capabilities
    )


def selected_verification_checks(
    *, component_codes: tuple[str, ...]
) -> tuple[VerificationCheckSpec, ...]:
    return tuple(
        check
        for check in VERIFICATION_CHECK_CATALOGUE.values()
        if check.component_code is None or check.component_code in component_codes
    )


def validate_configuration_value(
    *, field_code: str, value: str | tuple[str, ...]
) -> str | tuple[str, ...]:
    field = require_configuration_field(field_code)
    if field.value_type == "dns_name":
        if not isinstance(value, str) or not _is_fqdn(value):
            raise BadRequestError(f"{field_code!r} must be a canonical FQDN")
        return value
    if field.value_type == "dns_name_list":
        if not isinstance(value, tuple) or not value:
            raise BadRequestError(f"{field_code!r} must be a non-empty FQDN tuple")
        if any(not _is_fqdn(item) for item in value):
            raise BadRequestError(f"{field_code!r} contains a non-canonical FQDN")
        if len(set(value)) != len(value):
            raise BadRequestError(f"{field_code!r} contains duplicate DNS names")
        return tuple(sorted(value))
    if not isinstance(value, str):
        raise BadRequestError(f"{field_code!r} must be a string")
    if field.value_type == "https_endpoint":
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise BadRequestError(f"{field_code!r} has an invalid HTTPS port") from exc
        canonical_netloc = (
            parsed.hostname if port is None else f"{parsed.hostname}:{port}"
        )
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not _is_fqdn(parsed.hostname)
            or parsed.netloc != canonical_netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise BadRequestError(
                f"{field_code!r} must be an HTTPS endpoint with a canonical FQDN"
            )
        return value
    if field.value_type == "reference":
        if _REFERENCE.fullmatch(value) is None:
            raise BadRequestError(
                f"{field_code!r} must be a versioned non-secret reference"
            )
        return value
    if field.value_type == "secret_reference":
        if _SECRET_REFERENCE.fullmatch(value) is None:
            raise BadRequestError(
                f"{field_code!r} must be a versioned secret reference"
            )
        return value
    raise AssertionError(f"unhandled configuration type {field.value_type!r}")


def _duplicates(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if values.count(value) > 1}))


def _is_fqdn(value: str) -> bool:
    if not value or value != value.lower() or value.endswith(".") or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2 or not labels[-1][0].isalpha():
        return False
    return all(_FQDN_LABEL.fullmatch(label) is not None for label in labels)


__all__ = [
    "CAPABILITY_CATALOGUE",
    "COMPONENT_CATALOGUE",
    "CONFIGURATION_FIELD_CATALOGUE",
    "CONFIGURATION_VALUE_TYPES",
    "PRODUCT_CATALOGUE",
    "VERIFICATION_CHECK_CATALOGUE",
    "ComponentSpec",
    "ConfigurationFieldSpec",
    "ConnectorCapabilitySpec",
    "ConnectorEndpointSpec",
    "ProductSpec",
    "VerificationCheckSpec",
    "require_capability",
    "require_component",
    "require_configuration_field",
    "require_product",
    "required_configuration_fields",
    "resolve_components",
    "selected_capabilities",
    "selected_configuration_fields",
    "selected_verification_checks",
    "validate_component_selection",
    "validate_configuration_value",
]
