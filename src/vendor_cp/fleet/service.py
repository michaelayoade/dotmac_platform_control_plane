"""Single writer for account-owned fleet intent.

This service records provider-neutral desired state.  It never selects a
connector installation, dereferences a secret, opens a network connection or
touches a product data plane.  A later approval-bound execution slice may read
the immutable hashes produced here; it may not rewrite them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from dotmac_kernel import (
    ConflictError,
    NotFoundError,
    write_platform_audit_event,
)
from dotmac_kernel.messaging import enqueue_platform_event, process_once_platform
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vendor_cp.accounts.models import AccountStatus, VendorAccount
from vendor_cp.contracts.models import Contract, ContractStatus
from vendor_cp.fleet.models import (
    Deployment,
    DeploymentDesiredStateVersion,
    DeploymentTarget,
)
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.catalogues import ConfigurationFieldSpec

_CREATE_TARGET_COMMAND = "vendor.fleet.create_target"
_CREATE_DEPLOYMENT_COMMAND = "vendor.fleet.record_intent"
_UPDATE_AUTHORITIES = frozenset({"vendor_automatic", "customer_approved", "offline"})
_INTERNAL_SOURCE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,158}[a-z0-9])?$")
_REFERENCE = re.compile(r"^reference:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")
_SECRET_REFERENCE = re.compile(r"^secret:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")
_SNAPSHOT_REFERENCE = re.compile(
    r"^[a-z][a-z0-9._-]*:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$"
)
_FQDN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True, slots=True)
class CreateDeploymentTargetCommand:
    command_id: str
    account_id: UUID
    target_ref: str
    display_name: str
    region_code: str
    customer_ref: str | None = None
    actor_admin_id: UUID | None = None


ConfigurationScalar = str | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConfigurationValue:
    field_code: str
    value: ConfigurationScalar


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshotInput:
    snapshot_ref: str
    schema_version: int
    values: tuple[ConfigurationValue, ...]


@dataclass(frozen=True, slots=True)
class CreateDeploymentIntentCommand:
    command_id: str
    account_id: UUID
    target_id: UUID
    deployment_ref: str
    commercial_product_code: str
    profile_code: str
    profile_version: int
    selected_optional_components: tuple[str, ...]
    configuration_snapshot: ConfigurationSnapshotInput
    contract_id: UUID | None = None
    internal_source_code: str | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class DeploymentTargetView:
    id: UUID
    account_id: UUID
    target_ref: str
    customer_ref: str | None
    display_name: str
    region_code: str


@dataclass(frozen=True, slots=True)
class DeploymentView:
    id: UUID
    account_id: UUID
    target_id: UUID
    deployment_ref: str
    commercial_product_code: str
    status: str
    contract_id: UUID | None
    internal_source_code: str | None
    current_desired_state_revision: int


@dataclass(frozen=True, slots=True)
class DeploymentDesiredStateView:
    id: UUID
    deployment_id: UUID
    revision: int
    profile_version_id: UUID
    profile_content_hash: str
    configuration_hash: str
    desired_state_hash: str


@dataclass(frozen=True, slots=True)
class DeploymentIntentResult:
    deployment: DeploymentView
    desired_state: DeploymentDesiredStateView
    was_duplicate: bool


@dataclass(frozen=True, slots=True)
class _SelectedProfile:
    component_codes: tuple[str, ...]
    capabilities: tuple[dict[str, object], ...]
    endpoints: tuple[dict[str, object], ...]
    configuration_values: dict[str, object]
    checks: tuple[dict[str, object], ...]


def create_deployment_target(
    db: Session, command: CreateDeploymentTargetCommand
) -> DeploymentTargetView:
    """Create one account-owned target, replay-safe on `command_id`.

    Natural-key races use a SAVEPOINT.  A losing insert therefore becomes a
    typed conflict without aborting the caller's outer transaction.
    """

    _require_canonical(command.target_ref, label="target reference", limit=200)
    _require_text(command.display_name, label="target display name", limit=200)
    _require_canonical(command.region_code, label="region code", limit=80)
    if command.customer_ref is not None:
        _require_text(command.customer_ref, label="customer reference", limit=200)

    def handler(session: Session) -> Mapping[str, object]:
        account = session.get(VendorAccount, command.account_id)
        if account is None:
            raise NotFoundError(f"vendor account {command.account_id} not found")
        if account.status != AccountStatus.ACTIVE:
            raise ConflictError(
                f"vendor account {account.id} is not active; target creation refused"
            )
        natural_key = (DeploymentTarget.account_id == command.account_id) & (
            DeploymentTarget.target_ref == command.target_ref
        )
        if command.customer_ref is not None:
            natural_key = natural_key | (
                DeploymentTarget.customer_ref == command.customer_ref
            )
        existing = session.execute(
            select(DeploymentTarget).where(natural_key)
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"deployment target {command.target_ref!r} already exists for account"
            )

        row = DeploymentTarget(
            account_id=command.account_id,
            target_ref=command.target_ref,
            customer_ref=command.customer_ref,
            display_name=command.display_name,
            region_code=command.region_code,
        )
        _insert_with_conflict_savepoint(
            session,
            row,
            message="deployment target was created concurrently",
        )
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment_target.created",
            entity_type="deployment_target",
            entity_id=str(row.id),
            details={
                "account_id": str(row.account_id),
                "target_ref": row.target_ref,
                "has_customer_ref": row.customer_ref is not None,
                "region_code": row.region_code,
            },
        )
        return {"target_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CREATE_TARGET_COMMAND,
        handler=handler,
    )
    row = db.get(DeploymentTarget, UUID(str(outcome.result["target_id"])))
    if row is None:
        raise ConflictError("recorded deployment target disappeared")
    return _target_view(row)


def record_deployment_intent(
    db: Session, command: CreateDeploymentIntentCommand
) -> DeploymentIntentResult:
    """Record deployment existence and immutable desired-state revision one."""

    _require_canonical(command.deployment_ref, label="deployment reference", limit=200)
    _require_canonical(
        command.commercial_product_code,
        label="commercial product code",
        limit=120,
    )
    _require_canonical(command.profile_code, label="profile code", limit=120)
    if command.profile_version < 1:
        raise ConflictError("profile version must be positive")
    if (
        _SNAPSHOT_REFERENCE.fullmatch(command.configuration_snapshot.snapshot_ref)
        is None
    ):
        raise ConflictError(
            "configuration snapshot reference must be canonical and versioned"
        )
    if command.configuration_snapshot.schema_version < 1:
        raise ConflictError("configuration snapshot schema version must be positive")
    _validate_source_shape(command)

    def handler(session: Session) -> Mapping[str, object]:
        target = session.execute(
            select(DeploymentTarget).where(
                DeploymentTarget.id == command.target_id,
                DeploymentTarget.account_id == command.account_id,
            )
        ).scalar_one_or_none()
        if target is None:
            raise NotFoundError(
                "deployment target does not exist for the named vendor account"
            )
        _validate_commercial_source(session, command=command, target=target)

        profile = profiles.get_profile_version(
            session,
            commercial_product_code=command.commercial_product_code,
            profile_code=command.profile_code,
            version=command.profile_version,
        )
        if profile is None:
            raise NotFoundError(
                "no exact managed profile version exists for deployment intent"
            )
        selected = _validate_and_select_profile(
            profile,
            selected_optional_components=command.selected_optional_components,
            configuration_snapshot=command.configuration_snapshot,
        )

        existing = session.execute(
            select(Deployment).where(
                or_(
                    (
                        (Deployment.account_id == command.account_id)
                        & (Deployment.deployment_ref == command.deployment_ref)
                    ),
                    (
                        (Deployment.target_id == command.target_id)
                        & (
                            Deployment.commercial_product_code
                            == command.commercial_product_code
                        )
                    ),
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                "a deployment already owns this account reference or target product"
            )

        deployment = Deployment(
            account_id=command.account_id,
            target_id=command.target_id,
            deployment_ref=command.deployment_ref,
            commercial_product_code=command.commercial_product_code,
            status="intent_recorded",
            contract_id=command.contract_id,
            internal_source_code=command.internal_source_code,
            current_desired_state_revision=1,
        )
        configuration_document: dict[str, object] = {
            "snapshot_ref": command.configuration_snapshot.snapshot_ref,
            "schema_version": command.configuration_snapshot.schema_version,
            "values": selected.configuration_values,
        }
        configuration_hash = _content_hash(configuration_document)

        # The deployment id is part of the desired-state identity, so both rows
        # are inserted inside one SAVEPOINT and the deployment is flushed first.
        from dotmac_kernel.db import conflict_savepoint

        try:
            with conflict_savepoint(session):
                session.add(deployment)
                session.flush()
                desired_document: dict[str, object] = {
                    "content_schema": "vendor.deployment-desired-state@v1",
                    "deployment_id": str(deployment.id),
                    "account_id": str(command.account_id),
                    "target_id": str(command.target_id),
                    "deployment_ref": command.deployment_ref,
                    "commercial_product_code": command.commercial_product_code,
                    "profile": {
                        "id": str(profile.id),
                        "profile_code": profile.profile_code,
                        "version": profile.version,
                        "schema_version": profile.schema_version,
                        "content_hash": profile.content_hash,
                    },
                    "update_authority": profile.update_authority,
                    "selected_components": list(selected.component_codes),
                    "selected_capabilities": list(selected.capabilities),
                    "selected_endpoints": list(selected.endpoints),
                    "configuration_snapshot": configuration_document,
                    "configuration_hash": configuration_hash,
                    "verification_checks": list(selected.checks),
                }
                desired = DeploymentDesiredStateVersion(
                    deployment_id=deployment.id,
                    revision=1,
                    predecessor_id=None,
                    profile_version_id=profile.id,
                    profile_code=profile.profile_code,
                    profile_version=profile.version,
                    profile_content_hash=profile.content_hash,
                    commercial_product_code=command.commercial_product_code,
                    update_authority=profile.update_authority,
                    selected_components=list(selected.component_codes),
                    selected_capabilities=list(selected.capabilities),
                    selected_endpoints=list(selected.endpoints),
                    selected_verification_checks=list(selected.checks),
                    configuration_snapshot=selected.configuration_values,
                    configuration_snapshot_ref=(
                        command.configuration_snapshot.snapshot_ref
                    ),
                    configuration_schema_version=(
                        command.configuration_snapshot.schema_version
                    ),
                    configuration_hash=configuration_hash,
                    desired_state_hash=_content_hash(desired_document),
                )
                session.add(desired)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError("deployment intent was recorded concurrently") from exc

        safe_details: dict[str, object] = {
            "account_id": str(command.account_id),
            "target_id": str(command.target_id),
            "commercial_product_code": command.commercial_product_code,
            "profile_content_hash": profile.content_hash,
            "configuration_hash": configuration_hash,
            "desired_state_hash": desired.desired_state_hash,
            "source_kind": "contract" if command.contract_id else "internal",
        }
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment.intent_recorded",
            entity_type="deployment",
            entity_id=str(deployment.id),
            details=safe_details,
        )
        enqueue_platform_event(
            session,
            event_type="deployment.intent_recorded",
            payload={
                "deployment_id": str(deployment.id),
                "desired_state_version_id": str(desired.id),
                **safe_details,
            },
            correlation_id=str(deployment.id),
        )
        return {
            "deployment_id": str(deployment.id),
            "desired_state_id": str(desired.id),
        }

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_CREATE_DEPLOYMENT_COMMAND,
        handler=handler,
    )
    deployment = db.get(Deployment, UUID(str(outcome.result["deployment_id"])))
    desired = db.get(
        DeploymentDesiredStateVersion,
        UUID(str(outcome.result["desired_state_id"])),
    )
    if deployment is None or desired is None:
        raise ConflictError("recorded deployment intent disappeared")
    return DeploymentIntentResult(
        deployment=_deployment_view(deployment),
        desired_state=_desired_state_view(desired),
        was_duplicate=outcome.was_duplicate,
    )


def _insert_with_conflict_savepoint(db: Session, row: object, *, message: str) -> None:
    # Local import preserves wheel import-safety: dotmac_kernel.db constructs
    # configured engines at import time.
    from dotmac_kernel.db import conflict_savepoint

    try:
        with conflict_savepoint(db):
            db.add(row)
            db.flush()
    except IntegrityError as exc:
        raise ConflictError(message) from exc


def _validate_source_shape(command: CreateDeploymentIntentCommand) -> None:
    if (command.contract_id is None) == (command.internal_source_code is None):
        raise ConflictError(
            "deployment intent requires exactly one active contract or named "
            "internal source"
        )
    if (
        command.internal_source_code is not None
        and _INTERNAL_SOURCE.fullmatch(command.internal_source_code) is None
    ):
        raise ConflictError("internal source code must be a canonical named source")


def _validate_commercial_source(
    db: Session,
    *,
    command: CreateDeploymentIntentCommand,
    target: DeploymentTarget,
) -> None:
    if command.contract_id is None:
        return
    contract = db.get(Contract, command.contract_id)
    if contract is None:
        raise NotFoundError(f"contract {command.contract_id} not found")
    if contract.status != ContractStatus.ACTIVE.value:
        raise ConflictError("deployment intent requires an active contract")
    if target.customer_ref is None:
        raise ConflictError(
            "commercial deployment target has no account-owned customer reference"
        )
    if contract.customer_ref != target.customer_ref:
        raise ConflictError(
            "active contract customer reference does not match deployment target"
        )
    if contract.product_code != command.commercial_product_code:
        raise ConflictError("active contract product does not match deployment product")


def _validate_and_select_profile(
    profile: profiles.ManagedServiceProfileVersionView,
    *,
    selected_optional_components: tuple[str, ...],
    configuration_snapshot: ConfigurationSnapshotInput,
) -> _SelectedProfile:
    document = profile.document
    identity = {
        "schema_version": profile.schema_version,
        "commercial_product_code": profile.commercial_product_code,
        "profile_code": profile.profile_code,
        "version": profile.version,
    }
    for identity_field, expected in identity.items():
        if document.get(identity_field) != expected:
            raise ConflictError(
                "managed profile immutable document disagrees on " f"{identity_field}"
            )
    if profile.update_authority not in _UPDATE_AUTHORITIES:
        raise ConflictError("managed profile has an invalid update authority")
    if configuration_snapshot.schema_version != profile.schema_version:
        raise ConflictError(
            "configuration snapshot schema version does not match exact profile"
        )

    components = {
        component.component_code: component for component in profile.components
    }
    if len(components) != len(profile.components):
        raise ConflictError("managed profile contains a duplicate component")
    required = {
        component.component_code
        for component in profile.components
        if component.required
    }
    allowed_optional = set(profile.allowed_optional_components)
    declared_optional = set(components) - required
    if allowed_optional != declared_optional:
        raise ConflictError(
            "managed profile optional-component declaration disagrees with its graph"
        )
    if len(set(selected_optional_components)) != len(selected_optional_components):
        raise ConflictError("deployment optional component was selected twice")
    unsupported = set(selected_optional_components) - allowed_optional
    if unsupported:
        raise ConflictError(
            "deployment selected component outside the profile's allowed optional set: "
            + ", ".join(sorted(unsupported))
        )

    selected = required | set(selected_optional_components)
    pending = list(selected)
    while pending:
        component = components.get(pending.pop())
        if component is None:
            raise ConflictError("managed profile required component is undeclared")
        for dependency in component.depends_on:
            if dependency not in components:
                raise ConflictError(
                    f"component {component.component_code!r} has unavailable "
                    "dependency: "
                    f"{dependency}"
                )
            if dependency not in selected:
                selected.add(dependency)
                pending.append(dependency)
    component_codes = tuple(sorted(selected))
    for component_code in component_codes:
        component = components[component_code]
        missing = set(component.depends_on) - selected
        if missing:
            raise ConflictError(
                f"component {component.component_code!r} is missing dependency: "
                + ", ".join(sorted(missing))
            )

    capability_versions: dict[str, int] = {}
    capabilities: list[dict[str, object]] = []
    endpoints: set[tuple[str, str, int]] = set()
    for component_code in component_codes:
        component = components[component_code]
        for capability in component.capabilities:
            if capability.version < 1:
                raise ConflictError(
                    "managed profile capability version must be positive"
                )
            prior = capability_versions.get(capability.capability_code)
            if prior is not None and prior != capability.version:
                raise ConflictError(
                    f"capability {capability.capability_code!r} has multiple versions"
                )
            if prior is None:
                capability_versions[capability.capability_code] = capability.version
                capabilities.append(
                    {
                        "capability_code": capability.capability_code,
                        "version": capability.version,
                    }
                )
            for endpoint in capability.endpoints:
                if endpoint.version < 1:
                    raise ConflictError(
                        "managed profile endpoint version must be positive"
                    )
                endpoints.add(
                    (
                        capability.capability_code,
                        endpoint.endpoint_code,
                        endpoint.version,
                    )
                )

    field_by_code = {
        field_spec.field_code: field_spec for field_spec in profile.configuration_fields
    }
    if len(field_by_code) != len(profile.configuration_fields):
        raise ConflictError("managed profile contains a duplicate configuration field")
    selected_fields = {
        code: field_spec
        for code, field_spec in field_by_code.items()
        if (
            field_spec.component_code in selected
            or field_spec.capability_code in capability_versions
        )
    }
    values: dict[str, object] = {}
    for value in configuration_snapshot.values:
        if value.field_code in values:
            raise ConflictError("configuration snapshot contains a duplicate field")
        field_spec = field_by_code.get(value.field_code)
        if field_spec is None:
            raise ConflictError("configuration snapshot is outside the profile schema")
        if value.field_code not in selected_fields:
            raise ConflictError(
                "configuration snapshot contains a field for an unselected component"
            )
        validated = _validate_configuration_value(field_spec, value.value)
        values[value.field_code] = (
            list(validated) if isinstance(validated, tuple) else validated
        )
    missing = {
        field_spec.field_code
        for field_spec in selected_fields.values()
        if field_spec.required and field_spec.field_code not in values
    }
    if missing:
        raise ConflictError(
            "managed profile is missing required configuration field: "
            + ", ".join(sorted(missing))
        )

    checks: list[dict[str, object]] = []
    check_identities: set[tuple[str, int, str]] = set()
    for check in profile.verification_checks:
        if check.component_code is not None and check.component_code not in selected:
            continue
        identity_key = (check.check_code, check.version, check.gate)
        if check.version < 1 or identity_key in check_identities:
            raise ConflictError("managed profile has an invalid verification check")
        check_identities.add(identity_key)
        checks.append(
            {
                "check_code": check.check_code,
                "version": check.version,
                "gate": check.gate,
                "component_code": check.component_code,
            }
        )

    return _SelectedProfile(
        component_codes=component_codes,
        capabilities=tuple(
            sorted(capabilities, key=lambda item: str(item["capability_code"]))
        ),
        endpoints=tuple(
            {
                "capability_code": capability_code,
                "endpoint_code": endpoint_code,
                "version": version,
            }
            for capability_code, endpoint_code, version in sorted(endpoints)
        ),
        configuration_values={code: values[code] for code in sorted(values)},
        checks=tuple(
            sorted(
                checks,
                key=lambda item: (
                    str(item["check_code"]),
                    str(item["version"]),
                ),
            )
        ),
    )


def _validate_configuration_value(
    field: ConfigurationFieldSpec,
    value: str | tuple[str, ...],
) -> str | tuple[str, ...]:
    if field.value_type == "dns_name":
        if not isinstance(value, str) or not _is_fqdn(value):
            raise ConflictError(f"configuration field {field.field_code!r} is invalid")
        return value
    if field.value_type == "dns_name_list":
        if (
            not isinstance(value, tuple)
            or not value
            or len(set(value)) != len(value)
            or any(not _is_fqdn(item) for item in value)
        ):
            raise ConflictError(f"configuration field {field.field_code!r} is invalid")
        return tuple(sorted(value))
    if not isinstance(value, str):
        raise ConflictError(f"configuration field {field.field_code!r} is invalid")
    if field.value_type == "https_endpoint":
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not _is_fqdn(parsed.hostname)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ConflictError(f"configuration field {field.field_code!r} is invalid")
        return value
    if field.value_type == "reference":
        if _REFERENCE.fullmatch(value) is None:
            raise ConflictError(
                f"configuration field {field.field_code!r} must be a "
                "versioned reference"
            )
        return value
    if field.value_type == "secret_reference":
        if _SECRET_REFERENCE.fullmatch(value) is None:
            raise ConflictError(
                f"configuration field {field.field_code!r} must be a versioned "
                "secret reference"
            )
        return value
    raise ConflictError(
        f"configuration field {field.field_code!r} has an unknown value type"
    )


def _is_fqdn(value: str) -> bool:
    if not value or value != value.lower() or value.endswith(".") or len(value) > 253:
        return False
    labels = value.split(".")
    return (
        len(labels) >= 2
        and labels[-1][0].isalpha()
        and all(_FQDN_LABEL.fullmatch(label) is not None for label in labels)
    )


def _content_hash(value: object) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _require_text(value: str, *, label: str, limit: int) -> None:
    if not value or value != value.strip() or len(value) > limit:
        raise ConflictError(f"{label} must be non-blank and at most {limit} characters")


def _require_canonical(value: str, *, label: str, limit: int) -> None:
    _require_text(value, label=label, limit=limit)
    if _INTERNAL_SOURCE.fullmatch(value) is None:
        raise ConflictError(f"{label} must be a canonical lower-case code")


def _target_view(row: DeploymentTarget) -> DeploymentTargetView:
    return DeploymentTargetView(
        id=row.id,
        account_id=row.account_id,
        target_ref=row.target_ref,
        customer_ref=row.customer_ref,
        display_name=row.display_name,
        region_code=row.region_code,
    )


def _deployment_view(row: Deployment) -> DeploymentView:
    return DeploymentView(
        id=row.id,
        account_id=row.account_id,
        target_id=row.target_id,
        deployment_ref=row.deployment_ref,
        commercial_product_code=row.commercial_product_code,
        status=row.status,
        contract_id=row.contract_id,
        internal_source_code=row.internal_source_code,
        current_desired_state_revision=row.current_desired_state_revision,
    )


def _desired_state_view(
    row: DeploymentDesiredStateVersion,
) -> DeploymentDesiredStateView:
    return DeploymentDesiredStateView(
        id=row.id,
        deployment_id=row.deployment_id,
        revision=row.revision,
        profile_version_id=row.profile_version_id,
        profile_content_hash=row.profile_content_hash,
        configuration_hash=row.configuration_hash,
        desired_state_hash=row.desired_state_hash,
    )


__all__ = [
    "ConfigurationSnapshotInput",
    "ConfigurationValue",
    "CreateDeploymentIntentCommand",
    "CreateDeploymentTargetCommand",
    "DeploymentDesiredStateView",
    "DeploymentIntentResult",
    "DeploymentTargetView",
    "DeploymentView",
    "create_deployment_target",
    "record_deployment_intent",
]
