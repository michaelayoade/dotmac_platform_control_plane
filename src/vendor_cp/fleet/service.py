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
from dataclasses import dataclass, replace
from urllib.parse import urlsplit
from uuid import UUID

from dotmac_kernel import (
    CapabilityConfigValueFormat,
    CapabilityConfigValueType,
    CapabilitySchemaDocument,
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
    DeploymentCapabilityInstance,
    DeploymentDesiredStateVersion,
    DeploymentTarget,
)
from vendor_cp.managed_profiles import service as profiles
from vendor_cp.managed_profiles.instance_refs import is_capability_instance_ref
from vendor_cp.managed_profiles.operation_inputs import (
    DesiredOperationInputError,
    validate_desired_operation_input,
)
from vendor_cp.managed_profiles.service import ConfigurationFieldContract

_CREATE_TARGET_COMMAND = "vendor.fleet.create_target"
_CREATE_DEPLOYMENT_COMMAND = "vendor.fleet.record_intent"
_REVISE_DESIRED_STATE_COMMAND = "vendor.fleet.revise_desired_state"
_UPDATE_AUTHORITIES = frozenset({"vendor_automatic", "customer_approved", "offline"})
_INTERNAL_SOURCE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,158}[a-z0-9])?$")
_REFERENCE = re.compile(r"^reference:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")
_SECRET_REFERENCE = re.compile(r"^secret:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$")
_SNAPSHOT_REFERENCE = re.compile(
    r"^[a-z][a-z0-9._-]*:[a-z0-9][a-z0-9._/-]*@v[1-9][0-9]*$"
)
_FQDN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSIONED_ID = re.compile(r"^[a-z][a-z0-9_.:-]*\.v[1-9][0-9]*$")


@dataclass(frozen=True, slots=True)
class CreateDeploymentTargetCommand:
    command_id: str
    account_id: UUID
    target_ref: str
    display_name: str
    region_code: str
    customer_ref: str | None = None
    actor_admin_id: UUID | None = None


ConfigurationScalar = bool | int | str | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConfigurationValue:
    capability_instance_ref: str
    field_code: str
    value: ConfigurationScalar


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshotInput:
    snapshot_ref: str
    schema_version: int
    values: tuple[ConfigurationValue, ...]


@dataclass(frozen=True, slots=True)
class CapabilityOperationInput:
    """One product-owned APPLY input instance, before composition evidence."""

    capability_instance_ref: str
    component_code: str
    capability_id: str
    document: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CapabilityCompositionSelection:
    """Explicit deployment-instance edge selected from one owner contract."""

    composition_contract_digest: str
    binding_code: str
    source_capability_instance_ref: str
    target_capability_instance_ref: str


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
    desired_operation_inputs: tuple[CapabilityOperationInput, ...]
    composition_selections: tuple[CapabilityCompositionSelection, ...] = ()
    contract_id: UUID | None = None
    internal_source_code: str | None = None
    actor_admin_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ReviseDeploymentDesiredStateCommand:
    command_id: str
    deployment_id: UUID
    expected_current_revision: int
    profile_code: str
    profile_version: int
    selected_optional_components: tuple[str, ...]
    configuration_snapshot: ConfigurationSnapshotInput
    desired_operation_inputs: tuple[CapabilityOperationInput, ...]
    composition_selections: tuple[CapabilityCompositionSelection, ...] = ()
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
    operations: tuple[dict[str, object], ...]
    configuration_values: dict[str, dict[str, object]]
    desired_operation_inputs: dict[str, dict[str, object]]
    composition_bindings: tuple[dict[str, object], ...]
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
            desired_operation_inputs=command.desired_operation_inputs,
            composition_selections=command.composition_selections,
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
                _ensure_capability_instances(
                    session,
                    deployment_id=deployment.id,
                    selected_capabilities=selected.capabilities,
                )
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
                    "selected_operations": list(selected.operations),
                    "configuration_snapshot": configuration_document,
                    "configuration_hash": configuration_hash,
                    "desired_operation_inputs": selected.desired_operation_inputs,
                    "selected_composition_edges": list(selected.composition_bindings),
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
                    selected_operations=list(selected.operations),
                    selected_verification_checks=list(selected.checks),
                    configuration_snapshot=selected.configuration_values,
                    desired_operation_inputs=selected.desired_operation_inputs,
                    selected_composition_edges=list(selected.composition_bindings),
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


def revise_deployment_desired_state(
    db: Session, command: ReviseDeploymentDesiredStateCommand
) -> DeploymentDesiredStateView:
    """Append a desired-state revision and structurally invalidate its plan."""

    _require_canonical(command.profile_code, label="profile code", limit=120)
    if command.profile_version < 1 or command.expected_current_revision < 1:
        raise ConflictError(
            "profile and expected desired-state revisions must be positive"
        )
    if (
        _SNAPSHOT_REFERENCE.fullmatch(command.configuration_snapshot.snapshot_ref)
        is None
    ):
        raise ConflictError(
            "configuration snapshot reference must be canonical and versioned"
        )
    if command.configuration_snapshot.schema_version < 1:
        raise ConflictError("configuration snapshot schema version must be positive")

    def handler(session: Session) -> Mapping[str, object]:
        deployment = session.execute(
            select(Deployment)
            .where(Deployment.id == command.deployment_id)
            .with_for_update()
        ).scalar_one_or_none()
        if deployment is None:
            raise NotFoundError(f"deployment {command.deployment_id} not found")
        if (
            deployment.current_desired_state_revision
            != command.expected_current_revision
        ):
            raise ConflictError("deployment desired state changed before this revision")
        predecessor = session.execute(
            select(DeploymentDesiredStateVersion).where(
                DeploymentDesiredStateVersion.deployment_id == deployment.id,
                DeploymentDesiredStateVersion.revision
                == command.expected_current_revision,
            )
        ).scalar_one_or_none()
        if predecessor is None:
            raise ConflictError("deployment current desired-state pointer is broken")
        profile = profiles.get_profile_version(
            session,
            commercial_product_code=deployment.commercial_product_code,
            profile_code=command.profile_code,
            version=command.profile_version,
        )
        if profile is None:
            raise NotFoundError("no exact managed profile version exists for revision")
        if profile.content_hash != predecessor.profile_content_hash and not any(
            item.commercial_product_code == predecessor.commercial_product_code
            and item.content_hash == predecessor.profile_content_hash
            for item in profile.compatible_predecessors
        ):
            raise ConflictError(
                "managed profile does not admit the exact current predecessor"
            )
        selected = _validate_and_select_profile(
            profile,
            selected_optional_components=command.selected_optional_components,
            configuration_snapshot=command.configuration_snapshot,
            desired_operation_inputs=command.desired_operation_inputs,
            composition_selections=command.composition_selections,
        )
        _ensure_capability_instances(
            session,
            deployment_id=deployment.id,
            selected_capabilities=selected.capabilities,
        )
        configuration_document: dict[str, object] = {
            "snapshot_ref": command.configuration_snapshot.snapshot_ref,
            "schema_version": command.configuration_snapshot.schema_version,
            "values": selected.configuration_values,
        }
        configuration_hash = _content_hash(configuration_document)
        desired_document: dict[str, object] = {
            "content_schema": "vendor.deployment-desired-state@v1",
            "deployment_id": str(deployment.id),
            "account_id": str(deployment.account_id),
            "target_id": str(deployment.target_id),
            "deployment_ref": deployment.deployment_ref,
            "commercial_product_code": deployment.commercial_product_code,
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
            "selected_operations": list(selected.operations),
            "configuration_snapshot": configuration_document,
            "configuration_hash": configuration_hash,
            "desired_operation_inputs": selected.desired_operation_inputs,
            "selected_composition_edges": list(selected.composition_bindings),
            "verification_checks": list(selected.checks),
        }
        revision = command.expected_current_revision + 1
        row = DeploymentDesiredStateVersion(
            deployment_id=deployment.id,
            revision=revision,
            predecessor_id=predecessor.id,
            profile_version_id=profile.id,
            profile_code=profile.profile_code,
            profile_version=profile.version,
            profile_content_hash=profile.content_hash,
            commercial_product_code=deployment.commercial_product_code,
            update_authority=profile.update_authority,
            selected_components=list(selected.component_codes),
            selected_capabilities=list(selected.capabilities),
            selected_operations=list(selected.operations),
            selected_verification_checks=list(selected.checks),
            configuration_snapshot=selected.configuration_values,
            desired_operation_inputs=selected.desired_operation_inputs,
            selected_composition_edges=list(selected.composition_bindings),
            configuration_snapshot_ref=command.configuration_snapshot.snapshot_ref,
            configuration_schema_version=command.configuration_snapshot.schema_version,
            configuration_hash=configuration_hash,
            desired_state_hash=_content_hash(desired_document),
        )
        _insert_with_conflict_savepoint(
            session,
            row,
            message="deployment desired-state revision was created concurrently",
        )
        deployment.current_desired_state_revision = revision
        deployment.current_plan_id = None
        deployment.status = "intent_recorded"
        session.flush()
        write_platform_audit_event(
            session,
            actor_admin_id=command.actor_admin_id,
            action="vendor.deployment.desired_state_revised",
            entity_type="deployment",
            entity_id=str(deployment.id),
            details={
                "revision": revision,
                "predecessor_id": str(predecessor.id),
                "configuration_hash": configuration_hash,
                "desired_state_hash": row.desired_state_hash,
            },
        )
        enqueue_platform_event(
            session,
            event_type="deployment.desired_state_revised",
            payload={
                "deployment_id": str(deployment.id),
                "desired_state_version_id": str(row.id),
                "revision": revision,
                "desired_state_hash": row.desired_state_hash,
            },
            correlation_id=str(deployment.id),
        )
        return {"desired_state_id": str(row.id)}

    outcome = process_once_platform(
        db,
        command_id=command.command_id,
        command_type=_REVISE_DESIRED_STATE_COMMAND,
        handler=handler,
    )
    row = db.get(
        DeploymentDesiredStateVersion,
        UUID(str(outcome.result["desired_state_id"])),
    )
    if row is None:
        raise ConflictError("recorded desired-state revision disappeared")
    return _desired_state_view(row)


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


def _ensure_capability_instances(
    db: Session,
    *,
    deployment_id: UUID,
    selected_capabilities: tuple[dict[str, object], ...],
) -> None:
    """Materialize stable deployment-local capability identities.

    The caller holds either the not-yet-visible deployment insert or the
    deployment row lock, so revisions cannot race this exact-cover update.
    Historical instances remain: removing one from a later desired state does
    not recycle its identity for a different node.
    """

    required = {str(item["capability_instance_ref"]) for item in selected_capabilities}
    if any(not is_capability_instance_ref(item) for item in required):
        raise ConflictError("capability instance reference is not canonical")
    if len(required) != len(selected_capabilities):
        raise ConflictError("desired state contains a duplicate capability instance")
    existing = set(
        db.execute(
            select(DeploymentCapabilityInstance.capability_instance_ref).where(
                DeploymentCapabilityInstance.deployment_id == deployment_id
            )
        ).scalars()
    )
    rows = [
        DeploymentCapabilityInstance(
            deployment_id=deployment_id,
            capability_instance_ref=instance_ref,
        )
        for instance_ref in sorted(required - existing)
    ]
    if rows:
        db.add_all(rows)
        db.flush()


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
    desired_operation_inputs: tuple[CapabilityOperationInput, ...],
    composition_selections: tuple[CapabilityCompositionSelection, ...],
) -> _SelectedProfile:
    document = profile.document
    profile_identity = {
        "schema_version": profile.schema_version,
        "commercial_product_code": profile.commercial_product_code,
        "profile_code": profile.profile_code,
        "version": profile.version,
    }
    for identity_field, expected in profile_identity.items():
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

    expanded_contracts = _expand_capability_instances(
        components=components,
        component_codes=component_codes,
        desired_operation_inputs=desired_operation_inputs,
    )
    capability_snapshots: dict[str, dict[str, object]] = {}
    operations: dict[tuple[str, str], dict[str, object]] = {}
    apply_input_schemas: dict[str, CapabilitySchemaDocument] = {}
    for component_code, capability in expanded_contracts:
        if (
            not is_capability_instance_ref(capability.capability_instance_ref)
            or _VERSIONED_ID.fullmatch(capability.capability_id) is None
            or not capability.owner_code
            or not capability.contract_ref
            or _HASH.fullmatch(capability.content_hash) is None
            or capability.schema_version < 1
        ):
            raise ConflictError("managed profile capability evidence is incomplete")
        snapshot: dict[str, object] = {
            "capability_instance_ref": capability.capability_instance_ref,
            "component_code": component_code,
            "capability_id": capability.capability_id,
            "owner_code": capability.owner_code,
            "capability_code": capability.capability_code,
            "schema_version": capability.schema_version,
            "contract_ref": capability.contract_ref,
            "content_hash": capability.content_hash,
            "artifact_id": str(capability.artifact_id),
            "artifact_digest": capability.artifact_digest,
            "product_manifest_attestation_id": str(
                capability.product_manifest_attestation_id
            ),
            "product_manifest_digest": capability.product_manifest_digest,
            "contract_attestation_id": str(capability.contract_attestation_id),
            "contract_attestation_digest": (capability.contract_attestation_digest),
            "operations": [
                {
                    "operation_code": operation.operation_code,
                    "input_schema_ref": operation.input_schema_ref,
                    "input_schema_digest": operation.input_schema_digest,
                    "output_schema_ref": operation.output_schema_ref,
                    "output_schema_digest": operation.output_schema_digest,
                }
                for operation in capability.operations
            ],
            "endpoint_requirements": [
                {
                    "endpoint_code": endpoint.endpoint_code,
                    "endpoint_type": endpoint.endpoint_type.value,
                    "operation_codes": list(endpoint.operation_codes),
                    "required": endpoint.required,
                }
                for endpoint in capability.endpoint_requirements
            ],
            "schemas": [
                {
                    "schema_ref": schema.schema_ref,
                    "schema_digest": schema.schema_digest,
                    "attestation_id": str(schema.attestation_id),
                    "document_ref": schema.document_ref,
                    "document": json.loads(schema.document.to_json_bytes()),
                }
                for schema in capability.schemas
            ],
        }
        prior = capability_snapshots.get(capability.capability_instance_ref)
        if prior is not None and prior != snapshot:
            raise ConflictError(
                "capability instance "
                f"{capability.capability_instance_ref!r} has conflicting evidence"
            )
        if prior is None:
            capability_snapshots[capability.capability_instance_ref] = snapshot
        for operation in capability.operations:
            operation_identity = (
                capability.capability_instance_ref,
                operation.operation_code,
            )
            operation_document: dict[str, object] = {
                "capability_instance_ref": capability.capability_instance_ref,
                "capability_id": capability.capability_id,
                "operation_code": operation.operation_code,
                "input_schema_ref": operation.input_schema_ref,
                "input_schema_digest": operation.input_schema_digest,
                "output_schema_ref": operation.output_schema_ref,
                "output_schema_digest": operation.output_schema_digest,
            }
            prior_operation = operations.get(operation_identity)
            if prior_operation is not None and prior_operation != operation_document:
                raise ConflictError(
                    "managed profile capability operation evidence conflicts"
                )
            operations[operation_identity] = operation_document
            if operation.operation_code == "apply":
                schema_matches = tuple(
                    schema
                    for schema in capability.schemas
                    if schema.schema_ref == operation.input_schema_ref
                    and schema.schema_digest == operation.input_schema_digest
                )
                if len(schema_matches) != 1:
                    raise ConflictError(
                        "managed profile APPLY input lacks exact held schema"
                    )
                prior_schema = apply_input_schemas.get(
                    capability.capability_instance_ref
                )
                if (
                    prior_schema is not None
                    and prior_schema.digest != schema_matches[0].document.digest
                ):
                    raise ConflictError(
                        "managed profile APPLY input schema evidence conflicts"
                    )
                apply_input_schemas[capability.capability_instance_ref] = (
                    schema_matches[0].document
                )

    field_by_identity = {
        (capability.capability_instance_ref, field.field_code): (
            ConfigurationFieldContract(
                capability_instance_ref=capability.capability_instance_ref,
                capability_id=capability.capability_id,
                field_code=field.field_code,
                value_type=field.value_type.value,
                value_format=field.value_format.value,
                required=field.required,
            )
        )
        for _component_code, capability in expanded_contracts
        for field in capability.config_fields
    }
    expected_field_count = sum(
        len(capability.config_fields)
        for _component_code, capability in expanded_contracts
    )
    if len(field_by_identity) != expected_field_count:
        raise ConflictError("managed profile contains a duplicate configuration field")
    values: dict[str, dict[str, object]] = {}
    supplied_value_identities: set[tuple[str, str]] = set()
    for value in configuration_snapshot.values:
        identity = (value.capability_instance_ref, value.field_code)
        if identity in supplied_value_identities:
            raise ConflictError("configuration snapshot contains a duplicate field")
        supplied_value_identities.add(identity)
        field_spec = field_by_identity.get(identity)
        if field_spec is None:
            if any(
                identity
                == (profile_field.capability_instance_ref, profile_field.field_code)
                for profile_field in profile.configuration_fields
            ):
                raise ConflictError(
                    "configuration snapshot contains a field for an unselected "
                    "component"
                )
            raise ConflictError("configuration snapshot is outside the profile schema")
        validated = _validate_configuration_value(field_spec, value.value)
        values.setdefault(value.capability_instance_ref, {})[value.field_code] = (
            list(validated) if isinstance(validated, tuple) else validated
        )
    missing = {
        f"{field_spec.capability_instance_ref}:{field_spec.field_code}"
        for identity, field_spec in field_by_identity.items()
        if field_spec.required and identity not in supplied_value_identities
    }
    if missing:
        raise ConflictError(
            "managed profile is missing required configuration field: "
            + ", ".join(sorted(missing))
        )

    operation_inputs = _validate_desired_operation_inputs(
        desired_operation_inputs,
        apply_input_schemas=apply_input_schemas,
        capability_snapshots=capability_snapshots,
        composition_bindings=profile.prerequisite_evidence_bindings,
    )
    selected_composition_bindings = _validate_composition_selections(
        composition_selections,
        definitions=profile.prerequisite_evidence_bindings,
        capability_snapshots=capability_snapshots,
        operation_inputs=operation_inputs,
    )

    checks: list[dict[str, object]] = []
    check_identities: set[tuple[str, str]] = set()
    for _component_code, capability in expanded_contracts:
        for check in capability.checks:
            identity_key = (capability.capability_instance_ref, check.check_code)
            if identity_key in check_identities:
                raise ConflictError("managed profile has an invalid verification check")
            check_identities.add(identity_key)
            checks.append(
                {
                    "capability_instance_ref": capability.capability_instance_ref,
                    "capability_id": capability.capability_id,
                    "check_code": check.check_code,
                    "stage": check.stage.value,
                    "evidence_type": check.evidence_type.value,
                    "required": check.required,
                }
            )

    return _SelectedProfile(
        component_codes=component_codes,
        capabilities=tuple(
            capability_snapshots[instance_ref]
            for instance_ref in sorted(capability_snapshots)
        ),
        operations=tuple(operations[identity] for identity in sorted(operations)),
        configuration_values={
            instance_ref: {
                code: values[instance_ref][code]
                for code in sorted(values[instance_ref])
            }
            for instance_ref in sorted(values)
        },
        desired_operation_inputs=operation_inputs,
        composition_bindings=selected_composition_bindings,
        checks=tuple(
            sorted(
                checks,
                key=lambda item: (
                    str(item["check_code"]),
                    str(item["capability_id"]),
                ),
            )
        ),
    )


def _expand_capability_instances(
    *,
    components: Mapping[str, profiles.ComponentContract],
    component_codes: tuple[str, ...],
    desired_operation_inputs: tuple[CapabilityOperationInput, ...],
) -> tuple[tuple[str, profiles.CapabilityContract], ...]:
    """Resolve each explicit instance to one selected commercial requirement.

    A profile requirement is a reusable capability contract plus one mandatory
    baseline instance.  Additional instances may reuse that exact contract only
    under a selected component that declared the capability.  The caller names
    the component; Vendor never infers ownership from an instance-ref prefix.
    """

    baseline: dict[str, tuple[str, profiles.CapabilityContract]] = {}
    prototypes: dict[tuple[str, str], profiles.CapabilityContract] = {}
    ambiguous: set[tuple[str, str]] = set()
    for component_code in component_codes:
        for capability in components[component_code].capabilities:
            instance_ref = capability.capability_instance_ref
            if instance_ref in baseline:
                raise ConflictError(
                    "managed profile contains a duplicate capability instance"
                )
            baseline[instance_ref] = (component_code, capability)
            prototype_key = (component_code, capability.capability_id)
            prior = prototypes.get(prototype_key)
            if prior is not None and prior != capability:
                ambiguous.add(prototype_key)
            else:
                prototypes[prototype_key] = capability

    supplied: dict[str, CapabilityOperationInput] = {}
    for item in desired_operation_inputs:
        if not is_capability_instance_ref(item.capability_instance_ref):
            raise ConflictError("capability instance reference is not canonical")
        if _VERSIONED_ID.fullmatch(item.capability_id) is None:
            raise ConflictError("desired operation input capability is not versioned")
        _require_canonical(item.component_code, label="component code", limit=120)
        if item.capability_instance_ref in supplied:
            raise ConflictError("desired operation input instance is duplicated")
        supplied[item.capability_instance_ref] = item

    missing = sorted(set(baseline) - set(supplied))
    if missing:
        raise ConflictError(
            "desired operation inputs omit required capability instances: "
            + ", ".join(missing)
        )

    expanded: list[tuple[str, profiles.CapabilityContract]] = []
    for instance_ref in sorted(supplied):
        item = supplied[instance_ref]
        baseline_item = baseline.get(instance_ref)
        if baseline_item is not None:
            component_code, prototype = baseline_item
            if (
                item.component_code != component_code
                or item.capability_id != prototype.capability_id
            ):
                raise ConflictError(
                    f"baseline capability instance {instance_ref!r} was rebound"
                )
        else:
            if item.component_code not in component_codes:
                raise ConflictError(
                    f"capability instance {instance_ref!r} names an unselected "
                    "component"
                )
            prototype_key = (item.component_code, item.capability_id)
            if prototype_key in ambiguous:
                raise ConflictError(
                    "additional capability instance has an ambiguous profile "
                    "requirement"
                )
            resolved_prototype = prototypes.get(prototype_key)
            if resolved_prototype is None:
                raise ConflictError(
                    f"component {item.component_code!r} does not declare capability "
                    f"{item.capability_id!r}"
                )
            prototype = resolved_prototype
            component_code = item.component_code
        expanded.append(
            (
                component_code,
                replace(prototype, capability_instance_ref=instance_ref),
            )
        )
    return tuple(expanded)


def _validate_composition_selections(
    selections: tuple[CapabilityCompositionSelection, ...],
    *,
    definitions: tuple[profiles.PrerequisiteEvidenceBindingContract, ...],
    capability_snapshots: Mapping[str, Mapping[str, object]],
    operation_inputs: Mapping[str, Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    """Resolve abstract owner rules to an exact, cardinality-checked edge set."""

    definition_index: dict[
        tuple[str, str], profiles.PrerequisiteEvidenceBindingContract
    ] = {}
    for definition in definitions:
        identity = (
            definition.composition_contract_digest,
            definition.binding_code,
        )
        if identity in definition_index:
            raise ConflictError("managed profile repeats a composition binding")
        definition_index[identity] = definition

    selected_by_definition: dict[
        tuple[str, str], list[CapabilityCompositionSelection]
    ] = {identity: [] for identity in definition_index}
    edge_identities: set[tuple[str, str, str, str]] = set()
    injection_targets: set[tuple[str, str]] = set()
    result: list[dict[str, object]] = []
    for selection in selections:
        identity = (selection.composition_contract_digest, selection.binding_code)
        resolved_definition = definition_index.get(identity)
        if resolved_definition is None:
            raise ConflictError(
                "composition selection is not declared by the immutable profile"
            )
        definition = resolved_definition
        if not is_capability_instance_ref(
            selection.source_capability_instance_ref
        ) or not is_capability_instance_ref(selection.target_capability_instance_ref):
            raise ConflictError("composition selection instance is not canonical")
        source = capability_snapshots.get(selection.source_capability_instance_ref)
        target = capability_snapshots.get(selection.target_capability_instance_ref)
        if source is None or target is None:
            raise ConflictError("composition selection names an unknown instance")
        if (
            source.get("capability_id") != definition.source_capability_id
            or target.get("capability_id") != definition.target_capability_id
        ):
            raise ConflictError(
                "composition selection capability differs from its owner contract"
            )
        if not _selector_matches(
            operation_inputs[selection.source_capability_instance_ref],
            pointer=definition.source_selector_pointer,
            expected=definition.source_selector_value,
        ) or not _selector_matches(
            operation_inputs[selection.target_capability_instance_ref],
            pointer=definition.target_selector_pointer,
            expected=definition.target_selector_value,
        ):
            raise ConflictError(
                "composition selection instance does not match owner selectors"
            )
        edge_identity = (
            *identity,
            selection.source_capability_instance_ref,
            selection.target_capability_instance_ref,
        )
        if edge_identity in edge_identities:
            raise ConflictError("composition selection edge is duplicated")
        edge_identities.add(edge_identity)
        injection_target = (
            selection.target_capability_instance_ref,
            definition.target_pointer,
        )
        if injection_target in injection_targets:
            raise ConflictError(
                "composition selections compete for one target instance pointer"
            )
        injection_targets.add(injection_target)
        selected_by_definition[identity].append(selection)
        result.append(
            {
                "binding_code": definition.binding_code,
                "source_capability_instance_ref": (
                    selection.source_capability_instance_ref
                ),
                "source_capability_id": definition.source_capability_id,
                "source_pointer": definition.source_pointer,
                "source_schema_ref": definition.source_schema_ref,
                "source_schema_digest": definition.source_schema_digest,
                "target_capability_instance_ref": (
                    selection.target_capability_instance_ref
                ),
                "target_capability_id": definition.target_capability_id,
                "target_pointer": definition.target_pointer,
                "target_schema_ref": definition.target_schema_ref,
                "target_schema_digest": definition.target_schema_digest,
                "source_selector_pointer": definition.source_selector_pointer,
                "source_selector_value": definition.source_selector_value,
                "target_selector_pointer": definition.target_selector_pointer,
                "target_selector_value": definition.target_selector_value,
                "coverage": definition.coverage,
                "required": definition.required,
                "composition_contract_ref": definition.composition_contract_ref,
                "composition_contract_digest": (definition.composition_contract_digest),
                "composition_contract_attestation_id": str(
                    definition.composition_contract_attestation_id
                ),
            }
        )

    for identity, definition in definition_index.items():
        matching_sources = {
            instance_ref
            for instance_ref, snapshot in capability_snapshots.items()
            if snapshot.get("capability_id") == definition.source_capability_id
            and _selector_matches(
                operation_inputs[instance_ref],
                pointer=definition.source_selector_pointer,
                expected=definition.source_selector_value,
            )
        }
        matching_targets = {
            instance_ref
            for instance_ref, snapshot in capability_snapshots.items()
            if snapshot.get("capability_id") == definition.target_capability_id
            and _selector_matches(
                operation_inputs[instance_ref],
                pointer=definition.target_selector_pointer,
                expected=definition.target_selector_value,
            )
        }
        edges = selected_by_definition[identity]
        if any(
            edge.source_capability_instance_ref not in matching_sources
            or edge.target_capability_instance_ref not in matching_targets
            for edge in edges
        ):
            raise ConflictError("composition selection is outside selector scope")
        if definition.coverage == "each_source_exactly_one":
            counts = {
                instance_ref: sum(
                    edge.source_capability_instance_ref == instance_ref
                    for edge in edges
                )
                for instance_ref in matching_sources
            }
        elif definition.coverage == "each_target_exactly_one":
            counts = {
                instance_ref: sum(
                    edge.target_capability_instance_ref == instance_ref
                    for edge in edges
                )
                for instance_ref in matching_targets
            }
        else:
            raise ConflictError("managed profile composition coverage is invalid")
        failures = sorted(ref for ref, count in counts.items() if count != 1)
        if failures:
            raise ConflictError(
                f"composition binding {definition.binding_code!r} does not satisfy "
                f"{definition.coverage}: {', '.join(failures)}"
            )

    return tuple(
        sorted(
            result,
            key=lambda item: (
                str(item["composition_contract_digest"]),
                str(item["binding_code"]),
                str(item["source_capability_instance_ref"]),
                str(item["target_capability_instance_ref"]),
            ),
        )
    )


def _selector_matches(
    operation_input: Mapping[str, object],
    *,
    pointer: str | None,
    expected: str | None,
) -> bool:
    if pointer is None and expected is None:
        return True
    if pointer is None or expected is None:
        raise ConflictError("managed profile contains an incomplete selector")
    document = operation_input.get("document")
    if not isinstance(document, Mapping):
        raise ConflictError("desired operation input snapshot is malformed")
    try:
        actual: object = document
        for encoded_token in pointer[1:].split("/"):
            token = encoded_token.replace("~1", "/").replace("~0", "~")
            if not isinstance(actual, Mapping) or token not in actual:
                return False
            actual = actual[token]
    except (AttributeError, TypeError) as exc:
        raise ConflictError("composition selector pointer is invalid") from exc
    return actual == expected


def _validate_configuration_value(
    field: ConfigurationFieldContract,
    value: ConfigurationScalar,
) -> ConfigurationScalar:
    value_type = CapabilityConfigValueType(field.value_type)
    value_format = CapabilityConfigValueFormat(field.value_format)
    invalid = f"configuration field {field.field_code!r} is invalid"
    if value_type is CapabilityConfigValueType.BOOLEAN:
        if type(value) is not bool:
            raise ConflictError(invalid)
    elif value_type is CapabilityConfigValueType.INTEGER:
        if type(value) is not int:
            raise ConflictError(invalid)
    elif value_type is CapabilityConfigValueType.DECIMAL:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is None
        ):
            raise ConflictError(invalid)
    elif value_type is CapabilityConfigValueType.STRING_LIST:
        if (
            not isinstance(value, tuple)
            or not value
            or len(set(value)) != len(value)
            or not all(isinstance(item, str) for item in value)
        ):
            raise ConflictError(invalid)
        value = tuple(sorted(value))
    elif value_type in {
        CapabilityConfigValueType.STRING,
        CapabilityConfigValueType.REFERENCE,
        CapabilityConfigValueType.SECRET_REFERENCE,
    }:
        if not isinstance(value, str):
            raise ConflictError(invalid)
    else:  # pragma: no cover - enum exhaustiveness guard
        raise ConflictError(invalid)

    if value_type is CapabilityConfigValueType.REFERENCE and (
        not isinstance(value, str) or _REFERENCE.fullmatch(value) is None
    ):
        raise ConflictError(f"{invalid}; a versioned reference is required")
    if value_type is CapabilityConfigValueType.SECRET_REFERENCE and (
        not isinstance(value, str) or _SECRET_REFERENCE.fullmatch(value) is None
    ):
        raise ConflictError(f"{invalid}; a versioned secret reference is required")

    if value_format is CapabilityConfigValueFormat.FQDN:
        if not isinstance(value, str) or not _is_fqdn(value):
            raise ConflictError(invalid)
    elif value_format is CapabilityConfigValueFormat.FQDN_LIST:
        if not isinstance(value, tuple) or any(not _is_fqdn(item) for item in value):
            raise ConflictError(invalid)
    elif value_format is CapabilityConfigValueFormat.HTTPS_URL:
        if not isinstance(value, str):
            raise ConflictError(invalid)
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ConflictError(invalid) from exc
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
            raise ConflictError(invalid)
    elif value_format in {
        CapabilityConfigValueFormat.BYTE_QUANTITY,
        CapabilityConfigValueFormat.NONNEGATIVE_INTEGER,
    }:
        if type(value) is not int or value < 0:
            raise ConflictError(invalid)
    elif value_format is CapabilityConfigValueFormat.POSITIVE_INTEGER:
        if type(value) is not int or value < 1:
            raise ConflictError(invalid)
    elif value_format is CapabilityConfigValueFormat.EMAIL_ADDRESS:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", value) is None
        ):
            raise ConflictError(invalid)
    elif value_format is CapabilityConfigValueFormat.STABLE_CODE:
        if not isinstance(value, str) or _INTERNAL_SOURCE.fullmatch(value) is None:
            raise ConflictError(invalid)
    return value


def _validate_desired_operation_inputs(
    inputs: tuple[CapabilityOperationInput, ...],
    *,
    apply_input_schemas: Mapping[str, CapabilitySchemaDocument],
    capability_snapshots: Mapping[str, Mapping[str, object]],
    composition_bindings: tuple[profiles.PrerequisiteEvidenceBindingContract, ...],
) -> dict[str, dict[str, object]]:
    supplied: dict[str, CapabilityOperationInput] = {}
    for item in inputs:
        if _VERSIONED_ID.fullmatch(item.capability_id) is None:
            raise ConflictError("desired operation input capability is not versioned")
        if not is_capability_instance_ref(item.capability_instance_ref):
            raise ConflictError("capability instance reference is not canonical")
        if item.capability_instance_ref in supplied:
            raise ConflictError("desired operation input instance is duplicated")
        supplied[item.capability_instance_ref] = item
    required = set(apply_input_schemas)
    if set(supplied) != required:
        missing = sorted(required - set(supplied))
        extra = sorted(set(supplied) - required)
        raise ConflictError(
            "desired operation inputs must exactly cover selected APPLY capabilities: "
            f"missing={missing}, extra={extra}"
        )
    target_pointers: dict[str, list[str]] = {}
    for binding in composition_bindings:
        for instance_ref, snapshot in capability_snapshots.items():
            if snapshot.get("capability_id") == binding.target_capability_id:
                target_pointers.setdefault(instance_ref, []).append(
                    binding.target_pointer
                )
    validated: dict[str, dict[str, object]] = {}
    for instance_ref in sorted(required):
        item = supplied[instance_ref]
        expected_capability_id = capability_snapshots[instance_ref].get("capability_id")
        if item.capability_id != expected_capability_id:
            raise ConflictError(
                f"desired operation instance {instance_ref!r} selects the wrong "
                "capability contract"
            )
        if item.component_code != capability_snapshots[instance_ref].get(
            "component_code"
        ):
            raise ConflictError(
                f"desired operation instance {instance_ref!r} selects the wrong "
                "commercial component"
            )
        try:
            document = validate_desired_operation_input(
                item.document,
                schema=apply_input_schemas[instance_ref],
                composition_target_pointers=target_pointers.get(instance_ref, ()),
            )
        except DesiredOperationInputError as exc:
            raise ConflictError(
                f"desired APPLY input for {instance_ref!r} is invalid: {exc}"
            ) from exc
        validated[instance_ref] = {
            "component_code": item.component_code,
            "capability_id": item.capability_id,
            "document": document,
        }
    return validated


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
    "CapabilityOperationInput",
    "ConfigurationSnapshotInput",
    "ConfigurationValue",
    "CreateDeploymentIntentCommand",
    "CreateDeploymentTargetCommand",
    "ReviseDeploymentDesiredStateCommand",
    "DeploymentDesiredStateView",
    "DeploymentIntentResult",
    "DeploymentTargetView",
    "DeploymentView",
    "create_deployment_target",
    "record_deployment_intent",
    "revise_deployment_desired_state",
]
