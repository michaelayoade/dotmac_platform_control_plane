"""Contract tests for reusable managed-service profile schemas."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from dotmac_kernel import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    PlatformAdmin,
    PlatformAuditEvent,
)
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.testing import create_test_engine, isolated_session
from sqlalchemy import select
from sqlalchemy.orm import Session

from vendor_cp.managed_profiles import catalogues, service
from vendor_cp.managed_profiles.feature import feature
from vendor_cp.managed_profiles.models import ManagedServiceProfileVersion


@pytest.fixture(scope="module", autouse=True)
def _declared_audit_actions() -> Iterator[None]:
    """Install this feature's declaration for service-only unit tests.

    `create_app` owns this installation in production.  These focused tests do
    not build an app, so they install the same manifest-derived registry and
    restore the exact prior process state afterwards.
    """

    import dotmac_kernel.audit_actions as registry_module

    try:
        previous = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous = None
    install_audit_actions(AuditActionRegistry.from_manifests((feature,)))
    try:
        yield
    finally:
        if previous is None:
            registry_module._active_registry = None
        else:
            install_audit_actions(previous)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_test_engine()
    try:
        with isolated_session(engine) as session:
            yield session
    finally:
        engine.dispose()


def _suite_command(**overrides: object) -> service.PublishProfileVersionCommand:
    values: dict[str, object] = {
        "commercial_product_code": "managed-suite",
        "profile_code": "managed-suite-standard",
        "version": 1,
        "schema_version": 1,
        "update_authority": "customer_approved",
        "compatible_predecessors": (),
    }
    values.update(overrides)
    return service.PublishProfileVersionCommand(**values)  # type: ignore[arg-type]


def test_catalogues_are_closed_provider_neutral_and_versioned() -> None:
    assert set(catalogues.PRODUCT_CATALOGUE) == {
        "managed-email",
        "managed-collaboration",
        "managed-business",
        "managed-sso",
        "managed-suite",
        "managed-academy",
    }
    assert set(catalogues.COMPONENT_CATALOGUE) == {
        "identity",
        "email",
        "collaboration",
        "business",
        "academy",
        "workspace",
    }
    assert not any(
        provider in capability.capability_code.lower()
        for capability in catalogues.CAPABILITY_CATALOGUE.values()
        for provider in ("keycloak", "mailcow", "nextcloud", "moodle")
    )
    assert all(
        capability.version >= 1
        and all(endpoint.version >= 1 for endpoint in capability.endpoints)
        for capability in catalogues.CAPABILITY_CATALOGUE.values()
    )


def test_profile_publish_command_cannot_accept_customer_selection_or_values() -> None:
    fields = set(service.PublishProfileVersionCommand.__dataclass_fields__)
    assert "selected_optional_components" not in fields
    assert "configuration" not in fields
    assert "configuration_snapshot" not in fields


def test_profile_is_full_reusable_allowed_graph_not_customer_desired_state() -> None:
    built = service.build_profile_version(_suite_command())

    assert built.allowed_optional_components == ("workspace",)
    required = {
        component.component_code for component in built.components if component.required
    }
    optional = {
        component.component_code
        for component in built.components
        if not component.required
    }
    assert required == {
        "academy",
        "business",
        "collaboration",
        "email",
        "identity",
    }
    assert optional == {"workspace"}
    assert "configuration" not in built.document
    assert built.document["allowed_optional_components"] == ["workspace"]
    assert built.document["content_schema"] == ("vendor.managed-service-profile@v1")
    assert {field.field_code for field in built.configuration_fields} >= {
        "customer_domain",
        "workspace_endpoint",
    }


def test_non_suite_profile_contains_own_component_and_dependency_closure() -> None:
    built = service.build_profile_version(
        service.PublishProfileVersionCommand(
            commercial_product_code="managed-email",
            profile_code="managed-email-standard",
            version=1,
            schema_version=1,
            update_authority="customer_approved",
        )
    )
    assert built.allowed_optional_components == ()
    assert built.component_codes == ("email", "identity")
    assert all(component.required for component in built.components)


@pytest.mark.parametrize(
    ("field_code", "value"),
    [
        ("customer_domain", "https://customer.example"),
        ("customer_domain", "Customer.Example"),
        ("identity_endpoint", "http://id.customer.example"),
        ("identity_endpoint", "https:///missing-host"),
        ("identity_admin_secret_ref", "reference:identity/admin@v1"),
        ("identity_admin_secret_ref", "plaintext-password"),
        ("identity_policy_ref", "secret:identity/policy@v1"),
    ],
)
def test_typed_schema_rejects_invalid_values(field_code: str, value: str) -> None:
    with pytest.raises(BadRequestError):
        catalogues.validate_configuration_value(field_code=field_code, value=value)


def test_publish_creates_content_addressed_immutable_schema(db: Session) -> None:
    first = service.publish_profile_version(db, _suite_command())
    assert first.content_hash.startswith("sha256:")
    assert first.allowed_optional_components == ("workspace",)

    row = db.get(ManagedServiceProfileVersion, first.id)
    assert row is not None
    row.document = {"tampered": True}
    with pytest.raises(ConflictError, match="immutable"):
        db.flush()


def test_profile_publication_is_audited_with_only_safe_contract_identity(
    db: Session,
) -> None:
    admin = PlatformAdmin(
        email="profile-publisher@dotmac.io", password_hash="x", is_active=True
    )
    db.add(admin)
    db.flush()
    published = service.publish_profile_version(
        db, _suite_command(actor_admin_id=admin.id)
    )

    event = db.execute(
        select(PlatformAuditEvent).where(
            PlatformAuditEvent.action == "vendor.managed_profile.published"
        )
    ).scalar_one()
    assert event.entity_id == str(published.id)
    assert event.actor_admin_id == admin.id
    assert event.details == {
        "commercial_product_code": "managed-suite",
        "profile_code": "managed-suite-standard",
        "version": 1,
        "content_hash": published.content_hash,
    }
    assert feature.audit_actions == ("vendor.managed_profile.published",)


def test_same_profile_version_cannot_be_republished(db: Session) -> None:
    service.publish_profile_version(db, _suite_command())
    with pytest.raises(ConflictError, match="already exists"):
        service.publish_profile_version(
            db,
            _suite_command(update_authority="offline"),
        )


def test_content_hash_changes_for_every_profile_owned_input() -> None:
    baseline = service.build_profile_version(_suite_command()).content_hash
    assert (
        service.build_profile_version(
            _suite_command(update_authority="vendor_automatic")
        ).content_hash
        != baseline
    )
    assert (
        service.build_profile_version(_suite_command(schema_version=2)).content_hash
        != baseline
    )


def test_compatible_predecessor_requires_exact_persisted_product_and_hash(
    db: Session,
) -> None:
    first = service.publish_profile_version(db, _suite_command())
    exact = service.CompatiblePredecessor(
        commercial_product_code=first.commercial_product_code,
        content_hash=first.content_hash,
    )
    second = service.publish_profile_version(
        db,
        _suite_command(
            version=2,
            update_authority="vendor_automatic",
            compatible_predecessors=(exact,),
        ),
    )
    assert second.compatible_predecessors == (exact,)

    with pytest.raises(NotFoundError, match="exact predecessor"):
        service.publish_profile_version(
            db,
            _suite_command(
                profile_code="bad-predecessor-product",
                version=2,
                compatible_predecessors=(
                    service.CompatiblePredecessor(
                        commercial_product_code="managed-email",
                        content_hash=first.content_hash,
                    ),
                ),
            ),
        )
    with pytest.raises(NotFoundError, match="exact predecessor"):
        service.publish_profile_version(
            db,
            _suite_command(
                profile_code="bad-predecessor-hash",
                version=2,
                compatible_predecessors=(
                    service.CompatiblePredecessor(
                        commercial_product_code="managed-suite",
                        content_hash="sha256:" + "0" * 64,
                    ),
                ),
            ),
        )


def test_update_authority_is_closed() -> None:
    for authority in ("vendor_automatic", "customer_approved", "offline"):
        assert (
            service.build_profile_version(
                _suite_command(update_authority=authority)
            ).update_authority
            == authority
        )
    with pytest.raises(BadRequestError, match="update authority"):
        service.build_profile_version(_suite_command(update_authority="automatic"))


def test_representative_suite_schema_covers_identity_and_all_managed_products() -> None:
    built = service.build_profile_version(_suite_command())
    checks = {check.check_code for check in built.verification_checks}
    assert {
        "identity.oidc.pkce_s256",
        "identity.oidc.aud_azp",
        "identity.binding.immutable",
        "identity.binding.takeover_refused",
        "identity.session.provenance_revocation",
        "business.oidc.login",
        "business.authorization",
        "email.dns.mx",
        "email.dns.spf",
        "email.dns.dkim",
        "email.dns.dmarc",
        "email.delivery.inbound",
        "email.delivery.outbound",
        "email.app_password",
        "collaboration.oidc.login",
        "collaboration.files.roundtrip",
        "academy.oidc.login",
        "academy.course.access",
        "workspace.oidc.login",
        "workspace.launcher.authorization",
    } <= checks
