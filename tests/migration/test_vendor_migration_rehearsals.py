"""Vendor migration rehearsals on real PostgreSQL (the AccountService
deployability gate).

Proves the `vendor_accounts` lineage the way production runs it: composed with
the kernel base lineage, migrated by `app_admin`, with the platform-catalog grant
boundary enforced by real roles. Each rehearsal provisions its OWN scratch
database so the composed `upgrade` runs end-to-end in isolation.

Requires the test Postgres cluster (roles + kernel schema) from `make test-db-up`;
skips when `TEST_DATABASE_URL` is unset.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from dotmac_kernel.prerequisites import installed_bindings
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from vendor_cp.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS
from vendor_cp.migrations import composed_version_locations, make_alembic_config

KERNEL_HEAD = "0026_platform_audit_log"  # current composed Starter source
PREVIOUS_KERNEL_HEAD = "0012_platform_outbox"  # former pin (0.1.0a9)
RELEASE_CATALOG_HEAD = "rl_0002_artifact_origin"  # current composed Starter source
ENTITLEMENT_ALLOCATION_HEAD = "ea_0001_allocations"
# A STATIC head of its own lineage — but not a version ROW once `v012` depends
# on it, because a `depends_on` edge makes its target an ancestor of the
# depending revision. `alembic_version` holds current heads, not every applied
# revision, so this appears in `script.get_heads()` and not in `_versions()`.
APPROVALS_HEAD = "ap_0001_approvals"
VENDOR_ROOT = "v001_vendor_accounts"
VENDOR_ROOT_DEP = "0009_platform_audit_inbox"  # what v001 depends_on
VENDOR_HEAD = "v017_integrator_evidence"

#: The vendor head as it stood BEFORE allocation authority moved.
#:
#: A rehearsal of "an existing deployment we are upgrading FROM" must name the
#: revision it means. `vendor@head` is an alias, and using it here silently
#: re-described the scenario every time the head advanced: once `v014` declared
#: `depends_on = ea_0001_allocations`, upgrading to `vendor@head` installed the
#: module lineage, so the "before modules" state the test set up was no longer
#: that state at all.
PREVIOUS_VENDOR_HEAD = "v013_approvals_authority_switch"


# `scratch_db` and the DSN rewriter MOVED to `tests/migration/conftest.py`.
# They were defined here, which meant the composed live-catalogue audit could
# not reuse them without importing across modules of a test PACKAGE — the
# import-path fragility that file's docstring already warns about. Both arrive
# as FIXTURES (`scratch_db`, `url_for`), which is that file's stated convention.


def _upgrade(url: str, target: str = "heads") -> None:
    command.upgrade(make_alembic_config(url), target)


def _q(url: str, sql: str, **params):
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        eng.dispose()


def _table_exists(url: str, table: str) -> bool:
    return bool(_q(url, "SELECT to_regclass('public.' || :t) IS NOT NULL", t=table))


def _qualified_table_exists(url: str, table: str) -> bool:
    return bool(_q(url, "SELECT to_regclass(:t) IS NOT NULL", t=table))


def _column_names(url: str, table: str) -> set[str]:
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name=:t"
                ),
                {"t": table},
            ).scalars()
            return set(rows)
    finally:
        eng.dispose()


def _versions(url: str) -> set[str]:
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            if not conn.execute(
                text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
            ).scalar():
                return set()
            return set(
                conn.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
    finally:
        eng.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 1 — fresh install
# ─────────────────────────────────────────────────────────────────────────────
def test_fresh_install_creates_vendor_accounts(scratch_db: str) -> None:
    _upgrade(scratch_db, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _table_exists(scratch_db, "offer_versions")
    # v013 DROPPED these: approval authority moved to the module, and the empty
    # legacy tables went with the writer that owned them.
    assert not _table_exists(scratch_db, "approval_policies")
    assert not _table_exists(scratch_db, "approval_records")
    assert _table_exists(scratch_db, "contracts")
    assert _table_exists(scratch_db, "contract_lines")
    # v014 DROPPED these: allocation authority moved to the module, and the
    # empty legacy tables went with the writer that owned them.
    assert not _table_exists(scratch_db, "allocations")
    assert not _table_exists(scratch_db, "allocation_entries")
    assert _table_exists(scratch_db, "managed_service_profile_versions")
    assert _table_exists(scratch_db, "deployment_targets")
    assert _table_exists(scratch_db, "deployments")
    assert _table_exists(scratch_db, "deployment_capability_instances")
    assert _table_exists(scratch_db, "deployment_desired_state_versions")
    assert _table_exists(scratch_db, "deployment_bundle_manifest_versions")
    assert _table_exists(scratch_db, "deployment_plans")
    assert _table_exists(scratch_db, "deployment_plan_approval_requests")
    assert _table_exists(scratch_db, "deployment_plan_approval_grants")
    assert _table_exists(scratch_db, "integrator_command_dispatches")
    assert _table_exists(scratch_db, "integrator_execution_receipts")
    assert "product_code" in _column_names(scratch_db, "offer_versions")
    assert "product_code" in _column_names(scratch_db, "contracts")
    # Kernel platform tables the AccountService depends on are present too.
    assert _table_exists(scratch_db, "platform_audit_events")
    assert _table_exists(scratch_db, "platform_idempotency_records")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_rel.artifact_attestations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocation_entries")
    cols = _column_names(scratch_db, "vendor_accounts")
    assert {
        "id",
        "external_ref",
        "display_name",
        "status",
        "created_at",
        "updated_at",
    } <= cols
    # PLATFORM catalog: no tenant_id, and RLS is NOT enabled.
    assert "tenant_id" not in cols
    assert not _q(
        scratch_db,
        "SELECT relrowsecurity FROM pg_class WHERE oid='vendor_accounts'::regclass",
    )
    for table in (
        "managed_service_profile_versions",
        "deployment_targets",
        "deployments",
        "deployment_capability_instances",
        "deployment_desired_state_versions",
        "deployment_bundle_manifest_versions",
        "deployment_plans",
        "deployment_plan_approval_requests",
        "deployment_plan_approval_grants",
        "integrator_command_dispatches",
        "integrator_execution_receipts",
    ):
        assert "tenant_id" not in _column_names(scratch_db, table)
        assert not _q(
            scratch_db,
            "SELECT relrowsecurity FROM pg_class " "WHERE oid=CAST(:table AS regclass)",
            table=f"public.{table}",
        )
    # VERSION ROWS, which are not the same set as the static heads.
    #
    # `alembic_version` holds current heads only, and a `depends_on` edge makes
    # its target an ANCESTOR of the depending revision rather than a head in its
    # own right. `v012` depends on `ap_0001_approvals` and `v014` on
    # `ea_0001_allocations`, so both module revisions — while genuinely applied —
    # stop being version ROWS once the vendor lineage reaches them.
    #
    # They are still static heads, and `test_five_head_topology` asserts all five
    # through `script.get_heads()`. Listing them here as well would report them
    # missing on a perfectly complete database.
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


def test_alembic_env_installs_the_vendor_prerequisite_bindings(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db, "heads")

    assert installed_bindings() == ASSEMBLY_PREREQUISITE_BINDINGS


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 2 — five-head topology
# ─────────────────────────────────────────────────────────────────────────────
def test_five_head_topology(scratch_db: str) -> None:
    script = ScriptDirectory.from_config(make_alembic_config(scratch_db))
    assert set(script.get_heads()) == {
        KERNEL_HEAD,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        APPROVALS_HEAD,
        VENDOR_HEAD,
    }
    kernel_head = script.get_revision("kernel@head")
    vendor_head = script.get_revision("vendor@head")
    release_catalog_head = script.get_revision("release_catalog@head")
    allocation_head = script.get_revision("entitlement_allocation@head")
    assert kernel_head.revision == KERNEL_HEAD
    assert vendor_head.revision == VENDOR_HEAD
    assert release_catalog_head.revision == RELEASE_CATALOG_HEAD
    assert allocation_head.revision == ENTITLEMENT_ALLOCATION_HEAD
    # The vendor head is the tip of a single-parent chain that walks back to the
    # vendor ROOT; the ROOT is its own branch that DEPENDS ON (is not a child of)
    # a kernel head, so the lineages advance independently.
    node = vendor_head
    while node.down_revision is not None:
        assert isinstance(node.down_revision, str)  # linear vendor lineage
        node = script.get_revision(node.down_revision)
    assert node.revision == VENDOR_ROOT
    root = node
    assert root.down_revision is None
    deps = root.dependencies
    deps = (deps,) if isinstance(deps, str) else tuple(deps or ())
    assert VENDOR_ROOT_DEP in deps


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 3 — platform-role access, tenant-role denial
# ─────────────────────────────────────────────────────────────────────────────
def test_platform_role_access_and_tenant_role_denial(
    scratch_db: str, url_for: Callable[..., str]
) -> None:
    _upgrade(scratch_db, "heads")

    # platform_api may INSERT + SELECT vendor_accounts.
    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) "
                    "VALUES (gen_random_uuid(), 'r1', 'Acme', 'active')"
                )
            )
        with plat.connect() as conn:
            assert (
                conn.execute(text("SELECT count(*) FROM vendor_accounts")).scalar() == 1
            )
    finally:
        plat.dispose()

    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM mod_ealloc.allocations")
                ).scalar()
                == 0
            )
    finally:
        plat.dispose()

    # The module is a platform catalogue. The online platform role can read it,
    # while the product data-plane role is denied below.
    plat = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="platform_api")
    )
    try:
        with plat.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM mod_rel.release_artifacts")
                ).scalar()
                == 0
            )
    finally:
        plat.dispose()

    # app_user (tenant application role) may NOT even SELECT — REVOKEd. Each check
    # uses a FRESH connection: a permission error aborts the transaction, so a
    # second statement on the same connection would fail as "transaction aborted"
    # rather than "permission denied".
    appu = create_engine(
        url_for(scratch_db, scratch_db.rsplit("/", 1)[1], user="app_user")
    )
    try:
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text("SELECT count(*) FROM vendor_accounts")).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text(
                        "INSERT INTO vendor_accounts (id, external_ref, display_name) "
                        "VALUES (gen_random_uuid(), 'x', 'y')"
                    )
                )
        # The WS8 licence tables carried the same REVOKE, proven here by a
        # ten-name literal list. That list is GONE: it covered the tables
        # someone remembered, so every later migration silently widened the gap
        # between what shipped and what was checked.
        #
        # `test_composed_live_catalog.py` now sweeps EVERY vendor-owned table,
        # derived by diffing `public` across the two lineages, for all seven
        # PostgreSQL table privileges including the column-level ones. One
        # licence table stays here as the live-connection counterpart: the
        # sweep reads `has_table_privilege`, and this proves a real connection
        # is refused, so a catalogue that lied would not pass both.
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text("SELECT count(*) FROM licences")).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT count(*) FROM mod_rel.release_artifacts")
                ).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT count(*) FROM mod_ealloc.allocations")
                ).scalar()
        with appu.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text("SELECT count(*) FROM deployments")).scalar()
    finally:
        appu.dispose()


def test_v015_profile_and_desired_state_are_database_immutable(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db, "heads")
    ids = {
        name: str(uuid.uuid4())
        for name in (
            "account",
            "profile",
            "target",
            "deployment",
            "instance",
            "desired",
        )
    }
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) "
                    "VALUES (:id, 'immutable-canary', 'Immutable', 'active')"
                ),
                {"id": ids["account"]},
            )
            conn.execute(
                text(
                    "INSERT INTO managed_service_profile_versions "
                    "(id, profile_code, version, schema_version, "
                    "commercial_product_code, content_hash, document) VALUES "
                    "(:id, 'immutable', 1, 1, 'managed-collaboration', "
                    ":hash, CAST('{}' AS jsonb))"
                ),
                {"id": ids["profile"], "hash": "sha256:" + "a" * 64},
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_targets "
                    "(id, account_id, target_ref, display_name, region_code) "
                    "VALUES (:id, :account, 'immutable', 'Immutable', 'ng-abuja')"
                ),
                {"id": ids["target"], "account": ids["account"]},
            )
            conn.execute(
                text(
                    "INSERT INTO deployments "
                    "(id, account_id, target_id, deployment_ref, "
                    "commercial_product_code, internal_source_code) VALUES "
                    "(:id, :account, :target, 'immutable', "
                    "'managed-collaboration', 'dotmac.canary')"
                ),
                {
                    "id": ids["deployment"],
                    "account": ids["account"],
                    "target": ids["target"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_desired_state_versions "
                    "(id, deployment_id, revision, profile_version_id, profile_code, "
                    "profile_version, profile_content_hash, commercial_product_code, "
                    "update_authority, selected_components, selected_capabilities, "
                    "selected_operations, selected_verification_checks, "
                    "configuration_snapshot, desired_operation_inputs, "
                    "selected_composition_edges, "
                    "configuration_snapshot_ref, "
                    "configuration_schema_version, configuration_hash, "
                    "desired_state_hash) VALUES "
                    "(:id, :deployment, 1, :profile, 'immutable', 1, :profile_hash, "
                    "'managed-collaboration', 'customer_approved', "
                    "CAST('[]' AS jsonb), CAST('[]' AS jsonb), CAST('[]' AS jsonb), "
                    "CAST('[]' AS jsonb), CAST('{}' AS jsonb), CAST('{}' AS jsonb), "
                    "CAST('[]' AS jsonb), "
                    "'config:canary@v1', "
                    "1, :configuration_hash, :desired_hash)"
                ),
                {
                    "id": ids["desired"],
                    "deployment": ids["deployment"],
                    "profile": ids["profile"],
                    "profile_hash": "sha256:" + "a" * 64,
                    "configuration_hash": "sha256:" + "b" * 64,
                    "desired_hash": "sha256:" + "c" * 64,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_capability_instances "
                    "(id, deployment_id, capability_instance_ref) VALUES "
                    "(:id, :deployment, 'identity.realm')"
                ),
                {"id": ids["instance"], "deployment": ids["deployment"]},
            )

        with engine.connect() as conn:
            with pytest.raises(DBAPIError, match="profile versions are immutable"):
                conn.execute(
                    text(
                        "UPDATE managed_service_profile_versions "
                        "SET profile_code='mutated' WHERE id=CAST(:id AS uuid)"
                    ),
                    {"id": ids["profile"]},
                )
        with engine.connect() as conn:
            with pytest.raises(
                DBAPIError, match="desired-state versions are immutable"
            ):
                conn.execute(
                    text(
                        "UPDATE deployment_desired_state_versions SET revision=2 "
                        "WHERE id=CAST(:id AS uuid)"
                    ),
                    {"id": ids["desired"]},
                )
        with engine.connect() as conn:
            with pytest.raises(DBAPIError, match="capability instances are immutable"):
                conn.execute(
                    text(
                        "UPDATE deployment_capability_instances "
                        "SET capability_instance_ref='identity.other' "
                        "WHERE id=CAST(:id AS uuid)"
                    ),
                    {"id": ids["instance"]},
                )
        with engine.connect() as conn:
            with pytest.raises(DBAPIError, match="uq_deployment_capability"):
                conn.execute(
                    text(
                        "INSERT INTO deployment_capability_instances "
                        "(id, deployment_id, capability_instance_ref) VALUES "
                        "(:id, :deployment, 'identity.realm')"
                    ),
                    {"id": str(uuid.uuid4()), "deployment": ids["deployment"]},
                )
        with engine.connect() as conn:
            with pytest.raises(DBAPIError, match="ck_deployment_capability"):
                conn.execute(
                    text(
                        "INSERT INTO deployment_capability_instances "
                        "(id, deployment_id, capability_instance_ref) VALUES "
                        "(:id, :deployment, 'Identity__Realm')"
                    ),
                    {"id": str(uuid.uuid4()), "deployment": ids["deployment"]},
                )
    finally:
        engine.dispose()


def test_v016_v017_plan_approval_and_integrator_evidence_are_database_immutable(
    scratch_db: str,
) -> None:
    _upgrade(scratch_db, "heads")
    ids = {
        name: str(uuid.uuid4())
        for name in (
            "account",
            "profile",
            "target",
            "deployment",
            "instance",
            "desired",
            "bundle",
            "plan",
            "request",
            "authority_request",
            "grant",
            "dispatch",
            "receipt",
            "operation",
        )
    }
    hashes = {
        name: "sha256:" + fill * 64
        for name, fill in zip(
            (
                "profile",
                "desired",
                "configuration",
                "bundle",
                "plan",
                "request",
                "grant",
                "dispatch",
                "receipt",
                "module_receipt",
                "module_plan",
            ),
            "abcdef12345",
            strict=True,
        )
    }
    engine = create_engine(scratch_db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) VALUES "
                    "(:id, 'plan-immutable', 'Plan immutable', 'active')"
                ),
                {"id": ids["account"]},
            )
            conn.execute(
                text(
                    "INSERT INTO managed_service_profile_versions "
                    "(id, profile_code, version, schema_version, "
                    "commercial_product_code, content_hash, document) VALUES "
                    "(:id, 'plan-immutable', 1, 1, 'managed-sso', :hash, '{}'::jsonb)"
                ),
                {"id": ids["profile"], "hash": hashes["profile"]},
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_targets "
                    "(id, account_id, target_ref, display_name, region_code) VALUES "
                    "(:id, :account, 'plan-immutable', 'Plan immutable', 'ng-abuja')"
                ),
                {"id": ids["target"], "account": ids["account"]},
            )
            conn.execute(
                text(
                    "INSERT INTO deployments "
                    "(id, account_id, target_id, deployment_ref, "
                    "commercial_product_code, internal_source_code) VALUES "
                    "(:id, :account, :target, 'plan-immutable', "
                    "'managed-sso', 'dotmac.canary')"
                ),
                {
                    "id": ids["deployment"],
                    "account": ids["account"],
                    "target": ids["target"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_capability_instances "
                    "(id, deployment_id, capability_instance_ref) VALUES "
                    "(:id, :deployment, 'identity.realm')"
                ),
                {"id": ids["instance"], "deployment": ids["deployment"]},
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_desired_state_versions "
                    "(id, deployment_id, revision, profile_version_id, profile_code, "
                    "profile_version, profile_content_hash, commercial_product_code, "
                    "update_authority, selected_components, selected_capabilities, "
                    "selected_operations, selected_verification_checks, "
                    "configuration_snapshot, desired_operation_inputs, "
                    "selected_composition_edges, "
                    "configuration_snapshot_ref, "
                    "configuration_schema_version, configuration_hash, "
                    "desired_state_hash) VALUES "
                    "(:id, :deployment, 1, :profile, 'plan-immutable', 1, "
                    ":profile_hash, 'managed-sso', 'customer_approved', '[]'::jsonb, "
                    "'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb, "
                    "'{}'::jsonb, '[]'::jsonb, "
                    "'config:canary@v1', 1, :configuration_hash, :desired_hash)"
                ),
                {
                    "id": ids["desired"],
                    "deployment": ids["deployment"],
                    "profile": ids["profile"],
                    "profile_hash": hashes["profile"],
                    "configuration_hash": hashes["configuration"],
                    "desired_hash": hashes["desired"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_bundle_manifest_versions "
                    "(id, profile_version_id, bundle_code, version, "
                    "profile_content_hash, content_hash, document) VALUES "
                    "(:id, :profile, 'canary', 1, :profile_hash, :hash, '{}'::jsonb)"
                ),
                {
                    "id": ids["bundle"],
                    "profile": ids["profile"],
                    "profile_hash": hashes["profile"],
                    "hash": hashes["bundle"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_plans "
                    "(id, deployment_id, revision, desired_state_version_id, "
                    "bundle_manifest_version_id, plan_hash, document) VALUES "
                    "(:id, :deployment, 1, :desired, :bundle, :hash, '{}'::jsonb)"
                ),
                {
                    "id": ids["plan"],
                    "deployment": ids["deployment"],
                    "desired": ids["desired"],
                    "bundle": ids["bundle"],
                    "hash": hashes["plan"],
                },
            )
            conn.execute(
                text(
                    "UPDATE deployments SET current_plan_id=:plan, "
                    "latest_plan_revision=1 WHERE id=:deployment"
                ),
                {"plan": ids["plan"], "deployment": ids["deployment"]},
            )
            conn.execute(
                text(
                    "INSERT INTO integrator_command_dispatches "
                    "(id, plan_id, deployment_id, capability_instance_ref, "
                    "capability_binding_id, operation, command_id, "
                    "request_body_digest, envelope_digest, document) "
                    "VALUES (:id, :plan, :deployment, 'identity.realm', "
                    ":binding, 'apply', "
                    "'immutable-dispatch', :body_hash, :envelope_hash, '{}'::jsonb)"
                ),
                {
                    "id": ids["dispatch"],
                    "plan": ids["plan"],
                    "deployment": ids["deployment"],
                    "binding": ids["operation"],
                    "body_hash": hashes["dispatch"],
                    "envelope_hash": hashes["receipt"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO integrator_execution_receipts "
                    "(id, dispatch_id, plan_id, deployment_id, "
                    "capability_instance_ref, capability_binding_id, operation, "
                    "command_id, "
                    "request_body_digest, receipt_digest, outcome, operation_id, "
                    "latest_module_receipt_sequence, latest_module_receipt_hash, "
                    "occurred_at, document) VALUES "
                    "(:id, :dispatch, :plan, :deployment, 'identity.realm', "
                    ":binding, 'apply', "
                    "'immutable-dispatch', :body_hash, :receipt_hash, 'succeeded', "
                    ":operation_id, 1, :module_hash, now(), '{}'::jsonb)"
                ),
                {
                    "id": ids["receipt"],
                    "dispatch": ids["dispatch"],
                    "plan": ids["plan"],
                    "deployment": ids["deployment"],
                    "binding": ids["operation"],
                    "body_hash": hashes["dispatch"],
                    "receipt_hash": hashes["receipt"],
                    "operation_id": ids["operation"],
                    "module_hash": hashes["module_receipt"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_plan_approval_requests "
                    "(id, plan_id, approval_request_id, policy_code, policy_version, "
                    "expires_at, request_binding_hash, document) VALUES "
                    "(:id, :plan, :authority, 'canary', 1, now() + interval '1 hour', "
                    ":hash, '{}'::jsonb)"
                ),
                {
                    "id": ids["request"],
                    "plan": ids["plan"],
                    "authority": ids["authority_request"],
                    "hash": hashes["request"],
                },
            )
            conn.execute(
                text(
                    "INSERT INTO deployment_plan_approval_grants "
                    "(id, plan_id, approval_request_binding_id, approval_request_id, "
                    "expires_at, grant_digest, document) VALUES "
                    "(:id, :plan, :request, :authority, now() + interval '1 hour', "
                    ":hash, '{}'::jsonb)"
                ),
                {
                    "id": ids["grant"],
                    "plan": ids["plan"],
                    "request": ids["request"],
                    "authority": ids["authority_request"],
                    "hash": hashes["grant"],
                },
            )

        for statement, row_id in (
            (
                "UPDATE deployment_bundle_manifest_versions "
                "SET updated_at=now() WHERE id=:id",
                ids["bundle"],
            ),
            (
                "UPDATE deployment_plans SET updated_at=now() WHERE id=:id",
                ids["plan"],
            ),
            (
                "UPDATE deployment_plan_approval_requests "
                "SET updated_at=now() WHERE id=:id",
                ids["request"],
            ),
            (
                "UPDATE deployment_plan_approval_grants "
                "SET updated_at=now() WHERE id=:id",
                ids["grant"],
            ),
            (
                "UPDATE integrator_command_dispatches SET updated_at=now() "
                "WHERE id=:id",
                ids["dispatch"],
            ),
            (
                "UPDATE integrator_execution_receipts SET updated_at=now() "
                "WHERE id=:id",
                ids["receipt"],
            ),
        ):
            with engine.connect() as conn:
                with pytest.raises(DBAPIError, match="rows are immutable"):
                    conn.execute(text(statement), {"id": row_id})
    finally:
        engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 4 — upgrade from a kernel-only database
# ─────────────────────────────────────────────────────────────────────────────
def test_upgrade_from_kernel_only(scratch_db: str) -> None:
    # An existing deployment on the kernel schema but without the vendor lineage.
    _upgrade(scratch_db, "kernel@head")
    assert _table_exists(scratch_db, "platform_admins")
    assert not _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {KERNEL_HEAD}

    # Deploy the vendor and module lineages on top — data-safe.
    _upgrade(scratch_db, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _table_exists(scratch_db, "offer_versions")
    assert _table_exists(scratch_db, "contracts")
    # The module owns approvals now; the legacy tables are created by v003 and
    # dropped again by v013 within the same composed upgrade.
    assert not _table_exists(scratch_db, "approval_policies")
    assert _qualified_table_exists(
        scratch_db, "mod_approvals.platform_approval_requests"
    )
    # Allocations moved to the module too (v014); the legacy tables are created
    # by v005 and dropped again within the same composed upgrade.
    assert not _table_exists(scratch_db, "allocations")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _table_exists(scratch_db, "managed_service_profile_versions")
    assert _table_exists(scratch_db, "deployment_targets")
    assert _table_exists(scratch_db, "deployment_capability_instances")
    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


def test_upgrade_from_previous_vendor_deployment_preserves_data(
    scratch_db: str,
) -> None:
    """Rehearse a9 + vendor v010 to a45 + both installed module lineages."""
    _upgrade(scratch_db, PREVIOUS_VENDOR_HEAD)
    _upgrade(scratch_db, PREVIOUS_KERNEL_HEAD)
    assert _versions(scratch_db) == {PREVIOUS_KERNEL_HEAD, PREVIOUS_VENDOR_HEAD}
    assert not _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert not _qualified_table_exists(scratch_db, "mod_ealloc.allocations")

    account_id = str(uuid.uuid4())
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO vendor_accounts "
                    "(id, external_ref, display_name, status) "
                    "VALUES (:id, 'pre-module', 'Existing Vendor', 'active')"
                ),
                {"id": account_id},
            )
    finally:
        eng.dispose()

    _upgrade(scratch_db, "heads")

    assert _qualified_table_exists(scratch_db, "mod_rel.release_artifacts")
    assert _qualified_table_exists(scratch_db, "mod_ealloc.allocations")
    assert (
        _q(
            scratch_db,
            "SELECT count(*) FROM vendor_accounts WHERE id = CAST(:id AS uuid)",
            id=account_id,
        )
        == 1
    )
    assert _versions(scratch_db) == {
        KERNEL_HEAD,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Rehearsal 5 — kernel advance keeps the vendor head independent
# ─────────────────────────────────────────────────────────────────────────────
def test_kernel_advance_keeps_vendor_head_independent(
    scratch_db: str, tmp_path: Path
) -> None:
    """Simulate a FUTURE kernel migration (a child of the kernel head). The
    vendor and module heads must remain separate heads — and a composed upgrade
    must still apply all four lineages."""
    synth_rev = "9999_synthetic_kernel_advance"
    (tmp_path / f"{synth_rev}.py").write_text(
        "revision = '9999_synthetic_kernel_advance'\n"
        f"down_revision = '{KERNEL_HEAD}'\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "def upgrade():\n    pass\n"
        "def downgrade():\n    pass\n"
    )
    cfg = make_alembic_config(scratch_db)
    cfg.set_main_option(
        "version_locations", f"{composed_version_locations()} {tmp_path}"
    )
    script = ScriptDirectory.from_config(cfg)
    # Kernel advances independently; the vendor and module heads are untouched.
    assert set(script.get_heads()) == {
        synth_rev,
        ENTITLEMENT_ALLOCATION_HEAD,
        RELEASE_CATALOG_HEAD,
        APPROVALS_HEAD,
        VENDOR_HEAD,
    }

    command.upgrade(cfg, "heads")
    assert _table_exists(scratch_db, "vendor_accounts")
    assert _versions(scratch_db) == {
        synth_rev,
        RELEASE_CATALOG_HEAD,
        VENDOR_HEAD,
    }


# ─────────────────────────────────────────────────────────────────────────────
# v010 — legacy deliveries created before the destination boundary
# ─────────────────────────────────────────────────────────────────────────────


def test_v010_quarantines_legacy_deliveries_including_active_ones(
    scratch_db: str,
) -> None:
    """A v009-era delivery has no resolved destination. Both the in-flight and
    the ACTIVE ones must be parked.

    `active` is the case that matters: it was established under the previous
    semantics, where an acknowledgement needed no proven deployment identity,
    so it records only that someone claimed the licence was applied. Leaving it
    active would preserve exactly the unproven authority v010 exists to remove
    — and it would never be re-examined, because active rows are excluded from
    replay.
    """
    _upgrade(scratch_db, "v009_delivery_attempts")

    eng = create_engine(scratch_db)
    ids = {k: str(uuid.uuid4()) for k in ("target", "lic", "iss", "d1", "d2", "c", "a")}
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO licences (id, customer_ref, product, generation) "
                    "VALUES (:id, 'cust-legacy', 'dotmac-sub', 1)"
                ),
                {"id": ids["lic"]},
            )
            # Seeded, because at the v009 state this rehearsal builds,
            # `licence_issuances.allocation_id` still carries a real foreign key
            # to `public.allocations`. `v014` later drops that constraint and the
            # table with it — but this test is standing at v009, where the
            # constraint exists and must be satisfied.
            conn.execute(
                text(
                    "INSERT INTO contracts (id, customer_ref, legal_entity, "
                    "currency_code, term_start, term_end, status, content_hash) "
                    "VALUES (:id, 'cust-legacy', 'Dotmac Ltd', 'USD', "
                    "'2026-01-01', '2026-12-31', 'active', 'h')"
                ),
                {"id": ids["c"]},
            )
            conn.execute(
                text(
                    "INSERT INTO allocations (id, contract_id, customer_ref, "
                    "content_hash, status, source_event_id) VALUES "
                    "(:id, :c, 'cust-legacy', 'h', 'staged', 'evt')"
                ),
                {"id": ids["a"], "c": ids["c"]},
            )
            conn.execute(
                text(
                    "INSERT INTO licence_issuances (id, licence_id, allocation_id, "
                    "version, digest, key_id, envelope, status) VALUES "
                    "(:id, :lic, :a, 1, 'sha256:x', 'k', '{}'::jsonb, 'issued')"
                ),
                {"id": ids["iss"], "lic": ids["lic"], "a": ids["a"]},
            )
            for key, state in (("d1", "delivered"), ("d2", "active")):
                conn.execute(
                    text(
                        "INSERT INTO licence_deliveries (id, issuance_id, target_ref) "
                        "VALUES (:id, :iss, :ref)"
                    ),
                    {"id": ids[key], "iss": ids["iss"], "ref": f"legacy-{key}"},
                )
                conn.execute(
                    text(
                        "INSERT INTO licence_delivery_states "
                        "(id, delivery_id, state) VALUES (:id, :d, :state)"
                    ),
                    {"id": str(uuid.uuid4()), "d": ids[key], "state": state},
                )

        # v010 EXACTLY, which is what this test is named for and all it needs.
        #
        # Driving it to `heads` would drag `v014`'s greenfield precondition into
        # a test about delivery quarantine: the allocation row seeded above for
        # v009's foreign key is precisely what `v014` fails closed on. The two
        # requirements are irreconcilable at `heads` and neither is wrong — they
        # just belong to different points in the lineage, which is what naming
        # the target keeps straight.
        _upgrade(scratch_db, "v010_delivery_hardening")

        with eng.connect() as conn:
            states = dict(
                conn.execute(
                    text(
                        "SELECT delivery_id, state FROM licence_delivery_states "
                        "WHERE delivery_id = ANY(:ids)"
                    ),
                    {"ids": [ids["d1"], ids["d2"]]},
                ).all()
            )
        assert states[uuid.UUID(ids["d1"])] == "parked"
        # The important one: an ACTIVE legacy row is quarantined too.
        assert states[uuid.UUID(ids["d2"])] == "parked"
    finally:
        eng.dispose()


def test_v010_check_constraint_rejects_a_new_delivery_without_a_target(
    scratch_db: str,
) -> None:
    """Existing rows are tolerated (NOT VALID) but every NEW row must carry a
    destination — otherwise the boundary would only apply to code paths that
    remembered to enforce it."""
    _upgrade(scratch_db, "heads")
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            with pytest.raises(DBAPIError, match="ck_licence_delivery_has_target"):
                conn.execute(
                    text(
                        "INSERT INTO licence_deliveries (id, issuance_id, target_ref) "
                        "VALUES (gen_random_uuid(), gen_random_uuid(), 'x')"
                    )
                )
    finally:
        eng.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# v011 — product identity expand stage
# ─────────────────────────────────────────────────────────────────────────────


def test_v011_preserves_historical_rows_as_explicitly_unclassified(
    scratch_db: str,
) -> None:
    """The migration may not invent a default product for existing commerce."""
    _upgrade(scratch_db, "v010_delivery_hardening")
    offer_id = str(uuid.uuid4())
    contract_id = str(uuid.uuid4())
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO offer_versions "
                    "(id, offer_code, version, amount, currency_code, "
                    "capability_codes) VALUES "
                    "(:id, 'legacy', 1, '10.00', 'USD', '[\"cap.a\"]'::jsonb)"
                ),
                {"id": offer_id},
            )
            conn.execute(
                text(
                    "INSERT INTO contracts (id, customer_ref, legal_entity, "
                    "currency_code, term_start, term_end, status) VALUES "
                    "(:id, 'cust', 'Dotmac Ltd', 'USD', '2026-01-01', "
                    "'2026-12-31', 'draft')"
                ),
                {"id": contract_id},
            )

        _upgrade(scratch_db, "heads")

        with eng.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT product_code FROM offer_versions WHERE id=:id"),
                    {"id": offer_id},
                ).scalar_one()
                is None
            )
            assert (
                conn.execute(
                    text("SELECT product_code FROM contracts WHERE id=:id"),
                    {"id": contract_id},
                ).scalar_one()
                is None
            )
    finally:
        eng.dispose()


def test_v011_offer_identity_is_product_qualified_in_postgres(scratch_db: str) -> None:
    _upgrade(scratch_db, "heads")
    eng = create_engine(scratch_db)
    try:
        with eng.begin() as conn:
            for product in ("dotmac-sub", "dotmac-erp"):
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, product_code, offer_code, version, amount, "
                        "currency_code, capability_codes) VALUES "
                        "(gen_random_uuid(), :product, 'pro', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    ),
                    {"product": product},
                )
            with pytest.raises(DBAPIError, match="uq_offer_versions_product_code_ver"):
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, product_code, offer_code, version, amount, "
                        "currency_code, capability_codes) VALUES "
                        "(gen_random_uuid(), 'dotmac-sub', 'pro', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    )
                )
    finally:
        eng.dispose()


def test_v011_rejects_new_unclassified_commercial_rows(scratch_db: str) -> None:
    """NOT VALID preserves history; it still governs every new write."""
    _upgrade(scratch_db, "heads")
    eng = create_engine(scratch_db)
    try:
        with pytest.raises(DBAPIError, match="ck_offer_versions_product_identity"):
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO offer_versions "
                        "(id, offer_code, version, amount, currency_code, "
                        "capability_codes) VALUES "
                        "(gen_random_uuid(), 'unclassified', 1, '10.00', "
                        "'USD', '[]'::jsonb)"
                    )
                )
        with pytest.raises(DBAPIError, match="ck_contracts_product_identity"):
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO contracts (id, customer_ref, legal_entity, "
                        "currency_code, term_start, term_end, status) VALUES "
                        "(gen_random_uuid(), 'cust', 'Dotmac Ltd', 'USD', "
                        "'2026-01-01', '2026-12-31', 'draft')"
                    )
                )
    finally:
        eng.dispose()
