"""Real installed Control a14, real signatures, real migrated PostgreSQL.

Every issuer/standing/revocation/consumption/target/plan call below --
including the `_seed` helper -- runs against the `engine` fixture, which is
`platform_api`: the real online CP runtime role `dc_0014` actually grants the
rehearsal-issuer ledger to. Raw-SQL structural checks and the sensitivity
proofs below use `admin_engine` (the migrator/table-owner) instead, since
those need privileges no online runtime role should hold.
"""

# ruff: noqa: S101

from __future__ import annotations

import base64
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    TargetTransitionCommand,
    approve_plan,
    propose_plan,
    register_target,
    set_desired_state,
    suspend_target,
)
from dotmac_deployment_control.models import RehearsalIssuerAuthorizationRecord
from dotmac_deployment_control.rehearsal_harness_evidence import (
    RehearsalHarnessEvidenceRefusalCode,
    RehearsalHarnessEvidenceRefusedError,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    RehearsalIssuerAuthorizationRefusalCode,
    RehearsalIssuerAuthorizationStanding,
    RehearsalIssuerAuthorizationStandingResult,
    RehearsalIssuerAuthorizationV1,
)
from dotmac_deployment_control.rehearsal_issuer_issuance import (
    RehearsalIssuerIssuanceRefusalCode,
    RehearsalIssuerIssuanceRefusedError,
    rehearsal_issuer_standing_for,
    revoke_rehearsal_issuer_authorization,
    stage_rehearsal_issuer_consumption,
)
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from rehearsal_issuer_harness.runtime import issue_from_leaf
from rehearsal_issuer_harness.security import AuthorizationSecurity, HarnessSecurity
from vendor_cp.deployment.rehearsal_issuer_seam import (
    RehearsalIssuerCommand,
    RehearsalIssuerInvocation,
)

_DIGEST = "sha256:" + "ab" * 32
_PLAN = "sha256:" + "cd" * 32


def _id() -> str:
    return uuid.uuid4().hex


def _seed(
    engine: Engine,
    *,
    environment: str = "rehearsal",
    approve: bool = True,
    suspend: bool = False,
) -> tuple[str, uuid.UUID]:
    suffix = _id()
    target_ref = f"issuer-harness-{suffix}"
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=_id(),
                target_ref=target_ref,
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment=environment,
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_id(),
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@rehearsal", spec={"replicas": 1}, images=[]
                ),
            ),
        )
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=_id(),
                target_id=target.id,
                operation="deploy",
                descriptor_digest=_DIGEST,
                execution_plan_digest=_PLAN,
                requires_approval=True,
                approval_policy_code="deployment.production",
                approval_policy_version=1,
            ),
        )
        if approve:
            approve_plan(
                db,
                ApprovePlanCommand(
                    command_id=_id(),
                    plan_id=plan.id,
                    evidence=ApprovalEvidence(
                        policy_code="deployment.production",
                        policy_version=1,
                        decision_ref=f"decision-{suffix}",
                        content_digest=plan.plan_digest or "",
                        decided_at=datetime.now(UTC),
                        operation="deploy",
                        execution_plan_digest=_PLAN,
                        decision_status="granted",
                    ),
                ),
            )
        if suspend:
            suspend_target(
                db,
                TargetTransitionCommand(command_id=_id(), target_id=target.id),
            )
        db.commit()
    return target_ref, plan.id


def _evidence(
    harness: HarnessSecurity,
    target_ref: str,
    *,
    lease: str | None = None,
    issued_at: datetime | None = None,
    controller: str | None = None,
) -> tuple[str, dict[str, object]]:
    lease_id = lease or f"lease-{_id()}"
    return lease_id, harness.document(
        lease_id=lease_id,
        target_ref=target_ref,
        issued_at=issued_at,
        controller_fingerprint=controller,
    )


def _issue(
    engine: Engine,
    harness: HarnessSecurity,
    target_ref: str,
    plan_id: uuid.UUID,
) -> tuple[RehearsalIssuerAuthorizationV1, str, dict[str, object]]:
    lease, evidence = _evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(_id(), plan_id, "operator-rehearsal"), evidence
    )
    assert set(invocation.to_control_request()) == {
        "command_id",
        "plan_id",
        "actor_ref",
    }
    with Session(engine) as db:
        envelope = issue_from_leaf(db, invocation)
        db.commit()
    return envelope, lease, evidence


def _standing(
    engine: Engine, envelope: RehearsalIssuerAuthorizationV1, evidence: object
) -> RehearsalIssuerAuthorizationStandingResult:
    with Session(engine) as fresh:
        return rehearsal_issuer_standing_for(
            fresh,
            authorization_document=envelope.as_mapping(),
            harness_evidence_document=evidence,
        )


def test_leaf_issues_and_fresh_session_standing(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    signer, harness = security
    target_ref, plan_id = _seed(engine)
    envelope, lease, evidence = _issue(engine, harness, target_ref, plan_id)
    assert (
        signer.rehearsal_issuer_identity.public_key_fingerprint
        != harness.controller_fingerprint
    )
    assert envelope.statement.immutable_reference == str(plan_id)
    assert envelope.statement.target_ref == target_ref
    assert envelope.statement.lease_id == lease
    assert envelope.statement.desired_state_digest.startswith("sha256:")
    assert envelope.statement.profile_digest == _DIGEST
    assert envelope.statement.execution_plan_digest == _PLAN
    assert (
        _standing(engine, envelope, evidence).standing
        is RehearsalIssuerAuthorizationStanding.VALID
    )
    with Session(engine) as db:
        count = db.scalar(
            select(func.count())
            .select_from(RehearsalIssuerAuthorizationRecord)
            .where(
                RehearsalIssuerAuthorizationRecord.authorization_id
                == envelope.statement.authorization_id
            )
        )
        assert count == 1
        assert db.scalar(text("SELECT count(*) FROM mod_deploy.rollouts")) == 0


def test_standing_refuses_the_uncommitted_issuing_session(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    _, evidence = _evidence(harness, target_ref)
    invocation = RehearsalIssuerInvocation(
        RehearsalIssuerCommand(_id(), plan_id, "operator-rehearsal"), evidence
    )
    with Session(engine) as issuing:
        envelope = issue_from_leaf(issuing, invocation)
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as caught:
            rehearsal_issuer_standing_for(
                issuing,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=evidence,
            )
        assert (
            caught.value.code
            is RehearsalIssuerIssuanceRefusalCode.STANDING_REQUIRES_COMMITTED_SESSION
        )
        issuing.commit()
    assert (
        _standing(engine, envelope, evidence).standing
        is RehearsalIssuerAuthorizationStanding.VALID
    )


def test_wrong_controller_signed_evidence_cannot_rebind_standing(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    envelope, lease, _ = _issue(engine, harness, target_ref, plan_id)
    _, wrong_controller = _evidence(
        harness,
        target_ref,
        lease=lease,
        controller="sha256:" + "ef" * 32,
    )
    result = _standing(engine, envelope, wrong_controller)
    assert result.standing is RehearsalIssuerAuthorizationStanding.UNRESOLVED
    assert result.refusal is RehearsalIssuerAuthorizationRefusalCode.CONTROLLER_MISMATCH


@pytest.mark.parametrize(
    "case, expected",
    [
        ("forged", RehearsalHarnessEvidenceRefusalCode.SIGNATURE_INVALID),
        ("stale", RehearsalHarnessEvidenceRefusalCode.EXPIRED),
        ("wrong_target", RehearsalIssuerIssuanceRefusalCode.TARGET_MISMATCH),
    ],
)
def test_evidence_refusals_reach_real_control(
    engine: Engine,
    security: tuple[AuthorizationSecurity, HarnessSecurity],
    case: str,
    expected: object,
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    _, evidence = _evidence(
        harness,
        target_ref if case != "wrong_target" else "another-rehearsal-target",
        issued_at=datetime.now(UTC) - timedelta(hours=4) if case == "stale" else None,
    )
    if case == "forged":
        signature = dict(cast(Mapping[str, str], evidence["signature"]))
        signature["signature"] = base64.b64encode(bytes(64)).decode()
        evidence["signature"] = signature
    with Session(engine) as db:
        with pytest.raises(
            (RehearsalHarnessEvidenceRefusedError, RehearsalIssuerIssuanceRefusedError)
        ) as caught:
            issue_from_leaf(
                db,
                RehearsalIssuerInvocation(
                    RehearsalIssuerCommand(_id(), plan_id), evidence
                ),
            )
        refusal = caught.value
        assert isinstance(
            refusal,
            RehearsalHarnessEvidenceRefusedError | RehearsalIssuerIssuanceRefusedError,
        )
        assert refusal.code is expected
        db.rollback()


@pytest.mark.parametrize(
    "environment,approve,suspend,expected",
    [
        (
            "production",
            True,
            False,
            RehearsalIssuerIssuanceRefusalCode.NOT_A_REHEARSAL_TARGET,
        ),
        (
            "rehearsal",
            False,
            False,
            RehearsalIssuerIssuanceRefusalCode.APPROVAL_NOT_STANDING,
        ),
        ("rehearsal", True, True, RehearsalIssuerIssuanceRefusalCode.TARGET_NOT_ACTIVE),
    ],
)
def test_plan_state_refusals(
    engine: Engine,
    security: tuple[AuthorizationSecurity, HarnessSecurity],
    environment: str,
    approve: bool,
    suspend: bool,
    expected: RehearsalIssuerIssuanceRefusalCode,
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(
        engine, environment=environment, approve=approve, suspend=suspend
    )
    _, evidence = _evidence(harness, target_ref)
    with Session(engine) as db:
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as caught:
            issue_from_leaf(
                db,
                RehearsalIssuerInvocation(
                    RehearsalIssuerCommand(_id(), plan_id), evidence
                ),
            )
        assert caught.value.code is expected
        db.rollback()


def test_revoke_is_terminal_and_database_guarded(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    envelope, _, evidence = _issue(engine, harness, target_ref, plan_id)
    authorization_id = envelope.statement.authorization_id
    with Session(engine) as db:
        revoke_rehearsal_issuer_authorization(
            db, authorization_id=authorization_id, revocation_ref=f"revoke-{_id()}"
        )
        db.commit()
    assert (
        _standing(engine, envelope, evidence).standing
        is RehearsalIssuerAuthorizationStanding.REVOKED
    )
    with Session(engine) as db:
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as caught:
            revoke_rehearsal_issuer_authorization(
                db, authorization_id=authorization_id, revocation_ref=f"again-{_id()}"
            )
        assert caught.value.code is RehearsalIssuerIssuanceRefusalCode.NOT_REVOCABLE
        db.rollback()
    with Session(engine) as db:
        with pytest.raises(DBAPIError, match="immutable"):
            db.execute(
                text(
                    "UPDATE mod_deploy.rehearsal_issuer_authorizations "
                    "SET state='issued' WHERE authorization_id=:id"
                ),
                {"id": authorization_id},
            )
            db.flush()
        db.rollback()


def test_consumption_requires_later_evidence_and_is_single_use(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    envelope, lease, issuance_evidence = _issue(engine, harness, target_ref, plan_id)
    with Session(engine) as db:
        with pytest.raises(RehearsalIssuerIssuanceRefusedError) as caught:
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=issuance_evidence,
            )
        assert (
            caught.value.code
            is RehearsalIssuerIssuanceRefusalCode.STALE_HARNESS_EVIDENCE
        )
        db.rollback()
    _, later = _evidence(harness, target_ref, lease=lease, issued_at=datetime.now(UTC))
    with Session(engine) as db:
        staged = stage_rehearsal_issuer_consumption(
            db,
            authorization_document=envelope.as_mapping(),
            harness_evidence_document=later,
        )
        assert staged.lease_id == lease
        db.commit()
    assert (
        _standing(engine, envelope, later).standing
        is RehearsalIssuerAuthorizationStanding.CONSUMED
    )
    with Session(engine) as db:
        with pytest.raises(RehearsalIssuerIssuanceRefusedError):
            stage_rehearsal_issuer_consumption(
                db,
                authorization_document=envelope.as_mapping(),
                harness_evidence_document=later,
            )
        db.rollback()


def test_rollback_creates_no_authority(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    lease, evidence = _evidence(harness, target_ref)
    with Session(engine) as db:
        envelope = issue_from_leaf(
            db,
            RehearsalIssuerInvocation(RehearsalIssuerCommand(_id(), plan_id), evidence),
        )
        db.rollback()
    assert envelope.statement.lease_id == lease
    assert (
        _standing(engine, envelope, evidence).standing
        is RehearsalIssuerAuthorizationStanding.UNRESOLVED
    )
    with Session(engine) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(RehearsalIssuerAuthorizationRecord)
                .where(
                    RehearsalIssuerAuthorizationRecord.authorization_id
                    == envelope.statement.authorization_id
                )
            )
            == 0
        )


def test_concurrent_consumption_has_one_winner(
    engine: Engine, security: tuple[AuthorizationSecurity, HarnessSecurity]
) -> None:
    _, harness = security
    target_ref, plan_id = _seed(engine)
    envelope, lease, _ = _issue(engine, harness, target_ref, plan_id)
    _, later = _evidence(harness, target_ref, lease=lease, issued_at=datetime.now(UTC))

    def consume() -> str:
        with Session(engine) as db:
            try:
                stage_rehearsal_issuer_consumption(
                    db,
                    authorization_document=envelope.as_mapping(),
                    harness_evidence_document=later,
                )
                db.commit()
                return "spent"
            except RehearsalIssuerIssuanceRefusedError as error:
                db.rollback()
                return str(error.code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: consume(), range(2)))
    assert sorted(results) == sorted(
        ["spent", RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH.value]
    )
    assert (
        _standing(engine, envelope, later).standing
        is RehearsalIssuerAuthorizationStanding.CONSUMED
    )


# ── Sensitivity proofs (F1/F2/F3 from the independent review) ──────────────


def test_app_user_cannot_read_the_rehearsal_issuer_ledger(
    admin_engine: Engine,
) -> None:
    """dc_0014 REVOKEs ALL on the ledger from `app_user` -- prove the negative
    directly, as `app_user`, rather than trusting the migration's own grant
    comment. A planted removal of that REVOKE would turn this SELECT from a
    permission error into a real (empty) result, which is exactly the defect
    this test exists to catch.
    """
    app_user_url = admin_engine.url.set(username="app_user", password=None)
    app_user_engine = create_engine(app_user_url)
    try:
        with app_user_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(
                    text("SELECT 1 FROM mod_deploy.rehearsal_issuer_authorizations")
                )
    finally:
        app_user_engine.dispose()


def test_removing_platform_apis_target_update_grant_fails_the_real_operation(
    admin_engine: Engine, engine: Engine
) -> None:
    """Prove `platform_api`'s `UPDATE` on `deployment_targets` is load-bearing,
    not a redundant grant left over from `app_admin`'s own privileges: revoke
    it, attempt the real `suspend_target` operation as `platform_api`, and
    require a genuine DB-level permission error -- not a typed Control
    refusal, which would mean the grant was never actually reached.
    """
    target_ref, _ = _seed(engine)
    with admin_engine.connect() as conn:
        raw_target_id = conn.execute(
            text(
                "SELECT id FROM mod_deploy.deployment_targets WHERE target_ref = :ref"
            ),
            {"ref": target_ref},
        ).scalar_one()
        target_id = (
            raw_target_id
            if isinstance(raw_target_id, uuid.UUID)
            else uuid.UUID(str(raw_target_id))
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text("REVOKE UPDATE ON mod_deploy.deployment_targets FROM platform_api")
        )
    try:
        with Session(engine) as db:
            with pytest.raises(DBAPIError, match="permission denied"):
                suspend_target(
                    db, TargetTransitionCommand(command_id=_id(), target_id=target_id)
                )
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                text("GRANT UPDATE ON mod_deploy.deployment_targets TO platform_api")
            )


def test_app_admin_cannot_create_a_role(admin_engine: Engine) -> None:
    """If `init-roles.sh` had NOT pre-created `outbox_dispatcher`/
    `platform_outbox_dispatcher`, the Kernel migration's own
    ``CREATE ROLE IF NOT EXISTS`` would genuinely fail closed here, rather
    than the harness silently working around a missing role by granting
    itself the power to create one. `app_admin` must lack `CREATEROLE`
    entirely, not merely lack it for these two specific roles.
    """
    with admin_engine.connect() as conn, conn.begin():
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(f'CREATE ROLE "probe_{_id()}" LOGIN'))
