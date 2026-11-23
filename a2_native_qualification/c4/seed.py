"""Seed ONE requested+committed rollout (original authorization, no dispatch).

Runs in the Control checkout's environment (Control's own test doubles sign the
authorization) against the CI-ephemeral migrated CP database, as the migration
owner. Prints the coordinates (ids and refs, no secrets) as JSON.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import UTC, datetime

from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    SetDesiredStateCommand,
    approve_plan,
    module,
    propose_plan,
    register_target,
    request_rollout,
    set_desired_state,
)
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    install_audit_actions,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from tests.authorization_support import SIGNER

DESCRIPTOR = "sha256:" + "3c" * 32
EXECUTION_PLAN = "sha256:" + "1a" * 32


def main(url: str) -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))
    suffix = uuid.uuid4().hex[:10]
    engine = create_engine(url, future=True)
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=f"c4-target-{suffix}",
                target_ref=f"c4-target-{suffix}",
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=f"c4-desired-{suffix}",
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@1", spec={"replicas": 2}, images=[]
                ),
            ),
        )
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=f"c4-plan-{suffix}",
                target_id=target.id,
                operation="deploy",
                descriptor_digest=DESCRIPTOR,
                execution_plan_digest=EXECUTION_PLAN,
                purpose="foundation_execution",
                requires_approval=True,
                approval_policy_code="deployment.production",
                approval_policy_version=1,
            ),
        )
        approve_plan(
            db,
            ApprovePlanCommand(
                command_id=f"c4-approve-{suffix}",
                plan_id=plan.id,
                evidence=ApprovalEvidence(
                    policy_code="deployment.production",
                    policy_version=1,
                    decision_ref=f"decision-{suffix}",
                    content_digest=plan.plan_digest or "",
                    decided_at=datetime.now(UTC),
                    operation="deploy",
                    execution_plan_digest=EXECUTION_PLAN,
                    decision_status="granted",
                ),
            ),
        )
        command = RequestRolloutCommand(
            command_id=f"c4-rollout-{suffix}",
            rollout_ref=f"c4-rollout-{suffix}",
            plan_id=plan.id,
            authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        request_rollout(db, command, signer=SIGNER)
        db.commit()
        print(
            json.dumps(
                {
                    "rollout_ref": command.rollout_ref,
                    "plan_id": str(plan.id),
                    "rollout_command_id": command.command_id,
                    "dispatch_command_id": f"c4-recover-dispatch-{suffix}",
                }
            )
        )


if __name__ == "__main__":
    main(sys.argv[1])
