"""Account-owned fleet intent and immutable desired-state versions."""

from vendor_cp.fleet import service
from vendor_cp.fleet.models import (
    Deployment,
    DeploymentDesiredStateVersion,
    DeploymentTarget,
)
from vendor_cp.fleet.service import (
    CapabilityOperationInput,
    ConfigurationSnapshotInput,
    ConfigurationValue,
    CreateDeploymentIntentCommand,
    CreateDeploymentTargetCommand,
    DeploymentDesiredStateView,
    DeploymentIntentResult,
    DeploymentTargetView,
    DeploymentView,
    create_deployment_target,
    record_deployment_intent,
)

__all__ = [
    "CapabilityOperationInput",
    "CreateDeploymentIntentCommand",
    "CreateDeploymentTargetCommand",
    "ConfigurationSnapshotInput",
    "ConfigurationValue",
    "Deployment",
    "DeploymentDesiredStateVersion",
    "DeploymentDesiredStateView",
    "DeploymentIntentResult",
    "DeploymentTarget",
    "DeploymentTargetView",
    "DeploymentView",
    "create_deployment_target",
    "record_deployment_intent",
    "service",
]
