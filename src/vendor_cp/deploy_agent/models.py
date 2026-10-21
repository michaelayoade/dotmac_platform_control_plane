"""Typed CP commands and results; wire payload types remain contracts-owned."""

from typing import Literal, NotRequired, TypedDict

from . import contracts as c


class UnsignedDesired(TypedDict):
    product: Literal["dotmac_sub"]
    environment: Literal["staging"]
    host: c.Identifier
    deployment_ref: str
    image_reference: Literal["ghcr.io/michaelayoade/dotmac_sub"]
    image_digest: c.Digest
    from_image_digest: NotRequired[c.Digest]
    source_revision: c.Revision
    source_tree: c.Revision
    product_manifest_digest: c.Digest
    build_run_id: int
    evidence_run_id: int
    config_digest: c.Digest
    config_files: dict[c.ConfigPath, c.Digest]
    migration_policy: c.MigrationPolicy
    approvals: list[c.Approval]


class IssueCommand(TypedDict):
    command_id: str
    desired: UnsignedDesired
    approved_plan_digest: c.Digest


class PreviewCommand(TypedDict):
    mode: Literal["preview"]
    desired: UnsignedDesired


class PlanPreview(TypedDict):
    plan: c.Plan
    plan_digest: str


class RegisterKey(TypedDict):
    key_id: c.Identifier
    deployment_ref: str
    public_key_b64: str


class RevokeKey(TypedDict):
    operation: Literal["revoke"]
    key_id: c.Identifier


class KeyRecord(RegisterKey):
    actor_admin_id: str
    state: Literal["pending", "active", "revoked"]
    challenge: c.Challenge | None
    possession: NotRequired[c.Envelope]
    baseline_digest: NotRequired[c.Digest]
    received_at: NotRequired[str]


class ActivateKey(TypedDict):
    envelope: c.Envelope
    approved_public_key_fingerprint: c.Digest


class KeyState(TypedDict):
    state: Literal["active", "revoked"]


class IngestOutcome(TypedDict):
    verdict: str


class Drift(TypedDict):
    deployment_ref: str
    desired: c.DesiredState | None
    applied: c.AppliedState | None
    drift: bool


class Receipt(TypedDict):
    deployment_ref: str
    report_id: str
    path: str
    fingerprint: str


def parse_command(value: c.Json, model: type[object]) -> object:
    c._shape(value, model)
    return value
