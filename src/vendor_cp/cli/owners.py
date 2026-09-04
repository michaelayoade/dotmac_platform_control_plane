"""Which owner each command delegates to, declared once as data.

Every CLI command is an adapter over exactly one owning service or query
function, and this table says which. It exists because the claim "the CLI
implements no policy" is otherwise unfalsifiable prose: with the table, three
things become checkable rather than asserted.

**1. No mutation is owned here.** Every mutating command's owner resolves to a
module OUTSIDE `vendor_cp.cli`. A decision that existed only in the CLI would be
a second authority over a subject that already has one, and the browser and API
surfaces would disagree with the terminal.

**2. No mutating owner is claimed twice.** Two commands naming the same mutating
symbol would be two entry points to one transition — which is fine — but two
DIFFERENT symbols behind commands that mean the same thing is the duplicate this
checks for, so each mutating symbol appears exactly once and a second
spelling shows up as drift instead of as convenience.

**3. The owner is reachable from an installed wheel.** `diagnose self` resolves
each entry with `importlib.util.find_spec`, which locates a module without
executing it, and asserts its origin is under the interpreter's `purelib` or
`platlib`. A resolution that lands in a source tree fails, and that is the whole
point of the check: running against a checkout is exactly how a package can
report one identity while being another.

The `MUTATES` flag is the assembly's own statement about the command, not
something inferred from the owner's name. A read that happens to be spelled like
a write, or a write whose owner reads first, is classified by what it does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Owner:
    """One command, and the single service or query function behind it."""

    #: `"<group> <command>"`, exactly as the operator types it.
    command: str
    #: Import path of the module that owns the decision.
    module: str
    #: The callable within it. Resolved by name only when a command runs.
    symbol: str
    #: Whether invoking it changes durable state.
    mutates: bool
    #: One line an operator can read in `diagnose owners`.
    summary: str


#: The complete command surface. A command that is not here does not exist:
#: `tests/architecture/test_installed_cli.py` compares this table against the
#: argument parser in both directions, so a command added without an owner and
#: an owner declared without a command both fail.
OWNERS: Final[tuple[Owner, ...]] = (
    # ── admin ──────────────────────────────────────────────────────────────
    Owner(
        "admin create",
        "vendor_cp.platform_admin",
        "upsert_platform_admin",
        True,
        "create or rotate a platform administrator",
    ),
    Owner(
        "admin migrate",
        "vendor_cp.migrations",
        "deploy_config",
        True,
        "apply the composed migration lineage to its declared heads",
    ),
    Owner(
        "admin descriptor-drift",
        "vendor_cp.descriptor.drift",
        "compare",
        False,
        "compare the accepted descriptor with a catalogue capture, both ways",
    ),
    Owner(
        "admin accounts",
        "vendor_cp.accounts.service",
        "list_accounts",
        False,
        "list vendor accounts",
    ),
    Owner(
        "admin account-create",
        "vendor_cp.accounts.service",
        "create_account",
        True,
        "create one vendor account",
    ),
    # ── release ────────────────────────────────────────────────────────────
    Owner(
        "release record",
        "vendor_cp.release_evidence.service",
        "ingest_product_release_evidence",
        True,
        "catalogue exact product release evidence",
    ),
    Owner(
        "release pins",
        "vendor_cp.config",
        "load_vendor_settings",
        False,
        "show the configured product release pins",
    ),
    Owner(
        "release catalogue",
        "vendor_cp.offers.catalog",
        "configured_product_capability_catalogues",
        False,
        "resolve the pinned products' capability catalogues",
    ),
    # ── agreement ──────────────────────────────────────────────────────────
    Owner(
        "agreement list",
        "vendor_cp.contracts.adapter",
        "list_agreements",
        False,
        "page through commercial agreements",
    ),
    Owner(
        "agreement show",
        "vendor_cp.contracts.adapter",
        "get",
        False,
        "read one commercial agreement",
    ),
    # ── approval ───────────────────────────────────────────────────────────
    Owner(
        "approval publish-policy",
        "vendor_cp.approvals.adapter",
        "publish_policy_version",
        True,
        "publish an immutable approval policy revision",
    ),
    Owner(
        "approval open",
        "vendor_cp.approvals.adapter",
        "open_request",
        True,
        "open an approval request bound to one exact content digest",
    ),
    Owner(
        "approval decide",
        "vendor_cp.approvals.adapter",
        "record_decision",
        True,
        "record one approver's decision",
    ),
    Owner(
        "approval show",
        "vendor_cp.approvals.adapter",
        "evaluate_request",
        False,
        "read an approval request's current state",
    ),
    # ── allocation ─────────────────────────────────────────────────────────
    Owner(
        "allocation show",
        "vendor_cp.allocations.adapter",
        "read_allocation",
        False,
        "read one entitlement allocation",
    ),
    Owner(
        "allocation list",
        "vendor_cp.allocations.adapter",
        "list_for_contract",
        False,
        "list a contract's allocations",
    ),
    # ── licence ────────────────────────────────────────────────────────────
    Owner(
        "licence issue",
        "vendor_cp.licensing.adapter",
        "issue_licence",
        True,
        "issue a signed licence for a staged allocation",
    ),
    Owner(
        "licence revoke",
        "vendor_cp.licensing.adapter",
        "revoke_licence",
        True,
        "revoke a licence",
    ),
    Owner(
        "licence publish-revocations",
        "vendor_cp.licensing.adapter",
        "publish_revocation_list",
        True,
        "publish a signed revocation list",
    ),
    Owner(
        "licence issuances",
        "vendor_cp.licensing.adapter",
        "list_issuances",
        False,
        "list a licence's issuances",
    ),
    Owner(
        "licence keys",
        "vendor_cp.licensing.adapter",
        "list_signing_keys",
        False,
        "list registered signing keys and their standing",
    ),
    Owner(
        "licence dispatch",
        "vendor_cp.licensing.transport",
        "dispatch_pending",
        True,
        "dispatch pending licence deliveries through the configured transport",
    ),
    Owner(
        "licence health",
        "vendor_cp.licensing.delivery_ops",
        "pipeline_health",
        False,
        "report licence delivery pipeline health",
    ),
    # ── relay ──────────────────────────────────────────────────────────────
    Owner(
        "relay drain",
        "vendor_cp.relay.runner",
        "drain_once",
        True,
        "claim one platform outbox batch and deliver it",
    ),
    Owner(
        "relay run",
        "vendor_cp.relay.runner",
        "run",
        True,
        "run the platform outbox relay until stopped",
    ),
    Owner(
        "relay health",
        "vendor_cp.relay.health",
        "relay_health",
        False,
        "report whether the platform outbox is being drained",
    ),
    # ── deployment ─────────────────────────────────────────────────────────
    Owner(
        "deployment register-target",
        "vendor_cp.deployment.adapter",
        "register_deployment_target",
        True,
        "name a deployment this control plane is responsible for",
    ),
    Owner(
        "deployment set-desired-state",
        "vendor_cp.deployment.adapter",
        "set_target_desired_state",
        True,
        "declare what a registered target should converge on",
    ),
    Owner(
        "deployment targets",
        "vendor_cp.deployment.adapter",
        "read_target",
        False,
        "read one registered deployment target",
    ),
    Owner(
        "deployment propose",
        "vendor_cp.deployment.adapter",
        "propose_deployment_plan",
        True,
        "freeze the target's desired state into an immutable plan",
    ),
    Owner(
        "deployment authorize",
        "vendor_cp.deployment.adapter",
        "authorize_deployment",
        True,
        "carry an approval into the frozen plan and request the rollout",
    ),
    Owner(
        "deployment plan",
        "vendor_cp.deployment.adapter",
        "read_plan",
        False,
        "read a deployment plan and its approval standing",
    ),
    Owner(
        "deployment rollout",
        "vendor_cp.deployment.adapter",
        "read_rollout",
        False,
        "read a rollout and every attempt at it",
    ),
    Owner(
        "deployment drift",
        "vendor_cp.deployment.adapter",
        "read_drift",
        False,
        "compare a target's rolled-out and observed state",
    ),
    Owner(
        "deployment readiness-packet",
        "vendor_cp.deployment.readiness_packet",
        "validate_readiness_packet",
        False,
        "refuse a readiness packet that cannot yet justify naming a window",
    ),
    Owner(
        "deployment foundation",
        "vendor_cp.cli.delegate",
        "run_foundation",
        False,
        "pass arguments straight through to the published Foundation CLI",
    ),
    # ── recovery ───────────────────────────────────────────────────────────
    Owner(
        "recovery capture-sql",
        "vendor_cp.recovery.capture",
        "capture_sql",
        False,
        "emit the catalogue capture query a recovery is checked against",
    ),
    Owner(
        "recovery bundle",
        "vendor_cp.recovery.bundle",
        "build_bundle",
        False,
        "turn a catalogue capture into a PostgresRecoveryBundleV1 manifest",
    ),
    # ── diagnose ───────────────────────────────────────────────────────────
    Owner(
        "diagnose self",
        "vendor_cp.cli.diagnose",
        "self_report",
        False,
        "prove this command is running from an installed distribution",
    ),
    Owner(
        "diagnose version",
        "vendor_cp.cli.diagnose",
        "version_report",
        False,
        "report installed versions of the assembly and every composed owner",
    ),
    Owner(
        "diagnose owners",
        "vendor_cp.cli.diagnose",
        "owners_report",
        False,
        "print the command-to-owner table",
    ),
    Owner(
        "diagnose composition",
        "vendor_cp.cli.diagnose",
        "composition_report",
        False,
        "report the composed migration lineages and declared module planes",
    ),
)

#: `deployment foundation` is the one command whose owner is inside this
#: package, and it is a READ in this table's sense: it computes nothing and
#: decides nothing, it forwards an argument vector to
#: `dotmac-deployment-foundation`'s own console script and returns that
#: process's status. Reimplementing render, apply, observe or rollback here is
#: what this entry exists to make unnecessary.
DELEGATED_COMMANDS: Final[frozenset[str]] = frozenset({"deployment foundation"})


def by_command() -> dict[str, Owner]:
    return {owner.command: owner for owner in OWNERS}


def mutating_owners() -> tuple[Owner, ...]:
    return tuple(owner for owner in OWNERS if owner.mutates)


__all__ = ["DELEGATED_COMMANDS", "OWNERS", "Owner", "by_command", "mutating_owners"]
