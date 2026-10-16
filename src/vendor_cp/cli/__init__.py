"""`dotmac-platform` — the installed operator CLI for the Platform Control Plane.

## What it is

An adapter family, exactly like `router.py` and `web.py`, entered from a
terminal instead of over HTTP. Every command delegates to the same service or
query owner the browser and the API reach, and the mapping is declared as data
in `vendor_cp.cli.owners` so that claim is checkable rather than asserted. The
CLI implements no approval, plan-digest, rollback or recovery policy. A decision
that existed only here would be a second authority over a subject that already
has one, and an operator at a shell would get a different answer from an
operator at a screen.

## How it is installed, and why that is the point

This is a console script on an installed wheel — `dotmac-platform`, declared in
`pyproject.toml` — and the production image installs that wheel rather than
putting a checkout on `PYTHONPATH`. Production usage is therefore

    docker compose run --rm --no-deps ops dotmac-platform ...

and not an interpreter handed a path under `scripts/`.
`dotmac-platform diagnose self --strict` proves the difference at runtime by
resolving each module's `__file__` against `sysconfig`'s `purelib`/`platlib`;
the same command run from a checkout fails,
which is what makes it a proof rather than a canary.

## Exit codes

`vendor_cp.cli.exits` owns them. The pair worth restating here is `3` and `4`:
an owner REFUSED and there is NO EVIDENCE look identical from outside and mean
opposite things about whether to retry, so they are different numbers and stay
different through `docker compose run`, which propagates the container's status
unchanged.

## Secrets

Never on argv. `/proc/<pid>/cmdline` is world-readable for as long as a process
lives, and a registration token leaked into a transcript on this fleet exactly
that way. Commands that need one take `--<name>-file` or `--<name>-stdin`, and
`tests/architecture/test_installed_cli.py` fails the build if any option's
name reads like a secret that takes a value.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Final

from vendor_cp.cli import commands, diagnose
from vendor_cp.cli.delegate import delegate_exit, run_foundation
from vendor_cp.cli.exits import ExitCode, Refusal
from vendor_cp.cli.io import FORMATS, Result, emit
from vendor_cp.cli.owners import by_command
from vendor_cp.cli.runtime import installed_version, translate
from vendor_cp.identity import DISTRIBUTION

#: The console script's own name. Written here only for `prog=`; every check
#: that needs to know which command this is reads it from distribution
#: metadata instead — see `vendor_cp.installed_surface.sanctioned_entry_points`.
PROGRAM: Final[str] = "dotmac-platform"

#: The groups, in the order `--help` should list them.
GROUPS: Final[tuple[str, ...]] = (
    "admin",
    "release",
    "agreement",
    "approval",
    "allocation",
    "licence",
    "relay",
    "withdrawal-conflicts",
    "deployment",
    "recovery",
    "gate0",
    "diagnose",
)


class _Parser(argparse.ArgumentParser):
    """An argument parser whose usage errors exit `2` and say so in one place."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: {message}", file=sys.stderr)
        raise SystemExit(int(ExitCode.USAGE))


def _command(
    sub: argparse._SubParsersAction[_Parser], group: str, name: str, help_text: str
) -> _Parser:
    child = sub.add_parser(name, help=help_text)
    child.set_defaults(command=f"{group} {name}")
    return child


def build_parser() -> _Parser:
    """The whole command surface, built once and checked against the owner table."""
    parser = _Parser(prog=PROGRAM, description=__doc__.splitlines()[0])
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=FORMATS,
        default="table",
        help="output shape (default: table)",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="print the installed distribution version and exit",
    )
    groups = parser.add_subparsers(dest="group", parser_class=_Parser)

    # ── admin ──────────────────────────────────────────────────────────────
    admin = groups.add_parser("admin", help="platform administrators and the database")
    admin_sub = admin.add_subparsers(dest="name", parser_class=_Parser)

    create = _command(admin_sub, "admin", "create", "create or rotate a platform admin")
    create.add_argument("email")
    create.add_argument("--inactive", action="store_true")
    create.add_argument(
        "--password-file", help="path to a file this host already holds"
    )
    create.add_argument(
        "--password-stdin", action="store_true", help="read it from stdin"
    )
    create.set_defaults(handler=commands.admin_create)

    migrate = _command(
        admin_sub, "admin", "migrate", "apply the composed lineage to its heads"
    )
    migrate.add_argument("--target", default="heads")
    migrate.set_defaults(handler=commands.admin_migrate)

    descriptor_drift = _command(
        admin_sub,
        "admin",
        "descriptor-drift",
        "compare the accepted descriptor with a catalogue capture, both ways",
    )
    descriptor_drift.add_argument(
        "--descriptor", required=True, help="path to the accepted product.toml"
    )
    descriptor_drift.add_argument(
        "--capture",
        required=True,
        help="path to the JSON `recovery capture-sql` emitted from the target",
    )
    descriptor_drift.set_defaults(handler=commands.admin_descriptor_drift)

    accounts = _command(admin_sub, "admin", "accounts", "list vendor accounts")
    accounts.set_defaults(handler=commands.admin_accounts)

    account_create = _command(
        admin_sub, "admin", "account-create", "create one vendor account"
    )
    account_create.add_argument("--command-id", required=True)
    account_create.add_argument("--external-ref", required=True)
    account_create.add_argument("--display-name", required=True)
    account_create.set_defaults(handler=commands.admin_account_create)

    # `admin transition-fence-<close|holding|restore>` stays a flat
    # `<group> <name>` command like every other admin command — a genuine
    # three-level `admin transition-fence close` nesting broke
    # `test_every_command_help_renders`, which splits a command name on a
    # single space and feeds it straight to argparse as argv, and breaks the
    # image job's clean-install acceptance the same way. The hyphenated
    # `-close`/`-holding`/`-restore` suffixes keep the three verbs visually
    # grouped without a second level of subparsers.
    tf_close = _command(
        admin_sub,
        "admin",
        "transition-fence-close",
        "revoke writer CONNECT and drain open writer sessions",
    )
    tf_close.add_argument("--database", required=True)
    tf_close.add_argument("--fence-id", required=True)
    tf_close.add_argument("--session-wait-seconds", type=float, required=True)
    tf_close.add_argument(
        "--prior-expected-digest",
        help="the prior run's host-recorded digest; requires "
        "--expected-prior-fence-id, and reads the prior proof document as "
        "the first stdin line",
    )
    tf_close.add_argument(
        "--expected-prior-fence-id",
        help="the prior run's fence_id; requires --prior-expected-digest",
    )
    tf_close.set_defaults(handler=commands.transition_fence_close)

    tf_holding = _command(
        admin_sub,
        "admin",
        "transition-fence-holding",
        "read-only: does a previously closed fence still hold",
    )
    tf_holding.add_argument("--database", required=True)
    tf_holding.add_argument("--expected-digest", required=True)
    tf_holding.add_argument("--expected-fence-id", required=True)
    tf_holding.set_defaults(handler=commands.transition_fence_holding)

    tf_restore = _command(
        admin_sub,
        "admin",
        "transition-fence-restore",
        "restore the fenced ACL to exactly what the proof recorded",
    )
    tf_restore.add_argument("--database", required=True)
    tf_restore.add_argument("--expected-digest", required=True)
    tf_restore.add_argument("--expected-fence-id", required=True)
    tf_restore.add_argument("--session-wait-seconds", type=float, required=True)
    tf_restore.set_defaults(handler=commands.transition_fence_restore)

    # ── release ────────────────────────────────────────────────────────────
    release = groups.add_parser("release", help="product release evidence and pins")
    release_sub = release.add_subparsers(dest="name", parser_class=_Parser)

    record = _command(
        release_sub, "release", "record", "catalogue exact product release evidence"
    )
    for flag in (
        "--command-id",
        "--product-code",
        "--product-version",
        "--artifact-digest",
        "--artifact-ref",
        "--source-revision",
        "--product-manifest-digest",
        "--product-manifest-path",
        "--operator-ref",
    ):
        record.add_argument(flag, required=True)
    record.set_defaults(handler=commands.release_record)

    pins = _command(release_sub, "release", "pins", "show the configured release pins")
    pins.set_defaults(handler=commands.release_pins)

    catalogue = _command(
        release_sub, "release", "catalogue", "resolve the pinned capability catalogues"
    )
    catalogue.set_defaults(handler=commands.release_catalogue)

    # ── agreement ──────────────────────────────────────────────────────────
    agreement = groups.add_parser("agreement", help="commercial agreements")
    agreement_sub = agreement.add_subparsers(dest="name", parser_class=_Parser)

    ag_list = _command(agreement_sub, "agreement", "list", "page through agreements")
    ag_list.add_argument("--after")
    ag_list.add_argument("--limit", type=int, default=50)
    ag_list.set_defaults(handler=commands.agreement_list)

    ag_show = _command(agreement_sub, "agreement", "show", "read one agreement")
    ag_show.add_argument("agreement_id")
    ag_show.set_defaults(handler=commands.agreement_show)

    # ── approval ───────────────────────────────────────────────────────────
    approval = groups.add_parser("approval", help="approval policies and decisions")
    approval_sub = approval.add_subparsers(dest="name", parser_class=_Parser)

    policy = _command(
        approval_sub, "approval", "publish-policy", "publish a policy revision"
    )
    policy.add_argument("--command-id", required=True)
    policy.add_argument("--policy-code", required=True)
    policy.add_argument("--policy-version", type=int, required=True)
    policy.add_argument("--quorum", type=int, default=1)
    policy.add_argument("--allow-self-approval", action="store_true")
    policy.set_defaults(handler=commands.approval_publish_policy)

    ap_open = _command(approval_sub, "approval", "open", "open an approval request")
    ap_open.add_argument("--command-id", required=True)
    ap_open.add_argument("--policy-code", required=True)
    ap_open.add_argument("--policy-version", type=int, required=True)
    ap_open.add_argument("--subject-type", required=True)
    ap_open.add_argument("--subject-id", required=True)
    ap_open.add_argument("--content-hash", required=True)
    ap_open.add_argument("--requested-by", required=True)
    ap_open.set_defaults(handler=commands.approval_open)

    decide = _command(approval_sub, "approval", "decide", "record one decision")
    decide.add_argument("--command-id", required=True)
    decide.add_argument("--request-id", required=True)
    decide.add_argument("--approver-id", required=True)
    decide.add_argument("--content-hash", required=True)
    decide.add_argument("--reject", action="store_true")
    decide.set_defaults(handler=commands.approval_decide)

    ap_show = _command(approval_sub, "approval", "show", "read a request's state")
    ap_show.add_argument("request_id")
    ap_show.set_defaults(handler=commands.approval_show)

    # ── allocation ─────────────────────────────────────────────────────────
    allocation = groups.add_parser("allocation", help="entitlement allocations")
    allocation_sub = allocation.add_subparsers(dest="name", parser_class=_Parser)

    al_show = _command(allocation_sub, "allocation", "show", "read one allocation")
    al_show.add_argument("allocation_id")
    al_show.set_defaults(handler=commands.allocation_show)

    al_list = _command(
        allocation_sub, "allocation", "list", "list a contract's allocations"
    )
    al_list.add_argument("contract_id")
    al_list.set_defaults(handler=commands.allocation_list)

    # ── licence ────────────────────────────────────────────────────────────
    licence = groups.add_parser(
        "licence", help="licence issuance, revocation, delivery"
    )
    licence_sub = licence.add_subparsers(dest="name", parser_class=_Parser)

    issue = _command(licence_sub, "licence", "issue", "issue a signed licence")
    issue.add_argument("--allocation-id", required=True)
    issue.add_argument("--command-id", required=True)
    issue.add_argument("--edition")
    issue.add_argument("--deployment-id")
    issue.set_defaults(handler=commands.licence_issue)

    revoke = _command(licence_sub, "licence", "revoke", "revoke a licence")
    revoke.add_argument("--licence-id", required=True)
    revoke.add_argument("--command-id", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(handler=commands.licence_revoke)

    publish = _command(
        licence_sub, "licence", "publish-revocations", "publish a revocation list"
    )
    publish.add_argument("--command-id", required=True)
    publish.set_defaults(handler=commands.licence_publish_revocations)

    issuances = _command(
        licence_sub, "licence", "issuances", "list a licence's issuances"
    )
    issuances.add_argument("licence_id")
    issuances.set_defaults(handler=commands.licence_issuances)

    keys = _command(licence_sub, "licence", "keys", "list signing key ids and standing")
    keys.set_defaults(handler=commands.licence_keys)

    dispatch = _command(
        licence_sub, "licence", "dispatch", "dispatch pending deliveries"
    )
    dispatch.add_argument("--limit", type=int, default=100)
    dispatch.add_argument("--simulate", action="store_true")
    dispatch.set_defaults(handler=commands.licence_dispatch)

    health = _command(
        licence_sub, "licence", "health", "report delivery pipeline health"
    )
    health.set_defaults(handler=commands.licence_health)

    # ── relay ──────────────────────────────────────────────────────────────
    relay = groups.add_parser(
        "relay", help="the platform outbox relay: activation -> allocation"
    )
    relay_sub = relay.add_subparsers(dest="name", parser_class=_Parser)

    drain = _command(
        relay_sub, "relay", "drain", "claim one platform outbox batch and deliver it"
    )
    # `--worker-id` is required rather than defaulted to a hostname. The lease
    # is held BY this identifier, and two invocations that silently shared one
    # would each believe they held the other's claim. No secret is accepted on
    # argv here or anywhere: the dispatcher credential arrives through
    # `VENDOR_RELAY_DISPATCHER_DATABASE_URL`.
    drain.add_argument("--worker-id", required=True)
    drain.set_defaults(handler=commands.relay_drain)

    run_relay = _command(
        relay_sub, "relay", "run", "run the relay until stopped (the service)"
    )
    run_relay.add_argument("--worker-id", required=True)
    run_relay.add_argument("--poll-interval", type=float, default=1.0)
    run_relay.set_defaults(handler=commands.relay_run)

    preflight = _command(
        relay_sub,
        "relay",
        "preflight",
        "check the relay-enablement preconditions (read-only, no host contact)",
    )
    preflight.set_defaults(handler=commands.relay_preflight)

    relay_health_command = _command(
        relay_sub, "relay", "health", "report whether the outbox is being drained"
    )
    relay_health_command.set_defaults(handler=commands.relay_health)

    # ── withdrawal-conflicts ───────────────────────────────────────────────
    withdrawal_conflicts = groups.add_parser(
        "withdrawal-conflicts",
        help="unresolved approval-withdrawal security_conflict outcomes",
    )
    withdrawal_conflicts_sub = withdrawal_conflicts.add_subparsers(
        dest="name", parser_class=_Parser
    )

    withdrawal_conflicts_list_command = _command(
        withdrawal_conflicts_sub,
        "withdrawal-conflicts",
        "list",
        "list unresolved security_conflict outcomes (id, event_id, reason_code, "
        "recorded_at)",
    )
    withdrawal_conflicts_list_command.set_defaults(
        handler=commands.withdrawal_conflicts_list
    )

    # ── deployment ─────────────────────────────────────────────────────────
    deployment = groups.add_parser(
        "deployment", help="the operator workflow over Deployment Control"
    )
    deployment_sub = deployment.add_subparsers(dest="name", parser_class=_Parser)

    material_probe = _command(
        deployment_sub,
        "deployment",
        "candidate-material-probe",
        "validate candidate configuration and local materials without startup",
    )
    material_probe.add_argument("--role", choices=("app", "relay"), required=True)
    material_probe.set_defaults(handler=commands.deployment_candidate_material_probe)

    register_target = _command(
        deployment_sub,
        "deployment",
        "register-target",
        "name a deployment this control plane is responsible for",
    )
    register_target.add_argument("--command-id", required=True)
    register_target.add_argument("--target-ref", required=True)
    register_target.add_argument("--subject-ref", required=True)
    register_target.add_argument("--product-code", required=True)
    register_target.add_argument("--environment", required=True)
    register_target.add_argument("--actor-ref")
    register_target.set_defaults(handler=commands.deployment_register_target)

    desired = _command(
        deployment_sub,
        "deployment",
        "set-desired-state",
        "declare what a registered target should converge on",
    )
    desired.add_argument("--command-id", required=True)
    desired.add_argument("--target-id", required=True)
    desired.add_argument("--release-ref", required=True)
    desired.add_argument(
        "--spec",
        required=True,
        help="path to a file holding the desired specification as a JSON object",
    )
    desired.add_argument("--licence-ref")
    desired.add_argument(
        "--expect-record-version",
        type=int,
        help="refuse unless the target is still at exactly this record version",
    )
    desired.add_argument("--actor-ref")
    desired.set_defaults(handler=commands.deployment_set_desired_state)

    targets = _command(deployment_sub, "deployment", "targets", "read one target")
    targets.add_argument("target_id")
    targets.set_defaults(handler=commands.deployment_targets)

    propose = _command(
        deployment_sub, "deployment", "propose", "freeze the desired state into a plan"
    )
    propose.add_argument("--command-id", required=True)
    propose.add_argument("--target-id", required=True)
    propose.add_argument("--policy-code", required=True)
    propose.add_argument("--policy-version", type=int, required=True)
    propose.add_argument("--actor-ref")
    propose.set_defaults(handler=commands.deployment_propose)

    authorize = _command(
        deployment_sub,
        "deployment",
        "authorize",
        "carry an approval into a frozen plan and request its rollout",
    )
    authorize.add_argument("--command-id", required=True)
    authorize.add_argument("--plan-id", required=True)
    authorize.add_argument("--approval-request-id", required=True)
    authorize.add_argument("--rollout-ref", required=True)
    authorize.add_argument("--reason")
    authorize.add_argument("--actor-ref")
    authorize.add_argument(
        "--expect-plan-digest",
        help="refuse with exit 6 unless the frozen plan digest is exactly this",
    )
    authorize.add_argument("--expect-plan-version", type=int)
    authorize.set_defaults(handler=commands.deployment_authorize)

    plan = _command(deployment_sub, "deployment", "plan", "read a plan")
    plan.add_argument("plan_id")
    plan.set_defaults(handler=commands.deployment_plan)

    rollout = _command(deployment_sub, "deployment", "rollout", "read a rollout")
    rollout.add_argument("rollout_id")
    rollout.set_defaults(handler=commands.deployment_rollout)

    drift = _command(
        deployment_sub, "deployment", "drift", "compare desired to observed"
    )
    drift.add_argument("target_id")
    drift.set_defaults(handler=commands.deployment_drift)

    readiness_packet = _command(
        deployment_sub,
        "deployment",
        "readiness-packet",
        "validate the terms that must exist before a window is named",
    )
    readiness_packet.add_argument(
        "--packet",
        required=True,
        help="path to a file holding the readiness packet as a JSON object",
    )
    readiness_packet.set_defaults(handler=commands.deployment_readiness_packet)

    foundation = _command(
        deployment_sub,
        "deployment",
        "foundation",
        "pass arguments through to the published Foundation CLI",
    )
    foundation.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="forwarded verbatim to `dotmac-deploy`; put them after `--`",
    )
    foundation.set_defaults(handler=None)

    # ── recovery ───────────────────────────────────────────────────────────
    recovery = groups.add_parser("recovery", help="database recovery evidence")
    recovery_sub = recovery.add_subparsers(dest="name", parser_class=_Parser)

    capture = _command(
        recovery_sub, "recovery", "capture-sql", "emit the catalogue capture query"
    )
    capture.set_defaults(handler=commands.recovery_capture_sql)

    bundle = _command(
        recovery_sub, "recovery", "bundle", "build a PostgresRecoveryBundleV1 manifest"
    )
    for flag in (
        "--capture",
        "--dump-digest",
        "--product",
        "--environment",
        "--source-revision",
    ):
        bundle.add_argument(flag, required=True)
    bundle.add_argument("--postgres-major", type=int, required=True)
    bundle.add_argument("--captured-at", type=int, required=True)
    bundle.add_argument("--out")
    bundle.set_defaults(handler=commands.recovery_bundle)

    gate0 = groups.add_parser("gate0", help="finite protected service adapters")
    gate0_sub = gate0.add_subparsers(dest="name", parser_class=_Parser)
    _command(
        gate0_sub,
        "gate0",
        "collection-check-activation",
        "check selected collection input in this image",
    )
    _command(
        gate0_sub,
        "gate0",
        "collection-check-retirement",
        "check original collection retirement input",
    )
    _command(gate0_sub, "gate0", "issuer-run", "run one finite issuer window")
    _command(gate0_sub, "gate0", "collect-e", "collect private finite E evidence")
    _command(gate0_sub, "gate0", "finalize-e", "prepare encrypted private E evidence")
    _command(
        gate0_sub, "gate0", "await-e-transfer", "verify original encrypted transfer"
    )
    _command(gate0_sub, "gate0", "prepare-e-draft", "prepare selected E draft release")
    _command(gate0_sub, "gate0", "publish-e", "publish selected reviewed E evidence")
    _command(
        gate0_sub,
        "gate0",
        "public-jit-runner-credential",
        "exec selected public JIT runner",
    )
    _command(gate0_sub, "gate0", "verify-e-published", "verify completed E publication")
    _command(
        gate0_sub,
        "gate0",
        "verify-e-b-archive",
        "verify the selected B custody archive",
    )
    _command(
        gate0_sub, "gate0", "bootstrap-collector", "launch the fixed isolated collector"
    )
    _command(
        gate0_sub,
        "gate0",
        "collect-e-credential",
        "collect with the fixed private credential",
    )
    _command(gate0_sub, "gate0", "handoff-holder", "forward fixed root evidence")
    _command(gate0_sub, "gate0", "lifecycle-run", "run the fixed A9 root lifecycle")
    _command(
        gate0_sub,
        "gate0",
        "lifecycle-retire-jit",
        "retire the owned A9 runner invocation",
    )
    _command(
        gate0_sub,
        "gate0",
        "jit-runner-credential",
        "start the fixed credential-fed runner",
    )
    _command(
        gate0_sub,
        "gate0",
        "courier-original-oidc",
        "deliver the original job credential",
    )
    _command(gate0_sub, "gate0", "handoff-receiver", "receive fixed root evidence")
    _command(
        gate0_sub, "gate0", "attester-session", "serve one fixed SSH proof exchange"
    )
    _command(
        gate0_sub, "gate0", "capture-install", "receive one protected capture batch"
    )
    _command(gate0_sub, "gate0", "capture-send", "send the parent's captured batch")
    _command(gate0_sub, "gate0", "supervise", "run one fixed installed role window")

    # ── diagnose ───────────────────────────────────────────────────────────
    diagnose_group = groups.add_parser("diagnose", help="questions about this process")
    diagnose_sub = diagnose_group.add_subparsers(dest="name", parser_class=_Parser)

    self_cmd = _command(
        diagnose_sub,
        "diagnose",
        "self",
        "prove this command runs from an installed distribution",
    )
    self_cmd.add_argument(
        "--strict",
        action="store_true",
        help="exit 6 on any finding instead of reporting it",
    )
    self_cmd.set_defaults(handler=diagnose.self_report)

    version_cmd = _command(
        diagnose_sub, "diagnose", "version", "installed versions, from metadata"
    )
    version_cmd.set_defaults(handler=diagnose.version_report)

    owners_cmd = _command(
        diagnose_sub, "diagnose", "owners", "the command-to-owner table"
    )
    owners_cmd.set_defaults(handler=diagnose.owners_report)

    composition_cmd = _command(
        diagnose_sub, "diagnose", "composition", "composed lineages and planes"
    )
    composition_cmd.set_defaults(handler=diagnose.composition_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse, dispatch to exactly one owner, render, and return a stable code."""
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.version:
        print(f"{DISTRIBUTION} {installed_version(DISTRIBUTION) or 'not installed'}")
        return int(ExitCode.OK)

    if getattr(args, "group", None) is None or getattr(args, "name", None) is None:
        parser.print_help(sys.stderr)
        return int(ExitCode.USAGE)

    command = args.command
    if command == "deployment foundation":
        # The one passthrough. The delegate's own status is returned unchanged:
        # remapping it would invent a verdict this process did not compute.
        # Only a LEADING `--` is removed — it is this parser's separator, not
        # the delegate's argument. Stripping every occurrence would silently
        # rewrite a vector the whole point of this command is to forward
        # untouched.
        forwarded = list(args.argv)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        try:
            return int(delegate_exit(run_foundation(forwarded)))
        except Refusal as refusal:
            return int(emit(_as_result(command, refusal), args.output_format))

    if command not in by_command():
        parser.error(f"{command!r} has no declared owner")

    if command in {
        "gate0 collection-check-activation",
        "gate0 collection-check-retirement",
    }:
        try:
            from vendor_cp.deployment.gate0_collection_activation import (
                run_installed_collection_check_activation,
                run_installed_collection_check_retirement,
            )

            if command == "gate0 collection-check-activation":
                return run_installed_collection_check_activation()
            return run_installed_collection_check_retirement()
        except Exception:
            print("GATE0_COLLECTION_UNAVAILABLE", file=sys.stderr)
            return int(ExitCode.REFUSED)

    if command in {
        "gate0 finalize-e",
        "gate0 await-e-transfer",
        "gate0 prepare-e-draft",
        "gate0 publish-e",
        "gate0 verify-e-b-archive",
        "gate0 verify-e-published",
    }:
        try:
            if command == "gate0 await-e-transfer":
                from vendor_cp.deployment.gate0_e_transfer import (
                    run_installed_await_e_transfer,
                )

                return run_installed_await_e_transfer()
            if command == "gate0 prepare-e-draft":
                from vendor_cp.deployment.gate0_e_publication import (
                    run_installed_prepare_e_draft,
                )

                return run_installed_prepare_e_draft()
            if command == "gate0 publish-e":
                from vendor_cp.deployment.gate0_e_publication import (
                    run_installed_publish_e,
                )

                return run_installed_publish_e()
            if command == "gate0 verify-e-published":
                from vendor_cp.deployment.gate0_e_final_readback import (
                    run_installed_verify_e_published,
                )

                return run_installed_verify_e_published()
            if command == "gate0 finalize-e":
                from vendor_cp.deployment.gate0_e_writer import run_installed_prepare_e

                return run_installed_prepare_e()
            from vendor_cp.deployment.gate0_e_b_holder import (
                run_installed_verify_e_b_archive,
            )

            return run_installed_verify_e_b_archive()
        except Exception:
            print("GATE0_E_UNAVAILABLE", file=sys.stderr)
            return 3

    if command == "gate0 public-jit-runner-credential":
        try:
            from vendor_cp.deployment.gate0_runner_lifecycle_courier import (
                run_installed_public_jit_runner,
            )

            return run_installed_public_jit_runner()
        except Exception:
            return 3

    if command == "gate0 collect-e":
        from vendor_cp.cli.commands import gate0_collect_e

        return gate0_collect_e(args)

    if command in {
        "gate0 bootstrap-collector",
        "gate0 collect-e-credential",
        "gate0 lifecycle-run",
        "gate0 lifecycle-retire-jit",
        "gate0 jit-runner-credential",
        "gate0 courier-original-oidc",
    }:
        try:
            if command == "gate0 lifecycle-run":
                from vendor_cp.deployment.gate0_runner_supervisor import (
                    run_installed_lifecycle,
                )

                return run_installed_lifecycle()
            if command == "gate0 lifecycle-retire-jit":
                from vendor_cp.deployment.gate0_runner_supervisor import (
                    run_installed_lifecycle_retirement,
                )

                return run_installed_lifecycle_retirement()
            if command in {
                "gate0 jit-runner-credential",
                "gate0 courier-original-oidc",
            }:
                from vendor_cp.deployment.gate0_runner_lifecycle_courier import (
                    run_installed_jit_runner,
                    run_installed_job_courier,
                )

                if command == "gate0 jit-runner-credential":
                    return run_installed_jit_runner()
                return run_installed_job_courier()
            if command == "gate0 bootstrap-collector":
                from vendor_cp.deployment.gate0_runner_bootstrap import (
                    run_installed_bootstrap,
                )

                return run_installed_bootstrap()
            from vendor_cp.deployment.gate0_runner_credential import (
                run_installed_credential_collection,
            )

            return run_installed_credential_collection()
        except Exception:
            print("GATE0_BOOTSTRAP_UNAVAILABLE", file=sys.stderr)
            return int(ExitCode.REFUSED)

    if command in {"gate0 handoff-holder", "gate0 handoff-receiver"}:
        try:
            from vendor_cp.deployment import gate0_runner_handoff
        except Exception:
            print("GATE0_HANDOFF_REFUSED", file=sys.stderr)
            return int(ExitCode.REFUSED)
        if command == "gate0 handoff-holder":
            return gate0_runner_handoff.run_installed_handoff_holder()
        return gate0_runner_handoff.run_installed_handoff_receiver()

    if command in {
        "gate0 issuer-run",
        "gate0 attester-session",
        "gate0 capture-install",
        "gate0 capture-send",
        "gate0 supervise",
    }:
        # These owners speak a closed binary stdio protocol. Generic CLI result
        # rendering would corrupt the service's stdout stream.
        # Runtime/custody owners load only for the selected service. Building
        # the parser must not validate unrelated runtime environment settings.
        try:
            from vendor_cp.deployment import gate0_services
        except Exception:
            # Import-time configuration errors may contain sensitive values.
            # Keep this guard around the import only; owners retain their own
            # cancellation, incomplete-result and execution error handling.
            print("GATE0_SERVICE_REFUSED", file=sys.stderr)
            return int(ExitCode.REFUSED)

        if command == "gate0 issuer-run":
            return gate0_services.run_installed_issuer()
        if command == "gate0 attester-session":
            return gate0_services.run_installed_attester()
        if command == "gate0 capture-install":
            return gate0_services.run_installed_capture_receiver()
        if command == "gate0 capture-send":
            return gate0_services.run_installed_capture_sender()
        return gate0_services.run_installed_supervisor()

    if command == "deployment candidate-material-probe":
        from vendor_cp.deployment.candidate_materials import (
            CandidateMaterialProbeResult,
            quiet_evaluation,
            unavailable_result,
        )

        with quiet_evaluation():
            try:
                probe_result: CandidateMaterialProbeResult = args.handler(args)
                if type(probe_result) is not CandidateMaterialProbeResult:
                    probe_result = unavailable_result()
                document = probe_result.json_document()
                code = probe_result.exit_code
            except BaseException:
                probe_result = unavailable_result()
                document = probe_result.json_document()
                code = probe_result.exit_code
        print(document)
        return code

    try:
        result = args.handler(args)
    except Exception as error:  # noqa: BLE001 - every path below reports it
        result = _as_result(command, translate(error))
    return int(emit(result, args.output_format))


def _as_result(command: str, refusal: Refusal) -> Result:
    """One verdict, rendered as the same envelope a success uses."""
    return Result(
        command=command,
        exit_code=refusal.exit_code,
        refusal_code=refusal.code,
        message=refusal.message,
    )


def run() -> None:
    """The console-script entry point declared in `pyproject.toml`."""
    raise SystemExit(main())


__all__ = ["GROUPS", "PROGRAM", "build_parser", "main", "run"]
