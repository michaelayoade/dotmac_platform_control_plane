"""The command handlers: validate, authorise, delegate, render.

Every function here does the same four things and nothing else. It reads the
parsed arguments, opens the kernel's platform session, calls exactly one owner
named in `vendor_cp.cli.owners`, and turns the answer into a `Result`. There is
no business rule in this file, and `tests/architecture/test_installed_cli.py`
holds it to that: the owner table is compared against the parser in both
directions, and no mutating owner may live inside `vendor_cp.cli`.

Hard rule 6 applies to a console script exactly as it does to a route. These are
the same thin wrappers `router.py` files are, entered from a terminal instead of
from HTTP — which is why they call the SAME services, and why a screen, an API
client and an operator at a shell cannot reach three different answers.

## Imports are local to the handlers

`dotmac_kernel.db` builds its engine from `DATABASE_URL` at import time, so a
module-level import here would make `--help` require a configured database. The
clean-install acceptance runs `--help` in an environment that has none, and it
should keep working.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from uuid import UUID

from vendor_cp.cli.exits import refuse
from vendor_cp.cli.io import Result, read_bytes, read_secret
from vendor_cp.cli.runtime import platform_db


def _fields(value: object) -> dict[str, object]:
    """A frozen view object as a plain mapping the renderer can walk."""
    if is_dataclass(value) and not isinstance(value, type):
        return {key: item for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {"value": value}


# ── admin ───────────────────────────────────────────────────────────────────


def admin_create(args: argparse.Namespace) -> Result:
    """Create or rotate a platform administrator.

    The password arrives from a held file or stdin. There is no flag that takes
    it: `/proc/<pid>/cmdline` is world-readable for as long as the process
    lives, and a registration token leaked into a transcript on this fleet
    exactly that way.
    """
    from vendor_cp.platform_admin import upsert_platform_admin

    password = read_secret(
        from_file=args.password_file,
        from_stdin=args.password_stdin,
        prompt="platform admin password",
    )
    with platform_db() as db:
        outcome = upsert_platform_admin(
            db,
            email=args.email,
            password=password,
            is_active=not args.inactive,
        )
        return Result(
            command="admin create",
            data={
                "email": args.email,
                "created": outcome.created,
                "is_active": not args.inactive,
            },
            references={"platform_admin_id": str(outcome.admin.id)},
        )


def admin_migrate(args: argparse.Namespace) -> Result:
    """Apply the composed lineage to its declared heads, and nothing else.

    The refusal for any other target is `vendor_cp.migrations`' decision, not
    this command's: `alembic upgrade ap_0001_approvals` stops after the module's
    own migration and COMMITS a DML grant that vendor `v012` exists to remove.
    Nothing about that command looks dangerous, which is why the deploy path
    refuses it rather than documenting it.
    """
    import os

    from alembic import command as alembic_command

    from vendor_cp.migrations import (
        COMPOSED_TARGET,
        deploy_config,
        deploy_target_refusal,
    )

    url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not url:
        raise refuse(
            "config.missing",
            "set MIGRATION_DATABASE_URL (or DATABASE_URL) before migrating",
        )
    refusal = deploy_target_refusal(args.target)
    if refusal is not None:
        raise refuse("owner.migration_target_refused", refusal)
    os.environ.setdefault("DATABASE_URL", url)
    alembic_command.upgrade(deploy_config(url), COMPOSED_TARGET)
    return Result(
        command="admin migrate",
        data={"target": COMPOSED_TARGET},
        message="composed lineages advanced to heads",
    )


def admin_accounts(args: argparse.Namespace) -> Result:
    from vendor_cp.accounts.service import list_accounts

    with platform_db() as db:
        accounts = list_accounts(db)
    return Result(
        command="admin accounts",
        data={"count": len(accounts), "accounts": [_fields(a) for a in accounts]},
    )


def admin_account_create(args: argparse.Namespace) -> Result:
    from vendor_cp.accounts.service import CreateAccountCommand, create_account

    with platform_db() as db:
        outcome = create_account(
            db,
            CreateAccountCommand(
                command_id=args.command_id,
                external_ref=args.external_ref,
                display_name=args.display_name,
            ),
        )
        return Result(
            command="admin account-create",
            data={
                "account": _fields(outcome.account),
                "was_duplicate": outcome.was_duplicate,
            },
            references={"account_id": str(outcome.account.id)},
        )


# ── release ─────────────────────────────────────────────────────────────────


def release_record(args: argparse.Namespace) -> Result:
    """Catalogue exact release evidence for one product version."""
    from vendor_cp.config import vendor_settings
    from vendor_cp.release_evidence.service import (
        DirectoryProductManifestStore,
        ProductReleaseEvidenceCommand,
        ingest_product_release_evidence,
    )

    manifest = read_bytes(args.product_manifest_path, what="product manifest")
    with platform_db() as db:
        outcome = ingest_product_release_evidence(
            db,
            ProductReleaseEvidenceCommand(
                command_id=args.command_id,
                product_code=args.product_code,
                product_version=args.product_version,
                artifact_digest=args.artifact_digest,
                artifact_ref=args.artifact_ref,
                source_revision=args.source_revision,
                product_manifest_digest=args.product_manifest_digest,
                product_manifest=manifest,
                actor_admin_id=None,
                operator_ref=args.operator_ref,
            ),
            document_store=DirectoryProductManifestStore(
                root=vendor_settings.product_manifest_directory
            ),
        )
        return Result(
            command="release record",
            data={"replayed": outcome.replayed},
            references={
                "artifact_id": str(outcome.artifact_id),
                "attestation_id": str(outcome.attestation_id),
                "product_manifest_uri": outcome.product_manifest_uri,
            },
        )


def release_pins(args: argparse.Namespace) -> Result:
    from vendor_cp.config import load_vendor_settings

    settings = load_vendor_settings()
    return Result(
        command="release pins",
        data={
            "product_manifest_directory": str(settings.product_manifest_directory),
            "pins": {code: _fields(pin) for code, pin in settings.product_release_pins},
        },
    )


def release_catalogue(args: argparse.Namespace) -> Result:
    from vendor_cp.offers.catalog import configured_product_capability_catalogues

    with platform_db() as db:
        catalogues = configured_product_capability_catalogues(db)
    return Result(
        command="release catalogue",
        data={"resolved": True, "catalogues": repr(catalogues)},
        message="the pinned products' capability catalogues resolved",
    )


# ── agreement ───────────────────────────────────────────────────────────────


def agreement_list(args: argparse.Namespace) -> Result:
    from vendor_cp.contracts.adapter import list_agreements

    with platform_db() as db:
        page = list_agreements(
            db,
            after=UUID(args.after) if args.after else None,
            limit=args.limit,
        )
    return Result(
        command="agreement list",
        data={"items": [_fields(item) for item in page.items]},
        references={"next_after": str(page.next_after) if page.next_after else None},
    )


def agreement_show(args: argparse.Namespace) -> Result:
    from vendor_cp.contracts.adapter import get

    with platform_db() as db:
        view = get(db, UUID(args.agreement_id))
    if view is None:
        raise refuse(
            "evidence.not_found", f"commercial agreement {args.agreement_id} not found"
        )
    return Result(command="agreement show", data=_fields(view))


# ── approval ────────────────────────────────────────────────────────────────


def approval_publish_policy(args: argparse.Namespace) -> Result:
    from vendor_cp.approvals.adapter import PublishPolicyCommand, publish_policy_version

    with platform_db() as db:
        view = publish_policy_version(
            db,
            PublishPolicyCommand(
                command_id=args.command_id,
                policy_code=args.policy_code,
                version=args.policy_version,
                quorum=args.quorum,
                allow_self_approval=args.allow_self_approval,
            ),
        )
        return Result(command="approval publish-policy", data=_fields(view))


def approval_open(args: argparse.Namespace) -> Result:
    from vendor_cp.approvals.adapter import OpenRequestCommand, open_request

    with platform_db() as db:
        view = open_request(
            db,
            OpenRequestCommand(
                command_id=args.command_id,
                policy_code=args.policy_code,
                policy_version=args.policy_version,
                subject_type=args.subject_type,
                subject_id=args.subject_id,
                content_hash=args.content_hash,
                requested_by=UUID(args.requested_by),
            ),
        )
        return Result(
            command="approval open",
            data=_fields(view),
            references={"approval_request_id": str(view.request_id)},
        )


def approval_decide(args: argparse.Namespace) -> Result:
    from vendor_cp.approvals.adapter import RecordDecisionCommand, record_decision

    with platform_db() as db:
        view = record_decision(
            db,
            RecordDecisionCommand(
                command_id=args.command_id,
                request_id=UUID(args.request_id),
                approver_id=UUID(args.approver_id),
                content_hash=args.content_hash,
                approve=not args.reject,
            ),
        )
        return Result(command="approval decide", data=_fields(view))


def approval_show(args: argparse.Namespace) -> Result:
    from vendor_cp.approvals.adapter import evaluate_request

    with platform_db() as db:
        view = evaluate_request(db, request_id=UUID(args.request_id))
    return Result(command="approval show", data=_fields(view))


# ── allocation ──────────────────────────────────────────────────────────────


def allocation_show(args: argparse.Namespace) -> Result:
    from vendor_cp.allocations.adapter import read_allocation

    with platform_db() as db:
        view = read_allocation(db, UUID(args.allocation_id))
    if view is None:
        raise refuse("evidence.not_found", f"allocation {args.allocation_id} not found")
    return Result(command="allocation show", data=_fields(view))


def allocation_list(args: argparse.Namespace) -> Result:
    from vendor_cp.allocations.adapter import list_for_contract

    with platform_db() as db:
        views = list_for_contract(db, UUID(args.contract_id))
    return Result(
        command="allocation list",
        data={"count": len(views), "allocations": [_fields(v) for v in views]},
    )


# ── licence ─────────────────────────────────────────────────────────────────


def licence_issue(args: argparse.Namespace) -> Result:
    from vendor_cp.licensing.adapter import IssueLicenceCommand, issue_licence

    with platform_db() as db:
        view = issue_licence(
            db,
            IssueLicenceCommand(
                allocation_id=UUID(args.allocation_id),
                edition=args.edition,
                deployment_id=args.deployment_id,
                command_id=args.command_id,
            ),
        )
        return Result(
            command="licence issue",
            data={
                "licence_id": str(view.licence_id),
                "version": view.version,
                "status": view.status,
                "key_id": view.key_id,
            },
            references={"issuance_id": str(view.id), "digest": view.digest},
        )


def licence_revoke(args: argparse.Namespace) -> Result:
    from vendor_cp.licensing.adapter import RevokeLicenceCommand, revoke_licence

    with platform_db() as db:
        view = revoke_licence(
            db,
            RevokeLicenceCommand(
                licence_id=UUID(args.licence_id),
                reason=args.reason,
                command_id=args.command_id,
            ),
        )
        return Result(command="licence revoke", data=_fields(view))


def licence_publish_revocations(args: argparse.Namespace) -> Result:
    from vendor_cp.licensing.adapter import publish_revocation_list

    with platform_db() as db:
        view = publish_revocation_list(db, command_id=args.command_id)
        return Result(
            command="licence publish-revocations",
            data={
                "list_version": view.list_version,
                "entry_count": view.entry_count,
                "key_id": view.key_id,
            },
            references={"digest": view.digest},
        )


def licence_issuances(args: argparse.Namespace) -> Result:
    from vendor_cp.licensing.adapter import list_issuances

    with platform_db() as db:
        views = list_issuances(db, UUID(args.licence_id))
    return Result(
        command="licence issuances",
        data={
            "count": len(views),
            "issuances": [
                {
                    "id": str(v.id),
                    "version": v.version,
                    "status": v.status,
                    "digest": v.digest,
                    "key_id": v.key_id,
                }
                for v in views
            ],
        },
    )


def licence_keys(args: argparse.Namespace) -> Result:
    """List registered signing keys. Identifiers and standing only.

    A signing key's PRIVATE half never reaches this process and its public half
    is not what an operator is triaging, so neither is printed: the question
    this answers is which key ids exist and which of them may sign.
    """
    from vendor_cp.licensing.adapter import list_signing_keys

    with platform_db() as db:
        keys = list_signing_keys(db)
        rows = [{"key_id": key.key_id, "status": str(key.status)} for key in keys]
    return Result(command="licence keys", data={"count": len(rows), "keys": rows})


def licence_dispatch(args: argparse.Namespace) -> Result:
    from vendor_cp.licensing.transport import dispatch_pending

    with platform_db() as db:
        report = dispatch_pending(db, limit=args.limit, simulate=args.simulate)
        return Result(command="licence dispatch", data=_fields(report))


def licence_health(args: argparse.Namespace) -> Result:
    from datetime import UTC, datetime

    from vendor_cp.licensing.delivery_ops import pipeline_health

    with platform_db() as db:
        health = pipeline_health(db, now=datetime.now(UTC))
        return Result(command="licence health", data=_fields(health))


# ── deployment ──────────────────────────────────────────────────────────────


def deployment_targets(args: argparse.Namespace) -> Result:
    from vendor_cp.deployment.adapter import read_target

    with platform_db() as db:
        view = read_target(db, UUID(args.target_id))
    return Result(command="deployment targets", data=_fields(view))


def deployment_propose(args: argparse.Namespace) -> Result:
    """Freeze the target's desired state, and print what an approval must bind to."""
    from vendor_cp.deployment.adapter import (
        ProposePlanRequest,
        propose_deployment_plan,
    )

    with platform_db() as db:
        plan = propose_deployment_plan(
            db,
            ProposePlanRequest(
                command_id=args.command_id,
                target_id=UUID(args.target_id),
                approval_policy_code=args.policy_code,
                approval_policy_version=args.policy_version,
                actor_ref=args.actor_ref,
            ),
        )
        return Result(
            command="deployment propose",
            data=_fields(plan),
            references={
                "plan_id": str(plan.plan_id),
                "plan_digest": plan.plan_digest,
                "approval_subject_type": plan.subject_type,
                "approval_subject_id": str(plan.plan_id),
                "approval_content_hash": plan.approval_content_hash,
            },
            message=(
                "open an approval request against approval_subject_type / "
                "approval_subject_id / approval_content_hash, have it decided, "
                "then run `deployment authorize`"
            ),
        )


def deployment_authorize(args: argparse.Namespace) -> Result:
    """Carry the approval into the frozen plan and request the rollout.

    The `authorization_ref` this prints is the fleet's authorization run
    identity — the middle term a deployment foundation binds between the
    canonical descriptor and its own execution report. It is the reason this
    command exists.
    """
    from vendor_cp.deployment.adapter import AuthorizeRequest, authorize_deployment

    with platform_db() as db:
        receipt = authorize_deployment(
            db,
            AuthorizeRequest(
                command_id=args.command_id,
                plan_id=UUID(args.plan_id),
                approval_request_id=UUID(args.approval_request_id),
                rollout_ref=args.rollout_ref,
                reason=args.reason,
                actor_ref=args.actor_ref,
                expected_plan_digest=args.expect_plan_digest,
                expected_plan_version=args.expect_plan_version,
            ),
        )
        return Result(
            command="deployment authorize",
            data=_fields(receipt),
            references={
                "authorization_ref": receipt.authorization_ref,
                "rollout_ref": receipt.rollout_ref,
                "plan_digest": receipt.plan_digest,
                "approval_decision_ref": receipt.approval_decision_ref,
            },
        )


def deployment_plan(args: argparse.Namespace) -> Result:
    from vendor_cp.deployment.adapter import read_plan

    with platform_db() as db:
        view = read_plan(db, UUID(args.plan_id))
    return Result(command="deployment plan", data=_fields(view))


def deployment_rollout(args: argparse.Namespace) -> Result:
    from vendor_cp.deployment.adapter import read_rollout

    with platform_db() as db:
        view = read_rollout(db, UUID(args.rollout_id))
    return Result(command="deployment rollout", data=_fields(view))


def deployment_drift(args: argparse.Namespace) -> Result:
    from vendor_cp.deployment.adapter import read_drift

    with platform_db() as db:
        report = read_drift(db, UUID(args.target_id))
    return Result(command="deployment drift", data=_fields(report))


# ── recovery ────────────────────────────────────────────────────────────────


def recovery_capture_sql(args: argparse.Namespace) -> Result:
    """Emit the capture query. This command connects to nothing."""
    from vendor_cp.recovery.capture import capture_sql

    return Result(
        command="recovery capture-sql",
        data={"sql": capture_sql()},
        message="feed this to `psql -tA -f -` against the database being captured",
    )


def recovery_bundle(args: argparse.Namespace) -> Result:
    from vendor_cp.recovery.bundle import build_bundle

    raw = json.loads(
        read_bytes(args.capture, what="catalogue capture", limit=64_000_000)
    )
    try:
        outcome = build_bundle(
            raw,
            dump_digest=args.dump_digest,
            product=args.product,
            environment=args.environment,
            postgres_major=args.postgres_major,
            source_revision=args.source_revision,
            captured_at_epoch=args.captured_at,
        )
    except ModuleNotFoundError as error:
        raise refuse(
            "evidence.tool_absent",
            "dotmac-deployment-foundation is not installed, so the recovery "
            "facility that owns every bundle decision cannot be reached "
            f"({error}). This assembly does not pin it and must not "
            "re-implement it.",
        ) from error
    if args.out:
        from pathlib import Path

        Path(args.out).write_text(outcome.manifest_json, encoding="utf-8")
    return Result(
        command="recovery bundle",
        data={
            "excluded_superusers": list(outcome.excluded_superusers),
            "role_closure": [
                {"role": name, "reason": reason}
                for name, reason in outcome.role_closure
            ],
            "written_to": args.out,
        },
        references={"manifest_digest": outcome.manifest_digest},
        message=(
            f"excluded {len(outcome.excluded_superusers)} SUPERUSER role(s): a "
            "bundle refuses to carry one, because restoring a superuser turns "
            "possession of the artefact into possession of the cluster. A "
            "PRODUCT role in that list is a finding to fix at the source."
        ),
    )


__all__ = [
    "admin_account_create",
    "admin_accounts",
    "admin_create",
    "admin_migrate",
    "agreement_list",
    "agreement_show",
    "allocation_list",
    "allocation_show",
    "approval_decide",
    "approval_open",
    "approval_publish_policy",
    "approval_show",
    "deployment_authorize",
    "deployment_drift",
    "deployment_plan",
    "deployment_propose",
    "deployment_rollout",
    "deployment_targets",
    "licence_dispatch",
    "licence_health",
    "licence_issuances",
    "licence_issue",
    "licence_keys",
    "licence_publish_revocations",
    "licence_revoke",
    "recovery_bundle",
    "recovery_capture_sql",
    "release_catalogue",
    "release_pins",
    "release_record",
]
