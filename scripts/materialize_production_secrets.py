#!/usr/bin/env python3
"""Seed and materialize the Vendor Control Plane production secret contract."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from vendor_cp.production_secrets import (
    ROLLBACK_CONFIRMATION,
    HostSecretBundle,
    ProductionSecretError,
    build_host_bundle,
    build_rollback_payload,
    client_from_environment,
    complete_rotation_rollback,
    execute_secret_rotation,
    install_rotation_adapter,
    materialize_host_bundle,
    pin_product_release,
    read_rotation_receipt,
    reconcile_host_environment_declarations,
    retire_rotation_adapter,
    rollback_openbao_rotation,
    seed_missing_records,
    sync_github_deploy_key,
    transfer_host_bundle,
    transfer_rotation_payload,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("seed", help="create absent OpenBao records with CAS=0")

    rotate = subparsers.add_parser(
        "rotate-production",
        help="resume the fixed vendor-cp-prod incident rotation",
    )
    rotate.add_argument("--known-hosts", required=True, type=Path)
    rotate.add_argument("--custody-file", required=True, type=Path)
    rotate.add_argument("--receipt-file", required=True, type=Path)
    rotate.add_argument("--expected-image", required=True)
    rotate.add_argument("--expected-revision", required=True)

    rollback = subparsers.add_parser(
        "rollback-production-incident",
        help="restore exposed material for outage containment only",
    )
    rollback.add_argument("--known-hosts", required=True, type=Path)
    rollback.add_argument("--receipt-file", required=True, type=Path)
    rollback.add_argument(
        "--confirm",
        required=True,
        help=f"must equal {ROLLBACK_CONFIRMATION!r}",
    )

    push = subparsers.add_parser("push", help="materialize a host over SSH stdin")
    push.add_argument("--target", required=True, help="explicit user@host target")
    push.add_argument("--target-dir", required=True, help="installed adapter root")
    push.add_argument("--known-hosts", required=True, type=Path)

    receive = subparsers.add_parser("receive", help=argparse.SUPPRESS)
    receive.add_argument("--env-template", required=True, type=Path)
    receive.add_argument("--env-file", required=True, type=Path)
    receive.add_argument(
        "--signing-key-file",
        type=Path,
        default=Path(
            "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
        ),
    )
    receive.add_argument(
        "--authorized-keys-file",
        type=Path,
        default=Path("/root/.ssh/authorized_keys"),
    )

    install_adapter = subparsers.add_parser(
        "install-rotation-adapter",
        help="install the digest-bound vendor-cp-prod incident adapter",
    )
    install_adapter.add_argument("--known-hosts", required=True, type=Path)

    retire_adapter = subparsers.add_parser(
        "retire-rotation-adapter",
        help="remove the proved incident adapter from vendor-cp-prod",
    )
    retire_adapter.add_argument("--known-hosts", required=True, type=Path)

    reconcile = subparsers.add_parser(
        "reconcile-declarations",
        help="atomically update only assembly-owned non-secret host declarations",
    )
    reconcile.add_argument("--env-template", required=True, type=Path)
    reconcile.add_argument("--env-file", required=True, type=Path)

    pin = subparsers.add_parser(
        "pin-product-release",
        help="atomically select exact catalogued evidence for one product",
    )
    pin.add_argument("--env-file", required=True, type=Path)
    pin.add_argument("--product-code", required=True)
    pin.add_argument("--artifact-digest", required=True)
    pin.add_argument("--product-manifest-digest", required=True)

    github = subparsers.add_parser(
        "sync-github-deploy-key", help="pipe the held key into gh secret set"
    )
    github.add_argument("--repository", required=True)
    github.add_argument("--environment", default="production")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "seed":
            created = seed_missing_records(client_from_environment())
            for path in created:
                print(f"created {path}")
            if not created:
                print("all production OpenBao records already exist")
            return 0
        if args.command == "rotate-production":
            store = client_from_environment()
            completed = execute_secret_rotation(
                store,
                custody_file=args.custody_file,
                receipt_file=args.receipt_file,
                expected_image_reference=args.expected_image,
                expected_source_revision=args.expected_revision,
                host_apply=lambda payload: transfer_rotation_payload(
                    payload,
                    known_hosts_file=args.known_hosts,
                ),
            )
            print(completed.to_json(), end="")
            return 0
        if args.command == "install-rotation-adapter":
            digest = install_rotation_adapter(known_hosts_file=args.known_hosts)
            print(f"installed production rotation adapter {digest}")
            return 0
        if args.command == "retire-rotation-adapter":
            retire_rotation_adapter(known_hosts_file=args.known_hosts)
            print("retired production rotation adapter")
            return 0
        if args.command == "rollback-production-incident":
            store = client_from_environment()
            receipt = read_rotation_receipt(args.receipt_file)
            custody, receipt = rollback_openbao_rotation(
                store,
                receipt,
                receipt_file=args.receipt_file,
                incident_confirmation=args.confirm,
            )
            proof = transfer_rotation_payload(
                build_rollback_payload(store, custody, receipt),
                known_hosts_file=args.known_hosts,
            )
            rolled_back = complete_rotation_rollback(
                receipt,
                proof,
                receipt_file=args.receipt_file,
            )
            print(rolled_back.to_json(), end="")
            return 0
        if args.command == "push":
            bundle = build_host_bundle(client_from_environment())
            transfer_host_bundle(
                bundle,
                target=args.target,
                target_dir=args.target_dir,
                known_hosts_file=args.known_hosts,
            )
            print("production host secrets materialized")
            return 0
        if args.command == "reconcile-declarations":
            if os.geteuid() != 0:
                raise ProductionSecretError("reconcile-declarations must run as root")
            changed = reconcile_host_environment_declarations(
                env_template=args.env_template,
                env_file=args.env_file,
            )
            if changed:
                print("reconciled production declarations: " + ", ".join(changed))
            else:
                print("production declarations already current")
            return 0
        if args.command == "pin-product-release":
            if os.geteuid() != 0:
                raise ProductionSecretError("pin-product-release must run as root")
            pin_changed = pin_product_release(
                env_file=args.env_file,
                product_code=args.product_code,
                artifact_digest=args.artifact_digest,
                product_manifest_digest=args.product_manifest_digest,
            )
            state = "updated" if pin_changed else "already current"
            print(f"product release pin {state}: {args.product_code!r}")
            return 0
        if args.command == "sync-github-deploy-key":
            sync_github_deploy_key(
                client_from_environment(),
                repository=args.repository,
                environment=args.environment,
            )
            print("GitHub production deploy key synchronized")
            return 0
        if args.command == "receive":
            if os.geteuid() != 0:
                raise ProductionSecretError("receive must run as root")
            bundle = HostSecretBundle.from_json(sys.stdin.read())
            materialization = materialize_host_bundle(
                bundle,
                env_template=args.env_template,
                env_file=args.env_file,
                signing_key_file=args.signing_key_file,
                authorized_keys_file=args.authorized_keys_file,
                app_owner=(10001, 10001),
            )
            for materialized_path in (
                materialization.env_file,
                materialization.signing_key_file,
                materialization.authorized_keys_file,
            ):
                print(f"materialized {materialized_path}")
            return 0
    except ProductionSecretError as exc:
        print(f"production secret materialization refused: {exc}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
