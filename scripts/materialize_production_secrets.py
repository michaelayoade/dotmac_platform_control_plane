#!/usr/bin/env python3
"""Seed and materialize the Vendor Control Plane production secret contract."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from vendor_cp.production_secrets import (
    HostSecretBundle,
    ProductionSecretError,
    build_host_bundle,
    client_from_environment,
    materialize_host_bundle,
    seed_missing_records,
    sync_github_deploy_key,
    transfer_host_bundle,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("seed", help="create absent OpenBao records with CAS=0")

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
            receipt = materialize_host_bundle(
                bundle,
                env_template=args.env_template,
                env_file=args.env_file,
                signing_key_file=args.signing_key_file,
                authorized_keys_file=args.authorized_keys_file,
                app_owner=(10001, 10001),
            )
            for materialized_path in (
                receipt.env_file,
                receipt.signing_key_file,
                receipt.authorized_keys_file,
            ):
                print(f"materialized {materialized_path}")
            return 0
    except ProductionSecretError as exc:
        print(f"production secret materialization refused: {exc}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
