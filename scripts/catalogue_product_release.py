#!/usr/bin/env python
"""Catalogue one exact product release and its canonical manifest bytes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotmac_kernel.db import platform_session

from vendor_cp.config import vendor_settings
from vendor_cp.release_evidence.service import (
    DirectoryProductManifestStore,
    ProductReleaseEvidenceCommand,
    ingest_product_release_evidence,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command-id", required=True)
    parser.add_argument("--product-code", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--artifact-ref", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--product-manifest-digest", required=True)
    parser.add_argument("--product-manifest-path", type=Path, required=True)
    parser.add_argument("--operator-ref", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    command = ProductReleaseEvidenceCommand(
        command_id=args.command_id,
        product_code=args.product_code,
        product_version=args.product_version,
        artifact_digest=args.artifact_digest,
        artifact_ref=args.artifact_ref,
        source_revision=args.source_revision,
        product_manifest_digest=args.product_manifest_digest,
        product_manifest=args.product_manifest_path.read_bytes(),
        actor_admin_id=None,
        operator_ref=args.operator_ref,
    )
    with platform_session() as db:
        result = ingest_product_release_evidence(
            db,
            command,
            document_store=DirectoryProductManifestStore(
                vendor_settings.product_manifest_directory
            ),
        )
    print(
        json.dumps(
            {
                "artifact_id": str(result.artifact_id),
                "attestation_id": str(result.attestation_id),
                "product_manifest_uri": result.product_manifest_uri,
                "replayed": result.replayed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
