"""Hosted source conformance for the already-smoked role export, never retention.

Reuse fixed image/config/rootfs joins without any operational retention context.
Only bounded counts/hashes and false readiness are printed; no member is run,
extracted, logged or uploaded. The workflow supplies an outer hard deadline.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def owner(name):
    spec = importlib.util.spec_from_file_location(
        "role_export_" + name, ROOT / ".github/candidate" / (name + ".py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("source conformance owner missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(observation_argument, private_argument):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("hosted source conformance only")
    retention = owner("retain_gate0_publisher")
    inspector = owner("inspect_gate0_publisher")
    observation = retention.role_private_directory(observation_argument)
    started, wall = time.monotonic(), time.time()
    # One original five-minute clock; reserve twenty seconds for owned cleanup.
    deadline = retention.ProductionDeadline(started + 280, wall + 280)
    revision = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("source conformance revision")
    actual = (
        retention.run_bounded(
            ["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"], deadline
        )
        .decode("ascii")
        .strip()
    )
    if actual != revision:
        raise ValueError("source conformance revision")
    source = {
        "revision": revision,
        "files": {
            key: inspector.digest(
                retention.read_owned_regular(
                    ROOT / relative, 16 * 1024**2, private=False
                )
            )
            for key, relative in retention.ROLE_SOURCE_FILES.items()
        },
    }
    private = retention.role_private_directory(private_argument)
    if private == observation or any(private.iterdir()):
        raise ValueError("source conformance private ownership")
    completed = False
    try:
        for name in ("role-image-id", "role-image.json", "smoke.json", "network.json"):
            raw = retention.read_owned_regular(
                observation / name, retention.MAX_METADATA_BYTES, private=True
            )
            with inspector.private_output(private / name) as output:
                output.write(raw)
        image_id = (
            retention.read_owned_regular(private / "role-image-id", 128, private=True)
            .decode("ascii")
            .strip()
        )
        if not image_id.startswith("sha256:"):
            raise ValueError("source conformance image")
        retention.sha256(image_id[7:])
        # BuildKit may not materialize the pinned source base as a local image.
        # Pull only that exact immutable source base, never a role/rebuild/tag.
        try:
            base_raw = retention.run_bounded(
                ["/usr/bin/docker", "image", "inspect", retention.ROLE_BASE_IMAGE],
                deadline,
            )
        except retention.RetentionRefused:
            retention.run_bounded(
                ["/usr/bin/docker", "pull", retention.ROLE_BASE_IMAGE],
                deadline,
                maximum=1024**2,
            )
            base_raw = retention.run_bounded(
                ["/usr/bin/docker", "image", "inspect", retention.ROLE_BASE_IMAGE],
                deadline,
            )
        retention.role_base_identity(base_raw)
        container_id = retention.role_export_create(private, image_id, deadline)
        retention.run_bounded(
            [
                "/usr/bin/docker",
                "export",
                "--output",
                str(private / "role.tar"),
                container_id,
            ],
            deadline,
        )
        retention.run_bounded(
            [
                "/usr/bin/docker",
                "image",
                "save",
                "--output",
                str(private / "role-image-save.tar"),
                image_id,
            ],
            deadline,
        )
        images = retention.role_export_image_subject(
            private, revision, inspector, deadline
        )
        with inspector.private_input(
            private / "role.tar", retention.MAX_TAR_BYTES
        ) as rootfs:
            measured, _, _ = retention.role_export_measurement(
                private, source, retention.LIMITS, inspector, rootfs, image_id
            )
        retention.check_deadline(deadline)
        measurement = retention.parse_json(measured, retention.MAX_METADATA_BYTES)
        summary = {
            "schema": "Gate0RoleExportSourceConformance.v1",
            "footprint": measurement["footprint"],
            "rootfs_sha256": measurement["role_rootfs_sha256"],
            "config_sha256": images["role"]["config_sha256"],
            "runtime_retained": False,
            "live_readiness": False,
        }
        completed = True
    finally:
        # The shared pinned owner verifies captured CID/name/image and its
        # protected ownership records before any removal. Preserve evidence on
        # unknown/mismatched creation or cleanup; workflow fallback reuses it.
        if any(
            path.exists() or path.is_symlink()
            for path in (
                private / "export-ownership-intent.json",
                private / "export-container-id",
            )
        ):
            retention.role_export_cleanup(private)
        shutil.rmtree(private)
        if private.exists():
            raise ValueError("source conformance private cleanup")
    if completed:
        print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("source conformance arguments")
        check(sys.argv[1], sys.argv[2])
    except Exception:
        raise SystemExit("role export source conformance refused") from None
