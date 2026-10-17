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


# Only fixed metadata is eligible for failure output. No exception text, path,
# local/frame values, member names or post-failure file reads enter diagnostics.
_DIAGNOSTIC = {"phase": "entry", "cleanup_outcome": "not_started", "work_failure": None}
_SOURCE_OWNERS = {
    str(ROOT / "conformance/check_gate0_role_export.py"): "checker",
    str(ROOT / ".github/candidate/retain_gate0_publisher.py"): "role_retention",
    str(ROOT / ".github/candidate/inspect_gate0_publisher.py"): "role_inspector",
    __file__: "checker",
}
_EXCEPTION_KINDS = frozenset(
    {
        "ValueError",
        "RetentionRefused",
        "KeyError",
        "TypeError",
        "OSError",
        "FileNotFoundError",
        "PermissionError",
        "TimeoutError",
        "JSONDecodeError",
        "ReadError",
        "HeaderError",
        "UnicodeDecodeError",
        "ImportError",
        "ModuleNotFoundError",
        "AttributeError",
        "RuntimeError",
    }
)
_REFUSAL_PREDICATES = {
    "runtime retention refused": "retention_structural_refusal",
    "role saved-config rootfs mismatch": "saved_config_ordered_diff_ids",
    "role saved-config fields differ": "saved_config_field_equality",
    "private input shape": "private_input_shape",
    "rootfs archive framing": "rootfs_archive_framing",
    "rootfs archive terminator": "rootfs_archive_terminator",
    "rootfs trailing data": "rootfs_trailing_data",
    "rootfs header budget": "rootfs_header_budget",
    "rootfs extension budget": "rootfs_extension_budget",
    "rootfs extension framing": "rootfs_extension_framing",
    "sparse rootfs member": "rootfs_sparse_member",
    "noncanonical rootfs member": "rootfs_path_canonical",
    "rootfs budget": "rootfs_budget",
    "rootfs link budget": "rootfs_link_budget",
    "duplicate rootfs member": "rootfs_duplicate_member",
    "special rootfs member": "rootfs_special_member",
    "checkout, cache, or credential material": "rootfs_forbidden_material",
    "non-root protected owner": "protected_owner",
    "writable protected path": "protected_write_mode",
    "protected hardlink": "protected_hardlink",
    "protected native link": "protected_native_link",
    "protected link": "protected_link",
    "unsafe protected ancestry": "protected_ancestry",
    "unsafe protected link target": "protected_link_target",
    "embedded role metadata": "embedded_role_metadata",
    "installed wheel owner bytes": "installed_wheel_owner_bytes",
    "installed wheel owner closure": "installed_wheel_owner_closure",
    "native tool subject": "native_tool_subject",
    "role UID subject": "role_uid_subject",
    "role home custody": "role_home_custody",
    "hosted source conformance only": "hosted_only",
    "source conformance owner missing": "source_owner_missing",
    "source conformance revision": "source_revision",
    "source conformance private ownership": "private_directory_ownership",
    "source conformance image": "immutable_image_id",
    "source conformance private cleanup": "private_directory_cleanup",
    "source conformance arguments": "fixed_arguments",
}


_CONFIG_DIAGNOSTIC_FIELDS = frozenset(
    {
        "Hostname",
        "Domainname",
        "User",
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "ExposedPorts",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "Env",
        "Cmd",
        "Healthcheck",
        "ArgsEscaped",
        "Image",
        "Volumes",
        "WorkingDir",
        "Entrypoint",
        "NetworkDisabled",
        "MacAddress",
        "OnBuild",
        "Labels",
        "StopSignal",
        "StopTimeout",
        "Shell",
    }
)


def _config_diagnostic(error):
    value = getattr(error, "role_config_difference", None)
    keys = {
        "type_mismatch",
        "only_in_saved",
        "only_in_inspected",
        "different",
        "unknown_saved_count",
        "unknown_inspected_count",
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or type(value["type_mismatch"]) is not bool
    ):
        return None
    for key in ("only_in_saved", "only_in_inspected", "different"):
        rows = value[key]
        if (
            not isinstance(rows, list)
            or len(rows) > len(_CONFIG_DIAGNOSTIC_FIELDS)
            or any(
                type(row) is not str or row not in _CONFIG_DIAGNOSTIC_FIELDS
                for row in rows
            )
            or len(rows) != len(set(rows))
        ):
            return None
    if any(
        type(value[key]) is not int or not 0 <= value[key] <= 65536
        for key in ("unknown_saved_count", "unknown_inspected_count")
    ):
        return None
    return value


def _failure_metadata(error):
    kind = type(error).__name__
    # Look up exact reviewed literal messages; never render arbitrary arguments.
    message = (
        error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
    )
    predicate = _REFUSAL_PREDICATES.get(message, "unclassified")
    locations = []
    trace = error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        label = _SOURCE_OWNERS.get(trace.tb_frame.f_code.co_filename)
        if label is not None:
            locations.append({"owner": label, "line": trace.tb_lineno})
        trace = trace.tb_next
    return {
        "exception_kind": kind if kind in _EXCEPTION_KINDS else "other",
        "predicate": predicate,
        "source_locations": locations,
        "config_field_difference": _config_diagnostic(error),
    }


def _failure_chain(error):
    chain, seen = [], set()
    for _ in range(4):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        chain.append(_failure_metadata(error))
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return chain


def _failure_report(error):
    return {
        "schema": "Gate0RoleExportSourceConformanceFailure.v1",
        "phase": _DIAGNOSTIC["phase"],
        "cleanup_outcome": _DIAGNOSTIC["cleanup_outcome"],
        "work_failure": _DIAGNOSTIC["work_failure"],
        "exception_chain": _failure_chain(error),
    }


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
    _DIAGNOSTIC.update(
        phase="hosted_guard", cleanup_outcome="not_started", work_failure=None
    )
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("hosted source conformance only")
    _DIAGNOSTIC["phase"] = "owner_load"
    retention = owner("retain_gate0_publisher")
    inspector = owner("inspect_gate0_publisher")
    _DIAGNOSTIC["phase"] = "observation_directory"
    observation = retention.role_private_directory(observation_argument)
    started, wall = time.monotonic(), time.time()
    # One original five-minute clock; reserve twenty seconds for owned cleanup.
    deadline = retention.ProductionDeadline(started + 280, wall + 280)
    _DIAGNOSTIC["phase"] = "source_revision"
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
    _DIAGNOSTIC["phase"] = "source_hashes"
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
    _DIAGNOSTIC["phase"] = "export_directory"
    private = retention.role_private_directory(private_argument)
    if private == observation or any(private.iterdir()):
        raise ValueError("source conformance private ownership")
    completed = False
    try:
        _DIAGNOSTIC["phase"] = "observation_copy"
        for name in ("role-image-id", "role-image.json", "smoke.json", "network.json"):
            raw = retention.read_owned_regular(
                observation / name, retention.MAX_METADATA_BYTES, private=True
            )
            with inspector.private_output(private / name) as output:
                output.write(raw)
        _DIAGNOSTIC["phase"] = "immutable_image_id"
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
        _DIAGNOSTIC["phase"] = "base_inspection"
        try:
            base_raw = retention.run_bounded(
                ["/usr/bin/docker", "image", "inspect", retention.ROLE_BASE_IMAGE],
                deadline,
            )
        except retention.RetentionRefused:
            _DIAGNOSTIC["phase"] = "base_pull"
            retention.run_bounded(
                ["/usr/bin/docker", "pull", retention.ROLE_BASE_IMAGE],
                deadline,
                maximum=1024**2,
            )
            _DIAGNOSTIC["phase"] = "base_reinspection"
            base_raw = retention.run_bounded(
                ["/usr/bin/docker", "image", "inspect", retention.ROLE_BASE_IMAGE],
                deadline,
            )
        _DIAGNOSTIC["phase"] = "base_identity"
        retention.role_base_identity(base_raw)
        _DIAGNOSTIC["phase"] = "export_creation"
        container_id = retention.role_export_create(private, image_id, deadline)
        _DIAGNOSTIC["phase"] = "rootfs_export"
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
        _DIAGNOSTIC["phase"] = "image_save"
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
        _DIAGNOSTIC["phase"] = "image_config_join"
        images = retention.role_export_image_subject(
            private, revision, inspector, deadline
        )
        _DIAGNOSTIC["phase"] = "rootfs_subject_join"
        with inspector.private_input(
            private / "role.tar", retention.MAX_TAR_BYTES
        ) as rootfs:
            measured, _, _ = retention.role_export_measurement(
                private, source, retention.LIMITS, inspector, rootfs, image_id
            )
        _DIAGNOSTIC["phase"] = "final_work_deadline"
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
    except Exception as error:
        _DIAGNOSTIC["work_failure"] = {
            "phase": _DIAGNOSTIC["phase"],
            **_failure_metadata(error),
        }
        raise
    finally:
        _DIAGNOSTIC["phase"] = "owned_container_cleanup"
        _DIAGNOSTIC["cleanup_outcome"] = "unconfirmed"
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
        _DIAGNOSTIC["phase"] = "private_directory_cleanup"
        shutil.rmtree(private)
        if private.exists():
            raise ValueError("source conformance private cleanup")
        _DIAGNOSTIC["cleanup_outcome"] = "confirmed"
    if completed:
        print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("source conformance arguments")
        check(sys.argv[1], sys.argv[2])
    except Exception as error:
        print(json.dumps(_failure_report(error), sort_keys=True), file=sys.stderr)
        raise SystemExit("role export source conformance refused") from None
