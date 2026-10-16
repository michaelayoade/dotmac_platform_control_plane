"""Proposed finite original-root E assembly; no workflow plaintext privilege.

External qualification selects static source/policy/trust/recipient inputs. Only
actual existing-root observations bind dynamic export facts. No native receipt,
human adoption, deadline extension or E acceptance is generated here.
"""

from __future__ import annotations

import time
from typing import Any

from vendor_cp.deployment import gate0_e_transfer as transfer
from vendor_cp.deployment import gate0_e_writer as writer
from vendor_cp.deployment import gate0_runner_supervisor as supervisor


def _original_context() -> dict[str, Any]:
    installed = supervisor.SupervisorInstallation.load()
    supervisor.SupervisorManager(installed).qualify()
    profile, _, _ = writer._load_root_static_profile()
    writer._require(
        profile["writer"]["campaign_digest"] == installed.lifecycle["campaign_digest"]
    )
    writer._require(
        profile["writer"]["a9"]["lifecycle_binding_digest"]
        == installed.lifecycle["lifecycle_binding_digest"]
    )
    for key in ("collector_uid", "courier_uid", "courier_gid"):
        writer._require(profile[key] == installed.lifecycle[key])
    supervisor._before(installed.bounds.finalization_end)
    return dict(
        deadline=installed.bounds.finalization_end,
        boot_id=installed.bounds.boot_id,
        campaign_digest=installed.lifecycle["campaign_digest"],
        lifecycle_binding_digest=installed.lifecycle["lifecycle_binding_digest"],
        courier_uid=installed.lifecycle["courier_uid"],
        courier_gid=installed.lifecycle["courier_gid"],
        profile_digest=writer._sha(writer.canonical(profile)),
        source_bundle_digest=profile["writer"]["source_bundle_digest"],
    )


def _initialize_work() -> None:
    context = _original_context()
    transfer._initialize_original_transfer(**context)
    supervisor._before(context["deadline"])


def _prepare_work() -> None:
    context = _original_context()
    owner = None
    try:
        owner = writer.InstalledEWriter.from_original_root_export()
        writer._require(time.monotonic() < context["deadline"])
        owner.prepare(deadline=context["deadline"])
        supervisor._before(context["deadline"])
        transfer._publish_original_encrypted_pair(**context)
        supervisor._before(context["deadline"])
    finally:
        if owner is not None:
            owner._discard_private_state()


def _initialize_checked() -> writer._PrivateFailure | None:
    try:
        _initialize_work()
    except BaseException as error:
        return writer._private_failure(error)
    return None


def _prepare_checked() -> writer._PrivateFailure | None:
    try:
        _prepare_work()
    except BaseException as error:
        return writer._private_failure(error)
    return None


def initialize_original_export() -> None:
    """Fixed root-only initialization before the original JIT starts."""
    failure = _initialize_checked()
    if failure is not None:
        writer._raise_private_failure(failure)


def prepare_original_export() -> None:
    """Fixed root-only finalization after successful bootstrap, before JIT wait."""
    failure = _prepare_checked()
    if failure is not None:
        writer._raise_private_failure(failure)
