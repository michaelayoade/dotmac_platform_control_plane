"""Hosted installed-wheel Linux cgroup proofs; never run on a workstation.

These tests prove the native descendant boundary, including supervisor crash.
The coordinator's installed SSH bundle must additionally run actual ForceCommand
claims, both channel patterns and network/capture bootstrap. These tests alone
are not those missing installed-path qualification receipts.
"""

import os
import select
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

import pytest

from vendor_cp.deployment import gate0_launch


@pytest.fixture
def native_boundary():
    assert os.environ.get("GITHUB_ACTIONS") == "true", "hosted-only cgroup fixture"
    assert os.geteuid() == 0, "dedicated root cgroup fixture required"
    assert (
        Path(gate0_launch.__file__)
        .resolve()
        .is_relative_to(Path(sysconfig.get_path("purelib")).resolve())
    ), "installed wheel required"
    # The hosted installation owner supplies only this root delegation. Missing
    # cgroup.kill/delegation is failure, not a skip or process-group fallback.
    boundary = gate0_launch.SlotExecutionBoundary("issue")
    try:
        yield boundary
    finally:
        if not boundary._closed:
            boundary.terminate_and_confirm_empty()
        boundary.path.rmdir()  # fixture teardown only; production never rearms


def test_cgroup_kills_setsid_double_fork_and_native_stall(native_boundary):
    boundary = native_boundary
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = None
    try:
        boundary.start_watchdog(time.monotonic() + 2)
        child = subprocess.Popen(  # noqa: S603 -- fixed hosted synthetic process plant
            [
                sys.executable,
                "-I",
                "-c",
                "import os,time; os.setsid(); os.fork(); os.fork(); "
                "os.write(1,str(os.getpid()).encode()+b'\\n'); time.sleep(60)",
            ],
            stdout=writer,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            preexec_fn=boundary.enter_child,
        )
        os.close(writer)
        writer = -1
        assert select.select([reader], [], [], 1)[0], "plant must enter boundary"
        assert os.read(reader, 128)
        boundary.terminate_and_confirm_empty()
        child.wait(timeout=2)
        assert b"populated 0" in (boundary.path / "cgroup.events").read_bytes()
    finally:
        os.close(reader)
        if writer != -1:
            os.close(writer)
        if not boundary._closed:
            boundary.terminate_and_confirm_empty()
        if child is not None:
            child.wait(timeout=2)


def test_watchdog_kills_when_coordinator_crashes(native_boundary):
    boundary = native_boundary
    parent = os.fork()
    if parent == 0:
        try:
            boundary.start_watchdog(time.monotonic() + 2)
            reader, writer = os.pipe2(os.O_CLOEXEC)
            worker = os.fork()
            if worker == 0:
                # A real fixed daemon exec closes this CLOEXEC parent end.
                os.close(boundary._watchdog_write)
                os.close(reader)
                boundary.enter_child()
                os.write(writer, b"joined")
                os.close(writer)
                os.setsid()
                time.sleep(60)
                os._exit(0)
            os.close(writer)
            if (
                not select.select([reader], [], [], 1)[0]
                or os.read(reader, 64) != b"joined"
            ):
                os._exit(1)
            os.close(reader)
            if b"populated 1" not in (boundary.path / "cgroup.events").read_bytes():
                os._exit(1)
            # Only a positively joined live worker can license the crash plant.
            os._exit(0)
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(parent, 0)
    assert status == 0
    end = time.monotonic() + 4
    while time.monotonic() < end:
        if b"populated 0" in (boundary.path / "cgroup.events").read_bytes():
            break
        time.sleep(0.01)
    assert b"populated 0" in (boundary.path / "cgroup.events").read_bytes()
    # This parent did not own/reap the guardian started in the forked copy.
    # Empty descendants prove crash containment, not complete E cleanup.
    with pytest.raises(gate0_launch.ProviderRefused):
        boundary.terminate_and_confirm_empty()
    assert boundary._closed and not boundary._cleanup_complete


def test_installed_supervise_command_refuses_missing_operational_packet():
    assert (
        os.environ.get("GITHUB_ACTIONS") == "true"
    ), "hosted-only installed role image"
    assert os.geteuid() == 0
    assert (
        Path(gate0_launch.__file__)
        .resolve()
        .is_relative_to(Path(sysconfig.get_path("purelib")).resolve())
    )
    assert not (
        gate0_launch.ROOT / "packet.json"
    ).exists(), "negative fixture must have no operational packet"
    executable = "/opt/venv/bin/dotmac-platform"
    help_result = subprocess.run(  # noqa: S603 -- exact installed owner help command
        [executable, "gate0", "supervise", "--help"],
        timeout=5,
        capture_output=True,
        check=False,
    )
    assert help_result.returncode == 0
    refused = subprocess.run(  # noqa: S603 -- exact installed owner, no activation inputs
        [executable, "gate0", "supervise"],
        timeout=5,
        capture_output=True,
        check=False,
    )
    assert refused.returncode != 0
