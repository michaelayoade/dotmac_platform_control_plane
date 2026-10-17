"""Hosted Linux installed-owner mechanics ONLY; no official runner/GitHub proof.

Run via stdin inside the existing built runtime image, network disabled and without
checkout mounts. Root exists only inside this disposable synthetic container.
"""

from __future__ import annotations

import os
import select
import shutil
import socket
import subprocess
import sys
import sysconfig
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vendor_cp.deployment import gate0_a9_native_fixture as fixture
from vendor_cp.deployment import gate0_runner_lifecycle as life
from vendor_cp.deployment import gate0_runner_lifecycle_courier as courier
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_runner_handoff import measure_handoff_process


class InstalledFixtureConformance(unittest.TestCase):
    """Actual installed CLI, exact courier and bash descriptor; synthetic lineage."""

    def setUp(self):
        self.assertEqual(sys.platform, "linux")
        self.assertEqual(os.geteuid(), 0)
        self.assertTrue(hasattr(os, "pidfd_open"))
        for module in (fixture, courier, life):
            self.assertTrue(
                any(
                    Path(module.__file__).is_relative_to(Path(sysconfig.get_path(name)))
                    for name in ("purelib", "platlib")
                )
            )
        self.cli = shutil.which("dotmac-platform")
        self.assertIsNotNone(self.cli)
        self.uid = self.gid = 10001
        self.root = Path("/run/dotmac-gate0-collector")
        self.jobroot = Path("/run/dotmac-gate0-jit")
        self.assertFalse(self.root.exists())
        self.assertFalse(self.jobroot.exists())
        self.root.mkdir(mode=0o755)
        self.socketdir = self.root / "courier"
        self.socketdir.mkdir(mode=0o750)
        os.chown(self.socketdir, 0, self.gid)
        self.jobroot.mkdir(mode=0o755)
        self.scriptdir = self.jobroot / "work" / "_temp"
        self.scriptdir.mkdir(parents=True, mode=0o700)
        os.chown(self.jobroot / "work", self.uid, self.gid)
        os.chown(self.scriptdir, self.uid, self.gid)
        self.children = []
        self.server = None
        now = datetime.now(UTC)
        elapsed = time.monotonic()
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        executable = os.readlink("/proc/self/exe")

        def pin(path):
            return dict(path=str(path), digest=life._hash(Path(path).read_bytes()))

        # Actual preliminary public bytes, explicitly not a native receipt. The
        # courier only parses this digest; production qualification remains closed.
        inventory = canonical(
            dict(schema="SyntheticUnqualifiedInventory.v1", disposition="UNQUALIFIED")
        )
        launcher = dict(
            schema="Gate0A9JitLauncherSelection.v1",
            runner_id=1,
            runner_name="synthetic",
            runner_group_id=2,
            owner_id=3,
            workflow_id=4,
            job_id=5,
            job_name="synthetic",
            environment_id=6,
            source_revision="a" * 40,
            cli=pin(self.cli),
            interpreter=pin(executable),
            systemctl=dict(
                path="/usr/bin/systemctl", digest=life._hash(b"unavailable-unused")
            ),
            manager=dict(
                path="/usr/lib/systemd/systemd",
                digest=life._hash(b"unavailable-unused"),
            ),
            runner_binary=dict(
                path=str(life._RUNNER), digest=life._hash(b"unused-synthetic-runner")
            ),
            runner_tree_digest=life._hash(b"unused-synthetic-tree"),
            unit_digest=life._hash(b"unused-synthetic-unit"),
            groups=[],
            native_receipt_digest=life._hash(inventory),
        )
        selection = dict(
            schema="Gate0A9CourierSelection.v1",
            lifecycle_binding_digest=life._hash(b"synthetic-source-intent"),
            courier_uid=self.uid,
            courier_gid=self.gid,
            groups=[],
            original_bounds=dict(
                boot_id=boot,
                wall=now.isoformat(),
                monotonic=elapsed,
                provisioning_ends_at=(now + timedelta(seconds=20)).isoformat(),
                finalization_ends_at=(now + timedelta(seconds=30)).isoformat(),
            ),
            launcher=launcher,
            source_files=dict(
                gate0_runner_lifecycle=life._hash(Path(life.__file__).read_bytes()),
                gate0_runner_lifecycle_courier=life._hash(
                    Path(courier.__file__).read_bytes()
                ),
            ),
        )
        path = self.socketdir / "installation.json"
        path.write_bytes(canonical(selection))
        path.chmod(0o640)
        os.chown(path, 0, self.gid)

    def tearDown(self):
        for process in self.children:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        if self.server is not None:
            self.server.close()
        shutil.rmtree(self.root)
        shutil.rmtree(self.jobroot)

    def listen(self):
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.bind(str(life._SOCKET))
        os.chown(life._SOCKET, 0, self.gid)
        life._SOCKET.chmod(0o660)
        self.server.listen(1)
        self.server.settimeout(5)

    def launch(self, script, url=None):
        path = self.scriptdir / "generated.sh"
        path.write_bytes(script)
        path.chmod(0o600)
        os.chown(path, self.uid, self.gid)
        env = dict(
            PATH="/opt/venv/bin:/usr/bin:/bin",
            LC_ALL="C",
            ACTIONS_ID_TOKEN_REQUEST_TOKEN="synthetic-unread-secret-canary",  # noqa: S106 -- synthetic unread canary
        )
        if url is not None:
            env["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
        process = subprocess.Popen(  # noqa: S603 -- fixed synthetic installed script vector
            [
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-p",
                "-e",
                "-o",
                "pipefail",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            user=self.uid,
            group=self.gid,
            extra_groups=[],
        )
        self.children.append(process)
        return process, path

    def safe_completion(self, process, expected):
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, expected)
        self.assertNotIn(b"synthetic-unread-secret-canary", stdout + stderr)
        return stdout

    def test_positive_exact_installed_courier_and_actual_bash_script_fd(self):
        self.listen()
        script = (self.cli + " gate0 courier-original-oidc\nbuiltin exit\n").encode()
        process, path = self.launch(script, "https://synthetic.example/opaque?x=1")
        peer, _ = self.server.accept()
        descriptor = None
        pidfd = -1
        try:
            parent, uid, start = measure_handoff_process(process.pid)
            self.assertEqual(uid, self.uid)
            self.assertEqual(parent, os.getpid())
            # Deliberately synthetic direct bash lineage; not four-runner proof.
            pidfd = os.pidfd_open(process.pid, 0)
            self.assertFalse(select.select([pidfd], [], [], 0)[0])
            descriptor = fixture._ScriptDescriptor(
                process.pid,
                start,
                path,
                life._hash(script),
                self.uid,
                time.monotonic() + 5,
            )
            observed = descriptor.recheck()
            self.assertGreater(observed["position_before"], 0)
            self.assertEqual(observed["position_before"], observed["position_after"])
            self.assertEqual(observed["file"]["inode"], observed["path_file"]["inode"])
            peer.send(life._METADATA_READY)
            peer.settimeout(5)
            raw = peer.recv(32768)
            self.assertEqual(strict_object(raw)["schema"], "Gate0A9BrokerMetadata.v1")
            metadata = fixture._metadata(
                raw, "metadata-positive", ["https://synthetic.example"]
            )
            self.assertEqual(metadata["origin"], "https://synthetic.example")
            peer.close()  # exact installed courier refuses before its token getter
            self.safe_completion(process, 3)
            self.assertTrue(select.select([pidfd], [], [], 0)[0])
        finally:
            peer.close()
            if descriptor is not None:
                descriptor.close()
            if pidfd >= 0:
                os.close(pidfd)

    def test_synthetic_bash_duplicate_or_changed_script_descriptor_refuses(self):
        for duplicate in (True, False):
            self.listen()
            prefix = 'exec 9< "$0"\nread -r synthetic_line <&9\n' if duplicate else ""
            script = (
                prefix + self.cli + " gate0 courier-original-oidc\nbuiltin exit\n"
            ).encode()
            process, path = self.launch(script, "https://synthetic.example/opaque?x=1")
            peer, _ = self.server.accept()
            descriptor = None
            try:
                _, _, start = measure_handoff_process(process.pid)
                if duplicate:
                    with self.assertRaises(life.LifecycleRefused):
                        fixture._ScriptDescriptor(
                            process.pid,
                            start,
                            path,
                            life._hash(script),
                            self.uid,
                            time.monotonic() + 5,
                        )
                else:
                    descriptor = fixture._ScriptDescriptor(
                        process.pid,
                        start,
                        path,
                        life._hash(script),
                        self.uid,
                        time.monotonic() + 5,
                    )
                    path.write_bytes(b"synthetic changed current bytes\n")
                    with self.assertRaises(life.LifecycleRefused):
                        descriptor.recheck()
            finally:
                if descriptor is not None:
                    descriptor.close()
                peer.close()
                self.safe_completion(process, 3)
                self.server.close()
                self.server = None
                life._SOCKET.unlink()

    def test_negative_installed_probe_and_errexit_stop_courier_on_present_url(self):
        for value in ("", "https://synthetic.example/opaque?x=1"):
            self.listen()
            script = (
                self.cli
                + " gate0 native-url-presence\n"
                + self.cli
                + " gate0 courier-original-oidc\nbuiltin exit\n"
            ).encode()
            process, _ = self.launch(script, value)
            stdout = self.safe_completion(process, 3)
            self.assertEqual(stdout, b"Gate0A9UrlPresence.v1 present\n")
            self.assertFalse(select.select([self.server], [], [], 0)[0])
            self.server.close()
            self.server = None
            life._SOCKET.unlink()

    def test_negative_absence_probe_arrives_then_metadata_ready_eof(self):
        self.listen()
        script = (
            self.cli
            + " gate0 native-url-presence\n"
            + self.cli
            + " gate0 courier-original-oidc\nbuiltin exit\n"
        ).encode()
        process, _ = self.launch(script)
        peer, _ = self.server.accept()
        try:
            peer.send(life._METADATA_READY)
            peer.settimeout(5)
            raw = peer.recv(32768)
            self.assertEqual(raw, b"")
            self.assertIsNone(fixture._metadata(raw, "missing-url-negative", []))
            self.assertEqual(
                self.safe_completion(process, 3), b"Gate0A9UrlPresence.v1 absent\n"
            )
        finally:
            peer.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
