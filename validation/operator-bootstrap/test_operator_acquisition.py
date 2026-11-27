"""Hosted-only boundary tests; synthetic owner/curl perform no network or imports.

These isolate the adapter contract. The pinned acquisition owner's own hosted
suite remains necessary: this fake does not replace its archive/hash tests.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

import operator_acquisition as adapter


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.out = self.parent / "quarantine"
        self.token = "synthetic-test-only-credential-123456"
        self.manifest = b"[tool.poetry]\n"
        self.lock = b"package = []\n"
        self.plan = {"dotmac-kernel": "0.1.0a100",
                     "dotmac-deployment-control": "0.1.0a17",
                     **{f"fixture-{n}": "0.1.0a1" for n in range(5)}}
        # The sdist is deliberately hostile source-shaped opaque bytes. There
        # is no archive unpacker, import, resolver, builder or installer here.
        self.payloads = {}
        for name, version in self.plan.items():
            stem = name.replace("-", "_") + "-" + version
            self.payloads[stem + "-py3-none-any.whl"] = ("wheel:" + name).encode()
            self.payloads[stem + ".tar.gz"] = b"raise RuntimeError('sdist executed')"
        self.expected = {name: hashlib.sha256(data).hexdigest()
                         for name, data in self.payloads.items()}
        self.producer = SimpleNamespace(PRIVATE=self.plan,
                                       closed_plan=mock.Mock(return_value=(self.plan, self.expected)))
        self.owner = SimpleNamespace(subprocess=subprocess, ARTIFACT_MAX_BYTES=1024,
                                     ARTIFACT_MAX_SECONDS=30)
        self.owner.curl_argv = lambda url, target: [
            "curl", "--netrc", "--proto", "=https", "--max-redirs", "0",
            "--max-filesize", "1024", "--max-time", "30", "--silent",
            "--show-error", "-w", "%{http_code}", "-o", str(target), url]
        self.owner.approved_artifact_url = lambda url, base: url
        self.owner.credential_encodings = lambda value: {
            "raw": value,
            "base64": base64.b64encode(value.encode()).decode(),
            "owner_basic": base64.b64encode(("ci-reader:" + value).encode()).decode()}
        self.owner.acquired_matches_lock = mock.Mock(return_value=[])
        self.owner.wheel_identity_problems = mock.Mock(return_value=[])
        self.owner.acquire = self.acquire
        self.calls = []
        self.netrc_paths = []
        self.page_injection = b""
        self.extra = False
        self.change_hash = False
        self.return_changed = False
        self.fail = False
        self.bad_url = False
        self.bad_kwargs = False
        for name, value in (("MANIFEST_SHA256", hashlib.sha256(self.manifest).hexdigest()),
                            ("LOCK_SHA256", hashlib.sha256(self.lock).hexdigest()),
                            ("_RUN", self.curl)):
            patcher = mock.patch.object(adapter, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def curl(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertEqual(argv[:2], ["/usr/bin/curl", "--disable"])
        self.assertEqual(argv[4:10], ["--proxy", "", "--noproxy", "*", "--cacert", adapter.CA_FILE])
        netrc = Path(argv[3])
        self.netrc_paths.append(netrc)
        self.assertEqual(stat.S_IMODE(netrc.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(netrc.parent.stat().st_mode), 0o700)
        self.assertEqual(netrc.read_text(),
                         f"machine registry.dotmac.io login cp-bundle-reader password {self.token}\n")
        self.assertEqual(kwargs, {"check": False, "capture_output": True, "text": True,
                                 "env": {"PATH": "/usr/bin:/bin", "HOME": str(netrc.parent)},
                                 "timeout": 35})
        self.assertNotIn(self.token, repr(argv))
        self.assertNotIn(self.token, repr(kwargs))
        self.assertNotIn("--location", argv)
        self.assertNotIn("--retry", argv)
        self.assertNotIn("--netrc", argv)
        if self.fail:
            return SimpleNamespace(returncode=1, stdout="", stderr=self.token)
        target = Path(argv[-2])
        payload = self.payloads.get(target.name, b"<html>index</html>" + self.page_injection)
        target.write_bytes(payload)
        return SimpleNamespace(returncode=0, stdout="200", stderr="")

    def fetch(self, url, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=target.parent) as directory:
            staged = Path(directory) / target.name
            staged.parent.chmod(0o700)
            kwargs = {"check": False, "capture_output": True, "text": True}
            if self.bad_kwargs:
                kwargs["shell"] = True
            result = self.owner.subprocess.run(self.owner.curl_argv(url, staged), **kwargs)
            if result.returncode:
                raise RuntimeError(result.stderr)
            staged.rename(target)

    def acquire(self, plan, out, *, expected_artifacts):
        self.assertEqual(expected_artifacts, self.expected)
        (out / "files").mkdir(parents=True)
        for name in expected_artifacts:
            origin = "https://evil.invalid" if self.bad_url else adapter.ORIGIN
            self.fetch(origin + adapter.PREFIX + name, out / "files" / name)
        for name in plan:
            self.fetch(adapter.INDEX + "/" + name + "/", out / "pages" / (name + ".html"))
            directory = out / "simple" / name
            directory.mkdir(parents=True)
            (directory / "index.html").write_text("index")
        (out / "digests.json").write_text(json.dumps(expected_artifacts))
        if self.extra:
            (out / "unexpected.py").write_text("raise AssertionError")
        if self.change_hash:
            (out / "files" / next(iter(expected_artifacts))).write_bytes(b"changed")
        result = dict(expected_artifacts)
        if self.return_changed:
            result[next(iter(result))] = "0" * 64
        return result

    def run_acquisition(self):
        return adapter.acquire_baseline(self.owner, self.producer, self.manifest,
                                        self.lock, self.out, self.token)

    def assert_refused(self):
        with self.assertRaises(adapter.Refused) as caught:
            self.run_acquisition()
        self.assertEqual(str(caught.exception), "operator_acquisition_refused")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIs(self.owner.subprocess, subprocess)
        self.assertTrue(all(not p.exists() and not p.parent.exists() for p in self.netrc_paths))
        self.assertFalse((self.out / "accepted.json").exists())

    def test_transport_is_absolute_private_and_environment_isolated(self):
        with mock.patch.dict(os.environ, {"CURL_HOME": "/hostile", "CURL_CA_BUNDLE": "bad",
                                         "SSL_CERT_FILE": "bad", "HTTPS_PROXY": "evil",
                                         "PYTHONPATH": "evil", "GITHUB_TOKEN": self.token,
                                         "FORGEJO_CREDENTIAL": self.token}):
            result = self.run_acquisition()
        self.assertEqual(result["artifacts"], self.expected)
        self.assertEqual(result["artifact_count"], 14)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(len(self.calls), 21)
        self.assertEqual(self.owner.wheel_identity_problems.call_count, 7)
        self.assertEqual(self.owner.acquired_matches_lock.call_count, 7)
        self.assertIs(self.owner.subprocess, subprocess)
        self.assertTrue(all(not p.parent.exists() for p in self.netrc_paths))
        self.assertNotIn(self.token, repr(result))

    def test_raw_owner_failure_is_sanitized_and_proxy_restored(self):
        self.fail = True
        self.assert_refused()

    def test_timeout_is_sanitized_and_credentials_removed(self):
        def timeout(argv, **kwargs):
            self.netrc_paths.append(Path(argv[3]))
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=self.token)
        with mock.patch.object(adapter, "_RUN", timeout):
            self.assert_refused()

    def test_cp_basic_encoding_in_any_page_refuses(self):
        self.page_injection = base64.b64encode((adapter.CP_USERNAME + ":" + self.token).encode())
        self.assert_refused()
        self.assertEqual(len(self.calls), 21)

    def test_changed_file_bytes_refuse(self):
        self.change_hash = True
        self.assert_refused()

    def test_changed_returned_digest_refuses(self):
        self.return_changed = True
        self.assert_refused()

    def test_extra_bundle_file_refuses(self):
        self.extra = True
        self.assert_refused()

    def test_unapproved_url_never_reaches_curl(self):
        self.bad_url = True
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_other_subprocess_invocation_refuses(self):
        self.bad_kwargs = True
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_changed_curl_shape_refuses(self):
        original = self.owner.curl_argv
        self.owner.curl_argv = lambda url, target: original(url, target) + ["--location"]
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_output_parent_must_be_private(self):
        self.parent.chmod(0o755)
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_existing_destination_is_not_adopted(self):
        self.out.mkdir()
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_symlink_destination_refuses(self):
        self.out.symlink_to(self.parent, target_is_directory=True)
        self.assert_refused()
        self.assertEqual(self.calls, [])

    def test_owner_proxy_must_not_already_be_installed(self):
        stale = SimpleNamespace(run=mock.Mock())
        self.owner.subprocess = stale
        with self.assertRaisesRegex(adapter.Refused, "^operator_acquisition_refused$"):
            self.run_acquisition()
        self.assertIs(self.owner.subprocess, stale)
        stale.run.assert_not_called()

    def test_only_one_attempt_for_same_owner(self):
        self.fail = True
        self.assert_refused()
        count = len(self.calls)
        self.assert_refused()
        self.assertEqual(len(self.calls), count)

    def test_raw_input_identity_checked_before_producer(self):
        self.manifest += b"# changed"
        self.assert_refused()
        self.producer.closed_plan.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_wheel_identity_refusal_keeps_quarantine(self):
        self.owner.wheel_identity_problems.return_value = ["invalid identity"]
        self.assert_refused()
        self.assertTrue(self.out.is_dir())

    def test_symlink_anywhere_in_bundle_refuses(self):
        original = self.owner.acquire
        def acquire(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.out / "link").symlink_to(self.parent)
            return result
        self.owner.acquire = acquire
        self.assert_refused()


class RealOwnerCompositionTests(unittest.TestCase):
    """Exercise the real pinned owner, with only transport replaced.

    The hosted lane supplies the reviewed kernel_lock.py beside this test.
    Source/tool admission pins that file before test execution. The synthetic
    pair hash overrides are confined to this class and admit no live baseline.
    """

    def setUp(self):
        import kernel_lock

        self.owner = kernel_lock
        self.assertEqual(Path(kernel_lock.__file__).resolve(),
                         Path(__file__).resolve().with_name("kernel_lock.py"))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.parent.chmod(0o700)
        self.out = self.parent / "quarantine"
        self.token = "synthetic-owner-composition-only-credential"
        self.plan = {
            "dotmac-approvals": "0.1.0a8",
            "dotmac-commercial-agreements": "0.1.0a4",
            "dotmac-deployment-control": "0.1.0a17",
            "dotmac-entitlement-allocation": "0.1.0a6",
            "dotmac-kernel": "0.1.0a100",
            "dotmac-licensing": "0.1.0a1",
            "dotmac-release-catalog": "0.1.0a4",
        }
        self.payloads = {}
        for name, version in self.plan.items():
            stem = name.replace("-", "_") + "-" + version
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as wheel:
                wheel.writestr(stem + ".dist-info/METADATA",
                               f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n")
                wheel.writestr("hostile_fixture/__init__.py",
                               "raise AssertionError('acquired code executed')\n")
            self.payloads[stem + "-py3-none-any.whl"] = buffer.getvalue()
            self.payloads[stem + ".tar.gz"] = (
                b"opaque sdist; never extract or execute: "
                b"raise AssertionError('sdist code executed')\n" + name.encode())
        self.expected = {name: hashlib.sha256(payload).hexdigest()
                         for name, payload in self.payloads.items()}
        entries = []
        for name, version in self.plan.items():
            filenames = sorted(filename for filename in self.expected
                               if self.owner.artifact_belongs_to(filename, name, version))
            files = ", ".join("{file = " + json.dumps(filename) + ", hash = "
                              + json.dumps("sha256:" + self.expected[filename]) + "}"
                              for filename in filenames)
            entries.append(f"[[package]]\nname = {json.dumps(name)}\n"
                           f"version = {json.dumps(version)}\nfiles = [{files}]\n")
        self.lock = "\n".join(entries).encode()
        self.manifest = b"[tool.poetry]\nname = 'synthetic-owner-composition'\n"
        self.producer = SimpleNamespace(PRIVATE=self.plan,
                                       closed_plan=mock.Mock(return_value=(self.plan, self.expected)))
        self.calls = []
        self.netrc_paths = []
        self.corrupt = False
        self.pages = {}
        for name, version in self.plan.items():
            names = sorted(filename for filename in self.expected
                           if self.owner.artifact_belongs_to(filename, name, version))
            html = "\n".join(f'<a href="{adapter.ORIGIN}{adapter.PREFIX}{filename}">{filename}</a>'
                             for filename in names)
            self.pages[f"{adapter.INDEX}/{name}/"] = html.encode()
        # Each hosted test models a fresh launcher process/attempt. No owner
        # acquisition, fetch, publication or identity function is replaced.
        replacements = {"MANIFEST_SHA256": hashlib.sha256(self.manifest).hexdigest(),
                        "LOCK_SHA256": hashlib.sha256(self.lock).hexdigest(),
                        "_ATTEMPTED": [], "_RUN": self.fake_curl}
        for name, replacement in replacements.items():
            patcher = mock.patch.object(adapter, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fake_curl(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertEqual(argv[:2], ["/usr/bin/curl", "--disable"])
        self.assertEqual(argv[4:10], ["--proxy", "", "--noproxy", "*", "--cacert", adapter.CA_FILE])
        netrc = Path(argv[3])
        self.netrc_paths.append(netrc)
        self.assertEqual(stat.S_IMODE(netrc.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(netrc.parent.stat().st_mode), 0o700)
        self.assertIn("login cp-bundle-reader password " + self.token, netrc.read_text())
        self.assertEqual(kwargs, {"check": False, "capture_output": True, "text": True,
                                 "env": {"PATH": "/usr/bin:/bin", "HOME": str(netrc.parent)},
                                 "timeout": self.owner.ARTIFACT_MAX_SECONDS + 5})
        self.assertNotIn(self.token, repr(argv))
        self.assertNotIn(self.token, repr(kwargs))
        url = argv[-1]
        target = Path(argv[-2])
        if url in self.pages:
            payload = self.pages[url]
        else:
            self.assertEqual(url, adapter.ORIGIN + adapter.PREFIX + target.name)
            payload = self.payloads[target.name]
            if self.corrupt:
                payload += b"changed after reviewed digest"
        target.write_bytes(payload)
        return SimpleNamespace(returncode=0, stdout="200", stderr="")

    def acquire(self):
        return adapter.acquire_baseline(self.owner, self.producer, self.manifest,
                                        self.lock, self.out, self.token)

    def test_real_owner_complete_fourteen_artifact_closure(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "https://hostile.invalid",
                                         "CURL_HOME": "/hostile", "PYTHONPATH": "/hostile"}):
            result = self.acquire()
        self.assertEqual(result["artifacts"], self.expected)
        self.assertEqual(result["artifact_count"], 14)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(len(self.calls), 21)
        self.assertEqual({path.name for path in (self.out / "files").iterdir()}, set(self.expected))
        self.assertEqual(json.loads((self.out / "digests.json").read_text()), self.expected)
        self.assertEqual(len(list((self.out / "pages").glob("*.html"))), 7)
        self.assertEqual(len(list((self.out / "simple").glob("*/index.html"))), 7)
        for name, version in self.plan.items():
            filename = name.replace("-", "_") + "-" + version + "-py3-none-any.whl"
            metadata = self.owner.wheel_metadata(self.out / "files" / filename, name, version)
            self.assertEqual(metadata["name"], [name])
            self.assertEqual(metadata["version"], [version])
        self.assertIs(self.owner.subprocess, subprocess)
        self.assertTrue(all(not path.parent.exists() for path in self.netrc_paths))
        self.assertEqual(list(self.out.rglob(".staging-*")), [])
        self.assertFalse((self.out / "accepted.json").exists())
        self.assertNotIn(self.token, repr(result))

    def test_real_owner_hash_failure_prevents_publication_and_acceptance(self):
        self.corrupt = True
        with self.assertRaisesRegex(adapter.Refused, "^operator_acquisition_refused$"):
            self.acquire()
        # The real owner's fetch verifies the lock hash before atomic linking.
        self.assertTrue(self.out.is_dir())
        self.assertEqual(list((self.out / "files").iterdir()), [])
        self.assertFalse((self.out / "digests.json").exists())
        self.assertFalse((self.out / "accepted.json").exists())
        self.assertEqual(list(self.out.rglob(".staging-*")), [])
        self.assertIs(self.owner.subprocess, subprocess)
        self.assertTrue(all(not path.parent.exists() for path in self.netrc_paths))


if __name__ == "__main__":
    unittest.main()
