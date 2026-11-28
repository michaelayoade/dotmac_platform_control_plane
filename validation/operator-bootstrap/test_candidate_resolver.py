"""Synthetic unit tests. Run only in the authorized isolated Python 3.12 runtime."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

spec = importlib.util.spec_from_file_location("candidate_resolver", Path(__file__).with_name("candidate_resolver.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Owner:
    """Small file-aware double; driver structural checks remain fully exercised."""
    def __init__(self):
        self.projections = []

    def parse_dependency_delta(self, *args):
        return args

    def drift_problems(self, before, after, delta, bundle):
        self.projections.append(copy.deepcopy(after))
        return []

    def artifact_belongs_to(self, filename, name, version):
        return filename.startswith(name.replace("-", "_") + "-" + version + "-")

    def acquired_matches_lock(self, digests, lock, name, version):
        entry = next(e for e in lock["package"] if e["name"] == name)
        acquired = {f: "sha256:" + d for f, d in digests.items() if self.artifact_belongs_to(f, name, version)}
        return [] if acquired == {f["file"]: f["hash"] for f in entry["files"]} else ["files disagree"]

    def metadata_binding_problems(self, entry, wheel, digests):
        return [] if wheel.is_file() and r.digest(wheel) == digests[wheel.name] else ["missing wheel"]

    def lock_wheel_problems(self, lock):
        return [e["name"] for e in lock["package"] if not any(f["file"].endswith(".whl") for f in e["files"])]

    def wheel_only_problems(self, offers):
        return [name for name, version, files in offers if not any(f.endswith(".whl") for f in files)]


class CandidatePairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name)
        (self.bundle / "files").mkdir()
        self.owner = Owner()
        self.private = {r.CONTROL: "0.1.0a17", "dotmac-kernel": "0.1.0a100", "dotmac-approvals": "0.1.0a8"}
        source = {"type": "legacy", "url": "https://registry.dotmac.io/api/packages/dotmac/pypi/simple", "reference": "forgejo"}
        packages = []
        self.digests = {}
        for name, version in self.private.items():
            filename = name.replace("-", "_") + "-" + version + "-py3-none-any.whl"
            payload = (name + " synthetic wheel").encode()
            value = hashlib.sha256(payload).hexdigest()
            packages.append({"name": name, "version": version, "source": copy.deepcopy(source),
                             "dependencies": {"dotmac-kernel": ">=0.1.0a100"} if name == r.CONTROL else {},
                             "groups": ["main"], "files": [{"file": filename, "hash": "sha256:" + value}]})
            if name != r.CONTROL:
                (self.bundle / "files" / filename).write_bytes(payload)
                self.digests[filename] = value
        self.before = {"package": packages, "metadata": {"content-hash": "before", "lock-version": "2.1"}}
        self.actual = copy.deepcopy(self.before)
        control = self.actual["package"][0]
        control.update(version="0.1.0a18", source={"type": "legacy", "url": r.CANDIDATE_URL, "reference": r.CANDIDATE_NAME})
        # Synthetic bytes intentionally use a patched constant only inside these unit tests.
        self.original_sha = r.WHEEL_SHA
        (self.bundle / "files" / r.WHEEL).write_bytes(b"synthetic a18 wheel")
        r.WHEEL_SHA = r.digest(self.bundle / "files" / r.WHEEL)
        control["files"] = [{"file": r.WHEEL, "hash": "sha256:" + r.WHEEL_SHA}]
        self.digests[r.WHEEL] = r.WHEEL_SHA
        (self.bundle / "digests.json").write_text(json.dumps(self.digests))
        self.actual["metadata"]["content-hash"] = "after"
        self.planned = {"explicit": "planned manifest"}

    def tearDown(self):
        r.WHEEL_SHA = self.original_sha
        for path in self.bundle.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        self.temp.cleanup()

    def verify(self):
        return r.verify_candidate_pair(self.before, self.actual, self.planned, self.planned,
                                       self.owner, self.bundle, self.digests, self.private)

    def test_conforming_actual_pair_and_memory_only_projection(self):
        unchanged = copy.deepcopy(self.actual)
        self.assertTrue(self.verify())
        self.assertEqual(self.actual, unchanged)
        self.assertEqual(self.owner.projections[0]["package"][0]["source"], self.before["package"][0]["source"])
        self.assertEqual(self.actual["package"][0]["source"]["reference"], r.CANDIDATE_NAME)

    def test_wrong_actual_candidate_source_url_name_or_fake_forgejo(self):
        for change in ({"url": "https://evil.invalid/simple"}, {"reference": "candidate-alias"}, self.before["package"][0]["source"]):
            with self.subTest(change=change):
                original = copy.deepcopy(self.actual["package"][0]["source"])
                self.actual["package"][0]["source"].update(change)
                with self.assertRaises(r.Refused):
                    self.verify()
                self.actual["package"][0]["source"] = original
        self.assertEqual(self.owner.projections, [])

    def test_wrong_wheel_hash_sdist_extra_or_missing(self):
        for files in ([{"file": r.WHEEL, "hash": "sha256:" + "0" * 64}], [],
                      self.actual["package"][0]["files"] + [{"file": "invented.tar.gz", "hash": "sha256:" + "1" * 64}]):
            with self.subTest(files=files):
                original = self.actual["package"][0]["files"]
                self.actual["package"][0]["files"] = files
                with self.assertRaises(r.Refused):
                    self.verify()
                self.actual["package"][0]["files"] = original

    def test_changed_control_dependencies(self):
        self.actual["package"][0]["dependencies"]["dotmac-kernel"] = ">=0.1.0a110"
        with self.assertRaises(r.Refused):
            self.verify()

    def test_changed_kernel_unrelated_entry_or_source(self):
        for index, field, value in ((1, "version", "0.1.0a110"), (2, "groups", ["dev"]), (2, "source", {})):
            with self.subTest(index=index, field=field):
                original = copy.deepcopy(self.actual)
                self.actual["package"][index][field] = value
                with self.assertRaises(r.Refused):
                    self.verify()
                self.actual = original

    def test_duplicate_or_aliased_lock_identity(self):
        for name in ("dotmac-kernel", "Dotmac_Kernel"):
            with self.subTest(name=name):
                duplicate = copy.deepcopy(self.actual["package"][1])
                duplicate["name"] = name
                self.actual["package"].append(duplicate)
                with self.assertRaises(r.Refused):
                    self.verify()
                self.actual["package"].pop()

    def test_missing_extra_or_changed_input_file(self):
        path = self.bundle / "files" / r.WHEEL
        payload = path.read_bytes()
        path.unlink()
        with self.assertRaises(r.Refused):
            self.verify()
        path.write_bytes(payload)
        extra = self.bundle / "files" / "extra.whl"
        extra.write_bytes(b"extra")
        with self.assertRaises(r.Refused):
            self.verify()
        extra.unlink()
        path.write_bytes(b"changed")
        with self.assertRaises(r.Refused):
            self.verify()

    def test_manifest_and_metadata_changes(self):
        with self.assertRaises(r.Refused):
            r.verify_candidate_pair(self.before, self.actual, {}, self.planned, self.owner,
                                    self.bundle, self.digests, self.private)
        self.actual["metadata"]["lock-version"] = "changed"
        with self.assertRaises(r.Refused):
            self.verify()

    def test_index_separates_control_and_remains_read_only(self):
        index = self.bundle / "index"
        r.build_index(index, self.bundle / "files", self.digests, self.private, self.owner)
        baseline = {p.name for p in (index / "baseline/files").iterdir()}
        self.assertNotIn(r.WHEEL, baseline)
        self.assertEqual({p.name for p in (index / r.CANDIDATE_NAME / "files").iterdir()}, {r.WHEEL})
        page = index / r.CANDIDATE_NAME / "simple" / r.CONTROL / "index.html"
        self.assertIn("#sha256=" + r.WHEEL_SHA, page.read_text())
        self.assertFalse(page.stat().st_mode & 0o222)


class CommandShapeTests(unittest.TestCase):
    def test_lock_and_check_disable_plugins_with_isolated_interpreter(self):
        prefix = [sys.executable, "-I", "-B", "-m", "poetry", "--no-plugins"]
        self.assertEqual(r.poetry_argv("lock"), prefix + ["lock"])
        self.assertEqual(r.poetry_argv("check", "--lock"), prefix + ["check", "--lock"])
        self.assertNotIn("--regenerate", r.poetry_argv("lock"))


if __name__ == "__main__":
    unittest.main()
