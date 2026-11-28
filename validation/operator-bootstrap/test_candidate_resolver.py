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
        self.metadata_calls = []
        self.identity_calls = []
        self.metadata_identity_calls = []
        self.control_requirements = ["dotmac-kernel (>=0.1.0a100)"]

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
        self.metadata_calls.append(entry["name"])
        if entry["name"] != r.CONTROL:
            raise r.Refused("unchanged Kernel conditional metadata must not enter unconditional map")
        if any(";" in value for value in self.control_requirements):
            raise r.Refused("Control conditional Requires-Dist refused by inherited unconditional map")
        return [] if wheel.is_file() and r.digest(wheel) == digests[wheel.name] else ["missing wheel"]

    def wheel_identity_problems(self, wheel, name, version):
        self.identity_calls.append((name, version))
        return [] if wheel.is_file() and self.artifact_belongs_to(wheel.name, name, version) else ["wrong identity"]

    def wheel_metadata(self, wheel, name, version):
        self.metadata_identity_calls.append((name, version))
        return {"name": [name], "version": [version],
                "requires-dist": ['cryptography (>=42) ; extra == "licensing" or extra == "settings-crypto"']
                if name == "dotmac-kernel" else self.control_requirements if name == r.CONTROL else []}

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
        self.private = {r.CONTROL: "0.1.0a17", "dotmac-kernel": "0.1.0a100", "dotmac-approvals": "0.1.0a8",
                        "dotmac-commercial-agreements": "0.1.0a4", "dotmac-entitlement-allocation": "0.1.0a6",
                        "dotmac-licensing": "0.1.0a1", "dotmac-release-catalog": "0.1.0a4"}
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
        packages[1]["dependencies"] = {"cryptography": {"version": ">=42", "optional": True,
                                                       "markers": 'extra == "licensing" or extra == "settings-crypto"'}}
        packages[1]["extras"] = {"licensing": ["cryptography (>=42)"], "settings-crypto": ["cryptography (>=42)"]}
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
        self.assertEqual(self.owner.metadata_calls, [r.CONTROL])
        self.assertEqual(len(self.owner.identity_calls), 7)
        self.assertEqual(len(self.owner.metadata_identity_calls), 7)
        self.assertEqual(set(self.owner.metadata_identity_calls), set(self.owner.identity_calls))
        self.assertEqual(self.actual["package"][1], self.before["package"][1])
        self.assertEqual(set(self.owner.identity_calls),
                         {(name, "0.1.0a18" if name == r.CONTROL else version)
                          for name, version in self.private.items()})

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

    def test_conditional_control_metadata_still_enters_inherited_map_and_refuses(self):
        self.owner.control_requirements = ['dotmac-kernel (>=0.1.0a100) ; extra == "licensing"']
        with self.assertRaisesRegex(r.Refused, "Control conditional Requires-Dist"):
            self.verify()
        self.assertEqual(self.owner.metadata_calls, [r.CONTROL])
        self.assertIn((r.CONTROL, "0.1.0a18"), self.owner.metadata_identity_calls)

    def test_changed_kernel_unrelated_entry_or_source(self):
        for index, field, value in ((1, "version", "0.1.0a110"), (1, "files", [{"file": "changed.whl", "hash": "sha256:" + "0" * 64}]),
                                    (1, "dependencies", {"cryptography": ">=99"}),
                                    (2, "groups", ["dev"]), (2, "source", {})):
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


class ControlDependencyMapTests(unittest.TestCase):
    class DependencyOwner:
        """Underscore-keyed owner contract; no driver-side normalization."""
        def __init__(self):
            self.normalised_calls = []

        def requires_dist(self, headers):
            return headers["requires-dist"]

        def metadata_dependencies(self, requirements):
            if any(";" in value for value in requirements):
                raise r.Refused("conditional requirement")
            constraint = requirements[0].removeprefix("dotmac-kernel (").removesuffix(")")
            return {"dotmac_kernel": constraint}

        def locked_dependencies(self, entry):
            return entry["dependencies"]

        def _normalised(self, name):
            if name != "dotmac-kernel":
                raise AssertionError("unexpected owner normalization argument")
            self.normalised_calls.append(name)
            return "dotmac_kernel"

    def test_underscore_owner_key_and_exact_kernel_floor(self):
        owner = self.DependencyOwner()
        expected = {"dotmac_kernel": ">=0.1.0a100"}
        actual = r.verify_control_dependencies({"requires-dist": ["dotmac-kernel (>=0.1.0a100)"]},
                                               {"dependencies": expected}, owner)
        self.assertEqual(actual, expected)
        self.assertEqual(owner.normalised_calls, ["dotmac-kernel"])

    def test_wrong_floor_rejected_even_when_maps_agree(self):
        for constraint in (">=0.1.0a99", ">=0.1.0a110", "==0.1.0a100"):
            with self.subTest(constraint=constraint), self.assertRaises(r.Refused):
                r.verify_control_dependencies({"requires-dist": [f"dotmac-kernel ({constraint})"]},
                                              {"dependencies": {"dotmac_kernel": constraint}}, self.DependencyOwner())

    def test_changed_or_conditional_control_requirement_rejected(self):
        baseline = {"dependencies": {"dotmac_kernel": ">=0.1.0a100"}}
        for requirement in ("dotmac-kernel (>=0.1.0a110)", 'dotmac-kernel (>=0.1.0a100) ; extra == "licensing"'):
            with self.subTest(requirement=requirement), self.assertRaises(r.Refused):
                r.verify_control_dependencies({"requires-dist": [requirement]}, baseline, self.DependencyOwner())


class PinnedOwnerDependencyMapTests(unittest.TestCase):
    def test_actual_pinned_owner_normalization_and_conditional_boundary(self):
        candidates = [Path(__file__).with_name("kernel_lock.py"), Path("/source/scripts/kernel_lock.py"),
                      Path(__file__).resolve().parents[1] / "source/scripts/kernel_lock.py"]
        path = next((candidate for candidate in candidates if candidate.is_file()), None)
        self.assertIsNotNone(path, "provide the pinned owner beside the tests or at /source/scripts/kernel_lock.py")
        self.assertEqual(r.digest(path), r.BINDINGS["scripts/kernel_lock.py"])
        name = "candidate_test_pinned_owner"
        owner_spec = importlib.util.spec_from_file_location(name, path)
        owner = importlib.util.module_from_spec(owner_spec)
        sys.modules[name] = owner
        try:
            exec(compile(path.read_bytes(), str(path), "exec"), owner.__dict__)
            baseline = {"dependencies": {"dotmac-kernel": ">=0.1.0a100"}}
            headers = owner.parse_core_metadata("Metadata-Version: 2.3\nName: dotmac-deployment-control\nVersion: 0.1.0a18\nRequires-Dist: dotmac-kernel (>=0.1.0a100)\n\n")
            self.assertEqual(r.verify_control_dependencies(headers, baseline, owner),
                             {"dotmac_kernel": ">=0.1.0a100"})
            wrong = copy.deepcopy(headers)
            wrong["requires-dist"] = ["dotmac-kernel (>=0.1.0a110)"]
            with self.assertRaises(r.Refused):
                r.verify_control_dependencies(wrong, baseline, owner)
            conditional = copy.deepcopy(headers)
            conditional["requires-dist"] = ['dotmac-kernel (>=0.1.0a100) ; extra == "licensing"']
            with self.assertRaises(owner.Refusal):
                r.verify_control_dependencies(conditional, baseline, owner)
        finally:
            del sys.modules[name]


if __name__ == "__main__":
    unittest.main()
