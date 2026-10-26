"""Offline adversarial checks for the CI-only harness; no candidate execution."""

import copy
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "harness",
    Path(__file__).resolve().parents[2]
    / ".github/candidate/committed_continuation_acceptance.py",
)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class HarnessTests(unittest.TestCase):
    def test_public_fixture_is_staged_and_bound_without_checkout_access(self):
        source = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness.stage_public_fixtures(source, root)
            harness.verify_public_fixtures(root, dict(harness.FIXTURES))
            for selected in ({}, {**harness.FIXTURES, "../outside.toml": "bad"}):
                with self.subTest(selected=selected), self.assertRaises(ValueError):
                    harness.verify_public_fixtures(root, selected)
            relative = next(iter(harness.FIXTURES))
            fixture = root / relative
            fixture.write_bytes(fixture.read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                harness.verify_public_fixtures(root, dict(harness.FIXTURES))
            changed_source = root / "tests" / relative
            changed_source.parent.mkdir(parents=True)
            changed_source.write_bytes(fixture.read_bytes())
            with self.assertRaises(ValueError):
                harness.stage_public_fixtures(root, root / "output")

    def test_retained_report_binds_raw_bytes_candidate_and_preserves_native_facts(self):
        candidate = {
            "config_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "b" * 64,
            "source_revision": "c" * 40,
            "layers": ["sha256:" + "d" * 64],
            "platform": "linux/amd64",
        }
        native = {
            "schema": "dotmac.candidate_native_acceptance/1",
            "candidate": candidate,
            "negative": ["wrong owner", "durable replay"],
            "native_fact": "unchanged",
        }
        docker_image_id = "sha256:" + "e" * 64
        coordinates = {
            "target": candidate,
            "docker_image_ids": {"target": docker_image_id},
        }
        self.assertEqual(
            harness.candidate_coordinate(native, coordinates, candidate), candidate
        )
        cases = [name + "::test_contract" for name in harness.COLLECT]
        report = {
            "schema": harness.REPORT_SCHEMA,
            "scope": harness.REPORT_SCOPE,
            "collected": len(cases),
            "passed": len(cases),
            "rejected": 0,
            "cases": cases,
            "modules": {name: 1 for name in harness.COLLECT},
            "inputs": {
                "candidate": candidate,
                "docker_image_id": docker_image_id,
                "fixtures": copy.deepcopy(harness.FIXTURES),
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "candidate-native-acceptance.json"
            child = Path(directory) / "contract.json"
            observed = Path(directory) / "coordinates.json"
            observed.write_text(harness.json.dumps(coordinates))
            parent.write_text(harness.json.dumps(native))
            raw = (harness.json.dumps(report, indent=2) + "\n").encode()
            child.write_bytes(raw)
            harness.bind_report(parent, child, observed)
            bound = harness.json.loads(parent.read_text())
            vectors = bound["installed_contract_vectors"]
            self.assertEqual(vectors["report_raw_utf8"].encode(), raw)
            self.assertEqual(vectors["report_raw_sha256"], harness.sha256(raw))
            self.assertEqual(
                {k: v for k, v in bound.items() if k != "installed_contract_vectors"},
                native,
            )
            harness.verify_vectors(bound)
            with self.assertRaises(ValueError):
                harness.bind_report(parent, child, observed)
            for field in ("config_digest", "source_revision", "layers"):
                changed = copy.deepcopy(candidate)
                changed[field] = ["other"] if field == "layers" else "other"
                with self.subTest(field=field), self.assertRaises(ValueError):
                    harness.candidate_coordinate(
                        native, {**coordinates, "target": changed}, candidate
                    )
                tampered = copy.deepcopy(bound)
                tampered["candidate"] = changed
                with self.subTest(field=field), self.assertRaises(ValueError):
                    harness.verify_vectors(tampered)
            for kind in (
                "raw",
                "digest",
                "object",
                "candidate",
                "missing-module",
                "engine-id",
                "fixtures",
            ):
                tampered = copy.deepcopy(bound)
                vector = tampered["installed_contract_vectors"]
                if kind == "raw":
                    vector["report_raw_utf8"] += " "
                elif kind == "digest":
                    vector["report_raw_sha256"] = "sha256:" + "0" * 64
                elif kind == "object":
                    vector["report"]["passed"] = 0
                elif kind == "candidate":
                    vector["report"]["inputs"]["candidate"]["config_digest"] = "other"
                elif kind == "engine-id":
                    vector["docker_image_id"] = "sha256:" + "f" * 64
                elif kind == "fixtures":
                    vector["report"]["inputs"]["fixtures"] = {}
                else:
                    vector["report"]["cases"].pop()
                    vector["report"]["collected"] -= 1
                    vector["report"]["passed"] -= 1
                    vector["report"]["modules"][harness.COLLECT[-1]] = 0
                if kind in ("candidate", "missing-module", "fixtures"):
                    encoded = harness.json.dumps(vector["report"]).encode()
                    vector["report_raw_utf8"] = encoded.decode()
                    vector["report_raw_sha256"] = harness.sha256(encoded)
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    harness.verify_vectors(tampered)
            parent.write_text(harness.json.dumps(native))
            mismatched = copy.deepcopy(report)
            mismatched["inputs"]["docker_image_id"] = "sha256:" + "f" * 64
            child.write_text(harness.json.dumps(mismatched))
            with self.assertRaises(ValueError):
                harness.bind_report(parent, child, observed)

    def test_containerd_and_overlay2_ids_are_separate_from_config_identity(self):
        candidate = {
            "config_digest": "sha256:" + "a" * 64,
            "source_revision": "b" * 40,
            "platform": "linux/amd64",
            "layers": ["sha256:" + "c" * 64],
        }
        native = {
            "schema": "dotmac.candidate_native_acceptance/1",
            "candidate": candidate,
        }
        for actual in (candidate["config_digest"], "sha256:" + "d" * 64):
            coordinates = {"target": candidate, "docker_image_ids": {"target": actual}}
            with self.subTest(actual=actual):
                self.assertEqual(
                    harness.candidate_coordinate(native, coordinates, candidate),
                    candidate,
                )
        coordinates["docker_image_ids"]["target"] = "invalid"
        with self.assertRaises(ValueError):
            harness.candidate_coordinate(native, coordinates, candidate)
        coordinates["docker_image_ids"]["target"] = "sha256:" + "d" * 64
        for key in ("config_digest", "source_revision", "platform", "layers"):
            changed = copy.deepcopy(candidate)
            changed[key] = ["wrong"] if key == "layers" else "wrong"
            with self.subTest(key=key), self.assertRaises(ValueError):
                harness.candidate_coordinate(native, coordinates, changed)

    def test_installed_origin_guard_rejects_checkout_missing_record_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            purelib = Path(directory) / "site-packages"
            purelib.mkdir()
            source = purelib / "owner.py"
            source.write_bytes(b"# installed fixture\n")
            checksum = (
                harness.base64.urlsafe_b64encode(
                    harness.hashlib.sha256(source.read_bytes()).digest()
                )
                .decode()
                .rstrip("=")
            )
            record = SimpleNamespace(
                hash=SimpleNamespace(mode="sha256", value=checksum)
            )
            dist = SimpleNamespace(files=[record], locate_file=lambda _: source)
            modules = {
                name: SimpleNamespace(__file__=str(source))
                for name in ("vendor_cp", *harness.OWNERS)
            }
            with (
                patch.object(harness.sys, "modules", modules),
                patch.object(harness.sysconfig, "get_path", return_value=str(purelib)),
                patch.object(
                    harness.importlib.metadata, "distribution", return_value=dist
                ),
            ):
                self.assertEqual(set(harness.installed_origins()), set(modules))
                modules["vendor_cp"].__file__ = str(Path(directory) / "checkout.py")
                with self.assertRaises(ValueError):
                    harness.installed_origins()
                modules["vendor_cp"].__file__ = str(source)
                dist.files = []
                with self.assertRaises(ValueError):
                    harness.installed_origins()
                dist.files = [record]
                source.write_bytes(b"# tampered\n")
                with self.assertRaises(ValueError):
                    harness.installed_origins()

    def test_lock_selection_rejects_private_ambiguous_and_non_pure_tools(self):
        lock = {
            "package": [
                {
                    "name": name,
                    "version": "1.0",
                    "files": [
                        {
                            "file": f"{name}-1.0-py3-none-any.whl",
                            "hash": "sha256:" + "a" * 64,
                        }
                    ],
                }
                for name in harness.TOOL_ROOTS
            ]
        }
        self.assertEqual(set(harness.select_wheels(lock)), set(harness.TOOL_ROOTS))
        changes = []
        missing = copy.deepcopy(lock)
        missing["package"].pop()
        changes.append(missing)
        private = copy.deepcopy(lock)
        private["package"][0]["source"] = {"url": "https://example.invalid/private"}
        changes.append(private)
        duplicate = copy.deepcopy(lock)
        duplicate["package"].append(copy.deepcopy(duplicate["package"][0]))
        changes.append(duplicate)
        binary = copy.deepcopy(lock)
        binary["package"][0]["files"][0]["file"] = "pytest-1.0-cp312-linux.whl"
        changes.append(binary)
        bad_hash = copy.deepcopy(lock)
        bad_hash["package"][0]["files"][0]["hash"] = "sha256:" + "z" * 64
        changes.append(bad_hash)
        for candidate in changes:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                harness.select_wheels(candidate)

    def test_rehashed_wheel_still_rejects_application_overlay_and_path_escapes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pytest-1.0-py3-none-any.whl"
            for entry in (
                "pytest/__init__.py",
                "vendor_cp/__init__.py",
                "pytest/../../vendor_cp/a.py",
                "/pytest/a.py",
                "pytest\\a.py",
                "pytest-1.0.data/purelib/vendor_cp/a.py",
            ):
                with self.subTest(entry=entry):
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr(entry, "# fixture\n")
                    pin = {
                        "filename": path.name,
                        "sha256": harness.sha256(path.read_bytes()),
                    }
                    if entry == "pytest/__init__.py":
                        harness.validate_wheel(path, "pytest", pin)
                        pin["sha256"] = "sha256:" + "a" * 64
                    with self.assertRaises(ValueError):
                        harness.validate_wheel(path, "pytest", pin)

    def test_report_refuses_empty_partial_skip_xfail_and_duplicate_success(self):
        nodes = [name + "::test_contract" for name in harness.COLLECT]
        node = nodes[0]
        healthy = harness.Results()
        healthy.collected = nodes.copy()
        healthy.passed = nodes.copy()
        healthy.accept(0)
        for kind in (
            "empty",
            "partial",
            "skip",
            "xfail",
            "setup-error",
            "duplicate",
            "exit",
            "foreign",
        ):
            result = copy.deepcopy(healthy)
            if kind == "empty":
                result.collected = result.passed = []
            elif kind == "partial":
                result.passed = []
            elif kind in ("skip", "xfail", "setup-error"):
                attributes = dict(
                    nodeid=node,
                    failed=kind == "setup-error",
                    skipped=kind == "skip",
                    when="call",
                    passed=kind == "xfail",
                )
                if kind == "xfail":
                    attributes["wasxfail"] = "expected"
                result.pytest_runtest_logreport(SimpleNamespace(**attributes))
            elif kind == "duplicate":
                result.collected += [node]
                result.passed += [node]
            elif kind == "foreign":
                result.collected = result.passed = ["test_cp_transition.py::test_old"]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                result.accept(1 if kind == "exit" else 0)


if __name__ == "__main__":
    unittest.main()
