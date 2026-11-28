"""Pure/helper tests. No Docker, package imports, actual server or Poetry process."""
import hashlib
from pathlib import Path
import tempfile
import tomllib
import types
import unittest
from unittest import mock

import candidate_install as install
import prepare_overlay as prepare

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PAIR = FIXTURES / "pair"


def pair():
    return (PAIR / "pyproject.toml").read_bytes(), (PAIR / "poetry.lock").read_bytes()


class CandidateInstallTests(unittest.TestCase):
    def test_config_is_closed_and_owner_is_pinned_before_compile(self):
        files = {f"baseline/files/package-{i}.whl": "a" * 64 for i in range(12)}
        files.update({f"baseline/simple/package-{i}/index.html": "b" * 64 for i in range(6)})
        files["a2-control-candidate/files/" + install.WHEEL] = install.WHEEL_SHA
        files["a2-control-candidate/simple/" + install.CONTROL + "/index.html"] = "c" * 64
        config = {"manifest_sha256": install.MANIFEST_SHA, "lock_sha256": install.LOCK_SHA,
                  "owner_sha256": install.OWNER_SHA, "index_files": files}
        self.assertEqual(install.validate_config(config), files)
        with self.assertRaises(install.Refused):
            install.validate_config(dict(config, extra_index="https://wrong.invalid"))
        with self.assertRaises(install.Refused):
            install.validate_config(dict(config, owner_sha256="0" * 64))
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary) / "kernel_lock.py"
            owner.write_bytes(b"raise RuntimeError('must never execute')")
            with mock.patch("builtins.compile") as compile_mock:
                with self.assertRaises(install.Refused):
                    install.load_owner(owner)
                compile_mock.assert_not_called()

    def test_overlay_exact_only_known_instruction(self):
        original = (FIXTURES / "Dockerfile.original").read_bytes()
        candidate = prepare.overlay(original)
        before, after = original.split(prepare.OLD)
        self.assertEqual(candidate, before + prepare.NEW + after)
        self.assertEqual(candidate.replace(prepare.NEW, prepare.OLD), original)
        for needle in (b'RUN test "$(dpkg --print-architecture)" = amd64',
                       b'c6e5537631fca45f277ef405ce8751d139b491e9402cc20891a003525a8773b2',
                       b'python -m vendor_cp.deployment.profile',
                       b'python -m vendor_cp.deployment.image_heads'):
            self.assertIn(needle, candidate)
        with self.assertRaises(ValueError):
            prepare.overlay(original + b"\n")

    def test_overlay_existing_destination_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            sentinel = out / "sentinel"
            sentinel.write_bytes(b"retained")
            with mock.patch("sys.argv", ["prepare", "--dockerfile", str(FIXTURES / "Dockerfile.original"),
                                         "--out", str(out)]):
                with self.assertRaises(FileExistsError):
                    prepare.main()
            self.assertEqual(list(out.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"retained")

    def test_qualified_pair_source_and_hash_drift(self):
        manifest, lock = pair()
        install.validate_pair(manifest, lock)
        for bad_manifest, bad_lock in ((manifest + b"\n", lock), (manifest, lock + b"\n"),
            (manifest.replace(install.CANDIDATE.encode(), b"https://wrong.invalid/simple"), lock)):
            with self.assertRaises(install.Refused):
                install.validate_pair(bad_manifest, bad_lock)
        # A correctly hash-bound but unapproved source is still rejected semantically.
        bad = manifest.replace(install.CANDIDATE.encode(), b"https://wrong.invalid/simple")
        with mock.patch.object(install, "MANIFEST_SHA", install.sha(bad)):
            with self.assertRaises(install.Refused):
                install.validate_pair(bad, lock)

    def test_mirror_whole_parsed_transform_control_unchanged(self):
        manifest, lock = pair()
        owner = types.SimpleNamespace(point_at_mirror=lambda text, url: text.replace(install.CANONICAL, url))
        edited_manifest, edited_lock, expected = install.mirror_pair(manifest, lock, owner)
        self.assertEqual(tomllib.loads(edited_lock), expected)
        self.assertEqual(edited_lock.count(install.MIRROR), 6)
        self.assertEqual(edited_manifest.count(install.MIRROR), 1)
        before = tomllib.loads(lock.decode())
        self.assertEqual(next(p for p in expected["package"] if p["name"] == install.CONTROL),
                         next(p for p in before["package"] if p["name"] == install.CONTROL))
        for package in expected["package"]:
            if package.get("source", {}).get("url") == install.MIRROR:
                package["source"]["url"] = install.CANONICAL
        self.assertEqual(expected, before)

    def test_restore_pair_on_install_error(self):
        original = pair()
        with tempfile.TemporaryDirectory() as temporary:
            manifest, lock = Path(temporary) / "pyproject.toml", Path(temporary) / "poetry.lock"
            manifest.write_bytes(original[0])
            lock.write_bytes(original[1])
            with self.assertRaisesRegex(RuntimeError, "install failed"):
                with install.restored_pair(manifest, lock):
                    manifest.write_bytes(b"temporary mirror")
                    lock.write_bytes(b"temporary content hash")
                    raise RuntimeError("install failed")
            self.assertEqual((manifest.read_bytes(), lock.read_bytes()), original)

    def test_extra_index_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "index"
            root.mkdir()
            page = root / "index.html"
            page.write_bytes(b"known")
            page.chmod(0o444)
            root.chmod(0o555)
            expected = {"index.html": hashlib.sha256(b"known").hexdigest()}
            install.verify_index(root, expected)
            root.chmod(0o755)
            extra = root / "extra"
            extra.write_bytes(b"extra")
            extra.chmod(0o444)
            root.chmod(0o555)
            with self.assertRaises(install.Refused):
                install.verify_index(root, expected)
            root.chmod(0o755)
            extra.unlink()
            extra.symlink_to(page)
            root.chmod(0o555)
            with self.assertRaises(install.Refused):
                install.verify_index(root, expected)
            root.chmod(0o755)

    def test_credentials_and_netrc_refused_before_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for key in ("FORGEJO_TOKEN", "AWS_SECRET_ACCESS_KEY", "POETRY_HTTP_BASIC_FORGEJO_PASSWORD"):
                with self.assertRaises(install.Refused):
                    install.clean_environment(home / "unused", {"HOME": str(home), key: "synthetic"})
            (home / ".netrc").write_text("synthetic")
            with self.assertRaises(install.Refused):
                install.clean_environment(home / "unused", {"HOME": str(home)})
            self.assertFalse((home / "unused").exists())

    def test_clean_app_venv_and_no_second_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = install.clean_environment(root, {"HOME": str(root), "HTTP_PROXY": "discarded"})
            self.assertEqual(env["VIRTUAL_ENV"], "/opt/venv")
            self.assertEqual(env["POETRY_INSTALLER_RE_RESOLVE"], "false")
            self.assertEqual(env["POETRY_INSTALLER_ONLY_BINARY"], ":all:")
            self.assertNotIn("HTTP_PROXY", env)
        argv = install.install_argv()
        self.assertEqual(argv[:7], [install.PYTHON, "-I", "-B", "-m", "poetry", "--no-plugins", "install"])
        self.assertEqual(argv[7:], ["--only", "main", "--no-root", "--no-interaction", "--no-ansi"])
        self.assertNotIn("lock", argv)


if __name__ == "__main__":
    unittest.main()
