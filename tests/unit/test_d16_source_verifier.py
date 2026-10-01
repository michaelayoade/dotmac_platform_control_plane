"""Refusal controls for the temporary D16 Foundation source adapter.

The genuine Foundation policy call lives in the explicit conformance lane;
these tests need no private registry or second repository checkout.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import venv
from dataclasses import replace
from pathlib import Path

import pytest

from vendor_cp.deployment import d16_source_verifier as subject


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Git executable, temporary repo
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _source_repo(tmp_path: Path) -> tuple[Path, Path, str]:
    root = tmp_path / "source"
    package = root / subject._PACKAGE_RELATIVE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# test package\n", encoding="utf-8")
    (root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return root, package, _git(root, "rev-parse", "HEAD")


def _proof(data: bytes) -> subject.VerifiedDumpEvidence:
    return subject.VerifiedDumpEvidence(
        write_time_sha256="sha256:" + hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        magic_verified=True,
        full_decompression_verified=True,
        completed_at_epoch=1_800_000_000,
        evidence_id="synthetic-test-proof",
    )


def _inputs(tmp_path: Path, data: bytes) -> subject.D16SourceInputs:
    dump = tmp_path / "database.dump"
    dump.write_bytes(data)
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"{}")
    return subject.D16SourceInputs(
        foundation_checkout=tmp_path,
        descriptor_toml="",
        receipt_document={},
        previous_receipt_document=None,
        genesis_source_document=None,
        manifest_path=manifest,
        dump_path=dump,
        verified_dump_evidence=_proof(data),
        dataset_code="primary",
        observed_target_heads=(),
        observed_image_digest="sha256:" + "a" * 64,
        expected_run_id="run-1",
        expected_target="host-a",
    )


def _fake_source(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(subject, "_checked_source", lambda _: (tmp_path, "tree"))


def test_wrong_source_commit_refuses_before_import(tmp_path: Path) -> None:
    root, _, _ = _source_repo(tmp_path)
    with pytest.raises(subject._Refused) as caught:
        subject._checked_source(root)
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_REVISION


def test_dirty_source_refuses_even_when_git_index_hides_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    _git(root, "update-index", "--assume-unchanged", str(package / "__init__.py"))
    (package / "__init__.py").write_text(
        "# changed but index hidden\n", encoding="utf-8"
    )
    with pytest.raises(subject._Refused) as caught:
        subject._checked_source(root)
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_DIRTY


def test_ignored_importable_file_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    (package / "extra.pyc").write_bytes(b"untracked bytecode")
    with pytest.raises(subject._Refused) as caught:
        subject._checked_source(root)
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_DIRTY


def test_untracked_package_symlink_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    outside = tmp_path / "outside"
    outside.mkdir()
    (package / "injected").symlink_to(outside, target_is_directory=True)
    with pytest.raises(subject._Refused) as caught:
        subject._checked_source(root)
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_DIRTY


def test_clean_source_records_real_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    checked, tree = subject._checked_source(root)
    assert checked == package
    assert tree == _git(
        root, "rev-parse", f"HEAD:{subject._PACKAGE_RELATIVE.as_posix()}"
    )


def test_snapshot_uses_commit_blob_after_checkout_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    (package / "__init__.py").write_text("raise RuntimeError('swapped')\n")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    subject._snapshot_source(root, snapshot)
    assert (
        snapshot / "dotmac_deployment_foundation" / "__init__.py"
    ).read_text() == "# test package\n"


def test_replacement_ref_cannot_redirect_pinned_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, package, commit = _source_repo(tmp_path)
    monkeypatch.setattr(subject, "FOUNDATION_COMMIT", commit)
    relative = (subject._PACKAGE_RELATIVE / "__init__.py").as_posix()
    (package / "__init__.py").write_text("# replacement payload\n")
    _git(root, "add", relative)
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "replacement",
    )
    replacement = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "HEAD", commit)
    _git(root, "replace", commit, replacement)
    assert _git(root, "rev-parse", "HEAD") == commit
    assert _git(root, "show", f"{commit}:{relative}") == "# replacement payload"
    assert subject._git(root, "show", f"{commit}:{relative}") == b"# test package\n"
    with pytest.raises(subject._Refused) as caught:
        subject._checked_source(root)
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_DIRTY


def test_ambient_sitecustomize_cannot_execute_in_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = tmp_path / "python-env"
    venv.create(environment, with_pip=False)
    interpreter = environment / "bin" / "python"
    site_packages = (
        environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    marker = tmp_path / "sitecustomize-executed"
    customization = site_packages / "sitecustomize.py"
    customization.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
    )
    # A base-interpreter sitecustomize may already have won module lookup;
    # the venv .pth hook executes this injected customization explicitly.
    (site_packages / "injected-site.pth").write_text(
        f"import runpy; runpy.run_path({str(customization)!r})\n"
    )
    subprocess.run(  # noqa: S603 - private test interpreter
        [str(interpreter), "-I", "-B", "-c", "pass"], check=True, timeout=10
    )
    assert marker.read_text() == "executed"
    marker.unlink()
    monkeypatch.setattr(subject.sys, "executable", str(interpreter))
    with pytest.raises(subject._Refused) as caught:
        subject._run_isolated(tmp_path, {}, "test-tree")
    assert caught.value.code is subject.D16SourceRefusal.SOURCE_IMPORT
    assert not marker.exists()


def test_symlinked_file_and_parent_refuse(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "database.dump").write_bytes(b"dump")
    (tmp_path / "link.dump").symlink_to(real / "database.dump")
    (tmp_path / "link-dir").symlink_to(real, target_is_directory=True)
    for path in (tmp_path / "link.dump", tmp_path / "link-dir" / "database.dump"):
        with pytest.raises(subject._Refused) as caught:
            subject._read_local(path, maximum=100, keep_bytes=False)
        assert caught.value.code is subject.D16SourceRefusal.LOCAL_FILE_UNSAFE


def test_non_regular_and_oversized_file_refuse(tmp_path: Path) -> None:
    with pytest.raises(subject._Refused) as caught:
        subject._read_local(tmp_path, maximum=100, keep_bytes=False)
    assert caught.value.code is subject.D16SourceRefusal.LOCAL_FILE_UNSAFE
    large = tmp_path / "large"
    large.write_bytes(b"abc")
    with pytest.raises(subject._Refused) as caught:
        subject._read_local(large, maximum=2, keep_bytes=False)
    assert caught.value.code is subject.D16SourceRefusal.LOCAL_FILE_UNSAFE


def test_missing_write_time_evidence_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_source(monkeypatch, tmp_path)
    inputs = _inputs(tmp_path, b"archive")
    assert (
        subject.verify_d16_transition(
            replace(inputs, verified_dump_evidence=None)
        ).refusal
        is subject.D16SourceRefusal.BACKUP_PROOF_MISSING
    )


@pytest.mark.parametrize(
    "unproved_field", ("magic_verified", "full_decompression_verified")
)
def test_each_unproved_backup_property_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unproved_field: str
) -> None:
    _fake_source(monkeypatch, tmp_path)
    inputs = _inputs(tmp_path, b"archive")
    assert (
        subject.verify_d16_transition(
            replace(
                inputs,
                verified_dump_evidence=replace(
                    inputs.verified_dump_evidence, **{unproved_field: False}
                ),
            )
        ).refusal
        is subject.D16SourceRefusal.BACKUP_PROOF_MISSING
    )


def test_changed_dump_bytes_refuse_against_write_time_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_source(monkeypatch, tmp_path)
    inputs = _inputs(tmp_path, b"original")
    inputs.dump_path.write_bytes(b"mutated!")
    result = subject.verify_d16_transition(inputs)
    assert result.refusal is subject.D16SourceRefusal.BACKUP_PROOF_MISMATCH
    assert result.dump_sha256 == "sha256:" + hashlib.sha256(b"mutated!").hexdigest()


def test_malformed_input_refuses_before_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_source(monkeypatch, tmp_path)
    inputs = _inputs(tmp_path, b"archive")
    result = subject.verify_d16_transition(replace(inputs, descriptor_toml=None))  # type: ignore[arg-type]
    assert result.refusal is subject.D16SourceRefusal.INPUT_MALFORMED


def test_local_read_hashes_exact_bytes(tmp_path: Path) -> None:
    data = os.urandom(8193)
    path = tmp_path / "database.dump"
    path.write_bytes(data)
    digest, size, read_back = subject._read_local(path, maximum=10000, keep_bytes=True)
    assert digest == hashlib.sha256(data).hexdigest()
    assert size == len(data)
    assert read_back == data
