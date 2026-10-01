"""Exact descriptor bytes remain attached to CP's source and target captures."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from vendor_cp.deployment import transition_evidence as evidence


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    assert executable is not None, "git is required for the source-history control"
    result = subprocess.run(  # noqa: S603 - fixed executable and argv, no shell
        [
            executable,
            "-C",
            str(repo),
            "-c",
            "user.email=transition-evidence@example.invalid",
            "-c",
            "user.name=Transition Evidence",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_source_preserves_git_blob_and_target_preserves_later_working_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = tmp_path / "deploy" / "product.toml"
    descriptor.parent.mkdir()
    source_bytes = b'# original comment\r\nproduct = "old"\r\n'
    target_bytes = b'# edited comment\nproduct = "new"\n'
    descriptor.write_bytes(source_bytes)
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "add", "deploy/product.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "source descriptor")
    source_revision = _git(tmp_path, "rev-parse", "HEAD")

    # The working tree has already advanced when the source is captured.
    descriptor.write_bytes(target_bytes)
    monkeypatch.setattr(
        evidence, "read_current_migration_heads", lambda _conn: ("source_head",)
    )
    source = evidence.capture_genesis_baseline(
        object(), repo_root=tmp_path, source_revision=source_revision, now_epoch=10
    )
    assert type(source.descriptor_bytes) is bytes
    assert source.descriptor_bytes == source_bytes
    assert source.raw_bytes_descriptor_digest == _digest(source_bytes)
    assert source.migration_heads == ("source_head",)

    monkeypatch.setattr(
        evidence, "read_current_migration_heads", lambda _conn: ("target_head",)
    )
    target = evidence.capture_target_state(
        object(), descriptor_path=descriptor, now_epoch=20
    )
    assert type(target.descriptor_bytes) is bytes
    assert target.descriptor_bytes == target_bytes
    assert target.raw_bytes_descriptor_digest == _digest(target_bytes)
    assert target.migration_heads == ("target_head",)

    # Later checkout edits cannot change either frozen observation.
    descriptor.write_bytes(b'product = "later"\n')
    assert source.descriptor_bytes == source_bytes
    assert target.descriptor_bytes == target_bytes
    assert source.raw_bytes_descriptor_digest != target.raw_bytes_descriptor_digest


@pytest.mark.parametrize("side", ["source", "target"])
def test_frozen_capture_refuses_mutable_bytes_and_digest_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: str
) -> None:
    descriptor = tmp_path / "product.toml"
    original = b'# comment\r\nproduct = "old"\r\n'
    changed = b'# comment\r\nproduct = "new"\r\n'
    descriptor.write_bytes(original)
    monkeypatch.setattr(evidence, "read_current_migration_heads", lambda _conn: ())
    if side == "source":
        monkeypatch.setattr(
            evidence, "read_descriptor_at_revision", lambda **_kwargs: original
        )
        captured = evidence.capture_genesis_baseline(
            object(), repo_root=tmp_path, source_revision="a" * 40
        )
    else:
        captured = evidence.capture_target_state(object(), descriptor_path=descriptor)

    with pytest.raises(FrozenInstanceError):
        captured.descriptor_bytes = changed  # type: ignore[misc]
    with pytest.raises(TypeError, match="immutable bytes"):
        replace(captured, descriptor_bytes=bytearray(original))
    with pytest.raises(ValueError, match="does not match"):
        replace(captured, descriptor_bytes=changed)
    with pytest.raises(ValueError, match="does not match"):
        replace(captured, raw_bytes_descriptor_digest=_digest(changed))

    # A coherent new observation is valid; the guard does not just reject all edits.
    updated = replace(
        captured, descriptor_bytes=changed, raw_bytes_descriptor_digest=_digest(changed)
    )
    assert updated.descriptor_bytes == changed
    assert updated.raw_bytes_descriptor_digest == _digest(changed)
