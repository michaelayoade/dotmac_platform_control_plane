"""`transition_evidence`'s structural refusals — no Postgres needed.

Every test here proves either a refusal that must happen BEFORE any
subprocess call (an injection defence, not merely a correctness check), or
the structural non-circularity guarantee itself: that neither capture
function's signature has grown an escape hatch for a caller to supply what
the evidence "should" say.
"""

from __future__ import annotations

import inspect
import shutil
import subprocess
from pathlib import Path

import pytest

from vendor_cp.deployment.transition_evidence import (
    InvalidSourceRevision,
    SourceRevisionUnavailable,
    capture_genesis_baseline,
    capture_target_state,
    raw_bytes_digest,
    read_descriptor_at_revision,
    read_descriptor_from_working_tree,
)

#: A forbidden substring test: any parameter name containing one of these
#: (case-insensitive) would let a caller supply what the evidence "should"
#: say instead of only measuring what it actually is.
_FORBIDDEN_PARAMETER_SUBSTRINGS = ("expect", "override", "claim")


def _git_executable() -> str:
    executable = shutil.which("git")
    assert executable is not None, (
        "git is not on PATH — every other CP test that touches git assumes "
        "it, so this is a report-worthy environment gap, not a fixture bug"
    )
    return executable


def _init_git_repo(repo_root: Path) -> None:
    """A minimal, throwaway git repository — never the actual CP checkout,
    and never global git config."""
    subprocess.run(  # noqa: S603 - argv list, resolved executable
        [_git_executable(), "init", "--quiet", str(repo_root)],
        check=True,
    )


def _git(repo_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv list, resolved executable
        [
            _git_executable(),
            "-C",
            str(repo_root),
            "-c",
            "user.email=transition-evidence-tests@example.invalid",
            "-c",
            "user.name=Transition Evidence Tests",
            *arguments,
        ],
        capture_output=True,
        text=True,
        check=True,
    )


def test_capture_genesis_baseline_signature_has_no_expected_override_param() -> None:
    parameters = inspect.signature(capture_genesis_baseline).parameters
    offenders = [
        name
        for name in parameters
        if any(
            substring in name.lower() for substring in _FORBIDDEN_PARAMETER_SUBSTRINGS
        )
    ]
    assert offenders == [], (
        "capture_genesis_baseline must not accept a parameter letting a "
        f"caller supply what the evidence should say; found: {offenders}"
    )


def test_capture_target_state_signature_has_no_expected_override_param() -> None:
    parameters = inspect.signature(capture_target_state).parameters
    offenders = [
        name
        for name in parameters
        if any(
            substring in name.lower() for substring in _FORBIDDEN_PARAMETER_SUBSTRINGS
        )
    ]
    assert offenders == [], (
        "capture_target_state must not accept a parameter letting a caller "
        f"supply what the evidence should say; found: {offenders}"
    )


@pytest.mark.parametrize(
    "bad_revision",
    [
        "too-short",
        "a" * 39,
        "A" * 40,  # uppercase hex is refused
        "0123456789abcdef0123456789abcdef0123456;rm -rf /",
        "; rm -rf / #" + "a" * 40,
    ],
)
def test_read_descriptor_at_revision_refuses_a_malformed_revision_before_any_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_revision: str
) -> None:
    def _refuse_any_subprocess_call(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise AssertionError(
            "read_descriptor_at_revision called a subprocess before "
            "refusing a malformed source_revision"
        )

    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)

    with pytest.raises(InvalidSourceRevision):
        read_descriptor_at_revision(repo_root=tmp_path, source_revision=bad_revision)


def test_read_descriptor_at_revision_against_a_nonexistent_revision_raises_unavailable(
    tmp_path: Path,
) -> None:
    _init_git_repo(tmp_path)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "product.toml").write_text(
        'product = "old-value"\n', encoding="utf-8"
    )
    _git(tmp_path, "add", "deploy/product.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "add descriptor")

    # 40 hex characters, well-formed pattern, no such commit in this repo.
    nonexistent_revision = "0" * 40

    with pytest.raises(SourceRevisionUnavailable) as excinfo:
        read_descriptor_at_revision(
            repo_root=tmp_path, source_revision=nonexistent_revision
        )
    assert nonexistent_revision in str(excinfo.value)


def test_read_descriptor_from_working_tree_against_a_missing_path_raises_file_not_found(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "deploy" / "product.toml"

    with pytest.raises(FileNotFoundError):
        read_descriptor_from_working_tree(missing)


def test_raw_bytes_digest_is_deterministic_and_format_correct() -> None:
    first = raw_bytes_digest('product = "a"\n')
    again = raw_bytes_digest('product = "a"\n')
    second = raw_bytes_digest('product = "b"\n')

    for digest in (first, second):
        assert digest.startswith("sha256:")
        hex_part = digest.removeprefix("sha256:")
        assert len(hex_part) == 64
        assert hex_part == hex_part.lower()
        int(hex_part, 16)  # raises ValueError if not valid hex

    assert first == again, "hashing the same text twice must be deterministic"
    assert first != second, "different text must produce different digests"


def test_raw_bytes_digest_is_sensitive_to_a_trailing_newline() -> None:
    """Exact bytes, not a normalized comparison — a difference of only a
    trailing newline must still change the digest, since this module never
    strips or reformats descriptor text before hashing it."""
    without_newline = raw_bytes_digest('product = "a"')
    with_newline = raw_bytes_digest('product = "a"\n')

    assert without_newline != with_newline
