"""`transition_evidence`'s structural refusals — no Postgres needed.

Every test here proves either a refusal that must happen BEFORE any
subprocess call (an injection defence, not merely a correctness check), the
structural non-circularity guarantee itself (an EXACT parameter set, not a
forbidden-substring heuristic), or that hashing genuinely operates on raw
bytes rather than decoded/normalized text.
"""

from __future__ import annotations

import hashlib
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


def test_capture_genesis_baseline_has_exactly_the_designed_parameter_set() -> None:
    """An EXACT parameter-set assertion, not a forbidden-substring heuristic
    (`expect`/`override`/`claim` alone would miss e.g. `hint`, `reference`,
    or `baseline`). Any future parameter addition — whatever it is named —
    now forces a deliberate change to this test, which is the actual
    property non-circularity depends on."""
    parameters = set(inspect.signature(capture_genesis_baseline).parameters)
    assert parameters == {"conn", "repo_root", "source_revision", "now_epoch"}


def test_capture_target_state_has_exactly_the_designed_parameter_set() -> None:
    parameters = set(inspect.signature(capture_target_state).parameters)
    assert parameters == {"conn", "descriptor_path", "now_epoch"}


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
    ) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError(
            "read_descriptor_at_revision called a subprocess before "
            "refusing a malformed source_revision"
        )

    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)

    with pytest.raises(InvalidSourceRevision):
        read_descriptor_at_revision(repo_root=tmp_path, source_revision=bad_revision)


def test_read_descriptor_at_revision_refuses_a_non_string_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-`str` `source_revision` (an `int`, `None`, ...) must be refused
    the same clean way as a malformed string — never left to raise a bare
    `TypeError` out of `SOURCE_REVISION_PATTERN.fullmatch`, which only
    accepts `str`/`bytes`-like objects."""

    def _refuse_any_subprocess_call(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError(
            "read_descriptor_at_revision called a subprocess before "
            "refusing a non-string source_revision"
        )

    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)

    with pytest.raises(InvalidSourceRevision):
        read_descriptor_at_revision(
            repo_root=tmp_path,
            source_revision=1234567890,  # type: ignore[arg-type]
        )


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


def test_read_descriptor_at_revision_when_git_is_absent_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`git` missing from `PATH` is a distinct, absent-capability fact — not
    a malformed revision, and not a subprocess that was attempted and
    failed."""

    def _refuse_any_subprocess_call(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        raise AssertionError(
            "read_descriptor_at_revision called a subprocess when git was "
            "reported absent from PATH"
        )

    monkeypatch.setattr(
        "vendor_cp.deployment.transition_evidence.shutil.which", lambda _name: None
    )
    monkeypatch.setattr(subprocess, "run", _refuse_any_subprocess_call)

    with pytest.raises(SourceRevisionUnavailable, match="not on PATH"):
        read_descriptor_at_revision(repo_root=tmp_path, source_revision="a" * 40)


def test_read_descriptor_at_revision_on_timeout_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "vendor_cp.deployment.transition_evidence.shutil.which",
        lambda _name: "/usr/bin/git",
    )

    def _timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd="git", timeout=15)

    monkeypatch.setattr(subprocess, "run", _timeout)

    with pytest.raises(SourceRevisionUnavailable):
        read_descriptor_at_revision(repo_root=tmp_path, source_revision="a" * 40)


def test_read_descriptor_at_revision_on_os_error_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "vendor_cp.deployment.transition_evidence.shutil.which",
        lambda _name: "/usr/bin/git",
    )

    def _os_error(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        raise OSError("permission denied")

    monkeypatch.setattr(subprocess, "run", _os_error)

    with pytest.raises(SourceRevisionUnavailable):
        read_descriptor_at_revision(repo_root=tmp_path, source_revision="a" * 40)


def test_read_descriptor_from_working_tree_against_a_missing_path_raises_file_not_found(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "deploy" / "product.toml"

    with pytest.raises(FileNotFoundError):
        read_descriptor_from_working_tree(missing)


def test_raw_bytes_digest_is_deterministic_and_format_correct() -> None:
    first = raw_bytes_digest(b'product = "a"\n')
    again = raw_bytes_digest(b'product = "a"\n')
    second = raw_bytes_digest(b'product = "b"\n')

    for digest in (first, second):
        assert digest.startswith("sha256:")
        hex_part = digest.removeprefix("sha256:")
        assert len(hex_part) == 64
        assert hex_part == hex_part.lower()
        int(hex_part, 16)  # raises ValueError if not valid hex

    assert first == again, "hashing the same bytes twice must be deterministic"
    assert first != second, "different bytes must produce different digests"


def test_raw_bytes_digest_is_sensitive_to_a_trailing_newline() -> None:
    """Exact bytes, not a normalized comparison — a difference of only a
    trailing newline must still change the digest, since this module never
    strips or reformats descriptor bytes before hashing them."""
    without_newline = raw_bytes_digest(b'product = "a"')
    with_newline = raw_bytes_digest(b'product = "a"\n')

    assert without_newline != with_newline


def test_read_descriptor_at_revision_hashes_raw_bytes_not_decoded_normalized_text(
    tmp_path: Path,
) -> None:
    """The sensitivity proof for the raw-bytes fix: a descriptor committed
    with a literal CRLF line ending and a non-ASCII byte must round-trip
    through `read_descriptor_at_revision` + `raw_bytes_digest` UNCHANGED —
    `text=True`/universal-newline translation or a decode-then-re-encode
    round trip would silently turn `\\r\\n` into `\\n` and corrupt the
    digest, which this test would catch by comparing against an
    independently, directly computed digest of the exact bytes committed.
    """
    _init_git_repo(tmp_path)
    (tmp_path / "deploy").mkdir()
    descriptor_path = tmp_path / "deploy" / "product.toml"

    # A literal CRLF line ending plus a non-ASCII (UTF-8 multi-byte) value —
    # exactly the two things universal-newline translation and a
    # decode/re-encode round trip could each independently corrupt.
    committed_bytes = 'product = "café"\r\nregion = "ng"\r\n'.encode()
    descriptor_path.write_bytes(committed_bytes)

    _git(tmp_path, "add", "deploy/product.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "descriptor with CRLF + non-ASCII")
    revision = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()

    returned_bytes = read_descriptor_at_revision(
        repo_root=tmp_path, source_revision=revision
    )

    # The independently, directly computed expectation — not routed through
    # any of this module's own machinery.
    expected_digest = "sha256:" + hashlib.sha256(committed_bytes).hexdigest()

    assert returned_bytes == committed_bytes, (
        "read_descriptor_at_revision must return the exact committed bytes, "
        "CRLF and non-ASCII content included, with no newline translation "
        "or decode/re-encode round trip"
    )
    assert raw_bytes_digest(returned_bytes) == expected_digest
