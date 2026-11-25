"""Source contracts and synthetic negative cases; hosted acceptance is separate.

These tests never install or execute acquired package bytes. Their downloader is
synthetic; live Forgejo/dispatch qualification is not claimed by this suite.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import kernel_lock as owner  # noqa: E402
import warm_reviewed_private_artifacts as producer  # noqa: E402


@pytest.fixture
def pair(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, bytes]:
    manifest = (
        "[tool.poetry.dependencies]\n"
        + "\n".join(
            f'{name} = {{version = "{version}", source = "forgejo"}}'
            for name, version in producer.PRIVATE.items()
        )
        + '\n[[tool.poetry.source]]\nname = "forgejo"\n'
        + (f'url = "{owner.INDEX_URL}"\npriority = "explicit"\n')
    )
    packages = []
    for name, version in producer.PRIVATE.items():
        stem = f"{name.replace('-', '_')}-{version}"
        files = [f"{stem}-py3-none-any.whl", f"{stem}.tar.gz"]
        records = ",\n".join(
            f'{{file = "{filename}", hash = "sha256:'
            f'{hashlib.sha256(filename.encode()).hexdigest()}"}}'
            for filename in files
        )
        packages.append(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            f'files = [{records}]\n[package.source]\ntype = "legacy"\n'
            f'url = "{owner.INDEX_URL}"\nreference = "forgejo"\n'
        )
    result = manifest.encode(), "\n".join(packages).encode()
    monkeypatch.setattr(producer, "MANIFEST_SHA256S", {owner.sha256_hex(result[0])})
    monkeypatch.setattr(producer, "LOCK_SHA256", owner.sha256_hex(result[1]))
    return result


def test_real_protected_base_closes_over_seven_pairs() -> None:
    plan, artifacts = producer.closed_plan(
        (ROOT / "pyproject.toml").read_bytes(), (ROOT / "poetry.lock").read_bytes()
    )
    assert plan == producer.PRIVATE
    assert len(artifacts) == 14
    assert sum(name.endswith(".tar.gz") for name in artifacts) == 7


@pytest.mark.parametrize("target", [0, 1])
def test_unreviewed_pair_bytes_refuse(pair: tuple[bytes, bytes], target: int) -> None:
    changed = list(pair)
    changed[target] += b"\n# unreviewed bytes\n"
    with pytest.raises(owner.Refusal, match="reviewed baseline"):
        producer.closed_plan(*changed)


@pytest.mark.parametrize(
    "before,after",
    [
        ('name = "dotmac-approvals"', 'name = "dotmac_approvals"'),
        ('reference = "forgejo"', 'reference = "alias"'),
        ('type = "legacy"', 'type = "git"'),
        (owner.INDEX_URL, owner.INDEX_URL + "/"),
        (
            "dotmac_approvals-0.1.0a8.tar.gz",
            "dotmac_approvals-0.1.0a8-py3-none-any.whl",
        ),
        ("sha256:", "md5:"),
    ],
)
def test_raw_source_and_file_records_refuse(
    pair: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    before: str,
    after: str,
) -> None:
    manifest, lock = pair
    changed = lock.replace(before.encode(), after.encode(), 1)
    assert changed != lock
    # Reach the raw grammar behind the immutable-pair gate deliberately.
    monkeypatch.setattr(producer, "LOCK_SHA256", owner.sha256_hex(changed))
    with pytest.raises(owner.Refusal):
        producer.closed_plan(manifest, changed)


def test_duplicate_raw_package_refuses_before_dict_conversion(
    pair: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, lock = pair
    first = lock.split(b"[[package]]", 2)[1]
    changed = lock + b"\n[[package]]" + first
    monkeypatch.setattr(producer, "LOCK_SHA256", owner.sha256_hex(changed))
    with pytest.raises(owner.Refusal, match="duplicate"):
        producer.closed_plan(manifest, changed)


def test_repeated_digest_refuses(
    pair: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, lock = pair
    hashes = [
        line.split(b"sha256:")[1].split(b'"')[0]
        for line in lock.splitlines()
        if b"sha256:" in line
    ]
    changed = lock.replace(hashes[1], hashes[0])
    monkeypatch.setattr(producer, "LOCK_SHA256", owner.sha256_hex(changed))
    with pytest.raises(owner.Refusal, match="artifact identity"):
        producer.closed_plan(manifest, changed)


@pytest.fixture
def transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, str], list[str], list[str]]:
    names = [
        "dotmac_kernel-0.1.0a100-py3-none-any.whl",
        "dotmac_kernel-0.1.0a100.tar.gz",
    ]
    expected = {name: owner.sha256_hex(name.encode()) for name in names}
    offers = list(names)
    fetched: list[str] = []

    def fake(url: str, target: Path, *, expected_sha256: str | None = None) -> str:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.suffix == ".html":
            target.write_text(
                "\n".join(f'<a href="../../files/{name}">{name}</a>' for name in offers)
            )
            return owner.sha256_hex(target.read_bytes())
        name = url.rsplit("/", 1)[-1]
        fetched.append(name)
        assert expected_sha256 == expected[name]
        target.write_bytes(name.encode())
        return owner.sha256_hex(target.read_bytes())

    monkeypatch.setattr(owner, "fetch", fake)
    return expected, offers, fetched


@pytest.mark.parametrize("kind", ["duplicate", "missing", "extra"])
def test_exact_index_set_refuses_before_artifact_fetch(
    transfer: tuple[dict[str, str], list[str], list[str]],
    tmp_path: Path,
    kind: str,
) -> None:
    expected, offers, fetched = transfer
    if kind == "duplicate":
        offers.append(offers[0])
    elif kind == "missing":
        offers.pop()
    else:
        offers.append("dotmac_kernel-0.1.0a100.zip")
    with pytest.raises(owner.Refusal):
        owner.acquire(
            {owner.KERNEL: "0.1.0a100"}, tmp_path / "out", expected_artifacts=expected
        )
    assert fetched == []


def test_exact_acquisition_retains_sdist_and_expected_hashes(
    transfer: tuple[dict[str, str], list[str], list[str]],
    tmp_path: Path,
) -> None:
    expected, _, fetched = transfer
    out = tmp_path / "out"
    assert (
        owner.acquire({owner.KERNEL: "0.1.0a100"}, out, expected_artifacts=expected)
        == expected
    )
    assert len(fetched) == 2
    assert json.loads((out / "digests.json").read_text()) == expected
    assert any(path.name.endswith(".tar.gz") for path in (out / "files").iterdir())


@pytest.mark.parametrize("kind", ["replacement", "extra", "missing"])
def test_changed_final_files_refuse(
    transfer: tuple[dict[str, str], list[str], list[str]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    expected, _, _ = transfer
    original = owner.fetch

    def changed(url: str, target: Path, **kwargs: Any) -> str:
        digest = original(url, target, **kwargs)
        if target.name.endswith(".tar.gz"):
            if kind == "replacement":
                target.write_bytes(b"replacement")
            elif kind == "extra":
                (target.parent / "extra.whl").write_bytes(b"extra")
            else:
                target.unlink()
        return digest

    monkeypatch.setattr(owner, "fetch", changed)
    with pytest.raises(owner.Refusal, match="exact lock set"):
        owner.acquire(
            {owner.KERNEL: "0.1.0a100"}, tmp_path / "out", expected_artifacts=expected
        )


def test_binary_scan_checks_raw_bytes(tmp_path: Path) -> None:
    path = tmp_path / "opaque.whl"
    path.write_bytes(b"\xff\x00synthetic-token\x80")
    assert owner.credential_sightings([path], "synthetic-token")
    with pytest.raises(owner.Refusal):
        owner.credential_sightings([path], "")


def test_binder_refuses_substituted_source_without_import(tmp_path: Path) -> None:
    path = tmp_path / "scripts" / "warm_reviewed_wheelhouse.py"
    path.parent.mkdir()
    path.write_text("raise RuntimeError('must never run')\n")
    with pytest.raises(owner.Refusal, match="source mismatch"):
        producer.load_binder(tmp_path)


def test_workflow_orders_admission_binding_scan_upload() -> None:
    workflow = (ROOT / ".github/workflows/private-artifact-produce.yml").read_text()
    assert "environment: dependency-bundle" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert workflow.index('test "$GITHUB_REF"') < workflow.index(
        "uses: actions/checkout"
    )
    assert "ref: ${{ github.sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "git diff --exit-code" in workflow
    assert "git ls-files --others --exclude-standard" in workflow
    assert producer.TOOLING_REVISION in workflow
    bind_pos = workflow.index("private_artifacts.py bind")
    credential_pos = workflow.index("FORGEJO_BUNDLE_READ_TOKEN:")
    scan_pos = workflow.index("private_artifacts.py acquire")
    upload_pos = workflow.index("uses: actions/upload-artifact")
    assert bind_pos < credential_pos < scan_pos < upload_pos
    assert workflow.count("secrets.") == 1
    assert "retention-days: 14" in workflow
    assert "FORGEJO_READ_TOKEN" not in workflow
    for forbidden in (
        "continue-on-error",
        "always()",
        "success()",
        "actions/cache",
        "pip install",
        "poetry",
        "inputs.ref",
        "work/scripts",
    ):
        assert forbidden not in workflow


def test_acquisition_refuses_bound_head_substitution_and_dirty_snapshot(
    pair: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest, lock = pair
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "pyproject.toml").write_bytes(manifest)
    (snapshot / "poetry.lock").write_bytes(lock)
    (snapshot / "binding.json").write_text("{}")
    monkeypatch.setenv("GITHUB_REPOSITORY", producer.REPOSITORY)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_WORKFLOW_SHA", "a" * 40)
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        f"{producer.REPOSITORY}/{producer.PRODUCER_PATH}@refs/heads/main",
    )
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    with pytest.raises(owner.Refusal, match="binding changed"):
        producer.acquire(snapshot, tmp_path / "out", "273", "b" * 40)
    (snapshot / "candidate-code.py").write_text("raise RuntimeError\n")
    with pytest.raises(owner.Refusal, match="data-only"):
        producer.acquire(snapshot, tmp_path / "out", "273", "b" * 40)
    assert not (tmp_path / "out").exists()


def test_workflow_has_no_candidate_checkout_or_package_execution() -> None:
    source = (ROOT / "scripts/warm_reviewed_private_artifacts.py").read_text()
    assert "helper.bind_snapshot(" in source
    assert "helper.admit_dispatch(" in source
    assert source.index("owner.sha256_hex(payload)") < source.index(
        "exec(compile(payload"
    )
    assert "owner.acquire(plan, out, expected_artifacts=artifacts)" in source
    assert "owner.credential_sightings(paths, credential)" in source
    assert 'os.environ.pop("FORGEJO_BUNDLE_READ_TOKEN"' in source
    for forbidden in ("subprocess", "pip", "poetry lock", "zipfile", "tarfile"):
        assert forbidden not in source


def test_secret_sighting_refuses_and_removes_private_home(
    pair: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest, lock = pair
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    for name, data in (("pyproject.toml", manifest), ("poetry.lock", lock)):
        (snapshot / name).write_bytes(data)
    for name, value in {
        "GITHUB_REPOSITORY": producer.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": (
            f"{producer.REPOSITORY}/{producer.PRODUCER_PATH}@refs/heads/main"
        ),
        "GITHUB_RUN_ID": "7",
        "GITHUB_RUN_ATTEMPT": "2",
        "FORGEJO_BUNDLE_READ_TOKEN": "synthetic-private-marker",
        "HOME": str(tmp_path / "original-home"),
    }.items():
        monkeypatch.setenv(name, value)
    receipt = producer.run_binding("273", "b" * 40)
    receipt.update(
        {
            "manifest-sha256": owner.sha256_hex(manifest),
            "lock-sha256": owner.sha256_hex(lock),
        }
    )
    (snapshot / "binding.json").write_text(json.dumps(receipt))
    private_homes: list[Path] = []

    def fake_acquire(plan: Any, out: Path, *, expected_artifacts: Any) -> Any:
        import os

        private_home = Path(os.environ["HOME"])
        private_homes.append(private_home)
        assert "FORGEJO_BUNDLE_READ_TOKEN" not in os.environ
        assert private_home.stat().st_mode & 0o777 == 0o700
        assert (private_home / ".netrc").stat().st_mode & 0o777 == 0o600
        out.mkdir()
        (out / "binary.whl").write_bytes(b"\xffsynthetic-private-marker\x80")
        return expected_artifacts

    monkeypatch.setattr(owner, "acquire", fake_acquire)
    with pytest.raises(owner.Refusal, match="upload refused"):
        producer.acquire(snapshot, tmp_path / "out", "273", "b" * 40)
    assert private_homes and not private_homes[0].exists()
    import os

    assert os.environ["HOME"] == str(tmp_path / "original-home")


def test_binder_executes_captured_bytes_without_source_reopen(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "scripts" / "warm_reviewed_wheelhouse.py"
    path.parent.mkdir()
    payload = b"CAPTURED_MARKER = 'verified source'\n"
    path.write_bytes(payload)
    monkeypatch.setattr(producer, "BINDER_SHA256", owner.sha256_hex(payload))
    original = Path.read_bytes
    reads: list[Path] = []

    def replace_after_read(subject: Path) -> bytes:
        captured = original(subject)
        if subject == path:
            reads.append(subject)
            subject.write_text("raise RuntimeError('source reopened after hashing')\n")
        return captured

    monkeypatch.setattr(Path, "read_bytes", replace_after_read)
    loaded = producer.load_binder(tmp_path)
    assert loaded.CAPTURED_MARKER == "verified source"
    assert reads == [path]
    source = original(ROOT / "scripts/warm_reviewed_private_artifacts.py").decode()
    loader = source.split("def load_binder", 1)[1].split("def closed_plan", 1)[0]
    assert "exec_module" not in loader
    assert 'compile(payload, str(path), "exec")' in loader


@pytest.mark.parametrize(
    "coordinate,value",
    [
        (
            "GITHUB_WORKFLOW_REF",
            producer.REPOSITORY + "/.github/workflows/other.yml@refs/heads/main",
        ),
        (
            "GITHUB_WORKFLOW_REF",
            producer.REPOSITORY
            + "/"
            + producer.PRODUCER_PATH
            + "@refs/heads/candidate",
        ),
        ("GITHUB_WORKFLOW_SHA", "c" * 40),
    ],
)
def test_workflow_identity_substitution_refuses(
    monkeypatch: pytest.MonkeyPatch,
    coordinate: str,
    value: str,
) -> None:
    for name, expected in {
        "GITHUB_REPOSITORY": producer.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "7",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": (
            f"{producer.REPOSITORY}/{producer.PRODUCER_PATH}@refs/heads/main"
        ),
    }.items():
        monkeypatch.setenv(name, expected)
    monkeypatch.setenv(coordinate, value)
    with pytest.raises(owner.Refusal, match="producer workflow"):
        producer.run_binding("273", "b" * 40)


def test_receipt_binds_actual_producer_workflow_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_ref = f"{producer.REPOSITORY}/{producer.PRODUCER_PATH}@refs/heads/main"
    for name, value in {
        "GITHUB_REPOSITORY": producer.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "7",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": workflow_ref,
    }.items():
        monkeypatch.setenv(name, value)
    receipt = producer.run_binding("273", "b" * 40)
    assert receipt["workflow-ref"] == workflow_ref
    assert receipt["workflow-sha"] == receipt["trusted-main-sha"] == "a" * 40
    assert receipt["workflow-file-sha256"] == owner.sha256_hex(
        (ROOT / producer.PRODUCER_PATH).read_bytes()
    )
