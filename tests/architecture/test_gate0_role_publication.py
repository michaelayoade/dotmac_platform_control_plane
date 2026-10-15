"""Source contract for the manual role publisher; no registry or Docker calls."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from run_block_expressions import (
    _job_blocks,
    _resolved_step_blocks,
    _step_fields,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/production-image.yml"


def _contract(text: str) -> None:
    jobs = _job_blocks(text)
    role = jobs["gate0-role"]
    for term in (
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        "inputs.image_target == 'gate0-role'",
        "environment: production",
        "IMAGE_TARGET: gate0-role",
        (
            "IMAGE_REPOSITORY: ghcr.io/michaelayoade/"
            "dotmac_vendor_control_plane_gate0_role"
        ),
        "RECEIPT_PREFIX: gate0-role-release-receipt",
        "steps: *accepted_candidate_steps",
    ):
        assert term in role, term
    assert "IMAGE_TARGET: runtime" in jobs["candidate"]
    assert "inputs.image_target == 'runtime'" in jobs["candidate"]
    assert text.count("steps: &accepted_candidate_steps") == 1
    resolved = _resolved_step_blocks(jobs)
    assert resolved["candidate"] == resolved["gate0-role"]
    steps = [_step_fields(block) for block in resolved["gate0-role"]]
    runs = "\n".join(step.get("run", "") for step in steps)
    assert "${{" not in runs
    for term in (
        '--target "${IMAGE_TARGET}"',
        'base["gates"] + ["installed-sshd", "role-image"]',
        'gate_args=(--gates "$ROLE_GATES_FILE")',
        '"${gate_args[@]}"',
        'docker image save "${CANDIDATE_TAG}"',
        "archive.extractfile(member)",
        "hashlib.sha256(raw).hexdigest()",
        'test "$registry_config" = "$ACCEPTED_CONFIG_DIGEST"',
        '.github/candidate/acceptance.sh "${CANDIDATE_TAG}"',
        "dotmac-candidate-release-receipt/1",
        "dotmac-gate0-role-release-receipt/1",
    ):
        assert term in runs, term
    assert "extractall(" not in runs
    accept = next(
        s["run"] for s in steps if "Accept the candidate" in s.get("name", "")
    )
    for term in (
        "--network none --read-only --cap-drop ALL",
        "conformance/gate0_role_image_smoke.py,dst=/qualification.py,readonly",
        '"${CANDIDATE_TAG}" -I -B /qualification.py',
        '.schema == "Gate0RoleImageSmoke.v1"',
        ".passed == true and .live_readiness == false",
        ".source_revision == $revision",
    ):
        assert term in accept, term
    assert (
        runs.index("/qualification.py")
        < runs.index("docker login")
        < runs.index("docker push")
    )
    assert runs.index(
        'test "$registry_config" = "$ACCEPTED_CONFIG_DIGEST"'
    ) < runs.index("dotmac-gate0-role-release-receipt/1")


def test_one_guarded_role_job_reuses_accepted_publisher() -> None:
    _contract(WORKFLOW.read_text())


@pytest.mark.parametrize(
    "old,new",
    [
        ("environment: production", "environment: unprotected"),
        ("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'"),
        ("IMAGE_TARGET: gate0-role", "IMAGE_TARGET: runtime"),
        ('["installed-sshd", "role-image"]', '["installed-sshd"]'),
        (
            '"${CANDIDATE_TAG}" -I -B /qualification.py',
            "other-image -I -B /qualification.py",
        ),
        ('test "$registry_config" = "$ACCEPTED_CONFIG_DIGEST"', "true"),
    ],
)
def test_contract_refuses_publication_regressions(old: str, new: str) -> None:
    text = WORKFLOW.read_text()
    assert old in text
    with pytest.raises(AssertionError):
        _contract(text.replace(old, new))


def test_contract_refuses_push_before_acceptance() -> None:
    text = WORKFLOW.read_text()
    with pytest.raises(AssertionError):
        _contract(
            text.replace(
                "docker manifest inspect --help",
                'docker push "$CANDIDATE_TAG"\n'
                "          docker manifest inspect --help",
                1,
            )
        )


def _heredoc(marker: str) -> str:
    text = WORKFLOW.read_text()
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if f"<<'{marker}'" in line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == marker)
    return "\n".join(line[10:] for line in lines[start + 1 : end]) + "\n"


@pytest.mark.parametrize(
    "revision,layers,path,accepted",
    [
        ("a" * 40, ["sha256:" + "b" * 64], "c" * 64 + ".json", True),
        ("d" * 40, ["sha256:" + "b" * 64], "c" * 64 + ".json", False),
        ("a" * 40, [], "c" * 64 + ".json", False),
        ("a" * 40, ["sha256:" + "b" * 64], "../config.json", False),
    ],
)
def test_role_identity_hashes_actual_config_bytes(
    tmp_path: Path,
    revision: str,
    layers: list[str],
    path: str,
    accepted: bool,
) -> None:
    raw = json.dumps(
        {
            "config": {"Labels": {"org.opencontainers.image.revision": revision}},
            "rootfs": {"diff_ids": layers},
        }
    ).encode()
    with tarfile.open(tmp_path / "candidate-image.tar", "w") as archive:
        for name, data in (
            ("manifest.json", json.dumps([{"Config": path}]).encode()),
            (path, raw),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    environment = {
        **os.environ,
        "SOURCE_SHA": "a" * 40,
        "CANDIDATE_LAYERS": json.dumps(["sha256:" + "b" * 64]),
    }
    result = subprocess.run(  # noqa: S603 -- fixed repo-owned snippet, synthetic inputs
        [sys.executable, "-I", "-c", _heredoc("PYCONFIG")],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert (result.returncode == 0) is accepted
    if accepted:
        assert (
            result.stdout.decode().strip()
            == "sha256:" + hashlib.sha256(raw).hexdigest()
        )


@pytest.mark.parametrize(
    "base", [["check", "postgres"], [], ["check", "check"], [None]]
)
def test_role_gates_extend_the_existing_owner_without_replacing_it(
    tmp_path: Path,
    base: list[object],
) -> None:
    directory = tmp_path / ".github/candidate"
    directory.mkdir(parents=True)
    (directory / "required-gates.json").write_text(json.dumps({"gates": base}))
    output = tmp_path / "role-gates.json"
    result = subprocess.run(  # noqa: S603 -- fixed repo-owned snippet, synthetic inputs
        [sys.executable, "-I", "-c", _heredoc("PYROLE")],
        cwd=tmp_path,
        env={**os.environ, "ROLE_GATES_FILE": str(output)},
        capture_output=True,
        timeout=5,
        check=False,
    )
    if base == ["check", "postgres"]:
        assert result.returncode == 0
        assert json.loads(output.read_text())["gates"] == base + [
            "installed-sshd",
            "role-image",
        ]
    else:
        assert result.returncode != 0
        assert not output.exists()


@pytest.mark.parametrize(
    "target,same,accepted",
    [
        ("gate0-role", True, True),
        ("gate0-role", False, False),
        ("runtime", False, True),
    ],
)
def test_actual_role_readback_guard_refuses_config_identity_drift(
    target: str,
    same: bool,
    accepted: bool,
) -> None:
    text = WORKFLOW.read_text()
    guard_start = text.index(
        '          if [ "$IMAGE_TARGET" = gate0-role ]; then',
        text.index('registry_config="$(docker manifest'),
    )
    guard_end = text.index("          fi", guard_start) + len("          fi")
    guard = "\n".join(line[10:] for line in text[guard_start:guard_end].splitlines())
    digest = "sha256:" + "a" * 64
    result = subprocess.run(  # noqa: S603 -- fixed repo-owned snippet, synthetic inputs
        ["/bin/bash", "-euo", "pipefail", "-c", guard],
        env={
            **os.environ,
            "IMAGE_TARGET": target,
            "registry_config": digest,
            "ACCEPTED_CONFIG_DIGEST": digest if same else "sha256:" + "b" * 64,
        },
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert (result.returncode == 0) is accepted
    if not accepted:
        assert result.stderr == b"registry config differs from accepted role config\n"


def test_app_receipt_projection_remains_unchanged() -> None:
    text = WORKFLOW.read_text()
    projection = text[text.index("'{contract:") : text.index("> release-receipt.json")]
    assert (
        projection
        == """'{contract:"dotmac-candidate-release-receipt/1", accepted:$accepted,
              source_revision:$source_revision, ci_run_id:$ci_run_id,
              release_run_id:$release_run_id, registry_digest:$registry_digest,
              reference:$reference, config_digest:$config_digest,
              registry_config_digest:$registry_config_digest,
              rootfs_chain:$rootfs_chain, lock_digest:$lock_digest,
              dockerfile_digest:$dockerfile_digest,
              distributions:$distributions}' \\
            """
    )
