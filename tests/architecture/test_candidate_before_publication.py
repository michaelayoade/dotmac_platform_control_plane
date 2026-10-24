"""Require acceptance before publication and compare the same candidate afterward.

Ordering, immutable identity and a real registry read keep a failed candidate
from becoming a deployable release.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE_WORKFLOW = ROOT / ".github" / "workflows" / "production-image.yml"
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "production-deploy.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
STANDARDS_WORKFLOW = ROOT / ".github" / "workflows" / "engineering-standards.yml"
ACCEPTANCE = ROOT / ".github" / "candidate" / "acceptance.sh"
VERIFIER = ROOT / ".github" / "candidate" / "verify_source_revision.py"
GATES = ROOT / ".github" / "candidate" / "required-gates.json"
UI_EXPECTED = ROOT / ".github" / "candidate" / "ui-assets.expected"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


IMAGE = _text(IMAGE_WORKFLOW)
BATTERY = _text(ACCEPTANCE)
RECORDER = ROOT / ".github/candidate/record_identity.py"
IDENTITY = _text(RECORDER)
spec = importlib.util.spec_from_file_location("candidate_identity", RECORDER)
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)


def _manifest(media_type: str, **fields: object) -> str:
    return json.dumps({"schemaVersion": 2, "mediaType": media_type, **fields})


def _digest(raw: str) -> str:
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


@pytest.mark.parametrize("layout", ["classic", "oci"])
@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "missing-manifest",
        "duplicate-manifest",
        "link-manifest",
        "hardlink-manifest",
        "bad-manifest",
        "empty-manifest",
        "multiple-images",
        "large-manifest",
        "missing-config",
        "duplicate-config",
        "link-config",
        "hardlink-config",
        "large-config",
        "bad-path",
        "traversal",
        "wrong-hash",
        "bad-config",
        "wrong-platform",
        "wrong-layers",
        "wrong-revision",
        "bad-distributions",
        "wrong-config-revision",
        "bad-rootfs-type",
        "empty-layers",
        "bad-layer-digest",
    ],
)
def test_recorder_archive_and_output_guards(tmp_path, monkeypatch, layout, case):
    """Run the full shared recorder; every refusal must precede every output."""
    revision, layer = "a" * 40, "sha256:" + "b" * 64
    config = {
        "os": "linux",
        "architecture": "amd64",
        "config": {"Labels": {"org.opencontainers.image.revision": revision}},
        "rootfs": {"type": "layers", "diff_ids": [layer]},
    }
    if case == "wrong-config-revision":
        config["config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
    if case == "bad-rootfs-type":
        config["rootfs"]["type"] = "unknown"
    if case in {"empty-layers", "bad-layer-digest"}:
        config["rootfs"]["diff_ids"] = [] if case == "empty-layers" else ["bad"]
    raw = json.dumps(config).encode()
    if case == "bad-config":
        raw = b"{"
    if case == "wrong-platform":
        raw = raw.replace(b"amd64", b"arm64")
    name = hashlib.sha256(raw).hexdigest() + ".json"
    if layout == "oci":
        name = "blobs/sha256/" + name.removesuffix(".json")
    if case in {"bad-path", "traversal", "wrong-hash"}:
        name = {
            "bad-path": "config.json",
            "traversal": "../" + name,
            "wrong-hash": "c" * 64 + ".json",
        }[case]
    manifest = json.dumps(
        [{"Config": name}] * (2 if case == "multiple-images" else 1)
    ).encode()
    if case in {"bad-manifest", "empty-manifest"}:
        manifest = b"{" if case == "bad-manifest" else b"[]"
    archive_path = tmp_path / "fixture.tar"
    with tarfile.open(archive_path, "w") as archive:
        for kind, member_name, content in (
            ("manifest", "manifest.json", manifest),
            ("config", name, raw),
        ):
            if case == "missing-" + kind:
                continue
            for _ in range(2 if case == "duplicate-" + kind else 1):
                member = tarfile.TarInfo(member_name)
                member.size = len(content)
                if case in {"link-" + kind, "hardlink-" + kind}:
                    member.type = (
                        tarfile.LNKTYPE
                        if case.startswith("hardlink")
                        else tarfile.SYMTYPE
                    )
                    member.linkname = "elsewhere"
                if case == "large-" + kind:
                    content = b" " * (4 * 1024 * 1024 + 1)
                    member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    inspected = [
        {
            "Os": "linux",
            "Architecture": "amd64",
            "Id": "store-id",
            "Config": {"Labels": {"org.opencontainers.image.revision": revision}},
            "RootFS": {"Layers": [] if case == "wrong-layers" else [layer]},
        }
    ]
    distributions = {
        "files": [
            {"filename": "package" + suffix, "sha256": layer}
            for suffix in (".whl", ".tar.gz")
        ]
    }

    def docker(*args):
        if args == ("image", "inspect", "candidate"):
            return json.dumps(inspected).encode()
        if args[:3] == ("image", "save", "--platform"):
            assert (
                args[3] == "linux/amd64" and args[4] == "-o" and args[6] == "candidate"
            )
            Path(args[5]).write_bytes(archive_path.read_bytes())
            return b""
        assert args == (
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "cat",
            "candidate",
            "/app/distributions.json",
        )
        return (
            b"{}" if case == "bad-distributions" else json.dumps(distributions).encode()
        )

    monkeypatch.setattr(recorder, "docker", docker)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "outputs"))
    for filename in ("poetry.lock", "Dockerfile"):
        (tmp_path / filename).write_text(filename)
    if case != "valid":
        with pytest.raises((ValueError, KeyError, TypeError)):
            recorder.main(
                "candidate", "d" * 40 if case == "wrong-revision" else revision
            )
        assert not (tmp_path / "outputs").exists()
        assert not (tmp_path / "candidate-identity.json").exists()
        return
    recorder.main("candidate", revision)
    outputs = dict(
        line.split("=", 1) for line in (tmp_path / "outputs").read_text().splitlines()
    )
    assert (tmp_path / "outputs").read_text().count("identity_json=") == 1
    identity = json.loads(outputs["identity_json"])
    assert identity == json.loads((tmp_path / "candidate-identity.json").read_text())
    assert identity["config_digest"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert identity["layers"] == [layer] and identity["rootfs_chain"] == _digest(
        json.dumps([layer], separators=(",", ":"))
    )
    assert (
        identity["distributions"] == distributions
        and identity["source_revision"] == revision
    )
    for key in (
        "config_digest",
        "platform",
        "rootfs_chain",
        "lock_digest",
        "dockerfile_digest",
    ):
        assert outputs[key] == identity[key]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "no-layout",
        "config-only",
        "bad-size",
        "bad-layer",
        "wrong-diff-id",
        "wrong-platform",
        "duplicate",
    ],
)
def test_native_coordinate_requires_genuine_oci_manifest(tmp_path, fault):
    revision = "a" * 40
    layer = b"actual exported layer bytes"
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "config": {"Labels": {"org.opencontainers.image.revision": revision}},
            "rootfs": {
                "type": "layers",
                "diff_ids": [
                    "sha256:" + "d" * 64
                    if fault == "wrong-diff-id"
                    else _digest(layer.decode())
                ],
            },
        }
    ).encode()
    entries = {}

    def descriptor(raw, media_type):
        checksum = "sha256:" + hashlib.sha256(raw).hexdigest()
        entries["blobs/sha256/" + checksum[7:]] = raw
        return {"mediaType": media_type, "digest": checksum, "size": len(raw)}

    config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
    layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    if fault == "bad-size":
        layer_descriptor["size"] += 1
    if fault == "bad-layer":
        entries["blobs/sha256/" + layer_descriptor["digest"][7:]] = (
            b"altered exported layer bytes"
        )
    manifest = json.dumps(
        {"schemaVersion": 2, "config": config_descriptor, "layers": [layer_descriptor]}
    ).encode()
    selected = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    selected["platform"] = {
        "os": "linux",
        "architecture": "arm64" if fault == "wrong-platform" else "amd64",
    }
    entries["index.json"] = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [selected] * (2 if fault == "duplicate" else 1),
        }
    ).encode()
    entries["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    entries["manifest.json"] = json.dumps(
        [{"Config": "blobs/sha256/" + config_descriptor["digest"][7:]}]
    ).encode()
    if fault == "no-layout":
        del entries["oci-layout"]
    if fault == "config-only":
        entries["index.json"] = json.dumps(
            {"schemaVersion": 2, "manifests": [config_descriptor]}
        ).encode()
    path = tmp_path / "export.tar"
    with tarfile.open(path, "w") as archive:
        for name, raw in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    if fault:
        with pytest.raises((ValueError, KeyError)):
            recorder.archive_oci_coordinate(path, "linux/amd64", revision)
    else:
        coordinate, config_sha, layers = recorder.archive_oci_coordinate(
            path, "linux/amd64", revision
        )
        assert coordinate == selected["digest"] != config_descriptor["digest"]
        assert config_sha == config_descriptor["digest"]
        assert layers == [_digest(layer.decode())]


# ── the ordering, which is the whole point ──────────────────────────────────


def test_the_candidate_is_accepted_before_anything_is_published() -> None:
    """Accept recorded bytes before registry login, publication and receipts."""
    build = IMAGE.index("Build the candidate")
    identity = IMAGE.index("Record the candidate's identity")
    accept = IMAGE.index("Accept the candidate, or refuse it")
    login = IMAGE.index("Authenticate to GHCR")
    publish = IMAGE.index("Publish the accepted candidate")
    readback = IMAGE.index("Prove the registry holds the accepted candidate")
    receipt = IMAGE.index("Emit the release receipt")
    assert build < identity < accept < login < publish < readback < receipt
    assert identity < IMAGE.index("docker buildx imagetools inspect --help") < accept


def test_nothing_is_pushed_before_the_candidate_is_accepted() -> None:
    """The single assertion that would have caught the previous design."""
    accept = IMAGE.index("Accept the candidate, or refuse it")
    pushes = [
        index for index in range(len(IMAGE)) if IMAGE.startswith("docker push", index)
    ]
    assert pushes, "no publication step was found at all"
    assert all(index > accept for index in pushes), (
        "a `docker push` appears before the acceptance step; a failing "
        "acceptance would leave published bytes nobody accepted"
    )
    assert "docker login" not in IMAGE[:accept], (
        "the registry credential is acquired before acceptance, which is the "
        "shape that makes an early push possible"
    )


def test_the_identity_recorded_is_the_identity_compared() -> None:
    """Recording a digest nobody compares is bookkeeping, not a proof."""
    for field in ("config_digest", "rootfs_chain", "lock_digest", "dockerfile_digest"):
        assert field in IDENTITY, field
    assert "steps.identity.outputs.config_digest" in IMAGE
    assert "steps.identity.outputs.rootfs_chain" in IMAGE
    assert "source_revision" in IMAGE


def test_the_read_back_compares_like_for_like() -> None:
    """Saved original config bytes and registry raw manifests name like objects."""
    assert "--metadata-file" not in IMAGE
    assert "containerimage.config.digest" not in IMAGE
    assert 'docker("image", "save", "--platform", selected' in IDENTITY
    assert "hashlib.sha256(raw).hexdigest()" in IDENTITY
    assert ".Id" not in IMAGE and ".RepoDigests" not in IMAGE
    assert 'reference="${IMAGE_REPOSITORY}@$digest"' in IMAGE
    assert 'test "$registry_config" = "$ACCEPTED_CONFIG_DIGEST"' in IMAGE


@pytest.mark.parametrize(
    "case",
    [
        "oci",
        "docker",
        "index",
        "docker-index",
        "wrong-config",
        "malformed",
        "ambiguous",
        "wrong-platform",
        "wrong-child",
        "attestation",
        "bad-json",
        "bad-media",
        "malformed-child-digest",
        "wrong-root",
        "bad-schema",
        "bad-config-kind",
    ],
)
def test_registry_config_guard_executes_before_output(
    tmp_path: Path, case: str
) -> None:
    """Execute the actual registry guard with synthetic Docker output only."""
    readback = IMAGE.split("Prove the registry holds the accepted candidate", 1)[1]
    fields = readback.split("        run: |", 1)[0]
    for field in ("config_digest", "platform"):
        name = "ACCEPTED_" + field.upper()
        assert fields.count(name + ":") == 1
        assert f"{name}: ${{{{ steps.identity.outputs.{field} }}}}" in fields
    start = readback.index("          docker buildx imagetools inspect --raw")
    guard = textwrap.dedent(readback[start : readback.index("\n\n", start)])
    assert "${{" not in guard
    expected = "sha256:" + "a" * 64
    media = "application/vnd.oci.image.manifest.v1+json"
    if case.startswith("docker"):
        media = "application/vnd.docker.distribution.manifest.v2+json"
    config = "malformed" if case == "malformed" else "sha256:" + "b" * 64
    child = _manifest(
        media,
        schemaVersion=1 if case == "bad-schema" else 2,
        config={
            "mediaType": "unknown"
            if case == "bad-config-kind"
            else "application/vnd.oci.image.config.v1+json",
            "digest": config if case in {"malformed", "wrong-config"} else expected,
        },
    )
    digest = _digest(child)
    descriptor = {
        "digest": digest,
        "platform": {"os": "linux", "architecture": "amd64"},
    }
    root = child
    if case in {
        "index",
        "docker-index",
        "ambiguous",
        "wrong-platform",
        "wrong-child",
        "attestation",
        "malformed-child-digest",
    }:
        if case == "wrong-platform":
            descriptor["platform"]["architecture"] = "arm64"
        if case == "attestation":
            descriptor["annotations"] = {
                "vnd.docker.reference.type": "attestation-manifest"
            }
        if case == "malformed-child-digest":
            descriptor["digest"] = "malformed"
        descriptors = [descriptor] * (2 if case == "ambiguous" else 1)
        if case in {"index", "docker-index"}:
            descriptors.insert(
                0,
                dict(
                    descriptor,
                    annotations={"vnd.docker.reference.type": "attestation-manifest"},
                ),
            )
        root = _manifest(
            "application/vnd.docker.distribution.manifest.list.v2+json"
            if case == "docker-index"
            else "application/vnd.oci.image.index.v1+json",
            manifests=descriptors,
        )
    if case in {"bad-json", "bad-media"}:
        root = "{" if case == "bad-json" else _manifest("unknown")
    reference = "registry.invalid/candidate@" + _digest(root)
    output = tmp_path / "output"
    result = subprocess.run(  # noqa: S603 -- fixed workflow guard and fixtures
        [
            "/bin/bash",
            "-c",
            """set -euo pipefail
            docker() {
              [[ $# == 5 ]] || return 90
              [[ $1 == buildx && $2 == imagetools &&
                 $3 == inspect && $4 == --raw ]] || return 91
              if [[ $5 == "$reference" ]]; then
                printf %s "$ROOT_MANIFEST"
              elif [[ $5 == "$IMAGE_REPOSITORY@$CHILD_DIGEST" ]]; then
                printf %s "$CHILD_MANIFEST"
              else
                return 92
              fi
            }
            """
            + guard,
        ],
        env={
            "PATH": os.defpath + os.pathsep + "/sbin",
            "ROOT_MANIFEST": root + (" " if case == "wrong-root" else ""),
            "CHILD_MANIFEST": child + (" " if case == "wrong-child" else ""),
            "CHILD_DIGEST": digest,
            "reference": reference,
            "IMAGE_REPOSITORY": "registry.invalid/candidate",
            "GITHUB_OUTPUT": str(output),
            "ACCEPTED_CONFIG_DIGEST": expected,
            "ACCEPTED_PLATFORM": "linux/amd64",
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if case in {"oci", "docker", "index", "docker-index"}:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == f"registry_config={expected}\n"
    else:
        assert result.returncode != 0
        assert not output.exists()


def test_the_read_back_actually_leaves_the_runner() -> None:
    """A digest-pinned pull follows removal and proof of local absence."""
    remove = IMAGE.index("docker image rm -f")
    inspect_guard = IMAGE.index("the candidate is still resident locally")
    pull = IMAGE.index('docker pull --platform "$ACCEPTED_PLATFORM" "$reference"')
    compare = IMAGE.index("registry RootFS chain $pulled_chain != accepted")
    assert remove < inspect_guard < pull < compare
    # And the pull's own output is kept, so the run log carries the fetch as an
    # OBSERVATION rather than leaving the whole proof resting on the guard.
    # Measured need: release run 33474406793 passed this step with the output
    # discarded, and the log therefore showed no evidence the bytes had moved.
    assert (
        'docker pull --platform "$ACCEPTED_PLATFORM" "$reference" >/dev/null'
        not in IMAGE
    )


def test_the_distribution_digests_are_read_from_the_candidate_not_remeasured() -> None:
    """Read installed artifact digests without rebuilding timestamped archives."""
    identity = IDENTITY
    assert "/app/distributions.json" in identity
    # The property is that nothing INVOKES a second build, not that the words
    # are unmentionable — the comment explaining why it must not is the
    # documentation this rule most wants written. Same mistake, and same
    # correction, as the Dockerfile's PYTHONPATH guard.
    invocations = [
        line
        for line in identity.splitlines()
        if "poetry build" in line and not line.lstrip().startswith("#")
    ]
    assert invocations == [], invocations
    # And a receipt that recorded an empty list, or one format, would be a
    # narrowing nobody would notice. Both are required where they are read.
    assert 'endswith(".whl")' in identity
    assert 'endswith(".tar.gz")' in identity


def test_the_manifest_the_receipt_reads_is_checked_before_publication() -> None:
    """Validate the installed distribution manifest before publication."""
    assert "/app/distributions.json" in BATTERY
    assert "dotmac-distribution-digests/1" in BATTERY
    # Tied to the installed distribution, not free-floating.
    assert "importlib.metadata import version" in BATTERY


def test_the_image_carries_the_distributions_the_receipt_describes() -> None:
    """The claim is re-derivable from a pulled image, not only from a run log."""
    dockerfile = _text(ROOT / "Dockerfile")
    assert (
        "--format wheel" not in dockerfile
    ), "only a wheel is built, so the receipt cannot carry an sdist digest"
    assert "dotmac-distribution-digests/1" in dockerfile
    assert "no wheel was built" in dockerfile
    assert "no sdist was built" in dockerfile
    assert "/app/distributions.json ./distributions.json" in dockerfile


def test_the_battery_is_reachable_from_the_pull_request_path() -> None:
    """PR CI exercises the same candidate battery used for publication."""
    ci = _text(CI_WORKFLOW)
    assert "Rehearse the acceptance battery" in ci
    assert 'record_identity.py dotmac-vendor-control-plane:ci "$GITHUB_SHA"' in ci
    assert ci.index("record_identity.py") < ci.index("Boot-smoke the built bytes")
    assert (
        'record_identity.py "${CANDIDATE_TAG}" "${{ steps.select.outputs.source_sha }}"'
        in IMAGE
    )
    assert ".github/candidate/acceptance.sh" in ci
    # One script, two callers. A rehearsal that had its own copy would drift,
    # and a drifting rehearsal is worse than no rehearsal.
    assert "acceptance.sh" in _text(IMAGE_WORKFLOW)
    assert not (ROOT / ".github" / "candidate" / "acceptance-ci.sh").exists()


def test_the_rehearsal_does_not_become_the_acceptance() -> None:
    """Accept the exact candidate even when CI rehearsed the battery.
    A rehearsal image differs from the protected-main artifact being published.
    """
    accept = IMAGE.index("Accept the candidate, or refuse it")
    assert ".github/candidate/acceptance.sh" in IMAGE[accept:]
    assert IMAGE.index("docker push") > accept


def test_the_role_contract_query_renders_the_form_it_declares() -> None:
    """Render PostgreSQL booleans explicitly as text for the declared contract.
    Default boolean output uses t/f and cannot equal true/false.
    """
    contract = BATTERY[BATTERY.index('step "5  database ownership') :]
    contract = contract[: contract.index("owner_contract=")]
    for flag in ("rolsuper", "rolcreaterole", "rolbypassrls", "rolcanlogin"):
        assert f"{flag}::text" in contract, (
            f"{flag} is rendered by the boolean output function, which emits "
            "t/f and can never equal the declared true/false"
        )
    assert 'test "$role_contract" = "false|false|true|true"' in BATTERY


def test_the_receipt_binds_the_revision_the_run_and_the_bytes() -> None:
    receipt = IMAGE[IMAGE.index("Emit the release receipt") :]
    for field in (
        "source_revision",
        "ci_run_id",
        "release_run_id",
        "registry_digest",
        "config_digest",
        "rootfs_chain",
        "lock_digest",
        "dockerfile_digest",
        "distributions",
    ):
        assert field in receipt or field in IDENTITY, field
    assert "dotmac-candidate-release-receipt/1" in receipt
    assert "registry_config_digest" in receipt
    assert "steps.readback.outputs.registry_config" in receipt
    assert "ACCEPTED_IDENTITY: ${{ steps.identity.outputs.identity_json }}" in receipt
    assert '--argjson identity "$ACCEPTED_IDENTITY"' in receipt
    assert "del(.layers,.platform)" in receipt
    assert "$(cat candidate-distributions.json)" not in receipt
    assert "candidate-distributions.json" in receipt


def test_receipt_executes_with_latched_identity(tmp_path):
    """Mutation of uploaded files cannot change the identity in the receipt."""
    receipt = IMAGE.split("Emit the release receipt", 1)[1]
    script = textwrap.dedent(
        receipt.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    )
    replacements = {
        "${{ steps.publish.outputs.digest }}": "registry-digest",
        "${{ steps.publish.outputs.reference }}": "registry-reference",
        "${{ steps.readback.outputs.registry_config }}": "registry-config",
    }
    for key, value in replacements.items():
        script = script.replace(key, value)
    assert "${{" not in script
    identity = dict(
        source_revision="revision",
        config_digest="config",
        rootfs_chain="chain",
        lock_digest="lock",
        dockerfile_digest="dockerfile",
        distributions={"files": ["latched"]},
        layers=["layer"],
        platform="linux/amd64",
    )
    (tmp_path / "candidate-distributions.json").write_text('{"files":["mutated"]}')
    result = subprocess.run(  # noqa: S603 -- fixed workflow script and synthetic environment
        ["/bin/bash", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            "PATH": os.defpath,
            "ACCEPTED_IDENTITY": json.dumps(identity),
            "CI_RUN_ID": "ci",
            "GITHUB_RUN_ID": "release",
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        },
        check=False,
    )
    assert result.returncode == 0, result.stderr
    expected = {
        key: value
        for key, value in identity.items()
        if key not in {"layers", "platform"}
    }
    expected.update(
        contract="dotmac-candidate-release-receipt/1",
        accepted="candidate accepted before publication",
        ci_run_id="ci",
        release_run_id="release",
        registry_digest="registry-digest",
        reference="registry-reference",
        registry_config_digest="registry-config",
    )
    assert json.loads((tmp_path / "release-receipt.json").read_text()) == expected


# ── admission: which revisions may be built at all ──────────────────────────


def test_the_required_gate_set_matches_the_workflows_in_both_directions() -> None:
    """Compare declared required gates with workflow jobs in both directions.
    Either a missing gate or an invented gate invalidates source admission.
    """
    declared = set(json.loads(_text(GATES))["gates"])
    # Sliced from `jobs:` onward, because `on:` and `permissions:` also carry
    # two-space keys and a parser that took every one of them would report
    # `push` and `workflow_dispatch` as required gates.
    ci_body = _text(CI_WORKFLOW).split("\njobs:\n", 1)[1]
    ci_jobs = {
        line.strip().rstrip(":")
        for line in ci_body.splitlines()
        if line.startswith("  ")
        and not line.startswith("   ")
        and line.rstrip().endswith(":")
    }
    external = {
        name
        for name in (
            "Governance pin is a real approved revision",
            "Dotmac engineering standards",
        )
        if name in _text(STANDARDS_WORKFLOW)
    }
    assert declared == ci_jobs | external, {
        "declared_only": sorted(declared - (ci_jobs | external)),
        "undeclared": sorted((ci_jobs | external) - declared),
    }


def test_the_required_gate_set_is_not_empty() -> None:
    """NON-VACUITY. An admission rule requiring nothing admits everything."""
    assert json.loads(_text(GATES))["gates"]


def test_the_verifier_makes_all_seven_checks() -> None:
    """Require every source-revision admission check in the shared verifier.
    A successful run alone cannot prove source identity or required-gate success.
    """
    verifier = _text(VERIFIER)
    assert "belongs to" in verifier  # 1 repository
    assert "not {workflow_path!r}" in verifier  # 2 workflow
    assert "not completed" in verifier  # 3 terminal status
    assert "not success" in verifier  # 3 conclusion
    assert "head repository" in verifier  # 4 protected main, no fork
    assert "is not a 40-hex SHA" in verifier  # 5 SHA shape
    # 6 — the run describes the revision the CALLER named. The marker is the
    #     property sentence rather than the subject of it: this read
    #     "current {branch} is", which stopped matching the moment the check
    #     was correctly generalised from "the tip" to "the revision named",
    #     and a marker that breaks on a rewording was asserting the prose.
    assert "describes a tree nobody is deploying" in verifier
    assert "produced no check-run" in verifier  # 7 gate absent
    assert "even when a required job skipped" in verifier  # 7 gate skipped


def test_skipped_is_refused_by_name() -> None:
    """`skipped` reads as success at the workflow level. It is listed first in
    the non-passing set for that reason, and this holds it there."""
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("candidate_verifier", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert "skipped" in module.NON_PASSING
    assert module.NON_PASSING[0] == "skipped"
    for conclusion in (
        "neutral",
        "cancelled",
        "timed_out",
        "action_required",
        "failure",
    ):
        assert conclusion in module.NON_PASSING
    assert "success" not in module.NON_PASSING


def test_the_deploy_requires_a_receipt_rather_than_a_pasted_digest() -> None:
    workflow = _text(DEPLOY_WORKFLOW)
    assert "ci_run_id" in workflow
    assert "verify_source_revision.py" in workflow
    verify = workflow.index("Verify the source revision earned its way here")
    receipt = workflow.index("Require a release receipt binding this digest")
    deploy = workflow.index("Deploy the approved digest")
    assert verify < receipt < deploy
    assert 'receipt.get("registry_digest") != os.environ["IMAGE_DIGEST"]' in workflow


def test_every_verifier_argument_it_reads_is_one_it_declares() -> None:
    """Exercise each verifier against the workflow arguments it consumes.
    An undeclared option must fail in review rather than block publication.
    """
    import ast

    tree = ast.parse(_text(VERIFIER))

    declared: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(
                    argument.value, str
                ):
                    declared.add(argument.value.lstrip("-").replace("-", "_"))
            for keyword in node.keywords:
                if keyword.arg == "dest" and isinstance(keyword.value, ast.Constant):
                    declared.add(str(keyword.value.value))
    assert declared, "no argparse arguments were found; this check is inert"

    read = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "args"
    }
    assert read, "no `args.<name>` accesses were found; this check is inert"

    undeclared = sorted(read - declared)
    assert not undeclared, (
        f"the verifier reads {undeclared} but declares no such argument. On the "
        "ACCEPTED path this is an AttributeError, so the gate refuses "
        "everything and looks like it is working."
    )


def test_the_deploy_names_the_image_revision_rather_than_assuming_the_tip() -> None:
    """Bind deployment to the accepted image revision, distinct from adapter main.
    The accepted image may precede the adapter without losing its provenance.
    """
    workflow = _text(DEPLOY_WORKFLOW)

    assert "image_source_revision:" in workflow
    assert '--expect-head "$IMAGE_SOURCE_REVISION"' in workflow
    assert 'merge-base --is-ancestor "$IMAGE_SOURCE_REVISION" FETCH_HEAD' in workflow
    assert 'echo "source_sha=$IMAGE_SOURCE_REVISION"' in workflow

    # The conflation, by name. `current_main` as the deploying revision is the
    # exact line this change removed, and it must not come back.
    assert 'current_main="$(git rev-parse FETCH_HEAD)"' not in workflow
    assert "--current-main" not in workflow


def test_the_candidate_build_still_requires_the_tip() -> None:
    """Require candidate builds to use the current protected-main revision.
    Deployment may reuse accepted history; a new build must use the selected tip.
    """
    assert 'current_main="$(git rev-parse HEAD)"' in IMAGE
    assert '--expect-head "${{ steps.select.outputs.current_main }}"' in IMAGE


# ── the acceptance battery covers what it claims to ─────────────────────────


#: Every property the candidate must demonstrate, with the marker that proves
#: the battery still asks for it. Declared as data so a check quietly deleted
#: from the script fails here rather than disappearing.
REQUIRED_CHECKS: dict[str, str] = {
    "installed CLI": "the console script is not installed in the candidate",
    # An observation about THIS candidate, not a standing rule. The deployment
    # tool renders the execution plan an authorization binds; it has no business
    # in the application. Nothing asserts that today — it holds by
    # `poetry install --only main` — so the battery reads the built image.
    "deployment tool separation": (
        "the deployment tool must not be inside the application image"
    ),
    "deployment tool separation non-vacuity": (
        "so the absence above is not evidence of anything"
    ),
    "app import": "from vendor_cp.main import app",
    "fresh zero-to-head migration": "could not migrate an empty database to heads",
    "restored-production migration": (
        "lane B: a wrongly-owned restored copy is refused before DDL"
    ),
    "restored-production reason": "permission denied for database",
    "restored-production single variable": (
        "the lanes must differ only in DATABASE ownership"
    ),
    "restored-production not a table fault": (
        "SQLSTATE 42501 permission denied for database"
    ),
    "database ownership": "app_admin|app_admin",
    "role contract": "false|false|true|true",
    "grant isolation": "the plane boundary is open",
    # A column named `tenant_id` is not the same as a tenant-SCOPED table, and
    # the one exception is DECLARED as an equality so the ratchet fails when the
    # set grows AND when it shrinks.
    "rls declared, not assumed": "the declared resolver-input set is",
    "rls non-vacuity": "so the equality above is satisfied by the declaration",
    # Production-fatal under kernel a98 and absent from `.env.production.example`;
    # the battery supplies its own so the rest of the run is reachable.
    "production csrf secret": "CSRF_SECRET=candidate-csrf-secret",
    "dependency-aware readiness": (
        "readiness returned $ready_code with an unreachable database"
    ),
    "liveness as control": "liveness should answer 200 even with no database",
    "browser journey": "form login yields a session that reaches the console",
    # Replaying `Set-Cookie` is what lets a production `__Host-`/Secure cookie
    # survive a plain-HTTP runner. The refusal case is what proves the
    # protection is still on after doing it.
    "csrf still refuses without proof": "a form POST with no CSRF proof returned",
    # The distribution manifest the receipt reads is produced on every path,
    # but only READ on the publication path — so the candidate demonstrates it.
    "distribution manifest": "dotmac-distribution-digests/1",
    # The deploy preflight asks the artifact whether a host environment boots.
    # That call runs only at deploy time, so the property it depends on is
    # proved here — including that a refusal never carries a value.
    "deploy preflight property": "refuses an absent/short/reused CSRF_SECRET",
    "api journey": "the API did not issue a bearer token",
    # A refusal that names nothing costs a whole run to diagnose, and a refusal
    # that names too much echoes a credential. Both halves are required.
    "refusals name their reason": "refusal_reason",
    "cli journey": "a read reaches the same owner the browser and API just used",
    "wrong credential": "a wrong password returned $bad_code",
    "wrong standing": "an inactive administrator with the CORRECT password",
    "exact UI assets": "UI asset manifest digest",
    "documentation routes absent": "'/docs', '/docs/oauth2-redirect', '/redoc'",
    "documentation gate bidirectional": "the gate is not discriminating",
    "no fake provisioning surface": "/platform/vendor/provisioning",
    "no checkout dependency": "the same command refuses a checkout with 6",
}


@pytest.mark.parametrize(("what", "marker"), sorted(REQUIRED_CHECKS.items()))
def test_the_acceptance_battery_still_asks_this(what: str, marker: str) -> None:
    assert marker in BATTERY, f"the battery no longer checks {what}"


def test_the_restored_migration_test_has_both_lanes() -> None:
    """Prove correctly owned restores migrate and wrongly owned restores refuse.
    The negative lane must fail for database permissions, not an unrelated fault.
    """
    lane_a = BATTERY.index("lane A: a correctly-owned restored copy upgrades")
    lane_b = BATTERY.index("lane B: a wrongly-owned restored copy is refused")
    assert lane_a < lane_b
    assert "CREATE DATABASE restored_wrong_owner OWNER postgres" in BATTERY
    native = _text(ROOT / ".github/candidate/native_transition_acceptance.py")
    assert '"source_role_owner_mismatch"' in native
    assert 'error.orig.sqlstate == "42501"' in native
    assert '"permission denied for database" in str(error.orig)' in native
    assert "database in str(error.orig)" in native
    assert "transaction.rollback()" in native


def test_the_two_restore_lanes_differ_in_exactly_one_variable() -> None:
    """Hold public schema ownership fixed while varying database ownership.
    Otherwise a privilege failure cannot identify which ownership caused it.
    """
    assert "ALTER SCHEMA public OWNER TO app_admin" in BATTERY
    assert 'test "$ok_owners" = "app_admin|app_admin"' in BATTERY
    assert 'test "$bad_owners" = "postgres|app_admin"' in BATTERY
    setup = BATTERY.index("the lanes must differ only in DATABASE ownership")
    migrate = BATTERY.index("lane B: a wrongly-owned restored copy is refused")
    assert setup < migrate


def test_the_readiness_check_runs_its_negative_case_first() -> None:
    """A probe that returned 200 unconditionally would pass a positive-only test.

    So the unreachable-database case runs BEFORE the reachable one, and the
    liveness route is asserted alongside it as a positive control — otherwise
    "not ready" and "not answering" would be indistinguishable.
    """
    negative = BATTERY.index("database unreachable: /health 200")
    positive = BATTERY.index("database reachable: /health/ready 200")
    assert negative < positive


def test_the_acceptance_battery_is_not_under_scripts() -> None:
    """`scripts/` is production instructions, and those are being retired.

    A CI harness there would be the first new occurrence of the shape
    `vendor_cp.installed_surface` refuses.
    """
    assert ACCEPTANCE.exists()
    assert not (ROOT / "scripts" / "acceptance.sh").exists()
    assert ACCEPTANCE.stat().st_mode & 0o111, "the battery is not executable"


def test_the_declared_ui_asset_expectation_is_exact() -> None:
    lines = _text(UI_EXPECTED).split()
    assert len(lines) == 2, "expected a count and a digest"
    assert lines[0].isdigit() and int(lines[0]) > 0
    assert len(lines[1]) == 64 and all(c in "0123456789abcdef" for c in lines[1])


@pytest.mark.parametrize(
    ("status", "body", "transport_exit", "accepted"),
    [
        (
            200,
            {
                "deployment_ref": "fixture",
                "desired": None,
                "applied": None,
                "drift": False,
            },
            0,
            True,
        ),
        (503, {"detail": "feature_disabled"}, 0, False),
        (200, {"detail": "feature_disabled"}, 0, False),
        (
            200,
            {
                "deployment_ref": "fixture",
                "desired": None,
                "applied": None,
                "drift": True,
            },
            0,
            False,
        ),
        (
            200,
            {
                "deployment_ref": "fixture",
                "desired": None,
                "applied": None,
                "drift": False,
            },
            7,
            False,
        ),
    ],
)
@pytest.mark.parametrize("conditional", ["if", "or"])
def test_enabled_gate_rejects_disabled_and_unrelated_healthy_responses(
    tmp_path, status, body, transport_exit, accepted, conditional
):
    """Execute the actual shell predicate with synthetic HTTP observations."""
    function = BATTERY.split("assert_enabled_deployment() {", 1)[1].split(
        '\nstart_app "$(dsn app_admin restored_ok)" production-keyless-v1', 1
    )[0]
    (tmp_path / "deploy.json").write_text(json.dumps(body))
    invocation = (
        "if (assert_enabled_deployment); then exit 0; else exit 1; fi"
        if conditional == "if"
        else "assert_enabled_deployment || fail refused"
    )
    script = (
        "set -euo pipefail\nfail() { exit 1; }\n"
        f"deploy_read() {{ printf %s {status}; return {transport_exit}; }}\n"
        "assert_enabled_deployment() {" + function + "\n" + invocation + "\n"
    )
    result = subprocess.run(  # noqa: S603 -- repository gate, synthetic response
        ["/bin/bash", "-c", script],
        env={"PATH": os.defpath, "WORKDIR": str(tmp_path)},
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted, result.stderr


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"message": "ledger_unavailable"},
        {"code": "other"},
        {"details": {}},
        "plain",
    ],
)
def test_disabled_control_requires_the_pinned_kernel_refusal(tmp_path, change):
    body = {
        "code": "http_error",
        "message": "feature_disabled",
        "details": None,
        "request_id": "fixture",
    }
    if change == "plain":
        body = {"detail": "feature_disabled"}
    elif change is not None:
        body.update(change)
    path = tmp_path / "refusal.json"
    path.write_text(json.dumps(body))
    program = BATTERY.split("<<'DISABLED'\n", 1)[1].split("\nDISABLED", 1)[0]
    result = subprocess.run(  # noqa: S603 -- actual predicate, synthetic response
        [sys.executable, "-", str(path)],
        input=program,
        text=True,
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) is (change is None)


def test_both_candidate_callers_reach_the_same_enabled_runtime_gate():
    for workflow in (CI_WORKFLOW, IMAGE_WORKFLOW):
        assert ".github/candidate/acceptance.sh" in _text(workflow)
    gate = BATTERY.split('step "19  enabled deploy runtime', 1)[1]
    assert gate.index("VENDOR_DEPLOY_AGENT_ENABLED=false") < gate.index(
        "VENDOR_DEPLOY_AGENT_ENABLED=true"
    )
    assert (
        gate.count('start_app "$(dsn app_admin restored_ok)" production-keyless-v1')
        == 2
    )
    assert "if (assert_enabled_deployment)" in gate
    assert 'test "$(probe /health/ready)" = 200' in gate
    assert gate.index("assert_enabled_deployment || fail") < gate.index(
        "CANDIDATE ACCEPTED"
    )
    for evidence in (
        "--read-only --cap-drop ALL --security-opt no-new-privileges:true",
        "os.setuid(10001)",
        "os.fchmod(key.fileno(), 0o600)",
        "Ed25519PrivateKey.generate()",
        'ledger.append("candidate-runtime.json"',
        'ledger.git("rev-parse", "origin/main")',
        "/usr/local/bin/gh --version",
        "candidate_reader_unavailable",
        "ledger_unavailable",
        "desired-state signing key unavailable",
        '--volume "$WORKDIR/desired.key:/run/candidate/desired.key:ro"',
        'DEPLOY_VOLUME="$(docker volume create)"',
        'docker volume rm "$DEPLOY_VOLUME"',
    ):
        assert evidence in BATTERY


def test_runtime_transport_is_packaged_from_public_verified_inputs():
    recipe = _text(ROOT / "Dockerfile")
    runtime = recipe.split(" AS runtime", 1)[1]
    assert "apt-get install --no-install-recommends -y git ca-certificates" in runtime
    assert "COPY --from=github-cli --chown=root:root /gh /usr/local/bin/gh" in runtime
    assert "gh_2.87.3_checksums.txt" in recipe
    assert 'test "$(dpkg --print-architecture)" = amd64' in recipe
    assert "hashlib.sha256(archive).hexdigest() != expected" in recipe
    assert "c6e5537631fca45f277ef405ce8751d139b491e9402cc20891a003525a8773b2" in recipe
    assert "a95a4e011d77e9cd0e9922c13fda2b95195c6be29dfa58207075fd983bbae744" in BATTERY


@pytest.mark.parametrize(
    ("error_number", "accepted"),
    [(errno.EROFS, True), (errno.EACCES, False), (None, False)],
)
def test_desired_key_mount_probe_requires_read_only_filesystem(error_number, accepted):
    """Writable and permission-denied mounts must both fail the actual probe."""
    from unittest.mock import patch

    probe = BATTERY.split("<<'READ_ONLY_KEY'\n", 1)[1].split("\nREAD_ONLY_KEY", 1)[0]
    error = (
        OSError(error_number, "synthetic filesystem result") if error_number else None
    )
    with (
        patch.dict(os.environ, {"VENDOR_DESIRED_SIGNING_KEY_FILE": "/fixture/key"}),
        patch("os.open", side_effect=error, return_value=42),
        patch("os.close"),
    ):
        if accepted:
            exec(compile(probe, "<candidate-key-mount-probe>", "exec"), {})  # noqa: S102 -- trusted repository probe
        else:
            with pytest.raises((AssertionError, SystemExit)):
                exec(compile(probe, "<candidate-key-mount-probe>", "exec"), {})  # noqa: S102 -- trusted repository probe


def test_native_capture_adapter_executes_only_actual_owner_commands():
    """Evaluate the actual owner prefix and adapter; unknown calls never delegate."""
    import ast
    from types import SimpleNamespace

    path = ROOT / ".github/candidate/native_transition_acceptance.py"
    tree = ast.parse(_text(path))
    adapter = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "FixtureRecoveryProcess"
    )
    fixture_root = Path("/opt/candidate-native")

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    namespace = {
        "ROOT": fixture_root,
        "DOCKER": Path("/usr/bin/docker"),
        "require": require,
        "SubprocessExecutor": SimpleNamespace,
    }
    exec(  # noqa: S102 -- trusted repository adapter AST
        compile(ast.Module(body=[adapter], type_ignores=[]), str(path), "exec"),
        namespace,
    )  # noqa: S102 -- repository adapter AST, no application imports
    process = namespace["FixtureRecoveryProcess"](
        "a" * 64, {"acceptance.invalid/cp@sha256:fixture": "actual-image"}
    )
    effects_tree = ast.parse(_text(ROOT / "src/vendor_cp/deployment/effects.py"))
    owner = next(
        node
        for node in effects_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "PlatformCpRecoveryBundle"
    )
    compose = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "_compose"
    )
    compose.decorator_list = []
    exec(  # noqa: S102 -- trusted owner tuple AST
        compile(
            ast.Module(body=[compose], type_ignores=[]), "<actual-owner-prefix>", "exec"
        ),
        namespace,
    )  # noqa: S102 -- actual fixed tuple only
    owner_self = SimpleNamespace(
        _docker_bin="/usr/bin/docker",
        _spec=SimpleNamespace(product="dotmac_vendor_control_plane"),
        _deploy_dir=fixture_root,
        _env_file=fixture_root / ".env",
        _compose_file=fixture_root / "docker-compose.production.yml",
    )
    prefix = namespace["_compose"](owner_self)
    argv = (
        *prefix,
        "exec",
        "-T",
        "--user",
        "postgres",
        "db",
        "pg_dumpall",
        "--username",
        "postgres",
        "--globals-only",
        "--no-role-passwords",
    )
    translated = process.translate(argv)
    assert translated == [
        "/usr/bin/docker",
        "exec",
        "-i",
        "-e",
        "POSTGRES_DB=restored_ok",
        "--user",
        "postgres",
        "a" * 64,
        "pg_dumpall",
        "--username",
        "postgres",
        "--globals-only",
        "--no-role-passwords",
    ]
    for invalid in (
        ["/usr/bin/docker", "run", "unknown"],
        [*prefix, "exec", "-T", "db", "sh", "-c", "arbitrary command"],
        [*prefix, "exec", "-T", "other-db", "pg_restore", "--list"],
        [*prefix, "--changed-owner-option", "exec", "-T", "db", "pg_restore", "--list"],
        ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", "unknown-image"],
    ):
        with pytest.raises(ValueError):
            process.translate(invalid)


def test_native_harness_keeps_candidate_and_fixture_boundaries():
    native = _text(ROOT / ".github/candidate/native_transition_acceptance.py")
    builder = _text(ROOT / ".github/candidate/build_native_source_fixture.sh")
    lane = BATTERY.split('step "4 ', 1)[1].split('step "5 ', 1)[0]
    assert '--entrypoint python "$NATIVE_SOURCE_IMAGE" -I -c "$SCRIPT"' in lane
    assert '--entrypoint python "$IMAGE" -I /native_transition_acceptance.py' in lane
    assert "--pid host" in lane and "--user 0:0" in lane
    for role, variable in (
        ("app_user", "DATABASE_URL"),
        ("platform_api", "PLATFORM_DATABASE_URL"),
        ("app_admin", "MIGRATION_DATABASE_URL"),
    ):
        assert f'--env "{variable}=$(dsn {role} restored_ok)"' in lane
    assert "host._retain((bundle / name).read_bytes())" not in native
    assert "admin migrate" not in lane
    for marker in (
        "migrations.native_upgrade(",
        "owner.capture_transition(",
        "owner.verify(backup)",
        "host._restore_fresh(",
        "host._negative_reconnect(",
        "store.reserve(",
        "sysconfig.get_path(",
        'shutil.copytree("/app/alembic"',
        '"source_descriptor_not_actual_git_blob"',
        '"CI prospective fixture; not accepted descriptor promotion"',
    ):
        assert marker in native
    assert "monkeypatch" not in native and "_TRANSITION_PERMISSIONS" not in native
    assert "348c31315efaaca9ea23ea7c025d137a3afaad74" in builder
    assert "--secret id=forgejo_token,env=FORGEJO_READ_TOKEN" in builder
    assert "docker push" not in builder and "docker login" not in builder


def _native_function(name, namespace):
    import ast
    from contextlib import contextmanager

    tree = ast.parse(_text(ROOT / ".github/candidate/native_transition_acceptance.py"))
    node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace["contextmanager"] = contextmanager
    namespace["require"] = (
        lambda condition, reason: None
        if condition
        else (_ for _ in ()).throw(ValueError(reason))
    )
    exec(  # noqa: S102 -- trusted repository fixture function
        compile(
            ast.Module(body=[node], type_ignores=[]), "<native-fixture-owner>", "exec"
        ),
        namespace,
    )  # noqa: S102 -- trusted repository fixture function
    return namespace[name]


def test_actual_maintenance_fixture_measures_http_and_websocket_drain():
    import base64
    import http.client
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    fixture = _native_function(
        "maintenance_fixture",
        dict(
            base64=base64,
            hashlib=hashlib,
            http=http,
            threading=threading,
            BaseHTTPRequestHandler=BaseHTTPRequestHandler,
            ThreadingHTTPServer=ThreadingHTTPServer,
        ),
    )
    with fixture() as observed:
        assert observed["endpoint"].startswith("http://127.0.0.1:")
        assert observed["before_drain"] == {"active_http": 2, "active_websockets": 1}
        assert observed["held_request_statuses"] == [101, 503]
        assert observed["websocket_upgrade_status"] == 503
        assert observed["measured"] == {
            "external_status": 503,
            "active_http": 0,
            "active_websockets": 0,
        }


@pytest.mark.parametrize(
    "case", ["success", "cancel", "partial-create", "foreign-label"]
)
def test_writer_fixture_cleanup_uses_only_created_verified_cids(case):
    nonce, image_id = "c" * 64, "sha256:" + "d" * 64
    created, removed, calls = {}, [], []

    def cli(*argv):
        calls.append(argv)
        if argv[1] == "run":
            if case == "partial-create" and created:
                raise RuntimeError("second creation failed")
            role = "relay" if created else "app"
            identifier = ("b" if created else "a") * 64
            created[identifier] = {
                "Id": identifier,
                "Name": "/candidate-native-" + nonce[:32] + "-" + role,
                "Image": image_id,
                "Config": {
                    "Labels": {
                        "io.dotmac.candidate.run": nonce,
                        "io.dotmac.candidate.fixture": role,
                    }
                },
                "State": {"Running": False},
                "HostConfig": {"RestartPolicy": {"Name": "no"}},
            }
            return identifier.encode()
        if argv[1:3] == ("container", "inspect"):
            value = created[argv[3]]
            return json.dumps([value]).encode()
        if argv[1] == "rm":
            removed.append(argv[-1])
        return b""

    fixture = _native_function(
        "writer_fixtures", dict(cli=cli, json=json, DOCKER=Path("/usr/bin/docker"))
    )

    def run():
        with fixture("source-image", image_id, nonce) as writers:
            assert len(writers) == 2
            if case == "cancel":
                raise SystemExit("cancel")
            if case == "foreign-label":
                created["b" * 64]["Config"]["Labels"]["io.dotmac.candidate.run"] = (
                    "foreign"
                )

    if case == "cancel":
        with pytest.raises(SystemExit):
            run()
    elif case == "partial-create":
        with pytest.raises(RuntimeError):
            run()
    elif case == "foreign-label":
        with pytest.raises(ValueError, match="fixture_cleanup_identity_mismatch"):
            run()
    else:
        run()
    assert removed == (
        []
        if case == "foreign-label"
        else ["a" * 64]
        if case == "partial-create"
        else ["b" * 64, "a" * 64]
    )
    assert all(identifier in created for identifier in removed)
    cleanup = BATTERY.split("cleanup() {", 1)[1].split("trap cleanup", 1)[0]
    assert "candidate-native-source-app" not in cleanup
    assert "candidate-native-source-relay" not in cleanup


@pytest.mark.parametrize(
    "fault", [None, "wrong-container-image", "missing-digest", "wrong-digest-image"]
)
def test_postgres_restore_uses_joined_immutable_image(fault):
    container, image_id = "a" * 64, "sha256:" + "b" * 64
    reference = "postgres@sha256:" + "c" * 64

    def cli(*argv):
        if argv[1] == "container":
            value = {
                "Id": container,
                "State": {"Running": True},
                "Image": "other" if fault == "wrong-container-image" else image_id,
            }
        else:
            value = {
                "Id": "other"
                if fault == "wrong-digest-image" and argv[-1] == reference
                else image_id,
                "RepoDigests": [] if fault == "missing-digest" else [reference],
            }
        return json.dumps([value]).encode()

    measure = _native_function(
        "postgres_fixture_identity",
        dict(cli=cli, json=json, DOCKER=Path("/usr/bin/docker")),
    )
    if fault:
        with pytest.raises(ValueError):
            measure(container, "postgres:mutable")
    else:
        assert (
            measure(container, "postgres:mutable")["immutable_reference"] == reference
        )


@pytest.mark.parametrize("offset_hours", [0, -3, 5])
def test_native_fixture_expiry_is_accepted_by_actual_contract_timestamp(offset_hours):
    from datetime import UTC, datetime, timedelta, timezone

    # Load the portable contract module itself: no copied timestamp validator
    # and no substitute regex or mocked contract owner participates in this check.
    spec = importlib.util.spec_from_file_location(
        "candidate_timestamp_contract", ROOT / "src/vendor_cp/deploy_agent/contracts.py"
    )
    contracts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contracts)
    expiry = _native_function("fixture_expiry", dict(UTC=UTC, timedelta=timedelta))
    now = datetime(
        2026, 10, 24, 23, 30, 1, 123456, tzinfo=timezone(timedelta(hours=offset_hours))
    )
    encoded = expiry(now)
    assert contracts.timestamp(encoded) == now.astimezone(UTC) + timedelta(hours=2)
    # The old producer's timezone-offset spelling must still be refused by the
    # actual strict owner, so this regression cannot be fixed by weakening it.
    with pytest.raises(contracts.ContractError):
        contracts.timestamp((now.astimezone(UTC) + timedelta(hours=2)).isoformat())
